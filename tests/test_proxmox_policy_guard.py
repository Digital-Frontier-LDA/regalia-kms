#!/usr/bin/env python3

import copy
import configparser
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from deploy.proxmox import install_policy_guard, policy_guard


SITE_EXAMPLE = Path(__file__).parents[1] / "deploy" / "proxmox" / "site.example.json"


def parse_unit(text, section="Service"):
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(text)
    return parser[section]


class FakePVE:
    def __init__(self):
        self.responses = {
            "/cluster/resources": [
                {"type": "qemu", "vmid": 9401, "node": "pve-staging-01", "status": "running"},
            ],
            "/nodes/pve-staging-01/qemu/9401/config": {
                "bios": "ovmf", "machine": "q35", "balloon": 0, "hotplug": "0", "numa": 0,
                "hostpci0": "0000:03:00.0,pcie=1,rombar=0", "tags": "regalia-kms;no-backup;no-ha",
            },
            "/nodes/pve-staging-01/qemu/9401/pending": [
                {"key": "memory", "value": "4096"},
            ],
            "/nodes/pve-staging-01/qemu/9401/snapshot": [
                {"name": "current", "description": "You are here!"},
            ],
            "/nodes/pve-staging-01/qemu/9401/status/current": {
                "status": "running", "qmpstatus": "running", "vmid": 9401,
            },
            "/cluster/ha/resources": [],
            "/cluster/replication": [],
            "/cluster/backup": [],
        }
        self.stop_calls = []
        self.autostart_calls = []
        self.fail_autostart = False
        self.fail_stop = False

    def get(self, path, **params):
        self.last_params = params
        return copy.deepcopy(self.responses[path])

    def stop(self, node, vmid):
        if self.fail_stop:
            raise policy_guard.PolicyCheckError("synthetic stop failure")
        self.stop_calls.append((node, vmid))

    def disable_autostart(self, node, vmid):
        if self.fail_autostart:
            raise policy_guard.PolicyCheckError("synthetic autostart failure")
        self.autostart_calls.append((node, vmid))


def config():
    document = json.loads(SITE_EXAMPLE.read_text(encoding="utf-8"))
    document["vmid"] = 9401
    document["node"] = "pve-staging-01"
    document["controller"]["pci_address"] = "0000:03:00.0"
    return document


class PolicyGuardTests(unittest.TestCase):
    def test_pvesh_client_uses_argv_and_strict_json(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="[]", stderr="")

        client = policy_guard.PVEClient(runner)
        self.assertEqual(client.get("/cluster/resources", type="vm"), [])
        client.disable_autostart("pve-staging-01", 9401)
        client.stop("pve-staging-01", 9401)
        self.assertEqual(calls[0][0], [
            "pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json",
        ])
        self.assertNotIn("shell", calls[0][1])
        self.assertEqual(calls[1][0], [
            "pvesh", "set", "/nodes/pve-staging-01/qemu/9401/config", "--onboot", "0",
        ])
        self.assertEqual(calls[2][0], [
            "pvesh", "create", "/nodes/pve-staging-01/qemu/9401/status/stop", "--skiplock", "1",
        ])

    def test_pvesh_client_rejects_duplicate_json_fields(self):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, stdout='{"a": 1, "a": 2}', stderr="")

        with self.assertRaisesRegex(policy_guard.PolicyCheckError, "duplicate"):
            policy_guard.PVEClient(runner).get("/cluster/resources")

    def test_clean_live_state_passes_and_is_machine_readable(self):
        result = policy_guard.inspect(config(), FakePVE())
        self.assertTrue(result["compliant"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["actual_node"], "pve-staging-01")
        self.assertEqual(result["schema"], "regalia.proxmox-policy-check/v1")

    def test_persistent_snapshot_and_saved_memory_are_rejected(self):
        pve = FakePVE()
        pve.responses["/nodes/pve-staging-01/qemu/9401/snapshot"].append(
            {"name": "before-upgrade", "vmstate": True, "snaptime": 1}
        )
        pve.responses["/nodes/pve-staging-01/qemu/9401/config"]["vmstate"] = "kms-zfs:vm-9401-state"
        result = policy_guard.inspect(config(), pve)
        self.assertIn("snapshot:before-upgrade", result["violations"])
        self.assertIn("saved-memory-state", result["violations"])

    def test_pending_and_transient_dangerous_operations_are_rejected(self):
        pve = FakePVE()
        pve.responses["/nodes/pve-staging-01/qemu/9401/pending"][0]["pending"] = "8192"
        pve.responses["/nodes/pve-staging-01/qemu/9401/config"]["lock"] = "backup"
        pve.responses["/nodes/pve-staging-01/qemu/9401/status/current"]["qmpstatus"] = "suspended"
        violations = policy_guard.inspect(config(), pve)["violations"]
        self.assertIn("pending-config:memory", violations)
        self.assertIn("operation-lock:backup", violations)
        self.assertIn("qmp-state:suspended", violations)

    def test_ha_replication_and_migration_are_rejected_even_when_disabled(self):
        pve = FakePVE()
        pve.responses["/cluster/ha/resources"] = [{"sid": "vm:9401", "state": "ignored"}]
        pve.responses["/cluster/replication"] = [{"id": "9401-0", "guest": 9401, "disable": True}]
        pve.responses["/cluster/resources"][0]["node"] = "pve-other-01"
        pve.responses["/nodes/pve-other-01/qemu/9401/config"] = pve.responses.pop(
            "/nodes/pve-staging-01/qemu/9401/config")
        pve.responses["/nodes/pve-other-01/qemu/9401/pending"] = pve.responses.pop(
            "/nodes/pve-staging-01/qemu/9401/pending")
        pve.responses["/nodes/pve-other-01/qemu/9401/snapshot"] = pve.responses.pop(
            "/nodes/pve-staging-01/qemu/9401/snapshot")
        pve.responses["/nodes/pve-other-01/qemu/9401/status/current"] = pve.responses.pop(
            "/nodes/pve-staging-01/qemu/9401/status/current")
        violations = policy_guard.inspect(config(), pve)["violations"]
        self.assertIn("unexpected-node:pve-other-01", violations)
        self.assertIn("ha-resource:vm:9401", violations)
        self.assertIn("replication-job:9401-0", violations)

    def test_direct_all_and_pool_backup_selection_use_resolved_volume_api(self):
        for job in (
            {"id": "direct", "vmid": "9401", "enabled": 1},
            {"id": "all-guests", "all": 1, "enabled": 1},
            {"id": "pool-members", "pool": "sensitive", "enabled": 0},
        ):
            with self.subTest(job=job["id"]):
                pve = FakePVE()
                pve.responses["/cluster/backup"] = [job]
                pve.responses[f"/cluster/backup/{job['id']}/included_volumes"] = {
                    "children": [{"id": 9401, "type": "qemu", "children": [
                        {"id": "scsi0", "included": True, "name": "disk", "reason": "test"},
                    ]}]
                }
                violations = policy_guard.inspect(config(), pve)["violations"]
                self.assertIn(f"backup-job:{job['id']}", violations)

    def test_malformed_or_partial_api_data_fails_closed(self):
        for path, bad in (
            ("/cluster/resources", {}),
            ("/cluster/backup", None),
            ("/cluster/ha/resources", "not-json-shape"),
        ):
            with self.subTest(path=path):
                pve = FakePVE()
                pve.responses[path] = bad
                with self.assertRaises(policy_guard.PolicyCheckError):
                    policy_guard.inspect(config(), pve)

    def test_enforcement_quarantines_when_inspection_cannot_complete(self):
        pve = FakePVE()
        pve.responses["/cluster/backup"] = None
        result = policy_guard.run(config(), pve, enforce_stop=True)
        self.assertFalse(result["compliant"])
        self.assertEqual(result["violations"], ["inspection-incomplete"])
        self.assertTrue(result["autostart_disabled"])
        self.assertTrue(result["stop_requested"])
        self.assertEqual(pve.autostart_calls, [("pve-staging-01", 9401)])
        self.assertEqual(pve.stop_calls, [("pve-staging-01", 9401)])

    def test_known_vm_hardening_drift_is_a_violation_not_an_api_error(self):
        pve = FakePVE()
        pve.responses["/nodes/pve-staging-01/qemu/9401/config"]["balloon"] = 1024
        result = policy_guard.inspect(config(), pve)
        self.assertIn("config-drift:balloon", result["violations"])

    def test_enforcement_requests_stop_on_any_violation(self):
        pve = FakePVE()
        pve.responses["/cluster/ha/resources"] = [{"sid": "vm:9401"}]
        result = policy_guard.run(config(), pve, enforce_stop=True)
        self.assertFalse(result["compliant"])
        self.assertTrue(result["autostart_disabled"])
        self.assertTrue(result["stop_requested"])
        self.assertEqual(pve.autostart_calls, [("pve-staging-01", 9401)])
        self.assertEqual(pve.stop_calls, [("pve-staging-01", 9401)])

    def test_failed_autostart_quarantine_does_not_skip_emergency_stop(self):
        pve = FakePVE()
        pve.responses["/cluster/ha/resources"] = [{"sid": "vm:9401"}]
        pve.fail_autostart = True
        result = policy_guard.run(config(), pve, enforce_stop=True)
        self.assertIn("quarantine-incomplete", result["violations"])
        self.assertFalse(result["autostart_disabled"])
        self.assertTrue(result["stop_requested"])
        self.assertEqual(pve.stop_calls, [("pve-staging-01", 9401)])

    def test_enforcement_does_not_stop_a_clean_vm(self):
        pve = FakePVE()
        result = policy_guard.run(config(), pve, enforce_stop=True)
        self.assertTrue(result["compliant"])
        self.assertFalse(result["autostart_disabled"])
        self.assertFalse(result["stop_requested"])
        self.assertEqual(pve.autostart_calls, [])
        self.assertEqual(pve.stop_calls, [])

    def test_stopped_noncompliant_vm_has_autostart_disabled_without_stop(self):
        pve = FakePVE()
        pve.responses["/cluster/ha/resources"] = [{"sid": "vm:9401"}]
        pve.responses["/cluster/resources"][0]["status"] = "stopped"
        pve.responses["/nodes/pve-staging-01/qemu/9401/status/current"] = {
            "status": "stopped", "qmpstatus": "stopped", "vmid": 9401,
        }
        result = policy_guard.run(config(), pve, enforce_stop=True)
        self.assertTrue(result["autostart_disabled"])
        self.assertFalse(result["stop_requested"])
        self.assertEqual(pve.autostart_calls, [("pve-staging-01", 9401)])


class PolicyGuardInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config_path = self.root / "site.json"
        self.config_path.write_text(json.dumps(config()), encoding="utf-8")

    def test_install_writes_root_owned_layout_and_enforcing_timer(self):
        installed = install_policy_guard.install(self.config_path, root=self.root)
        guard = self.root / "usr/local/libexec/regalia-proxmox/policy_guard.py"
        provision = self.root / "usr/local/libexec/regalia-proxmox/provision.py"
        deployed_config = self.root / "etc/regalia/proxmox/9401.json"
        service = self.root / "etc/systemd/system/regalia-proxmox-policy@.service"
        timer = self.root / "etc/systemd/system/regalia-proxmox-policy@.timer"
        self.assertEqual(installed["vmid"], 9401)
        self.assertTrue(guard.is_file())
        self.assertTrue(provision.is_file())
        self.assertEqual(os.stat(guard).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(deployed_config).st_mode & 0o777, 0o600)
        service_config = parse_unit(service.read_text(encoding="utf-8"))
        timer_config = parse_unit(timer.read_text(encoding="utf-8"), "Timer")
        command = service_config.get("ExecStart", "")
        self.assertIn("--enforce-stop", command)
        self.assertIn("--output /var/lib/regalia-proxmox-policy/%i.json", command)
        self.assertEqual("regalia-proxmox-policy", service_config.get("StateDirectory"))
        self.assertEqual("15s", timer_config.get("OnUnitActiveSec"))
        self.assertEqual("true", timer_config.get("Persistent"))

    def test_commented_unit_directives_are_not_effective(self):
        service = parse_unit("[Service]\n# StateDirectory=regalia-proxmox-policy\n")
        timer = parse_unit("[Timer]\n# Persistent=true\n", section="Timer")
        self.assertIsNone(service.get("StateDirectory"),
                          "a commented systemd StateDirectory was treated as effective")
        self.assertNotIn("--enforce-stop", service.get("ExecStart", ""),
                         "a commented systemd ExecStart argument was treated as effective")
        self.assertIsNone(timer.get("Persistent"),
                          "a commented systemd timer directive was treated as effective")

    def test_install_refuses_a_symlinked_policy_target(self):
        target = self.root / "etc/regalia/proxmox/9401.json"
        target.parent.mkdir(parents=True)
        target.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(install_policy_guard.InstallError, "symlink"):
            install_policy_guard.install(self.config_path, root=self.root)

    def test_result_file_is_private_and_refuses_symlink_target(self):
        target = self.root / "result.json"
        policy_guard.write_result(target, {"compliant": True})
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        target.unlink()
        target.symlink_to(self.root / "elsewhere")
        with self.assertRaisesRegex(policy_guard.PolicyCheckError, "symlink"):
            policy_guard.write_result(target, {"compliant": False})


if __name__ == "__main__":
    unittest.main()
