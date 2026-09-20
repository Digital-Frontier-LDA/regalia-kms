#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from deploy.proxmox import network_probe, provision

SITE_EXAMPLE = Path(__file__).parents[1] / "deploy" / "proxmox" / "site.example.json"


def valid_config(image_path: str, image_sha256: str) -> dict:
    return {
        "schema_version": 2,
        "site": "lisbon",
        "node": "pve-lisbon-01",
        "vmid": 410,
        "name": "kms-lisbon-01",
        "image": {
            "host_path": image_path,
            "sha256": image_sha256,
        },
        "compute": {
            "cores": 4,
            "memory_mib": 4096,
            "cpu": "x86-64-v2-AES",
        },
        "storage": {
            "pool": "kms-zfs",
            "zfs_dataset": "rpool/kms-lisbon",
            "disk_gib": 32,
        },
        "network": {
            "bridge": "vmbr20",
            "vlan": 220,
            "mac": "02:00:00:00:04:10",
            "guest_ipv4": "10.20.0.10/24",
            "gateway_ipv4": "10.20.0.1",
            "kms_port": 8443,
            "ssh_port": 22,
            "client_cidrs": ["10.21.0.0/24"],
            "admin_cidrs": ["10.22.0.0/28"],
            "monitoring_cidrs": ["10.23.0.8/32"],
            "audit_sinks": [{"cidr": "10.24.0.5/32", "port": 6514}],
            "ntp_sinks": [{"cidr": "10.24.0.6/32", "port": 123}],
        },
        "controller": {
            "pci_address": "0000:65:00.0",
            "vendor_device": "1b21:2142",
            "physical_port": "rear-slot-4-port-1",
        },
        "cloud_init": {
            "user": "kms-bootstrap",
            "ssh_public_key_file": "/root/commissioning/kms-bootstrap.pub",
        },
        "controls": {
            "disable_host_ksm": True,
            "prohibit_snapshots_backups_ha_replication": True,
            "dedicated_admin_ownership_accepted": True,
            "commissioning_evidence_public_key_sha256": "c" * 64,
        },
    }


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.image = Path(self.temp.name) / "debian-12-genericcloud-amd64.qcow2"
        self.image.write_bytes(b"pinned Debian fixture")
        self.digest = hashlib.sha256(self.image.read_bytes()).hexdigest()

    def test_plan_is_a_full_qemu_vm_with_controller_passthrough(self):
        plan = provision.build_plan(valid_config(str(self.image), self.digest), verify_image=True)
        flattened = " ".join(plan["qm_create"] + plan["qm_set"])
        self.assertIn("--machine q35", flattened)
        self.assertIn("--bios ovmf", flattened)
        self.assertIn("--balloon 0", flattened)
        self.assertIn("--hostpci0 0000:65:00.0,pcie=1,rombar=0", flattened)
        self.assertNotIn("--usb", flattened)
        self.assertIn("ip6=manual", flattened)
        self.assertEqual(plan["vm_type"], "qemu")
        self.assertEqual(plan["proxmox_major"], 9)
        self.assertEqual(plan["commissioning_evidence_public_key_sha256"], "c" * 64)

    def test_repository_site_example_renders(self):
        document = json.loads(SITE_EXAMPLE.read_text(encoding="utf-8"))
        plan = provision.build_plan(document, verify_image=False)
        self.assertEqual(plan["schema"], "regalia.proxmox-plan/v1")

    def test_wrong_image_digest_is_rejected_before_a_plan(self):
        config = valid_config(str(self.image), "0" * 64)
        with self.assertRaisesRegex(provision.InvalidConfig, "image SHA-256 mismatch"):
            provision.build_plan(config, verify_image=True)

    def test_unknown_fields_and_unsafe_controls_are_rejected(self):
        config = valid_config(str(self.image), self.digest)
        config["surprise"] = True
        with self.assertRaisesRegex(provision.InvalidConfig, "fields mismatch"):
            provision.validate_config(config)
        config = valid_config(str(self.image), self.digest)
        config["controls"]["disable_host_ksm"] = False
        with self.assertRaisesRegex(provision.InvalidConfig, "KSM"):
            provision.validate_config(config)

    def test_boolean_schema_and_multicast_mac_are_rejected(self):
        config = valid_config(str(self.image), self.digest)
        config["schema_version"] = True
        with self.assertRaisesRegex(provision.InvalidConfig, "schema"):
            provision.validate_config(config)
        config = valid_config(str(self.image), self.digest)
        config["network"]["mac"] = "01:00:00:00:04:10"
        with self.assertRaisesRegex(provision.InvalidConfig, "MAC"):
            provision.validate_config(config)

    def test_firewall_is_default_deny_and_exactly_allowlisted(self):
        plan = provision.build_plan(valid_config(str(self.image), self.digest), verify_image=True)
        firewall = plan["firewall"]
        self.assertIn("policy_in: DROP", firewall)
        self.assertIn("policy_out: DROP", firewall)
        self.assertIn("IN ACCEPT -source 10.21.0.0/24 -p tcp -dport 8443", firewall)
        self.assertIn("IN ACCEPT -source 10.22.0.0/28 -p tcp -dport 22", firewall)
        self.assertIn("OUT ACCEPT -dest 10.24.0.5/32 -p tcp -dport 6514", firewall)
        self.assertIn("OUT ACCEPT -dest 10.24.0.6/32 -p udp -dport 123", firewall)
        self.assertNotIn("0.0.0.0/0", firewall)

    def test_network_categories_must_not_overlap(self):
        config = valid_config(str(self.image), self.digest)
        config["network"]["admin_cidrs"] = ["10.21.0.4/32"]
        with self.assertRaisesRegex(provision.InvalidConfig, "overlap"):
            provision.validate_config(config)

    def test_kms_and_ssh_ports_must_not_collapse_into_one_rule(self):
        config = valid_config(str(self.image), self.digest)
        config["network"]["ssh_port"] = config["network"]["kms_port"]
        with self.assertRaisesRegex(provision.InvalidConfig, "distinct"):
            provision.validate_config(config)

    def test_plan_output_is_deterministic_and_contains_no_private_material(self):
        config = valid_config(str(self.image), self.digest)
        first = json.dumps(provision.build_plan(config, verify_image=True), sort_keys=True)
        second = json.dumps(provision.build_plan(config, verify_image=True), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("PRIVATE KEY", first)
        self.assertNotIn("pin", first.lower())
        self.assertEqual(first.count("rpool/kms-lisbon"), 1)

    def test_network_probe_matrix_is_least_privilege(self):
        config = valid_config(str(self.image), self.digest)
        self.assertEqual(network_probe.expected_ports(config, "client"), {8443: True, 22: False})
        self.assertEqual(network_probe.expected_ports(config, "monitoring"), {8443: True, 22: False})
        self.assertEqual(network_probe.expected_ports(config, "admin"), {8443: False, 22: True})
        self.assertEqual(network_probe.expected_ports(config, "unauthorized"), {8443: False, 22: False})


if __name__ == "__main__":
    unittest.main()
