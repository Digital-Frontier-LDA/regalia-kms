import copy
import datetime
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from deploy.proxmox.verify import InvalidEvidence, load_evidence, main, validate
from tests.test_proxmox_provision import valid_config


EXAMPLE = Path(__file__).parents[1] / "deploy" / "proxmox" / "evidence.example.json"


class ProxmoxEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(EXAMPLE.read_text())

    def assert_invalid(self, mutate):
        document = copy.deepcopy(self.document)
        mutate(document)
        with self.assertRaises(InvalidEvidence):
            validate(document)

    def test_example_is_valid(self):
        validate(self.document)
        self.assertEqual(self.document["schema_version"], 4)
        self.assertTrue(self.document["cluster"]["policy_guard_timer_enabled"])

    def test_rejects_container_and_device_passthrough(self):
        self.assert_invalid(lambda d: d["vm"].update(type="lxc"))
        self.assert_invalid(lambda d: d["vm"]["usb_mappings"].append("host=20a0:4230"))

    def test_rejects_snapshot_backup_replication_ha_and_migration(self):
        self.assert_invalid(lambda d: d["vm"]["snapshots"].append("before-upgrade"))
        self.assert_invalid(lambda d: d["cluster"]["backup_jobs_including_vmid"].append("vzdump-nightly"))
        self.assert_invalid(lambda d: d["cluster"]["replication_jobs"].append("lisbon-to-porto"))
        self.assert_invalid(lambda d: d["cluster"].update(ha_managed=True))
        self.assert_invalid(lambda d: d["cluster"].update(live_migration_allowed=True))

    def test_rejects_memory_and_identity_gaps(self):
        self.assert_invalid(lambda d: d["guest"].update(core_dumps_disabled=False))
        self.assert_invalid(lambda d: d["guest"].update(hibernation_disabled=False))
        self.assert_invalid(lambda d: d["vm"].update(balloon=1024))
        self.assert_invalid(lambda d: d["token"].update(cryptographic_identity_verified_in_guest=False))

    def test_rejects_an_unrecorded_or_malformed_credential_pcr_policy(self):
        """The sealed PIN credentials' PCR policy must be recorded, explicitly, in signed evidence.

        kms/PIN-CUSTODY.md required binding credentials to measured-boot PCRs and recording the
        policy; nothing recorded it, and the documented `systemd-creds encrypt` command passed no
        --tpm2-pcrs. Each row below is a way to leave the policy unrecorded while looking recorded.

        This cannot prove the blob on the guest is sealed to the recorded set — only that a set was
        chosen, is well-formed, and was signed. PIN-CUSTODY.md says so.

        Falsifier: delete the credential_tpm2_pcrs checks in verify.validate. Every row here passes
        the verifier and this test fails alone.
        """
        self.assert_invalid(lambda d: d["guest"].pop("credential_tpm2_pcrs"))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=[]))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=True))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs="7"))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=[24]))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=[-1]))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=[True]))
        self.assert_invalid(lambda d: d["guest"].update(credential_tpm2_pcrs=[7, 7]))
        # Known-good arm in the same test (TESTING.md 18): every row above passes just as well
        # against a verifier that refuses the field unconditionally.
        for accepted in ([7], [0, 7, 11], [23]):
            document = json.loads(EXAMPLE.read_text())
            document["guest"]["credential_tpm2_pcrs"] = accepted
            validate(document)

    def test_the_guest_controls_no_other_test_names_are_refused_when_false(self):
        """Four of the six boolean guest controls had no test proving a False is refused.

        test_rejects_memory_and_identity_gaps covers core_dumps_disabled and hibernation_disabled.
        The other four were enforced only by the all-true loop, with nothing to notice if a key were
        exempted from it — and two of them are PIN-custody rules kms/PIN-CUSTODY.md cites as
        verified at this tier: runtime_credentials_excluded_from_backup and
        direct_token_clients_absent. The loop now skips credential_tpm2_pcrs by name, which is
        exactly the edit that could exempt the wrong one.

        Only the four uncovered keys are here, so this does not duplicate the existing test.

        Falsifier: extend the loop's skip in verify.validate to direct_token_clients_absent. This
        test fails, and test_rejects_memory_and_identity_gaps does not.
        """
        for control in ("swap_disabled_or_encrypted", "runtime_credentials_excluded_from_backup",
                        "direct_token_clients_absent", "kms_service_unprivileged"):
            with self.subTest(control=control):
                self.assert_invalid(lambda d, c=control: d["guest"].update({c: False}))

    def test_rejects_host_ksm_iommu_and_firewall_gaps(self):
        self.assert_invalid(lambda d: d["host"].update(ksm_run=1))
        self.assert_invalid(lambda d: d["host"].update(ksm_pages_shared=12))
        self.assert_invalid(lambda d: d["host"].update(iommu_enabled=False))
        self.assert_invalid(lambda d: d["host"].update(datacenter_firewall_enabled=False))
        self.assert_invalid(lambda d: d["host"].update(storage_encryption_active=False))

    def test_requires_pve9_and_the_live_policy_guard(self):
        self.assert_invalid(lambda d: d["host"].update(pve_version="pve-manager/8.4.0"))
        self.assert_invalid(lambda d: d["cluster"].update(policy_guard_timer_enabled=False))
        self.assert_invalid(lambda d: d["cluster"].update(policy_guard_enforce_stop=False))
        self.assert_invalid(lambda d: d["cluster"].update(policy_guard_interval_seconds=16))
        self.assert_invalid(lambda d: d["cluster"].update(policy_guard_last_result_sha256="sha256:nope"))

    def test_rejects_unknown_fields(self):
        self.assert_invalid(lambda d: d.update(comment="trust me"))

    def test_rejects_duplicate_json_fields(self):
        with self.assertRaisesRegex(InvalidEvidence, "duplicate"):
            load_evidence(b'{"schema_version": 2, "schema_version": 3}')

    def test_cli_requires_signed_production_evidence(self):
        self.assertNotEqual(main(["verify.py", str(EXAMPLE)]), 0)
        self.assertEqual(main(["verify.py", str(EXAMPLE), "--allow-unsigned-example"]), 0)

    def test_production_signature_is_bound_to_reviewed_site_key_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key, public_key = root / "key.pem", root / "key.pub.pem"
            evidence_path, signature = root / "evidence.json", root / "evidence.sig"
            site_path = root / "site.json"
            subprocess.run(
                ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", private_key],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key],
                check=True, capture_output=True,
            )
            der = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", public_key, "-outform", "DER"],
                check=True, capture_output=True,
            ).stdout
            evidence = copy.deepcopy(self.document)
            evidence["captured_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            site = valid_config("/var/lib/vz/template/debian.qcow2", "d" * 64)
            site["site"], site["node"], site["vmid"] = evidence["site"], evidence["node"], evidence["vmid"]
            site["controls"]["commissioning_evidence_public_key_sha256"] = hashlib.sha256(der).hexdigest()
            site_path.write_text(json.dumps(site), encoding="utf-8")
            subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", private_key, "-out", signature, evidence_path],
                check=True, capture_output=True,
            )
            args = ["verify.py", str(evidence_path), "--signature", str(signature),
                    "--public-key", str(public_key), "--site-config", str(site_path)]
            self.assertEqual(main(args), 0)
            site["controls"]["commissioning_evidence_public_key_sha256"] = "e" * 64
            site_path.write_text(json.dumps(site), encoding="utf-8")
            self.assertNotEqual(main(args), 0)


if __name__ == "__main__":
    unittest.main()


class DocumentedProbeAddressTests(unittest.TestCase):
    """The README's four probe commands are copied into a signed transcript. If one of them cannot
    pass against the shipped site file, the operator either records a failure that is not one or
    quietly edits the command — and the transcript stops meaning what it says.

    The `unauthorized` role requires every port CLOSED, so its source address must lie outside
    every role CIDR. It used 198.51.100.20, a CLIENT address: the firewall accepts it on 8443
    exactly as configured, the probe reports expected=closed observed=open, and a correct firewall
    reads as a failed one."""

    README = Path(__file__).parents[1] / "deploy" / "proxmox" / "README.md"
    SITE = Path(__file__).parents[1] / "deploy" / "proxmox" / "site.example.json"

    def documented_sources(self):
        import re
        found = {}
        for line in self.README.read_text(encoding="utf-8").splitlines():
            m = re.search(r"network_probe\.py \S+ --role (\w+) --source-ip (\S+)", line)
            if m:
                found.setdefault(m.group(1), []).append(m.group(2))
        return found

    def configured_networks(self):
        import ipaddress
        site = json.loads(self.SITE.read_text(encoding="utf-8"))["network"]
        nets = []
        for key in ("client_cidrs", "admin_cidrs", "monitoring_cidrs"):
            nets += [ipaddress.ip_network(c) for c in site.get(key, [])]
        nets += [ipaddress.ip_network(s["cidr"]) for s in site.get("audit_sinks", [])]
        return nets

    def test_the_readme_documents_a_probe_for_every_role(self):
        roles = self.documented_sources()
        self.assertEqual({"client", "monitoring", "admin", "unauthorized"}, set(roles),
                         f"the README's probe block no longer covers every role: {sorted(roles)}")

    def test_the_unauthorized_probe_source_is_outside_every_configured_cidr(self):
        import ipaddress
        nets = self.configured_networks()
        self.assertTrue(nets, "no CIDRs were read from site.example.json; this check would pass "
                              "by comparing against nothing")
        for addr in self.documented_sources()["unauthorized"]:
            ip = ipaddress.ip_address(addr)
            inside = [str(n) for n in nets if ip in n]
            self.assertFalse(
                inside,
                f"the documented unauthorized probe source {addr} is inside {inside}. The firewall "
                f"will accept it, the probe will report expected=closed observed=open and exit 1, "
                f"and the transcript will record a correct firewall as a failure.")

    def test_each_authorized_probe_source_is_inside_its_own_role_cidr(self):
        import ipaddress
        site = json.loads(self.SITE.read_text(encoding="utf-8"))["network"]
        key = {"client": "client_cidrs", "admin": "admin_cidrs", "monitoring": "monitoring_cidrs"}
        for role, addrs in self.documented_sources().items():
            if role == "unauthorized":
                continue
            nets = [ipaddress.ip_network(c) for c in site[key[role]]]
            for addr in addrs:
                self.assertTrue(
                    any(ipaddress.ip_address(addr) in n for n in nets),
                    f"the documented {role} probe source {addr} is outside {[str(n) for n in nets]}, "
                    f"so the firewall will refuse it and the run will record a false negative.")
