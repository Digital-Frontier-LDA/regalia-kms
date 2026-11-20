"""1ym: shipped ExecCondition/credential boundary and the reviewed inventory agree."""
import configparser
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
INITRD = ROOT / "deploy/baremetal/initrd"
UNIT = INITRD / "regalia-boot-render.service"
SOURCE = "/.extra/global_credentials/regalia.site.cred"


class SitePresence(unittest.TestCase):
    def setUp(self):
        self.unit = configparser.ConfigParser(interpolation=None, strict=False)
        self.unit.optionxform = str
        self.unit.read(UNIT)

    def test_the_code_checks_enrolment_before_credential_setup(self):
        self.assertFalse([key for key in self.unit["Unit"] if key.startswith("Condition")],
                         "a unit condition must not bypass the enrolment/TPM decision")
        self.assertEqual(self.unit["Service"].get("ExecCondition"), "/usr/bin/regalia-unlock -render-check",
                         "the helper must run as ExecCondition before credential setup")
        self.assertEqual(self.unit["Service"]["ExecStart"], "/usr/bin/regalia-unlock -render /run/regalia-boot")
        self.assertEqual(self.unit["Service"]["LoadCredential"], "regalia.site:" + SOURCE)
        self.assertNotIn("SuccessExitStatus", self.unit["Service"])

    def test_the_existing_render_hardening_is_preserved(self):
        expected = {"PrivateMounts": "yes", "PrivateTmp": "yes", "CapabilityBoundingSet": "CAP_SYS_ADMIN",
                    "NoNewPrivileges": "yes", "ProtectHome": "yes", "RestrictAddressFamilies": "AF_UNIX",
                    "LimitCORE": "0", "UMask": "0077", "RuntimeDirectoryMode": "0700", "TimeoutStartSec": "90"}
        for key, value in expected.items():
            self.assertEqual(self.unit["Service"][key], value, key)

    def assert_consumer_gate(self, name):
        unit = configparser.ConfigParser(interpolation=None, strict=False)
        unit.optionxform = str
        unit.read(INITRD / f"regalia-{name}.service")
        self.assertEqual(unit["Service"].get("ExecCondition"),
                         f"/usr/bin/regalia-unlock -consumer-check {name}",
                         f"{name} must check the render decision before credential setup")
        self.assertIn("LoadCredentialEncrypted", unit["Service"])
        for key in ("Requires", "After"):
            self.assertIn(UNIT.name, unit["Unit"][key].split())

    def test_wg_boot_consumer_gate(self):
        self.assert_consumer_gate("wg-boot")

    def test_unlock_consumer_gate(self):
        self.assert_consumer_gate("unlock")

    def test_the_inventory_pins_the_changed_unit(self):
        inventory = (INITRD / "initrd-inventory.txt").read_text().splitlines()
        for unit in (UNIT, INITRD / "regalia-wg-boot.service", INITRD / "regalia-unlock.service"):
            entries = [line.split() for line in inventory
                       if f" usr/lib/systemd/system/{unit.name} " in line]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0][-1], hashlib.sha256(unit.read_bytes()).hexdigest(),
                             "unit inventory digest must match the shipped bytes")


if __name__ == "__main__":
    unittest.main()
