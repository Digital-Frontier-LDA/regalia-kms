"""1ym: shipped ExecCondition/credential boundary and the reviewed inventory agree."""
import configparser
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy/baremetal/initrd/regalia-boot-render.service"
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

    def test_the_inventory_pins_the_changed_unit(self):
        inventory = (ROOT / "deploy/baremetal/initrd/initrd-inventory.txt").read_text().splitlines()
        entries = [line.split() for line in inventory if " usr/lib/systemd/system/regalia-boot-render.service " in line]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][-1], hashlib.sha256(UNIT.read_bytes()).hexdigest(),
                         "unit inventory digest must match the shipped bytes")


if __name__ == "__main__":
    unittest.main()
