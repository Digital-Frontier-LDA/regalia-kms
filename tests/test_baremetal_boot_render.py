"""1ym: evaluate the shipped presence gate with systemd itself, without a running manager.

These tests do not prove the unit result or journal on a disk boot. The staging boot must still
check ConditionResult=no, ActiveState=inactive, Result=success and the explanatory skip line.
"""
import configparser
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy/baremetal/initrd/regalia-boot-render.service"
SOURCE = "/.extra/global_credentials/regalia.site.cred"


class SitePresence(unittest.TestCase):
    def setUp(self):
        self.unit = configparser.ConfigParser(interpolation=None, strict=False)
        self.unit.optionxform = str
        self.unit.read(UNIT)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name) / "regalia.site.cred"

    def condition(self):
        conditions = [key + "=" + value.replace(SOURCE, str(self.site))
                      for key, value in self.unit["Unit"].items() if key.startswith("Condition")]
        if not conditions:
            return 0  # With no condition the manager starts the service unconditionally.
        done = subprocess.run(["systemd-analyze", "condition", *conditions], capture_output=True, text=True)
        self.assertIn(done.returncode, (0, 1), done.stdout + done.stderr)
        return done.returncode

    def test_absent_site_is_an_expected_pre_genesis_condition_skip(self):
        self.assertEqual(self.condition(), 1, "missing site must skip before credential setup")
        description = self.unit["Unit"]["Description"]
        self.assertIn("no site credential: expected pre-genesis skip", description,
                      "the manager's condition-skip line must explain pre-genesis")

    def test_present_bad_site_reaches_the_existing_hard_failure(self):
        for body in (b"", b"{", b"tampered"):
            with self.subTest(body=body):
                self.site.write_bytes(body)
                self.assertEqual(self.condition(), 0, "present bad site must not be condition-skipped")
        self.site.chmod(0)
        self.addCleanup(self.site.chmod, 0o600)
        self.assertEqual(self.condition(), 0, "unreadable site must not be condition-skipped")
        self.assertEqual(self.unit["Service"]["LoadCredential"], "regalia.site:" + SOURCE)
        self.assertNotIn("SuccessExitStatus", self.unit["Service"])

    def test_dangling_site_link_reaches_the_existing_hard_failure(self):
        self.site.symlink_to(Path(self.tmp.name) / "absent-target")
        self.assertEqual(self.condition(), 0, "dangling site link must not masquerade as pre-genesis")

    def test_the_inventory_pins_the_changed_unit(self):
        inventory = (ROOT / "deploy/baremetal/initrd/initrd-inventory.txt").read_text().splitlines()
        entries = [line.split() for line in inventory if " usr/lib/systemd/system/regalia-boot-render.service " in line]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][-1], hashlib.sha256(UNIT.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
