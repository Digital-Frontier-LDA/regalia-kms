"""deploy/baremetal/pcr_survey.py: classify PCRs from labelled boots (#65, PoC 5.2/5.3), and refuse a
survey it cannot interpret. The real survey runs on the DL360s; these pin the classification logic."""
import os
import tempfile
import unittest
from pathlib import Path

from deploy.baremetal import pcr_survey


def boot(label, n, **pcrs):
    base = {str(i): "%064x" % i for i in range(24)}
    base.update({str(k[3:]): v for k, v in pcrs.items()})
    return {"label": label, "boot_id": "boot-%d" % n, "pcrs": base}


class Classify(unittest.TestCase):
    def test_stable_volatile_and_moved_by(self):
        snaps = [boot("same", 0),
                 boot("same", 1, pcr10="aa" * 32),                                   # IMA log differs per boot
                 boot("kernel", 2, pcr10="bb" * 32, pcr4="44" * 32, pcr11="11" * 32),
                 boot("cmdline", 3, pcr10="cc" * 32, pcr4="44" * 32, pcr11="11" * 32, pcr12="12" * 32),
                 boot("same", 4, pcr10="dd" * 32, pcr4="44" * 32, pcr11="11" * 32, pcr12="12" * 32)]
        t = pcr_survey.classify(snaps)
        self.assertEqual(t["7"], {"volatile": False, "moved_by": [], "class": "stable"})
        self.assertEqual(t["10"]["class"], "volatile")
        self.assertEqual(t["4"]["moved_by"], ["kernel"])
        self.assertEqual(t["11"]["moved_by"], ["kernel"])
        self.assertEqual(t["12"]["moved_by"], ["cmdline"])

    def test_refusals(self):
        with self.assertRaises(ValueError):
            pcr_survey.classify([boot("kernel", 0)])                       # no baseline
        with self.assertRaises(ValueError):
            pcr_survey.classify([boot("same", 0), boot("same", 0)])        # one boot snapshotted twice
        with self.assertRaises(ValueError):
            pcr_survey.classify([boot("same", 0), boot("bogus", 1)])

    def test_a_partial_pcr_set_or_mixed_packaging_is_refused(self):
        partial = boot("same", 1)
        del partial["pcrs"]["23"]
        with self.assertRaises(ValueError):
            pcr_survey.classify([boot("same", 0), partial])
        a, b = boot("same", 0), boot("same", 1)
        a["boot_packaging"], b["boot_packaging"] = "grub+initramfs", "uki"
        with self.assertRaises(ValueError):
            pcr_survey.classify([a, b])

    def test_no_plain_reboot_yet_is_not_called_stable(self):
        t = pcr_survey.classify([boot("same", 0), boot("kernel", 1, pcr4="44" * 32)])
        self.assertEqual(t["7"]["class"], "unproven (no plain reboot yet)")


class Snapshot(unittest.TestCase):
    def test_reads_sysfs_pcrs_and_boot_identity(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        (root / "sys/class/tpm/tpm0/pcr-sha256").mkdir(parents=True)
        for i in range(24):
            (root / "sys/class/tpm/tpm0/pcr-sha256" / str(i)).write_text("%064X\n" % i)
        (root / "proc/sys/kernel/random").mkdir(parents=True)
        (root / "proc/sys/kernel/random/boot_id").write_text("b-1\n")
        (root / "proc/sys/kernel/osrelease").write_text("6.12.0-test\n")
        (root / "proc/cmdline").write_text("root=/dev/mapper/r ro\n")
        (root / "boot").mkdir()
        (root / "boot/vmlinuz-6.12.0-test").write_bytes(b"kernel")
        s = pcr_survey.snapshot("same", root=str(root))
        self.assertEqual(s["pcrs"]["7"], "%064x" % 7)            # normalized to lower case
        self.assertEqual(s["boot_id"], "b-1")
        self.assertIn("kernel", s["boot_files_sha256"])
        self.assertIsNone(s["secure_boot"])

    def test_a_uki_boot_is_identified_and_its_image_hashed(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        (root / "sys/class/tpm/tpm0/pcr-sha256").mkdir(parents=True)
        for i in range(24):
            (root / "sys/class/tpm/tpm0/pcr-sha256" / str(i)).write_text("%064x\n" % i)
        ev = root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(b"\x06\x00\x00\x00" + "systemd-stub".encode("utf-16-le"))
        (ev / "LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(
            b"\x06\x00\x00\x00" + "kms.efi".encode("utf-16-le") + b"\x00\x00")
        (root / "boot/efi/EFI/Linux").mkdir(parents=True)
        (root / "boot/efi/EFI/Linux/kms.efi").write_bytes(b"uki")
        s = pcr_survey.snapshot("same", root=str(root))
        self.assertEqual((s["boot_packaging"], s["boot_entry"]), ("uki", "kms.efi"))
        self.assertIn("uki", s["boot_files_sha256"])

    def test_a_uki_boot_without_its_image_refuses_the_snapshot(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        (root / "sys/class/tpm/tpm0/pcr-sha256").mkdir(parents=True)
        for i in range(24):
            (root / "sys/class/tpm/tpm0/pcr-sha256" / str(i)).write_text("%064x\n" % i)
        ev = root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "StubInfo-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(b"\x06\x00\x00\x00x\x00")
        with self.assertRaisesRegex(SystemExit, "LoaderEntrySelected"):
            pcr_survey.snapshot("same", root=str(root))
        (ev / "LoaderEntrySelected-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(b"\x06\x00\x00\x00" + "kms.efi".encode("utf-16-le"))
        with self.assertRaisesRegex(SystemExit, "not readable"):
            pcr_survey.snapshot("same", root=str(root))

    def test_a_partial_bank_refuses_the_snapshot(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        (root / "sys/class/tpm/tpm0/pcr-sha256").mkdir(parents=True)
        (root / "sys/class/tpm/tpm0/pcr-sha256/0").write_text("00" * 32)
        with self.assertRaises(SystemExit):
            pcr_survey.snapshot("same", root=str(root))

    def test_no_tpm_refuses(self):
        with self.assertRaises(SystemExit):
            pcr_survey.snapshot("same", root=tempfile.mkdtemp())


if __name__ == "__main__":
    unittest.main()
