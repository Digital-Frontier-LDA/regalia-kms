"""deploy/baremetal/bootnext.py: the firmware's boot entries for a rolling update's trial boot (#75, Phase 15).
efibootmgr is a fake that keeps the variables the firmware would; the images are PE files built as ukify lays
them out (tests/test_baremetal_uki.py)."""
import os
import shutil
import subprocess
import tempfile
import unittest

from deploy.baremetal import bootnext, membership as m, uki
from tests.test_baremetal_uki import pe

ESP_GUID = "0b8c6a2c-1111-2222-3333-444455556666"
OTHER_GUID = "9f3e0000-aaaa-bbbb-cccc-ddddeeeeffff"


class FakeEfibootmgr:
    """The EFI variables efibootmgr reads and writes, printed as efibootmgr 17 (File(...)) or 18 (bare path,
    with -v's hex continuation lines) prints them."""

    def __init__(self, style=17):
        self.style, self.calls, self.fail = style, [], None
        self.current, self.next, self.order = "0001", None, ["0001", "0000"]
        self.entries = {"0000": ("UEFI PXE", True, "PciRoot(0x0)/Pci(0x1c,0x0)/MAC(001122334455,0)"),
                        "0001": ("regalia-kms image-1", True, self.disk(ESP_GUID, r"\EFI\Linux\image-1.efi"))}

    def disk(self, guid, path):
        return "HD(1,GPT,%s,0x800,0x100000)/%s" % (guid.upper() if self.style == 17 else guid, "File(%s)" % path if self.style == 17 else path)

    def add(self, number, label, path, guid=ESP_GUID, active=True):
        self.entries[number] = (label, active, self.disk(guid, path))

    def report(self):
        lines = ["BootCurrent: %s" % self.current, "Timeout: 0 seconds"]
        if self.next:
            lines.append("BootNext: %s" % self.next)
        lines.append("BootOrder: %s" % ",".join(self.order))
        for number in sorted(self.entries):
            label, active, device = self.entries[number]
            lines.append("Boot%s%s %s\t%s" % (number, "*" if active else "", label, device))
            if self.style == 18:
                lines.append("      dp: 04 01 2a 00 01 00 00 00 00 08 00 00")
        return "\n".join(lines) + "\n"

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        assert argv[:2] == [bootnext.EFIBOOTMGR, "-v"] and kw["env"] == {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}, (argv, kw)
        if self.fail:
            return subprocess.CompletedProcess(argv, 5, "", self.fail)
        rest = argv[2:]
        if rest[:1] == ["--bootnext"]:
            self.next = rest[1]
        elif rest[:1] == ["--bootorder"]:
            self.order = rest[1].split(",")
        elif rest[:1] == ["--bootnum"] and rest[2:] == ["--delete-bootnum"]:
            del self.entries[rest[1]]
            self.order = [e for e in self.order if e != rest[1]]
        else:
            assert rest == [], rest
        return subprocess.CompletedProcess(argv, 0, self.report(), "")

    def reboot(self):
        """What the firmware does: BootNext once (and deleted), else BootOrder's first."""
        self.current, self.next = (self.next, None) if self.next else (self.order[0], None)


def image(cmdline):
    return pe([(".osrel", b"ID=debian\n"), (".cmdline", cmdline), (".linux", b"KERNEL"), (".initrd", b"INITRD"),
               (".uname", b"6.12.0\n"), (".sbat", b"sbat,1\n")])


def accepted(label, data):
    got = bootnext.measured(data)
    return {"label": label, "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
            "phases": {phase: {"11": value} for phase, value in got.items()}}


class Case(unittest.TestCase):
    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Reading(Case):
    def test_both_report_formats_read_the_same(self):
        for style in (17, 18):
            with self.subTest(style=style):
                fake = FakeEfibootmgr(style)
                fake.add("0002", "regalia-kms image-2", r"\EFI\Linux\image-2.efi")
                state = bootnext.state(fake)
                self.assertEqual((state["current"], state["next"], state["order"]), ("0001", None, ["0001", "0000"]))
                self.assertEqual(state["entries"]["0002"], {"label": "regalia-kms image-2", "active": True, "partition": ESP_GUID,
                                                            "path": r"\EFI\Linux\image-2.efi"})
                self.assertEqual(state["entries"]["0000"]["path"], None)

    def test_what_cannot_be_read_is_refused_not_guessed(self):
        good = FakeEfibootmgr().report()
        for label, text, reason in (
                ("no BootCurrent (not booted by UEFI)", good.replace("BootCurrent: 0001\n", ""), "reports no BootCurrent"),
                ("BootCurrent not listed", good.replace("BootCurrent: 0001", "BootCurrent: 0007"), "BootCurrent 0007 is not among"),
                ("no BootOrder", good.replace("BootOrder: 0001,0000\n", ""), "no readable BootOrder"),
                ("BootNext not listed", good.replace("Timeout: 0 seconds", "BootNext: 0009"), "BootNext 0009 is not among"),
                ("an entry listed twice", good + good.splitlines()[-1] + "\n", "lists Boot0001 twice"),
                ("an entry line that is not one", good + "Boot0003 \n".replace(" \n", "") + "\n", "cannot be read")):
            with self.subTest(label):
                self.refused(reason, bootnext.parse, text)

    def test_a_failing_efibootmgr_is_a_refusal(self):
        fake = FakeEfibootmgr()
        fake.fail = "EFI variables are not supported on this system."
        self.refused("efibootmgr -v failed (exit 5): EFI variables are not supported", bootnext.state, fake)


class TrialBoot(Case):
    def setUp(self):
        self.fake = FakeEfibootmgr()
        self.fake.add("0002", "regalia-kms image-2", r"\EFI\Linux\image-2.efi")

    def test_bootnext_boots_the_new_image_once_and_every_later_boot_is_the_current_one(self):
        state = bootnext.set_next("0002", self.fake)
        self.assertEqual((state["next"], state["order"]), ("0002", ["0001", "0000"]))
        self.fake.reboot()
        self.assertEqual((self.fake.current, self.fake.next), ("0002", None))      # the trial boot
        self.fake.reboot()
        self.assertEqual(self.fake.current, "0001")                                 # hung and reset: CURRENT again

    def test_promotion_only_of_the_image_this_host_is_running(self):
        bootnext.set_next("0002", self.fake)
        self.refused("Boot0002 is not the entry this host booted (Boot0001): only the running image is promoted", bootnext.promote, "0002", self.fake)
        self.fake.reboot()
        state = bootnext.promote("0002", self.fake)
        self.assertEqual(state["order"], ["0002", "0001", "0000"])
        self.fake.reboot()
        self.assertEqual(self.fake.current, "0002")
        calls = len(self.fake.calls)
        bootnext.promote("0002", self.fake)                       # already first: nothing written
        self.assertNotIn("--bootorder", sum(self.fake.calls[calls:], []))

    def test_what_bootnext_refuses(self):
        self.fake.add("0003", "inactive", r"\EFI\Linux\image-3.efi", active=False)
        for entry, reason in (("0001", "is the entry this host booted"), ("0009", "there is no Boot0009"),
                              ("0003", "is not active"), ("2", "four upper-case hex digits"), ("000a", "four upper-case hex digits")):
            with self.subTest(entry):
                self.refused(reason, bootnext.set_next, entry, self.fake)
        self.assertFalse(any("--bootnext" in call for call in self.fake.calls))

    def test_a_bootnext_that_does_not_read_back_is_a_refusal(self):
        real = self.fake.__call__

        def ignores(argv, **kw):
            if "--bootnext" in argv:
                return subprocess.CompletedProcess(argv, 0, self.fake.report(), "")
            return real(argv, **kw)
        self.refused("BootNext reads None after setting it to 0002: nothing is rebooted on that", bootnext.set_next, "0002", ignores)

    def test_removing_the_retired_entry(self):
        for entry, prep, reason in (("0001", None, "is the entry this host booted"),):
            self.refused(reason, bootnext.remove, entry, self.fake)
        bootnext.set_next("0002", self.fake)
        self.refused("Boot0002 is BootNext", bootnext.remove, "0002", self.fake)
        self.fake.reboot()
        self.refused("Boot0001 is first in BootOrder: promote the running image first", bootnext.remove, "0001", self.fake)
        bootnext.promote("0002", self.fake)
        state = bootnext.remove("0001", self.fake)
        self.assertNotIn("0001", state["entries"])
        self.assertEqual(state["order"], ["0002", "0000"])


class TheImage(Case):
    def setUp(self):
        self.esp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.esp, True)
        os.makedirs(os.path.join(self.esp, "EFI", "Linux"))
        self.one, self.two = image(b"one"), image(b"two")
        for name, data in (("image-1.efi", self.one), ("image-2.efi", self.two)):
            with open(os.path.join(self.esp, "EFI", "Linux", name), "wb") as f:
                f.write(data)
        self.fake = FakeEfibootmgr()
        self.fake.add("0002", "regalia-kms image-2", r"\efi\LINUX\Image-2.EFI")       # FAT: the firmware's case may differ

    def test_the_entry_s_image_is_read_from_this_esp_and_measured_against_the_set(self):
        boot = bootnext.state(self.fake)
        data = bootnext.image(self.esp, "0002", boot)
        self.assertEqual(data, self.two)
        got = bootnext.measures(data, accepted("image-2", self.two))
        parts = uki.measured(self.two)
        self.assertEqual(got, {"initrd": uki.pcr11(parts, "enter-initrd"), "system": uki.pcr11(parts, "enter-initrd:leave-initrd:sysinit:ready")})
        self.refused("it is not that image", bootnext.measures, data, accepted("image-1", self.one))
        self.refused("has no per-phase PCR 11", bootnext.measures, data, {"label": "x", "pcrs": {"11": "00" * 32}})

    def test_an_entry_on_another_disk_or_loading_something_else_is_refused(self):
        self.fake.add("0003", "elsewhere", r"\EFI\Linux\image-2.efi", guid=OTHER_GUID)
        self.fake.add("0004", "climbs", r"\EFI\..\image-2.efi")
        self.fake.add("0005", "missing", r"\EFI\Linux\image-9.efi")
        boot = bootnext.state(self.fake)
        self.refused("is on partition %s, not on the ESP this host booted from (%s)" % (OTHER_GUID, ESP_GUID), bootnext.image, self.esp, "0003", boot)
        self.refused("does not load a file", bootnext.image, self.esp, "0004", boot)
        self.refused("does not load a file", bootnext.image, self.esp, "0000", boot)
        self.refused("has no image-9.efi", bootnext.image, self.esp, "0005", boot)
        self.refused("must be an absolute path", bootnext.image, "esp", "0002", boot)

    def test_a_link_on_the_esp_is_not_followed(self):
        link = os.path.join(self.esp, "EFI", "Linux", "image-3.efi")
        os.symlink(os.path.join(self.esp, "EFI", "Linux", "image-2.efi"), link)
        self.fake.add("0003", "link", r"\EFI\Linux\image-3.efi")
        with self.assertRaises(OSError):
            bootnext.image(self.esp, "0003", bootnext.state(self.fake))


if __name__ == "__main__":
    unittest.main()
