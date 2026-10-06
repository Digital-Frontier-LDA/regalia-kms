"""deploy/baremetal/bootnext.py: the firmware's boot entries for a rolling update's trial boot (#75, Phase 15).
efibootmgr is a fake that keeps the variables the firmware would; the images are PE files built as ukify lays
them out (tests/test_baremetal_uki.py)."""
import os
import re
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
        elif rest == ["--delete-bootnext"]:
            self.next = None
        elif rest[:1] == ["--bootorder"]:
            self.order = rest[1].split(",")
        elif rest[:1] == ["--bootnum"] and rest[2:] == ["--delete-bootnum"]:
            del self.entries[rest[1]]
            self.order = [e for e in self.order if e != rest[1]]
        elif rest[:1] == ["--create"]:
            # what efibootmgr --create does: the next free number, the new entry first in BootOrder
            opts = dict(zip(rest[1::2], rest[2::2]))
            number = "%04X" % (max(int(n, 16) for n in self.entries) + 1)
            self.add(number, opts["--label"], opts["--loader"])
            self.order = [number] + self.order
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
                ("BootCurrent twice", good + "BootCurrent: 0000\n", "reports BootCurrent twice"),
                ("BootOrder twice", good + "BootOrder: 0000\n", "reports BootOrder twice"),
                ("BootNext twice", good.replace("Timeout: 0 seconds", "BootNext: 0000\nBootNext: 0001"), "reports BootNext twice"),
                ("an entry line that is not one", good + "Boot0003 \n".replace(" \n", "") + "\n", "cannot be read")):
            with self.subTest(label):
                self.refused(reason, bootnext.parse, text)

    def test_a_failing_efibootmgr_is_a_refusal(self):
        fake = FakeEfibootmgr()
        fake.fail = "EFI variables are not supported on this system."
        self.refused("efibootmgr -v failed (exit 5): EFI variables are not supported", bootnext.state, fake)


class OnAnEsp(Case):
    """A temporary directory standing for the ESP this host booted from: mounted vfat, from the partition
    BootCurrent's entry is on, the one systemd-stub names."""
    def setUp(self):
        self.esp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.esp, True)
        os.makedirs(os.path.join(self.esp, "EFI", "Linux"))
        self.one, self.two = image(b"one"), image(b"two")
        for name, data in (("image-1.efi", self.one), ("image-2.efi", self.two)):
            with open(os.path.join(self.esp, "EFI", "Linux", name), "wb") as f:
                f.write(data)
        self.fake = FakeEfibootmgr()
        self.devices = {ESP_GUID: 0x0801, OTHER_GUID: 0x0811}
        self.mounts = {self.esp: (0x0801, "vfat")}
        self.stub = ESP_GUID
        self.where = {"mount": lambda path: self.mounts[path] if path in self.mounts else bootnext.require(False, "%s is not a mount point" % path),
                      "partition_device": lambda guid: self.devices[guid], "loader_partition": lambda: self.stub}

    def image(self, entry):
        return bootnext.image(self.esp, entry, bootnext.state(self.fake), **self.where)


class TrialBoot(OnAnEsp):
    def setUp(self):
        super().setUp()
        self.fake.add("0002", "regalia-kms image-2", r"\EFI\Linux\image-2.efi")
        self.next = accepted("image-2", self.two)

    def trial(self, entry, accepted_set=None, run=None):
        return bootnext.trial(entry, self.esp, accepted_set or self.next, run or self.fake, **self.where)

    def test_bootnext_boots_the_new_image_once_and_every_later_boot_is_the_current_one(self):
        done = self.trial("0002")
        self.assertEqual((done["state"]["next"], done["state"]["order"]), ("0002", ["0001", "0000"]))
        self.assertEqual(done["measured"], bootnext.measured(self.two))
        self.fake.reboot()
        self.assertEqual((self.fake.current, self.fake.next), ("0002", None))      # the trial boot
        self.fake.reboot()
        self.assertEqual(self.fake.current, "0001")                                 # hung and reset: CURRENT again

    def test_promotion_only_of_the_image_this_host_is_running(self):
        self.trial("0002")
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
        with open(os.path.join(self.esp, "EFI", "Linux", "image-3.efi"), "wb") as f:
            f.write(self.two)
        self.fake.add("0003", "inactive", r"\EFI\Linux\image-3.efi", active=False)
        one = accepted("image-1", self.one)
        for entry, accepted_set, reason in (("0001", one, "is the entry this host booted"), ("0009", None, "there is no Boot0009"),
                                            ("0003", None, "is not active"), ("2", None, "four upper-case hex digits"),
                                            ("000a", None, "four upper-case hex digits")):
            with self.subTest(entry):
                self.refused(reason, self.trial, entry, accepted_set)
        self.assertFalse(any("--bootnext" in call for call in self.fake.calls))

    def test_an_image_that_does_not_measure_next_is_never_tried(self):
        """d9 on #325: measuring before BootNext is structural. trial() is the only writer of BootNext."""
        self.refused("it is not that image", self.trial, "0002", accepted("image-1", self.one))
        self.assertFalse(any("--bootnext" in call for call in self.fake.calls))
        self.assertFalse(hasattr(bootnext, "set_next"))

    def test_a_bootnext_that_does_not_read_back_is_a_refusal(self):
        real = self.fake.__call__

        def ignores(argv, **kw):
            if "--bootnext" in argv:
                return subprocess.CompletedProcess(argv, 0, self.fake.report(), "")
            return real(argv, **kw)
        self.refused("BootNext reads None after setting it to 0002: nothing is rebooted on that", self.trial, "0002", None, ignores)

    def test_an_armed_bootnext_is_cleared_and_read_back(self):
        self.trial("0002")
        self.assertIsNone(bootnext.clear_next(self.fake)["next"])
        self.fake.reboot()
        self.assertEqual(self.fake.current, "0001")
        calls = len(self.fake.calls)
        bootnext.clear_next(self.fake)                     # nothing armed: nothing written
        self.assertNotIn("--delete-bootnext", sum(self.fake.calls[calls:], []))

    def test_removing_the_retired_entry(self):
        for entry, prep, reason in (("0001", None, "is the entry this host booted"),):
            self.refused(reason, bootnext.remove, entry, self.fake)
        self.trial("0002")
        self.refused("Boot0002 is BootNext", bootnext.remove, "0002", self.fake)
        self.fake.reboot()
        self.refused("Boot0001 is first in BootOrder: promote the running image first", bootnext.remove, "0001", self.fake)
        bootnext.promote("0002", self.fake)
        state = bootnext.remove("0001", self.fake)
        self.assertNotIn("0001", state["entries"])
        self.assertEqual(state["order"], ["0002", "0000"])


class TheImage(OnAnEsp):
    def setUp(self):
        super().setUp()
        self.fake.add("0002", "regalia-kms image-2", r"\efi\LINUX\Image-2.EFI")       # FAT: the firmware's case may differ

    def test_the_entry_s_image_is_read_from_this_esp_and_measured_against_the_set(self):
        data = self.image("0002")
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
        self.refused("is on partition %s, not on the ESP this host booted from (%s)" % (OTHER_GUID, ESP_GUID), self.image, "0003")
        self.refused("does not load a file", self.image, "0004")
        self.refused("does not load a file", self.image, "0000")
        self.refused("has no image-9.efi", self.image, "0005")
        self.refused("must be an absolute path", bootnext.image, "esp", "0002", bootnext.state(self.fake), **self.where)

    def test_the_directory_read_must_be_the_esp_this_host_booted_from(self):
        """d9 on #325: two ESPs. The entry is on the booted partition, but the directory given is the OTHER
        disk's ESP, mounted where this one usually is: its file is not the one the firmware loads."""
        self.mounts[self.esp] = (self.devices[OTHER_GUID], "vfat")
        self.refused("is not the partition this host booted from (%s): another ESP is mounted there" % ESP_GUID, self.image, "0002")
        self.mounts[self.esp] = (self.devices[ESP_GUID], "ext4")
        self.refused("is a ext4 file system, not the ESP's vfat", self.image, "0002")
        del self.mounts[self.esp]
        self.refused("is not a mount point", self.image, "0002")
        self.mounts[self.esp] = (self.devices[ESP_GUID], "vfat")
        self.stub = OTHER_GUID
        self.refused("systemd-stub says this host booted from partition %s, but BootCurrent's entry is on %s" % (OTHER_GUID, ESP_GUID),
                     self.image, "0002")
        self.stub = None
        self.refused("LoaderDevicePartUUID is not set", self.image, "0002")

    def test_a_link_on_the_esp_is_not_followed(self):
        link = os.path.join(self.esp, "EFI", "Linux", "image-3.efi")
        os.symlink(os.path.join(self.esp, "EFI", "Linux", "image-2.efi"), link)
        self.fake.add("0003", "link", r"\EFI\Linux\image-3.efi")
        with self.assertRaises(OSError):
            self.image("0003")
        # ... nor a link to a directory on the way (d9: every component, not only the last)
        os.symlink(os.path.join(self.esp, "EFI", "Linux"), os.path.join(self.esp, "EFI", "Elsewhere"))
        self.fake.add("0004", "dir link", r"\EFI\Elsewhere\image-2.efi")
        with self.assertRaises(OSError):
            self.image("0004")



class TheHostsOwnRecords(Case):
    """The helpers image() reads the host through: /proc/self/mountinfo and systemd-stub's EFI variable."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_mountinfo_gives_the_visible_mount_at_the_point(self):
        esp = os.path.join(self.d, "e s p")
        os.mkdir(esp)
        info = os.path.join(self.d, "mountinfo")
        with open(info, "w") as f:
            f.write("22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
                    "30 22 8:17 / %s rw - vfat /dev/sdb1 rw\n"          # another disk's ESP, mounted first
                    "31 22 8:1 / %s rw shared:7 - vfat /dev/sda1 rw,fmask=0077\n" % ((esp.replace(" ", "\\040"),) * 2))
        self.assertEqual(bootnext._mount(esp, info), (os.makedev(8, 1), "vfat"))
        self.refused("is not a mount point", bootnext._mount, self.d, info)
        with open(info, "a") as f:
            f.write("32 22 8:1 /EFI %s rw - vfat /dev/sda1 rw\n" % esp.replace(" ", "\\040"))      # d9: ESP/EFI bound here
        self.refused("mounts /EFI of its file system, not the whole ESP", bootnext._mount, esp, info)

    def test_loader_device_part_uuid_is_read_as_systemd_stub_writes_it(self):
        name = os.path.join(self.d, "LoaderDevicePartUUID-" + bootnext.LOADER_VENDOR)
        with open(name, "wb") as f:
            f.write(b"\x06\0\0\0" + (ESP_GUID.upper() + "\0").encode("utf-16-le"))
        self.assertEqual(bootnext._loader_partition(self.d), ESP_GUID)
        with open(name, "wb") as f:
            f.write(b"\x06\0\0\0" + "not-a-guid\0".encode("utf-16-le"))
        self.refused("LoaderDevicePartUUID is not a GUID", bootnext._loader_partition, self.d)
        os.unlink(name)
        self.assertIsNone(bootnext._loader_partition(self.d))


class InstallEntry(unittest.TestCase):
    """install_entry (#61, install-host.sh): a new host's first entry, through bootnext.py as every other write is."""

    def test_the_entry_is_created_and_read_back_first_in_boot_order(self):
        fake = FakeEfibootmgr()
        done = bootnext.install_entry("/dev/sda", 1, ESP_GUID, "regalia image-2", r"\EFI\Linux\image-2.efi", run=fake)
        self.assertEqual(done["entry"], "0002")
        self.assertEqual(done["state"]["order"][0], "0002")
        self.assertIn([bootnext.EFIBOOTMGR, "-v", "--create", "--disk", "/dev/sda", "--part", "1", "--label", "regalia image-2",
                       "--loader", r"\EFI\Linux\image-2.efi"], fake.calls)

    def test_an_existing_label_is_refused_before_anything_is_created(self):
        fake = FakeEfibootmgr()
        with self.assertRaisesRegex(m.Refused, r"Boot0001 already carries the label 'regalia-kms image-1': remove it first"):
            bootnext.install_entry("/dev/sda", 1, ESP_GUID, "regalia-kms image-1", r"\EFI\Linux\image-1.efi", run=fake)
        self.assertFalse([c for c in fake.calls if "--create" in c])

    def test_an_entry_that_reads_back_wrong_is_refused(self):
        fake = FakeEfibootmgr()
        real = fake.__call__

        def wrong_loader(argv, **kw):
            done = real(argv, **kw)
            if "--create" in argv:
                label, active, _ = fake.entries["0002"]
                fake.entries["0002"] = (label, active, fake.disk(ESP_GUID, r"\EFI\Linux\other.efi"))
                done = subprocess.CompletedProcess(argv, 0, fake.report(), "")
            return done
        with self.assertRaisesRegex(m.Refused, r"Boot0002 loads '\\\\EFI\\\\Linux\\\\other.efi', not"):
            bootnext.install_entry("/dev/sda", 1, ESP_GUID, "regalia image-2", r"\EFI\Linux\image-2.efi", run=wrong_loader)

    def test_an_entry_on_another_partition_is_refused_and_deleted_again(self):
        """ed on #474: a wrong --disk/--part reads back with the right loader, first in order, on another partition."""
        fake = FakeEfibootmgr()
        with self.assertRaisesRegex(m.Refused, r"Boot0002 is on partition %s, not the ESP %s: a wrong --disk or --part; "
                                               r"Boot0002, just created, was deleted again" % (ESP_GUID, OTHER_GUID)):
            bootnext.install_entry("/dev/sda", 1, OTHER_GUID, "regalia image-2", r"\EFI\Linux\image-2.efi", run=fake)
        self.assertNotIn("0002", fake.entries)
        self.assertEqual(fake.order, ["0001", "0000"])
        # and a rerun with the right ESP then goes through: its label is free again
        self.assertEqual(bootnext.install_entry("/dev/sda", 1, ESP_GUID, "regalia image-2", r"\EFI\Linux\image-2.efi", run=fake)["entry"], "0002")

    def test_an_entry_that_cannot_be_deleted_again_names_the_recovery(self):
        fake = FakeEfibootmgr()
        real = fake.__call__

        def no_delete(argv, **kw):
            if "--delete-bootnum" in argv:
                return subprocess.CompletedProcess(argv, 5, "", "Could not delete")
            return real(argv, **kw)
        with self.assertRaisesRegex(m.Refused, r"Boot0002, just created, could NOT be deleted: delete it by hand "
                                               r"\(efibootmgr --bootnum 0002 --delete-bootnum\) before a rerun"):
            bootnext.install_entry("/dev/sda", 1, OTHER_GUID, "regalia image-2", r"\EFI\Linux\image-2.efi", run=no_delete)

    def test_the_esp_partuuid_must_be_a_guid(self):
        fake = FakeEfibootmgr()
        with self.assertRaisesRegex(m.Refused, "is not a GUID"):
            bootnext.install_entry("/dev/sda", 1, "not-a-guid", "x", r"\EFI\Linux\a.efi", run=fake)
        self.assertEqual(fake.calls, [])

    def test_its_arguments_are_judged_before_efibootmgr(self):
        for args, why in ((("sda", 1, "x", r"\EFI\Linux\a.efi"), "not a /dev path"),
                          (("/dev/../etc", 1, "x", r"\EFI\Linux\a.efi"), "not a /dev path"),
                          (("/dev/sda", 0, "x", r"\EFI\Linux\a.efi"), "not 1-128"),
                          (("/dev/sda", 1, "a;b", r"\EFI\Linux\a.efi"), "not plain text"),
                          (("/dev/sda", 1, "x", r"\EFI\..\a.efi"), "is not")):
            fake = FakeEfibootmgr()
            with self.subTest(args=args), self.assertRaisesRegex(m.Refused, why):
                bootnext.install_entry(args[0], args[1], ESP_GUID, args[2], args[3], run=fake)
            self.assertEqual(fake.calls, [])


class NothingElseWritesBootVariables(unittest.TestCase):
    def test_only_bootnext_py_calls_efibootmgr_or_writes_efi_variables(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        found = []
        for top in ("deploy", "e2e", "cmd"):
            for dirpath, _, files in os.walk(os.path.join(root, top)):
                for name in files:
                    path = os.path.join(dirpath, name)
                    if path.endswith(os.path.join("deploy", "baremetal", "bootnext.py")) or not name.endswith((".py", ".sh", ".go")):
                        continue
                    with open(path, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    # an invocation, not a mention: the program as a quoted word (Python, Go) or a shell command;
                    # and writing an EFI variable by hand needs its immutable bit cleared first (efivarfs): chattr -i
                    called = re.search(r"""["']([^"'\s]*/)?efibootmgr["']""", text) if not name.endswith(".sh") else \
                        re.search(r"^\s*(sudo\s+)?(\S*/)?efibootmgr\b", text, re.M)
                    if called or ("efivars" in text and "chattr -i" in text):
                        found.append(os.path.relpath(path, root))
        self.assertEqual(found, [], "only deploy/baremetal/bootnext.py may change the firmware's boot variables")

if __name__ == "__main__":
    unittest.main()
