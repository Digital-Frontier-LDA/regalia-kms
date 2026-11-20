"""A KMS host BOOTS through a peer (regalia-kms#66 PoC 6.1, 6.2, 6.5; #67 PoC 7.1, 7.4): a QEMU guest under
UEFI (OVMF) with a software TPM, MEASURED BOOT of a unified kernel image built and signed by
deploy/baremetal/uki.py, whose initrd is built by dracut with deploy/baremetal/initrd/dracut/90regalia-unlock
(the same for every host). Its disk: an ESP with the image and the host's credentials (loader/credentials,
measured by systemd-stub into PCR 12) and a GPT partition labelled regalia-root, a LUKS2 volume. The peers
expect PCR 7, PCR 11 per boot phase (the build record) and PCR 12 (deploy/baremetal/espcreds.py). Run by e2e/unlock-boot-qemu.sh, which builds the guest and names its directory
in REGALIA_BOOT_DIR. Nowhere else: it needs root, QEMU, and network namespaces.

The peers are those of tests/test_baremetal_unlock.py's OnSwtpm (real EKs and AKs, responses signed by
their software TPMs), here each in a network namespace of its own with the host firewall and the boot
mesh of e2e/wg-boot-netns.sh. The guest's TPM is the software TPM `a`, handed to QEMU."""
import base64
import hashlib
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import attest, bootcreds, bootnet, espcreds, firewall, membership, sitecfg, trails, uki, unlock
import tests.test_baremetal_unlock as tub

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import tpmdiag  # noqa: E402  regalia-zga, regalia-a0y: what a TPM failure is diagnosed from

BOOT = os.environ.get("REGALIA_BOOT_DIR", "")
UNDERLAY = {"a": "192.0.2.10", "b": "198.51.100.7", "c": "198.51.100.9"}
TUNNEL = {"a": "10.89.0.1", "b": "10.89.0.2", "c": "10.89.0.3"}
# the guest's card, by an address that is NOT QEMU's default for a first card (52:54:00:12:34:56): the boot
# passes only if wg-boot finds the card by its address, not by being the first one
GUEST_MAC = "52:54:00:ab:cd:02"
# systemd sees the systemd-recovery token in the header and asks for the recovery key by that name, naming
# the disk by its label when it has one ("for disk regalia-root (root)")
# ("recovery key" when that is the only kind of keyslot it knows of, "passphrase or recovery key" otherwise)
PROMPT = re.compile(rb"Please enter (?:passphrase or )?(?:recovery key|passphrase) for disk (?:root|regalia-root \(root\))")
OVMF = os.environ.get("REGALIA_OVMF", "/usr/share/OVMF")
# regalia-a0y: on ubuntu-26.04's QEMU 10.2.1 + swtpm 0.10.1 the FIRMWARE fails to extend a PCR about one boot in
# fifteen: swtpm answers the PCR_Extend at once, QEMU cancels it (CMD_CANCEL_TPM_CMD) and systemd-stub logs
# EFI_DEVICE_ERROR. The host's emulation, never the product: a boot that says so fails as exactly that, by name.
HOST_TPM_FAULT = re.compile(r"Failed to measure data for event \d+: 0x8000000000000007")


def host_tpm_fault(console):
    """The firmware's own line when the host's TPM emulation dropped a measurement (regalia-a0y), or None."""
    found = HOST_TPM_FAULT.search(console)
    return found.group(0) if found else None


# regalia-kms-a0g: main's run 41741497644 attempt 1 (5ff5fa23) failed with "the ESP did not mount" while passing on the
# same tree before (job 126164147549) and after (job 126285443219). The mount is the HOST's, before QEMU starts, and the
# old helper waited a fixed 5 s for <loop>p1, then returned in silence and dropped mount's stderr, so nothing said why.
# The wait is NOT lengthened and nothing retries: the setup fails as soon as it fails, by name, with what it measured.
PARTITION_WAIT = 5.0


def wait_for_partition(loop, number, timeout=PARTITION_WAIT, exists=None, clock=None, sleep=None):
    """Polls for <loop>p<number> after `losetup --partscan`. Returns (path, seconds it took to appear, or None if
    it never did within `timeout`)."""
    exists, clock, sleep = exists or os.path.exists, clock or time.monotonic, sleep or time.sleep
    path, start = "%sp%d" % (loop, number), clock()
    while True:
        if exists(path):
            return path, clock() - start
        if clock() - start >= timeout:
            return path, None
        sleep(0.1)


def esp_mount_failure(part, appeared_after, mount_rc, mount_stderr, losetup_list, lsblk):
    """Why the host could not mount the guest's ESP, by name and with what was measured, or None if it mounted.
    A partition seen late (after the bound) that still mounted is no failure: it passed before, and must still."""
    if mount_rc == 0:
        return None
    if appeared_after is None:
        head = "HOST LOOP PARTITION NOT READY: %s did not appear within %.1f s of losetup --partscan" % (part, PARTITION_WAIT)
    else:
        head = "HOST ESP MOUNT FAILED: %s appeared after %.2f s, then mount -t vfat exited %d" % (part, appeared_after, mount_rc)
    return "%s\n mount rc=%s stderr: %s\n losetup -l:\n%s\n lsblk:\n%s" % (
        head, mount_rc, (mount_stderr or "").strip() or "(empty)", losetup_list.rstrip(), lsblk.rstrip())
run = tub.run


def booted_pcrs(said):
    """The REGALIA-E2E-PCRS line's match, read only after systemd-pcrphase.service measured `ready` (#310): the
    guest says what it saw, and a read before `ready` (the sysinit value, one phase short of the record) fails
    here by name, not later as a PCR 11 mismatch. This proves ORDERING only: the unit runs systemd-pcrextend
    --graceful, which exits successfully without a TPM, so "success" is not proof of the extend; the PCR 11
    comparison that follows is."""
    shown = re.search(r"REGALIA-E2E-PCRS 7=(\S+) 11=(\S+) 12=(\S+)", said)
    if shown:
        phase = re.search(r"REGALIA-E2E-PCRPHASE systemd-pcrphase.service=(.*)", said)
        if not (phase and phase.group(1).split() == ["active", "success"]):       # not `assert`: python -O would drop it
            raise AssertionError("the PCRs were read before systemd-pcrphase measured ready (#310): %s"
                                 % (phase.group(1).strip() if phase else "no phase line"))
    return shown


def after_attempt(n):
    """For boot(recovery=): the recovery key is typed once the client has said how attempt `n` went, so the peers were
    asked before the console's answer opens the volume."""
    return lambda said, elapsed: "regalia-unlock: attempt %d: " % n in said


INITRD_PCR11 = re.compile(r"regalia-unlock: initrd PCR 11 \(sha256\) = ([0-9a-f]{64})")


def initrd_pcr11(said):
    """The initrd-phase PCR 11 the client said on the console (#412), or None."""
    shown = INITRD_PCR11.findall(said)
    return shown[0] if shown else None


def no_shell(test, said):
    """Nothing in the initrd offered a shell (rd.shell=0, rd.emergency=reboot): the console only ever asks for the key."""
    test.assertNotRegex(said, r"Emergency Shell|Rescue Shell|Give root password|emergency mode")


# a line systemd forwarded from the journal to the console (systemd.journald.forward_to_console=1, the wrong-usrhash
# image's only): its unit descriptions, "Emergency Shell" among them, are the journal's, not something the console offers
JOURNAL_LINE = re.compile(r"(?m)^.*\bsystemd\[1\]: .*$")


def usr_device_missing(said, roothash, booted):
    """What the console of a boot whose usrhash= is `roothash` lacks of the proof that it failed BECAUSE its /usr is not
    on the disk, [] when nothing (#722 review). `booted` is the root hash of the /usr that IS there: the half of
    `roothash` that differs from it is a PARTUUID no partition carries (the data or the hash partition,
    systemd-veritysetup-generator's convention). Its device times out, so systemd-veritysetup@usr cannot start, so
    /dev/mapper/usr never appears and the initrd cannot mount /usr: in this order, as systemd says it in the initrd's
    journal (on the console through systemd.journald.forward_to_console=1). A boot that fails for any other reason
    (killed, another device, another unit) lacks at least one of them."""
    def unit(half):
        uuid = "-".join((half[0:8], half[8:12], half[12:16], half[16:20], half[20:32]))
        return "dev-disk-by\\x2dpartuuid-%s.device" % uuid.replace("-", "\\x2d")
    absent = [mine for mine, there in ((roothash[:32], booted[:32]), (roothash[32:], booted[32:])) if mine != there]
    expected = ["Timed out waiting for device " + unit(half) for half in absent] + [
        "Dependency failed for systemd-veritysetup@usr.service", "Timed out waiting for device dev-mapper-usr.device",
        "Dependency failed for sysroot-usr.mount"]
    missing, at = [], 0
    for line in expected:
        found = said.find(line, at)
        if found < 0:
            missing.append(line)
        else:
            at = found
    return missing if absent else ["a root hash that names no other /usr than the one on the disk"]


def unattended(test, said):
    """Nobody typed (boot() was given no recovery), yet the root came up: the client's answer opened it. The prompt is
    up all the same, from the start (#70: the client answers beside the console, never in front of it)."""
    test.assertRegex(said, PROMPT.pattern.decode())
    test.assertIn("regalia-unlock: gave the key of ", said)
    test.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)


def initrd_unit(test, console, unit):
    prefix = f"REGALIA-E2E-INITRD regalia-{unit} "
    test.assertIn(prefix + "journal=ok", console, f"missing current-boot journal for {unit}")
    return "\n".join(line[len(prefix):] for line in console.splitlines() if line.startswith(prefix))


# ---- the verity /usr's boots (#61 K61V-4): what each boot's report says, parsed (e2e/lib/boot-guest/e2e-report) ----

def verity_proof(said):
    """The boot's REGALIA-E2E-VERITY line as {"usr", "root", "var": "SOURCE:FSTYPE", "status", "roothash"}, or None."""
    found = re.search(r"REGALIA-E2E-VERITY usr=(\S*) root=(\S*) var=(\S*) status=(\S+) roothash=(\S+)", said)
    return dict(zip(("usr", "root", "var", "status", "roothash"), found.groups())) if found else None


def unit_states(said):
    """{unit: {"load", "active", "result", "started" (monotonic µs, 0 = its main process never started; a timer's or a
    path unit's: when it became active), "enabled", "condition", "assert" (yes/no, the per-host units' line only: None
    otherwise)}}. A unit reported twice is its last line."""
    units = {}
    for m in re.finditer(r"REGALIA-E2E-UNIT (\S+) state=([^/\s]*)/([^/\s]*)/(\S*) started=(\S+) enabled=(\S+)(?: condition=(\S+) assert=(\S+))?", said):
        started = int(m.group(5)) if m.group(5).isdigit() else 0
        units[m.group(1)] = {"load": m.group(2), "active": m.group(3), "result": m.group(4), "started": started, "enabled": m.group(6),
                             "condition": m.group(7), "assert": m.group(8)}
    return units


def firewall_state(said):
    """The REGALIA-E2E-FIREWALL line as {"table", "input-policy", "ruleset-file"}, or None."""
    found = re.search(r"REGALIA-E2E-FIREWALL table=(\S+) input-policy=(\S+) ruleset-file=(\S+)", said)
    return dict(zip(("table", "input-policy", "ruleset-file"), found.groups())) if found else None


def kms_unit(said):
    """The REGALIA-E2E-KMSUNIT line as {"dropins": [path, ...], "credentials": str}, or None."""
    found = re.search(r"REGALIA-E2E-KMSUNIT dropins=(\S*) credentials=(\S*)", said)
    return {"dropins": [p for p in found.group(1).split(",") if p], "credentials": found.group(2)} if found else None


def machine(said):
    """The REGALIA-E2E-MACHINE line as {"id", "kept", "first-boot", "etc-links"}, or None."""
    found = re.search(r"REGALIA-E2E-MACHINE id=(\S+) kept=(\S+) first-boot=(\S+) etc-links=(\d+)", said)
    return dict(zip(("id", "kept", "first-boot", "etc-links"), found.groups())) if found else None


def boot_entry(said):
    """BootCurrent and the label of the entry it names (REGALIA-E2E-BOOTENTRY), or (None, None)."""
    found = re.search(r"REGALIA-E2E-BOOTENTRY current=(\S+) entry=(.*)", said)
    if not found:
        return None, None
    label = re.match(r"Boot[0-9A-Fa-f]{4}\*? (.*?)(?:\t| HD\(| PciRoot\(| VenHw\(|$)", found.group(2).strip())
    return found.group(1), (label.group(1).strip() if label else None)


class VerityReport(unittest.TestCase):
    """The parsers of the verity boots' report lines, on lines as e2e-report writes them (no guest needed)."""
    SAID = ("REGALIA-E2E-VERITY usr=/dev/mapper/usr:erofs root=tmpfs:tmpfs var=/dev/mapper/root:ext4 status=verified roothash=" + "ab" * 32 + "\n"
            "REGALIA-E2E-BOOTENTRY current=0003 entry=Boot0003* regalia e2e HD(1,GPT,0f0e,0x800,0x200000)/\\EFI\\Linux\\e2e.efi\n"
            "REGALIA-E2E-MACHINE id=" + "1" * 32 + " kept=" + "1" * 32 + " first-boot=yes etc-links=0\n"
            "REGALIA-E2E-UNIT regalia-kms.service state=loaded/activating/exit-code started=81234567 enabled=enabled\n"
            "REGALIA-E2E-UNIT apparmor.service state=loaded/inactive/success started=0 enabled=enabled\n"
            "REGALIA-E2E-UNIT nftables.service state=loaded/inactive/success started=0 enabled=gated condition=no assert=yes\n"
            "REGALIA-E2E-FIREWALL table=absent input-policy=none ruleset-file=absent\n"
            "REGALIA-E2E-KMSUNIT dropins=/usr/lib/systemd/system/regalia-kms.service.d/apparmor.conf,/run/systemd/generator/regalia-kms.service.d/50-regalia-credentials.conf credentials=\n")

    def test_the_proof_line(self):
        self.assertEqual(verity_proof(self.SAID), {"usr": "/dev/mapper/usr:erofs", "root": "tmpfs:tmpfs", "var": "/dev/mapper/root:ext4",
                                                   "status": "verified", "roothash": "ab" * 32})
        self.assertIsNone(verity_proof("nothing"))

    def test_the_units(self):
        units = unit_states(self.SAID)
        self.assertEqual(units["regalia-kms.service"]["started"], 81234567)
        self.assertEqual(units["apparmor.service"], {"load": "loaded", "active": "inactive", "result": "success", "started": 0, "enabled": "enabled",
                                                     "condition": None, "assert": None})
        self.assertEqual((units["nftables.service"]["condition"], units["nftables.service"]["assert"]), ("no", "yes"))

    def test_the_firewall_and_the_kms_unit(self):
        self.assertEqual(firewall_state(self.SAID), {"table": "absent", "input-policy": "none", "ruleset-file": "absent"})
        self.assertEqual(kms_unit(self.SAID)["dropins"][1], "/run/systemd/generator/regalia-kms.service.d/50-regalia-credentials.conf")
        self.assertEqual(kms_unit(self.SAID)["credentials"], "")
        self.assertIsNone(firewall_state("nothing"))
        self.assertIsNone(kms_unit("nothing"))

    def test_the_machine_and_the_entry(self):
        self.assertEqual(machine(self.SAID)["etc-links"], "0")
        self.assertEqual(boot_entry(self.SAID), ("0003", "regalia e2e"))
        self.assertEqual(boot_entry("REGALIA-E2E-BOOTENTRY current=0001 entry=Boot0001* UEFI Misc Device PciRoot(0x0)/Pci(0x3,0x0)"),
                         ("0001", "UEFI Misc Device"))
        self.assertEqual(boot_entry(""), (None, None))


class HostTpmFault(unittest.TestCase):
    """regalia-a0y's signature, judged without a guest: the firmware's line from runs 39919392188 and 39922567279."""

    def test_the_firmware_s_measurement_failure_is_named(self):
        console = "EFI stub: WARNING: Failed to measure data for event 1: 0x8000000000000007\r\nLoading Linux ...\n"
        self.assertEqual(host_tpm_fault(console), "Failed to measure data for event 1: 0x8000000000000007")

    def test_a_good_boot_and_another_error_are_not_it(self):
        self.assertIsNone(host_tpm_fault("EFI stub: Measured initrd data into PCR 9.\nWelcome to Debian\n"))
        self.assertIsNone(host_tpm_fault("Failed to measure data for event 1: 0x8000000000000002\n"))   # another status


class EspMountFailure(unittest.TestCase):
    """regalia-kms-a0g, judged without a guest: the host-side ESP setup fails by name, with its measurements."""

    class Clock:
        def __init__(self):
            self.now = 0.0

        def __call__(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    def test_a_partition_that_never_appears_is_measured_as_none_after_the_bound(self):
        clock = self.Clock()
        part, after = wait_for_partition("/dev/loop7", 1, exists=lambda path: False, clock=clock, sleep=clock.sleep)
        self.assertEqual(part, "/dev/loop7p1")
        self.assertIsNone(after)
        self.assertGreaterEqual(clock.now, PARTITION_WAIT)
        self.assertLess(clock.now, PARTITION_WAIT + 0.2)   # the bound is not lengthened

    def test_a_partition_that_appears_late_reports_how_long_it_took(self):
        clock = self.Clock()
        part, after = wait_for_partition("/dev/loop7", 1, exists=lambda path: clock.now >= 0.3, clock=clock, sleep=clock.sleep)
        self.assertAlmostEqual(after, 0.3, places=6)

    def test_a_missing_partition_is_named_with_mount_s_answer_and_the_loop_state(self):
        why = esp_mount_failure("/dev/loop7p1", None, 32, "mount: /x: special device /dev/loop7p1 does not exist.\n",
                                "NAME       SIZELIMIT OFFSET BACK-FILE\n/dev/loop7 0 0 /w/disk.img\n", "loop7 7:7 2G loop\n")
        self.assertTrue(why.startswith("HOST LOOP PARTITION NOT READY: /dev/loop7p1 did not appear within 5.0 s"), why)
        for measured in ("mount rc=32", "special device /dev/loop7p1 does not exist", "/dev/loop7 0 0 /w/disk.img", "loop7 7:7 2G loop"):
            self.assertIn(measured, why)

    def test_a_partition_that_appeared_but_did_not_mount_is_named_apart(self):
        why = esp_mount_failure("/dev/loop7p1", 0.42, 32, "mount: wrong fs type\n", "", "")
        self.assertTrue(why.startswith("HOST ESP MOUNT FAILED: /dev/loop7p1 appeared after 0.42 s, then mount -t vfat exited 32"), why)
        self.assertIn("wrong fs type", why)
        self.assertIn("stderr: mount: wrong fs type", why)

    def test_esp_itself_fails_by_name_when_the_partition_never_appears_and_still_detaches(self):
        """The wiring, not only the helpers: OnQemu's own partition() and esp(), with the host's commands faked."""
        from unittest import mock
        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            out = {"--find": "/dev/loop7\n", "-l": "/dev/loop7 0 0 /w/disk.img\n", "-O": "/w/disk.img\n"}
            if argv[0] == "mount":
                return subprocess.CompletedProcess(argv, 32, "", "mount: special device /dev/loop7p1 does not exist.\n")
            if argv[0] == "lsblk":
                return subprocess.CompletedProcess(argv, 0, "loop7 7:7 2G loop\n", "")
            key = next((a for a in argv if a in out), None)
            return subprocess.CompletedProcess(argv, 0, out.get(key, ""), "")

        class Host(unittest.TestCase):
            partition, esp = OnQemu.partition, OnQemu.esp

            def runTest(self):
                pass

        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        host = Host()
        host.image, host.d = "/w/disk.img", d
        module = sys.modules[__name__]
        with mock.patch.object(module, "run", fake_run), \
                mock.patch.object(module, "wait_for_partition", lambda loop, number: (loop + "p%d" % number, None)), \
                mock.patch.object(module.os.path, "realpath", lambda path: path):
            with self.assertRaises(host.failureException) as raised:
                host.esp({})
            host.doCleanups()
        self.assertTrue(str(raised.exception).startswith("HOST LOOP PARTITION NOT READY: /dev/loop7p1"), raised.exception)
        for measured in ("mount rc=32", "special device /dev/loop7p1", "/dev/loop7 0 0 /w/disk.img", "loop7 7:7 2G loop"):
            self.assertIn(measured, str(raised.exception))
        self.assertIn(["losetup", "-d", "/dev/loop7"], calls)
        self.assertNotIn(["umount", d + "/esp"], calls)   # it never mounted

    def test_esp_itself_passes_a_late_partition_that_mounts_and_says_it_was_late(self):
        """regalia-01 F1, on the wiring: p1 not seen within the bound, then mounted; that passed on main, and does."""
        import contextlib
        import io
        import tempfile
        from unittest import mock
        calls, d, boot = [], tempfile.mkdtemp(), tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.addCleanup(shutil.rmtree, boot, True)
        for sub in ("esp/loader/credentials", "esp/EFI/BOOT"):
            os.makedirs(os.path.join(d, sub))
        with open(os.path.join(boot, "e2e.efi"), "wb") as f:
            f.write(b"stub")

        def fake_run(argv, **kwargs):
            calls.append(argv)
            out = {"--find": "/dev/loop7\n", "-O": "/w/disk.img\n"}
            key = next((a for a in argv if a in out), None)
            return subprocess.CompletedProcess(argv, 0, out.get(key, ""), "")

        class Host(unittest.TestCase):
            partition, esp = OnQemu.partition, OnQemu.esp

            def runTest(self):
                pass

        host = Host()
        host.image, host.d, host.chain = "/w/disk.img", d, {}
        module, said = sys.modules[__name__], io.StringIO()
        with mock.patch.object(module, "run", fake_run), mock.patch.object(module, "BOOT", boot), \
                mock.patch.object(module, "wait_for_partition", lambda loop, number: (loop + "p%d" % number, None)), \
                mock.patch.object(module.os.path, "realpath", lambda path: path), contextlib.redirect_stderr(said):
            files = host.esp({"x": b"1"})
            host.doCleanups()
        self.assertEqual(files, {"x.cred": b"1"})
        self.assertIn("was not seen within 5.0 s; mount succeeded anyway", said.getvalue())
        self.assertIn(["umount", d + "/esp"], calls)

    def test_a_mounted_esp_is_no_failure_even_when_its_partition_was_seen_late(self):
        self.assertIsNone(esp_mount_failure("/dev/loop7p1", 0.1, 0, "", "", ""))
        self.assertIsNone(esp_mount_failure("/dev/loop7p1", None, 0, "", "", ""))   # regalia-01 F1: passed on main, still passes

    def test_an_empty_stderr_still_says_so(self):
        self.assertIn("stderr: (empty)", esp_mount_failure("/dev/loop7p1", None, 32, "", "", ""))


class PreGenesisFixture(unittest.TestCase):
    def test_first_boot_has_no_membership_anchor_or_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "disk.img").touch()
            (root / "e2e.efi").touch()
            (root / "esp/loader/credentials").mkdir(parents=True)
            (root / "esp/EFI/BOOT").mkdir(parents=True)

            fixture = OnQemu()
            fixture.d, fixture.m1 = directory, {}
            fixture.tcti, fixture.pids = {"a": "synthetic"}, {"a": 123}
            fixture.partition_appeared_after = 0
            fixture.partition = Mock(return_value=("/dev/loop-test", "/dev/loop-testp1"))
            fixture.network = Mock()
            fixture.on = Mock()
            fixture.addCleanup = Mock()

            # Exercise the real QEMU setup and ESP writer over an ordinary directory.
            with (patch.object(sys.modules[__name__], "BOOT", directory),
                  patch.object(sys.modules[__name__], "run", return_value=Mock(stdout="YWJj", returncode=0)),
                  patch.object(tub.OnSwtpm, "setUp"), patch.object(os, "kill"),
                  patch.object(membership, "HighWater") as high_water,
                  patch.object(membership, "accept_chain"), patch.object(membership.Store, "_digests")):
                fixture.setUp()
                self.assertEqual(fixture.esp({}), {})

            with self.subTest(evidence="TPM"):
                high_water.return_value.define.assert_not_called()
                high_water.return_value.anchor.assert_not_called()
            with self.subTest(evidence="ESP"):
                self.assertFalse((root / "esp" / bootcreds.CHAIN_ON_ESP).exists(),
                                 "the ESP chain would make render refuse instead of skipping")


@unittest.skipUnless(os.environ.get("REGALIA_EXPECT_QEMU") == "1", "needs a guest built by e2e/unlock-boot-qemu.sh")
class OnQemu(tub.OnSwtpm):
    # the fixtures of OnSwtpm are reused, not its tests
    test_tpm_plus_one_peer_opens_the_disk_and_a_retired_image_a_stolen_disk_or_a_revoked_node_does_not = None
    test_systemd_cryptsetup_asks_the_client_answers_and_the_console_is_never_taken_away = None

    # The membership root the image trusts (#156): e2e/unlock-boot-qemu.sh builds the initrd with the TEST root of
    # tests/vectors/highwater-v1.json, whose private key is fixed there (make-highwater-v1.py); the chain on the
    # guest's ESP is signed with it (#66 B3)
    ROOT = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    def signed(self, manifest):
        """An envelope of `manifest`, signed by the root the image trusts."""
        from cryptography.hazmat.primitives import serialization
        public = self.ROOT.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        return {"manifest": manifest, "signature": {"signer": "root", "key": public,
                                                    "sig": self.ROOT.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}

    def setUp(self):
        self.assertTrue(os.path.exists(BOOT + "/disk.img"), "REGALIA_BOOT_DIR must hold the guest e2e/unlock-boot-qemu.sh built")
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "highwater-v1.json")) as f:
            vector_root = json.load(f)["root_public"]
        self.assertEqual(self.signed({})["signature"]["key"], vector_root, "the test root is not the vector's: the image would refuse the chain")
        self.keys = {}
        for node in "abc":                                  # a WG-BOOT and a WG-SERVICE pair each, as the manifest lists them
            for kind in ("boot", "service"):
                private = run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
                public = run(["wg", "pubkey"], input=private.encode(), capture_output=True, check=True).stdout.strip()
                self.keys[node, kind] = (private, base64.b64decode(public).hex())
        super().setUp()                                     # the three TPMs with their AKs, the manifest, the peers b and c
        self.image = BOOT + "/disk.img"
        self.disk = None                                    # the LUKS2 partition, through a loop device while the guest is off
        self.chain = None                                   # boot 1 has neither ESP membership nor a TPM anchor
        # the guest's TPM is `a`: provisioned above through its socket, from here on QEMU's
        self.on("a", attest.tpm2, "shutdown", "-c")
        os.kill(self.pids.pop("a"), 15)
        self.namespaces, self.processes = [], []
        self.addCleanup(self.teardown_network)
        self.network()

    def manifest(self, previous, **states):
        manifest = super().manifest(previous, **states)
        for node in manifest["nodes"]:
            node["wg_boot_pub"], node["wg_service_pub"] = self.keys[node["node_id"], "boot"][1], self.keys[node["node_id"], "service"][1]
        return manifest

    def site(self, node):
        return sitecfg.validate({
            "schema": sitecfg.SCHEMA, "site": "site-" + node, "host_ipv4": UNDERLAY[node], "kms_port": 8443, "ssh_port": 22,
            "client_cidrs": ["198.18.0.0/24"], "monitoring_cidrs": ["198.18.1.1/32"], "admin_cidrs": ["198.18.2.0/28"],
            "outbound": [{"name": "audit", "cidr": "198.18.3.1/32", "proto": "tcp", "port": 6514}],
            "time": {"nts": [{"name": "nts-a.lab", "cidrs": ["198.18.3.2/32"]}, {"name": "nts-b.lab", "cidrs": ["198.18.3.3/32"]}]},
            "boot_mesh": {"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": TUNNEL[node], "unlock_port": 7443,
                          "nic_mac": GUEST_MAC, "prefix": 32, "gateway": None,
                          "peers": [{"node_id": p, "underlay": UNDERLAY[p], "address": TUNNEL[p]} for p in "abc" if p != node]},
            "service_mesh": None})

    # -- the network: a bridge and QEMU's tap in one namespace, each peer in its own --
    def ip(self, *argv, ns=None, stdin=None):
        done = run((["ip", "netns", "exec", ns] if ns else []) + list(argv), input=stdin, capture_output=True)
        self.assertEqual(done.returncode, 0, "%s: %s" % (" ".join(argv), done.stderr.decode(errors="replace")))
        return done.stdout

    def network(self):
        tag = "%d" % os.getpid()
        self.switch = "ru-sw-" + tag
        self.ip("ip", "netns", "add", self.switch)
        self.namespaces.append(self.switch)
        self.ip("ip", "link", "add", "br0", "type", "bridge", ns=self.switch)
        self.ip("ip", "link", "set", "br0", "up", ns=self.switch)
        self.ip("ip", "tuntap", "add", "tap0", "mode", "tap", ns=self.switch)
        self.ip("ip", "link", "set", "tap0", "master", "br0", "up", ns=self.switch)
        self.peer_ns = {}
        for peer in ("b", "c"):
            ns = self.peer_ns[peer] = "ru-%s-%s" % (peer, tag)
            self.ip("ip", "netns", "add", ns)
            self.namespaces.append(ns)
            veth = "v%s%s" % (peer, tag[-8:])
            self.ip("ip", "link", "add", veth, "type", "veth", "peer", "name", "eth0", "netns", ns)
            self.ip("ip", "link", "set", veth, "netns", self.switch)
            self.ip("ip", "link", "set", veth, "master", "br0", "up", ns=self.switch)
            for argv in (["ip", "link", "set", "lo", "up"], ["ip", "link", "set", "eth0", "up"], ["ip", "addr", "add", UNDERLAY[peer] + "/32", "dev", "eth0"],
                         ["ip", "route", "add", "default", "dev", "eth0"], ["ip", "link", "add", "wg-unlock", "type", "wireguard"]):
                self.ip(*argv, ns=ns)
            cfg = self.site(peer)
            self.apply_wireguard(peer)
            for argv in (["ip", "addr", "add", TUNNEL[peer] + "/32", "dev", "wg-unlock"], ["ip", "link", "set", "wg-unlock", "up"],
                         ["ip", "route", "add", "10.89.0.0/24", "dev", "wg-unlock"]):
                self.ip(*argv, ns=ns)
            self.ip("nft", "-f", "-", ns=ns, stdin=firewall.render(cfg).encode())
            listener = self.listen_in(ns, TUNNEL[peer], cfg["boot_mesh"]["unlock_port"])
            self.addCleanup(listener.close)
            threading.Thread(target=unlock.serve, args=(self.served[peer], listener), daemon=True,
                             kwargs={"caller": lambda address, peer=peer, cfg=cfg: bootnet.caller_of(cfg, self.stores[peer].load())(address)}).start()

    def apply_wireguard(self, peer):
        """The peer's WireGuard list under the manifest it holds now, with its key added in memory."""
        conf = bootnet.with_key(bootnet.peer_wg_conf(self.site(peer), self.stores[peer].load()), self.keys[peer, "service"][0])
        self.ip("wg", "syncconf", "wg-unlock", "/dev/stdin", ns=self.peer_ns[peer], stdin=conf.encode())

    def listen_in(self, ns, address, port):
        """A listening socket made inside a network namespace (a thread joins it, makes the socket, and ends)."""
        made = []

        def make():
            with open("/run/netns/" + ns) as f:
                os.setns(f.fileno(), os.CLONE_NEWNET)
            made.append(socket.create_server((address, port)))
        thread = threading.Thread(target=make)
        thread.start()
        thread.join()
        self.assertTrue(made, "no listener in " + ns)
        return made[0]

    def teardown_network(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
        for ns in self.namespaces:
            pids = run(["ip", "netns", "pids", ns], capture_output=True, text=True).stdout.split()
            for pid in pids:
                try:
                    os.kill(int(pid), 9)
                except OSError:
                    pass
            run(["ip", "netns", "del", ns], capture_output=True)

    # -- the guest --
    def partition(self, number):
        """A partition of the guest's disk as a block device on this machine, while the guest is off. The caller
        detaches it; a cleanup does too, only if it is still this image's (a freed loop name may be another's)."""
        loop = run(["losetup", "--find", "--show", "--partscan", self.image], capture_output=True, text=True, check=True).stdout.strip()
        def detach():
            if os.path.realpath(run(["losetup", "-n", "-O", "BACK-FILE", loop], capture_output=True, text=True).stdout.strip() or "/") == os.path.realpath(self.image):
                run(["losetup", "-d", loop], capture_output=True)
        self.addCleanup(detach)
        part, self.partition_appeared_after = wait_for_partition(loop, number)
        return loop, part

    def esp(self, named, image="e2e"):
        """Puts exactly these credentials ({name: bytes}) in the ESP's loader/credentials, as <name>.cred, and
        `image` (<image>.efi of REGALIA_BOOT_DIR, signed by e2e/unlock-boot-qemu.sh) as the one boot image, and
        the membership chain (self.chain, #66 B3) at EFI/regalia/membership.json once enrolled.
        Returns the credential files as systemd-stub will read them."""
        loop, part = self.partition(1)
        mnt = self.d + "/esp"
        os.makedirs(mnt, exist_ok=True)
        mount = run(["mount", "-t", "vfat", part, mnt], capture_output=True, text=True)
        mounted = mount.returncode == 0
        try:
            if not mounted:
                self.fail(esp_mount_failure(part, self.partition_appeared_after, mount.returncode, mount.stderr,
                                            run(["losetup", "-l"], capture_output=True, text=True).stdout,
                                            run(["lsblk", "-o", "NAME,MAJ:MIN,SIZE,TYPE,FSTYPE", loop], capture_output=True, text=True).stdout))
            if self.partition_appeared_after is None:
                print("the ESP's partition %s was not seen within %.1f s; mount succeeded anyway" % (part, PARTITION_WAIT), file=sys.stderr)
            elif self.partition_appeared_after >= 1.0:
                print("the ESP's partition %s appeared after %.2f s" % (part, self.partition_appeared_after), file=sys.stderr)
            where = mnt + "/loader/credentials"
            for name in os.listdir(where):
                os.unlink(os.path.join(where, name))
            files = {name + ".cred": content for name, content in named.items()}
            for name, content in files.items():
                with open(os.path.join(where, name), "wb") as f:
                    f.write(content)
            shutil.copyfile("%s/%s.efi" % (BOOT, image), mnt + "/EFI/BOOT/BOOTX64.EFI")
            # and at the installer's own path (install-host.sh: \EFI\Linux\e2e.efi, its firmware entry's loader), when the
            # disk has one: what an update leaves, the image to boot at the path the entry names (#61 K61V-4)
            if os.path.isdir(mnt + "/EFI/Linux"):
                shutil.copyfile("%s/%s.efi" % (BOOT, image), mnt + "/EFI/Linux/e2e.efi")
            chain_path = Path(mnt) / bootcreds.CHAIN_ON_ESP
            if self.chain is None:
                chain_path.unlink(missing_ok=True)
            else:
                chain_path.parent.mkdir(parents=True, exist_ok=True)
                chain_path.write_bytes(membership.canonical(self.chain))
        finally:
            unmounted = not mounted or run(["umount", mnt], capture_output=True).returncode == 0
            run(["losetup", "-d", loop], capture_output=True)
        self.assertTrue(unmounted, "the ESP did not unmount")
        return files

    def boot(self, label, credentials=None, enrol_disk=None, recovery=False, timeout=None, smbios=None, smbios_strings=(), image="e2e",
             watch=None, nvram=None):
        """One boot of the guest under OVMF, to power-off, with `credentials` and `image` on its ESP. Returns what its
        console said. With `recovery`, the recovery key is typed whenever the console asks for a passphrase; when it is
        a function of (console so far, seconds since start), only once that says so (and what it returns, when that is
        bytes, is typed instead). `watch`, a function of the same, is
        called as the console grows (to change the network under the guest), and the times it returned true are kept in
        self.watched."""
        self.on_esp = self.esp(credentials or {}, image)
        # the firmware's variables: fresh for every boot, or with `nvram` one store kept from boot to boot (a host's
        # NVRAM, where the installer's firmware entry stays: #61 K61V-4)
        variables = "%s/vars-%s.fd" % (self.d, nvram or label)
        if not (nvram and os.path.exists(variables)):
            shutil.copyfile(OVMF + "/OVMF_VARS_4M.fd", variables)
        kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
        timeout = timeout or (600 if kvm else 2400)
        ctrl = self.d + "/a.ctrl"
        if os.path.exists(ctrl):
            os.unlink(ctrl)
        # regalia-a0y's cause was in this swtpm's log at level 20 (an answered PCR_Extend, then CMD_CANCEL_TPM_CMD): written in
        # self.d (under /tmp, where swtpm's AppArmor profile lets it write), then kept beside the boot's console
        tpm_log = "%s/swtpm-%s.log" % (self.d, label)
        tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-a" % self.d, "--ctrl", "type=unixio,path=" + ctrl,
                                "--log", tpmdiag.log_arg(tpm_log)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(tpm)
        for _ in range(100):
            if os.path.exists(ctrl):
                break
            time.sleep(0.1)
        argv = ["ip", "netns", "exec", self.switch, "qemu-system-x86_64", "-machine", "q35,accel=" + ("kvm" if kvm else "tcg"),
                "-cpu", "host" if kvm else "max", "-m", "1536", "-smp", "2", "-display", "none", "-no-reboot", "-serial", "stdio",
                "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=%s/OVMF_CODE_4M.fd" % OVMF,
                "-drive", "if=pflash,format=raw,unit=1,file=" + variables,
                # The guest's disk is the first boot option, whatever OVMF would order: ubuntu-26.04's (fresh variables, a
                # virtio NIC) tried PXE and HTTP boot first, about 60 s each, and boot 1 asked after 158 s (regalia-oiq)
                "-drive", "file=%s,format=raw,if=none,id=boot" % self.image, "-device", "virtio-blk-pci,drive=boot,bootindex=0",
                "-netdev", "tap,id=n0,ifname=tap0,script=no,downscript=no", "-device", "virtio-net-pci,netdev=n0,mac=%s" % GUEST_MAC,
                "-chardev", "socket,id=chrtpm,path=" + ctrl, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"]
        if enrol_disk:
            argv += ["-drive", "file=%s,format=raw,if=virtio" % enrol_disk]
        for name, content in sorted((smbios or {}).items()):        # SMBIOS type 11: a channel the firmware owns
            path = "%s/smbios-%s-%s" % (self.d, label, name)
            with open(path, "w") as f:
                f.write("io.systemd.credential.binary:%s=%s" % (name, base64.b64encode(content).decode()))
            argv += ["-smbios", "type=11,path=" + path]
        for n, string in enumerate(smbios_strings):                  # SMBIOS type 11 strings as they are, e.g. for systemd-stub
            path = "%s/smbios-%s-string-%d" % (self.d, label, n)
            with open(path, "w") as f:
                f.write(string)
            argv += ["-smbios", "type=11,path=" + path]
        qemu = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.processes.append(qemu)
        said, answered, started = b"", 0, time.monotonic()
        deadline, self.prompted_after, self.watched = started + timeout, None, []
        with open("%s/console-%s.log" % (BOOT, label), "wb") as log:
            while True:
                ready, _, _ = select.select([qemu.stdout], [], [], 1)
                if ready:
                    chunk = os.read(qemu.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    said += chunk
                    log.write(chunk)
                    log.flush()
                    prompts = len(PROMPT.findall(said))
                    if prompts and self.prompted_after is None:
                        self.prompted_after = time.monotonic() - started
                    elapsed = time.monotonic() - started
                    text = said.decode(errors="replace") if watch or callable(recovery) else ""   # what boot() returns
                    if watch and watch(text, elapsed):
                        self.watched.append(elapsed)
                    typed = recovery and prompts > answered and (recovery is True or recovery(text, elapsed))
                    if typed:
                        answered = prompts
                        time.sleep(1)
                        qemu.stdin.write((typed if isinstance(typed, bytes) else tub.RECOVERY) + b"\n")
                        qemu.stdin.flush()
                elif qemu.poll() is not None:
                    break
                if time.monotonic() > deadline:
                    qemu.kill()
                    said += b"\n[the test's time limit of %d s was reached: the guest was killed]\n" % timeout
                    break
        qemu.wait(30)
        tpm.terminate()
        tpm.wait(30)
        if os.path.exists(tpm_log):
            shutil.copyfile(tpm_log, "%s/swtpm-%s.log" % (BOOT, label))      # e2e/unlock-boot-qemu.sh keeps it on a failure
        text = said.decode(errors="replace")
        fault = host_tpm_fault(text)
        if fault:
            # a distinct outcome, never retried in silence: the boots share one TPM and one disk, so a boot run again
            # is not the same boot; the shell runner counts these and says so (e2e/unlock-boot-qemu.sh)
            print("\nHOST TPM EMULATION FAULT (regalia-a0y) in boot %s: %s" % (label, fault), file=sys.stderr)
            self.fail("boot %s: HOST TPM EMULATION FAULT (regalia-a0y): the firmware could not measure (%s); the host's "
                      "QEMU/swtpm, not the product. The job runs on ubuntu-24.04 for this reason (.github/workflows/ci.yml)"
                      % (label, fault))
        print("\n----- boot %s (%s): %d lines of console; the lines that matter:" % (label, "KVM" if kvm else "TCG", text.count("\n")), file=sys.stderr)
        for line in text.splitlines():
            if re.search(r"REGALIA-E2E|regalia-unlock|wg-boot|Please enter|time limit|cryptsetup\[", line):
                print("    " + line.strip()[:300], file=sys.stderr)
        return text

    def enrolment_disk(self, local, wg_private, extra=None):
        """The second disk of the enrolment boot: what the running guest seals to its own TPM (and `extra`, {name:
        bytes}, what e2e/lib/boot-guest/e2e-enrol acts on when it is there: esp-partuuid, chrony.conf)."""
        image, mnt = self.d + "/enrol.img", self.d + "/enrol"
        with open(image, "wb") as f:
            f.truncate(16 * 1024 * 1024)
        os.mkdir(mnt)
        self.addCleanup(lambda: run(["umount", mnt], capture_output=True))     # if a failure leaves it mounted
        for argv in (["mkfs.ext4", "-q", image], ["mount", "-o", "loop", image, mnt]):
            self.assertEqual(run(argv, capture_output=True).returncode, 0, argv)
        with open(BOOT + "/initrd.pub", "rb") as f:
            initrd_public = f.read()
        for name, content in (("local.bin", local), ("wg-boot.key", wg_private.encode() + b"\n"), ("initrd.pub", initrd_public),
                              *sorted((extra or {}).items())):
            with open(os.open("%s/%s" % (mnt, name), os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
                f.write(content)
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        return image, mnt

    def test_a_host_boots_through_a_peer_and_with_no_peer_it_asks_for_the_recovery_key(self):
        # boot 1, ENROLMENT: nothing is enrolled and no credential is given. The client has no configuration and
        # gives nothing, the console asks, the recovery key opens the volume (PoC 6.5: the manual path needs no
        # peer and no credential), and the running guest seals the two boot credentials to its own TPM and
        # reports the PCRs this image boots with.
        local = os.urandom(32)
        image, mnt = self.enrolment_disk(local, self.keys["a", "boot"][0])
        said = self.boot("1-enrolment", enrol_disk=image, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        for unit, diagnostic in (
            ("boot-render", "no site credential: expected pre-genesis skip"),
            ("wg-boot", "regalia-wg-boot: expected pre-genesis skip"),
            ("unlock", "regalia-unlock: expected pre-genesis skip"),
        ):
            with self.subTest(pre_genesis_unit=unit):
                journal = initrd_unit(self, said, unit)
                self.assertIn(diagnostic, journal, f"{unit} did not skip before credential setup")
                self.assertNotRegex(journal, r"Failed (?:with result|to start|to set up credentials)|243/CREDENTIALS")
        print("boot 1: the console asked %.0f s after the guest started" % self.prompted_after, file=sys.stderr)
        self.assertLess(self.prompted_after, 120)
        self.assertIn("REGALIA-E2E-ENROLLED", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        self.assertRegex(said, r"REGALIA-E2E-ESP mount=ok type=vfat kernel=\S+ modules-tree=absent",
                         "ESP_MOUNT_AFTER_SWITCH_ROOT: the UKI initrd must preload the ESP filesystem")
        self.assertEqual(run(["mount", "-o", "loop,ro", image, mnt], capture_output=True).returncode, 0)
        def text(name):
            with open("%s/%s" % (mnt, name)) as f:
                return "".join(f.read().split())
        sealed = {name: text(name) for name in ("unlock-local.cred", "wg-boot.cred")}
        pcrs = {str(i): text("pcr%d" % i).lower() for i in (7, 11, 12)}
        self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        # sealed to PCR 7 and to the image's signed PCR 11 policy: systemd's key type for the TPM with a public key
        self.assertEqual(unlock.local_key_type(sealed["unlock-local.cred"]), "tpm2-with-public-key")
        print("the guest's PCRs once booted: 7=%s 11=%s 12=%s" % (pcrs["7"], pcrs["11"], pcrs["12"]), file=sys.stderr)
        # MEASURED BOOT: the stub and systemd measured what the build record says, and an empty ESP left PCR 12 alone
        with open(BOOT + "/e2e.record.json") as f:
            record = json.load(f)
        # the image's own command line (signed, in PCR 11) stops systemd importing any credential, from any source
        with open(BOOT + "/e2e.efi", "rb") as f:
            cmdline = dict(uki.sections(f.read()))[".cmdline"].decode()
        self.assertIn("systemd.import_credentials=no", cmdline.split())
        self.assertEqual(pcrs["11"], record["pcr11"]["system"])
        self.assertEqual(pcrs["12"], espcreds.ZERO)

        # the peers take the guest's PCR 7, the image's PCR 11 per phase and the PCR 12 of the host's credentials
        # as reference, and each gives a path its half
        firmware = self.reference["tpm_firmware_version"]          # (the reference is replaced below; its firmware stays)

        with open(BOOT + "/e2e-old.record.json") as f:
            older = json.load(f)                                    # the second signed image of the same build (#135)
        self.assertNotEqual(older["pcr11"], record["pcr11"])

        def reference(pcr12, images=(("e2e", record),)):
            # an accepted set per image, as measurements.bind() gives it: PCR 7 and 12 in every phase, PCR 11 per phase
            return {"accepted": [{"label": label, "tpm_firmware_version": firmware,
                                  "pcrs": {"7": pcrs["7"], "12": pcr12}, "phases": {phase: {"11": built["pcr11"][phase]} for phase in attest.PHASES}}
                                 for label, built in images]}
        loop, self.disk = self.partition(6)          # regalia-root: install-host.sh's sixth partition (#61 K61V-4)
        for peer in ("b", "c"):
            enrolment = unlock.Enrolment("a")
            wrapped = unlock.contribute(self.contributions[peer], self.m1, peer, "a", enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(self.disk, "a", peer, epoch, local, sealed["unlock-local.cred"], secret, tub.RECOVERY, run)
        del local, secret
        self.assertTrue(unlock.judge_tokens(unlock.luks_meta(self.disk, run), "a", ["b", "c"])[0])
        run(["losetup", "-d", loop], capture_output=True)

        # what the host gives its initrd from now on, as system credentials (on a host: on the ESP, written
        # after each accepted manifest; the image itself is unchanged)
        cfg = self.site("a")
        device = "/dev/disk/by-partlabel/regalia-root"
        credentials = {
            "regalia.unlock-local": sealed["unlock-local.cred"].encode() + b"\n", "regalia.wg-boot-key": sealed["wg-boot.cred"].encode() + b"\n",
            # the one measured file of the host's own (#66 B3): its site; the rest the initrd renders from the chain
            "regalia.site": bootcreds.site_document(cfg, device)}

        expected = espcreds.record({name + ".cred": content for name, content in credentials.items()})

        self.enrol_membership()

        # Present invalid site data must reach render validation and block both
        # consumers. The independent console agent can still open the volume.
        bad_site = dict(credentials, **{"regalia.site": b"{"})
        self.reference = reference(espcreds.pcr12({n + ".cred": c for n, c in bad_site.items()}))
        said = self.boot("1a-bad-site", bad_site, recovery=True)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        self.assertNotIn("regalia-unlock: gave the key", said)
        journal = initrd_unit(self, said, "boot-render")
        self.assertIn("regalia.site", journal)
        self.assertIn("Failed with result 'exit-code'", journal)
        self.assertNotIn("expected pre-genesis skip", journal)
        for unit in ("wg-boot", "unlock"):
            journal = initrd_unit(self, said, unit)
            self.assertNotRegex(journal, r"(?m)^(Starting|Started|Finished) |expected pre-genesis skip|243/CREDENTIALS")

        # boot 1b, A SEALED CREDENTIAL THAT DOES NOT DECRYPT (another machine's, or damaged): the client cannot
        # start, and the console asks, promptly: it asks from the start whatever the client does (#66, #70)
        broken = dict(credentials, **{"regalia.unlock-local": b"bm90IGEgY3JlZGVudGlhbA==\n"})
        self.reference = reference(espcreds.pcr12({n + ".cred": c for n, c in broken.items()}))
        # Wait for the unit's failure on the console before answering. The prompt
        # can appear while the mesh is still coming up and credential setup is pending.
        def unlock_refused(console, _elapsed):
            # PID 1 may ellipsize the unit name to fit the serial console.
            return re.search(r"Failed to start [^\r\n]*regalia-unl", console) is not None

        said = self.boot("1b-undecryptable", broken, recovery=unlock_refused)
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        journal = initrd_unit(self, said, "unlock")
        self.assertIn("Failed with result 'exit-code'", journal)
        self.assertRegex(journal, r"243/CREDENTIALS|Failed to set up credentials")
        self.assertNotIn("expected pre-genesis skip", journal)
        print("boot 1b: the console asked %.0f s after the guest started" % self.prompted_after, file=sys.stderr)
        self.assertLess(self.prompted_after, 120)

        # boot 2, UNATTENDED: nobody types anything
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2-unattended", credentials)
        unattended(self, said)
        # #75 tier Q, Q1: the client says the initrd-phase PCR 11 before it quotes (#412), and it is the value the HOST
        # computed from the image's build record, never one the guest computes. Equality, not just a line: a phase that
        # did not run (systemd-pcrphase-initrd) would show the pre-phase value
        self.assertEqual(initrd_pcr11(said), record["pcr11"]["initrd"])
        gave = re.search(r"regalia-unlock: gave the key of %s for keyslot ([12]), through ([bc])" % re.escape(device), said)
        self.assertIsNotNone(gave, "the client did not give the key")
        slot, through = gave.group(1), gave.group(2)
        # #66 B3: the boot configuration was rendered in the initrd, from the chain on the ESP, verified against the TPM
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 1 (TPM high-water 1)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)      # the first layer, seen working
        allowed = [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:] if e["event"] == "unlock"]
        self.assertEqual(allowed, [("unlock", "a", "ALLOW")])
        # after switch-root the running system finds the session the peer recorded, in a directory only root writes
        left = re.search(r"REGALIA-E2E-SESSION dir=(\S+) id=([0-9a-f]{64}) through=(\S+) (\d+)", said)
        self.assertIsNotNone(left, "the booted guest did not report the boot session")
        self.assertEqual((left.group(1), left.group(3), left.group(4)), ("root:root:755", through, slot))
        self.assertEqual(hashlib.sha256(bytes.fromhex(left.group(2))).hexdigest(), self.recorded_session(through)[0])
        # the client did not outlive the initrd: it stood down when the volume opened, or systemd stopped it (Conflicts=)
        self.assertIn("REGALIA-E2E-CLIENT processes=0", said)
        # and the pages it used are zeroed when freed (#221): the words are signed into the image, and the
        # kernel says it enabled them (a kernel without the options would ignore the words)
        with open(BOOT + "/e2e.efi", "rb") as f:
            signed = dict(uki.sections(f.read()))[".cmdline"].decode().split()
        self.assertIn("init_on_free=1", signed)
        self.assertIn("init_on_alloc=1", signed)
        meminit = next((l for l in said.splitlines() if "REGALIA-E2E-MEMINIT" in l), "")
        print("boot 2: %s" % meminit.strip(), file=sys.stderr)
        self.assertRegex(meminit, r"heap alloc:on")
        self.assertRegex(meminit, r"heap free:on")
        # the client's own line (#412), not PID 1's "Stopped" status, which a `quiet` command line hides (#413)
        self.assertIn("regalia-unlock: /dev/mapper/root is open: standing down", said)
        # PCR 12 is what espcreds computes from the ESP's files, and nothing moved it after the initrd
        booted = booted_pcrs(said)
        self.assertIsNotNone(booted)
        self.assertEqual([v.lower() for v in booted.groups()], [pcrs["7"], record["pcr11"]["system"], expected["pcr12"]])
        print("PCR 12 with the host's six credentials: %s, as espcreds computes it" % expected["pcr12"], file=sys.stderr)

        # boot 2e, A FORKED CHAIN (#66 B3): another epoch 1, validly signed by the root the image trusts, in place of the
        # one the TPM recorded (a substituted ESP). The render verifies it against the TPM's anchor and refuses it:
        # nothing is rendered, no peer is asked, and the console's prompt takes the recovery key. PCR 12 is unchanged
        # (the chain is not measured): it is the anchor, not the peers, that refuses it.
        good = self.chain
        self.chain = [self.signed(dict(self.m1, policy_version="forked"))]
        since = len(self.events)
        said = self.boot("2e-forked-chain", credentials, recovery=True)
        self.chain = good
        self.assertRegex(said, r"regalia-unlock: the boot configuration cannot be rendered: CONFLICT")
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        self.assertEqual([e for e in self.events[since:] if e.get("event") == "unlock"], [])

        # boot 2c, AN OLDER SIGNED IMAGE, APPROVED (#135): the same build with one word more on its command line, so
        # another PCR 11, signed by the same keys. The peers' document lists both images; it boots unattended.
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-old", older)))
        since = len(self.events)
        said = self.boot("2c-older-approved", credentials, image="e2e-old")
        unattended(self, said)
        self.assertIsNotNone(re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said))
        self.assertIn("regalia.e2e-image=old", re.search(r"REGALIA-E2E-CMDLINE (.*)", said).group(1).split())
        shown = booted_pcrs(said)
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], older["pcr11"]["system"], expected["pcr12"]])
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])

        # boot 2k, #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS (the same kernel with bytes appended: it boots
        # identically, and only its measurement differs). Before it boots: its .linux is e2e's plus the bytes, and they
        # alone change its predicted PCR 11 (not only its command line). Not approved, both peers refuse it for PCR 11;
        # approved as NEXT beside CURRENT, it boots unattended; the client says the initrd-phase PCR 11 its OWN record predicts, and
        # it is booted on the system-phase one. Its signed command line has no journald forwarding (#413): the
        # client's lines reach the console through its unit alone (#412), as on a production console.
        with open(BOOT + "/e2e-k2.record.json") as f:
            other_kernel = json.load(f)
        with open(BOOT + "/e2e.efi", "rb") as f:
            first_parts = uki.measured(f.read())
        with open(BOOT + "/e2e-k2.efi", "rb") as f:
            k2_parts = uki.measured(f.read())
        # e2e-k2 differs from e2e in its kernel AND its command line (no journald forwarding), and PCR 11 measures both. So
        # that the kernel's change is what is under test (regalia-kms-d9 on #415): the appended bytes ARE in the measured
        # .linux section, and they alone change the prediction: with e2e's kernel put back, e2e-k2's PCR 11 is another
        self.assertEqual(k2_parts["linux"], first_parts["linux"] + b"R" * 4096, "the Q1 image's .linux is not e2e's kernel with the 4096 bytes")
        for phase, path in uki.PHASE_PATHS.items():
            self.assertEqual(uki.pcr11(k2_parts, path), other_kernel["pcr11"][phase])           # computed here as uki.py does
            self.assertNotEqual(uki.pcr11(dict(k2_parts, linux=first_parts["linux"]), path), other_kernel["pcr11"][phase],
                                "the kernel's bytes do not change the Q1 image's PCR 11 (%s)" % phase)
            self.assertNotEqual(other_kernel["pcr11"][phase], record["pcr11"][phase], "Q1's image predicts the first image's PCR 11 (%s)" % phase)
        self.assertNotIn("systemd.journald.forward_to_console=1", k2_parts["cmdline"].decode().split())

        # first NOT approved: the document lists the current image only. Both peers refuse it, naming PCR 11 (the
        # security half: a different kernel is refused until the root approves it; 2d refuses a RETIRED image)
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2k-other-kernel-unapproved", credentials, recovery=after_attempt(1), image="e2e-k2")
        print("boot 2k-unapproved: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:160])
                                                                 for e in self.events[since:]], file=sys.stderr)
        self.assertEqual(initrd_pcr11(said), other_kernel["pcr11"]["initrd"])
        self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
        self.assertRegex(said, PROMPT.pattern.decode())
        no_shell(self, said)
        events = self.events[since:]
        self.assertNotIn(("unlock", "ALLOW"), {(e["event"], e["outcome"]) for e in events})
        refused = {e["peer"]: e["reason"] for e in events if e["event"] == "unlock" and e["outcome"] == "DENY"}
        self.assertEqual(sorted(refused), ["b", "c"], events)
        for peer, reason in refused.items():
            self.assertIn("PCR 11 is %s, expected %s" % (other_kernel["pcr11"]["initrd"], record["pcr11"]["initrd"]), reason)
            self.assertNotRegex(reason, r"PCR (7|12) is")

        # then approved as NEXT beside CURRENT (a node's document holds at most two sets, attest.MAX_SETS: CURRENT and
        # NEXT; listing a third refuses every request before a nonce): it boots unattended
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-k2", other_kernel)))
        since = len(self.events)
        said = self.boot("2k-other-kernel", credentials, image="e2e-k2")
        # what the peers decided, said whatever happens (a refusal at hello names its reason only here)
        print("boot 2k: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:160])
                                                      for e in self.events[since:]], file=sys.stderr)
        unattended(self, said)                                      # the client's "gave the key" line, through its unit only
        self.assertEqual(initrd_pcr11(said), other_kernel["pcr11"]["initrd"])
        # the test's report lines go to /dev/console themselves (e2e/lib/boot-guest/e2e-report), with no forwarding (#413)
        reported = re.search(r"REGALIA-E2E-CMDLINE (.*)", said)
        self.assertIsNotNone(reported, "no REGALIA-E2E-CMDLINE on the console (the report writes to /dev/console, #413)")
        self.assertNotIn("systemd.journald.forward_to_console=1", reported.group(1).split())
        shown = booted_pcrs(said)
        self.assertIsNotNone(shown, "no REGALIA-E2E-PCRS on the console (#413)")
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], other_kernel["pcr11"]["system"], expected["pcr12"]])
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])

        # boot 2d, THE SAME IMAGE, RETIRED (#135): the document lists the current image only. The guest's TPM still
        # releases the local half, as it does for every image the PCR-signing key signed (a signed policy has no
        # counter): the client starts, which it cannot without that half (boot 1b), and asks both peers. Both refuse
        # the quote, each naming PCR 11 and nothing else; nothing is given. The client keeps asking, at backoff's
        # cadence; the console asked from the start, and the recovery key typed there (once both refused) opens.
        # A refusal never ends in a shell (rd.shell=0, rd.emergency=reboot).
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("2d-older-retired", credentials, recovery=after_attempt(1), image="e2e-old")
        self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
        self.assertRegex(said, PROMPT.pattern.decode())
        self.assertLess(self.prompted_after, 120)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        shown = booted_pcrs(said)
        self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], older["pcr11"]["system"], expected["pcr12"]])
        events = self.events[since:]
        self.assertNotIn(("unlock", "ALLOW"), {(e["event"], e["outcome"]) for e in events})
        refused = {e["peer"]: e["reason"] for e in events if e["event"] == "unlock" and e["outcome"] == "DENY"}
        self.assertEqual(sorted(refused), ["b", "c"], events)
        for peer, reason in refused.items():
            self.assertIn("PCR 11 is %s, expected %s" % (older["pcr11"]["initrd"], record["pcr11"]["initrd"]), reason)
            self.assertNotRegex(reason, r"PCR (7|12) is")
            print("boot 2d: %s refused the retired image: %s" % (peer, reason), file=sys.stderr)

        # boot 2b, CREDENTIALS FROM SMBIOS (which the firmware owns, and nothing the peers attest measures): an extra
        # unit that would print a marker on the console, and a drop-in that makes the initrd want it. systemd imports
        # no credential (it says so in the journal, reported once booted), so neither is acted on, and the unlock
        # goes on as in boot 2 (PCR 12 does not see SMBIOS: this boot is NOT refused by the peers). It is also the
        # current image's first boot after 2d retired the older one: retiring an image strands nothing (#135).
        planted = {"systemd.extra-unit.regalia-planted.service":
                   b"[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'echo \"<2>REGALIA-E2E-PLANTED-RAN\" > /dev/kmsg'\n",
                   "systemd.unit-dropin.initrd.target": b"[Unit]\nWants=regalia-planted.service\n"}
        said = self.boot("2b-smbios", credentials, smbios=planted)
        self.assertNotIn("REGALIA-E2E-PLANTED-RAN", said)
        self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)
        self.assertIsNotNone(re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said))
        unattended(self, said)
        if "skipping importing of credentials" in said:
            print("boot 2b: systemd said it imports no credential", file=sys.stderr)

        # boots 3-5, A PLANTED CREDENTIAL: each adds one file to the ESP under a name systemd in the initrd acts on
        # (these are plain, so systemd ignores them as undecryptable; what matters here is that ANY extra file
        # changes PCR 12). PCR 7 and 11 are unchanged, PCR 12 is what espcreds computes for the seven files, every
        # peer refuses the quote, nothing is given, the console asks.
        planted = {"systemd.unit-dropin.regalia-unlock.service": b"[Service]\nEnvironment=PLANTED=1\n",
                   "systemd.extra-unit.regalia-planted.service": b"[Service]\nExecStart=/bin/true\n",
                   "tmpfiles.extra": b"f /run/regalia-planted - - - - planted\n",
                   # an EMPTY file: the stub packs it (systemd 257 skips no zero-length file), so PCR 12 moves too
                   "regalia.empty": b""}
        for n, (name, content) in enumerate(sorted(planted.items()), 3):
            with self.subTest(planted=name):
                since = len(self.events)
                said = self.boot("%d-planted" % n, dict(credentials, **{name: content}), recovery=after_attempt(1))
                self.assertRegex(said, r"regalia-unlock: attempt 1: .*; asking again in ")
                shown = booted_pcrs(said)
                self.assertIsNotNone(shown)
                self.assertEqual([v.lower() for v in shown.groups()], [pcrs["7"], record["pcr11"]["system"], espcreds.pcr12(self.on_esp)])
                self.assertNotEqual(shown.group(3).lower(), expected["pcr12"])
                self.assertRegex(said, PROMPT.pattern.decode())
                outcomes = {(e["event"], e["outcome"]) for e in self.events[since:]}
                self.assertNotIn(("unlock", "ALLOW"), outcomes)
                refusals = [e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"]
                self.assertTrue(refusals and all("PCR" in r for r in refusals), refusals)
                print("planted %s: refused (%s)" % (name, refusals[0]), file=sys.stderr)

        # boot 7, A COMMAND LINE FROM SMBIOS: systemd-stub reads io.systemd.stub.kernel-cmdline-extra from SMBIOS type 11
        # and, where it honours it, appends it to the command line and measures it into PCR 12. Here it would switch
        # credential import back on, with an extra unit passed beside it. Either the stub ignores it (the command line
        # and PCR 12 are unchanged, systemd still imports nothing, and the unlock goes on), or it is appended (PCR 12
        # moves and every peer refuses). In neither case does anything planted run: even with import switched back on,
        # the second layer (no debug generator, every credential import reset, #219) keeps the extra unit from being
        # made, so import=yes is not harmless by itself, the two layers are. The local half alone opens nothing (it is
        # sealed to PCR 7 and the signed PCR 11, which this does not change).
        since = len(self.events)
        extra_unit = {"systemd.extra-unit.regalia-planted.service":
                      b"[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh -c 'echo \"<2>REGALIA-E2E-PLANTED-RAN\" > /dev/kmsg'\n",
                      "systemd.unit-dropin.initrd.target": b"[Unit]\nWants=regalia-planted.service\n"}
        said = self.boot("7-cmdline-extra", credentials, recovery=after_attempt(1), smbios=extra_unit,
                         smbios_strings=["io.systemd.stub.kernel-cmdline-extra=systemd.import_credentials=yes"])
        self.assertNotIn("REGALIA-E2E-PLANTED-RAN", said)
        cmdline = re.search(r"REGALIA-E2E-CMDLINE (.*)", said).group(1)
        shown = booted_pcrs(said).groups()
        allowed = ("unlock", "ALLOW") in {(e["event"], e["outcome"]) for e in self.events[since:]}
        if "systemd.import_credentials=yes" in cmdline.split():
            self.assertNotEqual(shown[2].lower(), expected["pcr12"])             # appended: measured, and refused
            self.assertFalse(allowed)
            self.assertRegex(said, PROMPT.pattern.decode())
            print("boot 7: the stub appended the SMBIOS command line; PCR 12 moved and the peers refused", file=sys.stderr)
        else:
            self.assertEqual(shown[2].lower(), expected["pcr12"])                # ignored: nothing changed, and still no import
            self.assertIn("REGALIA-E2E-IMPORT credentials-imported=no", said)
            self.assertTrue(allowed)                                             # nothing changed: the unlock goes on
            print("boot 7: the stub ignored the SMBIOS command line; the unlock went on (%s)" % ("allowed" if allowed else "refused"),
                  file=sys.stderr)

        # boot 8, NO PEER, FOR LONGER THAN ANY DEFAULT TIMEOUT (#70): the client keeps asking, at the backoff's schedule
        # and past its cap (attempt 6), and the console, which asked from the start, still takes the recovery key after
        # 150 s: neither systemd-cryptsetup (timeout=0) nor /var's device wait (systemd.mount-extra=...x-systemd.device-timeout=0, #61;
        # 90 s by default) gave up meanwhile. A WRONG key typed first only brings the prompt back (tries=0): no
        # emergency, no reboot. Nothing ends in a shell. Under TCG the long boots 8 and 9 would outlast the job, so they
        # need KVM; with REGALIA_EXPECT_KVM=1 (CI) its absence FAILS. The skip RETURNS: boots 8 and 9 stay the last ones,
        # and a boot added after them goes before this line, or it would be skipped with them.
        kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
        if not kvm:
            self.assertNotEqual(os.environ.get("REGALIA_EXPECT_KVM"), "1", "REGALIA_EXPECT_KVM=1 and no usable /dev/kvm: boots 8 and 9 cannot run")
            print("boots 8 and 9 SKIPPED: they wait 150 s each, which needs KVM", file=sys.stderr)
            return
        for peer in ("b", "c"):
            self.ip("ip", "link", "set", "eth0", "down", ns=self.peer_ns[peer])
        since = len(self.events)
        attempts, mistyped = {}, []           # attempt -> (seconds since start when its line arrived, the pause it announced)
        def seen(said, elapsed):
            for m in re.finditer(r"regalia-unlock: attempt (\d+): .*; asking again in (?:(\d+)m)?(\d+)s\b", said):
                attempts.setdefault(int(m.group(1)), (elapsed, int(m.group(2) or 0) * 60 + int(m.group(3))))
            return False
        def wrong_then_right(said, elapsed):
            if elapsed <= 150 or "regalia-unlock: attempt 6: " not in said:
                return False
            if not mistyped:
                mistyped.append(len(said))
                return b"not-the-recovery-key"
            return True
        said = self.boot("8-no-peer", credentials, recovery=wrong_then_right, watch=seen, timeout=1200)
        self.assertEqual(len(mistyped), 1, "the wrong key was never typed")
        self.assertRegex(said[mistyped[0]:], PROMPT.pattern.decode(), "the prompt did not come back after a wrong key")
        self.assertLess(self.prompted_after, 120)
        print("boot 8: attempts (arrived at, announced pause): %s" % sorted(attempts.items()), file=sys.stderr)
        self.assertTrue(all(n in attempts for n in range(1, 7)), sorted(attempts))
        for n in range(1, 7):
            arrived, pause = attempts[n]
            nominal = min(2 * 2 ** (n - 1), 60)                  # 2 s doubling, capped at 60 s, then x[0.8, 1.2)
            self.assertTrue(0.8 * nominal - 1 <= pause <= 1.2 * nominal + 1, "attempt %d announced %d s, nominal %d s" % (n, pause, nominal))
            if n + 1 in attempts:                                # and it did pause that long: no hot loop
                self.assertGreaterEqual(attempts[n + 1][0] - arrived, pause - 2, "attempt %d came early" % (n + 1))
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        # Here the recovery key opened root while the client sat in its backoff, and systemd stopped it at switch-root
        # between two of its looks: the stop handler says the client's own line on the way out (#572), as the loop does
        # when it sees root open itself. The test report's count, written to /dev/console whatever the command line,
        # proves independently that no client survived into the system.
        self.assertIn("regalia-unlock: /dev/mapper/root is open: standing down", said)
        self.assertIn("REGALIA-E2E-CLIENT processes=0", said)
        no_shell(self, said)
        self.assertEqual(self.events[since:], [])

        # boot 9, THE PEERS COME BACK (#70, the blackout): nobody types anything; the peers are unreachable until the
        # client is past the backoff's cap and 150 s have passed, then they return, and the host unlocks by itself
        def back(said, elapsed):
            if self.watched or elapsed <= 150 or "regalia-unlock: attempt 6: " not in said:
                return False
            for peer in ("b", "c"):            # the link back, and its route: setting eth0 down deleted the default route
                self.ip("ip", "link", "set", "eth0", "up", ns=self.peer_ns[peer])
                self.ip("ip", "route", "replace", "default", "dev", "eth0", ns=self.peer_ns[peer])
            return True
        since = len(self.events)
        said = self.boot("9-peers-return", credentials, watch=back, timeout=1200)
        self.assertEqual(len(self.watched), 1, "the peers were never brought back")
        print("boot 9: the peers came back %.0f s after the guest started" % self.watched[0], file=sys.stderr)
        gave = re.search(r"regalia-unlock: gave the key of %s for keyslot [12], through [bc]" % re.escape(device), said)
        self.assertIsNotNone(gave, "the client did not give the key once the peers came back")
        self.assertIn("regalia-unlock: attempt 6: ", said[:gave.start()])
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes wg-boot=absent table=absent addresses=0 link=down", said)
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])
        no_shell(self, said)

        # boots 10-12, A NEW MANIFEST (#66 B3, the ESP advance): regalia-sync never moves the TPM anchor;
        # regalia-esp-advance writes the chain to the ESP, THEN anchors it. These boots come last: they leave the
        # guest's anchor at epoch 2. The peers still hold epoch 1, so the unlock itself is not what is shown here
        # (the recovery key is typed if asked): only what the initrd renders from, or refuses.
        m2 = dict(self.m1, epoch=2, prev_digest=membership.digest(self.m1), issued_at="2026-10-04T00:00:00Z")
        two = [self.chain[0], self.signed(m2)]
        # boot 10, THE ESP AHEAD OF THE ANCHOR: the ESP written and the anchor not yet (a crash between the two
        # steps, or a reboot before the service ran): accepted, and rendered under the new epoch
        self.chain = two
        said = self.boot("10-esp-ahead", credentials, recovery=True)
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 2 (TPM high-water 1)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        # boot 11, BOTH ADVANCED: the anchor moved to the chain the ESP holds, as regalia-esp-advance leaves a host
        self.anchor_guest(two)
        said = self.boot("11-advanced", credentials, recovery=True)
        self.assertIn("regalia-unlock: rendered the boot configuration of a under manifest epoch 2 (TPM high-water 2)", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        # boot 12, THE ORDER REVERSED: an ESP left at epoch 1 under an anchor at 2 (what a sync that anchored first
        # would leave after a crash) is a ROLLBACK to the initrd: nothing rendered, no peer asked, the recovery key
        self.chain = two[:1]
        since = len(self.events)
        said = self.boot("12-esp-behind", credentials, recovery=True)
        self.assertRegex(said, r"regalia-unlock: the boot configuration cannot be rendered: ROLLBACK")
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        no_shell(self, said)
        self.assertEqual([e for e in self.events[since:] if e.get("event") == "unlock"], [])

    def enrol_membership(self):
        """Initialise the guest's anchor after the recovery boot; the next boot writes the matching ESP chain."""
        chain = [self.signed(self.m1)]
        self.anchor_guest(chain, initial=True)
        self.chain = chain

    def anchor_guest(self, envelopes, initial=False):
        """The guest's TPM anchor moved to the tip of `envelopes` while the guest is off (what regalia-esp-advance
        does on a running host, after the ESP holds the chain: node.esp_advance)."""
        sock = self.d + "/a-off.sock"
        tpm_log = self.d + "/swtpm-anchor.log"
        tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-a" % self.d, "--server", "type=unixio,path=" + sock,
                                "--ctrl", "type=unixio,path=%s.ctrl" % sock, "--flags", "not-need-init,startup-clear",
                                "--log", tpmdiag.log_arg(tpm_log)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if os.path.exists(sock):
                    break
                time.sleep(0.1)
            tcti = "swtpm:path=" + sock
            membership.accept_chain(None, envelopes, self.signed({})["signature"]["key"])
            manifests = [e["manifest"] for e in envelopes]
            anchor = membership.HighWater("0x1500016", tcti=tcti, lock_path=self.d + "/a-hw.lock")
            if initial:
                anchor.define()
            anchor.anchor(len(manifests), membership.Store._digests(manifests))
            anchor.check(len(manifests))
            run(["tpm2_shutdown", "-c", "-T", tcti], capture_output=True, check=True)
        finally:
            tpm.terminate()
            tpm.wait(30)
            if os.path.exists(tpm_log):
                shutil.copyfile(tpm_log, BOOT + "/swtpm-anchor.log")   # self.d is removed after the test; the script keeps BOOT's


@unittest.skipUnless(os.environ.get("REGALIA_EXPECT_QEMU") == "1", "needs a guest built by e2e/unlock-boot-qemu.sh (REGALIA_BOOT_CASES=verity)")
class OnQemuVerity(OnQemu):
    """THE VERITY /usr BOOTS (#61 K61V-4): the REAL image's /usr (build-rootfs.sh's rootfs.tar, with the test's two units
    only), as an erofs image under dm-verity, on a disk install-host.sh laid out (its test mode).
    Every boot proves what it booted: /usr is /dev/mapper/usr (verified, the root hash its UKI names), / a tmpfs, /var
    the LUKS2 volume mounted by the initrd, the firmware entry the installer's. Then: a wrong usrhash, a tampered block,
    the A/B slots and the fallback, and a broken factory /etc, each beside a boot that passes."""
    test_a_host_boots_through_a_peer_and_with_no_peer_it_asks_for_the_recovery_key = None
    LABEL = "regalia e2e"            # the entry e2e-enrol makes through bootnext, as install-host.sh's step 7 would
    # node_exporter's EnvironmentFile, a link to /var that enrolment writes (00-regalia-etc.conf): without it the unit
    # fails to start (Result=resources, measured on an unenrolled guest). The test's stand-in listens on loopback only
    NODE_EXPORTER = b"# the test's (MONITORING.md: metrics node-exporter-args renders a host's)\nARGS=\"--web.listen-address=127.0.0.1:9100\"\n"
    CHRONY = b"# the test's: two NTS servers no guest reaches (chronyd runs, and synchronises with nothing)\nserver 198.18.3.2 iburst nts\nserver 198.18.3.3 iburst nts\n"
    # THE PER-HOST FILES (regalia-kms-r1s.8), each at its /var name (e2e-enrol writes them as an operator does): what the
    # image's gates read. The node units' gate, node.json, is NOT written: the guest is no member of a membership, so
    # those units must stay skipped, which is their gate's other half shown
    RULESET_VAR = "lib/regalia-etc/nftables.d/regalia-kms.nft"           # under /var
    AUDIT_ENV_VAR = "lib/regalia-etc/regalia/audit-ship.env"
    NODE_UNITS = ("regalia-authtime.service", "regalia-site-check.service", "regalia-wg-apply.service", "regalia-wg-apply.path",
                  "regalia-boot-session.service", "regalia-admission.service", "regalia-sync.service", "regalia-etcd.service",
                  "regalia-esp-advance.service", "regalia-esp-advance.path")
    KMS_DROPINS = ("/usr/lib/systemd/system/regalia-kms.service.d/apparmor.conf", "/usr/lib/systemd/system/regalia-kms.service.d/firewall.conf",
                   "/usr/lib/systemd/system/regalia-kms.service.d/hardening.conf", "/usr/lib/systemd/system/regalia-kms.service.d/memlock.conf",
                   "/run/systemd/generator/regalia-kms.service.d/50-regalia-credentials.conf")

    def per_host_files(self):
        """The enrolment disk's per-host files (regalia-kms-r1s.8): this guest's firewall, rendered by firewall.py from its
        site configuration; an audit collector configuration the shippers' own check accepts (a TEST CA and client
        certificate made here, valid from a day ago, a receipt key), for a collector no guest reaches; a TEST PIN, which
        the guest seals as seal-hsm-pin.sh does."""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        now = datetime.datetime.now(datetime.timezone.utc)
        def certificate(subject, key, issuer, signer, ca):
            builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
                       .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                       .not_valid_after(now + datetime.timedelta(days=30))
                       .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
            return builder.sign(signer, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
        ca_key, client_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
        receipt = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"regalia-kms.nft": firewall.render(self.site("a")).encode(),
                "audit-ship.env": b"COLLECTOR=https://198.18.3.1:6514\nSITE=site-a\n",
                "audit-ship-client.crt": certificate("node a (e2e)", client_key, "e2e collector CA", ca_key, False),
                "audit-ship-client.key": client_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                  serialization.NoEncryption()),
                "audit-ship-collector-ca.pem": certificate("e2e collector CA", ca_key, "e2e collector CA", ca_key, True),
                "audit-ship-collector-receipt.pub": receipt.hex().encode() + b"\n",
                "kms-e2e.pin": b"e2e-test-pin-not-a-secret"}

    def var_rename(self, pairs):
        """Renames files on the guest's /var (the LUKS2 volume, partition 6) while it is off: [(old, new)], each under
        /var. Opened with the recovery key (keyslot 0, as the console takes it), closed again."""
        loop, part = self.partition(6)
        name, mnt = "regalia-e2e-var", self.d + "/var"
        os.makedirs(mnt, exist_ok=True)
        opened = run(["cryptsetup", "open", "--key-slot", "0", "--key-file", "-", part, name], input=tub.RECOVERY, capture_output=True)
        try:
            self.assertEqual(opened.returncode, 0, opened.stderr)
            mounted = run(["mount", "/dev/mapper/" + name, mnt], capture_output=True)
            self.assertEqual(mounted.returncode, 0, mounted.stderr)
            try:
                for old, new in pairs:
                    os.rename(os.path.join(mnt, old), os.path.join(mnt, new))
            finally:
                self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        finally:
            run(["cryptsetup", "close", name], capture_output=True)
            run(["losetup", "-d", loop], capture_output=True)

    def per_host_started(self, said):
        """The per-host units (regalia-kms-r1s.8), with this host's files on /var: enabled by the image under /usr, gated on
        them, started at this boot with nothing under /etc/systemd/system (proven(): etc-links=0). The firewall loaded
        (firewall.py's table, input on drop) and the KMS behind it, its PIN credential named by the image's generator;
        every trail's shipper started and its prune timer armed. The node units stay skipped: no node.json."""
        units = unit_states(said)
        nft = units.get("nftables.service")
        self.assertIsNotNone(nft, "no line for nftables.service")
        self.assertEqual((nft["condition"], nft["active"], nft["result"]), ("yes", "active", "success"), nft)
        self.assertEqual(firewall_state(said), {"table": "loaded", "input-policy": "drop", "ruleset-file": "present"})
        self.assertEqual(units["regalia-kms.service"]["assert"], "yes", units["regalia-kms.service"])
        merged = kms_unit(said)
        self.assertIsNotNone(merged, "no REGALIA-E2E-KMSUNIT line")
        for path in self.KMS_DROPINS:
            self.assertIn(path, merged["dropins"], "regalia-kms.service runs without %s" % path)
        self.assertFalse([p for p in merged["dropins"] if p.startswith("/etc/")], merged["dropins"])
        for trail in trails.TRAILS:
            ship, prune = units.get("regalia-audit-ship@%s.service" % trail), units.get("regalia-audit-prune@%s.timer" % trail)
            self.assertIsNotNone(ship, "no line for regalia-audit-ship@%s: the image does not enable it" % trail)
            self.assertEqual(ship["condition"], "yes", (trail, ship))
            self.assertGreater(ship["started"], 0, "regalia-audit-ship@%s never started (its check refused the configuration?) %r" % (trail, ship))
            self.assertIsNotNone(prune, "no line for regalia-audit-prune@%s.timer: the image does not enable it" % trail)
            self.assertEqual((prune["condition"], prune["active"]), ("yes", "active"), (trail, prune))
        for unit in self.NODE_UNITS:
            self.assertIn(unit, units, "no line for %s: the image does not enable it" % unit)
            self.assertEqual((units[unit]["condition"], units[unit]["started"]), ("no", 0), (unit, units[unit]))
        print("boot proof: per host: nftables %s, table %s, %d shippers started, KMS drop-ins %s" % (
            nft["active"], firewall_state(said)["table"], sum(units["regalia-audit-ship@%s.service" % t]["started"] > 0 for t in trails.TRAILS),
            ",".join(p.rsplit("/", 1)[1] for p in merged["dropins"])), file=sys.stderr)

    def setUp(self):
        for name in ("e2e-b.efi", "e2e-c.efi", "e2e-badhash.efi", "usr-a.json", "usr-b.json", "usr-c.json"):
            self.assertTrue(os.path.exists("%s/%s" % (BOOT, name)), "REGALIA_BOOT_DIR has no %s: built without REGALIA_BOOT_CASES=verity" % name)
        super().setUp()
        self.usr = {}
        for slot in "abc":
            with open("%s/usr-%s.json" % (BOOT, slot)) as f:
                self.usr[slot] = json.load(f)["usr"]
        installs = [n for n in os.listdir(BOOT + "/install") if n.startswith("install-") and n.endswith(".json")]
        self.assertEqual(len(installs), 1, installs)
        with open(BOOT + "/install/" + installs[0]) as f:
            self.installed = json.load(f)
        self.assertEqual((self.installed["layout"], self.installed["usr"]["roothash"]), ("verity-ab", self.usr["a"]["roothash"]))
        self.machine_id = None

    def proven(self, said, slot, entry=True):
        """What every boot that reached the system shows (the proof): /usr from dm-verity, verified, under the root hash
        of `slot`'s image; / a tmpfs; /var the LUKS2 mapping, mounted in the initrd; the firmware entry the installer's
        (`entry`); nothing enabled under /etc; one machine ID, kept on /var, boot after boot."""
        self.assertRegex(said, r"REGALIA-E2E-ESP mount=ok type=vfat kernel=\S+ modules-tree=absent",
                         "ESP_MOUNT_AFTER_SWITCH_ROOT: the shipped module-free /usr must mount and write the ESP")
        self.assertIn("REGALIA-E2E-BINFMT mount=ok", said, "BINFMT_MOUNT_AFTER_SWITCH_ROOT (r1s.18)")
        proof = verity_proof(said)
        self.assertIsNotNone(proof, "no REGALIA-E2E-VERITY line: the report did not run")
        # / is the tmpfs root=tmpfs makes (findmnt names its source "rootfs")
        self.assertTrue(proof["root"].endswith(":tmpfs"), proof)
        self.assertEqual(dict(proof, root=None), {"usr": "/dev/mapper/usr:erofs", "root": None, "var": "/dev/mapper/root:ext4",
                                                  "status": "verified", "roothash": self.usr[slot]["roothash"]})
        self.assertIn("usrhash=" + self.usr[slot]["roothash"], re.search(r"REGALIA-E2E-CMDLINE (.*)", said).group(1).split())
        self.assertRegex(said, r"REGALIA-E2E-VARMOUNT initrd=Mounted sysroot-var\.mount")
        current, label = boot_entry(said)
        if entry:
            self.assertEqual(label, self.LABEL, "BootCurrent %s is not the installer's entry" % current)
        seen = machine(said)
        self.assertIsNotNone(seen)
        self.assertEqual(seen["etc-links"], "0", "something was enabled under /etc (a first boot's preset pass?)")
        self.assertRegex(seen["id"], r"^[0-9a-f]{32}$")
        self.assertEqual(seen["id"], seen["kept"], "the machine ID is not the one kept on /var")
        if self.machine_id:
            self.assertEqual(seen["id"], self.machine_id, "the machine ID changed between boots")
        self.machine_id = seen["id"]
        print("boot proof: usrhash=%s /usr %s, / %s, /var %s, BootCurrent %s (%s), first-boot=%s" % (
            proof["roothash"][:16], proof["usr"], proof["root"], proof["var"], current, label, seen["first-boot"]), file=sys.stderr)
        # every boot is a first boot (/etc starts empty): systemd-firstboot runs, and asks nothing (the factory /etc
        # has the locale, the time zone and the accounts), nor does the preset pass enable anything (etc-links above)
        self.assertNotRegex(said, r"Please enter (?:system locale|timezone|a new root password|system keymap|hostname)|Please choose your|Please configure your system")
        firstboot = unit_states(said).get("systemd-firstboot.service")
        print("boot proof: systemd-firstboot.service %s" % (firstboot,), file=sys.stderr)
        no_shell(self, said)
        return proof

    def started(self, said):
        """The image's own units, enabled under /usr, ran: the factory /etc, the system users, AppArmor with the KMS's
        profile, chronyd, node_exporter, and the KMS's main process (started is what is shown, not serving: the test
        gives it no configuration). Not `systemctl is-enabled`: it counts links under /etc and /run only, and says
        "disabled" for a unit the image wants from /usr (measured on the first local run); started is the proof."""
        units = unit_states(said)
        self.assertIn("REGALIA-E2E-FACTORY assert=yes", said)
        for unit in ("regalia-etc-factory.service", "systemd-sysusers.service", "apparmor.service"):
            self.assertEqual((units[unit]["active"], units[unit]["result"]), ("active", "success"), (unit, units[unit]))
        for unit in ("chrony.service", "prometheus-node-exporter.service"):
            self.assertEqual(units[unit]["active"], "active", (unit, units[unit]))
            self.assertGreater(units[unit]["started"], 0, (unit, units[unit]))
        self.assertGreater(units["regalia-kms.service"]["started"], 0, "regalia-kms.service's main process never started")
        self.per_host_started(said)
        self.assertRegex(said, r"REGALIA-E2E-APPARMOR enabled=Y regalia-kms=regalia-kms \(enforce\) etc-passwd=present")
        # chronyd confined by its profile in enforce mode while it reads /etc/chrony/regalia.conf through the link to /var
        self.assertRegex(said, r"REGALIA-E2E-CHRONYD confined=\S*chronyd\S* \(enforce\)")

    def write_slot_b(self, slot):
        """The updater's step, by hand: `slot`'s image into usr-b and usr-b-verity (partitions 4 and 5), their PARTUUIDs
        set to its root hash's halves, as the updater must (systemd-veritysetup-generator finds them by those)."""
        for number, name in ((4, "usr.erofs"), (5, "usr.verity")):
            loop, part = self.partition(number)
            done = run(["dd", "if=%s/usr-%s/%s" % (BOOT, slot, name), "of=" + part, "bs=4M", "conv=fsync", "status=none"], capture_output=True)
            run(["losetup", "-d", loop], capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)
        for number, key in ((4, "usr_partuuid"), (5, "usr_verity_partuuid")):
            done = run(["sfdisk", "--part-uuid", self.image, str(number), self.usr[slot][key]], capture_output=True)
            self.assertEqual(done.returncode, 0, done.stderr)

    def flip(self, number, offset):
        """One byte of partition `number` at `offset` inverted (run twice: put back)."""
        loop, part = self.partition(number)
        try:
            fd = os.open(part, os.O_RDWR)
            try:
                byte = os.pread(fd, 1, offset)
                os.pwrite(fd, bytes([byte[0] ^ 0xFF]), offset)
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            run(["losetup", "-d", loop], capture_output=True)
        return byte[0]

    def test_the_verity_usr_boots(self):
        # boot v1, ENROLMENT, as OnQemu's boot 1, on a host's NVRAM kept from here on: the recovery key typed, the
        # credentials sealed, and the installer's firmware entry made on the running guest (install-host.sh's step 7,
        # through bootnext; its test mode makes none). First an entry carrying LOAD OPTIONS: refused, and deleted again
        local = os.urandom(32)
        image, mnt = self.enrolment_disk(local, self.keys["a", "boot"][0],
                                         extra={"esp-partuuid": self.installed["partuuids"]["esp"].encode(), "chrony.conf": self.CHRONY,
                                                "node-exporter.default": self.NODE_EXPORTER, **self.per_host_files()})
        said = self.boot("v1-enrolment", enrol_disk=image, recovery=True, nvram="host")
        self.assertIn("REGALIA-E2E-ENROLLED", said)
        self.assertIn("REGALIA-E2E-ROOT-UP root=yes", said)
        self.proven(said, "a", entry=False)          # (the firmware's own removable-media entry: none was installed yet)
        self.assertEqual(run(["mount", "-o", "loop,ro", image, mnt], capture_output=True).returncode, 0)
        def text(name):
            with open("%s/%s" % (mnt, name)) as f:
                return f.read()
        try:
            sealed = {name: "".join(text(name).split()) for name in ("unlock-local.cred", "wg-boot.cred")}
            pcrs = {str(i): "".join(text("pcr%d" % i).split()).lower() for i in (7, 11, 12)}
            options = (text("entry-options.rc").strip(), text("entry-options.log"))
            made = (text("entry.rc").strip(), text("entry.log"), text("entries.txt"))
        finally:
            self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
        print("boot v1: the entry with options: rc %s: %s" % (options[0], options[1].strip()[:400]), file=sys.stderr)
        print("boot v1: the installer's entry: rc %s: %s\n%s" % (made[0], made[1].strip()[:300], made[2].strip()[:600]), file=sys.stderr)
        self.assertEqual(options[0], "3", options[1])
        self.assertRegex(options[1], r"REFUSED Refused: Boot[0-9A-F]{4} carries load options \(optional data\): an installed entry passes none; "
                                     r"Boot[0-9A-F]{4}, just created, was deleted again")
        self.assertNotIn("e2e-options", made[2])
        self.assertEqual(made[0], "0", made[1])
        self.assertIn(self.LABEL, made[2])
        with open(BOOT + "/e2e.record.json") as f:
            record = json.load(f)
        self.assertEqual(record["usr_roothash"], self.usr["a"]["roothash"])
        self.assertEqual(pcrs["11"], record["pcr11"]["system"])
        records = {}
        for name in ("e2e-b", "e2e-c", "e2e-badhash"):
            with open("%s/%s.record.json" % (BOOT, name)) as f:
                records[name] = json.load(f)
        firmware = self.reference["tpm_firmware_version"]

        def reference(pcr12, images=(("e2e", record),)):
            return {"accepted": [{"label": label, "tpm_firmware_version": firmware,
                                  "pcrs": {"7": pcrs["7"], "12": pcr12}, "phases": {phase: {"11": built["pcr11"][phase]} for phase in attest.PHASES}}
                                 for label, built in images]}
        loop, self.disk = self.partition(6)
        for peer in ("b", "c"):
            enrolment = unlock.Enrolment("a")
            wrapped = unlock.contribute(self.contributions[peer], self.m1, peer, "a", enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(self.disk, "a", peer, epoch, local, sealed["unlock-local.cred"], secret, tub.RECOVERY, run)
        del local, secret
        run(["losetup", "-d", loop], capture_output=True)
        device = "/dev/disk/by-partlabel/regalia-root"
        credentials = {"regalia.unlock-local": sealed["unlock-local.cred"].encode() + b"\n",
                       "regalia.wg-boot-key": sealed["wg-boot.cred"].encode() + b"\n",
                       "regalia.site": bootcreds.site_document(self.site("a"), device)}
        expected = espcreds.record({name + ".cred": content for name, content in credentials.items()})

        self.enrol_membership()

        # boot v2, THE CONTROL: unattended through a peer, from the installer's firmware entry; the proof, and the
        # image's units started from their enablement under /usr
        self.reference = reference(expected["pcr12"])
        since = len(self.events)
        said = self.boot("v2-control", credentials, nvram="host")
        unattended(self, said)
        self.proven(said, "a")
        self.started(said)
        self.assertIn(("unlock", "a", "ALLOW"), [(e["event"], e["subject"], e["outcome"]) for e in self.events[since:]])

        # boot v2m, THE PER-HOST FILES GONE (regalia-kms-r1s.8): this host's ruleset and its collector configuration moved
        # aside on /var. Each gate holds by name: nftables.service and every shipper and prune timer are SKIPPED (their
        # ConditionPathExists=), and the KMS, which a skipped nftables would not stop (Requires= counts a skip as
        # success), REFUSES: its AssertPathExists= on the ruleset fails, its main process never starts, and no firewall
        # table is in the kernel. Then the files go back, and v5's control starts all of it again
        aside = [(self.RULESET_VAR, self.RULESET_VAR + ".aside"), (self.AUDIT_ENV_VAR, self.AUDIT_ENV_VAR + ".aside")]
        self.var_rename(aside)
        said = self.boot("v2m-per-host-missing", credentials, nvram="host")
        unattended(self, said)
        self.proven(said, "a")
        units = unit_states(said)
        print("boot v2m: %s" % {u: (s["active"], s["condition"], s["assert"], s["started"]) for u, s in units.items()
                                if u.startswith(("nftables", "regalia-kms", "regalia-audit-ship@sync"))}, file=sys.stderr)
        self.assertEqual((units["apparmor.service"]["active"], units["apparmor.service"]["result"]), ("active", "success"))
        nft = units["nftables.service"]
        self.assertEqual(nft["condition"], "no", nft)
        self.assertEqual(nft["started"], 0, nft)
        self.assertNotEqual(nft["active"], "active", nft)
        self.assertEqual(firewall_state(said), {"table": "absent", "input-policy": "none", "ruleset-file": "absent"})
        kms = units["regalia-kms.service"]
        self.assertEqual(kms["assert"], "no", "regalia-kms.service did not refuse on the missing ruleset: %r" % kms)
        self.assertEqual(kms["started"], 0, "regalia-kms.service started with no firewall: %r" % kms)
        self.assertNotEqual(kms["active"], "active", kms)
        for trail in trails.TRAILS:
            ship, prune = units["regalia-audit-ship@%s.service" % trail], units["regalia-audit-prune@%s.timer" % trail]
            self.assertEqual((ship["condition"], ship["started"]), ("no", 0), (trail, ship))
            self.assertEqual(prune["condition"], "no", (trail, prune))
            self.assertNotEqual(prune["active"], "active", (trail, prune))
        self.var_rename([(new, old) for old, new in aside])

        # boot v3, A WRONG USRHASH: a UKI signed by the same keys whose command line names a root hash one digit off A's
        # (its PARTUUIDs derived from it). No partition carries them: the initrd waits for its /usr, gives up, and reboots
        # (rd.emergency=reboot; -no-reboot ends the guest). No /usr, no system. Its PCR 11 is its own, never approved: no
        # peer gives a key (the client still asks in the initrd, and is refused by PCR 11: no ALLOW)
        self.assertNotEqual(records["e2e-badhash"]["usr_roothash"], self.usr["a"]["roothash"])
        self.assertEqual(sum(x != y for x, y in zip(records["e2e-badhash"]["usr_roothash"], self.usr["a"]["roothash"])), 1)
        since = len(self.events)
        said = self.boot("v3-wrong-usrhash", credentials, image="e2e-badhash", nvram="host")
        print("boot v3: the peers' decisions: %s" % [(e.get("event"), e.get("peer"), e.get("outcome"), (e.get("reason") or "")[:120])
                                                     for e in self.events[since:]], file=sys.stderr)
        self.assertNotIn("REGALIA-E2E-ROOT-UP", said)
        self.assertNotIn("REGALIA-E2E-VERITY", said)
        self.assertNotIn("regalia-unlock: gave the key", said)
        self.assertNotIn("time limit", said, "the guest did not end by itself: it waited rather than failing closed")
        self.assertNotIn(("unlock", "ALLOW"), {(e["event"], e["outcome"]) for e in self.events[since:]})
        # ... and positive evidence that THIS UKI booted to its initrd (#722 review): a guest that never started would pass
        # every absence above. Its client asked, and a peer refused it on PCR 11, the badhash image's own and unapproved
        refused = [e for e in self.events[since:] if e.get("event") == "unlock" and e.get("outcome") == "DENY"]
        self.assertTrue(any("PCR" in (e.get("reason") or "") for e in refused),
                        "no peer refused the wrong-usrhash image's unlock on its PCRs: did its initrd run? %r" % self.events[since:])
        # ... and it failed BECAUSE of its /usr (#722 review): the partition its usrhash= names is not there, so the verity
        # device, then /usr, never came. An unrelated failure after the denial lacks these. MEASURED on the review's local
        # run: "Timed out waiting for device dev-disk-by\x2dpartuuid-<the changed half>.device", "Dependency failed for
        # systemd-veritysetup@usr.service", "Timed out waiting for device dev-mapper-usr.device", "Dependency failed for
        # sysroot-usr.mount"; then emergency.target, which rd.shell=0 and rd.emergency=reboot turn into a reboot
        self.assertEqual(usr_device_missing(said, records["e2e-badhash"]["usr_roothash"], self.usr["a"]["roothash"]), [],
                         "the wrong-usrhash boot did not fail on its missing /usr")
        no_shell(self, JOURNAL_LINE.sub("", said))
        self.assertRegex(said, r"Boot has failed\.[^\n]*\n+Rebooting\.", "the initrd did not reboot (rd.emergency=reboot)")

        # boot v4, A TAMPERED BLOCK: one byte of usr-a inverted at offset 1024 (the erofs superblock, read at mount). The
        # kernel's dm-verity finds the block corrupted and panics (panic-on-corruption): no /usr, no system
        before = self.flip(2, 1024)
        said = self.boot("v4-tampered", credentials, nvram="host")
        self.assertIn("device-mapper: verity", said)
        self.assertIn("is corrupted", said)
        self.assertIn("Kernel panic", said)
        self.assertNotIn("REGALIA-E2E-ROOT-UP", said)
        self.assertNotIn("time limit", said)
        self.assertEqual(self.flip(2, 1024), before ^ 0xFF)          # put back

        # boot v5, THE CONTROL after both: the same disk, put back, boots unattended
        said = self.boot("v5-control", credentials, nvram="host")
        unattended(self, said)
        self.proven(said, "a")
        self.started(said)

        # boot v6, A/B: image B (another root hash) written to usr-b, and its UKI (approved beside A's) to the ESP, as the
        # updater leaves a host. B's /usr boots; then A's UKI back on the ESP (the fallback): A's /usr, untouched in its
        # slot, boots again. Each time the root hash dm-verity holds is the one its UKI names
        self.write_slot_b("b")
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-b", records["e2e-b"])))
        said = self.boot("v6-slot-b", credentials, image="e2e-b", nvram="host")
        unattended(self, said)
        self.proven(said, "b")
        self.started(said)
        said = self.boot("v7-fallback-a", credentials, nvram="host")
        unattended(self, said)
        self.proven(said, "a")

        # boot v8, A BROKEN FACTORY /etc (#723's runtime case): image C, the image with /usr/share/factory/etc taken out,
        # in slot B. regalia-etc-factory.service's assert fails; systemd-sysusers and apparmor.service require it and do
        # not run; regalia-kms.service requires apparmor.service and never starts: the KMS fails closed
        self.write_slot_b("c")
        self.reference = reference(expected["pcr12"], (("e2e", record), ("e2e-c", records["e2e-c"])))
        said = self.boot("v8-broken-factory", credentials, image="e2e-c", nvram="host")
        unattended(self, said)
        proof = verity_proof(said)
        self.assertEqual((proof["usr"], proof["status"], proof["roothash"]), ("/dev/mapper/usr:erofs", "verified", self.usr["c"]["roothash"]))
        units = unit_states(said)
        print("boot v8: %s" % {u: (s["active"], s["result"], s["started"]) for u, s in units.items()}, file=sys.stderr)
        self.assertIn("REGALIA-E2E-FACTORY assert=no", said)
        self.assertEqual(units["regalia-etc-factory.service"]["started"], 0, units["regalia-etc-factory.service"])
        self.assertNotEqual(units["regalia-etc-factory.service"]["active"], "active", units["regalia-etc-factory.service"])
        # systemd-firstboot too (systemd-firstboot.service.d/regalia-etc.conf): measured before it, it ran on the empty /etc
        # and held the boot at "Please configure your system! -- Press any key to proceed --"
        self.assertNotIn("Please configure your system", said)
        for unit in ("systemd-firstboot.service", "systemd-sysusers.service", "apparmor.service", "regalia-kms.service"):
            self.assertEqual(units[unit]["started"], 0, "%s ran with no factory /etc" % unit)
            self.assertNotEqual(units[unit]["active"], "active", (unit, units[unit]))
        self.assertRegex(said, r"REGALIA-E2E-APPARMOR enabled=\S+ regalia-kms=none etc-passwd=absent")
        # ... and no firewall, which the KMS (not started, above) would have refused to run without anyway
        self.assertNotEqual(units["nftables.service"]["active"], "active", units["nftables.service"])

        # boot v9, THE CONTROL: A's UKI again, A's /usr, everything started
        said = self.boot("v9-control", credentials, nvram="host")
        unattended(self, said)
        self.proven(said, "a")
        self.started(said)


if __name__ == "__main__":
    unittest.main()
