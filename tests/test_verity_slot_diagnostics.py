"""Slot-B pre-boot diagnostics, with host commands faked and no QEMU/TPM/device access."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests import test_baremetal_unlock_boot as boot


class SlotBReadback(unittest.TestCase):
    def setUp(self):
        class Host(unittest.TestCase):
            write_slot_b = boot.OnQemuVerity.write_slot_b

            def partition(self, number):
                return "/dev/loop7", "/dev/loop7p%d" % number

            def runTest(self):
                pass

        self.host = Host()
        self.host.image = "/fixture/disk.img"
        self.record = {"usr_partuuid": "01234567-89ab-cdef-0123-456789abcdef",
                       "usr_verity_partuuid": "fedcba98-7654-3210-fedc-ba9876543210", "roothash": "ab" * 32}
        self.host.usr = {"b": self.record}
        self.calls = []
        self.wrong_uuid = None
        self.failure = None
        self.raised = None
        self.hash_appeared = 0.1

    def host_command(self, argv, **kwargs):
        self.calls.append(argv)
        if self.raised == argv[0]:
            raise OSError("injected host command error")
        if self.failure == argv[0]:
            return subprocess.CompletedProcess(argv, 2, "", "injected command refusal")
        if argv[0] == "blkid":
            key = "usr_partuuid" if argv[-1].endswith("p4") else "usr_verity_partuuid"
            value = "00000000-0000-0000-0000-000000000000" if self.wrong_uuid == key else self.record[key]
            return subprocess.CompletedProcess(argv, 0, value.upper() + "\n", "")
        self.assertIn(argv[0], {"dd", "losetup", "sfdisk", "veritysetup"}, "unexpected host command")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def write(self):
        output = io.StringIO()
        with patch.object(boot, "run", self.host_command), \
                patch.object(boot, "wait_for_partition", return_value=("/dev/loop7p5", self.hash_appeared)), \
                contextlib.redirect_stderr(output):
            self.host.write_slot_b("b")
        return output.getvalue()

    def detached(self):
        return self.calls.count(["losetup", "-d", "/dev/loop7"])

    def test_success_checks_both_partuuids_then_verifies_the_written_pair_under_the_recorded_root(self):
        said = self.write()
        probes = [argv for argv in self.calls if argv[0] == "blkid"]
        self.assertEqual(probes, [["blkid", "-p", "-s", "PART_ENTRY_UUID", "-o", "value", "/dev/loop7p4"],
                                  ["blkid", "-p", "-s", "PART_ENTRY_UUID", "-o", "value", "/dev/loop7p5"]])
        self.assertEqual(self.calls[-2], ["veritysetup", "verify", "/dev/loop7p4", "/dev/loop7p5", self.record["roothash"]])
        self.assertEqual(self.detached(), 3)
        self.assertIn("HOST SLOT B VERIFIED", said)
        self.assertIn(self.record["roothash"], said)

    def test_wrong_data_or_hash_partuuid_fails_by_name_without_verifying_or_repairing_and_detaches(self):
        for key, number in (("usr_partuuid", 4), ("usr_verity_partuuid", 5)):
            with self.subTest(key=key):
                self.calls.clear()
                self.wrong_uuid = key
                with self.assertRaisesRegex(AssertionError, "HOST SLOT B PARTUUID MISMATCH.*partition %d" % number):
                    self.write()
                self.assertFalse(any(argv[0] == "veritysetup" for argv in self.calls))
                self.assertEqual(self.detached(), 3)
                self.assertEqual(self.calls[-1], ["losetup", "-d", "/dev/loop7"])

    def test_failed_blkid_probe_preserves_its_error_and_detaches(self):
        self.failure = "blkid"
        with self.assertRaisesRegex(AssertionError, "HOST SLOT B PARTUUID READ FAILED.*injected command refusal"):
            self.write()
        self.assertEqual(self.detached(), 3)

    def test_corrupt_pair_verification_fails_with_the_devices_root_and_stderr_and_detaches(self):
        self.failure = "veritysetup"
        with self.assertRaisesRegex(AssertionError, "HOST SLOT B VERITY VERIFY FAILED") as caught:
            self.write()
        for detail in ("/dev/loop7p4", "/dev/loop7p5", self.record["roothash"], "rc=2", "injected command refusal"):
            self.assertIn(detail, str(caught.exception))
        self.assertEqual(self.detached(), 3)
        self.assertEqual(self.calls[-1], ["losetup", "-d", "/dev/loop7"])

    def test_verifier_exception_still_detaches_the_readback_mapping(self):
        self.raised = "veritysetup"
        with self.assertRaisesRegex(OSError, "injected host command error"):
            self.write()
        self.assertEqual(self.detached(), 3)

    def test_a_hash_partition_that_never_appears_fails_by_name_and_detaches(self):
        self.hash_appeared = None
        with self.assertRaisesRegex(AssertionError, "HOST SLOT B HASH PARTITION NOT READY"):
            self.write()
        self.assertEqual(self.detached(), 3)
        self.assertFalse(any(argv[0] in {"blkid", "veritysetup"} for argv in self.calls))

    def test_partuuid_probe_exception_still_detaches_the_readback_mapping(self):
        self.raised = "blkid"
        with self.assertRaisesRegex(OSError, "injected host command error"):
            self.write()
        self.assertEqual(self.detached(), 3)

    def test_dd_failure_or_exception_still_detaches_its_mapping(self):
        for attribute, error in (("failure", AssertionError), ("raised", OSError)):
            with self.subTest(attribute=attribute):
                self.calls.clear()
                self.failure = self.raised = None
                setattr(self, attribute, "dd")
                with self.assertRaises(error):
                    self.write()
                self.assertEqual(self.detached(), 1)
                self.assertEqual(self.calls[-1], ["losetup", "-d", "/dev/loop7"])

    def test_partuuid_write_failure_stops_before_readback_with_no_mapping_left(self):
        self.failure = "sfdisk"
        with self.assertRaises(AssertionError):
            self.write()
        self.assertEqual(self.detached(), 2)
        self.assertFalse(any(argv[0] in {"blkid", "veritysetup"} for argv in self.calls))


class SlotBJournalCommandLine(unittest.TestCase):
    def command_lines(self, override=None):
        """Execute only the real cmdline printf and B/C build calls, with uki_image replaced by an argv recorder."""
        source = (Path(__file__).resolve().parents[1] / "e2e/unlock-boot-qemu.sh").read_text()
        base = next(line for line in source.splitlines() if line.startswith("printf ") and "REGALIA_BOOT_CMDLINE:-" in line)
        start = source.index("  # the verity boots' images")
        end = source.index("  # WRONG USRHASH", start)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tmp/uki").mkdir(parents=True)
            env = dict(os.environ, ROOT=str(root), KVER="test-kernel")
            env.pop("REGALIA_BOOT_CMDLINE", None)
            if override is not None:
                env["REGALIA_BOOT_CMDLINE"] = override
            record = 'uki_image() { printf "%s\\n" "$@" > "$ROOT/$1.args"; }\n'
            subprocess.run(["bash", "-eu", "-c", record + base + "\n" + source[start:end]], env=env, check=True)
            args = {name: (root / (name + ".args")).read_text().splitlines() for name in ("e2e-b", "e2e-c")}
            lines = {name: (root / args[name][1].lstrip("/")).read_text().split() for name in args}
            return (root / "tmp/uki/cmdline").read_text().split(), lines, args

    def test_only_b_gets_documented_warning_console_options_and_all_boot_restrictions_stay(self):
        base, lines, args = self.command_lines()
        diagnostics = ["systemd.journald.forward_to_console=1", "systemd.journald.max_level_console=warning"]
        self.assertEqual(lines["e2e-b"], base + diagnostics)
        self.assertEqual(lines["e2e-c"], base)
        self.assertEqual(args["e2e-b"], ["e2e-b", "/tmp/uki/cmdline-b", "/boot/vmlinuz-test-kernel", "/tmp/uki/usr-b.json"])
        for restriction in ("rd.shell=0", "rd.emergency=reboot", "systemd.import_credentials=no"):
            self.assertIn(restriction, lines["e2e-b"])

    def test_a_test_command_line_override_is_preserved_verbatim_before_the_two_diagnostic_options(self):
        override = "console=ttyS0,115200 rd.shell=0 rd.emergency=reboot systemd.import_credentials=no custom=kept"
        base, lines, _ = self.command_lines(override)
        self.assertEqual(base, override.split())
        self.assertEqual(lines["e2e-b"], base + ["systemd.journald.forward_to_console=1", "systemd.journald.max_level_console=warning"])
        self.assertEqual(lines["e2e-c"], base)


if __name__ == "__main__":
    unittest.main()
