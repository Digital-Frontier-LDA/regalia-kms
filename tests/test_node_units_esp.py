"""The node-units ESP setup, before any caller may write the credential."""

from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from e2e.lib import node_units_esp


class FixtureEspTests(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.work = Path(scratch.name)
        self.esp = self.work / "efi"
        self.image = self.work / "node-units-esp.img"
        self.commands = []
        self.status = {"mountpoint": 32}
        self.fstype = "vfat"
        self.entered = False

    def sh(self, *argv, check=True):
        self.commands.append(argv)
        name = argv[0]
        status = self.status.get(name, 0)
        if name == "mkfs.vfat":
            self.assertEqual(Path(argv[-1]), self.image, "format target must be the new image")
            self.assertTrue(self.image.is_file(), "format target must be a regular file")
            self.assertFalse(self.image.is_symlink(), "format target must not be a symlink")
            self.assertEqual(self.image.stat().st_size, 64 * 1024 * 1024)
        if check and status != 0:
            raise SystemExit(f"{name} fixture error")
        return SimpleNamespace(returncode=status, stdout=self.fstype + "\n")

    def exercise(self):
        with node_units_esp.mounted(self.work, self.esp, self.sh):
            # Stands for the scenario's credential write, which is outside
            # this context's setup and must not execute on a refusal.
            self.entered = True
            return self.image.exists()

    def command_names(self):
        return [argv[0] for argv in self.commands]

    def test_format_mount_readback_then_unmount_owned_image(self):
        self.assertTrue(self.exercise())
        self.assertTrue(self.entered)
        self.assertEqual(self.command_names(), ["mountpoint", "mkfs.vfat", "mount", "findmnt", "umount"])
        self.assertEqual(self.commands[2][-2:], (str(self.image), str(self.esp)))
        self.assertIn("loop", self.commands[2][4].split(","))
        self.assertEqual(self.commands[3][-2:], ("--mountpoint", str(self.esp)))
        self.assertFalse(self.image.exists(), "successful unmount must remove the backing image")
        self.assertFalse(self.esp.exists(), "successful cleanup must remove an owned mountpoint")

    def test_cleanup_leaves_preexisting_directory(self):
        self.esp.mkdir()
        self.assertTrue(self.exercise())
        self.assertTrue(self.esp.is_dir(), "cleanup must keep a pre-existing directory")

    def test_existing_mount_or_bad_probe_refuses_without_setup(self):
        self.esp.mkdir()
        for code in (0, 1):
            with self.subTest(code=code):
                self.commands.clear()
                self.status["mountpoint"] = code
                with self.assertRaisesRegex(SystemExit, f"mountpoint exited {code}"):
                    self.exercise()
                self.assertFalse(self.entered, "probe refusal must block the credential write")
                self.assertEqual(self.command_names(), ["mountpoint"])
                self.assertFalse(self.image.exists())

    def test_symlink_mountpoint_is_refused_before_probe(self):
        target = self.work / "elsewhere"
        target.mkdir()
        self.esp.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(SystemExit, "refusing a symlink"):
            self.exercise()
        self.assertEqual(self.commands, [])
        self.assertFalse(self.entered)

    def test_existing_image_is_not_formatted_or_unlinked(self):
        self.image.write_bytes(b"unrelated image")
        with self.assertRaises(FileExistsError):
            self.exercise()
        self.assertEqual(self.command_names(), ["mountpoint"])
        self.assertTrue(self.image.is_file(), "cleanup must keep a pre-existing image")
        self.assertEqual(self.image.read_bytes(), b"unrelated image")
        self.assertFalse(self.esp.exists())

    def test_command_errors_fail_before_inserting_the_credential(self):
        for command, expected in (
            ("mkfs.vfat", ["mountpoint", "mkfs.vfat"]),
            ("mount", ["mountpoint", "mkfs.vfat", "mount"]),
            ("findmnt", ["mountpoint", "mkfs.vfat", "mount", "findmnt", "umount"]),
        ):
            with self.subTest(command=command):
                self.commands.clear()
                self.status[command] = 1
                with self.assertRaisesRegex(SystemExit, f"{command} fixture error"):
                    self.exercise()
                del self.status[command]
                self.assertFalse(self.entered, "command failure must block the credential write")
                self.assertEqual(self.command_names(), expected)
                self.assertFalse(self.image.exists())
                self.assertFalse(self.esp.exists())

    def test_wrong_type_readback_blocks_write_and_unmounts(self):
        self.fstype = "tmpfs"
        with self.assertRaisesRegex(SystemExit, "must be mounted as vfat, found 'tmpfs'"):
            self.exercise()
        self.assertFalse(self.entered, "a tmpfs readback must block the credential write")
        self.assertEqual(self.command_names()[-2:], ["findmnt", "umount"])
        self.assertFalse(self.image.exists())

    def test_body_error_still_unmounts_before_deleting_image(self):
        with self.assertRaisesRegex(RuntimeError, "scenario failed"):
            with node_units_esp.mounted(self.work, self.esp, self.sh):
                raise RuntimeError("scenario failed")
        self.assertEqual(self.command_names()[-1], "umount")
        self.assertFalse(self.image.exists())
        self.assertFalse(self.esp.exists())

    def test_failed_unmount_preserves_mounted_image_and_directory(self):
        self.status["umount"] = 1
        with self.assertRaisesRegex(SystemExit, "umount fixture error"):
            self.exercise()
        self.assertTrue(self.image.exists(), "failed unmount must retain the backing image")
        self.assertTrue(self.esp.exists(), "failed unmount must retain the mountpoint")
