"""deploy/baremetal/generators/regalia-boot-esp: the boot ESP, at /efi, from the stub's LoaderDevicePartUUID
(regalia-kms-9tv). The image's consumers (regalia-site-check, regalia-esp-advance, the node CLIs) look for the ESP
at /efi; systemd-gpt-auto-generator's automount puts it at /boot on the image (root=tmpfs: no /efi exists), so
the consumers fail. This generator reads the stub's identity (the GPT partition the firmware loaded), writes
efi.mount and efi.automount, and suppresses gpt-auto's competing units.

Held here, with a MUTANT CONTROL for the fail-closed rules: a missing or malformed identity, an unsupported
layout, or a non-ESP partition must refuse (no units written, a named refusal on stderr). The QEMU boots
(OnQemuVerity) show the mount on the real image: the ESP at /efi, vfat, rw, the root-only masks, no /boot
competing mount, and a successful write/read/remove.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GENERATOR = "deploy/baremetal/generators/regalia-boot-esp"
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
XBOOT_TYPE = "eb0d1b61-9d14-4e60-b3f8-2c022c24dcb2"


def _efivar(uuid):
    """The efivars file's bytes: 4 attribute bytes + UTF-16LE + NUL padding."""
    if uuid is None:
        return b""
    text = uuid.encode("utf-16-le")
    return b"\x00\x00\x00\x00" + text + b"\x00" * max(0, 64 - len(text))


def _gpt(parts):
    """A GPT partition list: "TYPE-GUID PART-GUID" per line, as the generator reads it (or udev gives it)."""
    return "\n".join("%s %s" % (t, p) for t, p in parts) + "\n"


def _run(out, efivars, gpt):
    """Run the generator; (rc, stderr, {path: text or None})."""
    done = subprocess.run(
        ["sh", str(ROOT / GENERATOR), out, out + "/early", out + "/late", efivars, gpt],
        capture_output=True, text=True)
    units = {}
    for name in ("efi.mount", "efi.automount", "boot.mount", "boot.automount"):
        path = Path(out) / name
        units[name] = path.read_text() if path.exists() else None
    want = Path(out) / "local-fs.target.wants" / "efi.automount.service"
    units["want"] = "present" if want.exists() else None
    return done.returncode, done.stderr, units


class BootEsp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = self._tmp.name + "/out"
        os.makedirs(self.out)
        self.efivars = self._tmp.name + "/efivars"
        os.makedirs(self.efivars)
        self.gpt = self._tmp.name + "/gpt.txt"

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, uuid=None, parts=None):
        name = "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
        if uuid is not None:
            with open(os.path.join(self.efivars, name), "wb") as f:
                f.write(_efivar(uuid))
        if parts is not None:
            with open(self.gpt, "w") as f:
                f.write(_gpt(parts))

    def _mount(self, text):
        """The [Mount] fields of efi.mount as a dict, or {} if the unit is absent."""
        if text is None:
            return {}
        out = {}
        section = None
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
            elif section == "Mount":
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip()
        return out

    def _unit(self, text, section, key):
        if text is None:
            return None
        found = None
        cur = None
        for line in text.splitlines():
            line = line.strip()
            if not line or line[0] in "#;":
                continue
            if line.startswith("[") and line.endswith("]"):
                cur = line[1:-1]
            elif cur == section:
                k, _, v = line.partition("=")
                if k.strip() == key:
                    found = v.strip()
        return found

    def test_it_writes_the_mount_on_the_supported_layout(self):
        """The image's layout: one ESP partition, the stub's identity on it: efi.mount and efi.automount, the
        want, and the gpt-auto units emptied."""
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [(ESP_TYPE, "11223344-5566-7788-99aa-bbccddeeff00"),
                     ("ea2b7845-6a63-4e81-9735-12a1a8576c3f", "99993344-5566-7788-99aa-bbccddeeff01")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNotNone(units["efi.mount"], "no efi.mount: %s" % said)
        self.assertIsNotNone(units["efi.automount"], "no efi.automount: %s" % said)
        self.assertEqual(units["want"], "present")
        self.assertEqual(units["boot.mount"], "")
        self.assertEqual(units["boot.automount"], "")
        mount = self._mount(units["efi.mount"])
        self.assertEqual(mount.get("What"), "/dev/disk/by-partuuid/11223344-5566-7788-99aa-bbccddeeff00")
        self.assertEqual(mount.get("Where"), "/efi")
        self.assertEqual(mount.get("Type"), "vfat")
        self.assertEqual(mount.get("Options"), "rw,nosuid,nodev,noexec,fmask=0077,dmask=0077")
        self.assertEqual(mount.get("DirectoryMode"), "0700")
        self.assertEqual(self._unit(units["efi.mount"], "Unit", "Requires"),
                         "dev-disk-by-partuuid-11223344-5566-7788-99aa-bbccddeeff00-device")
        self.assertEqual(self._unit(units["efi.automount"], "Automount", "Where"), "/efi")
        self.assertEqual(self._unit(units["efi.automount"], "Automount", "IdleTimeoutSec"), "120")
        self.assertEqual(self._unit(units["efi.automount"], "Install", "WantedBy"), "local-fs.target")

    def test_a_missing_identity_refuses(self):
        """No LoaderDevicePartUUID (a boot without the stub, or a non-GPT boot): no units, a named refusal."""
        self._write(None, [(ESP_TYPE, "11223344-5566-7788-99aa-bbccddeeff00")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNone(units["efi.mount"], said)
        self.assertIsNone(units["efi.automount"], said)
        self.assertIsNone(units["want"], said)
        self.assertIn("LoaderDevicePartUUID", said)
        self.assertIn("absent", said)

    def test_a_malformed_identity_refuses(self):
        """A value the stub could not have written (a non-hex digit, or too short): no units, a named refusal."""
        for bad in ("zz223344-5566-7788-99aa-bbccddeeff00", "11223344-5566", "112233445566778899aabbccddeeff00"):
            with self.subTest(bad=bad):
                self._write(bad, [(ESP_TYPE, "11223344-5566-7788-99aa-bbccddeeff00")])
                rc, said, units = _run(self.out, self.efivars, self.gpt)
                self.assertEqual(rc, 0, said)
                self.assertIsNone(units["efi.mount"], (bad, said))
                self.assertIn("not a GPT UUID", said)

    def test_a_nonboot_decoy_esp_refuses(self):
        """An ESP partition that is NOT the one the firmware loaded: no units, a named refusal."""
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [(ESP_TYPE, "99993344-5566-7788-99aa-bbccddeeff01")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNone(units["efi.mount"], said)
        self.assertIn("not the one the firmware loaded", said)

    def test_an_xbootldr_refuses(self):
        """An XBOOTLDR partition: the layout is not the image's: no units, a named refusal."""
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [(ESP_TYPE, "11223344-5566-7788-99aa-bbccddeeff00"),
                     (XBOOT_TYPE, "aabbccdd-1122-3344-5566-778899aabbcc")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNone(units["efi.mount"], said)
        self.assertIn("XBOOTLDR", said)

    def test_two_esps_refuse(self):
        """Two ESP partitions: the layout is not the image's: no units, a named refusal."""
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [(ESP_TYPE, "11223344-5566-7788-99aa-bbccddeeff00"),
                     (ESP_TYPE, "99993344-5566-7788-99aa-bbccddeeff01")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNone(units["efi.mount"], said)
        self.assertIn("two ESP partitions", said)

    def test_no_esp_partition_refuses(self):
        """No ESP-typed partition at all: no units, a named refusal."""
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [("ea2b7845-6a63-4e81-9735-12a1a8576c3f", "11223344-5566-7788-99aa-bbccddeeff00")])
        rc, said, units = _run(self.out, self.efivars, self.gpt)
        self.assertEqual(rc, 0, said)
        self.assertIsNone(units["efi.mount"], said)
        self.assertIn("no partition of the ESP type", said)

    def test_a_generator_that_trusts_any_partition_is_caught(self):
        """MUTANT: the partuuid check gone, a decoy ESP is mounted, and the test above fails."""
        text = (ROOT / GENERATOR).read_text()
        anchor = "if [ \"$device\" != \"$partuuid\" ]; then"
        self.assertEqual(text.count(anchor), 1)
        planted = Path(tempfile.mkdtemp(), "g")
        planted.write_text(text.replace(anchor, "if [ 0 = 1 ]; then"))
        os.chmod(planted, 0o755)
        self._write("11223344-5566-7788-99aa-bbccddeeff00",
                    [(ESP_TYPE, "99993344-5566-7788-99aa-bbccddeeff01")])
        done = subprocess.run(
            ["sh", str(planted), self.out, self.out + "/early", self.out + "/late", self.efivars, self.gpt],
            capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue((Path(self.out) / "efi.mount").exists(),
                        "the mutant generator did not write efi.mount: %s" % done.stderr)


if __name__ == "__main__":
    unittest.main()
