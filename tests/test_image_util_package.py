"""Refuse package substitution without installing or executing the package."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import util_package
from deploy.images.verify import VerificationError
from lab.appliance import util_profile


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb required")
class UtilityPackageBoundaries(unittest.TestCase):
    def test_package_substitution_and_privilege_boundaries(self):
        original = json.loads(util_package.POLICY.read_text())
        control = dict(original["packages"]["mount"]["control"], Architecture="amd64", **{"Installed-Size": "1"})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = root / "policy.json"
            marker = root / "must-not-execute"
            def package(label, attack=None, architecture="amd64", alias=False):
                stage = root / label
                (stage / "DEBIAN").mkdir(parents=True)
                (stage / "usr/bin").mkdir(parents=True)
                for directory in (stage, stage / "DEBIAN", stage / "usr", stage / "usr/bin"):
                    directory.chmod(0o755)
                fields = dict(control)
                fields["Architecture"] = architecture
                if attack == "source": fields["Source"] = "different-source"
                if attack == "version": fields["Version"] = "2.42.5-0+regalia1"
                if attack == "flags": fields["Essential"] = "yes"
                (stage / "DEBIAN/control").write_text("\n".join(k + ": " + v.replace("\n", "\n ") for k, v in fields.items()) + "\n")
                elf = bytearray(20)
                elf[:6] = b"\x7fELF\x02\x01"
                machine = {"amd64": 62, "arm64": 183}[architecture]
                elf[18:20] = (183 if attack == "architecture" else machine).to_bytes(2, "little")
                executable = stage / "usr/bin/mount"
                if attack == "symlink": executable.symlink_to("/bin/sh")
                else:
                    executable.write_bytes(elf)
                    executable.chmod(0o6755 if attack == "privilege" else 0o4755)
                if attack == "extra": (stage / "usr/bin/unreviewed").write_bytes(elf)
                if alias:
                    alias_path = stage / "usr/bin/i386"
                    alias_path.symlink_to("/etc/shadow" if attack == "alias" else "mount")
                    # Darwin creates a symlink with the caller's umask; Linux
                    # package links have 0777. Normalize this fixture only.
                    if alias_path.lstat().st_mode & 0o777 != 0o777:
                        alias_path.chmod(0o777, follow_symlinks=False)
                if attack == "script":
                    script = stage / "DEBIAN/postinst"
                    script.write_text("#!/bin/sh\ntouch " + str(marker) + "\n")
                    script.chmod(0o755)
                output = root / (label + ".deb")
                subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(output)],
                               check=True, capture_output=True)
                return output
            good = package("good")
            # A minimal reviewed layout keeps these adversarial fixtures small;
            # the actual nine-package policy is checked against native packages.
            def descriptor(kind, mode, elf=False):
                return {"kind": kind, "mode": mode, "link": None, "elf": elf}
            entry = original["packages"]["mount"]
            entry["payload_members"] = {name: descriptor("directory", 0o755) for name in (".", "usr", "usr/bin")}
            entry["payload_members"]["usr/bin/mount"] = descriptor("file", 0o4755, True)
            entry["control_members"].pop("md5sums")
            original["packages"] = {"mount": entry}
            policy.write_text(json.dumps(original))
            with patch.object(util_package, "POLICY", policy):
                result = util_package.inspect(good, "amd64")
                self.assertFalse(result["package_admitted"])
                self.assertFalse(result["production_approved"])
                original_bytes = good.read_bytes()
                real_parser = util_package.deb_archive
                def replace_after_control(path, option, limit, **kwargs):
                    parsed = real_parser(path, option, limit, **kwargs)
                    if option == "--ctrl-tarfile": good.write_bytes(b"replaced caller input")
                    return parsed
                with patch.object(util_package, "deb_archive", side_effect=replace_after_control):
                    frozen = util_package.inspect(good, "amd64")
                self.assertEqual(frozen["package_sha256"], hashlib.sha256(original_bytes).hexdigest())
                good.write_bytes(original_bytes)
                for attack in ("source", "version", "flags", "architecture", "symlink", "privilege", "extra", "script"):
                    with self.subTest(attack=attack), self.assertRaises(VerificationError):
                        util_package.inspect(package(attack, attack), "amd64")
                with self.assertRaises(VerificationError): util_package.inspect(good, "arm64")
                with self.assertRaises(VerificationError): util_package.inspect(good, "riscv64")
                linked = root / "linked.deb"
                linked.symlink_to(good)
                with self.assertRaises((VerificationError, OSError)): util_package.inspect(linked, "amd64")
                self.assertFalse(marker.exists(), "inspection executed an injected maintainer script")
                # Architecture-specific paths are exact additions, never
                # optional files or a wildcard exception for other targets.
                entry["architecture_payload_members"] = {"amd64": {"usr/bin/i386": {
                    "kind": "symlink", "mode": 0o777, "link": "mount", "elf": False}}}
                policy.write_text(json.dumps(original))
                util_package.inspect(package("amd-alias", alias=True), "amd64")
                util_package.inspect(package("arm-base", architecture="arm64"), "arm64")
                for target, arch in ((good, "amd64"),
                                     (package("arm-alias", architecture="arm64", alias=True), "arm64"),
                                     (package("redirected-alias", attack="alias", alias=True), "amd64")):
                    with self.subTest(target=target.name), self.assertRaises(VerificationError):
                        util_package.inspect(target, arch)
                entry["architecture_payload_members"]["amd64"]["usr/bin/mount"] = entry["payload_members"]["usr/bin/mount"]
                policy.write_text(json.dumps(original))
                with self.assertRaises(VerificationError):
                    util_package.inspect(package("common-replacement", alias=True), "amd64")


class UtilityProfileBoundaries(unittest.TestCase):
    def test_all_inputs_checked_before_edits_and_no_second_application(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {name: "fixture original\n" for name in util_profile.FILES}
            files["debian/control"] = "Maintainer: Chris Hofstaedtler <zeha@debian.org>\n"
            files["debian/patches/series"] = "retained.patch\n" + "".join(p + "\n" for p in util_profile.UPSTREAMED)
            files["debian/patches/debian/lsfd-usrbin.patch"] = "lsfd-cmd/file.c: errnos.h\n"
            hashes = {}
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
                hashes[name] = hashlib.sha256(text.encode()).hexdigest()
            target = root / "libmount/src/context.c"
            target.write_text("modified source\n")
            with patch.object(util_profile, "FILES", hashes):
                with self.assertRaises(VerificationError): util_profile.prepare(root)
                for name, text in files.items():
                    if name != "libmount/src/context.c": self.assertEqual((root / name).read_text(), text)
                target.write_text(files["libmount/src/context.c"])
                util_profile.prepare(root)
                self.assertEqual((root / "debian/patches/series").read_text(), "retained.patch\n")
                with self.assertRaises(VerificationError): util_profile.prepare(root)
