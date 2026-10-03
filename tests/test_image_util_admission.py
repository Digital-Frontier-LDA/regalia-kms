"""Verify utility admission against actual rootfs bytes and signed inventories."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import source_package, util_admission, util_package
from deploy.images.verify import VerificationError


class InstalledUtilityPayload(unittest.TestCase):
    def test_missing_substituted_redirected_or_privileged_payload_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = root / "policy.json"
            policy.write_text(json.dumps({"packages": {"mount": {"payload_members": {
                "usr/bin/mount": {"kind": "file", "mode": 0o4755, "link": None, "elf": True},
                "usr/lib/{triplet}/libmount.so.1": {"kind": "symlink", "mode": 0o777,
                                                  "link": "libmount.so.1.1", "elf": False}}}}}))
            data = b"public rootfs fixture"
            inspected = [{"control": {"Package": "mount", "Architecture": "amd64"},
                          "policy_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
                          "payload_sha256": {"usr/bin/mount": hashlib.sha256(data).hexdigest()}}]
            def filesystem(attack):
                path = root / (attack + ".tar.gz")
                with tarfile.open(path, "w:gz") as archive:
                    if attack != "missing":
                        item = tarfile.TarInfo("./usr/bin/mount")
                        item.mode = 0o4755 if attack == "mode" else 0o755
                        item.uid = 123 if attack == "owner" else 0
                        content = b"substituted" if attack == "bytes" else data
                        item.size = len(content)
                        if attack == "hardlink":
                            item.type, item.linkname, item.size = tarfile.LNKTYPE, "etc/shadow", 0
                        archive.addfile(item, io.BytesIO(content))
                        if attack == "duplicate": archive.addfile(item, io.BytesIO(content))
                    link = tarfile.TarInfo("./usr/lib/x86_64-linux-gnu/libmount.so.1")
                    link.mode, link.type = 0o777, tarfile.SYMTYPE
                    link.linkname = "/etc/shadow" if attack == "link" else "libmount.so.1.1"
                    archive.addfile(link)
                return path
            with patch.object(util_package, "POLICY", policy):
                passed = util_admission.installed_payload(filesystem("good"), inspected)
                self.assertEqual((passed["regular_files"], passed["symlinks"]), (1, 1))
                for attack in ("missing", "bytes", "mode", "owner", "hardlink", "duplicate", "link"):
                    with self.subTest(attack=attack), self.assertRaises(VerificationError):
                        util_admission.installed_payload(filesystem(attack), inspected)


class UtilityInventoryBinding(unittest.TestCase):
    def test_nine_reviewed_local_rows_do_not_exempt_any_other_package(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "packages.tsv"
            tpm = {"schema": "regalia.source-package-binding/v1", "status": "verified",
                   "package": "tpm2-tools", "version": source_package.VERSION}
            util = {"schema": "regalia.util-linux-source-binding/v1", "status": "verified",
                    "packages": util_admission.versions()}
            rows = ["libc6\t1.0", "tpm2-tools\t" + source_package.VERSION]
            rows.extend(name + "\t" + version for name, version in util["packages"].items())
            inventory = [{"Package": "libc6", "Version": "1.0"}]
            path.write_text("\n".join(rows) + "\n")
            result = source_package.installed_binding(path, inventory, tpm, util)
            self.assertEqual((result["source_built_packages"], result["archive_packages"]), (10, 1))
            for mutation in (rows + ["unsigned\t1"], rows + [rows[-1]],
                             [row.replace("libc6\t1.0", "libc6\t2.0") for row in rows],
                             [row.replace("mount\t2.42.4", "mount\t2.42.5") for row in rows]):
                path.write_text("\n".join(mutation) + "\n")
                with self.assertRaises(VerificationError):
                    source_package.installed_binding(path, inventory, tpm, util)
