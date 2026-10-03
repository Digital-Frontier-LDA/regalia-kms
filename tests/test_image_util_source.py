"""Exercise source substitution boundaries without replacing real GPG tests."""
import hashlib
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import source, util_source
from deploy.images.verify import VerificationError


def binding(data):
    return hashlib.sha256(data).hexdigest(), len(data)


def packaging(authority, *, duplicate=False, symlink=False):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        for _ in range(2 if duplicate else 1):
            member = tarfile.TarInfo(util_source.ANCHOR_PATH)
            member.size = len(authority)
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = "../../outside"
            archive.addfile(member, io.BytesIO(authority))
    return output.getvalue()


def record(files, directory="pool/main/u/util-linux"):
    return (f"Package: {util_source.PACKAGE}\nVersion: {util_source.DEBIAN_VERSION}\n"
            f"Directory: {directory}\nChecksums-Sha256:\n" +
            "".join(f" {digest} {size} {name}\n" for name, (digest, size) in files.items())).encode()


class UtilLinuxSourceBoundaries(unittest.TestCase):
    def test_exact_debian_source_record(self):
        def parse(data):
            return source.source_record(data, package=util_source.PACKAGE,
                                        version=util_source.DEBIAN_VERSION,
                                        reviewed_files=util_source.DEBIAN_FILES)
        good = record(util_source.DEBIAN_FILES)
        self.assertEqual(parse(good), ("pool/main/u/util-linux", util_source.DEBIAN_FILES))
        changed = dict(util_source.DEBIAN_FILES)
        name = next(iter(changed))
        changed[name] = ("0" * 64, changed[name][1])
        for bad in (good + b"\n" + good, record(changed),
                    record(util_source.DEBIAN_FILES, "pool/../outside"),
                    good.replace(util_source.DEBIAN_VERSION.encode(), b"2.42.4-0+regalia1")):
            with self.subTest(bad=bad[:80]), self.assertRaises(VerificationError):
                parse(bad)

    def test_packaged_authority_refuses_duplicate_link_and_substitution(self):
        authority = b"public fixture authority"
        with tempfile.TemporaryDirectory() as temp, patch.object(util_source, "ANCHOR", binding(authority)):
            root = Path(temp)
            path = root / "util-linux_2.41.5-0+deb13u1.debian.tar.xz"
            path.write_bytes(packaging(authority))
            self.assertEqual(util_source.packaged_authority(root), authority)
            for content in (packaging(authority, duplicate=True),
                            packaging(authority, symlink=True), packaging(b"different fixture key")):
                path.write_bytes(content)
                with self.subTest(content=binding(content)), self.assertRaises(VerificationError):
                    util_source.packaged_authority(root)

    def test_every_input_is_rechecked_and_a_receipt_cannot_authorize_tampering(self):
        anchor = b"packaged public authority"
        raw_tar = b"fixture uncompressed source"
        files = {name: b"fixture " + name.encode() for name in util_source.DEBIAN_FILES}
        files["util-linux_2.41.5-0+deb13u1.debian.tar.xz"] = packaging(anchor)
        files.update({name: b"fixture " + name.encode() for name in util_source.UPSTREAM_FILES})
        files["util-linux-2.42.4.tar.xz"] = lzma.compress(raw_tar)
        files["upstream-authority.asc"] = b"refreshed public authority"
        debian = {name: binding(files[name]) for name in util_source.DEBIAN_FILES}
        upstream = {name: binding(files[name]) for name in util_source.UPSTREAM_FILES}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, data in files.items():
                (root / name).write_bytes(data)
            (root / "verification.json").write_text(json.dumps({"status": "verified"}))
            with patch.object(util_source, "archive_source_index", return_value=({}, record(debian))), \
                    patch.object(util_source, "DEBIAN_FILES", debian), \
                    patch.object(util_source, "UPSTREAM_FILES", upstream), \
                    patch.object(util_source, "TAR", binding(raw_tar)), \
                    patch.object(util_source, "ANCHOR", binding(anchor)), \
                    patch.object(util_source, "AUTHORITY", binding(files["upstream-authority.asc"])), \
                    patch.object(util_source, "verify_detached", return_value={"status": "fixture"}) as verify:
                report = util_source.validate(root)
                self.assertEqual(report["status"], "verified")
                self.assertFalse(report["production_approved"])
                self.assertEqual(verify.call_count, 3)
                for name, original in files.items():
                    (root / name).write_bytes(b"tampered input")
                    with self.subTest(name=name), self.assertRaises(VerificationError):
                        util_source.validate(root)
                    (root / name).write_bytes(original)
                # Even re-pinning the compressed fixture cannot bypass the
                # separately reviewed expansion that the upstream signer signs.
                bad_tar = lzma.compress(b"different source expansion")
                (root / "util-linux-2.42.4.tar.xz").write_bytes(bad_tar)
                upstream["util-linux-2.42.4.tar.xz"] = binding(bad_tar)
                with self.assertRaises(VerificationError):
                    util_source.validate(root)

    def test_untrusted_release_or_source_index_cannot_direct_downloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository = root / "snapshot" / "debian"
            repository.mkdir(parents=True)
            for name in ("InRelease", "archive-key-13.asc"):
                (repository / name).write_bytes(b"fixture")
            with patch.object(util_source, "verify_release", side_effect=VerificationError("bad signature")), \
                    patch.object(util_source, "download") as download:
                with self.assertRaises(VerificationError):
                    util_source.fetch(root / "output", root / "snapshot")
                download.assert_not_called()
            with patch.object(util_source, "verify_release", return_value=({}, {source.INDEX: ("0" * 64, 1)})), \
                    patch.object(util_source, "archive_source_index", side_effect=VerificationError("bad index")), \
                    patch.object(util_source, "download") as download:
                with self.assertRaises(VerificationError):
                    util_source.fetch(root / "output", root / "snapshot")
                self.assertEqual(download.call_count, 1)
                self.assertFalse((root / "output").exists())
                self.assertEqual(list(root.glob(".util-source-*")), [])
