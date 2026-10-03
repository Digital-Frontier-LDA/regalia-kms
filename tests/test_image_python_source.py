"""Python source inputs must retain their authority and frozen byte bindings."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import python_source
from deploy.images.verify import VerificationError


class PythonSourceBoundaries(unittest.TestCase):
    def test_packaged_authority_rejects_duplicates_links_and_changed_bytes(self):
        authority = b"public authority fixture\n"
        expected = (hashlib.sha256(authority).hexdigest(), len(authority))
        def archive(attack=None):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:xz") as output:
                for _ in range(2 if attack == "duplicate" else 1):
                    item = tarfile.TarInfo(python_source.ANCHOR_PATH)
                    item.size = len(authority)
                    data = authority
                    if attack == "bytes": data = b"X" + authority[1:]
                    if attack == "missing": item.name = "unreviewed-key.asc"
                    if attack == "link":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "/etc/shadow"
                        item.size = 0
                    output.addfile(item, io.BytesIO(data) if item.isfile() else None)
            return stream.getvalue()
        with patch.object(python_source, "ANCHOR", expected):
            self.assertEqual(python_source.packaged_authority(archive()), authority)
            for attack in ("duplicate", "bytes", "missing", "link"):
                with self.subTest(attack=attack), self.assertRaises(VerificationError):
                    python_source.packaged_authority(archive(attack))

    def test_inputs_are_bounded_regular_frozen_bytes(self):
        data = b"signed input fixture\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "input"
            path.write_bytes(data)
            expected = {"input": (hashlib.sha256(data).hexdigest(), len(data))}
            frozen = python_source.inputs(root, expected)
            path.write_bytes(b"X" * len(data))
            self.assertEqual(frozen["input"], data)
            with self.assertRaises(VerificationError): python_source.inputs(root, expected)
            path.write_bytes(data + b"extra")
            with self.assertRaises(VerificationError): python_source.inputs(root, expected)
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaises((OSError, VerificationError)): python_source.inputs(root, expected)

    def test_unknown_suite_and_cross_suite_source_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(python_source, 'archive_source_index') as index:
                with self.assertRaises(VerificationError):
                    python_source.validate(root, packaging_suite='testing')
                index.assert_not_called()
            # An authenticated stable record cannot substitute for the pinned sid version.
            record = ('Package: python3.13\nVersion: 3.13.5-2+deb13u5\n'
                      'Directory: pool/main/p/python3.13\nChecksums-Sha256:\n'
                      + ''.join(f' {digest} {size} {name}\n'
                                for name, (digest, size) in python_source.DEBIAN_FILES.items())).encode()
            with patch.object(python_source, 'archive_source_index', return_value=({}, record)) as index, \
                 patch.object(python_source, 'inputs') as inputs:
                with self.assertRaises(VerificationError):
                    python_source.validate(root, packaging_suite='sid')
                index.assert_called_once_with(root, python_source.POLICY, suite='sid')
                inputs.assert_not_called()

    def test_source_authentication_grants_no_package_or_image_admission(self):
        tar = b"upstream tar fixture"
        signature = b"signature fixture"
        key = b"authority fixture"
        frozen = {"Python-3.13.16.tar.xz": tar, "Python-3.13.16.tar.xz.asc": signature,
                  "upstream-authority.asc": key,
                  "python3.13_3.13.5-2+deb13u5.debian.tar.xz": b"packaging fixture"}
        with patch.object(python_source, "archive_source_index", return_value=({}, b"index fixture")), \
             patch.object(python_source, "source_record", return_value=("pool/main/p/python3.13", python_source.DEBIAN_FILES)), \
             patch.object(python_source, "inputs", return_value=frozen), \
             patch.object(python_source, "packaged_authority"), \
             patch.object(python_source, "verify_detached", return_value={"verified": True}) as verify:
            report = python_source.validate(Path("unused"))
            verify.assert_called_once_with(tar, signature, key, python_source.SIGNER)
            self.assertFalse(report["production_approved"])
            self.assertFalse(report["package_admitted"])
            self.assertFalse(report["sigstore_signature_verified"])
            verify.side_effect = VerificationError("signature refused")
            with self.assertRaises(VerificationError): python_source.validate(Path("unused"))


if __name__ == "__main__":
    unittest.main()
