"""Refuse ambiguous source inputs and tampered signed-index chains."""
import copy
import hashlib
import json
import lzma
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import source, snapshot
from deploy.images.verify import VerificationError


def record(files=None, directory="pool/main/t/tpm2-tools"):
    files = source.FILES if files is None else files
    return (f"Package: {source.PACKAGE}\nVersion: {source.VERSION}\nDirectory: {directory}\n"
            "Checksums-Sha256:\n" + "".join(f" {digest} {size} {name}\n" for name, (digest, size) in files.items()))


class ReviewedSourceInputs(unittest.TestCase):
    def test_exact_record_and_duplicate_or_unreviewed_inputs(self):
        good = record()
        self.assertEqual(source.source_record(good.encode())[1], source.FILES)
        changed = dict(source.FILES)
        name = next(iter(changed))
        changed[name] = ("0" * 64, changed[name][1])
        malformed = [good + "\n" + good, good.replace("5.7-1", "5.8-1"), record(changed),
                     record(directory="pool/../evil"), record(directory="https://evil.invalid"),
                     good + next(line for line in good.splitlines(True) if line.startswith(" ")),
                     good.replace(name, "../" + name), good.replace("Checksums-Sha256", "Files")]
        for data in malformed:
            with self.subTest(data=data[:80]), self.assertRaises(VerificationError):
                source.source_record(data.encode())

    def test_source_file_bytes_are_checked_after_index_authentication(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = json.loads(snapshot.POLICY.read_text())
            content = b"public source input"
            filename = "tpm2-tools_5.7.orig.tar.gz"
            reviewed = {filename: (hashlib.sha256(content).hexdigest(), len(content))}
            with patch.object(source, "FILES", reviewed):
                compressed = lzma.compress(record(reviewed).encode())
                sums = {source.INDEX: (hashlib.sha256(compressed).hexdigest(), len(compressed))}
                (root / "policy.json").write_bytes(snapshot.POLICY.read_bytes())
                (root / "Sources.xz").write_bytes(compressed)
                (root / filename).write_bytes(content)
                with patch.object(source, "verify_release", return_value=({"status": "fixture"}, sums)) as verify, \
                        patch.object(source, "policy", return_value=copy.deepcopy(config)):
                    self.assertEqual(source.validate(root)["status"], "verified")
                    verify.assert_called_with(root / "InRelease", root / "archive-key-13.asc",
                                              snapshot.ARCHIVES["debian"][2], "trixie")
                    for path, replacement in [(root / filename, b"modified source"),
                                              (root / "Sources.xz", lzma.compress(b"malicious index")),
                                              (root / "policy.json", b"{}")]:
                        original = path.read_bytes()
                        path.write_bytes(replacement)
                        with self.subTest(path=path.name), self.assertRaises(VerificationError):
                            source.validate(root)
                        path.write_bytes(original)

    def test_unauthenticated_index_cannot_direct_source_downloads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repository = root / "snapshot" / "debian"
            repository.mkdir(parents=True)
            for name in ("InRelease", "archive-key-13.asc"):
                (repository / name).write_bytes(b"fixture")
            def download(url, path, limit):
                path.write_bytes(lzma.compress(record(directory="pool/evil").encode()))
            config = json.loads(snapshot.POLICY.read_text())
            with patch.object(source, "verify_release", return_value=({}, {source.INDEX: ("0" * 64, 1)})), \
                    patch.object(source, "policy", return_value=config), \
                    patch.object(source, "download", side_effect=download) as fetch:
                with self.assertRaises(VerificationError):
                    source.fetch(root / "output", root / "snapshot")
                self.assertEqual(fetch.call_count, 1)
                self.assertFalse((root / "output").exists())
