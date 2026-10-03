"""Independent comparisons require distinct runner boots and matching bytes."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from deploy.images.independent import verify
from deploy.images.verify import VerificationError


class IndependentBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.commit = "a" * 40
        self.first, self.second = [self.root / name for name in ("first", "second")]
        for index, path in enumerate((self.first, self.second), 1):
            (path / "payload").mkdir(parents=True)
            (path / "payload/regalia-kms").write_bytes(b"public executable fixture")
            report = {"schema":"regalia.independent-binary/v1", "status":"passed", "source_commit":self.commit,
                      "source_archive_sha256":"b"*64, "host_boot_id":f"00000000-0000-0000-0000-{index:012d}",
                      "platform":{"system":"Linux","architecture":"x86_64"}, "flags":"reviewed flags",
                      "toolchain":{"go":"go1.26.6", "gcc":"fixture", "ld":"fixture"},
                      "binary_sha256":hashlib.sha256((path / "payload/regalia-kms").read_bytes()).hexdigest()}
            (path / "build.json").write_text(json.dumps(report))

    def change_report(self, key, value):
        path = self.second / "build.json"
        report = json.loads(path.read_text())
        report[key] = value
        path.write_text(json.dumps(report))

    def test_distinct_instances_and_exact_bytes_pass_with_limited_claim(self):
        result = verify(self.first, self.second, self.commit)
        self.assertEqual(result["status"], "identical")
        self.assertFalse(result["production_approved"])
        self.assertEqual(result["disk_reproducibility"], "not-established")

    def test_same_runner_is_not_independent(self):
        self.change_report("host_boot_id", json.loads((self.first / "build.json").read_text())["host_boot_id"])
        with self.assertRaisesRegex(VerificationError, "distinct Linux"):
            verify(self.first, self.second, self.commit)

    def test_wrong_source_and_toolchain_fail(self):
        with self.assertRaisesRegex(VerificationError, "expected source"):
            verify(self.first, self.second, "c" * 40)
        self.change_report("toolchain", {"go":"different"})
        with self.assertRaisesRegex(VerificationError, "inputs differ"):
            verify(self.first, self.second, self.commit)

    def test_changed_binary_is_rejected_even_with_updated_local_hash(self):
        path = self.second / "payload/regalia-kms"
        path.write_bytes(b"different output")
        with self.assertRaisesRegex(VerificationError, "differs from report"):
            verify(self.first, self.second, self.commit)
        self.change_report("binary_sha256", hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaisesRegex(VerificationError, "bytes differ"):
            verify(self.first, self.second, self.commit)
