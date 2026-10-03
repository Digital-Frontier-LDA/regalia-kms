"""A final image scan must bind the build, including blocked verdicts."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab.appliance.scan_build import scan_build
from deploy.images.verify import VerificationError


class BuildScanTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build, self.output = self.root / "build", self.root / "scan"
        (self.build / "export").mkdir(parents=True)
        self.commit = "a" * 40
        self.exports = {}
        for name in ("rootfs.tar.gz", "regalia-kms"):
            data = (name + " public fixture").encode()
            (self.build / "export" / name).write_bytes(data)
            self.exports[name] = hashlib.sha256(data).hexdigest()
        self.report = {"schema": "regalia.appliance-build/v1", "status": "passed",
                       "source_commit": self.commit, "export": self.exports}
        self.write_report()

    def write_report(self):
        (self.build / "build-report.json").write_text(json.dumps(self.report))

    def run_scan(self, status):
        def scanner(rootfs, tools, output):
            self.assertEqual(rootfs, self.build / "export/rootfs.tar.gz")
            output.mkdir()
            report = {"status": status, "rootfs_sha256": self.exports["rootfs.tar.gz"]}
            (output / "scan-report.json").write_text(json.dumps(report))
            return report
        with patch("lab.appliance.scan_build.scan", side_effect=scanner):
            return scan_build(self.build, self.root / "tools", self.output, self.commit)

    def test_blocked_verdict_is_retained_and_never_admissible(self):
        result = self.run_scan("blocked")
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["release_admissible"])
        self.assertFalse(result["production_approved"])
        self.assertEqual(json.loads((self.output / "build-binding.json").read_text()), result)

    def test_passing_scan_binds_exact_export_and_report(self):
        result = self.run_scan("passed")
        self.assertTrue(result["release_admissible"])
        self.assertEqual(result["rootfs_sha256"], self.exports["rootfs.tar.gz"])
        self.assertEqual(result["scan_report_sha256"], hashlib.sha256((self.output / "scan-report.json").read_bytes()).hexdigest())

    @patch("lab.appliance.scan_build.scan")
    def test_substituted_exports_fail_before_scanning(self, scanner):
        for name in self.exports:
            path = self.build / "export" / name
            original = path.read_bytes()
            path.write_bytes(b"substituted")
            with self.assertRaisesRegex(VerificationError, "export differs"):
                scan_build(self.build, self.root / "tools", self.output, self.commit)
            path.write_bytes(original)
        scanner.assert_not_called()

    @patch("lab.appliance.scan_build.scan")
    def test_failed_build_and_wrong_source_refuse_before_scanning(self, scanner):
        with self.assertRaises(VerificationError):
            scan_build(self.build, self.root / "tools", self.output, "b" * 40)
        self.report["status"] = "failed"
        self.write_report()
        with self.assertRaises(VerificationError):
            scan_build(self.build, self.root / "tools", self.output, self.commit)
        scanner.assert_not_called()
