"""Triage is a bound diagnostic, never authority to suppress scanner findings."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import triage
from deploy.images.verify import VerificationError


def package(identifier="a", name="libexample1", source="example", version="1:2.0-1", **metadata):
    return {"id": identifier, "name": name, "version": version, "type": "deb",
            "metadata": {"source": source, **metadata}}


def match(artifact, cve="CVE-2026-10000"):
    return {"artifact": artifact, "vulnerability": {"id": cve, "severity": "High",
            "namespace": "debian:distro:debian:13", "fix": {"state": "wont-fix"}}}


def inventory(packages):
    return {"artifacts": packages, "distro": {"id": "debian", "versionID": "13.7"}}


class TriageTests(unittest.TestCase):
    def test_real_dpkg_epoch_tilde_and_debian_revision_comparison(self):
        self.assertTrue(triage.at_least("1:2.0-1", "9.0-1"))
        self.assertFalse(triage.at_least("2.0~rc1-1", "2.0-1"))
        self.assertTrue(triage.at_least("2.0-1+deb13u2", "2.0-1+deb13u1"))
        for invalid in ("--help", "1.0\n2.0", "1.0;id", ""):
            with self.assertRaises(VerificationError):
                triage.at_least(invalid, "1.0")

    @patch("deploy.images.triage.subprocess.run")
    def test_version_tool_error_is_not_a_false_comparison(self, run):
        run.return_value = subprocess.CompletedProcess([], 2, b"", b"failure")
        with self.assertRaises(VerificationError):
            triage.at_least("8.888-1", "8.888-2")

    def test_repeated_binary_matches_group_by_source_without_waivers(self):
        packages = [package(), package("b", "libexample2")]
        tracker = {"example": {"CVE-2026-10000": {"releases": {"trixie": {
            "status": "open", "urgency": "unimportant", "nodsa": "Minor issue"}}}}}
        result = triage.summarize(inventory(packages), {"matches": [match(p) for p in packages]}, tracker)
        self.assertEqual(result["blocking_matches"], 2)
        self.assertEqual(result["unique_cves"], 1)
        self.assertEqual(result["review_groups"], 1)
        self.assertEqual(result["classification_matches"], {"vendor-open": 2})
        self.assertEqual(result["waivers"], [])
        self.assertFalse(result["production_approved"])

    def test_source_version_and_installed_fix_are_compared(self):
        artifact = package(version="2:99.0-1", sourceVersion="1.0-1")
        tracker = {"example": {"CVE-2026-10000": {"releases": {"trixie": {
            "status": "resolved", "fixed_version": "1.0-2"}}}}}
        result = triage.summarize(inventory([artifact]), {"matches": [match(artifact)]}, tracker)
        self.assertEqual(result["classification_matches"], {"update-required": 1})
        artifact["metadata"]["sourceVersion"] = "1.0-3"
        result = triage.summarize(inventory([artifact]), {"matches": [match(artifact)]}, tracker)
        self.assertEqual(result["classification_matches"], {"vendor-fixed-candidate": 1})
        self.assertEqual(result["status"], "review-required")

    def test_unknown_record_is_preserved_and_never_classified_safe(self):
        artifact = package()
        result = triage.summarize(inventory([artifact]), {"matches": [match(artifact)]}, {})
        self.assertEqual(result["classification_matches"], {"tracker-unknown": 1})
        self.assertEqual(result["blocking_matches"], 1)

    def test_kernel_mapping_requires_unique_exact_file_owner(self):
        kernel = {"id": "kernel", "name": "linux-kernel", "version": "6.12.111+deb13-amd64",
                  "type": "linux-kernel", "locations": [{"path": "/boot/vmlinuz-6.12.111+deb13-amd64"}]}
        owner = package("owner", "linux-image-6.12.111+deb13-amd64", "linux-signed-amd64", "6.12.111-1",
                        sourceVersion="6.12.111+1", files=[{"path": kernel["locations"][0]["path"]}])
        self.assertEqual(triage.source_identity(kernel, [kernel, owner]),
                         ("linux", "6.12.111-1", "kernel-package-ownership-candidate"))
        self.assertEqual(triage.source_identity(kernel, [kernel, owner, owner])[2], "unmapped")
        owner["metadata"]["files"] = [{"path": "/wrong"}]
        self.assertEqual(triage.source_identity(kernel, [kernel, owner])[2], "unmapped")

    def test_missing_duplicate_or_mismatched_artifact_is_rejected(self):
        artifact = package()
        for packages, finding in (([], match(artifact)), ([artifact, artifact], match(artifact)),
                                  ([artifact], match({**artifact, "version": "9.0"}))):
            with self.subTest(packages=packages), self.assertRaises(VerificationError):
                triage.summarize(inventory(packages), {"matches": [finding]}, {})

    def test_bound_evidence_and_existing_output_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            artifact = package()
            values = {"sbom.syft.json": inventory([artifact]), "vulnerabilities.json": {"matches": [match(artifact)]}}
            hashes = {}
            for name, value in values.items():
                data = json.dumps(value).encode()
                (evidence / name).write_bytes(data)
                hashes[name] = hashlib.sha256(data).hexdigest()
            scan = {"schema": "regalia.image-scan/v1", "status": "blocked", "rootfs_sha256": "1" * 64,
                    "evidence": hashes}
            scan_path = evidence / "scan-report.json"
            scan_path.write_text(json.dumps(scan))
            tracker = root / "tracker.json"
            tracker.write_text("{}")
            output = root / "review"
            result = triage.triage(evidence, output, tracker)
            self.assertEqual(result["scan_status"], "blocked")
            self.assertEqual(result["tracker"]["authentication"], "operator-supplied")
            self.assertEqual(json.loads(scan_path.read_text()), scan)
            with self.assertRaises(VerificationError):
                triage.triage(evidence, output, tracker)
            (evidence / "sbom.syft.json").write_text("{}")
            with self.assertRaisesRegex(VerificationError, "hash mismatch"):
                triage.triage(evidence, root / "mismatched", tracker)
            self.assertFalse((root / "mismatched").exists())

    @patch("deploy.images.triage.download", side_effect=OSError("HTTPS failure"))
    def test_tracker_download_failure_does_not_publish_review(self, download):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            hashes = {}
            for name in ("sbom.syft.json", "vulnerabilities.json"):
                (evidence / name).write_text("{}")
                hashes[name] = hashlib.sha256(b"{}").hexdigest()
            (evidence / "scan-report.json").write_text(json.dumps({"schema": "regalia.image-scan/v1",
                "status": "blocked", "evidence": hashes}))
            with self.assertRaises(OSError):
                triage.triage(evidence, root / "review")
            self.assertFalse((root / "review").exists())
            self.assertFalse(list(root.glob(".image-triage-*")))


if __name__ == "__main__":
    unittest.main()
