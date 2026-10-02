"""Exercise release authenticity, artifact binding and scanner failure gates."""

import hashlib
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import release, scan, tools
from deploy.images.verify import VerificationError


COMMIT = "1" * 40
REF = "refs/heads/main"


def payload(root):
    directory = root / "payload"
    directory.mkdir()
    for name in release.REQUIRED:
        (directory / name).write_bytes(b"public fixture\n")
    files = release.artifact_set(directory)
    build = {"schema": "regalia.appliance-build/v1", "status": "passed", "source_commit": COMMIT,
             "disk_sha256": files["regalia-debian13-amd64.qcow2"]["sha256"],
             "export": {name: files[name]["sha256"] for name in ("rootfs.tar.gz", "regalia-kms")}}
    scanner = {"schema": "regalia.image-scan/v1", "status": "passed", "fail_on": "High",
               "rootfs_sha256": files["rootfs.tar.gz"]["sha256"], "evidence": {
                   name: files[name]["sha256"] for name in ("sbom.syft.json", "sbom.spdx.json", "sbom.cdx.json", "vulnerabilities.json")}}
    (directory / "build-report.json").write_text(json.dumps(build))
    (directory / "scan-report.json").write_text(json.dumps(scanner))
    return directory


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload = payload(self.root)
        self.manifest = self.root / "release.json"
        self.manifest.write_text(json.dumps(release.prepare(self.payload, COMMIT, REF)))

    def test_exact_artifact_set_is_bound(self):
        self.assertEqual(release.validate(self.manifest.read_bytes(), self.payload, COMMIT, REF)["status"], "verified")
        (self.payload / "extra").write_text("unreviewed")
        with self.assertRaises(VerificationError):
            release.validate(self.manifest.read_bytes(), self.payload, COMMIT, REF)

    def test_missing_or_tampered_artifact_is_rejected(self):
        for action in ("tamper", "remove"):
            with self.subTest(action=action):
                path = self.payload / "regalia-kms"
                path.write_text("changed") if action == "tamper" else path.unlink()
                with self.assertRaises(VerificationError):
                    release.validate(self.manifest.read_bytes(), self.payload, COMMIT, REF)

    def test_wrong_source_commit_is_rejected(self):
        with self.assertRaises(VerificationError):
            release.validate(self.manifest.read_bytes(), self.payload, "2" * 40, REF)

    def test_blocked_scan_cannot_be_signed_as_passed(self):
        path = self.payload / "scan-report.json"
        result = json.loads(path.read_text())
        result["status"] = "blocked"
        path.write_text(json.dumps(result))
        with self.assertRaises(VerificationError):
            release.prepare(self.payload, COMMIT, REF)

    def test_scan_for_another_filesystem_is_rejected(self):
        path = self.payload / "scan-report.json"
        result = json.loads(path.read_text())
        result["rootfs_sha256"] = "0" * 64
        path.write_text(json.dumps(result))
        with self.assertRaises(VerificationError):
            release.prepare(self.payload, COMMIT, REF)

    def test_rebuild_requires_all_exact_names_and_bytes(self):
        other = self.root / "rebuild"
        shutil.copytree(self.payload, other)
        self.assertEqual(release.compare(self.payload, other)["status"], "identical")
        (other / "regalia-kms").write_text("different build")
        with self.assertRaises(VerificationError):
            release.compare(self.payload, other)
        (other / "regalia-kms").unlink()
        with self.assertRaises(VerificationError):
            release.compare(self.payload, other)

    def test_symlink_artifact_is_rejected(self):
        path = self.payload / "regalia-kms"
        path.unlink()
        path.symlink_to(self.manifest)
        with self.assertRaises(OSError):
            release.artifact_set(self.payload)

    @patch("deploy.images.release.run", side_effect=VerificationError("invalid signature"))
    def test_signature_precedes_parsing_or_execution(self, verifier):
        self.manifest.write_text("not JSON; must never be executed")
        bundle = self.root / "bundle.json"
        bundle.write_text("proof fixture")
        with self.assertRaisesRegex(VerificationError, "invalid signature"):
            release.verify_blob(self.manifest, bundle, "https://github.com/" + release.WORKFLOW + "@" + REF,
                                "https://token.actions.githubusercontent.com", self.payload, COMMIT, REF)
        self.assertNotIn("--insecure-ignore-tlog", verifier.call_args.args[0])

    @patch("deploy.images.release.run")
    def test_unapproved_identity_rejected_before_verifier(self, verifier):
        with self.assertRaises(VerificationError):
            release.verify_blob(self.manifest, self.root / "absent", ".*", "https://token.actions.githubusercontent.com",
                                self.payload, COMMIT, REF)
        verifier.assert_not_called()

    @patch("deploy.images.release.run")
    def test_attestation_verifies_expected_source_and_subject(self, verifier):
        artifact = self.payload / "regalia-kms"
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        statement = {"predicateType": "https://slsa.dev/provenance/v1", "subject": [{"digest": {"sha256": digest}}]}
        verifier.return_value = json.dumps([{"verificationResult": {"statement": statement}}])
        self.assertEqual(release.verify_attestation(artifact, COMMIT, REF)["status"], "verified")
        command = verifier.call_args.args[0]
        for flag in ("--source-digest", "--source-ref", "--cert-identity", "--signer-workflow", "--deny-self-hosted-runners"):
            self.assertIn(flag, command)
        statement["subject"][0]["digest"]["sha256"] = "0" * 64
        verifier.return_value = json.dumps([{"verificationResult": {"statement": statement}}])
        with self.assertRaises(VerificationError):
            release.verify_attestation(artifact, COMMIT, REF)


class OfflineSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.home = Path(cls.temporary.name)
        cls.command = ["gpg", "--no-options", "--homedir", str(cls.home), "--batch", "--pinentry-mode", "loopback", "--passphrase", ""]
        subprocess.run(cls.command + ["--quick-generate-key", "lab-only@example.invalid", "ed25519", "sign", "0"],
                       check=True, capture_output=True)
        listing = subprocess.run(cls.command + ["--with-colons", "--list-keys"], check=True, capture_output=True, text=True).stdout
        cls.fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        cls.key = cls.home / "release.pub"
        cls.key.write_bytes(subprocess.run(cls.command + ["--export", cls.fingerprint], check=True, capture_output=True).stdout)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "all"], check=True)
        cls.temporary.cleanup()

    def test_real_offline_signature_and_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = payload(root)
            manifest = root / "release.json"
            manifest.write_text(json.dumps(release.prepare(directory, COMMIT, REF)))
            checksums = root / "SHA512SUMS"
            checksums.write_text(hashlib.sha512(manifest.read_bytes()).hexdigest() + "  release.json\n")
            signature = root / "SHA512SUMS.sign"
            subprocess.run(self.command + ["--output", str(signature), "--detach-sign", str(checksums)], check=True, capture_output=True)
            result = release.verify_offline(manifest, checksums, signature, self.key, self.fingerprint, directory, COMMIT, REF)
            self.assertEqual(result["offline_signer"], self.fingerprint)
            manifest.write_text(manifest.read_text() + " ")
            with self.assertRaises(VerificationError):
                release.verify_offline(manifest, checksums, signature, self.key, self.fingerprint, directory, COMMIT, REF)


class ScannerTests(unittest.TestCase):
    def test_findings_and_tool_errors_fail_closed(self):
        result = {"matches": [], "descriptor": {"db": {"status": {
            "valid": True, "built": datetime.now(timezone.utc).isoformat()}}}}
        self.assertEqual(scan.verdict(result, 0, "High"), ("passed", {}))
        with self.assertRaises(VerificationError):
            scan.verdict(result, 1, "High")
        result["matches"] = [{"vulnerability": {"severity": "High"}}]
        self.assertEqual(scan.verdict(result, 2, "High"), ("blocked", {"High": 1}))
        # Independent policy check also catches a scanner that wrongly returns 0.
        self.assertEqual(scan.verdict(result, 0, "High")[0], "blocked")
        result["descriptor"]["db"]["status"]["valid"] = False
        with self.assertRaises(VerificationError):
            scan.verdict(result, 0, "High")

    def test_archive_paths_links_duplicates_and_limits(self):
        for name, kind, expected in (("etc/os-release", "file", True), ("../outside", "file", False),
                                     ("/absolute", "file", False), ("etc/link", "link", True),
                                     ("etc/duplicate", "duplicate", False), ("etc/large", "limit", False)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive_path = root / "rootfs.tar"
                destination = root / "projection"
                destination.mkdir()
                with tarfile.open(archive_path, "w") as archive:
                    member = tarfile.TarInfo(name)
                    if kind == "link":
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/passwd"
                        archive.addfile(member)
                    else:
                        member.size = 4
                        archive.addfile(member, io.BytesIO(b"test"))
                        if kind == "duplicate":
                            archive.addfile(member, io.BytesIO(b"test"))
                if expected:
                    result = scan.project_rootfs(archive_path, destination)
                    if kind == "link":
                        self.assertEqual(result["skipped"], {"links": 1})
                        self.assertFalse((destination / name).exists())
                else:
                    with self.assertRaises((VerificationError, FileExistsError)):
                        scan.project_rootfs(archive_path, destination, limit=3 if kind == "limit" else 100)

    def test_signed_checksum_requires_unique_exact_artifact(self):
        digest = "1" * 64
        self.assertEqual(tools.checksum((digest + "  syft.tar.gz\n").encode(), "syft.tar.gz"), digest)
        for content in (digest + "  ../syft.tar.gz\n", (digest + "  syft.tar.gz\n") * 2, digest + "  other.tar.gz\n"):
            with self.assertRaises(VerificationError):
                tools.checksum(content.encode(), "syft.tar.gz")


class ScannerInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "installed"
        self.policy = self.root / "policy.json"
        self.document = json.loads(tools.POLICY.read_text())
        self.downloads = []
        self.archive = io.BytesIO()
        with tarfile.open(fileobj=self.archive, mode="w:gz") as archive:
            member = tarfile.TarInfo("syft")
            member.size = len(b"verified binary fixture")
            archive.addfile(member, io.BytesIO(b"verified binary fixture"))
        self.archive_data = self.archive.getvalue()
        self.digest = hashlib.sha256(self.archive_data).hexdigest()
        self.document["tools"]["syft"]["archives"]["linux_amd64"] = self.digest
        self.policy.write_text(json.dumps(self.document))

    def download(self, url, destination, limit):
        self.downloads.append(destination.name)
        if destination.name.endswith("checksums.txt"):
            name = "syft_1.54.0_linux_amd64.tar.gz"
            destination.write_text(self.digest + "  " + name + "\n")
        elif destination.name.endswith(".tar.gz"):
            destination.write_bytes(self.archive_data)
        else:
            destination.write_text("signature fixture")

    @patch("deploy.images.tools.run", side_effect=VerificationError("wrong publisher"))
    def test_bad_publisher_aborts_before_archive_download(self, verifier):
        with patch("deploy.images.tools.download", side_effect=self.download):
            with self.assertRaisesRegex(VerificationError, "wrong publisher"):
                tools.install(self.output, self.policy, "linux_amd64")
        self.assertFalse(self.output.exists())
        self.assertFalse(any(name.endswith(".tar.gz") for name in self.downloads))
        self.assertFalse(list(self.root.glob(".verified-scanners-*")))

    @patch("deploy.images.tools.run", return_value="Verified OK")
    def test_tampered_archive_cannot_install(self, verifier):
        self.archive_data = b"tampered archive"
        with patch("deploy.images.tools.download", side_effect=self.download):
            with self.assertRaisesRegex(VerificationError, "checksum mismatch"):
                tools.install(self.output, self.policy, "linux_amd64")
        self.assertFalse(self.output.exists())

    @patch("deploy.images.tools.run", return_value="Verified OK")
    def test_changed_reviewed_pin_rejects_signed_checksum(self, verifier):
        self.document["tools"]["syft"]["archives"]["linux_amd64"] = "0" * 64
        self.policy.write_text(json.dumps(self.document))
        with patch("deploy.images.tools.download", side_effect=self.download):
            with self.assertRaisesRegex(VerificationError, "reviewed digest"):
                tools.install(self.output, self.policy, "linux_amd64")
        self.assertFalse(self.output.exists())

    def test_modified_installed_executable_is_rejected(self):
        directory = self.root / "installed"
        (directory / "syft").mkdir(parents=True)
        (directory / "syft/bin").write_bytes(b"tampered executable")
        report = {"status": "verified", "policy_sha256": hashlib.sha256(tools.POLICY.read_bytes()).hexdigest(),
                  "tools": {"syft": {"version": "1.54.0", "binary_sha256": "0" * 64}}}
        (directory / "verification.json").write_text(json.dumps(report))
        with self.assertRaisesRegex(VerificationError, "executable changed"):
            tools.verified_executable(directory, "syft")
