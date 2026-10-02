"""Real GnuPG signatures exercise the image-consumption trust boundary."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import fetch_debian, verify


class GPGImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("gpg") is None:
            raise RuntimeError("image verification tests require GnuPG; missing tools must fail CI")
        cls.directory = tempfile.TemporaryDirectory(prefix="regalia-signature-tests-")
        cls.home = Path(cls.directory.name)
        cls.gpg = ["gpg", "--no-options", "--homedir", str(cls.home), "--batch",
                   "--pinentry-mode", "loopback", "--passphrase", ""]
        for name in ("release", "attacker"):
            cls.execute(["--quick-generate-key", f"{name}@example.invalid", "ed25519", "sign", "0"])
        listing = cls.execute(["--with-colons", "--list-keys"])
        cls.fingerprints = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")]
        cls.key = cls.home / "release.pub"
        cls.key.write_bytes(subprocess.run(cls.gpg + ["--export", cls.fingerprints[0]],
                                           check=True, capture_output=True).stdout)

    @classmethod
    def execute(cls, args):
        return subprocess.run(cls.gpg + args, check=True, capture_output=True, text=True).stdout

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--homedir", str(cls.home), "--kill", "all"], check=True)
        cls.directory.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.image = self.root / "appliance.raw"
        self.image.write_bytes(b"uncommissioned image fixture\n")
        self.manifest = self.root / "SHA512SUMS"
        self.signature = self.root / "SHA512SUMS.sign"
        self.digest = hashlib.sha512(self.image.read_bytes()).hexdigest()
        self.sign(f"{self.digest}  {self.image.name}\n")

    def sign(self, contents, *, signer=0, extra=()):
        self.manifest.write_text(contents, encoding="ascii")
        self.execute(["--yes", "--local-user", self.fingerprints[signer] + "!", *extra,
                      "--output", str(self.signature), "--detach-sign", str(self.manifest)])

    def check(self, **changes):
        args = dict(image=self.image, manifest=self.manifest, signature=self.signature,
                    key=self.key, fingerprint=self.fingerprints[0])
        args.update(changes)
        return verify.verify_gpg(**args)

    def test_valid_image_and_binary_checksum_marker(self):
        report = self.check()
        self.assertEqual(report["status"], "verified")
        self.assertEqual(report["digest"], self.digest)
        self.assertEqual(report["primary_fingerprint"], self.fingerprints[0])
        self.sign(f"{self.digest} *{self.image.name}\n")
        self.assertEqual(self.check()["status"], "verified")

    def test_wrong_signer_and_wrong_key_pin(self):
        with self.assertRaisesRegex(verify.VerificationError, "fingerprint"):
            self.check(fingerprint=self.fingerprints[1])
        self.sign(f"{self.digest}  {self.image.name}\n", signer=1)
        with self.assertRaises(verify.VerificationError):
            self.check()

    def test_modified_image_and_manifest(self):
        self.image.write_bytes(b"corrupt")
        with self.assertRaisesRegex(verify.VerificationError, "checksum mismatch"):
            self.check()
        self.manifest.write_text(f"{'0' * 128}  {self.image.name}\n")
        with self.assertRaises(verify.VerificationError):
            self.check()

    def test_ambiguous_missing_and_unsafe_entries(self):
        for contents in (f"{self.digest}  appliance.raw\n" * 2,
                         f"{self.digest}  other.raw\n",
                         f"{self.digest}  ../appliance.raw\n", "nonsense\n", ""):
            with self.subTest(contents=contents):
                self.sign(contents)
                with self.assertRaises(verify.VerificationError):
                    self.check()

    def test_missing_proof_and_symlink_image(self):
        self.signature.unlink()
        with self.assertRaises(OSError):
            self.check()
        self.sign(f"{self.digest}  appliance.raw\n")
        target = self.root / "target"
        self.image.rename(target)
        self.image.symlink_to(target)
        with self.assertRaises(OSError):
            self.check()

    def test_short_fingerprint_and_weak_signature_digest(self):
        with self.assertRaisesRegex(verify.VerificationError, "full uppercase"):
            self.check(fingerprint=self.fingerprints[0][-16:])
        self.sign(f"{self.digest}  appliance.raw\n", extra=("--digest-algo", "SHA1"))
        with self.assertRaises(verify.VerificationError):
            self.check()

    def test_signed_manifest_cannot_hide_an_extra_public_key(self):
        bundle = self.root / "bundle.pub"
        bundle.write_bytes(subprocess.run(self.gpg + ["--export"], check=True, capture_output=True).stdout)
        with self.assertRaisesRegex(verify.VerificationError, "fingerprint"):
            self.check(key=bundle)

    def test_multiple_signatures_are_not_ambiguous_authorization(self):
        self.signature.write_bytes(self.signature.read_bytes() * 2)
        with self.assertRaisesRegex(verify.VerificationError, "exactly one"):
            self.check()

    def test_signing_subkey_is_bound_to_approved_primary(self):
        self.execute(["--quick-add-key", self.fingerprints[0], "ed25519", "sign", "0"])
        listing = self.execute(["--with-colons", "--list-keys", self.fingerprints[0]])
        subkey = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")][-1]
        key = self.root / "with-subkey.pub"
        key.write_bytes(subprocess.run(self.gpg + ["--export", self.fingerprints[0]],
                                       check=True, capture_output=True).stdout)
        self.execute(["--yes", "--local-user", subkey + "!", "--output", str(self.signature),
                      "--detach-sign", str(self.manifest)])
        self.assertEqual(self.check(key=key)["signing_fingerprint"], subkey)

    def test_expired_signing_key_is_rejected(self):
        expired_home = self.root / "expired-home"
        expired_home.mkdir(mode=0o700)
        command = ["gpg", "--no-options", "--homedir", str(expired_home), "--batch",
                   "--pinentry-mode", "loopback", "--passphrase", "", "--faked-system-time", "1577836800"]
        try:
            subprocess.run(command + ["--quick-generate-key", "expired@example.invalid", "ed25519", "sign", "1d"],
                           check=True, capture_output=True)
            listing = subprocess.run(command + ["--with-colons", "--list-keys"], check=True, capture_output=True,
                                     text=True).stdout
            fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
            key = self.root / "expired.pub"
            key.write_bytes(subprocess.run(command + ["--export"], check=True, capture_output=True).stdout)
            subprocess.run(command + ["--output", str(self.root / "expired.sig"), "--detach-sign", str(self.manifest)],
                           check=True, capture_output=True)
            with self.assertRaises(verify.VerificationError):
                self.check(key=key, fingerprint=fingerprint, signature=self.root / "expired.sig")
        finally:
            subprocess.run(["gpgconf", "--homedir", str(expired_home), "--kill", "all"], check=True)

    def media_fixture(self):
        policy = json.loads((Path(__file__).parents[1] / "deploy/images/debian-policy.json").read_text())
        policy["primary_fingerprint"] = self.fingerprints[0]
        policy_path = self.root / "policy.json"
        policy_path.write_text(json.dumps(policy))
        self.sign(f"{self.digest}  {policy['image']}\n")
        files = {policy["image"]: self.image.read_bytes(), "SHA512SUMS": self.manifest.read_bytes(),
                 "SHA512SUMS.sign": self.signature.read_bytes()}

        def downloader(url, path, limit):
            path.write_bytes(self.key.read_bytes() if url == policy["key_url"] else files[url.rsplit("/", 1)[1]])
        return policy_path, downloader

    def test_fetch_publishes_only_verified_media_and_refuses_existing_output(self):
        policy, downloader = self.media_fixture()
        destination = self.root / "verified"
        with patch.object(fetch_debian, "download", side_effect=downloader):
            report = fetch_debian.fetch(destination, policy)
            self.assertEqual(report["status"], "verified")
            self.assertEqual(json.loads((destination / "verification.json").read_text()), report)
            with self.assertRaisesRegex(verify.VerificationError, "already exists"):
                fetch_debian.fetch(destination, policy)

    def test_failed_download_or_tampering_publishes_nothing(self):
        policy, downloader = self.media_fixture()
        destination = self.root / "verified"
        with patch.object(fetch_debian, "download", side_effect=OSError("network failure")):
            with self.assertRaises(OSError):
                fetch_debian.fetch(destination, policy)

        def corrupt(url, path, limit):
            downloader(url, path, limit)
            if path.suffix == ".iso":
                path.write_bytes(b"corrupt")
        with patch.object(fetch_debian, "download", side_effect=corrupt):
            with self.assertRaisesRegex(verify.VerificationError, "checksum mismatch"):
                fetch_debian.fetch(destination, policy)
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.root.glob(".regalia-media-*")))


class OCIVerificationTests(unittest.TestCase):
    reference = "registry.example.invalid/kms@sha256:" + "a" * 64

    def payload(self, digest=None):
        return json.dumps([{"critical": {"image": {"docker-manifest-digest": digest or "sha256:" + "a" * 64},
                                          "type": "cosign container image signature"}}])

    def check(self):
        return verify.verify_oci(self.reference, identity="release@example.invalid",
                                 issuer="https://issuer.example.invalid")

    def test_exact_identity_digest_and_safe_cosign_options(self):
        with patch.object(verify, "run", return_value=self.payload()) as command:
            self.assertEqual(self.check()["status"], "verified")
        argv = command.call_args.args[0]
        self.assertIn("--certificate-identity", argv)
        self.assertIn("--certificate-oidc-issuer", argv)
        self.assertEqual(argv[-1], self.reference)
        self.assertFalse(any("insecure" in flag or "ignore" in flag or "regexp" in flag for flag in argv))

    def test_tag_only_missing_identity_empty_or_wrong_claims_fail(self):
        with self.assertRaises(verify.VerificationError):
            verify.verify_oci("debian:trixie")
        with self.assertRaises(verify.VerificationError):
            verify.verify_oci(self.reference)
        for output in ("[]", "{}", "garbage", self.payload("sha256:" + "b" * 64)):
            with self.subTest(output=output), patch.object(verify, "run", return_value=output):
                with self.assertRaises(verify.VerificationError):
                    self.check()

    def test_cosign_failure_cannot_become_a_checksum_only_success(self):
        with patch.object(verify, "run", side_effect=verify.VerificationError("unsigned")):
            with self.assertRaises(verify.VerificationError):
                self.check()

    def test_public_key_is_pinned_before_cosign(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "cosign.pub"
            key.write_bytes(b"public key fixture")
            with self.assertRaisesRegex(verify.VerificationError, "pin mismatch"):
                verify.verify_oci(self.reference, key=key, key_sha256="0" * 64)
            with patch.object(verify, "run", return_value=self.payload()):
                self.assertEqual(verify.verify_oci(self.reference, key=key,
                                 key_sha256=hashlib.sha256(key.read_bytes()).hexdigest())["status"], "verified")
