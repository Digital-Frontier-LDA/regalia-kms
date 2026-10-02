#!/usr/bin/env python3
"""Authenticate image manifests with GnuPG and OCI digests with Cosign."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


class VerificationError(ValueError):
    """No artifact may be consumed after this error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def run(command: list[str], *, timeout: int = 120) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f"{command[0]} verification operation failed")
    return result.stdout


def read_regular(path: Path, limit: int = 4 * 1024 * 1024) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), "input must be a regular file")
        data = handle.read(limit + 1)
    require(len(data) <= limit, "verification metadata exceeds size limit")
    return data


def hash_regular(path: Path, algorithm: str) -> tuple[str, int]:
    digest = hashlib.new(algorithm)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode), "image must be a regular file")
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(handle.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "image changed during verification")
    return digest.hexdigest(), before.st_size


def verify_gpg(image: Path, manifest: Path, signature: Path, key: Path,
               fingerprint: str, algorithm: str = "sha512") -> dict:
    require(re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}", fingerprint) is not None,
            "a full uppercase signing-key fingerprint is required")
    require(algorithm in {"sha256", "sha512"}, "only SHA-256 and SHA-512 are supported")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", image.name) is not None,
            "unsafe image basename")
    # Verify private copies: concurrent replacement of metadata cannot change the
    # data parsed after its signature has been checked. Never consult ambient trust.
    signed_data = read_regular(manifest)
    key_data, signature_data = read_regular(key), read_regular(signature)
    with tempfile.TemporaryDirectory(prefix="regalia-image-gpg-") as directory:
        home = Path(directory)
        copies = {"key": key_data, "signature": signature_data, "manifest": signed_data}
        for name, data in copies.items():
            (home / name).write_bytes(data)
        gpg = ["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-autostart",
               "--no-auto-key-retrieve", "--auto-key-locate", "clear"]
        run(gpg + ["--import", str(home / "key")])
        listing = run(gpg + ["--with-colons", "--fingerprint", "--list-keys"])
        primary = []
        is_primary = False
        for line in listing.splitlines():
            fields = line.split(":")
            if fields[0] in {"pub", "sub"}:
                is_primary = fields[0] == "pub"
            elif fields[0] == "fpr" and is_primary:
                primary.append(fields[9])
                is_primary = False
        require(primary == [fingerprint], "public key does not match the approved primary fingerprint")
        status = run(gpg + ["--status-fd", "1", "--verify",
                            str(home / "signature"), str(home / "manifest")])
        records = [line.split()[1:] for line in status.splitlines() if line.startswith("[GNUPG:] ")]
        forbidden = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG",
                     "KEYEXPIRED", "SIGEXPIRED", "FAILURE"}
        require(not any(record[0] in forbidden for record in records), "unacceptable GPG signature status")
        valid = [record for record in records if record[0] == "VALIDSIG"]
        require(len(valid) == 1 and len(valid[0]) in {10, 11}, "exactly one valid signature is required")
        record = valid[0]
        require((record[10] if len(record) == 11 else record[1]) == fingerprint,
                "signature is not from the approved primary key")
        require(record[8] in {"8", "9", "10"}, "weak signature digest rejected")
        signing_fingerprint = record[1]
    try:
        lines = signed_data.decode("ascii").splitlines()
    except UnicodeError as error:
        raise VerificationError("checksum manifest must be ASCII") from error
    size = hashlib.new(algorithm).digest_size * 2
    checksums = {}
    for line in lines:
        match = re.fullmatch(r"([a-fA-F0-9]{" + str(size) + r"}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        require(match is not None, "malformed or unsafe checksum manifest entry")
        checksum, name = match.groups()
        require(name not in checksums, "duplicate checksum manifest entry")
        checksums[name] = checksum.lower()
    require(image.name in checksums, "image is absent from authenticated checksum manifest")
    actual, byte_count = hash_regular(image, algorithm)
    require(actual == checksums[image.name], "image checksum mismatch")
    return {"schema": "regalia.image-verification/v1", "status": "verified",
            "method": "gpg-signed-checksum", "image": image.name,
            "algorithm": algorithm, "digest": actual, "bytes": byte_count,
            "primary_fingerprint": fingerprint, "signing_fingerprint": signing_fingerprint,
            "manifest_sha256": hashlib.sha256(signed_data).hexdigest(),
            "signature_sha256": hashlib.sha256(signature_data).hexdigest()}


def verify_oci(reference: str, *, key: Path | None = None,
               key_sha256: str | None = None, identity: str | None = None,
               issuer: str | None = None) -> dict:
    require(re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[a-f0-9]{64}", reference) is not None
            and "://" not in reference, "OCI reference must include an immutable SHA-256 digest")
    command = ["cosign", "verify", "--output", "json"]
    with tempfile.TemporaryDirectory(prefix="regalia-image-cosign-") as directory:
        if key is not None:
            require(identity is None and issuer is None, "choose a public key or an exact identity/issuer")
            require(isinstance(key_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", key_sha256) is not None,
                    "Cosign public key requires a SHA-256 pin")
            key_data = read_regular(key)
            require(hashlib.sha256(key_data).hexdigest() == key_sha256, "Cosign public key pin mismatch")
            key_copy = Path(directory) / "cosign.pub"
            key_copy.write_bytes(key_data)
            command += ["--key", str(key_copy)]
            authority = {"public_key_sha256": key_sha256}
        else:
            require(key_sha256 is None and isinstance(identity, str) and bool(identity)
                    and isinstance(issuer, str) and issuer.startswith("https://"),
                    "Cosign requires an exact certificate identity and HTTPS OIDC issuer")
            command += ["--certificate-identity", identity, "--certificate-oidc-issuer", issuer]
            authority = {"certificate_identity": identity, "oidc_issuer": issuer}
        # Never disable claim checks, Rekor verification or certificate validation.
        try:
            payloads = json.loads(run(command + [reference], timeout=180))
        except json.JSONDecodeError as error:
            raise VerificationError("Cosign returned invalid verification evidence") from error
    require(isinstance(payloads, list) and bool(payloads), "Cosign returned no verified signatures")
    digest = reference.rsplit("@", 1)[1]
    for payload in payloads:
        require(isinstance(payload, dict), "invalid Cosign payload")
        critical = payload.get("critical", {})
        require(isinstance(critical, dict) and isinstance(critical.get("image"), dict)
                and critical["image"].get("docker-manifest-digest") == digest
                and critical.get("type") == "cosign container image signature",
                "verified Cosign claims do not bind the requested image digest")
    return {"schema": "regalia.image-verification/v1", "status": "verified",
            "method": "cosign", "image": reference, "digest": digest,
            "verified_signatures": len(payloads), "authority": authority}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    gpg = modes.add_parser("gpg")
    for flag in ("image", "manifest", "signature", "key"):
        gpg.add_argument("--" + flag, required=True, type=Path)
    gpg.add_argument("--fingerprint", required=True)
    gpg.add_argument("--algorithm", choices=("sha256", "sha512"), default="sha512")
    oci = modes.add_parser("oci")
    oci.add_argument("reference")
    oci.add_argument("--key", type=Path)
    oci.add_argument("--key-sha256")
    oci.add_argument("--identity")
    oci.add_argument("--issuer")
    args = vars(parser.parse_args())
    mode = args.pop("mode")
    try:
        report = verify_gpg(**args) if mode == "gpg" else verify_oci(**args)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
