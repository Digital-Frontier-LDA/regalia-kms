"""Bind exact artifact sets to authenticated release manifests and provenance."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from .verify import VerificationError, hash_regular, read_regular, require, run, verify_gpg


REPOSITORY = "Digital-Frontier-LDA/regalia-kms"
WORKFLOW = REPOSITORY + "/.github/workflows/appliance.yml"
REQUIRED = {"regalia-debian13-amd64.qcow2", "rootfs.tar.gz", "regalia-kms", "build-report.json",
            "scan-report.json", "sbom.syft.json", "sbom.spdx.json", "sbom.cdx.json", "vulnerabilities.json"}
REQUIRED.add("sbom.attestation.spdx.json")


def artifact_set(directory: Path) -> dict:
    require(directory.is_dir() and not directory.is_symlink(), "artifact directory must be private and regular")
    result = {}
    for path in sorted(directory.iterdir()):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", path.name) is not None, "unsafe artifact name")
        digest, size = hash_regular(path, "sha256")
        result[path.name] = {"sha256": digest, "bytes": size}
    require(bool(result), "artifact set is empty")
    return result


def compare(first: Path, second: Path) -> dict:
    left, right = artifact_set(first), artifact_set(second)
    require(left == right, "rebuild artifact names or bytes differ")
    return {"schema": "regalia.rebuild/v1", "status": "identical", "artifacts": left}


def source(commit: str, ref: str):
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "full source commit required")
    require(re.fullmatch(r"refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*", ref) is not None
            and ".." not in ref, "explicit source branch or tag required")


def prepare(directory: Path, commit: str, ref: str) -> dict:
    source(commit, ref)
    files = artifact_set(directory)
    require(REQUIRED <= files.keys(), "required appliance evidence is missing")
    build = json.loads(read_regular(directory / "build-report.json"))
    scan = json.loads(read_regular(directory / "scan-report.json"))
    require(build.get("schema") == "regalia.appliance-build/v1" and build.get("status") == "passed"
            and build.get("source_commit") == commit, "appliance build did not pass for this source")
    require(scan.get("schema") == "regalia.image-scan/v1" and scan.get("status") == "passed"
            and scan.get("fail_on") in {"Medium", "High"}, "vulnerability gate did not pass")
    require(build.get("disk_sha256") == files["regalia-debian13-amd64.qcow2"]["sha256"], "build evidence does not bind this disk")
    require(isinstance(build.get("export"), dict) and all(
        build["export"].get(name) == files[name]["sha256"] for name in ("rootfs.tar.gz", "regalia-kms")),
        "build evidence does not bind this filesystem and executable")
    require(scan.get("rootfs_sha256") == files["rootfs.tar.gz"]["sha256"], "scan evidence does not bind this filesystem")
    require(isinstance(scan.get("evidence"), dict) and
            {"sbom.syft.json", "sbom.spdx.json", "sbom.attestation.spdx.json", "sbom.cdx.json", "vulnerabilities.json"} <= scan["evidence"].keys(),
            "scan evidence is incomplete")
    for name, digest in scan["evidence"].items():
        require(name in files and files[name]["sha256"] == digest, "scan evidence artifact differs")
    return {"schema": "regalia.appliance-release/v1", "repository": REPOSITORY,
            "source_commit": commit, "source_ref": ref, "artifacts": files,
            "evidence_class": "emulated", "production_approved": False,
            "limitations": ["Hardware commissioning is required", "Disk reproducibility is not established"]}


def validate(data: bytes, directory: Path, commit: str, ref: str) -> dict:
    source(commit, ref)
    manifest = json.loads(data)
    require(manifest.get("schema") == "regalia.appliance-release/v1"
            and manifest.get("repository") == REPOSITORY and manifest.get("source_commit") == commit
            and manifest.get("source_ref") == ref, "release source identity differs from expected policy")
    require(manifest.get("production_approved") is False, "prototype manifest misstates production status")
    require(manifest.get("artifacts") == artifact_set(directory), "release artifact set differs from signed manifest")
    # Do not accept a correctly signed manifest with failed/missing build evidence.
    prepared = prepare(directory, commit, ref)
    require(prepared["artifacts"] == manifest["artifacts"], "release evidence mismatch")
    return {"schema": "regalia.release-verification/v1", "status": "verified", "source_commit": commit,
            "source_ref": ref, "artifacts": manifest["artifacts"], "production_approved": False}


def verify_blob(manifest: Path, bundle: Path, identity: str, issuer: str, directory: Path,
                commit: str, ref: str) -> dict:
    require(identity == f"https://github.com/{WORKFLOW}@{ref}", "unexpected release signing workflow")
    require(issuer == "https://token.actions.githubusercontent.com", "unexpected release signing issuer")
    data = read_regular(manifest)
    with tempfile.TemporaryDirectory(prefix="regalia-release-verification-") as temporary:
        copied, proof = Path(temporary) / "release.json", Path(temporary) / "bundle.json"
        copied.write_bytes(data)
        proof.write_bytes(read_regular(bundle, 16 * 1024 ** 2))
        run(["cosign", "verify-blob", str(copied), "--bundle", str(proof),
             "--certificate-identity", identity, "--certificate-oidc-issuer", issuer], timeout=180)
    # Parse build claims only AFTER signature/certificate/transparency verification.
    return validate(data, directory, commit, ref)


def verify_offline(manifest: Path, checksums: Path, signature: Path, key: Path,
                   fingerprint: str, directory: Path, commit: str, ref: str) -> dict:
    data = read_regular(manifest)
    with tempfile.TemporaryDirectory(prefix="regalia-release-offline-") as temporary:
        copied = Path(temporary) / manifest.name
        copied.write_bytes(data)
        proof = verify_gpg(copied, checksums, signature, key, fingerprint)
    result = validate(data, directory, commit, ref)
    result["offline_signer"] = proof["primary_fingerprint"]
    return result


def verify_attestation(artifact: Path, commit: str, ref: str, bundle: Path | None = None,
                       sbom: Path | None = None) -> dict:
    source(commit, ref)
    predicate_type = "https://spdx.dev/Document/v2.3" if sbom is not None else "https://slsa.dev/provenance/v1"
    command = ["gh", "attestation", "verify", str(artifact), "--repo", REPOSITORY,
               "--signer-workflow", WORKFLOW, "--cert-identity", f"https://github.com/{WORKFLOW}@{ref}",
               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
               "--source-digest", commit, "--source-ref", ref, "--deny-self-hosted-runners",
               "--predicate-type", predicate_type, "--format", "json"]
    if bundle is not None:
        command += ["--bundle", str(bundle)]
    results = json.loads(run(command, timeout=180))
    require(isinstance(results, list) and bool(results), "no verified provenance returned")
    expected_sbom = json.loads(read_regular(sbom, 16 * 1024 ** 2)) if sbom is not None else None
    if expected_sbom is not None:
        require(expected_sbom.get("spdxVersion") == "SPDX-2.3", "unsupported SBOM attestation format")
    digest, _ = hash_regular(artifact, "sha256")
    for result in results:
        statement = result.get("verificationResult", {}).get("statement", {})
        require(statement.get("predicateType") == predicate_type
                and any(subject.get("digest", {}).get("sha256") == digest for subject in statement.get("subject", [])),
                "verified provenance does not bind this artifact")
        if expected_sbom is not None:
            require(statement.get("predicate") == expected_sbom, "attested SBOM differs from released SBOM")
    return {"schema": "regalia.attestation-verification/v1", "status": "verified", "sha256": digest,
            "source_commit": commit, "source_ref": ref, "predicate_type": predicate_type,
            "verified_attestations": len(results)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    prep = modes.add_parser("prepare")
    prep.add_argument("artifacts", type=Path)
    prep.add_argument("--output", type=Path, required=True)
    comparison = modes.add_parser("compare")
    comparison.add_argument("first", type=Path)
    comparison.add_argument("second", type=Path)
    verify = modes.add_parser("verify")
    verify.add_argument("artifacts", type=Path)
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--identity", required=True)
    verify.add_argument("--issuer", required=True)
    offline = modes.add_parser("verify-offline")
    offline.add_argument("artifacts", type=Path)
    for field in ("manifest", "checksums", "signature", "key"):
        offline.add_argument("--" + field, type=Path, required=True)
    offline.add_argument("--fingerprint", required=True)
    attest = modes.add_parser("verify-attestation")
    attest.add_argument("artifact", type=Path)
    attest.add_argument("--bundle", type=Path)
    attest.add_argument("--sbom", type=Path, help="verify an SPDX 2.3 attestation and its exact released SBOM")
    for mode in (prep, verify, offline, attest):
        mode.add_argument("--commit", required=True)
        mode.add_argument("--ref", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "prepare":
            result = prepare(args.artifacts, args.commit, args.ref)
            with args.output.open("x") as handle:
                json.dump(result, handle, sort_keys=True, indent=2)
                handle.write("\n")
        elif args.mode == "compare":
            result = compare(args.first, args.second)
        elif args.mode == "verify":
            result = verify_blob(args.manifest, args.bundle, args.identity, args.issuer, args.artifacts, args.commit, args.ref)
        elif args.mode == "verify-offline":
            result = verify_offline(args.manifest, args.checksums, args.signature, args.key, args.fingerprint,
                                    args.artifacts, args.commit, args.ref)
        else:
            result = verify_attestation(args.artifact, args.commit, args.ref, args.bundle, args.sbom)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
