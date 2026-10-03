"""Authenticate the reviewed TPM source bundle through Debian's signed archive.

This downloads public source inputs only. It does not build, install, sign or
approve a package, and does not treat a maintainer's .dsc signature as verified.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .fetch_debian import download
from .snapshot import ARCHIVES, POLICY, archive_url, fields, policy, verify_release
from .verify import VerificationError, read_regular, require

PACKAGE = "tpm2-tools"
VERSION = "5.7-1"
FILES = {
    "tpm2-tools_5.7-1.dsc": ("d0d0d9ea97195214c44a54442ae1680677ca23bacf9c97858dbf0ce26992a2fe", 2193),
    "tpm2-tools_5.7.orig.tar.gz": ("714912361fddbd7e01473be9065b2949b5ad2f5dff80063648f00f4eaf38971b", 784535),
    "tpm2-tools_5.7-1.debian.tar.xz": ("fa85351716424934be848c18863eac785d71f90dc1e9857adc20aaaf39cf03c6", 18468),
}
INDEX = "main/source/Sources.xz"


def source_record(data, *, package=None, version=None, reviewed_files=None):
    package = PACKAGE if package is None else package
    version = VERSION if version is None else version
    reviewed_files = FILES if reviewed_files is None else reviewed_files
    records = [fields(block) for block in data.decode("utf-8").strip().split("\n\n")]
    matches = [row for row in records if row.get("Package") == package and row.get("Version") == version]
    require(len(matches) == 1, "reviewed source version absent or duplicated")
    row = matches[0]
    directory = row.get("Directory", "")
    require(re.fullmatch(r"pool/[A-Za-z0-9/._+~-]+", directory) is not None
            and ".." not in directory.split("/"), "unsafe source directory")
    files = {}
    for line in row.get("Checksums-Sha256", "").splitlines():
        if not line.strip():
            continue
        pieces = line.split()
        require(len(pieces) == 3, "malformed source checksum")
        digest, size, name = pieces
        require(re.fullmatch(r"[a-f0-9]{64}", digest) is not None and size.isdecimal()
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]*", name) is not None
                and name not in files, "unsafe or duplicate source file")
        files[name] = (digest, int(size))
    require(files == reviewed_files, "source inputs differ from reviewed hashes and lengths")
    return directory, files


def archive_source_index(directory, policy_path=POLICY, *, suite=None):
    policy_bytes = read_regular(policy_path)
    config = policy(json.loads(policy_bytes))
    require(read_regular(directory / "policy.json") == policy_bytes, "source policy differs from reviewed policy")
    default_suite, key, fingerprint = ARCHIVES["debian"]
    suite = default_suite if suite is None else suite
    require(suite in {default_suite, "sid"}, "unsupported source-only suite")
    release, sums = verify_release(directory / "InRelease", directory / key, fingerprint, suite)
    if suite == "sid":
        require(release.get("valid_until") is not None, "source-only sid Release expiry missing")
    compressed = read_regular(directory / "Sources.xz", 64 * 1024 * 1024)
    digest = hashlib.sha256(compressed).hexdigest()
    require(sums.get(INDEX) == (digest, len(compressed)), "source index hash or length mismatch")
    with lzma.LZMAFile(io.BytesIO(compressed)) as handle:
        data = handle.read(256 * 1024 * 1024 + 1)
    require(len(data) <= 256 * 1024 * 1024, "source index expansion exceeds bounds")
    return {"timestamp": config["timestamp"], "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "release": release, "sources_index_sha256": digest}, data


def validate(directory, policy_path=POLICY):
    index_proof, data = archive_source_index(directory, policy_path)
    source_directory, files = source_record(data)
    for name, expected in files.items():
        content = read_regular(directory / name, expected[1])
        require((hashlib.sha256(content).hexdigest(), len(content)) == expected,
                "source file hash or length mismatch")
    return {"schema": "regalia.authenticated-source/v1", "status": "verified",
            "production_approved": False, "package": PACKAGE, "version": VERSION,
            **index_proof,
            "directory": source_directory,
            "files": {name: {"sha256": value[0], "bytes": value[1]} for name, value in files.items()},
            "authentication": "pinned GPG InRelease -> SHA256 Sources -> SHA256 source files",
            "maintainer_dsc_signature_verified": False}


def fetch(destination, snapshot, policy_path=POLICY):
    policy_bytes = read_regular(policy_path)
    config = policy(json.loads(policy_bytes))
    require(not destination.exists() and not destination.is_symlink(), "source output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".source-inputs-", dir=destination.parent))
    try:
        (staging / "policy.json").write_bytes(policy_bytes)
        suite, key, fingerprint = ARCHIVES["debian"]
        for name in ("InRelease", key):
            (staging / name).write_bytes(read_regular(snapshot / "debian" / name))
        _, sums = verify_release(staging / "InRelease", staging / key, fingerprint, suite)
        require(INDEX in sums, "signed source index absent")
        base = archive_url("debian", config["timestamp"])
        download(base + f"dists/{suite}/" + INDEX, staging / "Sources.xz", 64 * 1024 * 1024)
        # Authenticate metadata before using any download path from it.
        compressed = read_regular(staging / "Sources.xz", 64 * 1024 * 1024)
        require((hashlib.sha256(compressed).hexdigest(), len(compressed)) == sums[INDEX],
                "source index hash or length mismatch")
        with lzma.LZMAFile(io.BytesIO(compressed)) as handle:
            data = handle.read(256 * 1024 * 1024 + 1)
        require(len(data) <= 256 * 1024 * 1024, "source index expansion exceeds bounds")
        source_directory, files = source_record(data)
        for name, (_, size) in files.items():
            download(base + source_directory + "/" + name, staging / name, size)
        report = validate(staging, policy_path)
        (staging / "verification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        require(not destination.exists() and not destination.is_symlink(), "source output appeared during capture")
        staging.rename(destination)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.destination, args.snapshot), indent=2))
    except (VerificationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
