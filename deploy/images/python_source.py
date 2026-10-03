"""Authenticate the CPython candidate without granting package admission.

Debian's signed source index binds its packaging and upstream primary key.
A refreshed key must retain that exact identity. No expired-signature exception,
ambient GPG trust, package installation or vulnerability waiver is used.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from .fetch_debian import download
from .snapshot import ARCHIVES, POLICY, archive_url, policy, verify_release
from .source import INDEX, archive_source_index, source_record
from .verify import VerificationError, read_regular, require, verify_detached

PACKAGE = "python3.13"
DEBIAN_VERSION = "3.13.5-2+deb13u5"
UPSTREAM_VERSION = "3.13.16"
SIGNER = "7169605F62C751356D054A26A821E680E5FA6305"
DEBIAN_FILES = {
    "python3.13_3.13.5-2+deb13u5.dsc": ("4be84e20fb902354fa86955e2fbea6e8bdbd158f54833423488308a9b3532662", 4298),
    "python3.13_3.13.5.orig.tar.xz": ("93e583f243454e6e9e4588ca2c2662206ad961659863277afcdb96801647d640", 22856016),
    "python3.13_3.13.5.orig.tar.xz.asc": ("da6e013d98dcf8fc6696cdb2872b0051fc8fdeb632f73ef9f54d7b5a68647401", 963),
    "python3.13_3.13.5-2+deb13u5.debian.tar.xz": ("a51f456e654ce2c9b40cc1db8005e5041cdb0b2c3aa96ab0871c49fe95280366", 299640),
}
NEWER_DEBIAN_VERSION = "3.13.15-1"
NEWER_DEBIAN_FILES = {
    "python3.13_3.13.15-1.dsc": ("4078ff651ea7096e6933f794b854054cda195d600e02ac83306cee524da31b87", 4040),
    "python3.13_3.13.15.orig.tar.xz": ("1e66a7945a48390ee4c2a4268a0e4185884059a13c4aab6d148aa208deea4a76", 23160540),
    "python3.13_3.13.15-1.debian.tar.xz": ("1cf592dd51de735ff73644743e8959fb16bd50714168855509b709fdeede8342", 261776),
}


def packaging_profile(suite):
    require(suite in {"trixie", "sid"}, "unreviewed Python packaging suite")
    return (DEBIAN_VERSION, DEBIAN_FILES) if suite == "trixie" else (NEWER_DEBIAN_VERSION, NEWER_DEBIAN_FILES)


UPSTREAM_FILES = {
    "Python-3.13.16.tar.xz": ("f4b1bfb3c79b5bb11b8d228a12504163b4c0dab4d679828d8f5f26b6cb6ab35d", 23225704),
    "Python-3.13.16.tar.xz.asc": ("34ca55d174d627771a78db0bdb4838243791cd1f23eb2f3a1cc284dcd75672c8", 833),
}
AUTHORITY = ("1de2bbd31e2dd10aab4098c3ab2f937c530d924ddbfa2dd091f0c7cfb2ee182a", 12310)
ANCHOR_PATH = "debian/upstream/signing-key.asc"
ANCHOR = ("f0116877747ac7bb245815039fa864b944195a5e52fa9f60103c6448bddc0bf7", 6555)
AUTHORITY_PATH = Path(__file__).with_name("keys") / "python-313.asc"
UPSTREAM_URL = "https://www.python.org/ftp/python/3.13.16/"


def inputs(directory, files):
    """Hash and verify the same bounded bytes later consumed by the parsers."""
    frozen = {}
    for name, expected in files.items():
        data = read_regular(directory / name, expected[1])
        require((hashlib.sha256(data).hexdigest(), len(data)) == expected,
                "reviewed Python input hash or length differs: " + name)
        frozen[name] = data
    return frozen


def packaged_authority(packaging):
    with tarfile.open(fileobj=io.BytesIO(packaging), mode="r:xz") as archive:
        matches = [item for item in archive.getmembers() if item.name == ANCHOR_PATH]
        require(len(matches) == 1 and matches[0].isfile() and matches[0].size == ANCHOR[1],
                "Python packaged authority missing, ambiguous or unsafe")
        data = archive.extractfile(matches[0]).read(ANCHOR[1] + 1)
    require((hashlib.sha256(data).hexdigest(), len(data)) == ANCHOR,
            "Python packaged authority differs from reviewed anchor")
    return data


def validate(directory, policy_path=POLICY, *, packaging_suite="trixie"):
    version, reviewed = packaging_profile(packaging_suite)
    index_proof, data = archive_source_index(directory, policy_path, suite=packaging_suite)
    source_directory, files = source_record(data, package=PACKAGE, version=version,
                                           reviewed_files=reviewed)
    frozen = inputs(directory, {**files, **UPSTREAM_FILES, "upstream-authority.asc": AUTHORITY})
    packaged_authority(frozen[f"python3.13_{version}.debian.tar.xz"])
    signature = verify_detached(frozen["Python-3.13.16.tar.xz"],
                                frozen["Python-3.13.16.tar.xz.asc"],
                                frozen["upstream-authority.asc"], SIGNER)
    return {"schema": "regalia.python-authenticated-source/v1", "status": "verified",
            "production_approved": False, "package_admitted": False, "package": PACKAGE,
            "upstream_version": UPSTREAM_VERSION, "debian_packaging_version": version, "packaging_suite": packaging_suite,
            "directory": source_directory, **index_proof,
            "files": {name: {"sha256": value[0], "bytes": value[1]}
                      for name, value in {**files, **UPSTREAM_FILES}.items()},
            "upstream_signature": signature, "primary_fingerprint": SIGNER,
            "authority_sha256": AUTHORITY[0], "packaged_authority_sha256": ANCHOR[0],
            "authentication": "pinned Debian InRelease -> Sources -> packaging authority; same-primary refreshed key -> signed CPython tar",
            "maintainer_dsc_signature_verified": False,
            "sigstore_signature_verified": False}


def fetch(destination, snapshot, policy_path=POLICY, *, packaging_suite="trixie"):
    version, reviewed = packaging_profile(packaging_suite)
    policy_bytes = read_regular(policy_path)
    config = policy(json.loads(policy_bytes))
    require(not destination.exists() and not destination.is_symlink(), "Python source output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".python-source-", dir=destination.parent))
    try:
        (staging / "policy.json").write_bytes(policy_bytes)
        _, key, fingerprint = ARCHIVES["debian"]
        base = archive_url("debian", config["timestamp"])
        (staging / key).write_bytes(read_regular(snapshot / "debian" / key))
        if packaging_suite == "trixie":
            (staging / "InRelease").write_bytes(read_regular(snapshot / "debian" / "InRelease"))
        else:
            # Source packaging only; the appliance's binary suites do not change.
            download(base + "dists/sid/InRelease", staging / "InRelease", 4 * 1024 * 1024)
        suite = packaging_suite
        _, sums = verify_release(staging / "InRelease", staging / key, fingerprint, suite)
        require(INDEX in sums, "signed Python source index absent")
        download(base + f"dists/{suite}/" + INDEX, staging / "Sources.xz", 64 * 1024 * 1024)
        _, data = archive_source_index(staging, policy_path, suite=packaging_suite)
        source_directory, files = source_record(data, package=PACKAGE, version=version,
                                               reviewed_files=reviewed)
        for name, (_, size) in files.items():
            download(base + source_directory + "/" + name, staging / name, size)
        packaged_authority(inputs(staging, files)[f"python3.13_{version}.debian.tar.xz"])
        for name, (_, size) in UPSTREAM_FILES.items():
            download(UPSTREAM_URL + name, staging / name, size)
        (staging / "upstream-authority.asc").write_bytes(read_regular(AUTHORITY_PATH, AUTHORITY[1]))
        report = validate(staging, policy_path, packaging_suite=packaging_suite)
        (staging / "verification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        require(not destination.exists() and not destination.is_symlink(), "Python source output appeared during capture")
        staging.rename(destination)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--packaging-suite", choices=("trixie", "sid"), default="trixie")
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.destination, args.snapshot, packaging_suite=args.packaging_suite), sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
