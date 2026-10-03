"""Authenticate the reviewed util-linux candidate and its Debian packaging.

The archive-bound packaging anchors the upstream signer. Its refreshed key
must retain that exact primary identity. This admits source inputs only, not
a package, image, vulnerability waiver or release.
"""
import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from .fetch_debian import download
from .snapshot import ARCHIVES, POLICY, archive_url, policy, verify_release
from .source import INDEX, archive_source_index, source_record
from .verify import VerificationError, hash_regular, read_regular, require, verify_detached

PACKAGE = "util-linux"
DEBIAN_VERSION = "2.41.5-0+deb13u1"
UPSTREAM_VERSION = "2.42.4"
SIGNER = "B0C64D14301CC6EFAEDF60E4E4B71D5EEC39C284"
DEBIAN_FILES = {
    "util-linux_2.41.5-0+deb13u1.dsc": ("43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5", 4988),
    "util-linux_2.41.5.orig.tar.xz": ("f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728", 9474992),
    "util-linux_2.41.5-0+deb13u1.debian.tar.xz": ("5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6", 107604),
}
UPSTREAM_FILES = {
    "util-linux-2.42.4.tar.xz": ("fbd62a100ab7bb8746ba0661255c3c48185b1e9021507c624da01fbc696330ec", 10729748),
    "util-linux-2.42.4.tar.sign": ("d3b4e930a38c3b4512761708d0d226a55a1420995e3996c1efca0910d7effd3e", 833),
    "v2.42.4-ChangeLog": ("2bc9725049a3396cc209cddd91c0a3f65d8875e6d34da3256d66c9891945f503", 29598),
    "v2.42.4-ChangeLog.sign": ("91a958ea1673f94493073d77c78e79df0c052aa12cc5a885d5041b0dc3fc53d6", 833),
    "v2.42.4-ReleaseNotes": ("102c4dd03e99180b2b1035fc4d7412bc266ef735f24c9f6102d69885a413fb16", 1713),
    "v2.42.4-ReleaseNotes.sign": ("92189c4af599596beadaac5c08e3f304dbd99374593270aab3f21d2a74a7ea1c", 833),
}
TAR = ("5eec78fac0908c1bc18dbe91478741115a3209156dc6105a78ec46dce0f590b3", 100249600)
AUTHORITY = ("ab6fb7fab1351270d0520e8ee090e3b8d3e174023e8c18634801d8d16c4a6115", 11555)
ANCHOR_PATH = "debian/upstream/signing-key.asc"
ANCHOR = ("00f98634547af7d591c1e1821848df3099ba48c716b8129887770cfe15be2e08", 3078)
UPSTREAM_URL = "https://www.kernel.org/pub/linux/utils/util-linux/v2.42/"
AUTHORITY_PATH = Path(__file__).with_name("keys") / "util-linux.asc"


def check_files(directory, files):
    for name, expected in files.items():
        require(hash_regular(directory / name, "sha256") == expected,
                "reviewed util-linux input hash or length differs: " + name)


def packaged_authority(directory):
    # Inspect a single regular member, without extracting archive paths or
    # executing the source's packaging. Reject duplicate authority members.
    data = read_regular(directory / "util-linux_2.41.5-0+deb13u1.debian.tar.xz", 107604)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
        matches = [member for member in archive.getmembers() if member.name == ANCHOR_PATH]
        require(len(matches) == 1 and matches[0].isfile() and matches[0].size == ANCHOR[1],
                "Debian packaging authority missing, ambiguous or unsafe")
        authority = archive.extractfile(matches[0]).read()
    require((hashlib.sha256(authority).hexdigest(), len(authority)) == ANCHOR,
            "packaged upstream authority differs from reviewed anchor")
    return authority


def upstream_tar(directory):
    compressed = read_regular(directory / "util-linux-2.42.4.tar.xz", UPSTREAM_FILES["util-linux-2.42.4.tar.xz"][1])
    with lzma.LZMAFile(io.BytesIO(compressed)) as handle:
        data = handle.read(TAR[1] + 1)
    require((hashlib.sha256(data).hexdigest(), len(data)) == TAR,
            "upstream source tar expansion differs from reviewed bytes")
    return data


def validate(directory, policy_path=POLICY):
    index_proof, data = archive_source_index(directory, policy_path)
    source_directory, files = source_record(data, package=PACKAGE, version=DEBIAN_VERSION,
                                             reviewed_files=DEBIAN_FILES)
    check_files(directory, files)
    packaged_authority(directory)
    check_files(directory, {**UPSTREAM_FILES, "upstream-authority.asc": AUTHORITY})
    authority = read_regular(directory / "upstream-authority.asc", AUTHORITY[1])
    signatures = {}
    for name, contents in (("util-linux-2.42.4.tar", upstream_tar(directory)),
                           ("v2.42.4-ChangeLog", read_regular(directory / "v2.42.4-ChangeLog")),
                           ("v2.42.4-ReleaseNotes", read_regular(directory / "v2.42.4-ReleaseNotes"))):
        signatures[name] = verify_detached(contents, read_regular(directory / (name + ".sign")),
                                           authority, SIGNER)
    return {"schema": "regalia.util-linux-authenticated-source/v1", "status": "verified",
            "production_approved": False, "package": PACKAGE, "upstream_version": UPSTREAM_VERSION,
            "debian_packaging_version": DEBIAN_VERSION, "directory": source_directory, **index_proof,
            "files": {name: {"sha256": value[0], "bytes": value[1]}
                      for name, value in {**files, **UPSTREAM_FILES}.items()},
            "upstream_signatures": signatures, "primary_fingerprint": SIGNER,
            "authority_sha256": AUTHORITY[0], "packaged_authority_sha256": ANCHOR[0],
            "authentication": "pinned Debian InRelease -> Sources -> packaging authority; same-primary refreshed key -> signed upstream tar/notes",
            "maintainer_dsc_signature_verified": False}


def fetch(destination, snapshot, policy_path=POLICY):
    config_data = read_regular(policy_path)
    config = policy(json.loads(config_data))
    require(not destination.exists() and not destination.is_symlink(), "source output already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".util-source-", dir=destination.parent))
    try:
        (staging / "policy.json").write_bytes(config_data)
        suite, key, fingerprint = ARCHIVES["debian"]
        for name in ("InRelease", key):
            (staging / name).write_bytes(read_regular(snapshot / "debian" / name))
        _, sums = verify_release(staging / "InRelease", staging / key, fingerprint, suite)
        require(INDEX in sums, "signed source index absent")
        base = archive_url("debian", config["timestamp"])
        download(base + f"dists/{suite}/" + INDEX, staging / "Sources.xz", 64 * 1024 * 1024)
        _, data = archive_source_index(staging, policy_path)
        source_directory, files = source_record(data, package=PACKAGE, version=DEBIAN_VERSION,
                                                 reviewed_files=DEBIAN_FILES)
        for name, (_, size) in files.items():
            download(base + source_directory + "/" + name, staging / name, size)
        check_files(staging, files)
        packaged_authority(staging)
        for name, (_, size) in UPSTREAM_FILES.items():
            download(UPSTREAM_URL + name, staging / name, size)
        (staging / "upstream-authority.asc").write_bytes(read_regular(AUTHORITY_PATH, AUTHORITY[1]))
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
