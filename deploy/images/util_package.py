"""Inspect the reviewed util-linux package structure without executing it.

This gate preserves package identities, relationships, scripts and file layout.
It is not source authentication, reproducible-build proof or package admission.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess

from .snapshot import fields
from .source_package import deb_archive
from .verify import VerificationError, hash_regular, read_regular, require

POLICY = Path(__file__).with_name("util-package-policy.json")
VERSION = "2.42.4-0+regalia1"
TRIPLETS = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}
PRIVILEGED_MODES = {"usr/bin/mount": 0o4755, "usr/bin/umount": 0o4755, "usr/bin/su": 0o4755}


def metadata(item, content, triplet, *, payload=False):
    result = {"kind": "directory" if item.isdir() else "symlink" if item.issym() else "file",
              "mode": item.mode, "link": item.linkname.replace(triplet, "{triplet}") if item.issym() else None}
    if payload:
        result["elf"] = bool(content and content.startswith(b"\x7fELF"))
    return result


def inspect(package, architecture):
    require(architecture in TRIPLETS, "unreviewed utility package architecture")
    # All parser invocations consume the same private bytes, even if the caller
    # replaces its input while inspection runs. Never execute package scripts.
    data = read_regular(package, 32 * 1024 * 1024)
    with tempfile.TemporaryDirectory(prefix="regalia-util-package-") as temp:
        frozen = Path(temp) / "candidate.deb"
        frozen.write_bytes(data)
        return inspect_frozen(frozen, architecture)


def inspect_frozen(package, architecture):
    policy_bytes = read_regular(POLICY)
    policy = json.loads(policy_bytes)
    require(policy.get("schema") == "regalia.util-linux-package-structure-policy/v1"
            and policy.get("version") == VERSION, "unreviewed utility package structure policy")
    controls = deb_archive(package, "--ctrl-tarfile", 1024 * 1024)
    require("control" in controls and controls["control"][0].isfile(), "utility control missing or unsafe")
    control = fields(controls["control"][1].decode())
    name = control.get("Package")
    require(name in policy["packages"], "unreviewed utility binary package")
    reviewed = policy["packages"][name]
    expected = dict(reviewed["control"], Architecture=architecture)
    installed_size = control.get("Installed-Size", "")
    require(installed_size.isdecimal() and 0 < int(installed_size) <= 32768,
            "utility installed size missing or exceeds bounds")
    expected["Installed-Size"] = installed_size
    require(control == expected, "utility package identity, relationships or flags differ")
    require(set(controls) == set(reviewed["control_members"]), "unreviewed utility control member or script")
    triplet = TRIPLETS[architecture]
    for path, (item, content) in controls.items():
        approved = reviewed["control_members"][path]
        descriptor = metadata(item, content, triplet)
        descriptor["sha256"] = (hashlib.sha256(content).hexdigest()
                                if content is not None and path not in ("control", "md5sums") else None)
        require(descriptor == approved, "utility control metadata or script differs: " + path)
    payload = deb_archive(package, "--fsys-tarfile", 32 * 1024 * 1024,
                          privileged_modes=PRIVILEGED_MODES)
    normalized = {path.replace(triplet, "{triplet}"): value for path, value in payload.items()}
    require(len(normalized) == len(payload) and set(normalized) == set(reviewed["payload_members"]),
            "utility package file layout differs: " + name
            + "; missing=" + repr(sorted(set(reviewed["payload_members"]) - set(normalized))[:32])
            + "; extra=" + repr(sorted(set(normalized) - set(reviewed["payload_members"]))[:32]))
    hashes = {}
    for path, (item, content) in normalized.items():
        descriptor = metadata(item, content, triplet, payload=True)
        require(descriptor == reviewed["payload_members"][path], "utility file type, mode or link differs: " + path)
        if descriptor["elf"]:
            require(content[:6] == b"\x7fELF\x02\x01" and len(content) >= 20
                    and int.from_bytes(content[18:20], "little") == {"amd64": 62, "arm64": 183}[architecture],
                    "utility executable/library architecture differs: " + path)
        if content is not None:
            hashes[path] = hashlib.sha256(content).hexdigest()
    return {"schema": "regalia.util-linux-package-structure/v1", "status": "verified",
            "production_approved": False, "package_admitted": False, "control": control,
            "package_sha256": hash_regular(package, "sha256")[0],
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(), "payload_sha256": hashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--architecture", choices=tuple(TRIPLETS), required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.package, args.architecture), sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
