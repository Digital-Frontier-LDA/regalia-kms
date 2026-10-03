"""Bind the nine reviewed utility packages to source, reproduction and rootfs.

This development admission is independent of signed archive packages and does
not change vulnerability matching or authorize a production release.
"""
import hashlib
import json
import os
import stat
import tarfile

from . import util_package, util_source
from .snapshot import check_installed
from .verify import hash_regular, read_regular, require

PACKAGES = ("bsdutils", "mount", "util-linux", "util-linux-extra", "libmount1", "libblkid1",
            "libuuid1", "libsmartcols1", "liblastlog2-2")


def versions():
    return {name: ("1:" if name == "bsdutils" else "") + util_package.VERSION for name in PACKAGES}


def installed_payload(rootfs, inspected):
    """Read actual exported bytes; a guest-provided checksum is insufficient."""
    triplet = util_package.TRIPLETS[inspected[0]["control"]["Architecture"]]
    policy_bytes = read_regular(util_package.POLICY)
    require(all(package.get("policy_sha256") == hashlib.sha256(policy_bytes).hexdigest()
                for package in inspected), "installed utility policy differs from inspected packages")
    policy = json.loads(policy_bytes)
    expected = {}
    for package in inspected:
        name = package["control"]["Package"]
        for path, descriptor in policy["packages"][name]["payload_members"].items():
            if descriptor["kind"] == "directory":
                continue  # Shared directory permissions are not package-owned.
            actual = path.replace("{triplet}", triplet)
            entry = dict(descriptor, sha256=package["payload_sha256"].get(path))
            if actual in ("usr/bin/mount", "usr/bin/umount"):
                entry["mode"] = 0o755  # Required persistent appliance overrides.
            require(actual not in expected or expected[actual] == entry, "overlapping utility payload differs")
            expected[actual] = entry
    found = {}
    with os.fdopen(os.open(rootfs, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode), "rootfs must be a regular file")
        archive = tarfile.open(fileobj=source, mode="r:gz")
        # Do not extract filesystem paths or execute any package content.
        # Read only reviewed members, bounding individual file expansion.
        for item in archive:
            path = item.name.removeprefix("./").rstrip("/")
            if path not in expected:
                continue
            require(path not in found, "duplicate installed utility path")
            entry = expected[path]
            require(item.uid == item.gid == 0 and item.mode == entry["mode"],
                    "installed utility ownership/mode differs: " + path)
            if entry["kind"] == "symlink":
                require(item.issym() and item.linkname.replace(triplet, "{triplet}") == entry["link"],
                        "installed utility link differs: " + path)
                found[path] = None
            else:
                # Refuse links rather than silently reading a different member.
                require(item.isfile() and 0 <= item.size <= 32 * 1024 * 1024,
                        "installed utility file type/length differs: " + path)
                data = archive.extractfile(item).read(item.size + 1)
                digest = hashlib.sha256(data).hexdigest()
                require(len(data) == item.size and digest == entry["sha256"],
                        "installed utility bytes differ: " + path)
                found[path] = digest
        archive.close()
        # Bind the same open file, even if its pathname is replaced. Changes to
        # that inode while it is parsed or hashed invalidate the whole result.
        source.seek(0)
        rootfs_digest = hashlib.file_digest(source, "sha256").hexdigest()
        after = os.fstat(source.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "rootfs changed during admission")
    require(set(found) == set(expected), "installed utility payload incomplete")
    return {"status": "verified", "regular_files": sum(value is not None for value in found.values()),
            "symlinks": sum(value is None for value in found.values()),
            "rootfs_sha256": rootfs_digest,
            "payload_binding_sha256": hashlib.sha256(json.dumps(found, sort_keys=True).encode()).hexdigest()}


def validate(exports, bundle, inventory, recipe_hashes, rootfs, architecture="amd64"):
    report = json.loads(read_regular(exports / "util-source-build.json"))
    authenticated = util_source.validate(bundle)
    require(report.get("schema") == "regalia.util-linux-source-build/v1"
            and report.get("status") == "installed" and report.get("production_approved") is False
            and report.get("architecture") == architecture
            and report.get("authenticated_source") == authenticated
            and report.get("recipe_inputs") == recipe_hashes,
            "utility source/build/install provenance differs")
    require(recipe_hashes.get("util-package-policy.json") == hash_regular(util_package.POLICY, "sha256")[0],
            "utility admission policy differs from build recipe")
    compiler = exports / "compiler-packages.tsv"
    require(hash_regular(compiler, "sha256")[0] == report.get("compiler_inventory_sha256"),
            "utility compiler inventory binding differs")
    compiler_binding = check_installed(compiler, inventory)
    builds = report.get("builds")
    require(isinstance(builds, list) and len(builds) == 2 and builds[0] == builds[1]
            and report.get("packages_reproduced") is True and report.get("independent_builders") is False,
            "utility package reproduction missing")
    inspected = []
    for label in ("first", "second"):
        packages = builds[0].get("packages", {})
        require(set(packages) == set(PACKAGES), "utility package set differs")
        require(hash_regular(exports / (label + ".log"), "sha256")[0] == report.get("logs", {}).get(label),
                "utility build/test log binding differs")
        for name in PACKAGES:
            package = util_package.inspect(exports / (label + "-packages") / (name + ".deb"), architecture)
            require(package == packages[name] and package["control"]["Package"] == name,
                    "utility package differs from reproduced build: " + name)
            if label == "first":
                inspected.append(package)
    binding = installed_payload(rootfs, inspected)
    return {"schema": "regalia.util-linux-source-binding/v1", "status": "verified",
            "production_approved": False, "architecture": architecture, "source": authenticated,
            "packages": versions(), "package_sha256": {p["control"]["Package"]: p["package_sha256"] for p in inspected},
            "recipe_inputs": recipe_hashes, "compiler_inputs": compiler_binding,
            "build_receipt_sha256": hash_regular(exports / "util-source-build.json", "sha256")[0],
            "installed_payload": binding}
