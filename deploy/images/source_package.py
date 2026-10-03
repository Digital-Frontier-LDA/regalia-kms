"""Admit the single reviewed source-built TPM package to development evidence.

This is a separate provenance path, not a signed-archive exception or scan
waiver. Every other package must still match authenticated Debian indexes.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tarfile
import tempfile

from . import source
from .snapshot import check_installed, fields
from .verify import hash_regular, read_regular, require

VERSION = "5.7-1+regalia1"
DEPENDENCIES = {"libc6", "libssl3t64", "libtss2-esys-3.0.2-0t64", "libtss2-mu-4.0.1-0t64",
                "libtss2-rc0t64", "libtss2-sys1t64", "libtss2-tctildr0t64", "libtss2-tcti-device0t64"}


def deb_archive(package, option, limit, *, privileged_modes=None):
    # Bound both disk output and wall time while a trusted dpkg parser expands
    # an untrusted package. Never execute its binary or maintainer scripts.
    def bounds():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    with tempfile.TemporaryDirectory(prefix="regalia-deb-inspect-") as temp:
        path = Path(temp) / "members.tar"
        with path.open("wb") as output:
            result = subprocess.run(["dpkg-deb", option, str(package)], stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=30, preexec_fn=bounds)
        require(result.returncode == 0, "package archive expansion failed or exceeded bounds")
        data = read_regular(path, limit)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = {}
        for item in archive.getmembers():
            name = item.name.removeprefix("./").rstrip("/")
            require(not name.startswith("/") and ".." not in name.split("/") and name not in members,
                    "unsafe or duplicate package path")
            allowed_privilege = (item.isfile() and privileged_modes is not None
                                 and privileged_modes.get(name) == item.mode)
            require(item.uid == item.gid == 0 and (not item.mode & 0o7000 or allowed_privilege)
                    and (item.issym() or not item.mode & 0o022)
                    and (item.isdir() or item.isfile() or item.issym()), "unsafe package ownership/type/mode")
            content = archive.extractfile(item).read() if item.isfile() else None
            members[name] = (item, content)
    return members


def inspect_payload(package, binary_sha256):
    controls = deb_archive(package, "--ctrl-tarfile", 1024 * 1024)
    require(set(controls) <= {"", ".", "control", "md5sums"} and "control" in controls,
            "unreviewed package control or maintainer script")
    require(controls["control"][0].isfile(), "package control is not regular")
    control = fields(controls["control"][1].decode("utf-8"))
    require(set(control) == {"Package", "Version", "Source", "Architecture", "Section", "Priority",
                             "Maintainer", "Depends", "Description"}, "unreviewed package control field")
    require(control.get("Package") == source.PACKAGE and control.get("Version") == VERSION
            and control.get("Source") == source.PACKAGE + " (" + VERSION + ")"
            and control.get("Architecture") in {"amd64", "arm64"}
            and not any(name in control for name in ("Pre-Depends", "Provides", "Replaces", "Conflicts", "Essential")),
            "package identity or relationships differ from reviewed profile")
    dependencies = control["Depends"].split(", ")
    require(len(dependencies) == len(DEPENDENCIES)
            and {value.split()[0] for value in dependencies} == DEPENDENCIES,
            "unreviewed package dependency closure")
    payload = deb_archive(package, "--fsys-tarfile", 32 * 1024 * 1024)
    for name, (item, content) in payload.items():
        require(name in {"", ".", "usr", "usr/bin", "usr/share"} or name.startswith(("usr/bin/", "usr/share/")),
                "package writes outside reviewed runtime paths")
        if name in {"", ".", "usr", "usr/bin", "usr/share"}:
            require(item.isdir(), "package parent path is not a directory")
        if name.startswith("usr/bin/"):
            tool = name.removeprefix("usr/bin/")
            require(tool == "tpm2" or re.fullmatch(r"tpm2_[A-Za-z0-9_]+", tool) is not None,
                    "unreviewed executable name")
            require(tool != "tpm2_getekcertificate", "omitted downloader remains in package")
            if tool == "tpm2":
                require(item.isfile() and item.mode == 0o755
                        and hashlib.sha256(content).hexdigest() == binary_sha256,
                        "package executable differs from reproducible build")
                require(content[:6] == b"\x7fELF\x02\x01" and len(content) >= 20
                        and int.from_bytes(content[18:20], "little") ==
                        {"amd64": 62, "arm64": 183}[control["Architecture"]],
                        "package executable architecture differs")
            else:
                require(item.issym() and item.linkname == "tpm2", "unsafe TPM command alias")
        elif item.issym():
            require(not item.linkname.startswith("/") and ".." not in item.linkname.split("/"),
                    "unsafe supporting-file link")
    require("usr/bin/tpm2" in payload, "package executable missing")
    return control, payload


def validate(exports, bundle, inventory, recipe_hashes, architecture="amd64"):
    report = json.loads(read_regular(exports / "tpm-source-package.json"))
    authenticated = source.validate(bundle)
    require(report.get("schema") == "regalia.tpm-source-package/v1"
            and report.get("status") == "installed" and report.get("production_approved") is False,
            "source package build/install evidence missing")
    require(all(report.get(name) == expected for name, expected in {
        "package": source.PACKAGE, "version": VERSION, "source": source.PACKAGE,
        "source_version": VERSION, "architecture": architecture,
        "authenticated_source": authenticated, "recipe_inputs": recipe_hashes,
        "source_inputs": {name: value[0] for name, value in source.FILES.items()}}.items()),
        "source package provenance differs from authenticated inputs or reviewed recipe")
    compiler = exports / "compiler-packages.tsv"
    require(hash_regular(compiler, "sha256")[0] == report["compiler_inventory_sha256"],
            "compiler inventory binding differs")
    compiler_binding = check_installed(compiler, inventory)
    builds = report.get("builds")
    require(isinstance(builds, list) and len(builds) == 2 and builds[0] == builds[1]
            and report.get("independent_builders") is False, "reproducible TPM build evidence missing")
    binary_sha256 = builds[0]["binary_sha256"]
    for name in ("first.tpm2", "second.tpm2"):
        require(hash_regular(exports / name, "sha256")[0] == binary_sha256,
                "TPM build executable differs")
    package = exports / "tpm2-tools.deb"
    require(hash_regular(package, "sha256")[0] == report["package_sha256"], "local package hash differs")
    require(report.get("packages_reproduced") is True
            and hash_regular(exports / "second-tpm2-tools.deb", "sha256")[0] == report["package_sha256"],
            "local package reproduction differs")
    control, payload = inspect_payload(package, binary_sha256)
    require(control["Architecture"] == architecture and control["Depends"] == report["dependencies"],
            "local package control differs from build evidence")
    require(sorted(name.removeprefix("usr/bin/") for name in payload if name.startswith("usr/bin/"))
            == builds[0]["tools"], "local package tool inventory differs")
    require(payload["usr/share/doc/tpm2-tools/regalia-source.json"][1]
            == read_regular(bundle / "verification.json"), "installed source metadata differs")
    require(hash_regular(exports / "installed.tpm2", "sha256")[0] == binary_sha256,
            "installed TPM executable differs from admitted package")
    return {"schema": "regalia.source-package-binding/v1", "status": "verified",
            "production_approved": False, "package": source.PACKAGE, "version": VERSION,
            "architecture": architecture, "source": authenticated,
            "binary_sha256": binary_sha256, "package_sha256": report["package_sha256"],
            "build_receipt_sha256": hash_regular(exports / "tpm-source-package.json", "sha256")[0],
            "compiler_inputs": compiler_binding, "recipe_inputs": recipe_hashes}


def installed_binding(path, inventory, admitted):
    require(admitted.get("schema") == "regalia.source-package-binding/v1" and admitted.get("status") == "verified"
            and admitted.get("package") == source.PACKAGE and admitted.get("version") == VERSION,
            "reviewed source admission required")
    rows = read_regular(path).decode("utf-8").splitlines()
    own = [row for row in rows if row.split("\t")[0].split(":")[0] == source.PACKAGE]
    require(own == [source.PACKAGE + "\t" + VERSION], "source-built installed package missing or ambiguous")
    with tempfile.TemporaryDirectory(prefix="regalia-archive-inventory-") as temp:
        filtered = Path(temp) / "packages.tsv"
        filtered.write_text("\n".join(row for row in rows if row not in own) + "\n")
        signed = check_installed(filtered, inventory)
    return {"status": "verified", "packages": len(rows), "archive_packages": signed["packages"],
            "source_built_packages": 1, "inventory_sha256": hash_regular(path, "sha256")[0],
            "source_package": admitted}
