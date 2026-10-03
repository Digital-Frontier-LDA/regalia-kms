"""Build the reviewed TPM profile twice and prepare one local Debian package.

The host must authenticate the complete source bundle before injecting it into
the disposable guest. This module checks exact source hashes again. Its receipt
does not by itself grant package admission or release approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

from deploy.images.source import FILES, PACKAGE
from deploy.images.source_package import VERSION
from deploy.images.verify import hash_regular, read_regular, require
from . import tpm_profile

BUILD_PACKAGES = ("make", "autoconf", "automake", "autoconf-archive", "libtool",
                  "libtss2-dev", "libssl-dev", "pkg-config", "dpkg-dev")
REQUIRED_TOOLS = ("tpm2_getcap", "tpm2_quote", "tpm2_checkquote", "tpm2_createek",
                  "tpm2_create", "tpm2_createprimary", "tpm2_import", "tpm2_load",
                  "tpm2_readpublic", "tpm2_unseal", "tpm2_pcrread", "tpm2_pcrextend",
                  "tpm2_startauthsession", "tpm2_policysecret", "tpm2_createpolicy",
                  "tpm2_nvread", "tpm2_nvreadpublic", "tpm2_nvdefine", "tpm2_nvwrite",
                  "tpm2_nvundefine", "tpm2_evictcontrol", "tpm2_flushcontext")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
       "DEBIAN_FRONTEND": "noninteractive", "SOURCE_DATE_EPOCH": "1790985600"}


def command(args, cwd=None):
    result = subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=900)
    require(result.returncode == 0, f"{args[0]} failed: {result.stderr[-3000:]}")
    return result.stdout


def dependency_list(text):
    require(text.startswith("shlibs:Depends=") and len(text.splitlines()) == 1,
            "unexpected generated library dependencies")
    value = text.strip().split("=", 1)[1]
    require(re.fullmatch(r"[a-z0-9.+-]+(?: \(>= [0-9A-Za-z.+:~\-]+\))?(?:, [a-z0-9.+-]+(?: \(>= [0-9A-Za-z.+:~\-]+\))?)*", value)
            is not None, "unsafe generated dependencies")
    names = [item.split()[0] for item in value.split(", ")]
    expected = {"libc6", "libssl3t64", "libtss2-esys-3.0.2-0t64", "libtss2-mu-4.0.1-0t64",
                "libtss2-rc0t64", "libtss2-sys1t64", "libtss2-tctildr0t64"}
    require(set(names) == expected and len(names) == len(expected), "unreviewed TPM dependency closure")
    return value + ", libtss2-tcti-device0t64"


def check_binaries(prefix):
    binary = prefix / "usr/bin/tpm2"
    require(binary.is_file() and not binary.is_symlink(), "TPM executable is missing")
    for name in REQUIRED_TOOLS:
        link = prefix / "usr/bin" / name
        require(link.is_symlink() and os.readlink(link) == "tpm2", "required TPM tool missing or redirected")
    tools = sorted(path.name for path in (prefix / "usr/bin").iterdir())
    require(not any(name.startswith("tss2") or name == "tpm2_getekcertificate" for name in tools),
            "omitted network/FAPI tools remain")
    needed = command(["readelf", "--dynamic", str(binary)])
    libraries = command(["ldd", str(binary)])
    require("not found" not in libraries and all(name not in needed + libraries for name in ("libcurl", "libtss2-fapi")),
            "unexpected or missing TPM runtime library")
    return {"binary_sha256": hash_regular(binary, "sha256")[0], "tools": tools,
            "elf_needed": [line.strip() for line in needed.splitlines() if "(NEEDED)" in line],
            "runtime_library_names": sorted(set(re.findall(r"\b(lib[A-Za-z0-9_.-]+)\s+=>", libraries)))}


def build(bundle, output, install=False):
    require(not output.exists(), "TPM build output already exists")
    output.mkdir(parents=True, mode=0o700)
    for name, expected in FILES.items():
        require(hash_regular(bundle / name, "sha256") == expected, "TPM source input hash or size changed")
    command(["apt-get", "update"])
    command(["apt-get", "install", "-y", "--no-install-recommends", *BUILD_PACKAGES])
    inventory = command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    (output / "compiler-packages.tsv").write_text(inventory)
    architecture = command(["dpkg", "--print-architecture"]).strip()
    require(architecture in {"amd64", "arm64"}, "unsupported TPM build architecture")
    builds = []
    for label in ("first", "second"):
        root = output / label
        root.mkdir()
        with tarfile.open(bundle / "tpm2-tools_5.7.orig.tar.gz") as archive:
            archive.extractall(root, filter="data")
        source = root / "tpm2-tools-5.7"
        tpm_profile.apply(source)
        command(["./bootstrap"], cwd=source)
        command(["./configure", "--disable-fapi", "--with-efivar=no", "--prefix=/usr",
                 "CFLAGS=-O2 -g0 -ffile-prefix-map=" + str(source) + "=.",
                 "LDFLAGS=-Wl,--build-id=none,-z,relro,-z,now"], cwd=source)
        command(["make", "-j4"], cwd=source)
        stage = root / "stage"
        command(["make", "install", "DESTDIR=" + str(stage)], cwd=source)
        builds.append(check_binaries(stage))
        shutil.copyfile(stage / "usr/bin/tpm2", output / (label + ".tpm2"))
    require(builds[0] == builds[1], "TPM output differs across compilation paths")
    stage = output / "first/stage"
    debian = stage / "DEBIAN"
    debian.mkdir()
    # dpkg-shlibdeps uses the local source control record and the installed
    # signed libraries' shlibs/symbols metadata; no library dependency is hidden.
    source_control = output / "first/tpm2-tools-5.7/debian"
    source_control.mkdir(exist_ok=True)
    (source_control / "control").write_text("Source: tpm2-tools\n\nPackage: tpm2-tools\nArchitecture: any\nDescription: Local reviewed TPM profile\n")
    dependencies = dependency_list(command(["dpkg-shlibdeps", "-O", "-e" + str(stage / "usr/bin/tpm2")],
                                          cwd=source_control.parent))
    control = (f"Package: {PACKAGE}\nVersion: {VERSION}\nSource: {PACKAGE} ({VERSION})\n"
               f"Architecture: {architecture}\nSection: utils\nPriority: optional\n"
               "Maintainer: Regalia laboratory <noreply@example.invalid>\n"
               f"Depends: {dependencies}\n"
               "Description: Locally built TPM ESYS profile for the Regalia laboratory\n"
               " Authenticated upstream sources; excludes FAPI and the network EK downloader.\n"
               " This is a local source build, not a Debian-produced binary or release approval.\n")
    (debian / "control").write_text(control)
    doc = stage / "usr/share/doc/tpm2-tools"
    doc.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output / "first/tpm2-tools-5.7/docs/LICENSE", doc / "copyright")
    (doc / "regalia-source.json").write_bytes(read_regular(bundle / "verification.json"))
    # Normalize package member timestamps, modes and owners across both builds.
    epoch = int(ENV["SOURCE_DATE_EPOCH"])
    for path in sorted(stage.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path == stage / "usr/bin/tpm2" else 0o644)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(stage, (epoch, epoch))
    package = output / "tpm2-tools.deb"
    command(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(package)])
    second_stage = output / "second/stage"
    shutil.copytree(debian, second_stage / "DEBIAN")
    shutil.copytree(doc, second_stage / "usr/share/doc/tpm2-tools", dirs_exist_ok=True)
    for path in sorted(second_stage.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() or path == second_stage / "usr/bin/tpm2" else 0o644)
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    os.utime(second_stage, (epoch, epoch))
    second_package = output / "second-tpm2-tools.deb"
    command(["dpkg-deb", "--root-owner-group", "--build", str(second_stage), str(second_package)])
    require(hash_regular(package, "sha256") == hash_regular(second_package, "sha256"),
            "TPM package differs across compilation paths")
    if install:
        command(["dpkg", "--install", str(package)])
        require(command(["dpkg-query", "-W", "-f=${Version}", PACKAGE]) == VERSION,
                "installed TPM source package differs")
        shutil.copyfile("/usr/bin/tpm2", output / "installed.tpm2")
    receipt = {"schema": "regalia.tpm-source-package/v1", "status": "installed" if install else "built",
               "production_approved": False, "package": PACKAGE, "version": VERSION,
               "source": PACKAGE, "source_version": VERSION, "architecture": architecture,
               "authenticated_source": json.loads(read_regular(bundle / "verification.json")),
               "source_inputs": {name: expected[0] for name, expected in FILES.items()},
               "recipe_inputs": {"tpm_profile.py": hash_regular(Path(tpm_profile.__file__), "sha256")[0],
                                 "tpm_build.py": hash_regular(Path(__file__), "sha256")[0]},
               "compiler_inventory_sha256": hash_regular(output / "compiler-packages.tsv", "sha256")[0],
               "package_sha256": hash_regular(package, "sha256")[0], "dependencies": dependencies,
               "builds": builds, "packages_reproduced": True, "independent_builders": False}
    (output / "tpm-source-package.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.bundle, args.output, args.install), indent=2))


if __name__ == "__main__":
    main()
