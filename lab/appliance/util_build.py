"""Build the authenticated utility candidate twice using Debian's test policy.

The host authenticates sources before injection and independently admits the
exported packages afterwards. This guest receipt grants no release approval.
Build before installing any local source packages: compiler inventory must
remain entirely on the signed Debian archive path.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

from deploy.images import util_package, util_source
from deploy.images.verify import hash_regular, read_regular, require
from . import util_profile

BUILD_PACKAGES = ("build-essential", "debhelper", "dh-exec", "dh-package-notes",
                  "dh-sequence-installsysusers", "dh-sequence-zz-debputy-rrr",
                  "asciidoctor", "bc", "bison", "flex", "gettext", "libaudit-dev",
                  "libcap-ng-dev", "libcrypt-dev", "libcryptsetup-dev", "libncurses-dev",
                  "libpam0g-dev", "libreadline-dev", "libselinux1-dev", "libsqlite3-dev",
                  "libsystemd-dev", "libtool", "libudev-dev", "netbase", "pkgconf",
                  "po-debconf", "po4a", "socat", "systemd-dev", "zlib1g-dev")
PACKAGES = ("bsdutils", "mount", "util-linux", "util-linux-extra", "libmount1", "libblkid1",
            "libuuid1", "libsmartcols1", "liblastlog2-2")
USER = "regalia-util-build"
UID = 61001
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C",
       "DEBIAN_FRONTEND": "noninteractive", "SOURCE_DATE_EPOCH": "1790985600",
       "DEB_BUILD_OPTIONS": "parallel=4"}


def command(args):
    result = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=900)
    require(result.returncode == 0, args[0] + " failed: " + result.stderr[-3000:])
    return result.stdout


def recipe_inputs():
    return {"util_build.py": hash_regular(Path(__file__), "sha256")[0],
            "util_profile.py": hash_regular(Path(util_profile.__file__), "sha256")[0],
            "util_package.py": hash_regular(Path(util_package.__file__), "sha256")[0],
            "util-package-policy.json": hash_regular(util_package.POLICY, "sha256")[0]}


def build(bundle, output):
    require(os.geteuid() == 0, "utility build setup requires the disposable guest's root")
    require(not output.exists() and not output.is_symlink(), "utility build output already exists")
    util_source.check_files(bundle, {**util_source.DEBIAN_FILES, **util_source.UPSTREAM_FILES})
    require(subprocess.run(["getent", "passwd", USER], capture_output=True).returncode == 2
            and subprocess.run(["getent", "passwd", str(UID)], capture_output=True).returncode == 2,
            "utility build identity already exists")
    output.mkdir(parents=True, mode=0o755)
    output.chmod(0o755)
    command(["apt-get", "update"])
    command(["apt-get", "install", "-y", "--no-install-recommends", *BUILD_PACKAGES])
    compiler = output / "compiler-packages.tsv"
    compiler.write_text(command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"]))
    architecture = command(["dpkg", "--print-architecture"]).strip()
    require(architecture in util_package.TRIPLETS, "unsupported utility build architecture")
    command(["useradd", "--system", "--uid", str(UID), "--home-dir", "/nonexistent",
             "--shell", "/usr/sbin/nologin", USER])
    builds = []
    try:
        for label in ("first", "second"):
            root = output / label
            root.mkdir(mode=0o755)
            with tarfile.open(bundle / "util-linux-2.42.4.tar.xz") as archive:
                archive.extractall(root, filter="data")
            source = root / "util-linux-2.42.4"
            with tarfile.open(bundle / "util-linux_2.41.5-0+deb13u1.debian.tar.xz") as archive:
                archive.extractall(source, filter="data")
            edits = util_profile.prepare(source)
            # No root or Docker marker is used to skip upstream's ordinary-user
            # tests. The unchanged Debian rules determine known skips/XFAILs.
            command(["chown", "-R", USER, str(root)])
            log = output / (label + ".log")
            with log.open("wb") as stream:
                result = subprocess.run(["runuser", "-u", USER, "--", "env",
                                         "HOME=/nonexistent", "SHELL=/bin/sh",
                                         "dpkg-buildpackage", "-b", "-us", "-uc"],
                                        cwd=source, env=ENV, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=3600)
            require(result.returncode == 0, "utility Debian build/tests failed; see " + str(log)
                    + ": " + log.read_text(errors="replace")[-6000:])
            packages = {}
            destination = output / (label + "-packages")
            destination.mkdir(mode=0o700)
            for name in PACKAGES:
                candidates = list(root.glob(name + "_" + util_package.VERSION + "_" + architecture + ".deb"))
                require(len(candidates) == 1, "missing or ambiguous utility package: " + name)
                package = destination / (name + ".deb")
                shutil.copyfile(candidates[0], package)
                inspected = util_package.inspect(package, architecture)
                require(inspected["control"]["Package"] == name, "utility output name differs")
                packages[name] = inspected
            builds.append({"packages": packages, "profile_edits": edits})
        require(builds[0] == builds[1], "utility packages differ across compilation paths")
    finally:
        command(["userdel", USER])
    report = {"schema": "regalia.util-linux-source-build/v1", "status": "built",
              "production_approved": False, "architecture": architecture,
              "authenticated_source": json.loads(read_regular(bundle / "verification.json")),
              "recipe_inputs": recipe_inputs(), "builds": builds,
              "compiler_inventory_sha256": hash_regular(compiler, "sha256")[0],
              "logs": {label: hash_regular(output / (label + ".log"), "sha256")[0]
                       for label in ("first", "second")},
              "packages_reproduced": True, "independent_builders": False,
              "test_policy": "unmodified Debian rules, ordinary UID 61001; vendor skips/XFAILs retained"}
    (output / "util-source-build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    # Retain packages, logs and compiler binding, rather than compiled source
    # trees. The eventual installed filesystem is validated separately.
    for label in ("first", "second"):
        shutil.rmtree(output / label)
    return report


def install(output):
    report = json.loads(read_regular(output / "util-source-build.json"))
    architecture = command(["dpkg", "--print-architecture"]).strip()
    require(report.get("status") == "built" and report.get("architecture") == architecture
            and report.get("recipe_inputs") == recipe_inputs(), "utility install recipe differs")
    packages = []
    for name in PACKAGES:
        package = output / "first-packages" / (name + ".deb")
        require(util_package.inspect(package, architecture) == report["builds"][0]["packages"][name],
                "utility package changed before installation")
        require(hash_regular(output / "second-packages" / (name + ".deb"), "sha256")
                == hash_regular(package, "sha256"), "utility reproduced package changed")
        packages.append(str(package))
    # Normal dependency resolution; no forced Essential removal, dependency
    # override, unauthenticated option or downloads during local installation.
    command(["apt-get", "install", "-y", "--no-install-recommends", "--no-download", *packages])
    require(command(["dpkg", "--audit"]).strip() == "", "utility installation left broken packages")
    for name in PACKAGES:
        expected = ("1:" if name == "bsdutils" else "") + util_package.VERSION
        require(command(["dpkg-query", "-W", "-f=${Version}", name]) == expected,
                "utility installed version differs: " + name)
    report["status"] = "installed"
    (output / "util-source-build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--install-built", action="store_true")
    actions.add_argument("--purge-build-dependencies", action="store_true")
    args = parser.parse_args()
    if args.purge_build_dependencies:
        # Keep netbase's runtime protocol/service tables. Everything else in
        # this fixed list is a development tool or development package.
        command(["apt-get", "purge", "-y", *(name for name in BUILD_PACKAGES if name != "netbase")])
        report = {"status": "compiler dependencies purged", "production_approved": False}
    elif args.install_built:
        report = install(args.output)
    else:
        if args.bundle is None:
            parser.error("--bundle is required to build")
        report = build(args.bundle, args.output)
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
