#!/usr/bin/env python3
"""Which image variant a build is, judged on what it holds (regalia-kms-dx7.14; operator decision of 2026-11-19).

build-rootfs.sh --variant staging adds, for the staging DL360 only, a key-only operator sshd refused without
regalia.staging=1 on the kernel command line, systemd-networkd for the staging management net, and a persistent
journal (deploy/baremetal/image/staging/). The PRODUCTION image must hold none of it: check() refuses a production
build whose listing has any of STAGING_PATHS, any other path naming regalia-staging, or any staging package, and a
staging build that lacks one of them. build-rootfs.sh runs it on every build before writing its output, and
e2e/rootfs-reproducible.sh (CI) on the production build.

The deploy package is copied whole into /usr/lib/regalia-kms/deploy (every unit's WorkingDirectory), so the staging
SOURCES are there as inert data on both variants; DEPLOY_COPY is not judged. Nothing under it is a unit, a
configuration systemd or sshd reads, or a program on PATH.

    python3 -Es -m deploy.baremetal.imagevariant check --listing rootfs-listing.txt --record rootfs-build.json
"""
import argparse
import json
import os
import sys

VARIANTS = ("production", "staging")
STAGING_PACKAGES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "image", "staging", "packages.txt")
DEPLOY_COPY = "./usr/lib/regalia-kms/deploy/"

# every path the staging variant adds (build-rootfs.sh's staging step), as rootfs-listing.txt names them
STAGING_PATHS = (
    "./usr/sbin/sshd",
    "./usr/lib/regalia-staging/VARIANT",
    "./usr/lib/regalia-staging/sshd_config",
    "./usr/lib/regalia-staging/banner",
    "./usr/lib/systemd/system/regalia-staging-sshd.service",
    "./usr/lib/systemd/system/multi-user.target.wants/regalia-staging-sshd.service",
    "./usr/lib/systemd/system/multi-user.target.wants/systemd-networkd.service",
    "./usr/lib/systemd/system/sockets.target.wants/systemd-networkd.socket",
    "./usr/lib/systemd/system/systemd-networkd.service.d/regalia-staging.conf",
    "./usr/lib/systemd/journald.conf.d/90-regalia-staging.conf",
    "./usr/lib/tmpfiles.d/regalia-staging.conf",
)


def staging_packages(path=STAGING_PACKAGES_FILE):
    """The staging variant's extra Debian packages: 'name | what | why' lines; a malformed line is a ValueError."""
    names = []
    with open(path) as f:
        for number, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = [x.strip() for x in line.split("|")]
            if len(fields) != 3 or not all(fields):
                raise ValueError("%s line %d: not 'name | what | why'" % (path, number))
            names.append(fields[0])
    return names


def listing_paths(text):
    """The paths of a rootfs-listing.txt (tab-separated, the path first)."""
    return [line.split("\t", 1)[0] for line in text.splitlines() if line]


def check(listing_text, record, packages=None):
    """The problems with this build as the variant its record names; an empty list is a pass."""
    variant = record.get("variant")
    if variant not in VARIANTS:
        return ["the build record names no variant (%r): one of %s" % (variant, ", ".join(VARIANTS))]
    packages = staging_packages() if packages is None else packages
    paths = set(listing_paths(listing_text))
    installed = {p.split("=", 1)[0] for p in record.get("packages", [])}
    problems = []
    if variant == "production":
        problems += ["a production image holds %s (staging only)" % p for p in STAGING_PATHS if p in paths]
        problems += ["a production image holds %s (it names regalia-staging)" % p for p in sorted(paths)
                     if "regalia-staging" in p and p not in STAGING_PATHS and not p.startswith(DEPLOY_COPY)]
        problems += ["a production image has the staging package %s" % n for n in packages if n in installed]
    else:
        problems += ["the staging image lacks %s" % p for p in STAGING_PATHS if p not in paths]
        problems += ["the staging image lacks the package %s" % n for n in packages if n not in installed]
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(prog="imagevariant")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--listing", required=True)
    c.add_argument("--record", required=True)
    a = p.parse_args(argv)
    with open(a.listing) as f:
        listing = f.read()
    with open(a.record) as f:
        record = json.load(f)
    problems = check(listing, record)
    for line in problems:
        print("imagevariant: " + line, file=sys.stderr)
    if problems:
        return 1
    print("imagevariant: %s image, as its record says" % record["variant"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
