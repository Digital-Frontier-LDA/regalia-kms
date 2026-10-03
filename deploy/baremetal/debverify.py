#!/usr/bin/env python3
"""Every "package" entry of the initrd's inventory, checked against the Debian package it came from (#246).

    python3 -Es -m deploy.baremetal.debverify --inventory deploy/baremetal/initrd/initrd-inventory.txt \
        --keyring KEYRING --source URL SUITE [--source URL SUITE ...] --cache DIR --out VERIFIED.json

The inventory (#198) names, for each file the initrd holds that a package owns, the package and its version, as the
build machine's dpkg database said. That database is the build machine's own word. This replaces it with the
archive's, along the chain Debian signs:

  InRelease   fetched from each SOURCE (a snapshot.debian.org URL and a suite), its signature checked with gpgv
              against KEYRING (Debian's archive keyring, itself pinned by hash: e2e/lib/debian-keyring.sh)
  Packages    main/binary-amd64/Packages.xz, its SHA-256 the one InRelease states
  .deb        the package's file in the pool, its SHA-256 the one Packages states for that package AT THAT VERSION
  the file    extracted from the .deb's data archive, compared with the inventory: a file's sha256, a link's target,
              a directory's presence. Merged /usr: a package may ship /lib/x for the image's usr/lib/x.

Any mismatch, and any package or file that cannot be found or fetched, is a refusal: exit 1, every finding
printed. Exit 0 writes VERIFIED.json: {"schema", "packages": {name: version}, "sources": [...], "entries": N},
which `uki build --verified-packages` records and `uki sign` requires (#246). What it does NOT check: the
files dracut generated (the inventory's "generated" lines, read by a reviewer) and our own (pinned in uki.py).
Standard library, plus gpgv and, for a .deb compressed with zstd, the zstd tool.
"""
import argparse
import hashlib
import io
import json
import lzma
import os
import re
import subprocess
import sys
import tarfile
import urllib.request

SCHEMA = "regalia.initrd-packages/v1"
ARCH = "amd64"
MAX_DOWNLOAD = 512 * 1024 * 1024


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url, cache, opener=urllib.request.urlopen):
    """`url`'s bytes, kept in `cache` under its own sha256 name so a rerun does not fetch again. Never trusted
    for what it is: every caller checks the bytes against a hash from the signed chain."""
    os.makedirs(cache, exist_ok=True)
    path = os.path.join(cache, hashlib.sha256(url.encode()).hexdigest())
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    with opener(url, timeout=300) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    require(len(data) <= MAX_DOWNLOAD, "%s is larger than %d bytes" % (url, MAX_DOWNLOAD))
    with open(path + ".part", "wb") as f:
        f.write(data)
    os.replace(path + ".part", path)
    return data


def verified_release(data, keyring, run=subprocess.run):
    """The signed text of an InRelease file, after gpgv checks its signature against `keyring`."""
    done = run(["gpgv", "--keyring", keyring, "--output", "-", "-"], input=data, capture_output=True)
    require(done.returncode == 0, "the InRelease signature does not verify against %s: %s"
            % (keyring, done.stderr.decode("utf-8", "replace").strip()[-300:]))
    return done.stdout.decode("utf-8", "replace")


def release_hashes(text):
    """{path: (sha256, size)} from a Release file's SHA256 section."""
    hashes, inside = {}, False
    for line in text.splitlines():
        if line.startswith("SHA256:"):
            inside = True
            continue
        if inside and line.startswith(" "):
            digest, size, path = line.split()
            hashes[path] = (digest, int(size))
        elif inside:
            inside = False
    return hashes


def packages_index(text):
    """{(package, version): (Filename, sha256, size)} from a Packages file."""
    found, fields = {}, {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if {"Package", "Version", "Filename", "SHA256", "Size"} <= set(fields):
                found[(fields["Package"], fields["Version"])] = (fields["Filename"], fields["SHA256"], int(fields["Size"]))
            fields = {}
        elif not line.startswith(" ") and ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value.strip()
    return found


def source_index(base, suite, keyring, cache, opener=urllib.request.urlopen, run=subprocess.run):
    """One source's packages, every step checked: InRelease by signature, Packages.xz by the hash it states."""
    base = base.rstrip("/")
    release = release_hashes(verified_release(fetch("%s/dists/%s/InRelease" % (base, suite), cache, opener), keyring, run))
    path = "main/binary-%s/Packages.xz" % ARCH
    require(path in release, "%s %s's Release names no %s" % (base, suite, path))
    data = fetch("%s/dists/%s/%s" % (base, suite, path), cache, opener)
    require((sha256(data), len(data)) == release[path], "%s %s's %s is not the one its signed Release states" % (base, suite, path))
    return {key: (base, value) for key, value in packages_index(lzma.decompress(data).decode("utf-8", "replace")).items()}


def ar_members(data):
    """{name: bytes} of an ar archive (a .deb)."""
    require(data[:8] == b"!<arch>\n", "not an ar archive")
    members, pos = {}, 8
    while pos + 60 <= len(data):
        head = data[pos:pos + 60]
        name = head[:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(head[48:58].decode("ascii").strip())
        members[name] = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
    return members


def deb_files(data, run=subprocess.run):
    """{path without "./": ("f", sha256) | ("l", target) | ("d", None)} of a .deb's data archive."""
    members = ar_members(data)
    name = next((n for n in members if n.startswith("data.tar")), None)
    require(name is not None, "the .deb has no data archive")
    body = members[name]
    if name.endswith(".zst"):
        done = run(["zstd", "-dc"], input=body, capture_output=True)
        require(done.returncode == 0, "the .deb's data archive does not decompress (zstd)")
        body, mode = done.stdout, "r:"
    else:
        mode = {".xz": "r:xz", ".gz": "r:gz", ".bz2": "r:bz2", ".tar": "r:"}[os.path.splitext(name)[1] if name != "data.tar" else ".tar"]
    files = {}
    with tarfile.open(fileobj=io.BytesIO(body), mode=mode) as tar:
        for member in tar:
            path = os.path.normpath(member.name).lstrip("./").lstrip("/") if member.name not in (".", "./") else ""
            if not path:
                continue
            if member.isreg():
                files[path] = ("f", sha256(tar.extractfile(member).read()))
            elif member.issym():
                files[path] = ("l", member.linkname)
            elif member.islnk():
                files[path] = ("hard", os.path.normpath(member.linkname).lstrip("./"))
            elif member.isdir():
                files[path] = ("d", None)
    for path, (kind, target) in list(files.items()):        # a hard link: the content of the file it names
        if kind == "hard" and files.get(target, ("", None))[0] == "f":
            files[path] = files[target]
    return files


def inventory_packages(lines):
    """{"name=version": [(path, kind, value), ...]} of the inventory's package entries."""
    owned = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        cls, origin, kind, _, _, path, value = line.split(" ")
        if cls == "package":
            owned.setdefault(origin, []).append((path, kind, value))
    return owned


def _unescape(text):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def verify(owned, index, cache, opener=urllib.request.urlopen, run=subprocess.run):
    """(findings, {name: version}). `index`: {(package, version): (base, (Filename, sha256, size))}."""
    findings, verified = [], {}
    for origin in sorted(owned):
        name, _, version = origin.partition("=")
        if (name, version) not in index:
            findings.append("%s %s: not in the signed Packages of any source" % (name, version))
            continue
        base, (filename, digest, size) = index[(name, version)]
        try:
            data = fetch("%s/%s" % (base, filename), cache, opener)
        except (OSError, ValueError) as error:
            findings.append("%s %s: %s cannot be fetched (%s)" % (name, version, filename, error))
            continue
        if (sha256(data), len(data)) != (digest, size):
            findings.append("%s %s: %s is not the .deb its signed Packages states" % (name, version, filename))
            continue
        try:
            files = deb_files(data, run)
        except (Refused, tarfile.TarError, KeyError, ValueError) as error:
            findings.append("%s %s: the .deb cannot be read (%s)" % (name, version, error))
            continue
        before = len(findings)
        for path, kind, value in owned[origin]:
            path = _unescape(path)
            shipped = files.get(path) or (files.get(path[4:]) if path.startswith("usr/") else None)
            if shipped is None:
                findings.append("%s %s: ships no %s" % (name, version, path))
            elif kind == "f" and shipped != ("f", value):
                findings.append("%s %s: %s is not the file the package ships (%s, not %s)"
                                % (name, version, path, value[:16], (shipped[1] or "")[:16] if shipped[0] == "f" else shipped[0]))
            elif kind == "l" and shipped != ("l", _unescape(value)):
                findings.append("%s %s: the link %s points at %s, the package's at %s" % (name, version, path, _unescape(value), shipped))
            elif kind == "d" and shipped[0] != "d":
                findings.append("%s %s: %s is a directory in the image, not in the package" % (name, version, path))
        if len(findings) == before:
            verified[name] = version
    return findings, verified


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--keyring", required=True)
    parser.add_argument("--source", nargs=2, action="append", metavar=("URL", "SUITE"), required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.inventory) as f:
            owned = inventory_packages(f)
        index = {}
        for base, suite in args.source:
            for key, value in source_index(base, suite, args.keyring, args.cache).items():
                index.setdefault(key, value)
        findings, verified = verify(owned, index, args.cache)
    except (Refused, OSError, ValueError) as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 1
    for finding in findings:
        print("REFUSED: %s" % finding, file=sys.stderr)
    if findings:
        print("debverify: %d of %d packages verified; %d finding(s)" % (len(verified), len(owned), len(findings)), file=sys.stderr)
        return 1
    entries = sum(len(v) for v in owned.values())
    with open(args.out, "w") as f:
        json.dump({"schema": SCHEMA, "packages": verified, "sources": [" ".join(s) for s in args.source], "entries": entries},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    print("debverify: %d packages, %d entries, each as the archive's signed chain gives it" % (len(verified), entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
