#!/usr/bin/env python3
"""Every "package" entry of the initrd's inventory, checked against the Debian package it came from (#246).

    python3 -Es -m deploy.baremetal.debverify --inventory deploy/baremetal/initrd/initrd-inventory.txt \
        --keyring KEYRING --source URL SUITE [--source URL SUITE ...] --cache DIR --out VERIFIED.json

The inventory (#198) names, for each file the initrd holds that a package owns, the package and its version, as the
build machine's dpkg database said. That database is the build machine's own word. This replaces it with the
archive's, along the chain Debian signs. INVENTORY is the COMMITTED inventory, the one a pull request's reviewer
read: build-initrd.sh first requires the inventory of the initrd it built to equal it line for line, class and
origin included, so what is verified here is what was reviewed.

  InRelease   fetched from each SOURCE (a snapshot.debian.org URL and a suite), its signature checked with gpgv
              against KEYRING, which must be the pinned one (KEYRING_SHA256: Debian's debian-archive-keyring
              2025.1, as e2e/lib/debian-keyring.sh fetches it); gpgv's status lines must show a good signature,
              by a key neither expired nor revoked, whose primary key is one of SIGNERS (trixie's archive and
              security keys). Exit status alone is not enough: it does not say which key signed. Expiry and
              revocation are gpgv's, as of the day the build runs (gpgv takes no other time): a pinned key that
              has expired since the snapshot refuses the build, and the snapshot moves. Valid-Until is
              NOT checked: a dated snapshot's Release files are past it soon after the snapshot, by design. An
              older InRelease replayed changes nothing: the versions come from the inventory, and every
              Packages and .deb is held to the hash the signed text states.
  Packages    main/binary-amd64/Packages.xz, its SHA-256 the one InRelease states
  .deb        the package's file in the pool, its SHA-256 the one Packages states for that package AT THAT VERSION
  the file    extracted from the .deb's data archive, compared with the inventory: a file's sha256, a link's target,
              a directory's presence. Merged /usr: a package may ship /lib/x for the image's usr/lib/x.

Dracut's copies at a package's path (the inventory's "generated dracut-over:" lines) are checked too, against
uki.DRACUT_OVER, the pinned list of the paths dracut writes over: a link must point where the list says, and a
file must be the dracut-core file the list names, in dracut-core's .deb at the version the inventory names. A
dracut-over line the list does not name is refused (uki.load_inventory), so a package file that differs from its
.deb is never moved out of reach by calling it dracut's.

Any mismatch, and any package or file that cannot be found or fetched, is a refusal: exit 1, every finding
printed. Exit 0 writes VERIFIED.json: {"schema", "packages": {name: {"version", "deb_sha256"}}, "releases": {"URL SUITE":
InRelease sha256}, "keyring_sha256", "inventory_sha256", "entries": package lines, "dracut_over": dracut-over lines},
which build-initrd.sh puts in the initrd's build record as verified_packages; uki build and sign require it to
name exactly the inventory's packages, the pinned keyring, and the inventory they review (#246). What it does NOT
check: the files dracut generated where no package has a file (the "generated dracut" lines, read by a
reviewer) and our own (pinned in uki.py).
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
# The keyring, by the sha256 of debian-archive-keyring.gpg in debian-archive-keyring 2025.1 (the .deb itself is
# pinned in e2e/lib/debian-keyring.sh), and the primary keys whose signatures on the trixie, trixie-updates and
# trixie-security InRelease files at snapshot 20261003T121500Z gpgv reported as VALIDSIG. The bookworm keys sign
# them too, and are not needed. A move of either is a reviewed change, with the snapshot date (KERNEL-UPDATE.md).
KEYRING_SHA256 = "506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017"
SIGNERS = {"04B54C3CDCA79751B16BC6B5225629DF75B188BD": "Debian Archive Automatic Signing Key (13/trixie)",
           "5E04A1E3223A19A20706E20F9904613D4CCE68C6": "Debian Security Archive Automatic Signing Key (13/trixie)"}
REFUSED_STATUS = ("BADSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")


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


def verified_release(data, keyring, run=subprocess.run, signers=None):
    """The signed text of an InRelease file, after gpgv checks its signature against `keyring`: a good signature
    (VALIDSIG) whose primary key is one of `signers` (default SIGNERS), and no bad, expired or revoked one."""
    signers = SIGNERS if signers is None else signers
    status_r, status_w = os.pipe()
    try:
        done = run(["gpgv", "--status-fd", str(status_w), "--keyring", keyring, "--output", "-", "-"], input=data,
                   capture_output=True, pass_fds=(status_w,))
        os.close(status_w)
        status_w = None
        with os.fdopen(status_r, "rb") as f:
            status_r = None
            status = f.read().decode("utf-8", "replace")
    finally:
        for fd in (status_r, status_w):
            if fd is not None:
                os.close(fd)
    stderr = done.stderr.decode("utf-8", "replace").strip()[-300:]
    require(done.returncode == 0, "the InRelease signature does not verify against %s: %s" % (keyring, stderr))
    pinned, good, signature = {k.upper() for k in signers}, [], []
    for line in status.splitlines() + ["[GNUPG:] NEWSIG"]:        # one group of status lines per signature
        words = line.split()[1:] if line.startswith("[GNUPG:] ") else []
        if words[:1] == ["NEWSIG"]:
            kinds = {w[0] for w in signature}
            primary = next((w[10].upper() for w in signature if w[0] == "VALIDSIG" and len(w) > 10), None)
            require("BADSIG" not in kinds, "the InRelease carries a bad signature")
            if primary in pinned:
                require(not kinds & set(REFUSED_STATUS), "the InRelease's signature by the pinned key %s is %s"
                        % (primary, ", ".join(sorted(kinds & set(REFUSED_STATUS)))))
                good.append(primary)
            signature = []
        elif words:
            signature.append(words)
    require(good, "the InRelease signature does not verify against %s: no good signature by a pinned key (%s)"
            % (keyring, ", ".join(sorted(signers))))
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


def source_index(base, suite, keyring, cache, opener=urllib.request.urlopen, run=subprocess.run, releases=None, signers=None):
    """One source's packages, every step checked: InRelease by signature, Packages.xz by the hash it states.
    `releases`, when given, collects {"BASE SUITE": the InRelease's sha256}."""
    base = base.rstrip("/")
    inrelease = fetch("%s/dists/%s/InRelease" % (base, suite), cache, opener)
    release = release_hashes(verified_release(inrelease, keyring, run, signers))
    if releases is not None:
        releases["%s %s" % (base, suite)] = sha256(inrelease)
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
            path = os.path.normpath(member.name).removeprefix("./").lstrip("/") if member.name not in (".", "./") else ""
            if not path:
                continue
            if member.isreg():
                files[path] = ("f", sha256(tar.extractfile(member).read()))
            elif member.issym():
                files[path] = ("l", member.linkname)
            elif member.islnk():
                files[path] = ("hard", os.path.normpath(member.linkname).removeprefix("./").lstrip("/"))
            elif member.isdir():
                files[path] = ("d", None)
    for path, (kind, target) in list(files.items()):        # a hard link: the content of the file it names
        if kind == "hard" and files.get(target, ("", None))[0] == "f":
            files[path] = files[target]
    return files


def inventory_packages(lines):
    """{"name=version": [(path, kind, value), ...]} of the inventory's package entries."""
    return inventory_entries(lines)[0]


def inventory_entries(lines):
    """({"name=version": [(path, kind, value)]} of the "package" lines, [(path, kind, value, owner)] of the
    "generated dracut-over:OWNER" lines)."""
    owned, over = {}, []
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        cls, origin, kind, _, _, path, value = line.split(" ")
        if cls == "package":
            owned.setdefault(origin, []).append((path, kind, value))
        elif cls == "generated" and origin.startswith("dracut-over:"):
            over.append((path, kind, value, origin[len("dracut-over:"):]))
    return owned, over


def _unescape(text):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), text)


def _deb(name, version, index, cache, opener, run, findings):
    """(the .deb's sha256, its files) for name=version along the signed chain, or None with a finding."""
    if (name, version) not in index:
        findings.append("%s %s: not in the signed Packages of any source" % (name, version))
        return None
    base, (filename, digest, size) = index[(name, version)]
    try:
        data = fetch("%s/%s" % (base, filename), cache, opener)
    except (OSError, ValueError) as error:
        findings.append("%s %s: %s cannot be fetched (%s)" % (name, version, filename, error))
        return None
    if (sha256(data), len(data)) != (digest, size):
        findings.append("%s %s: %s is not the .deb its signed Packages states" % (name, version, filename))
        return None
    try:
        return digest, deb_files(data, run)
    except (Refused, tarfile.TarError, KeyError, ValueError) as error:
        findings.append("%s %s: the .deb cannot be read (%s)" % (name, version, error))
        return None


def verify_dracut_over(over, versions, pinned, index, cache, opener=urllib.request.urlopen, run=subprocess.run):
    """Findings for the inventory's dracut-over lines, each held to `pinned` (uki.DRACUT_OVER: {path: (owner,
    ("link", target) | (package, path in its .deb))}): a link to the pinned target, a file the pinned package's
    file, that package at the version `versions` ({name: version}, from the inventory) gives it."""
    findings, debs = [], {}
    for path, kind, value, owner in over:
        rule = pinned.get(path)
        if rule is None or rule[0] != owner.partition("=")[0]:
            findings.append("%s: dracut-over:%s is not on the pinned list of the paths dracut writes over" % (path, owner))
            continue
        source = rule[1]
        if source[0] == "link":
            if (kind, _unescape(value)) != ("l", source[1]):
                findings.append("%s: dracut's link points at %s, the pinned list's at %s" % (path, _unescape(value), source[1]))
            continue
        package, source_path = source
        if package not in versions:
            findings.append("%s: the inventory names no version of %s, whose %s it is" % (path, package, source_path))
            continue
        if package not in debs:
            debs[package] = _deb(package, versions[package], index, cache, opener, run, findings)
        if debs[package] is None:
            continue
        shipped = debs[package][1].get(source_path)
        if kind != "f" or shipped != ("f", value):
            findings.append("%s: not %s's %s at %s (%s)" % (path, package, source_path, versions[package], value[:16]))
    return findings


def verify(owned, index, cache, opener=urllib.request.urlopen, run=subprocess.run):
    """(findings, {name: {"version", "deb_sha256"}}). `index`: {(package, version): (base, (Filename, sha256, size))}."""
    findings, verified = [], {}
    for origin in sorted(owned):
        name, _, version = origin.partition("=")
        got = _deb(name, version, index, cache, opener, run, findings)
        if got is None:
            continue
        digest, files = got
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
            verified[name] = {"version": version, "deb_sha256": digest}
    return findings, verified


def result(verified, releases, keyring_sha256, inventory_sha256, entries, dracut_over):
    """What the initrd's build record carries as verified_packages (build-initrd.sh; uki.check_initrd_build)."""
    return {"schema": SCHEMA, "packages": verified, "releases": releases, "keyring_sha256": keyring_sha256,
            "inventory_sha256": inventory_sha256, "entries": entries, "dracut_over": dracut_over}


def inventory_versions(owned, over):
    """{name: version} of every package the inventory names, by its package or dracut-over lines; a package at two
    versions is refused."""
    versions = {}
    for origin in list(owned) + [o for _, _, _, o in over]:
        name, _, version = origin.partition("=")
        require(versions.setdefault(name, version) == version, "the inventory names %s at two versions" % name)
    return versions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--keyring", required=True)
    parser.add_argument("--source", nargs=2, action="append", metavar=("URL", "SUITE"), required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    from deploy.baremetal import uki            # its pinned list of dracut's overwrites; uki reads this module's pins
    try:
        with open(args.keyring, "rb") as f:
            keyring_sha256 = sha256(f.read())
        require(keyring_sha256 == KEYRING_SHA256, "%s is not the pinned Debian archive keyring (sha256 %s, not %s)"
                % (args.keyring, keyring_sha256, KEYRING_SHA256))
        with open(args.inventory, "rb") as f:
            raw = f.read()
        owned, over = inventory_entries(raw.decode("utf-8").splitlines())
        versions = inventory_versions(owned, over)
        index, releases = {}, {}
        for base, suite in args.source:
            for key, value in source_index(base, suite, args.keyring, args.cache, releases=releases).items():
                index.setdefault(key, value)
        findings, verified = verify(owned, index, args.cache)
        findings += verify_dracut_over(over, versions, uki.DRACUT_OVER, index, args.cache)
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
        json.dump(result(verified, releases, keyring_sha256, sha256(raw), entries, len(over)), f, indent=2, sort_keys=True)
        f.write("\n")
    print("debverify: %d packages, %d entries and %d of dracut's over them, each as the archive's signed chain gives it"
          % (len(verified), entries, len(over)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
