#!/usr/bin/env python3
"""What changed in the KMS host's initrd since its inventory was reviewed (#198): the report the scheduled
initrd-drift workflow files as a GitHub issue.

    python3 -Es -m deploy.baremetal.initrd_drift --pinned deploy/baremetal/initrd/initrd-inventory.txt \
        --current CURRENT.txt [--security PACKAGES-FILE] --out REPORT.md

The pinned inventory is the reviewed one; CURRENT is `uki initrd-inventory --root /` of an initrd built from
TODAY's archive (main, updates and security). Exit 0: nothing moved. Exit 1: REPORT.md says what did, in the
order a reader takes it:
  * packages whose version moved (A -> B), and which of them the security archive carries: a pinned
    snapshot freezes security fixes too, and KERNEL-UPDATE.md says the date must move when one touches a
    package of the inventory;
  * the lines dracut generated that changed: the ones a reviewer reads;
  * every other entry added, removed or changed, by path.
The client binary's line (=compiled) is not compared: it follows this repository's source, not the archive.
Nothing here decides anything: the inventory changes only in a pull request whose diff someone reads.
Standard library only.
"""
import argparse
import hashlib
import sys

COLUMNS = ("cls", "origin", "kind", "mode", "owner", "path", "value")


def parse(lines):
    """{path: {column: value}} from inventory lines (comments and blanks skipped)."""
    out = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        words = line.split(" ")
        if len(words) != len(COLUMNS):
            raise ValueError("not an inventory line: %r" % line[:120])
        out[words[5]] = dict(zip(COLUMNS, words))
    return out


def packages(entries):
    """{package: version} named by the entries' ORIGIN column."""
    found = {}
    for entry in entries.values():
        if entry["cls"] == "package" and "=" in entry["origin"]:
            name, version = entry["origin"].split("=", 1)
            found[name] = version
    return found


def security_versions(text):
    """{package: version} from a Debian Packages file (the security archive's)."""
    found, package = {}, None
    for line in text.splitlines():
        if line.startswith("Package: "):
            package = line[9:].strip()
        elif line.startswith("Version: ") and package:
            found[package] = line[9:].strip()
        elif not line.strip():
            package = None
    return found


def md(text):
    """Archive data (a package name, a version, a path) made inert in GitHub markdown: HTML special characters as
    entities, every markdown punctuation character backslash-escaped, so nothing in it links, mentions, formats,
    closes a table cell or opens a tag."""
    text = str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("@", "&#64;")
    return "".join("\\" + c if c in "\\`*_{}[]()#+-.!|~:" else c for c in text)


def fenced(text):
    """A line for the fenced block: no backtick, so the fence cannot be closed from inside."""
    return str(text).replace("`", "'")


def report(pinned, current, security=None):
    """(changed, markdown). `pinned` and `current`: parsed inventories; `security`: {package: version}."""
    old, new = packages(pinned), packages(current)
    moved = sorted(p for p in set(old) | set(new) if old.get(p) != new.get(p))
    state = lambda e: (e["kind"], e["mode"], e["owner"], e["value"])
    changed = []
    for path in sorted(set(pinned) | set(current)):
        a, b = pinned.get(path), current.get(path)
        if a and b and (a["value"] == "=compiled" or b["value"] == "=compiled"):
            continue
        if a is None or b is None or state(a) != state(b):
            changed.append((path, a, b))
    if not moved and not changed:
        return False, ""
    out = ["The initrd built from today's Debian archive differs from the reviewed inventory "
           "(`deploy/baremetal/initrd/initrd-inventory.txt`, #198). Until the snapshot date moves and the inventory is "
           "refreshed in a pull request, images keep being built from the pinned snapshot, without these changes.", ""]
    if moved:
        out += ["### Packages (%d)" % len(moved), "", "| package | reviewed | today | security archive |", "|---|---|---|---|"]
        for p in moved:
            sec = (security or {}).get(p)
            flag = "**%s**" % md(sec) if sec and sec == new.get(p) else md(sec or "")
            out.append("| %s | %s | %s | %s |" % (md(p), md(old.get(p, "(absent)")), md(new.get(p, "(absent)")), flag))
        if security and any((security or {}).get(p) == new.get(p) for p in moved):
            out += ["", "**A package of the inventory has a security update** (bold above). KERNEL-UPDATE.md: the snapshot "
                    "date must move, and the inventory be refreshed, before the next image is signed."]
        out.append("")
    generated = [(p, a, b) for p, a, b in changed if (a or b)["cls"] == "generated" or (b and b["cls"] == "generated")]
    if generated:
        out += ["### Generated by dracut (%d): read these" % len(generated), "", "```"]
        for p, a, b in generated:
            out += ["- %s" % fenced(" ".join(a[c] for c in COLUMNS))] if a else []
            out += ["+ %s" % fenced(" ".join(b[c] for c in COLUMNS))] if b else []
        out += ["```", ""]
    rest = [(p, a, b) for p, a, b in changed if (p, a, b) not in generated]
    if rest:
        out += ["### Other entries (%d)" % len(rest), ""]
        for p, a, b in rest[:400]:
            what = "added" if a is None else "removed" if b is None else "changed"
            out.append("- %s %s (%s)" % (md(p), what, md((b or a)["origin"])))
        if len(rest) > 400:
            out.append("- ... and %d more" % (len(rest) - 400))
        out.append("")
    body = "\n".join(out)
    digest = hashlib.sha256(body.encode()).hexdigest()[:16]
    return True, body + "\n<!-- initrd-drift %s -->\n" % digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pinned", required=True)
    parser.add_argument("--current", required=True)
    parser.add_argument("--security", help="the security archive's Packages file, uncompressed")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    with open(args.pinned) as f:
        pinned = parse(f)
    with open(args.current) as f:
        current = parse(f)
    security = None
    if args.security:
        with open(args.security, encoding="utf-8", errors="replace") as f:
            security = security_versions(f.read())
    changed, body = report(pinned, current, security)
    with open(args.out, "w") as f:
        f.write(body)
    print("initrd-drift: %s" % ("the initrd has moved since its inventory was reviewed" if changed else "no change"))
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main())
