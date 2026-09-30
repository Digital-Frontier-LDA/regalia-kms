#!/usr/bin/env python3
"""sops_breakglass.py — replace the organisation-wide SOPS breakglass recipient, in two stages.

  sops_breakglass.py add    --old <age1…> --new <age1pq1…>   # stage 1: per repository, any order
  sops_breakglass.py check  --require <age1pq1…> [--forbid <age1…>]
  sops_breakglass.py remove --old <age1…> --new <age1pq1…>   # stage 2: every repository at once

Run from a repository's top level, with SOPS_AGE_KEY set to a key that can decrypt its files (the
repository's CI key) and a sops that understands the recipients (>= 3.13 for age1pq1 keys).

WHY TWO STAGES (regalia doc/SOPS-MIGRATION.md): the breakglass key is the same key in every
repository, so removing it in some and not others leaves an estate where recovery works in some
places and not others. Adding the new recipient never breaks recovery, so stage 1 runs repository by
repository. Stage 2 removes the old one everywhere at once, and only after `check --require` passes
in every repository and a recovery drill has opened a file with the new key.

WHAT IT CHANGES:
- `.sops.yaml`: the new recipient is written next to each occurrence of the old one, in the form
  that occurrence uses (a list item, or a comma-separated value, flat or under key_groups), so
  comments and layout are kept. The result is parsed back and checked rule by rule.
- every encrypted file tracked by git: `sops updatekeys -y`, then `sops rotate -i`, so the data key is
  new and the file carries exactly the recipients its rule now names.

Every line reads OK, WARN or FAIL; the last line is DONE / CHECK OK, or FAILED (exit 1).
"""
import argparse
import os
import re
import subprocess
import sys

RECIPIENT = re.compile(r"^age1[0-9a-z]+$")
MARKERS = ('"sops":', "\nsops:", "sops_version=", "sops_mac=")


def say(level, msg):
    colour = {"OK": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m"}[level]
    print("  %s%-4s\033[0m %s" % (colour, level, msg))


def recipients_in(value):
    """Recipients named by an `age:` value: a list, or a comma/whitespace-separated string."""
    if value is None:
        return []
    items = value if isinstance(value, list) else re.split(r"[,\s]+", str(value))
    return [str(x).strip() for x in items if str(x).strip()]


def rules_recipients(config_text):
    """[(rule index, [recipients])] for every creation rule, flat `age` and key_groups alike."""
    import yaml
    data = yaml.safe_load(config_text) or {}
    out = []
    for i, rule in enumerate(data.get("creation_rules") or []):
        found = recipients_in(rule.get("age"))
        for group in rule.get("key_groups") or []:
            found += recipients_in((group or {}).get("age"))
        out.append((i, found))
    return out


def add_text(text, old, new):
    """Write `new` next to every occurrence of `old`, keeping each occurrence's form."""
    lines = text.split("\n")
    out = []
    for line in lines:
        out.append(line)
        m = re.match(r"^(\s*-\s*)" + re.escape(old) + r"\s*(#.*)?$", line)
        if m:
            out.append(m.group(1) + new)          # list item: a sibling item
        elif old in line:
            out[-1] = line.replace(old, old + "," + new)   # a comma-separated value
    return "\n".join(out)


def remove_text(text, old):
    """Remove every occurrence of `old`, keeping the rest of each value intact."""
    out = []
    for line in text.split("\n"):
        if re.match(r"^\s*-\s*" + re.escape(old) + r"\s*(#.*)?$", line):
            continue                                # a list item on its own line
        line = re.sub(re.escape(old) + r"\s*,\s*", "", line)   # old, followed by another
        line = re.sub(r"\s*,\s*" + re.escape(old), "", line)   # another, followed by old
        line = line.replace(old, "")
        out.append(line)
    return "\n".join(out)


def encrypted_files():
    """Every git-tracked file that carries SOPS metadata. Recipients are stored in clear, so a
    file's recipients are checked by text, whatever its format (YAML, JSON, dotenv, INI, binary)."""
    names = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.split(b"\0")
    found = []
    for raw in names:
        path = raw.decode()
        if not path or not os.path.isfile(path) or os.path.basename(path) == ".sops.yaml":
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                head = f.read()
        except (UnicodeDecodeError, OSError):
            continue
        if any(m in head for m in MARKERS) and "age1" in head:
            found.append((path, head))
    return found


def sops(*args):
    r = subprocess.run(["sops", *args], capture_output=True, text=True)
    return r.returncode, (r.stderr or r.stdout).strip().splitlines()[-1:] or [""]


def rekey(files):
    bad = 0
    for path, _ in files:
        rc, err = sops("updatekeys", "-y", path)
        if rc == 0:
            rc, err = sops("rotate", "-i", path)
        if rc == 0:
            say("OK", "%s: recipients updated, data key rotated" % path)
        else:
            say("FAIL", "%s: %s" % (path, err[0]))
            bad += 1
    return bad


def edit_config(transform, verify, label):
    if not os.path.isfile(".sops.yaml"):
        say("FAIL", "no .sops.yaml at the repository top level")
        return False
    before = open(".sops.yaml", encoding="utf-8").read()
    after = transform(before)
    try:
        problems = verify(rules_recipients(after))
    except Exception as e:  # a transform that broke the YAML must never be written
        say("FAIL", ".sops.yaml would no longer parse (%s); nothing written" % e)
        return False
    if problems:
        for p in problems:
            say("FAIL", p)
        say("FAIL", ".sops.yaml not written")
        return False
    if after != before:
        with open(".sops.yaml", "w", encoding="utf-8") as f:
            f.write(after)
    say("OK", ".sops.yaml: %s" % label)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    for mode in ("add", "remove"):
        p = sub.add_parser(mode)
        p.add_argument("--old", required=True)
        p.add_argument("--new", required=True)
    c = sub.add_parser("check")
    c.add_argument("--require", required=True)
    c.add_argument("--forbid")
    a = ap.parse_args()

    keys = [k for k in (getattr(a, "old", None), getattr(a, "new", None), getattr(a, "require", None),
                        getattr(a, "forbid", None)) if k]
    for k in keys:
        if not RECIPIENT.match(k):
            print("Error: not an age recipient (age1…, bech32): %.24s…" % k, file=sys.stderr)
            return 2
    if a.mode in ("add", "remove") and a.old == a.new:
        print("Error: --old and --new are the same recipient", file=sys.stderr)
        return 2

    bad = 0
    files = encrypted_files()
    if a.mode == "add":
        ok = edit_config(
            lambda t: t if a.new in t else add_text(t, a.old, a.new),
            lambda rules: ["rule %d names the old breakglass but not the new one" % i
                           for i, r in rules if a.old in r and a.new not in r],
            "the new breakglass recipient sits next to the old one in every rule")
        bad += 0 if ok else 1
        if ok:
            bad += rekey(files)
    elif a.mode == "remove":
        def verify(rules):
            return (["rule %d still names the old breakglass" % i for i, r in rules if a.old in r]
                    + ["rule %d would be left without the new breakglass" % i for i, r in rules if a.new not in r])
        # Refuse before touching anything if any file lacks the new recipient: removing the old one
        # there would leave that file with no breakglass at all.
        missing = [p for p, t in files if a.new not in t]
        for p in missing:
            say("FAIL", "%s does not carry the new breakglass yet; run add first" % p)
        if missing:
            bad += len(missing)
        else:
            ok = edit_config(lambda t: remove_text(t, a.old), verify, "the old breakglass recipient removed from every rule")
            bad += 0 if ok else 1
            if ok:
                bad += rekey(files)
    # check (also run at the end of add and remove)
    files = encrypted_files()
    req = a.require if a.mode == "check" else a.new
    forbid = a.forbid if a.mode == "check" else (a.old if a.mode == "remove" else None)
    if not files:
        say("WARN", "no SOPS-encrypted files tracked here")
    for path, text in files:
        if req not in text:
            say("FAIL", "%s: the breakglass recipient is missing" % path); bad += 1
        elif forbid and forbid in text:
            say("FAIL", "%s: still encrypted to the retired breakglass recipient" % path); bad += 1
        else:
            say("OK", "%s: breakglass recipient present%s" % (path, ", retired one absent" if forbid else ""))
    if os.path.isfile(".sops.yaml"):
        for i, r in rules_recipients(open(".sops.yaml", encoding="utf-8").read()):
            if req not in r:
                say("FAIL", ".sops.yaml rule %d does not name the breakglass recipient" % i); bad += 1
            if forbid and forbid in r:
                say("FAIL", ".sops.yaml rule %d still names the retired breakglass recipient" % i); bad += 1
    print()
    if bad:
        print("\033[31mFAILED\033[0m — %d problem(s) above; fix them before the next stage." % bad)
        return 1
    print("\033[32m%s\033[0m" % ("CHECK OK" if a.mode == "check" else "DONE — commit .sops.yaml and the re-encrypted files"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
