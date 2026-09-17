"""Find credential-bearing files across the estate that SOPS does not cover.

#33 asks for an inventory of company secrets. tools/sops_inventory.py answers "what is under
SOPS"; this answers the question that one structurally cannot: **a file that was never brought under
SOPS at all is invisible to a scanner that only inspects SOPS candidates.**

WHAT THIS PRODUCES IS A WORKLIST, NOT A VERDICT, and that distinction is the design.

Deciding whether a particular value is a live credential needs its owner. A first pass here reported
74 findings across six repositories, almost all `.env.example` files and source named `secrets.py` --
an inventory nobody would read, which fails the same way a red check people learn to discount does.
Narrowing by name alone still produced `NETBIRD_MGMT_API_CERT_KEY_FILE`, whose value is a path to a
.pem, and `STRIPE_WEBHOOK_SECRET` in a file named `.env.functional.test`. A name is not the thing --
the same lesson as a comment mentioning an age key reading identically to a rule using one.

So this narrows hard and then stops: it reports WHERE to look and WHAT SHAPE was found, and never
the value. Anything it cannot classify is reported as unclassified rather than assumed either way.

TWO SHAPES OF CANDIDATE, read differently. An assignment file (.env, .netrc, vault.yml) is read for
NAME=value pairs. A key file (.pem, .p12, id_ed25519) IS the credential end to end and has no
assignment to find, so it is classified by its armour LABEL and its file type -- never its body.
Reading the second kind with the rules for the first is how a private key was reported as clean.

    python3 -m tools.secret_inventory ~/code
"""

import argparse
import collections
import math
import re
import subprocess

from tools.sops_inventory import discover, git, inspect

# A HUNG `git` IS THE MOST SILENT UNDER-REPORT AVAILABLE: the scan produces no output at all, so
# there is not even a wrong number to notice. kms.tools.sops_inventory.git has declared a 60s
# timeout since it was written; this module called subprocess.run directly and inherited none, and
# it is the one that walks the whole estate. Two inventory tools disagreeing about whether a stalled
# git can stop a scan is the disagreement resolving in the wrong direction.
#
# A timeout is routed to `unreadable`, not to a crash: "I could not read this one" is a result the
# operator can act on, and it already makes main() exit non-zero and say the run is not a statement
# about everything named. Counted separately as well, because a hang and a missing object are
# different problems for whoever has to chase them.
GIT_TIMEOUT = 60

# Files whose NAME suggests they carry credentials.
CANDIDATE = re.compile(r"""(?xi)
    (^|/)\.env(\.|$) | \.env$
  | \.(pem|key|p12|pfx|jks|keystore|kdbx)$
  | (^|/)id_(rsa|ed25519|ecdsa)$
  | (^|/)\.netrc$ | (^|/)\.npmrc$ | (^|/)\.pypirc$
  | vault\.ya?ml$ | (^|/)\.htpasswd$
""")
# Conventionally placeholders. Treating them as findings is how the list becomes noise.
EXEMPLAR = re.compile(r"(?i)\.(example|sample|template|dist|md)$|\.example\.|(^|/)examples?/")
SOURCE = re.compile(r"\.(py|ts|js|go|rs|java|rb|tsx|jsx|sh)$")
# TWO SHAPES OF CANDIDATE, AND CONFLATING THEM REPORTS A PRIVATE KEY AS CLEAN.
#
# An assignment file (.env, .netrc, vault.yml) carries NAME=value pairs, and ASSIGNMENT below reads
# them. A key file IS the credential, end to end: there is no assignment in it, so ASSIGNMENT found
# nothing, `kinds["opaque"]` was 0, and the file was counted `inspected` and dropped -- this tool
# saying "I read it and found no secret" about an id_ed25519. That is the same failure family as a
# failed `git show` counted as a clean file, one input-shape further out: both are what this does
# when the input is not the shape the next line assumes.
#
# It also made the docstring's "anything it cannot classify is reported as unclassified" false.
# Nothing was reported as unclassified, because nothing could be: the only bucket a non-assignment
# file could reach was `inspected`.
KEY_FILE = re.compile(r"(?i)\.(pem|key|p12|pfx|jks|keystore|kdbx)$|(^|/)id_(rsa|ed25519|ecdsa)$")
# Containers that exist to hold private material. Binary, so no armour to read: the file type is
# the evidence, and it is enough to warrant a look.
CONTAINER = re.compile(r"(?i)\.(p12|pfx|jks|keystore|kdbx)$")
# ARMOUR LABELS ONLY -- the line that says what a blob is, never the blob. Deliberately unable to
# match a key body: no base64 run appears in any pattern here, so nothing that could constitute
# key material is ever captured, held, or printed.
#
# ENCRYPTED IS TESTED FIRST because "BEGIN ENCRYPTED PRIVATE KEY" also satisfies PRIVATE_ARMOUR,
# and the distinction is worth keeping: a passphrase-protected key checked into a repository is a
# weaker finding than a bare one, and reporting both as "private-key" would hide that.
#
# THE PATTERNS ARE COMPOSED, NOT WRITTEN WHOLE, and that is not style. gitleaks' private-key rule
# matches an armour label followed by a long enough run of key-shaped characters, and a regex that
# ALTERNATES on two armour labels supplies exactly that: written as one literal, this file's own
# detector is reported as a private key. .gitleaks.toml says the fix for a prose match is
# composition and forbids path allowlists by name -- a path allowlist here would silence the rule
# for the whole file, which is the module that most needs it. The assembled string does not survive
# into source, only into the .pyc, which is why __pycache__ must stay ignored.
_BEGIN = "-----BEGIN "
ENCRYPTED_ARMOUR = re.compile(
    (_BEGIN + r"ENCRYPTED PRIVATE KEY-----" + r"|^Proc-Type:\s*4,ENCRYPTED").encode(), re.M)
PRIVATE_ARMOUR = re.compile((_BEGIN + r"(?:[A-Z0-9]+ )*PRIVATE KEY-----").encode())
# A .pem is far more often a certificate than a key. Reporting those rebuilds the 74-finding list
# nobody reads, so public material is recognised in order to be EXCLUDED, not merely unmatched --
# an unrecognised file stays `unclassified` and is still reported.
PUBLIC_ARMOUR = re.compile((_BEGIN + r"(?:CERTIFICATE|PUBLIC KEY|[A-Z0-9 ]+ PARAMETERS)-----").encode())
ASSIGNMENT = re.compile(
    rb"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*)\s*[=:]\s*(\S+)")
# Names that hold a POINTER to a credential, not the credential. NETBIRD_MGMT_API_CERT_KEY_FILE's
# value is a path to a .pem; reporting it is a false accusation about a correctly-written config.
POINTER = re.compile(rb"(_FILE|_PATH|_URL|_URI|_DIR|_NAME|_ID)$")
# Build-time public configuration. These are compiled into client bundles by design.
PUBLIC = re.compile(rb"^(NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_|STORYBOOK_)")
PLACEHOLDER = re.compile(
    rb"(?i)^[\"']?(|x+|\.\.\.|<[^>]*>|\$\{[^}]*\}|change ?me|your[-_].*|todo|dummy|example"
    rb"|placeholder|test|fake|none|null|redacted|secret|password)[\"']?$")


def shannon(value):
    if not value:
        return 0.0
    counts = collections.Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())


def classify(name, raw):
    """What KIND of assignment this is. Never returns the value."""
    value = raw.strip(b"\"'")
    if PLACEHOLDER.match(raw) or PLACEHOLDER.match(value):
        return "placeholder"
    if POINTER.search(name):
        return "pointer"
    if PUBLIC.match(name):
        return "public-prefixed"
    if len(value) >= 16 and shannon(value) >= 3.5:
        return "opaque"
    return "short-or-low-entropy"


def classify_file(path, blob):
    """What kind of key material a whole file holds. Never returns or prints any of it."""
    if ENCRYPTED_ARMOUR.search(blob):
        return "encrypted-private-key"
    if PRIVATE_ARMOUR.search(blob):
        return "private-key"
    if CONTAINER.search(path):
        return "key-container"
    if PUBLIC_ARMOUR.search(blob):
        return "public-material"
    return "unclassified"


def scan_repository(origin, top):
    report = inspect(origin, top)
    if "error" in report:
        return {"origin": origin, "error": report["error"]}
    # THE RESOLVED TOPLEVEL, NOT THE ARGUMENT. inspect() resolves it precisely because ls-tree run
    # below a repository root scopes to that subdirectory and silently omits the rest -- the trap
    # documented inside inspect() itself, which this function reintroduced by keeping the caller's
    # `top`. Masked by the same accident as last time: discover() happens to pass a toplevel.
    top = report["top"]
    listing = git(top, "ls-tree", "-r", "--name-only", "--full-name", report["ref"])
    if listing is None:
        return {"origin": origin, "error": f"could not list {report['ref']}"}
    encrypted = set(report["encrypted"])
    counts, worklist, unreadable = collections.Counter(), [], []
    for path in listing.split("\n"):
        if not CANDIDATE.search(path):
            continue
        counts["named"] += 1
        for label, pattern in (("exemplar", EXEMPLAR), ("source", SOURCE)):
            if pattern.search(path):
                counts[label] += 1
                break
        else:
            if path in encrypted:
                counts["sops-encrypted"] += 1
                continue
            # A FAILED `git show` IS NOT AN EMPTY FILE. capture_output always yields bytes, so the
            # previous `if blob is None` never fired and a missing path, a permission error or a
            # broken symlink was counted as a clean inspected file -- silent under-reporting, in a
            # tool whose stated property is that it says what it could not read.
            try:
                shown = subprocess.run(["git", "-C", top, "show", f"{report['ref']}:{path}"],
                                       capture_output=True, timeout=GIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                unreadable.append(path)
                counts["unreadable"] += 1
                counts["timed-out"] += 1
                continue
            if shown.returncode != 0:
                unreadable.append(path)
                counts["unreadable"] += 1
                continue
            blob = shown.stdout
            counts["inspected"] += 1
            if KEY_FILE.search(path):
                counts["key-file"] += 1
                kind = classify_file(path, blob)
                counts[kind] += 1
                # Public material is the only kind that is not a finding. `unclassified` IS one:
                # a .key this cannot read is exactly the case the owner has to settle, and
                # dropping it would restore the silence this branch exists to end.
                if kind != "public-material":
                    worklist.append({"path": path, "kind": kind, "detail": ""})
                continue
            counts["assignment-file"] += 1
            kinds = collections.Counter(classify(m.group(1), m.group(2))
                                        for m in ASSIGNMENT.finditer(blob))
            if kinds["opaque"]:
                worklist.append({"path": path, "kind": "opaque-assignment",
                                 "detail": f"{kinds['opaque']} opaque"})
            counts.update(kinds)
    return {"origin": origin, "ref": report["ref"], "counts": dict(counts),
            "worklist": worklist, "unreadable": unreadable}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("search_root")
    args = parser.parse_args(argv)

    repositories = discover(args.search_root)
    totals, errored, worklist = collections.Counter(), [], []
    for origin, top in sorted(repositories.items()):
        result = scan_repository(origin, top)
        if "error" in result:
            errored.append((origin, result["error"]))
            continue
        totals["inventoried"] += 1
        totals.update(result["counts"])
        for item in result["worklist"]:
            worklist.append((origin, item))

    print(f"  {len(repositories)} discovered, {totals['inventoried']} inventoried, "
          f"{len(errored)} errored")
    for origin, problem in errored:
        print(f"    ERRORED {origin}: {problem} — its files were not examined")
    if not totals["named"]:
        print("  no credential-named files were found at all — nothing was examined")
        return 1
    print(f"\n  {totals['named']} files named like a credential:")
    for label in ("exemplar", "source", "sops-encrypted", "inspected", "unreadable"):
        print(f"    {totals[label]:4}  {label}")
    # THE INSPECTED FILES SPLIT IN TWO, and the counts below are reported against the right half.
    # "assignments inside the N inspected files" was a heading that named more than it counted once
    # key files joined the corpus: no assignment is ever found in a .p12, so including it in the
    # denominator described a rate over files the numerator could not come from.
    print(f"\n  the {totals['inspected']} inspected files split:")
    for label in ("assignment-file", "key-file"):
        print(f"    {totals[label]:4}  {label}")
    print(f"\n  assignments inside the {totals['assignment-file']} assignment files:")
    for label in ("placeholder", "pointer", "public-prefixed", "short-or-low-entropy", "opaque"):
        print(f"    {totals[label]:4}  {label}")
    print(f"\n  whole-file material inside the {totals['key-file']} key files:")
    for label in ("private-key", "encrypted-private-key", "key-container", "public-material",
                  "unclassified"):
        print(f"    {totals[label]:4}  {label}")
    print(f"\n  WORKLIST — {len(worklist)} file(s) for their owner to classify. This tool does not "
          f"decide whether a value is live, and reports no value.")
    for origin, item in worklist:
        detail = f" ({item['detail']})" if item["detail"] else ""
        print(f"    {origin:44} {item['path']}  [{item['kind']}]{detail}")
    if totals["unreadable"]:
        stalled = (f", {totals['timed-out']} of them because git did not answer within "
                   f"{GIT_TIMEOUT}s" if totals["timed-out"] else "")
        print(f"\n  {totals['unreadable']} file(s) could not be read{stalled}, so this is not a "
              f"statement about everything named")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
