#!/usr/bin/env python3
"""Write an OpenSC configuration under which ONLY the readers of the tokens under test are visible.

    opensc_isolate.py <slot id>[,<slot id>…] <conf path> [module]   # run with the OPENSC_CONF that resolved the slots

A drill that uses two cards (a restore from one to the other, two sites) names both slots; every other
reader is ignored.

OpenSC ignores a reader whose name CONTAINS an ignored_readers entry: the match is by SUBSTRING, not by
equality. That is why reader names that overlap are refused below, and why a configuration that lists
" " ignores every reader. If OpenSC ever matched by equality instead, both would silently change.

Why: OpenSC numbers PKCS#11 slots over the readers it sees. When a token's reader disappears (a USB
removal, a pcscd restart) the readers after it are renumbered, and another token can take its slot ID,
so a login "on the same slot" can hand this token's PIN to a different card (measured 2026-10-02:
DENK0404380 slid into DENK0404144's slot 0x4). With every other reader ignored there is no other
token to slide in, and OpenSC no longer probes the other cards (an SLE-4442 in the ACR40U cost ~15 s a
call; the YubiKey's PIV applet was left selected, which cost three PIV PIN tries elsewhere).

Readers are ignored by their BASE name (the PC/SC name without the trailing "NN NN" index), so the
rule still holds after re-enumeration changes the index. Refuses (exit 1) if the slot's reader cannot
be found or another reader shares its base name.
"""
import re
import subprocess
import sys

MODULE = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"


def base(name):
    return re.sub(r"\s+\d{2}\s+\d{2}\s*$", "", name.strip())


def main(argv):
    slots, conf = [s for s in argv[0].split(",") if s], argv[1]
    module = argv[2] if len(argv) > 2 else MODULE
    if not slots or len(set(slots)) != len(slots):
        sys.exit("opensc_isolate: name each slot once")
    listing = subprocess.run(["pkcs11-tool", "--module", module, "-L"], capture_output=True, text=True).stdout
    found = {}
    for line in listing.splitlines():
        m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\): (.*)$", line)
        if m and m.group(1) in slots:
            found[m.group(1)] = base(m.group(2))
    missing = [s for s in slots if s not in found]
    if missing:
        sys.exit("opensc_isolate: slot(s) %s not found" % ", ".join(missing))
    targets = sorted(set(found.values()))
    if len(targets) != len(slots):
        sys.exit("opensc_isolate: two of the slots share one reader name: cannot isolate by name")
    # Every reader PC/SC knows, straight from pcscd (pyscard lists names without connecting to a card).
    # Not opensc-tool: under the caller's OPENSC_CONF it would not show the readers that config already
    # ignores, and they would then be missing from the new ignore list.
    try:
        from smartcard.System import readers as pcsc_readers
    except ImportError:
        sys.exit("opensc_isolate: needs pyscard (python3-pyscard) in the python3 on PATH")
    names = [base(str(r)) for r in pcsc_readers()]
    for target in targets:
        if names.count(target) != 1:
            sys.exit("opensc_isolate: the reader %r is not exactly one of %r" % (target, names))
    others = sorted({n for n in names if n not in targets})
    for n in others + targets:
        for target in targets:
            if n != target and (n in target or target in n):
                sys.exit("opensc_isolate: reader names overlap (%r / %r): cannot isolate by name" % (n, target))
    # The snapshot misses a reader that is off the bus right now (e.g. a YubiKey replugged later), so
    # the caller's own list (HSM_IGNORE_READERS, comma-separated) is always kept as well.
    import os
    extra = [n.strip().replace('"', "") for n in os.environ.get("HSM_IGNORE_READERS", "").split(",") if n.strip()]
    for n in extra:
        for target in targets:
            if n in target:
                sys.exit("opensc_isolate: HSM_IGNORE_READERS entry %r would hide the reader %r under test" % (n, target))
    quoted = ", ".join('"%s"' % n.replace('"', '') for n in sorted(set(others) | set(extra)))
    with open(conf, "w") as f:
        f.write("app default {\n  ignored_readers = %s;\n}\n" % (quoted if quoted else '"__none__"'))
    print("\n".join(targets))


if __name__ == "__main__":
    main(sys.argv[1:])
