#!/usr/bin/env python3
"""Write an OpenSC configuration under which ONLY the reader of one token is visible.

    opensc_isolate.py <slot id> <conf path>        # run with the OPENSC_CONF that resolved the slot

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
    slot, conf = argv[0], argv[1]
    module = argv[2] if len(argv) > 2 else MODULE
    listing = subprocess.run(["pkcs11-tool", "--module", module, "-L"], capture_output=True, text=True).stdout
    target = None
    for line in listing.splitlines():
        m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\): (.*)$", line)
        if m and m.group(1) == slot:
            target = base(m.group(2))
    if not target:
        sys.exit("opensc_isolate: slot %s not found" % slot)
    # Every reader PC/SC knows, straight from pcscd (pyscard lists names without connecting to a card).
    # Not opensc-tool: under the caller's OPENSC_CONF it would not show the readers that config already
    # ignores, and they would then be missing from the new ignore list.
    from smartcard.System import readers as pcsc_readers
    names = [base(str(r)) for r in pcsc_readers()]
    if names.count(target) != 1:
        sys.exit("opensc_isolate: the reader %r is not exactly one of %r" % (target, names))
    others = sorted({n for n in names if n != target})
    for n in others:
        if n in target or target in n:
            sys.exit("opensc_isolate: reader names overlap (%r / %r): cannot isolate by name" % (n, target))
    quoted = ", ".join('"%s"' % n.replace('"', '') for n in others)
    with open(conf, "w") as f:
        f.write("app default {\n  ignored_readers = %s;\n}\n" % (quoted if quoted else '"__none__"'))
    print(target)


if __name__ == "__main__":
    main(sys.argv[1:])
