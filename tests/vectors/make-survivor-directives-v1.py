#!/usr/bin/env python3
"""The survivor's directives file as deploy/baremetal/survivor.py's Directives reads it: each case is the file's bytes
(hex) and what Directives.disabled() gives for them, the sorted object IDs or "refused" (every key refused).
internal/admission's ReadDisabled must give the same for the same bytes (TestSurvivorDirectivesVector), so the daemon
refuses exactly the keys the survivor applied, and every key whenever the survivor would (regalia-j18, owner item 212).

    python3 -Es tests/vectors/make-survivor-directives-v1.py > tests/vectors/survivor-directives-v1.json

The inputs are the line separators bytes.splitlines() takes, each field of a directive at and just past its bounds,
the forms a JSON document can take that the store's writer never makes, and lines that are not directives at all.
The file's ownership, mode and links are not here: tests on each side make those on the disk.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import membership, survivor  # noqa: E402

DIGEST = "ab" * 32
SIG = {"party": "owner", "key": "11" * 32, "sig": "22" * 64}


def directive(**over):
    body = {"schema": survivor.DIRECTIVE_SCHEMA, "object_id": "kek-a", "state": "disabled", "quarantine_epoch": 7,
            "quarantine_digest": DIGEST, "issued_at": "2026-10-30T12:00:00Z", "reason": "the token was seen at another site"}
    body.update(over)
    return body


def line(**over):
    return membership.canonical({"directive": directive(**over), "signature": SIG})


A, B = line(), line(object_id="kek-b")
CASES = [
    ("no directive (an empty file)", b""),
    ("one directive", A + b"\n"),
    ("one directive, no final newline", A),
    ("the same directive twice", A + b"\n" + A + b"\n"),
    ("two keys", B + b"\n" + A + b"\n"),
    ("CRLF line ends", A + b"\r\n" + B + b"\r\n"),
    ("a lone CR between lines", A + b"\r" + B),
    ("a final CR only", A + b"\r"),
    ("an empty line between two", A + b"\n\n" + B + b"\n"),
    ("a file that is one newline", b"\n"),
    ("a line that is not JSON", A + b"\nnot json\n"),
    ("a JSON array", b"[]\n"),
    ("JSON with a repeated key", A[:-1] + b',"signature":{}}\n'),
    ("a float epoch", A.replace(b'"quarantine_epoch":7', b'"quarantine_epoch":7.0') + b"\n"),
    ("an extra field beside directive and signature", membership.canonical({"directive": directive(), "signature": SIG, "x": 1}) + b"\n"),
    ("no signature", membership.canonical({"directive": directive()}) + b"\n"),
    ("an extra field in the directive", line(extra="x") + b"\n"),
    ("another schema", line(schema="regalia.survivor-directive/v2") + b"\n"),
    ("a state that re-enables", line(state="enabled") + b"\n"),
    ("a state that destroys", line(state="destroyed") + b"\n"),
    ("an object ID of 256 characters", line(object_id="k" * 256) + b"\n"),
    ("an object ID of 257 characters", line(object_id="k" * 257) + b"\n"),
    ("an object ID with a space", line(object_id="kek a") + b"\n"),
    ("an object ID with a tilde and a bang", line(object_id="!kek~") + b"\n"),
    ("an object ID with a non-ASCII letter", line(object_id="k\u00e9k") + b"\n"),
    ("an empty object ID", line(object_id="") + b"\n"),
    ("an object ID that is a number", line(object_id=5) + b"\n"),
    ("epoch 1", line(quarantine_epoch=1) + b"\n"),
    ("epoch 0", line(quarantine_epoch=0) + b"\n"),
    ("a negative epoch", line(quarantine_epoch=-3) + b"\n"),
    ("a boolean epoch", line(quarantine_epoch=True) + b"\n"),
    ("an epoch as a string", line(quarantine_epoch="7") + b"\n"),
    ("an epoch past 64 bits", line(quarantine_epoch=10 ** 30) + b"\n"),
    ("a digest in upper case", line(quarantine_digest=DIGEST.upper()) + b"\n"),
    ("a digest one short", line(quarantine_digest=DIGEST[:-1]) + b"\n"),
    ("a second 60", line(issued_at="2026-10-30T23:59:60Z") + b"\n"),
    ("the 30th of February", line(issued_at="2026-02-30T12:00:00Z") + b"\n"),
    ("a time with a fraction", line(issued_at="2026-10-30T12:00:00.5Z") + b"\n"),
    ("a time with an offset", line(issued_at="2026-10-30T12:00:00+00:00") + b"\n"),
    ("year 0", line(issued_at="0000-01-01T00:00:00Z") + b"\n"),
    ("year 1", line(issued_at="0001-01-01T00:00:00Z") + b"\n"),
    ("an empty reason", line(reason="") + b"\n"),
    ("a reason of spaces", line(reason="   ") + b"\n"),
    ("a reason with a newline", line(reason="two\nlines") + b"\n"),
    ("a reason with a right-to-left override", line(reason="seen \u202eetis\u202c") + b"\n"),
    ("a reason with a no-break space", line(reason="seen\u00a0there") + b"\n"),
    ("a reason of 512 bytes, two per character", line(reason="\u00e9" * 256) + b"\n"),
    ("a reason of 513 bytes", line(reason="\u00e9" * 256 + "x") + b"\n"),
    ("a reason with a CJK letter and an emoji", line(reason="\u9375 \U0001f511 lost") + b"\n"),
    ("a good line after a bad one", b"{}\n" + A + b"\n"),
]


def judge(raw):
    with tempfile.TemporaryDirectory() as d:
        os.chmod(d, 0o700)
        path = os.path.join(d, survivor.DIRECTIVES_FILE)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        try:
            return sorted(survivor.Directives(path, owner_uid=os.getuid()).disabled())
        except survivor.Refused:
            return "refused"


print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": [
    {"name": name, "file": raw.hex(), "disabled": judge(raw)} for name, raw in CASES]}, indent=1, ensure_ascii=False))
