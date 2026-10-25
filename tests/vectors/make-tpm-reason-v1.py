#!/usr/bin/env python3
"""The suffix a refused anchor read carries, " (TPM: …)", decided by the Python (membership._why) for raw tool output:
each case is the bytes a TPM tool wrote on stderr (hex), how many bytes came back on stdout, the size asked for, and
the suffix. cmd/regalia-unlock/membership's tpmReason must give the same suffix for the same bytes as its error text
(TestTheTPMReasonIsTheSameRuleInBoth), so a reason is made safe to print the same way in both readers (#450).

    python3 -Es tests/vectors/make-tpm-reason-v1.py > tests/vectors/tpm-reason-v1.json

The inputs are the ways a tool's text can differ between the readers or reach a terminal unsafely: a line separator
other than "\\n", an ANSI escape, a C1 control, a run of bytes that are not UTF-8, a truncated or surrogate sequence,
a text longer than the bound, a line that is nothing but controls.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import membership as m  # noqa: E402

CASES = [
    ("the last line, not the first", b"WARNING:esys: a non-TPM Error\nERROR: TPM_RC_RETRY\n\n", 0, 8),
    ("an ANSI colour escape", b"\x1b[31mERROR\x1b[0m: TPM_RC_RETRY", 0, 8),
    ("a carriage return inside the line", b"progress 10%\rERROR: TPM_RC_YIELDED\r\n", 0, 8),
    ("a run of bytes that are not UTF-8", b"bad \xff\xfe\xfd byte", 0, 8),
    ("a truncated sequence", b"cut \xe2\x82 end", 0, 8),
    ("an encoded surrogate", b"half \xed\xa0\x80 pair", 0, 8),
    ("C1 controls (NEL, CSI)", b"one\xc2\x85two\xc2\x9b3", 0, 8),
    ("a NUL and a BEL", b"nul\x00bel\x07end", 0, 48),
    ("U+FFFD already in the text, twice", b"was \xef\xbf\xbd\xef\xbf\xbd here", 0, 8),
    ("a Unicode line separator is not a newline", b"a\xe2\x80\xa8b", 0, 8),
    ("more than 200 characters, multi-byte", "é".encode() * 250, 0, 8),
    ("more than 200 characters after a bad byte", b"\xff" + b"x" * 300, 0, 8),
    ("nothing but controls: the byte count", b"\x1b\x07\r\n\t\n", 3, 8),
    ("no text at all: the byte count", b"", 0, 48),
]


def suffix(stderr, stdout_len, size):
    return m._why(subprocess.CompletedProcess(["tpm2_nvread"], 1, b"\0" * stdout_len, stderr), size)


print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": [
    {"name": name, "stderr": stderr.hex(), "stdout_len": n, "size": size, "suffix": suffix(stderr, n, size)}
    for name, stderr, n, size in CASES]}, indent=1, ensure_ascii=False))
