#!/usr/bin/env python3
"""Writes tests/vectors/pcr-values-v2.json: a real quote from a software TPM (swtpm, tpm2-tools) with the values of
its PCRs read beside it, and the cases the unlock exchange's version 2 must refuse, each with the verifier's
exact reason. Run again only to replace the vector; both the Go client (cmd/regalia-unlock) and the Python
verifier (deploy/baremetal/attest.py) are tested against the file as it is committed.

    python3 -Es tests/vectors/make-pcr-values-v2.py > tests/vectors/pcr-values-v2.json
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import attest  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    tcti = "swtpm:path=%s/tpm.sock" % d
    tpm = subprocess.Popen(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + d, "--server", "type=unixio,path=%s/tpm.sock" % d,
                            "--ctrl", "type=unixio,path=%s/tpm.sock.ctrl" % d, "--flags", "not-need-init,startup-clear"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        env = dict(os.environ, TPM2TOOLS_TCTI=tcti)
        def run(*argv):
            done = subprocess.run(list(argv), env=env, capture_output=True, cwd=d)
            if done.returncode:
                raise SystemExit("%s: %s" % (argv[0], done.stderr.decode(errors="replace").strip()))
            return done
        for _ in range(50):
            if subprocess.run(["tpm2_pcrread", "sha256:7"], env=env, capture_output=True).returncode == 0:
                break
            time.sleep(0.1)
        run("tpm2_createek", "-c", "ek.ctx", "-G", "ecc", "-u", "ek.pub")
        run("tpm2_createak", "-C", "ek.ctx", "-c", "ak.ctx", "-G", "ecc", "-g", "sha256", "-s", "ecdsa", "-u", "ak.pub", "-n", "ak.name")
        run("tpm2_flushcontext", "-t")                                # (no resource manager in front of swtpm)
        run("tpm2_flushcontext", "-s")
        for pcr, what in ((7, b"secure boot state"), (11, b"the image"), (12, b"the credentials")):
            run("tpm2_pcrextend", "%d:sha256=%s" % (pcr, hashlib.sha256(what).hexdigest()))
        qualifying = hashlib.sha256(b"regalia pcr-values-v2 vector").hexdigest()
        run("tpm2_quote", "-c", "ak.ctx", "-l", "sha256:7,11,12", "-q", qualifying, "-m", "quote.msg", "-s", "quote.sig", "-g", "sha256")
        read = run("tpm2_pcrread", "sha256:7,11,12").stdout.decode()
        values = {}
        for line in read.splitlines():
            line = line.strip()
            if ":" in line and line.split(":")[0].strip().isdigit():
                index, value = line.split(":", 1)
                values[index.strip()] = value.strip().lower().removeprefix("0x")
        with open(os.path.join(d, "quote.msg"), "rb") as f:
            quote = f.read()
    finally:
        tpm.terminate()
        tpm.wait(10)

q = attest.parse_quote(quote)
selection = q["pcrs"]
digest = q["pcr_digest"]
assert digest == attest.expected_pcr_digest(values), "the values read beside the quote are not the quoted ones"


def reason(values):
    try:
        attest.check_reported_values(values, selection, digest)
    except attest.Refused as refusal:
        return str(refusal)
    return None


tampered = dict(values, **{"11": "%064x" % (int(values["11"], 16) ^ 1)})
cases = {"tampered": tampered, "outside_the_selection": dict(values, **{"8": "00" * 32}),
         "missing": {k: v for k, v in values.items() if k != "12"}, "another_spelling": {("0" + k if k == "7" else k): v for k, v in values.items()},
         "malformed": dict(values, **{"7": values["7"].upper()})}
print(json.dumps({
    "about": "The unlock exchange's version 2 (deploy/baremetal/unlock.py): a quote from a software TPM and the values of its "
             "PCRs read beside it; the cases a peer must refuse, with attest.check_reported_values' reasons. Made by "
             "tests/vectors/make-pcr-values-v2.py.",
    "quote": quote.hex(), "selection": selection, "pcr_digest": digest.hex(), "pcr_values": values,
    "refused": {name: {"pcr_values": v, "reason": reason(v)} for name, v in cases.items()},
}, indent=2, sort_keys=True))
