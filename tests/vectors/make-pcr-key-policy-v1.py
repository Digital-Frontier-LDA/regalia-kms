#!/usr/bin/env python3
"""Writes tests/vectors/pcr-key-policy-v1.json: for each fixed system-phase PCR public key in tests/fixtures/pcr-keys,
the TPM Name it loads under, systemd's fingerprint (pkfp), and the write policy of the TPM anchor and the node's
signing key, PolicyAuthorize(Name) with an empty policyRef (#242, #357). signkey.py computes them, and every one
is checked here against a REAL TPM (swtpm) before it is written: tpm2_loadexternal gives the same Name, as it does
for the writer and as it does with signkey's explicit attributes, and a tpm2_policyauthorize trial session gives
the same digest. The Go initrd (cmd/regalia-unlock) and the Python both replay this file, so neither can drift
from the digest the TPM enforces.

    python3 -Es tests/vectors/make-pcr-key-policy-v1.py > tests/vectors/pcr-key-policy-v1.json

The exponent is written out (65537, never 0 for "the default"): the TPM's own Name pins that. A TPM refuses a small exponent
such as 3 at TPM2_LoadExternal (TPM_RC_VALUE, checked on swtpm), so no such key is a PCR key here.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from deploy.baremetal import signkey  # noqa: E402

KEYS = ROOT / "tests" / "fixtures" / "pcr-keys"


def tpm_check(pem_path, env, work):
    """(Name with tpm2-tools' default attributes, Name with signkey's, PolicyAuthorize digest) from the TPM itself."""
    def tpm(*argv):
        done = subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=env, capture_output=True)
        if done.returncode != 0:
            raise SystemExit("tpm2_%s failed: %s" % (argv[0], done.stderr.decode(errors="replace")))
        subprocess.run(["tpm2_flushcontext", "-t"], env=env, capture_output=True)
    out = {}
    for label, extra in (("default", ()), ("explicit", ("-a", signkey.PCR_KEY_TOOL_ATTRIBUTES))):
        tpm("loadexternal", "-C", "o", "-G", "rsa", *extra, "-u", str(pem_path), "-c", work + "/key.ctx", "-n", work + "/" + label + ".name")
        out[label] = pathlib.Path(work + "/" + label + ".name").read_bytes().hex()
    pathlib.Path(work + "/zero.pol").write_bytes(bytes(32))
    tpm("startauthsession", "-S", work + "/trial.ctx")
    tpm("policyauthorize", "-S", work + "/trial.ctx", "-L", work + "/policy", "-n", work + "/default.name", "-i", work + "/zero.pol")
    tpm("flushcontext", work + "/trial.ctx")
    out["policy"] = pathlib.Path(work + "/policy").read_bytes().hex()
    return out


def main():
    if not shutil.which("swtpm"):
        raise SystemExit("make-pcr-key-policy-v1: swtpm is needed: every vector is checked against a real TPM before it is written")
    work = tempfile.mkdtemp()
    try:
        sock = work + "/swtpm.sock"
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + work, "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/pid" % work], check=True, capture_output=True)
        time.sleep(0.5)
        env = dict(os.environ, TPM2TOOLS_TCTI="swtpm:path=" + sock)
        cases = []
        for path in sorted(KEYS.glob("*.pub.pem")):
            pem = path.read_bytes()
            name, policy, pkfp = signkey.pcr_key_name(pem).hex(), signkey.policy(pem).hex(), signkey.pcr_key_fingerprint(pem)
            seen = tpm_check(path, env, work)
            if (seen["default"], seen["explicit"], seen["policy"]) != (name, name, policy):
                raise SystemExit("%s: the TPM disagrees with signkey: %s, signkey name %s policy %s" % (path.name, seen, name, policy))
            cases.append({"name": path.name, "pem": pem.decode("ascii"), "tpm_name": name, "pkfp": pkfp, "policy": policy})
    finally:
        try:
            os.kill(int(pathlib.Path(work + "/pid").read_text()), 15)
        except (OSError, ValueError):
            pass
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "cases": cases}, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
