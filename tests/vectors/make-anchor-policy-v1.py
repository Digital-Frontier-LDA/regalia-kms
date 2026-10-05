#!/usr/bin/env python3
"""Writes tests/vectors/anchor-policy-v1.json (#361): the TPM's OWN Names and policy digests for the anchor-policy
authority, measured on a private swtpm by trial sessions, so deploy/baremetal/anchorpolicy.py (and the Go reader) are
held to what a TPM computes, not to a second reading of the specification.

    python3 -B tests/vectors/make-anchor-policy-v1.py > tests/vectors/anchor-policy-v1.json

Needs swtpm and tpm2-tools (measured with 5.7). The keys are PUBLIC test keys: K_A is the P-256 point of a fixed
scalar, K_sys an RSA-2048 public key generated once and kept here as PEM. No private key is written out."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PORT = 27395
ROTATION_INDEX = 0x01500395
ROTATION_ATTRIBUTES = "nt=counter|authread|policywrite|no_da"
REFS = ("anchor", "slots", "heartbeat", "signing-counter", "rotation", "signing")
K_A_SCALAR = int("361" * 21, 16) % (2 ** 255)                  # a fixed test scalar: the PUBLIC point is what is kept
# K_sys: an RSA-2048 public key generated once for these vectors (openssl genpkey), the private half not kept
K_SYS_PEM = None                                                # filled from tests/vectors/anchor-policy-ksys.pub.pem


def tpm(env, *argv, check=True):
    done = subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=env, capture_output=True)
    if check and done.returncode != 0:
        sys.exit("tpm2_%s failed: %s" % (argv[0], done.stderr.decode()[-400:]))
    return done


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "anchor-policy-ksys.pub.pem"), "rb") as f:
        ksys_pem = f.read()
    ka = ec.derive_private_key(K_A_SCALAR, ec.SECP256R1()).public_key()
    ka_pem = ka.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    ka_point = ka.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    d = tempfile.mkdtemp(prefix="anchor-policy-vectors-")
    env = dict(os.environ, TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=%d" % PORT)
    pid = os.path.join(d, "swtpm.pid")
    os.makedirs(os.path.join(d, "state"))
    subprocess.run(["swtpm", "socket", "--tpmstate", "dir=" + os.path.join(d, "state"), "--tpm2", "--server", "type=tcp,port=%d" % PORT,
                    "--ctrl", "type=tcp,port=%d" % (PORT + 1), "--flags", "not-need-init,startup-clear", "--daemon", "--pid", "file=" + pid],
                   check=True)
    try:
        time.sleep(1)
        p = lambda name: os.path.join(d, name)                      # noqa: E731
        with open(p("ka.pem"), "wb") as f:
            f.write(ka_pem)
        with open(p("ksys.pem"), "wb") as f:
            f.write(ksys_pem)

        def flush():
            tpm(env, "flushcontext", "-t", check=False)
            tpm(env, "flushcontext", "-s", check=False)

        def loadexternal(name, alg):
            flush()
            tpm(env, "loadexternal", "-C", "o", "-G", alg, "-u", p(name + ".pem"), "-c", p(name + ".ctx"), "-n", p(name + ".name"))
            tpm(env, "readpublic", "-c", p(name + ".ctx"), "-o", p(name + ".tpmt"))
            return open(p(name + ".name"), "rb").read().hex(), open(p(name + ".tpmt"), "rb").read().hex()

        def trial(*steps):
            """A trial session running `steps` (tpm2 argv lists with {S} for the session file); its final digest."""
            flush()
            tpm(env, "startauthsession", "-S", p("t.ctx"))
            for step in steps:
                tpm(env, *[a.replace("{S}", p("t.ctx")) for a in step])
            tpm(env, "getpolicydigest", "-S", p("t.ctx"), "-o", p("dig"))
            return open(p("dig"), "rb").read().hex()

        ka_name, ka_public = loadexternal("ka", "ecc")
        ksys_name, ksys_public = loadexternal("ksys", "rsa")
        refs = {}
        for ref in REFS:
            refs[ref] = trial(["policyauthorize", "-S", "{S}", "-i", "/dev/null", "-n", p("ka.name"), "-q", ref.encode().hex()])
        # the rotation counter, under PA(K_A, "rotation"), written once by the increment approval
        with open(p("pa_rot.pol"), "wb") as f:
            f.write(bytes.fromhex(refs["rotation"]))
        flush()
        tpm(env, "nvdefine", "0x%08x" % ROTATION_INDEX, "-C", "o", "-s", "8", "-a", ROTATION_ATTRIBUTES, "-L", p("pa_rot.pol"))
        public_unwritten = tpm(env, "nvreadpublic", "0x%08x" % ROTATION_INDEX).stdout.decode()
        # written once as enrolment will: under K_A's approval of "increment" (policyRef "rotation"). The counter has
        # policywrite only, so not even the owner can increment it (TPM_RC_AUTH_UNAVAILABLE): that is the point.
        inc = trial(["policycommandcode", "-S", "{S}", "TPM2_CC_NV_Increment"])
        with open(p("inc.pol"), "wb") as f:
            f.write(bytes.fromhex(inc))
        with open(p("msg"), "wb") as f:
            f.write(bytes.fromhex(inc) + b"rotation")
        with open(p("ka.key.pem"), "wb") as f:                    # the test key's private half, in the temp dir only
            f.write(ec.derive_private_key(K_A_SCALAR, ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", p("ka.key.pem"), "-out", p("sig.der"), p("msg")], check=True)
        flush()
        tpm(env, "loadexternal", "-C", "o", "-G", "ecc", "-u", p("ka.pem"), "-c", p("ka.ctx"))
        tpm(env, "verifysignature", "-c", p("ka.ctx"), "-g", "sha256", "-m", p("msg"), "-s", p("sig.der"), "-f", "ecdsa", "-t", p("inc.tkt"))
        flush()
        tpm(env, "startauthsession", "--policy-session", "-S", p("s.ctx"))
        tpm(env, "policycommandcode", "-S", p("s.ctx"), "TPM2_CC_NV_Increment")
        tpm(env, "policyauthorize", "-S", p("s.ctx"), "-i", p("inc.pol"), "-n", p("ka.name"), "-q", b"rotation".hex(), "-t", p("inc.tkt"))
        tpm(env, "nvincrement", "0x%08x" % ROTATION_INDEX, "-P", "session:" + p("s.ctx"))
        public_written = tpm(env, "nvreadpublic", "0x%08x" % ROTATION_INDEX).stdout.decode()
        name_of = lambda text: next(l.split(":", 1)[1].strip() for l in text.splitlines() if l.strip().startswith("name:"))  # noqa: E731
        pa_ksys = trial(["policyauthorize", "-S", "{S}", "-i", "/dev/null", "-n", p("ksys.name")])
        approved = {}
        for g in (1, 2):
            with open(p("g.bin"), "wb") as f:
                f.write(g.to_bytes(8, "big"))
            approved[str(g)] = trial(["policyauthorize", "-S", "{S}", "-i", "/dev/null", "-n", p("ksys.name")],
                                     ["policynv", "-S", "{S}", "-i", p("g.bin"), "0x%08x" % ROTATION_INDEX, "ule"])
        first = trial(["policycommandcode", "-S", "{S}", "TPM2_CC_NV_Increment"], ["policynvwritten", "-S", "{S}", "c"])
        later = {}
        for n in (1, 2):
            with open(p("n.bin"), "wb") as f:
                f.write(n.to_bytes(8, "big"))
            later[str(n)] = trial(["policycommandcode", "-S", "{S}", "TPM2_CC_NV_Increment"],
                                  ["policynv", "-S", "{S}", "-i", p("n.bin"), "0x%08x" % ROTATION_INDEX, "eq"])
        json.dump({
            "schema": "regalia.anchor-policy-vectors/v1",
            "measured_with": "swtpm, tpm2-tools %s" % subprocess.run(["tpm2_startup", "--version"], capture_output=True, text=True).stdout.split('version="')[-1].split('"')[0],
            "k_a": {"point": ka_point, "tpmt_public": ka_public, "name": ka_name},
            "k_sys": {"pem": ksys_pem.decode(), "tpmt_public": ksys_public, "name": ksys_name, "policy_authorize": pa_ksys},
            "refs": {ref: {"policy_ref_hex": ref.encode().hex(), "auth_policy": refs[ref]} for ref in REFS},
            "rotation": {"index": "0x%08x" % ROTATION_INDEX, "attributes": ROTATION_ATTRIBUTES, "size": 8,
                         "name_unwritten": name_of(public_unwritten), "name_written": name_of(public_written)},
            "approved": approved,                                  # P(K_sys, G) = PolicyNV(R <= G) over PA(K_sys), R written
            "increment": {"first": first, "from": later},           # CC(NV_Increment) + NvWritten(clear); CC + PolicyNV(R == n)
        }, sys.stdout, indent=1, sort_keys=True)
        sys.stdout.write("\n")
    finally:
        try:
            with open(pid) as f:
                os.kill(int(f.read().strip()), 15)
        except (OSError, ValueError):
            pass
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    main()
