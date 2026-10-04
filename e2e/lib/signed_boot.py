#!/usr/bin/env python3
"""A booted, signed image on a software TPM, for the swtpm tests of the anchor's policy writes (#242).

From #242 on, the TPM anchor is written only through PolicyAuthorize(system-phase PCR key): a write needs
PCR 11 at a value that key signed. A test node on swtpm therefore needs what systemd-stub and
systemd-pcrphase leave on a host that booted an approved image. This makes it without building an image:
  * PCR 11, extended the way the stub measures a UKI's sections and the phases extend it
    (deploy/baremetal/uki.py's pcr11), up to the phase asked for. The default is the booted system's,
    enter-initrd:leave-initrd:sysinit:ready;
  * the PCR key: RSA-2048, the size uki.py requires;
  * tpm2-pcr-signature.json, as `systemd-measure sign` writes it:
    {"sha256": [{"pcrs": [11], "pkfp", "pol", "sig"}]}, where pol is uki.policy_digest of the PCR 11 value
    and sig is RSASSA-PKCS1-v1_5 SHA-256 over pol.

As a command, for the e2e scripts (TPM2TOOLS_TCTI names the TPM):

    python3 -Es "$HERE/e2e/lib/signed_boot.py" DIR [--image NAME] [--phases PATH] [--key FILE] [--no-boot]

It writes DIR/tpm2-pcr-signature.json, plus DIR/pcr-key.pem and DIR/pcr-key.pub.pem unless --key names an
existing key. Two images signed by one key share it. It extends PCR 11 unless --no-boot (for an image
signed but not booted). It prints {"pcr11", "pol", "pkfp"}.

The TPM must have just started, with PCR 11 at zero. Extending a PCR 11 that holds anything else would not
give the signed value, so the tool refuses, and it refuses again if the TPM's PCR 11 is not the signed
value afterwards.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from deploy.baremetal import uki   # noqa: E402

SYSTEM = uki.PHASE_PATHS["system"]


def image(name="approved"):
    """A stand-in image's measured sections, different for each name: what the stub would measure."""
    tag = name.encode()
    return {"linux": b"a kernel for " + tag, "osrel": b"ID=regalia-test\nVERSION_ID=%s\n" % tag,
            "cmdline": b"root=/dev/mapper/root ro rd.shell=0 rd.emergency=reboot", "initrd": b"an initrd for " + tag,
            "uname": b"6.12.0-" + tag, "sbat": b"sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n"}


def key(directory, run=subprocess.run):
    """A new PCR key in `directory`: (private PEM path, public PEM path)."""
    private, public = os.path.join(directory, "pcr-key.pem"), os.path.join(directory, "pcr-key.pub.pem")
    run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % uki.KEY_BITS, "-out", private],
        check=True, capture_output=True)
    run(["openssl", "pkey", "-in", private, "-pubout", "-out", public], check=True, capture_output=True)
    return private, public


def fingerprint(public, run=subprocess.run):
    """systemd's pkfp: the SHA-256 of the PKCS#1 DER public key."""
    der = run(["openssl", "rsa", "-pubin", "-in", public, "-RSAPublicKey_out", "-outform", "der"], check=True, capture_output=True).stdout
    return hashlib.sha256(der).hexdigest()


def signature(parts, private, public, phases=SYSTEM, run=subprocess.run):
    """One entry of tpm2-pcr-signature.json for `parts` booted up to `phases`, signed by the key."""
    value = uki.pcr11(parts, phases)
    policy = uki.policy_digest(value)
    sig = run(["openssl", "dgst", "-sha256", "-sign", private], input=bytes.fromhex(policy), check=True, capture_output=True).stdout
    return {"pcrs": [11], "pkfp": fingerprint(public, run), "pol": policy, "sig": base64.b64encode(sig).decode()}, value


def pcr11(env=None, run=subprocess.run):
    """PCR 11 (SHA-256) as the TPM holds it, in hex."""
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, "pcr")
        run(["tpm2_pcrread", "sha256:11", "-o", out], check=True, capture_output=True, env=env)
        with open(out, "rb") as f:
            return f.read().hex()


def boot(parts, phases=SYSTEM, env=None, run=subprocess.run):
    """Extend the TPM's PCR 11 as a boot of `parts` up to `phases` would. Returns the value."""
    if pcr11(env, run) != "00" * 32:
        raise SystemExit("signed_boot: PCR 11 is not zero: this TPM did not just start, and the boot would not give the signed value")
    for name in uki.ORDER:
        if name in parts:
            for data in (b"." + name.encode() + b"\0", parts[name]):
                run(["tpm2_pcrextend", "11:sha256=" + hashlib.sha256(data).hexdigest()], check=True, capture_output=True, env=env)
    for phase in phases.split(":"):
        run(["tpm2_pcrextend", "11:sha256=" + hashlib.sha256(phase.encode()).hexdigest()], check=True, capture_output=True, env=env)
    value, want = pcr11(env, run), uki.pcr11(parts, phases)
    if value != want:
        raise SystemExit("signed_boot: the TPM's PCR 11 is %s after the boot, not the signed %s" % (value, want))
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory")
    parser.add_argument("--image", default="approved", help="the stand-in image's name (another name, another image)")
    parser.add_argument("--phases", default=SYSTEM, help="the phase path signed and booted (default: the booted system's)")
    parser.add_argument("--key", help="an existing PCR key (private PEM); its public half is FILE with .pem replaced by .pub.pem")
    parser.add_argument("--no-boot", action="store_true", help="sign only: PCR 11 is left as it is")
    args = parser.parse_args(argv)
    os.makedirs(args.directory, exist_ok=True)
    if args.key:
        private, public = args.key, args.key[:-len(".pem")] + ".pub.pem"
    else:
        private, public = key(args.directory)
    parts = image(args.image)
    entry, value = signature(parts, private, public, args.phases)
    path = os.path.join(args.directory, "tpm2-pcr-signature.json")
    with open(path, "w") as f:
        json.dump({"sha256": [entry]}, f)
    if not args.no_boot:
        boot(parts, args.phases)
    print(json.dumps({"pcr11": value, "pol": entry["pol"], "pkfp": entry["pkfp"]}))


if __name__ == "__main__":
    main()
