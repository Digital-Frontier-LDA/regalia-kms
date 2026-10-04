#!/usr/bin/env python3
"""A node's signing key (#199, schema v4's `signing_key`): the P-256 key in its own TPM with which it signs
heartbeats and restrictive membership changes as one party of a quorum. There is no authority host: the three
nodes and the owner keep each other fresh, so this key is what a node's vote is.

    python3 -Es -m deploy.baremetal.signkey create  --pcr-key SYSTEM-PCR-KEY.pem
    python3 -Es -m deploy.baremetal.signkey certify --out-dir DIR       (signing.pub, signing.certify, signing.sig)
    python3 -Es -m deploy.baremetal.signkey public

WHO CAN USE IT. Only a node booted on an approved image, in its booted phase. The key's authPolicy is
PolicyAuthorize(the system-phase PCR key, #242): it signs under any PCR 11 policy that key has signed, and under
nothing else. systemd-stub puts the image's signatures where systemd reads them (tpm2-pcr-signature.json), and
the system-phase key signs only the PCR 11 an approved image measures once booted, so: a stolen disk booted
elsewhere, an image nobody approved, and the same image still in its initrd all have no signature for their
PCR 11, and the key does not sign. A new image signed by the same key needs no new enrolment (the reason for
PolicyAuthorize over a PCR value). userWithAuth is CLEAR, so the policy is the only way to use it; its
authValue is empty and gives the admin role only (adminWithPolicy clear), which Certify needs and which can
neither duplicate the key (fixedParent) nor loosen its use. Made in the TPM (sensitiveDataOrigin), never leaves
it (fixedTPM), sign only (no decrypt, not restricted: it signs a digest it is given).

    attributes  fixedTPM | fixedParent | sensitiveDataOrigin | sign            (0x00040032, and nothing else)
    scheme      ECDSA with SHA-256, NIST P-256, in the key itself
    authPolicy  H(H(0^32 || TPM_CC_PolicyAuthorize || Name(PCR key)) || "")   (empty policyRef)
    parent      the owner hierarchy's ECC P-256 storage primary (tpm2_createprimary's default template)
    handle      0x81010003, beside the EK (0x81010001) and AK (0x81010002)

The PCR key's Name is computed here as tpm2_loadexternal loads it (an RSA-2048 public: decrypt | sign |
userWithAuth, SHA-256 Name, no scheme, no symmetric, the exponent written out), so the policy is checkable without
a TPM, and the TPM's own Name for the key is required to equal it, at creation and before every signature. It is
the Name tpm2_loadexternal gives by default too, so it is the same PolicyAuthorize #242's anchor writes are under
(tests/test_e2e_signed_boot.py).

WHAT THE ROOT ENROLS. The node's AK certifies the key (TPM2_Certify): the AK the manifest pins says that this TPM
holds an object of this Name, and the Name is the hash of the public area, so the attributes and the policy are
proven, not claimed. verify_certification checks it all without a TPM: the AK under the manifest's EK signed it
(its qualifiedSigner: so it is this node's TPM, and no other node's AK can stand in), for exactly this public area, whose attributes, scheme, curve and authPolicy are the ones
above for the system-phase key the root names. Only then is the point the node's `signing_key`.

SIGNING (sign) is ECDSA P-256 over SHA-256 of the message, returned as r || s with s made low (the form
membership.verify_revocation accepts), and checked against the key's public point before it is returned.
"""
import argparse
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from deploy.baremetal import attest, membership, uki

Refused, require = membership.Refused, membership.require

HANDLE = "0x81010003"
ALG_RSA = 0x0001
CC_POLICY_AUTHORIZE = 0x0000016A
ST_ATTEST_CERTIFY = 0x8017
TOOLS_QUALIFYING = bytes.fromhex("00ff55aa")         # tpm2-tools 5's fixed qualifyingData for tpm2_certify (tools/tpm2_certify.c)
# fixedTPM | fixedParent | sensitiveDataOrigin | sign: no userWithAuth, no adminWithPolicy, no restricted, no decrypt
ATTRIBUTES = 0x00040032
TOOL_ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|sign"
# how the PCR public key is loaded to check its signature (systemd's attributes for it): decrypt | sign | userWithAuth
PCR_KEY_ATTRIBUTES, PCR_KEY_TOOL_ATTRIBUTES = 0x00060040, "decrypt|sign|userwithauth"
PCR_SIGNATURE_PATHS = ("/run/systemd/tpm2-pcr-signature.json", "/etc/systemd/tpm2-pcr-signature.json", "/usr/lib/systemd/tpm2-pcr-signature.json")
P256_ORDER = membership.P256_ORDER


# ---- the policy, without a TPM ----

def pcr_key_name(pem):
    """The TPM Name of an RSA PCR public key (PEM), as tpm2_loadexternal -a PCR_KEY_TOOL_ATTRIBUTES loads it: nameAlg
    SHA-256 || SHA-256(TPMT_PUBLIC)."""
    try:
        key = serialization.load_pem_public_key(pem)
    except ValueError:
        raise Refused("the PCR key is not a PEM public key") from None
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 2048, "the PCR key must be RSA-2048 (systemd seals only to RSA)")
    numbers = key.public_numbers()
    modulus = numbers.n.to_bytes(256, "big")
    area = struct.pack(">HHI", ALG_RSA, attest.ALG_SHA256, PCR_KEY_ATTRIBUTES) + struct.pack(">H", 0) + \
        struct.pack(">HHHI", attest.ALG_NULL, attest.ALG_NULL, 2048, numbers.e) + struct.pack(">H", len(modulus)) + modulus
    return attest.name_of(area)


def pcr_key_fingerprint(pem):
    """systemd's `pkfp` for a PCR key: SHA-256 of its PKCS#1 DER public key (uki.public_key)."""
    key = serialization.load_pem_public_key(pem)
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)).hexdigest()


def policy(pem):
    """The signing key's authPolicy: PolicyAuthorize(Name(PCR key)) with an empty policyRef."""
    first = hashlib.sha256(bytes(32) + struct.pack(">I", CC_POLICY_AUTHORIZE) + pcr_key_name(pem)).digest()
    return hashlib.sha256(first).digest()


def identity(public_blob, pem):
    """(Name, uncompressed point hex) of a signing key's TPM2B_PUBLIC, if it is exactly the key above for the PCR
    key `pem`. Everything is read from the public area, whose hash is the Name the TPM certifies."""
    area = attest.public_area(public_blob, "the signing key's public area")
    r = attest.Reader(area, "the signing key's public area")
    require(r.u("H") == attest.ALG_ECC, "the signing key must be an ECC key")
    require(r.u("H") == attest.ALG_SHA256, "the signing key's name algorithm must be SHA-256")
    attributes = r.u("I")
    require(attributes == ATTRIBUTES, "the signing key must be a fixedTPM, sign-only key made in the TPM and usable only through "
            "its policy (attributes 0x%08x, not 0x%08x)" % (attributes, ATTRIBUTES))
    require(r.sized() == policy(pem), "the signing key's policy is not PolicyAuthorize of this system-phase PCR key")
    require(r.u("H") == attest.ALG_NULL, "a signing key has no symmetric algorithm")
    require((r.u("H"), r.u("H")) == (attest.ALG_ECDSA, attest.ALG_SHA256), "the signing key's scheme must be ECDSA with SHA-256")
    require(r.u("H") == attest.CURVE_P256, "the signing key's curve must be NIST P-256")
    require(r.u("H") == attest.ALG_NULL, "the signing key must not carry a KDF")
    x, y = r.sized(), r.sized()
    r.end()
    require(len(x) == 32 and len(y) == 32, "the signing key's public point is not a P-256 point")
    point = b"\x04" + x + y
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        raise Refused("the signing key's public point is not on P-256") from None
    return attest.name_of(area), point.hex()


def parse_certify(blob):
    """TPMS_ATTEST for a Certify: its signer, extra data and the certified Name."""
    r = attest.Reader(blob, "the certification")
    require(r.u("I") == attest.TPM_GENERATED, "the certification was not generated by a TPM (magic)")
    require(r.u("H") == ST_ATTEST_CERTIFY, "the attestation is not a certification")
    out = {"qualified_signer": r.sized(), "extra_data": r.sized()}
    r.take(8 + 4 + 4 + 1 + 8)                       # clockInfo and firmwareVersion
    out["name"], out["qualified_name"] = r.sized(), r.sized()
    r.end()
    return out


def verify_certification(public_blob, certification, signature, ak_public, ek_name, pem, run=subprocess.run):
    """The node's `signing_key` entry ({"alg": "ecdsa-p256", "key": <130 hex>}), if the AK `ak_public` under the EK
    named `ek_name` (hex), the node's in the manifest, certified a key of exactly this public area, and the area is
    the signing key for the system-phase PCR key `pem`. Needs no TPM. (tpm2_certify takes no qualifying data: it
    always passes TOOLS_QUALIFYING. None is needed: the certification states a fact of this TPM, which a replay
    cannot change.)"""
    require(len(public_blob) <= 1024 and len(certification) <= 1024 and len(signature) <= 256, "a signing key document is oversized")
    name, point = identity(public_blob, pem)
    ak_name, spki = attest.ak_identity(ak_public)
    try:
        attest.verify_signature(spki, certification, signature, run)
    except attest.Refused:
        raise Refused("the certification's signature does not verify under the AK") from None
    c = parse_certify(certification)
    require(c["qualified_signer"] == attest.qualified_name(bytes.fromhex(ek_name), ak_name), "the certification's signer is not this AK under this EK")
    require(c["extra_data"] == TOOLS_QUALIFYING, "the certification carries qualifying data tpm2_certify does not")
    require(c["name"] == name, "the certification is for another key than this public area")
    return {"alg": "ecdsa-p256", "key": point}


def low_s(der):
    """r || s (hex) of a DER ECDSA P-256 signature, with s made low."""
    r, s = decode_dss_signature(der)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def pcr_signature(document, pem, pcr11_hex):
    """(policy, signature) from a tpm2-pcr-signature.json: the one entry by this PCR key over PolicyPCR(PCR 11 =
    `pcr11_hex`), or Refused: this boot is not an approved image's booted phase."""
    require(isinstance(document, dict) and isinstance(document.get("sha256"), list), "the PCR signature document has no SHA-256 bank")
    want, fingerprint = uki.policy_digest(pcr11_hex), pcr_key_fingerprint(pem)
    mine = [e for e in document["sha256"] if isinstance(e, dict) and e.get("pkfp") == fingerprint and e.get("pcrs") == [11] and e.get("pol") == want]
    require(len(mine) == 1, "this boot's PCR 11 carries no signature by the system-phase PCR key: the signing key signs only in an "
            "approved image's booted phase")
    try:
        return bytes.fromhex(want), base64.b64decode(mine[0].get("sig", ""), validate=True)
    except ValueError:
        raise Refused("the PCR signature is not base64") from None


# ---- the TPM ----

def _env(tcti):
    return dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None


def _tpm(run, tcti, *args):
    done = run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=_env(tcti))
    _flush_transients(run, tcti)            # each call's objects are in its saved context files; the next call loads them
    require(done.returncode == 0, "tpm2_%s failed: %s" % (args[0], (done.stderr or b"").decode("utf-8", "replace").strip()[-300:]))
    return done.stdout


def _flush_transients(run, tcti):
    """As attest.node_init: only a private simulator, which has no resource manager, keeps what each call loaded (three
    object slots), so there every call's transient objects are flushed after it. Production goes through the kernel's
    resource manager (/dev/tpmrm0), which does this per connection, and flushing everything there would break the TPM's
    other users."""
    if (tcti or os.environ.get("TPM2TOOLS_TCTI", "")).startswith(("swtpm", "mssim")):
        run(["tpm2_flushcontext", "-t"], capture_output=True, env=_env(tcti))


def _write(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(data)


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def create(pem, tcti=None, run=subprocess.run, record=None):
    """Make the signing key in this TPM, persistent at HANDLE, its policy PolicyAuthorize(`pem`). Returns its
    TPM2B_PUBLIC. A handle already in use is refused: the key a manifest names is never replaced in place.
    `record(name_hex)`, if given, is called with the new key's Name after it is made and BEFORE it is persistent,
    so a crash between the two leaves a key its caller can prove it made (enrol's journal)."""
    held = run(["tpm2_readpublic", "-c", HANDLE], capture_output=True, env=_env(tcti))
    require(held.returncode != 0, "%s already holds a key: a node's signing key is made once (`signkey public` reads it)" % HANDLE)
    with tempfile.TemporaryDirectory(prefix="signkey-") as d:
        p = {n: os.path.join(d, n) for n in ("pcr.pem", "pcr.ctx", "pcr.name", "policy", "srk.ctx", "key.pub", "key.priv", "key.ctx")}
        _write(p["pcr.pem"], pem)
        # the TPM's own Name for the PCR key must be the one the policy is computed from (and the root checks)
        _tpm(run, tcti, "loadexternal", "-C", "o", "-G", "rsa", "-a", PCR_KEY_TOOL_ATTRIBUTES, "-u", p["pcr.pem"], "-c", p["pcr.ctx"], "-n", p["pcr.name"])
        require(_read(p["pcr.name"]) == pcr_key_name(pem), "the TPM names the PCR key otherwise than this policy does")
        _write(p["policy"], policy(pem))
        _tpm(run, tcti, "createprimary", "-C", "o", "-g", "sha256", "-G", "ecc256", "-c", p["srk.ctx"])
        _tpm(run, tcti, "create", "-C", p["srk.ctx"], "-g", "sha256", "-G", "ecc256:ecdsa-sha256", "-a", TOOL_ATTRIBUTES, "-L", p["policy"],
             "-u", p["key.pub"], "-r", p["key.priv"])
        _tpm(run, tcti, "load", "-C", p["srk.ctx"], "-u", p["key.pub"], "-r", p["key.priv"], "-c", p["key.ctx"])
        if record is not None:
            record(attest.name_of(attest.public_area(_read(p["key.pub"]), "the signing key's public area")).hex())
        _tpm(run, tcti, "evictcontrol", "-C", "o", "-c", p["key.ctx"], HANDLE)
        blob = _read(p["key.pub"])
    identity(blob, pem)                              # what was made is what the root will check
    return blob


def public(tcti=None, run=subprocess.run):
    """The TPM2B_PUBLIC of the key at HANDLE."""
    with tempfile.TemporaryDirectory(prefix="signkey-") as d:
        out = os.path.join(d, "key.pub")
        _tpm(run, tcti, "readpublic", "-c", HANDLE, "-o", out)
        return _read(out)


def certify(tcti=None, run=subprocess.run):
    """(TPMS_ATTEST, DER signature): this node's AK certifies the signing key."""
    with tempfile.TemporaryDirectory(prefix="signkey-") as d:
        info, sig = os.path.join(d, "certify"), os.path.join(d, "sig")
        _tpm(run, tcti, "certify", "-c", HANDLE, "-C", attest.AK_HANDLE, "-g", "sha256", "-o", info, "-s", sig, "-f", "plain")
        return _read(info), _read(sig)


def sign(message, pem, tcti=None, run=subprocess.run, signatures=None):
    """ECDSA P-256 over SHA-256(`message`) by the signing key, as r || s hex with low s, under a policy session: PolicyPCR
    of this boot's PCR 11, then PolicyAuthorize with the system-phase key's signature over it. `signatures`: the parsed
    tpm2-pcr-signature.json (default: the first of PCR_SIGNATURE_PATHS that exists)."""
    if signatures is None:
        found = [p for p in PCR_SIGNATURE_PATHS if os.path.exists(p)]
        require(found, "no tpm2-pcr-signature.json: this boot is not a UKI with signed PCR policies")
        signatures = membership.load(_read(found[0]), 65536)
    with tempfile.TemporaryDirectory(prefix="signkey-") as d:
        p = {n: os.path.join(d, n) for n in ("pcr11", "pcr.pem", "pcr.ctx", "pcr.name", "pol", "pol.sig", "ticket", "session", "digest", "sig")}
        _tpm(run, tcti, "pcrread", "sha256:11", "-o", p["pcr11"])
        approved, rsa_sig = pcr_signature(signatures, pem, _read(p["pcr11"]).hex())
        _write(p["pcr.pem"], pem)
        _write(p["pol"], approved)
        _write(p["pol.sig"], rsa_sig)
        _write(p["digest"], hashlib.sha256(message).digest())
        _tpm(run, tcti, "loadexternal", "-C", "o", "-G", "rsa", "-a", PCR_KEY_TOOL_ATTRIBUTES, "-u", p["pcr.pem"], "-c", p["pcr.ctx"], "-n", p["pcr.name"])
        require(_read(p["pcr.name"]) == pcr_key_name(pem), "the TPM names the PCR key otherwise than this policy does")
        _tpm(run, tcti, "verifysignature", "-c", p["pcr.ctx"], "-g", "sha256", "-m", p["pol"], "-s", p["pol.sig"], "-f", "rsassa", "-t", p["ticket"])
        _tpm(run, tcti, "startauthsession", "--policy-session", "-S", p["session"])
        try:
            _tpm(run, tcti, "policypcr", "-S", p["session"], "-l", "sha256:11")
            _tpm(run, tcti, "policyauthorize", "-S", p["session"], "-i", p["pol"], "-n", p["pcr.name"], "-t", p["ticket"])
            _tpm(run, tcti, "sign", "-c", HANDLE, "-p", "session:" + p["session"], "-g", "sha256", "-d", "-f", "plain", "-o", p["sig"], p["digest"])
        finally:
            run(["tpm2_flushcontext", p["session"]], capture_output=True, env=_env(tcti))
        out = low_s(_read(p["sig"]))
    _, point = identity(public(tcti, run), pem)
    membership.verify_revocation("ecdsa-p256", point, message, out, "the signing key's")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(prog="signkey", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="op", required=True)
    c = sub.add_parser("create", help="make the signing key in this TPM")
    c.add_argument("--pcr-key", required=True, help="the system-phase PCR public key (PEM) the image carries")
    k = sub.add_parser("certify", help="the AK's certification of the signing key, for the root")
    k.add_argument("--out-dir", required=True)
    sub.add_parser("public", help="the signing key's TPM2B_PUBLIC, hex")
    args = parser.parse_args(argv)
    try:
        if args.op == "create":
            print(create(_read(args.pcr_key)).hex())
        elif args.op == "certify":
            info, sig = certify()
            for name, data in (("signing.pub", public()), ("signing.certify", info), ("signing.sig", sig)):
                _write(os.path.join(args.out_dir, name), data)
            print(json.dumps({"files": ["signing.pub", "signing.certify", "signing.sig"]}))
        else:
            print(public().hex())
    except Refused as refusal:
        print("signkey: refused: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
