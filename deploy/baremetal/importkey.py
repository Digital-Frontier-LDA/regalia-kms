#!/usr/bin/env python3
"""The PIN import key's certification by the EK-bound AK (regalia-kms#702; ADR-0002 D21 point 2;
PIN-IMPORT-DESIGN.md).

The ceremony wraps a site's PIN to the host's import key (#671: an ECC P-256 storage key at 0x81000101).
The hand-copied fingerprint pins WHICH key that is; it cannot say that the key lives in this host's TPM and
cannot leave it. A host compromised before commissioning could show the fingerprint of a software P-256 key,
and the ceremony would wrap the PIN to it. This module closes that: the node's AK certifies the import key
(TPM2_Certify), and the AK is proven to sit in the TPM with the recorded EK by credential activation, the
machinery attest.py and enrol.py already use (TPM2_MakeCredential in software, TPM2_ActivateCredential on the
host). Nothing here is a new cryptographic construction.

    python3 -Es -m deploy.baremetal.importkey challenge --ek-public EK.pub --ak-public AK.pub \
        --credential CRED.bin --keep KEEP.json                 (the verifier's side, no TPM)
    sudo python3 -Es -m deploy.baremetal.importkey host-publics --out-dir DIR        (on the host: ek.pub, ak.pub)
    sudo deploy/seal-hsm-pin.sh --init-import-key --ak-credential CRED.bin [--certification FILE]
        (on the host: activates the credential FIRST, so a wrong one makes nothing; then makes the key and has
         the AK certify it: host-activate and host-certify below)
    python3 -Es -m deploy.baremetal.importkey verify --certification FILE --keep KEEP.json \
        --ek-name HEX --fingerprint HEX                        (no TPM)

WHAT verify CHECKS, each refusal naming its check:
  missing      a certification is on record at all (without one the key is trusted by its fingerprint alone)
  template     the certified public area is exactly the import key's (#671): ECC P-256, SHA-256 Name,
               AES-128-CFB, scheme and KDF NULL, empty authPolicy, attributes 0x00030472 and nothing else
  attributes   fixedTPM, fixedParent and sensitiveDataOrigin, named on their own (the template check
               above refuses the same keys; this says WHICH property is missing)
  fingerprint  the SHA-256 of the key's DER public key is the one copied by hand at the console
  ek           the EK the certification names is the one recorded for this host at intake (its EK
               certificate, #65 PoC 5.2): a certification made in ANOTHER TPM fails here
  binding      the AK is bound to that EK: the credential the verifier made for (EK, AK Name) was opened,
               and only the TPM holding both can open it (keep holds the secret's SHA-256, never the secret)
  signature    the certification verifies under that AK's public key
  signer       its qualifiedSigner is that AK under that EK
  name         the certified Name is the import key's Name (the hash of the public area checked above)
  parent       the certified object is a child of a storage key, not an object at a hierarchy: what
               TPM2_LoadExternal would make of a software key's public area
tpm2_certify (tpm2-tools 5) takes no qualifying data and always passes 00ff55aa: none is needed, the
certification states a fact of this TPM that a replay cannot change (signkey.verify_certification's reasoning).

NOT COVERED: the EK's chain to the TPM manufacturer (the swtpm EK has none; the DL360's is checked at intake,
#65 PoC 5.2): `--ek-name` is the intake record, and this module trusts it. Measured on swtpm only.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

from deploy.baremetal import attest

Refused, require = attest.Refused, attest.require

SCHEMA = "regalia-kms/import-key-certification/v1"
CHALLENGE_SCHEMA = "regalia-kms/import-key-challenge/v1"
DOCUMENT_KEYS = ("schema", "import_public", "ek_public", "ak_public", "certify", "signature", "answer")
CHALLENGE_KEYS = ("schema", "ek_name", "ak_name", "secret_sha256")
HANDLE = "0x81000101"               # seal-hsm-pin.sh's default import handle
MAX_PUBLIC, MAX_CERTIFY, MAX_SIGNATURE = 1024, 1024, 256

# seal-hsm-pin.sh --init-import-key's template (#671), field by field
ATTRIBUTES = 0x00030472             # fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|noDA|restricted|decrypt
FIXED_TPM, FIXED_PARENT, SENSITIVE_DATA_ORIGIN = 0x00000002, 0x00000010, 0x00000020
ALG_AES, ALG_CFB, AES_BITS = 0x0006, 0x0043, 128
# TPM_RH_OWNER, TPM_RH_NULL, TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM: an object at one of these has the hierarchy
# for its parent (a primary key, or anything TPM2_LoadExternal loaded); the import key is a CHILD key
HIERARCHIES = (0x40000001, 0x40000007, 0x4000000B, 0x4000000C)


def identity(public_blob):
    """(Name, DER SubjectPublicKeyInfo) of an import key's TPM2B_PUBLIC, if it is exactly the import key's template.
    Everything is read from the public area, whose hash is the Name a certification names."""
    area = attest.public_area(public_blob, "the import key's public area")
    r = attest.Reader(area, "the import key's public area")
    require(r.u("H") == attest.ALG_ECC, "template: the import key must be an ECC key")
    require(r.u("H") == attest.ALG_SHA256, "template: the import key's name algorithm must be SHA-256")
    attributes = r.u("I")
    for bit, label in ((FIXED_TPM, "fixedTPM"), (FIXED_PARENT, "fixedParent"), (SENSITIVE_DATA_ORIGIN, "sensitiveDataOrigin")):
        require(attributes & bit, "attributes: the import key is not %s (attributes 0x%08x): it is not a key made in, "
                "and kept by, one TPM" % (label, attributes))
    require(attributes == ATTRIBUTES, "template: the import key's attributes are 0x%08x, not 0x%08x" % (attributes, ATTRIBUTES))
    require(r.sized() == b"", "template: the import key must not carry an auth policy")
    require((r.u("H"), r.u("H"), r.u("H")) == (ALG_AES, AES_BITS, ALG_CFB), "template: the import key's symmetric algorithm must be AES-128-CFB")
    require(r.u("H") == attest.ALG_NULL, "template: the import key's scheme must be NULL")
    require(r.u("H") == attest.CURVE_P256, "template: the import key's curve must be NIST P-256")
    require(r.u("H") == attest.ALG_NULL, "template: the import key must not carry a KDF")
    x, y = r.sized(), r.sized()
    r.end()
    require(len(x) == 32 and len(y) == 32, "template: the import key's public point is not a P-256 point")
    point = b"\x04" + x + y
    from cryptography.hazmat.primitives.asymmetric import ec      # only here: evidence.py imports this module
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    except ValueError:
        raise Refused("template: the import key's public point is not on P-256") from None
    return attest.name_of(area), attest.P256_SPKI_PREFIX + point


def fingerprint(public_blob):
    """The SHA-256 of the import key's DER public key: what --init-import-key prints and the console copy records."""
    return hashlib.sha256(identity(public_blob)[1]).hexdigest()


def _hex(value, label, limit):
    require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})+", value) is not None, "%s is not lowercase hex" % label)
    require(len(value) <= 2 * limit, "%s is oversized" % label)
    return bytes.fromhex(value)


def check_document(document):
    """The certification document's shape: exact keys, hex fields within their sizes. Returns its parts as bytes."""
    require(isinstance(document, dict), "missing: the certification is not a document")
    keys = set(document)
    require(keys == set(DOCUMENT_KEYS), "the certification's fields mismatch: missing=%s unknown=%s"
            % (sorted(set(DOCUMENT_KEYS) - keys), sorted(keys - set(DOCUMENT_KEYS))))
    require(document["schema"] == SCHEMA, "the certification's schema must be %s" % SCHEMA)
    parts = {k: _hex(document[k], "the certification's " + k, limit) for k, limit in
             (("import_public", MAX_PUBLIC), ("ek_public", MAX_PUBLIC), ("ak_public", MAX_PUBLIC),
              ("certify", MAX_CERTIFY), ("signature", MAX_SIGNATURE), ("answer", 64))}
    require(len(parts["answer"]) == 32, "the certification's answer is not 32 bytes")
    return parts


def check_challenge(keep):
    """What the verifier kept from `challenge`: exact keys, the Names and the secret's SHA-256 in their forms."""
    require(isinstance(keep, dict) and set(keep) == set(CHALLENGE_KEYS), "the kept challenge is not one `importkey challenge` wrote")
    require(keep["schema"] == CHALLENGE_SCHEMA, "the kept challenge's schema must be %s" % CHALLENGE_SCHEMA)
    for k, n in (("ek_name", 68), ("ak_name", 68), ("secret_sha256", 64)):
        require(attest.is_hex(keep[k], n), "the kept challenge's %s is not %d lowercase hex" % (k, n))
    return keep


def qualified_parent_is_hierarchy(qualified_name, name):
    """True when `qualified_name` is that of an object whose parent is a hierarchy: H(handle || Name)."""
    return any(qualified_name == struct.pack(">H", attest.ALG_SHA256) + hashlib.sha256(struct.pack(">I", h) + name).digest()
               for h in HIERARCHIES)


def _certified(parts, ek_name, ak_name, spki, name, run):
    """The checks on the certification itself (signature, signer, name, parent), shared by verify and host_certify."""
    from deploy.baremetal import signkey                          # its TPMS_ATTEST parser; imports cryptography
    try:
        attest.verify_signature(spki, parts["certify"], parts["signature"], run)
    except Refused:
        raise Refused("signature: the certification does not verify under the AK") from None
    try:
        c = signkey.parse_certify(parts["certify"])
    except signkey.Refused as refusal:                            # membership's Refused, not attest's: name it here
        raise Refused("certify: %s" % refusal) from None
    require(c["qualified_signer"] == attest.qualified_name(ek_name, ak_name), "signer: the certification's signer is not this AK under this EK")
    require(c["extra_data"] == signkey.TOOLS_QUALIFYING, "signer: the certification carries qualifying data tpm2_certify does not")
    require(c["name"] == name, "name: the certification is for another object than this import key (certified Name %s, the key's %s)"
            % (c["name"].hex(), name.hex()))
    require(not qualified_parent_is_hierarchy(c["qualified_name"], name),
            "parent: the certified object sits directly under a hierarchy (TPM2_LoadExternal, or a primary key), not under a storage key")


def verify(document, keep, ek_name, expected_fingerprint, run=subprocess.run):
    """The import key's facts ({fingerprint, name, ek_name, ak_name}) if `document` certifies it as above, or Refused.
    `keep` is the verifier's own record of the challenge it made; `ek_name` (hex) and `expected_fingerprint` (hex) are
    the intake record and the console copy. Needs no TPM."""
    require(isinstance(ek_name, str) and attest.is_hex(ek_name, 68), "the recorded EK Name must be 68 lowercase hex")
    require(isinstance(expected_fingerprint, str) and re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint) is not None,
            "the hand-copied fingerprint must be 64 lowercase hex")
    if document is None:
        raise Refused("missing: no certification of the import key is on record: the key would be trusted by its fingerprint "
                      "alone, which cannot tell a key in this TPM from a software key (#702)")
    parts = check_document(document)
    name, spki = identity(parts["import_public"])
    require(hmac.compare_digest(hashlib.sha256(spki).hexdigest(), expected_fingerprint),
            "fingerprint: the certified key's fingerprint is %s, not the one copied by hand (%s)" % (hashlib.sha256(spki).hexdigest(), expected_fingerprint))
    ek_doc = attest.name_of(attest.public_area(parts["ek_public"], "the EK public area"))
    ak_name, ak_spki = attest.ak_identity(parts["ak_public"])
    require(hmac.compare_digest(ek_doc.hex(), ek_name),
            "ek: the certification names EK %s, not this host's EK recorded at intake (%s): it was made in another TPM" % (ek_doc.hex(), ek_name))
    keep = check_challenge(keep)
    require(hmac.compare_digest(keep["ek_name"], ek_doc.hex()) and hmac.compare_digest(keep["ak_name"], ak_name.hex())
            and hmac.compare_digest(hashlib.sha256(parts["answer"]).hexdigest(), keep["secret_sha256"]),
            "binding: the AK is not proven to be in the TPM with this EK: the answer does not open the challenge made for "
            "this EK and this AK (credential activation)")
    _certified(parts, ek_doc, ak_name, ak_spki, name, run)
    return {"fingerprint": expected_fingerprint, "name": name.hex(), "ek_name": ek_doc.hex(), "ak_name": ak_name.hex()}


# ---- the verifier's challenge (no TPM) ----

def challenge(ek_public, ak_public, run=subprocess.run, rand=os.urandom):
    """(credential, keep): attest.make_credential to this EK and this AK's Name, and what to keep to check the answer (the
    secret's SHA-256, never the secret). An AK enrolment challenge carrying nothing else (attest.make_credential's
    invariant): what it proves is only that the AK is in the TPM that holds the EK."""
    require(len(ek_public) <= MAX_PUBLIC and len(ak_public) <= MAX_PUBLIC, "a public area exceeds 1 KiB")
    ek_name = attest.name_of(attest.public_area(ek_public, "the EK public area"))
    ak_name, _ = attest.ak_identity(ak_public)
    secret = bytearray(rand(32))
    try:
        credential = attest.make_credential(ek_public, ak_name, bytes(secret), run)
        keep = {"schema": CHALLENGE_SCHEMA, "ek_name": ek_name.hex(), "ak_name": ak_name.hex(),
                "secret_sha256": hashlib.sha256(secret).hexdigest()}
    finally:
        secret[:] = bytes(len(secret))
    return credential, keep


# ---- the host (tpm2-tools against the TPM named by TPM2TOOLS_TCTI) ----

def _readpublic(handle, path, run):
    attest.tpm2("readpublic", "-c", handle, "-o", path, run=run)
    with open(path, "rb") as f:
        return f.read(MAX_PUBLIC + 1)


def _flush(run):
    # as attest.node_init: only a private simulator (no resource manager) keeps what each call loaded
    if os.environ.get("TPM2TOOLS_TCTI", "").startswith(("swtpm", "mssim")):
        run(["tpm2_flushcontext", "-t"], capture_output=True)


def host_publics(out_dir, run=subprocess.run):
    """The EK's and AK's TPM2B_PUBLIC at their persistent handles, as ek.pub and ak.pub (what `challenge` takes)."""
    with tempfile.TemporaryDirectory(prefix="importkey-") as d:
        for name, handle in (("ek.pub", attest.EK_HANDLE), ("ak.pub", attest.AK_HANDLE)):
            blob = _readpublic(handle, os.path.join(d, name), run)
            path = os.path.join(out_dir, name)
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), "wb") as f:
                f.write(blob)


def host_activate(credential_path, run=subprocess.run):
    """The secret this TPM releases for the verifier's credential (attest.node_activate), as 64 hex: proof that this
    TPM holds the EK and the AK the credential was made for. Run BEFORE the import key is made, so a credential for
    another TPM makes nothing. Not a lasting secret: it opens this one challenge, whose keep holds only its hash."""
    with tempfile.TemporaryDirectory(prefix="importkey-") as d:
        out = os.path.join(d, "secret")
        attest.node_activate(credential_path, out, run=run)
        with open(out, "rb") as f:
            secret = f.read(33)
    require(len(secret) == 32, "the activated secret is not 32 bytes")
    return secret.hex()


def host_certify(answer, handle=HANDLE, run=subprocess.run):
    """The certification document: this TPM's AK certifies the key at `handle`; with the EK's and AK's public areas and
    `answer` (host_activate's). Checked here as verify will check it, but for the intake record and the keep, which only
    the verifier has."""
    require(isinstance(answer, str) and attest.is_hex(answer, 64), "the activation answer must be 64 lowercase hex")
    with tempfile.TemporaryDirectory(prefix="importkey-") as d:
        blobs = {n: _readpublic(h, os.path.join(d, n), run) for n, h in
                 (("import", handle), ("ek", attest.EK_HANDLE), ("ak", attest.AK_HANDLE))}
        info, sig = os.path.join(d, "certify"), os.path.join(d, "sig")
        try:
            attest.tpm2("certify", "-c", handle, "-C", attest.AK_HANDLE, "-g", "sha256", "-o", info, "-s", sig, "-f", "plain", run=run)
        finally:
            _flush(run)
        with open(info, "rb") as f:
            certify = f.read(MAX_CERTIFY + 1)
        with open(sig, "rb") as f:
            signature = f.read(MAX_SIGNATURE + 1)
    document = {"schema": SCHEMA, "import_public": blobs["import"].hex(), "ek_public": blobs["ek"].hex(),
                "ak_public": blobs["ak"].hex(), "certify": certify.hex(), "signature": signature.hex(), "answer": answer}
    parts = check_document(document)
    name, _ = identity(parts["import_public"])
    ak_name, ak_spki = attest.ak_identity(parts["ak_public"])
    ek_name = attest.name_of(attest.public_area(parts["ek_public"], "the EK public area"))
    _certified(parts, ek_name, ak_name, ak_spki, name, run)
    return document


# ---- command line ----

def _load_json(path):
    return attest.load_json(attest.read(path), path)


def _write_new(path, data, mode=0o644):
    """Written whole beside its final name and renamed into place: a reader sees the old file or the new one."""
    tmp = path + ".tmp-%d" % os.getpid()
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def main(argv=None):
    p = argparse.ArgumentParser(prog="importkey", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("challenge", help="verifier, no TPM: a credential to the host's EK and AK")
    c.add_argument("--ek-public", required=True)
    c.add_argument("--ak-public", required=True)
    c.add_argument("--credential", required=True)
    c.add_argument("--keep", required=True)
    c = sub.add_parser("host-publics", help="host: export the EK's and AK's public areas")
    c.add_argument("--out-dir", required=True)
    c = sub.add_parser("host-activate", help="host: open the verifier's credential; prints the answer (64 hex)")
    c.add_argument("--credential", required=True)
    c = sub.add_parser("host-certify", help="host: the AK certifies the import key; writes the certification")
    c.add_argument("--answer-file", required=True, help="host-activate's output")
    c.add_argument("--handle", default=HANDLE)
    c.add_argument("--out", required=True)
    c = sub.add_parser("verify", help="no TPM: check a certification against the intake EK and the hand-copied fingerprint")
    c.add_argument("--certification", help="the certification document (omitted: none is on record, which is refused)")
    c.add_argument("--keep", required=True)
    c.add_argument("--ek-name", required=True, help="the host's EK Name recorded at intake (68 hex)")
    c.add_argument("--fingerprint", required=True, help="the fingerprint copied by hand at --init-import-key (64 hex)")
    a = p.parse_args(argv)
    try:
        if a.command == "challenge":
            credential, keep = challenge(attest.read(a.ek_public, MAX_PUBLIC), attest.read(a.ak_public, MAX_PUBLIC))
            _write_new(a.credential, credential)
            _write_new(a.keep, json.dumps(keep, sort_keys=True, indent=2).encode() + b"\n", 0o600)
            print("challenge made for EK %s AK %s" % (keep["ek_name"], keep["ak_name"]))
        elif a.command == "host-publics":
            host_publics(a.out_dir)
            print(json.dumps({"files": ["ek.pub", "ak.pub"]}))
        elif a.command == "host-activate":
            print(host_activate(a.credential))
        elif a.command == "host-certify":
            answer = attest.read(a.answer_file, 65).decode("ascii", "replace").strip()
            require(re.fullmatch(r"0x81[0-9a-fA-F]{6}", a.handle) is not None, "--handle must be a persistent handle, 0x81xxxxxx")
            document = host_certify(answer, a.handle)
            _write_new(a.out, json.dumps(document, sort_keys=True, indent=2).encode() + b"\n")
            print("CERTIFIED %s fingerprint %s" % (a.handle, fingerprint(bytes.fromhex(document["import_public"]))))
        else:
            document = _load_json(a.certification) if a.certification else None
            facts = verify(document, _load_json(a.keep), a.ek_name, a.fingerprint)
            print("VERIFIED " + json.dumps(facts, sort_keys=True))
        return 0
    except (Refused, OSError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
