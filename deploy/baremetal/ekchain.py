#!/usr/bin/env python3
"""A server's TPM EK certificates, checked at intake against the pinned Infineon OPTIGA roots (regalia-kms-x6x, #190).

    python3 -Es -m deploy.baremetal.ekchain verify --server server-2 \\
        --rsa EK.der CA.der --ecc EK.der CA.der [--ek-public EK.pub] [--out RECORD.json]
    python3 -Es -m deploy.baremetal.ekchain pins

Each server is checked on its own, from its own EK certificates (tpm2_getekcertificate, NV 0x1c00002 for RSA
and 0x1c0000a for ECC) and the issuing CA its AIA names: one server's pass says nothing about another's.

For each family (rsa, ecc), in this order, and every failure a refusal:

  root      deploy/baremetal/ekroots/<file>, its DER SHA-256 the one PINS states for the family. The roots were
            pinned from public sources that agree (ekroots/SOURCES.md); a root file that is not the pinned
            one refuses the run before anything is verified.
  CA        the issuing CA's SubjectPublicKeyInfo SHA-256 one of the family's ca-spki pins. The KEY is pinned,
            not the certificate: Infineon's CA 029 exists as issued in 2017 and as re-issued in 2023 under
            one key (ekroots/SOURCES.md, "AC3"), and the EK's AIA serves the re-issue. A CA with the right
            name and another key, or the other family's CA, is refused here.
  chain     openssl verify -x509_strict -no-CApath -no-CAstore -CAfile ROOT -untrusted CA -show_chain EK,
            in an environment with no SSL_CERT_* variable. NEVER -partial_chain: the trust anchor is the
            pinned root and nothing else, so a chain that stops at the CA fails. The pass is rc 0 AND
            "EK: OK" on stdout AND the chain openssl printed ending in the root's subject; openssl's
            output is kept verbatim in the record either way.

Both families are required: a TPM read at intake gives both certificates (the DL360's Infineon TPMs carry
both), and a run that leaves one out is refused, never "verified" on the other alone.
ek_name is written only when both families passed. It is the Name of the RSA EK
that enrolment makes (enrol._this_tpms_ek: tpm2_createek -G rsa, the TCG default template L-1):
000b || SHA-256(TPMT_PUBLIC), the public area built from that template and the certificate's modulus. With
--ek-public (tpm2_createek -G rsa -u's output, read on the same server), that public area must be byte for
byte the one built from the certificate, and the record says the Name was read from the TPM.

Exit 0 writes the record (RECORD.json, or stdout) with "status": "verified"; exit 1 prints every finding
and writes a record with "status": "refused" and NO ek_name. Standard library and openssl.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

from deploy.baremetal import attest

RECORD_SCHEMA = "regalia-kms/ek-intake/v1"
PINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ekroots")
FAMILIES = ("rsa", "ecc")

# TCG EK Credential Profile 2.0, template L-1 (what tpm2_createek -G rsa makes): fixedTPM | fixedParent |
# sensitiveDataOrigin | adminWithPolicy | restricted | decrypt; PolicyA (PolicySecret(TPM_RH_ENDORSEMENT));
# AES-128-CFB, no scheme, 2048 bits, exponent 0 (65537).
EK_RSA_ATTRIBUTES = 0x000300B2
EK_POLICY_A = bytes.fromhex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
ALG_RSA, ALG_AES, ALG_CFB, ALG_NULL = 0x0001, 0x0006, 0x0043, 0x0010


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


# --- DER, as much of it as a certificate's SubjectPublicKeyInfo needs ---

def _tlv(data, i, label):
    require(i + 2 <= len(data), "%s: truncated DER" % label)
    tag, n = data[i], data[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        require(1 <= k <= 4 and i + k <= len(data), "%s: bad DER length" % label)
        n = int.from_bytes(data[i:i + k], "big")
        i += k
    require(i + n <= len(data), "%s: truncated DER" % label)
    return tag, data[i:i + n], i + n


def _children(body, label):
    out, i = [], 0
    while i < len(body):
        tag, value, j = _tlv(body, i, label)
        out.append((tag, value, body[i:j]))
        i = j
    return out


def spki_der(cert_der, label):
    """The certificate's SubjectPublicKeyInfo, as the DER bytes it holds."""
    tag, cert, end = _tlv(cert_der, 0, label)
    require(tag == 0x30 and end == len(cert_der), "%s is not one DER certificate" % label)
    tbs = _children(cert, label)
    require(len(tbs) == 3 and tbs[0][0] == 0x30, "%s is not a certificate" % label)
    fields = _children(tbs[0][1], label)
    if fields and fields[0][0] == 0xA0:          # [0] version
        fields = fields[1:]
    # serial, signature, issuer, validity, subject, subjectPublicKeyInfo
    require(len(fields) >= 6 and fields[5][0] == 0x30, "%s has no SubjectPublicKeyInfo" % label)
    return fields[5][2]


def spki_sha256(cert_der, label):
    return hashlib.sha256(spki_der(cert_der, label)).hexdigest()


def rsa_public(cert_der, label):
    """(modulus, exponent) of an RSA certificate's key."""
    alg, bits = _children(_tlv(spki_der(cert_der, label), 0, label)[1], label)
    require(alg[1].startswith(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"), "%s is not an RSA key" % label)
    require(bits[0] == 0x03 and bits[1][:1] == b"\x00", "%s: bad key BIT STRING" % label)
    n, e = _children(_tlv(bits[1][1:], 0, label)[1], label)
    require(n[0] == 0x02 and e[0] == 0x02, "%s: bad RSAPublicKey" % label)
    return n[1].lstrip(b"\x00"), int.from_bytes(e[1], "big")


def der_of(blob, label):
    """A certificate file's DER: the file itself, or the one PEM block it holds."""
    if blob.lstrip().startswith(b"-----BEGIN"):
        m = re.fullmatch(rb"\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*", blob)
        require(m is not None, "%s is not exactly one PEM certificate" % label)
        return base64.b64decode(b"".join(m.group(1).split()), validate=True)
    return blob


def pem_of(der):
    b = base64.b64encode(der).decode()
    return "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n" % "\n".join(b[i:i + 64] for i in range(0, len(b), 64))


# --- the EK's Name ---

def ek_public_area_l1(modulus):
    """The TPMT_PUBLIC tpm2_createek -G rsa makes for an EK with this modulus (template L-1)."""
    require(len(modulus) == 256, "the RSA EK is not 2048 bits; template L-1 does not make it")
    return (struct.pack(">HHI", ALG_RSA, attest.ALG_SHA256, EK_RSA_ATTRIBUTES)
            + struct.pack(">H", len(EK_POLICY_A)) + EK_POLICY_A
            + struct.pack(">HHHHHI", ALG_AES, 128, ALG_CFB, ALG_NULL, 2048, 0)
            + struct.pack(">H", len(modulus)) + modulus)


def ek_name(rsa_ek_der, ek_public=None):
    """(Name hex, source). The Name of the RSA EK the certificate certifies, under template L-1; with
    `ek_public` (a TPM2B_PUBLIC from tpm2_createek -G rsa -u), that area must be exactly the template's."""
    modulus, exponent = rsa_public(rsa_ek_der, "the RSA EK certificate")
    require(exponent == 65537, "the RSA EK certificate's exponent is %d; template L-1 makes 65537" % exponent)
    area = ek_public_area_l1(modulus)
    source = "rsa-ek-certificate+tcg-template-l1"
    if ek_public is not None:
        held = attest.public_area(ek_public, "--ek-public")
        require(held == area, "--ek-public is not the default-template RSA EK of this certificate's key: it is "
                "another TPM's EK, another template, or not the TPM this certificate was read from")
        source = "tpm2_createek-public-area"
    return attest.name_of(area).hex(), source


# --- PINS ---

def load_pins(directory=PINS_DIR):
    """{"root": {family: (sha256, path)}, "ca_spki": {family: {sha256: label}}, "sha256": PINS file's}."""
    path = os.path.join(directory, "PINS")
    with open(path, "rb") as f:
        raw = f.read()
    roots, cas = {}, {f: {} for f in FAMILIES}
    for n, line in enumerate(raw.decode("ascii").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(None, 3)
        require(len(parts) == 4 and parts[1] in FAMILIES and re.fullmatch(r"[0-9a-f]{64}", parts[2]),
                "PINS line %d is not '<root|ca-spki> <rsa|ecc> <sha256> <file or label>'" % n)
        kind, family, digest, rest = parts
        if kind == "root":
            require(family not in roots, "PINS pins two roots for %s" % family)
            require(re.fullmatch(r"[a-z0-9.-]+\.der", rest) is not None, "PINS line %d: bad root file name" % n)
            roots[family] = (digest, os.path.join(directory, rest))
        elif kind == "ca-spki":
            cas[family][digest] = rest
        else:
            raise Refused("PINS line %d: unknown kind %r" % (n, kind))
    for family in FAMILIES:
        require(family in roots and cas[family], "PINS has no root or no CA key for %s" % family)
    return {"root": roots, "ca_spki": cas, "sha256": hashlib.sha256(raw).hexdigest()}


def pinned_root(pins, family):
    """The family's root DER, refused unless it is the pinned one."""
    digest, path = pins["root"][family]
    with open(path, "rb") as f:
        der = f.read()
    require(hashlib.sha256(der).hexdigest() == digest, "%s is not the pinned %s root (PINS says %s..., the file is %s...)"
            % (os.path.basename(path), family, digest[:16], hashlib.sha256(der).hexdigest()[:16]))
    return der


# --- openssl ---

def openssl_verify(root_der, ca_der, ek_der, run=subprocess.run, attime=None):
    """openssl verify -x509_strict of EK -> CA -> ROOT, the root the only anchor. {"argv", "rc", "stdout", "stderr",
    "chain_ends_at_root"}; argv names the files by role, as they were written to a scratch directory."""
    with tempfile.TemporaryDirectory(prefix="ekchain-") as d:
        for name, der in (("root.pem", root_der), ("ca.pem", ca_der), ("ek.pem", ek_der)):
            with open(os.path.join(d, name), "w") as f:
                f.write(pem_of(der))
        argv = ["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile", "root.pem",
                "-untrusted", "ca.pem", "-show_chain"]
        if attime is not None:
            argv += ["-attime", str(int(attime))]
        argv.append("ek.pem")
        require("-partial_chain" not in argv, "internal: -partial_chain is never passed")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
        p = run(argv, cwd=d, env=env, capture_output=True, text=True, timeout=60)
        root_subject = run(["openssl", "x509", "-in", "root.pem", "-noout", "-subject"],
                           cwd=d, env=env, capture_output=True, text=True, timeout=60)
    chain = [l for l in p.stdout.splitlines() if l.startswith("depth=")]
    subject = root_subject.stdout.strip()
    ends = (root_subject.returncode == 0 and subject.startswith("subject=") and len(chain) == 3
            and chain[2] == "depth=2: " + subject[len("subject="):])
    return {"argv": argv, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr, "chain_ends_at_root": ends}


def openssl_version(run=subprocess.run):
    p = run(["openssl", "version"], capture_output=True, text=True, timeout=60)
    return p.stdout.strip()


# --- intake ---

def verify_family(pins, family, ek_der, ca_der, run=subprocess.run):
    """One family's evidence and findings: ({...}, [finding, ...]). An empty list is a pass."""
    findings = []
    ev = {"ek_cert_sha256": hashlib.sha256(ek_der).hexdigest(), "ca_cert_sha256": hashlib.sha256(ca_der).hexdigest()}
    try:
        root = pinned_root(pins, family)
        ev["root_sha256"] = hashlib.sha256(root).hexdigest()
    except (Refused, OSError) as e:
        return ev, ["%s: %s" % (family, e)]
    try:
        ev["ca_spki_sha256"] = spki_sha256(ca_der, "the %s CA" % family)
        require(ev["ca_spki_sha256"] in pins["ca_spki"][family],
                "the %s issuing CA's key (SPKI %s...) is not a pinned %s CA key; a CA with another key, or the other "
                "family's CA, is refused" % (family, ev["ca_spki_sha256"][:16], family))
        ev["ca"] = pins["ca_spki"][family][ev["ca_spki_sha256"]]
    except Refused as e:
        findings.append("%s: %s" % (family, e))
        return ev, findings
    out = openssl_verify(root, ca_der, ek_der, run)
    ev["openssl"] = out
    if out["rc"] != 0 or not out["stdout"].startswith("ek.pem: OK\n"):
        findings.append("%s: openssl verify -x509_strict refused the chain (rc %d): %s"
                        % (family, out["rc"], (out["stderr"] or out["stdout"]).strip().replace("\n", " | ")))
    elif not out["chain_ends_at_root"]:
        findings.append("%s: openssl's chain is not EK -> CA -> the pinned root:\n%s" % (family, out["stdout"]))
    return ev, findings


def intake(server, chains, ek_public=None, pins_dir=PINS_DIR, run=subprocess.run, now=None):
    """The intake record for one server: chains is {family: (ek_der, ca_der)}. Returns (record, findings)."""
    require(re.fullmatch(r"server-[0-9]+", server) is not None, "--server must be server-<n>: the hostnames and "
            "chassis serials stay in the private repository")
    missing = [f for f in FAMILIES if f not in chains]
    require(not missing, "the %s EK certificate and its CA are required: intake verifies both families, and "
            "ek_name is the RSA EK's" % " and ".join(f.upper() for f in missing))
    require(set(chains) == set(FAMILIES), "unknown family: %s" % sorted(set(chains) - set(FAMILIES)))
    pins = load_pins(pins_dir)
    record = {"schema": RECORD_SCHEMA, "server": server, "pins_sha256": pins["sha256"],
              "openssl_version": openssl_version(run),
              "checked_at": (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "families": {}}
    findings = []
    for family in FAMILIES:
        ev, f = verify_family(pins, family, *chains[family], run=run)
        record["families"][family] = ev
        findings += f
    if not findings:
        try:
            record["ek_name"], record["ek_name_source"] = ek_name(chains["rsa"][0], ek_public)
        except Refused as e:
            findings.append(str(e))
    record["status"] = "refused" if findings else "verified"
    if findings:
        record.pop("ek_name", None)
        record.pop("ek_name_source", None)
        record["findings"] = findings
    return record, findings


def _read(path, label):
    with open(path, "rb") as f:
        return der_of(f.read(), label)


def main(argv=None, out=sys.stdout, err=sys.stderr):
    ap = argparse.ArgumentParser(prog="ekchain", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--server", required=True)
    v.add_argument("--rsa", nargs=2, metavar=("EK", "CA"), required=True)
    v.add_argument("--ecc", nargs=2, metavar=("EK", "CA"), required=True)
    v.add_argument("--ek-public")
    v.add_argument("--pins", default=PINS_DIR)
    v.add_argument("--out")
    p = sub.add_parser("pins")
    p.add_argument("--pins", default=PINS_DIR)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "pins":
            pins = load_pins(a.pins)
            for family in FAMILIES:
                pinned_root(pins, family)
                print("%s root %s: pinned" % (family, pins["root"][family][0]), file=out)
            return 0
        chains = {"rsa": (_read(a.rsa[0], "the RSA EK certificate"), _read(a.rsa[1], "the RSA CA")),
                  "ecc": (_read(a.ecc[0], "the ECC EK certificate"), _read(a.ecc[1], "the ECC CA"))}
        ek_public = None
        if a.ek_public:
            with open(a.ek_public, "rb") as f:
                ek_public = f.read()
        record, findings = intake(a.server, chains, ek_public, a.pins)
    except (Refused, OSError, ValueError) as e:
        print("ekchain: refused: %s" % e, file=err)
        return 1
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(text)
    else:
        out.write(text)
    for f in findings:
        print("ekchain: refused: %s" % f, file=err)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
