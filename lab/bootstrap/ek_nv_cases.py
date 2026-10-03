"""Offline EK-certificate feasibility with disposable software TPMs and test CAs.

This is not a production EK enrollment verifier. It does not qualify real
manufacturer roots, certificate profiles, firmware or hardware NV permissions.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from lab import TPM, run, tpm_refused


def authority(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def endorsement_certificate(public, key, issuer):
    now = datetime.now(timezone.utc)
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable EK fixture")]))
            .issuer_name(issuer.subject).public_key(public).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("2.23.133.8.1")]), critical=False)
            .sign(key, hashes.SHA256()))


def fixture_verify(root, der, public, trusted_root):
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return False
    # Only public certificates are written; the fixture CA private key stays in
    # ephemeral process memory and is never included in the report.
    path = root / "received.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    result = run("openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", trusted_root,
                 "-purpose", "any", path, required=False)
    encoding = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return result.returncode == 0 and cert.public_key().public_bytes(*encoding) == public.public_bytes(*encoding)


def exercise():
    report = {"schema": "regalia.ek-nv-fixture/v1", "status": "failed",
              "production_approved": False, "evidence_class": "emulated",
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "checks": []}
    with tempfile.TemporaryDirectory(prefix="regalia-ek-nv-") as temp:
        root = Path(temp)
        node = TPM(root, "certificate")
        try:
            node.start()
            issuer_key, issuer = authority("fixture manufacturer root")
            _, wrong_issuer = authority("untrusted fixture root")
            trusted = root / "trusted-root.pem"
            wrong = root / "wrong-root.pem"
            trusted.write_bytes(issuer.public_bytes(serialization.Encoding.PEM))
            wrong.write_bytes(wrong_issuer.public_bytes(serialization.Encoding.PEM))
            wrong_public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
            # These conventional RSA/ECC indices are used by the authenticated
            # tpm2-tools 5.7 getekcertificate source. No downloader is invoked.
            for algorithm, handle, index in [("rsa", "0x81010001", "0x01c00002"),
                                              ("ecc", "0x81010006", "0x01c0000a")]:
                if algorithm == "ecc":
                    node.call("tpm2_createek", "-G", algorithm, "-c", handle, "-Q")
                absent = node.call("tpm2_nvread", index, "-o", root / "missing.der", required=False)
                cases = [("absent certificate fails with TPM handle refusal", tpm_refused(absent, 0x18B))]
                public_path = root / "ek.pem"
                node.call("tpm2_readpublic", "-c", handle, "-f", "pem", "-o", public_path, "-Q")
                public = serialization.load_pem_public_key(public_path.read_bytes())
                der = endorsement_certificate(public, issuer_key, issuer).public_bytes(serialization.Encoding.DER)
                original = root / "original.der"
                original.write_bytes(der)
                node.call("tpm2_nvdefine", index, "-C", "o", "-s", str(len(der)),
                          "-a", "ownerwrite|authread|no_da", "-Q")
                node.call("tpm2_nvwrite", index, "-C", "o", "-i", original, "-Q")
                received = root / "received.der"
                node.call("tpm2_nvread", index, "-o", received, "-Q")
                actual = received.read_bytes()
                cases.extend([
                    ("NV read preserves exact DER bytes", actual == der),
                    ("trusted fixture chain and EK public key bind", fixture_verify(root, actual, public, trusted)),
                    ("wrong fixture root refuses", not fixture_verify(root, actual, public, wrong)),
                    ("valid chain with substituted EK public key refuses", not fixture_verify(root, actual, wrong_public, trusted)),
                    ("malformed certificate refuses", not fixture_verify(root, b"not a certificate", public, trusted)),
                ])
                damaged = bytearray(actual)
                damaged[-1] ^= 1
                cases.append(("corrupted certificate signature refuses", not fixture_verify(root, bytes(damaged), public, trusted)))
                node.call("tpm2_nvundefine", index, "-C", "o", "-Q")
                report["checks"].extend({"name": algorithm + ": " + name,
                                         "status": "passed" if passed else "failed"} for name, passed in cases)
            report["status"] = "passed" if all(row["status"] == "passed" for row in report["checks"]) else "failed"
        except Exception as error:
            report["failure_class"] = type(error).__name__
            report["tpm_failures"] = node.failures
        finally:
            node.close()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = exercise()
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
