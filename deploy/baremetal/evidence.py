"""Signed commissioning evidence for a bare-metal KMS host (ADR-0002 D21; deploy/baremetal/README.md).

host_probe.py MEASURES what the running host can show. The firmware settings it cannot read (iLO,
AC power recovery, chassis intrusion, used-hardware intake) and the records it compares against (the
import key's fingerprint) are ATTESTED here, in a document signed with the commissioning evidence key
(ECDSA P-256, as for the earlier Proxmox evidence). The key is trusted only by its SHA-256 fingerprint,
recorded at commissioning and supplied by the operator, never by whatever key file sits beside the
evidence.

    {
      "schema": "regalia-kms/baremetal-evidence/v1",
      "site": "site-a", "host_serial": "<server serial>", "captured_at": "2026-09-30T10:00:00Z",
      "host": {
        "<every control host_probe measures>": true,
        "pin_import_key_sha256": "<64 hex>",           # written by hand at --init-import-key
        "hsm_usb_path": "<sysfs USB path>",             # the INTERNAL port
        "credential_tpm2_pcrs": "7+11",
        "ilo_isolated_or_disabled": true, "ac_power_recovery": true,
        "chassis_intrusion_armed": true, "used_hardware_intake": true,
        "runtime_credentials_excluded_from_backup": true
      }
    }

Every field is required and no other is allowed; every boolean must be true (evidence records a
commissioned host, not a partial one).
"""
import datetime
import hashlib
import json
import re
import subprocess

SCHEMA = "regalia-kms/baremetal-evidence/v1"
ATTESTED = ("ilo_isolated_or_disabled", "ac_power_recovery", "chassis_intrusion_armed", "used_hardware_intake",
            "runtime_credentials_excluded_from_backup")
RECORDS = ("pin_import_key_sha256", "hsm_usb_path", "credential_tpm2_pcrs")
MAX_BYTES = 128 * 1024


class InvalidEvidence(Exception):
    pass


def require(cond, message):
    if not cond:
        raise InvalidEvidence(message)


def load(raw):
    require(len(raw) <= MAX_BYTES, "evidence exceeds 128 KiB")

    def unique(pairs):
        out = {}
        for k, v in pairs:
            require(k not in out, "duplicate evidence field: %s" % k)
            out[k] = v
        return out
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except ValueError as error:
        raise InvalidEvidence("evidence is not valid JSON") from error


def exact_keys(value, keys, label):
    require(isinstance(value, dict), "%s must be an object" % label)
    missing, unknown = set(keys) - set(value), set(value) - set(keys)
    require(not missing and not unknown, "%s fields mismatch: missing=%s unknown=%s" % (label, sorted(missing), sorted(unknown)))
    return value


def validate(doc, measured_names, now=None):
    """The document's structure and values; returns its host section."""
    root = exact_keys(doc, ("schema", "site", "host_serial", "captured_at", "host"), "evidence")
    require(root["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    for k in ("site", "host_serial"):
        require(isinstance(root[k], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", root[k]), "%s is not a plain name" % k)
    try:
        at = datetime.datetime.strptime(root["captured_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise InvalidEvidence("captured_at must be UTC, YYYY-MM-DDTHH:MM:SSZ")
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(at <= now + datetime.timedelta(minutes=5), "captured_at is in the future")
    host = exact_keys(root["host"], tuple(measured_names) + ATTESTED + RECORDS, "host")
    for k in tuple(measured_names) + ATTESTED:
        require(host[k] is True, "host.%s must be true: the evidence records a commissioned host" % k)
    require(isinstance(host["pin_import_key_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", host["pin_import_key_sha256"]),
            "host.pin_import_key_sha256 must be 64 lowercase hex")
    require(isinstance(host["hsm_usb_path"], str) and re.fullmatch(r"\d+-\d+(\.\d+)*", host["hsm_usb_path"]),
            "host.hsm_usb_path must be a sysfs USB path such as 1-1.4")
    require(isinstance(host["credential_tpm2_pcrs"], str) and re.fullmatch(r"\d{1,2}(\+\d{1,2})*", host["credential_tpm2_pcrs"]),
            "host.credential_tpm2_pcrs must be a PCR list such as 7+11")
    require("10" not in host["credential_tpm2_pcrs"].split("+"),
            "host.credential_tpm2_pcrs must not include PCR 10 (IMA): the credential is decrypted before "
            "regalia-kms runs, so it could never unseal at an unattended start (README, section 3)")
    return host


def verify_signature(evidence_path, signature_path, key_path, key_sha256, run=subprocess.run):
    """The detached signature, by a P-256 key whose DER SHA-256 is the recorded fingerprint."""
    text = run(["openssl", "pkey", "-pubin", "-in", key_path, "-text_pub", "-noout"], capture_output=True, text=True)
    require(text.returncode == 0 and "ASN1 OID: prime256v1" in text.stdout,
            "the commissioning evidence key must be an ECDSA P-256 public key")
    der = run(["openssl", "pkey", "-pubin", "-in", key_path, "-outform", "DER"], capture_output=True)
    require(der.returncode == 0, "cannot encode the commissioning evidence key")
    require(re.fullmatch(r"[0-9a-f]{64}", key_sha256 or "") is not None, "the evidence key fingerprint must be 64 hex")
    require(hashlib.sha256(der.stdout).hexdigest() == key_sha256,
            "the commissioning evidence key does not match the recorded fingerprint")
    checked = run(["openssl", "dgst", "-sha256", "-verify", key_path, "-signature", signature_path, evidence_path],
                  capture_output=True, text=True)
    require(checked.returncode == 0, "the evidence signature does not verify")
