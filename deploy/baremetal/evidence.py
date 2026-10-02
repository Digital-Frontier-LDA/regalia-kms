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
        "credential_tpm2_pcrs": "7",                    # bound directly; never 10 or 11
        "credential_tpm2_signed_pcrs": "11",            # bound through a signed PCR policy (#57): "11",
        "credential_tpm2_pcr_key_pkfp": "<64 hex>",     #   with the PCR-signing key's pkfp; or both ""
        "ilo_isolated_or_disabled": true, "ac_power_recovery": true, "redundant_power_supplies": true,
        "chassis_intrusion_armed": true, "used_hardware_intake": true,
        "runtime_credentials_excluded_from_backup": true,
        "system_rom_version": "P89 v3.40 (2024-03-22)",  # intake records (README, section 1)
        "ilo_firmware_version": "2.82",
        "tpm_ek_certificate_present": true
      }
    }

Every field is required and no other is allowed; every control boolean must be true (evidence records
a commissioned host, not a partial one). The evidence is at most 24 hours old: the firmware settings
are not re-measured, so an old document must not vouch for today's host.

The evidence, its signature and the key are each read ONCE into a private snapshot, and both the
validation and every OpenSSL call use that snapshot: a path that changes between reads cannot get one
document validated and another verified.
"""
import datetime
import hashlib
import json
import os
import re
import subprocess
import tempfile

SCHEMA = "regalia-kms/baremetal-evidence/v1"
ATTESTED = ("ilo_isolated_or_disabled", "ac_power_recovery", "redundant_power_supplies", "chassis_intrusion_armed",
            "used_hardware_intake", "runtime_credentials_excluded_from_backup")
RECORDS = ("pin_import_key_sha256", "hsm_usb_path", "credential_tpm2_pcrs", "credential_tpm2_signed_pcrs",
           "credential_tpm2_pcr_key_pkfp", "system_rom_version", "ilo_firmware_version", "tpm_ek_certificate_present")
MAX_AGE = datetime.timedelta(hours=24)
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


def credential_binding(pcrs, signed_pcrs, pkfp, label="host."):
    """The PIN credentials' recorded TPM binding: the PCRs bound directly, the PCRs bound through a
    signed policy, and that policy's signing key. Returns (direct PCR numbers, signed PCR numbers, pkfp).
    Shared with host_probe.py, which holds its --credential-* arguments to the same rules."""
    require(isinstance(pcrs, str) and re.fullmatch(r"\d{1,2}(\+\d{1,2})*", pcrs),
            "%scredential_tpm2_pcrs must be a PCR list such as 7" % label)
    direct = [int(x) for x in pcrs.split("+")]
    require(all(0 <= x <= 23 for x in direct) and len(set(direct)) == len(direct),
            "%scredential_tpm2_pcrs must be distinct PCRs 0-23" % label)
    require(7 in direct, "%scredential_tpm2_pcrs must include PCR 7 (Secure Boot state; README, section 3)" % label)
    require(10 not in direct, "%scredential_tpm2_pcrs must not include PCR 10 (IMA): the credential is decrypted "
            "before regalia-kms runs, so it could never unseal at an unattended start (README, section 3)" % label)
    require(11 not in direct, "%scredential_tpm2_pcrs must not include PCR 11 directly: the kernel image changes "
            "at every update; only a signed PCR policy binds it, recorded in credential_tpm2_signed_pcrs "
            "(README, section 3)" % label)
    # The signed policy: PCR 11 (the only PCR systemd-measure signs) by one RSA key, named by the
    # fingerprint its signature files carry (SHA-256 of the PKCS#1 DER key). Both, or neither.
    require(signed_pcrs in ("", "11"), '%scredential_tpm2_signed_pcrs must be "11" or "" (no signed policy)' % label)
    require(isinstance(pkfp, str) and re.fullmatch(r"([0-9a-f]{64})?", pkfp),
            '%scredential_tpm2_pcr_key_pkfp must be 64 lowercase hex, or "" with no signed policy' % label)
    require(bool(signed_pcrs) == bool(pkfp), "%scredential_tpm2_signed_pcrs and credential_tpm2_pcr_key_pkfp "
            "go together: a signed PCR needs its signing key's pkfp, and a key needs a PCR" % label)
    return sorted(direct), [int(signed_pcrs)] if signed_pcrs else [], pkfp


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
    require(now - at <= MAX_AGE, "the evidence is older than 24 hours: capture and sign it again")
    host = exact_keys(root["host"], tuple(measured_names) + ATTESTED + RECORDS, "host")
    for k in tuple(measured_names) + ATTESTED:
        require(host[k] is True, "host.%s must be true: the evidence records a commissioned host" % k)
    require(isinstance(host["pin_import_key_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", host["pin_import_key_sha256"]),
            "host.pin_import_key_sha256 must be 64 lowercase hex")
    require(isinstance(host["hsm_usb_path"], str) and re.fullmatch(r"\d+-\d+(\.\d+)*", host["hsm_usb_path"]),
            "host.hsm_usb_path must be a sysfs USB path such as 1-1.4")
    credential_binding(host["credential_tpm2_pcrs"], host["credential_tpm2_signed_pcrs"], host["credential_tpm2_pcr_key_pkfp"])
    for k in ("system_rom_version", "ilo_firmware_version"):
        require(isinstance(host[k], str) and re.fullmatch(r"[A-Za-z0-9 ._()/-]{1,64}", host[k]), "host.%s must be a version string" % k)
    require(isinstance(host["tpm_ek_certificate_present"], bool), "host.tpm_ek_certificate_present must be true or false")
    return host


class Snapshot:
    """Read each input once into a private (0700) directory; everything after uses only the copies."""

    def __init__(self, **paths):
        self.dir = tempfile.mkdtemp(prefix="bm-evidence-")
        self.paths, self.data = {}, {}
        for name, src in paths.items():
            with open(src, "rb") as f:
                data = f.read(MAX_BYTES + 1)
            require(len(data) <= MAX_BYTES, "%s exceeds 128 KiB" % name)
            dst = os.path.join(self.dir, name)
            with open(os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(data)
            self.paths[name], self.data[name] = dst, data

    def close(self):
        for p in self.paths.values():
            os.unlink(p)
        os.rmdir(self.dir)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def verify_signature(evidence_path, signature_path, key_path, key_sha256, run=subprocess.run):
    """The detached signature, by a P-256 key whose DER SHA-256 is the recorded fingerprint. Call it with
    snapshot paths (Snapshot): each file is then the same bytes for every check."""
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
