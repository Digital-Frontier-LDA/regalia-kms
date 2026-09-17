#!/usr/bin/env python3
"""Fail-closed validation of captured Proxmox KMS commissioning evidence."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from deploy.proxmox.provision import load_json, validate_config

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TOP = {"schema_version", "captured_at", "site", "node", "vmid", "host", "vm", "cluster", "guest", "token"}


class InvalidEvidence(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidEvidence(message)


def exact_keys(value: object, keys: set[str], label: str) -> dict:
    require(isinstance(value, dict), f"{label} must be an object")
    unknown = set(value) - keys
    missing = keys - set(value)
    require(not unknown and not missing, f"{label} fields mismatch: missing={sorted(missing)} unknown={sorted(unknown)}")
    return value


def load_evidence(raw: bytes) -> object:
    require(len(raw) <= 128 * 1024, "evidence exceeds 128 KiB")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate evidence field: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError as error:
        raise InvalidEvidence("evidence is not valid JSON") from error


def validate(document: object, *, now: datetime.datetime | None = None) -> None:
    root = exact_keys(document, TOP, "evidence")
    require(type(root["schema_version"]) is int and root["schema_version"] == 4, "unsupported evidence schema")
    require(isinstance(root["vmid"], int) and 100 <= root["vmid"] <= 999_999_999, "invalid VMID")
    for name in ("captured_at", "site", "node"):
        require(isinstance(root[name], str) and root[name].strip(), f"invalid {name}")
    try:
        captured = datetime.datetime.fromisoformat(root["captured_at"].replace("Z", "+00:00"))
    except (ValueError, TypeError) as error:
        raise InvalidEvidence("captured_at must be an RFC 3339 timestamp") from error
    require(captured.tzinfo is not None and captured.utcoffset() == datetime.timedelta(0),
            "captured_at must use UTC")
    if now is not None:
        age = now - captured
        require(datetime.timedelta(0) <= age <= datetime.timedelta(hours=24),
                "evidence must not be future-dated or older than 24 hours")

    host = exact_keys(root["host"], {
        "pve_version", "iommu_enabled", "ksm_run", "ksm_pages_shared", "datacenter_firewall_enabled",
        "storage_encryption_active",
    }, "host")
    require(isinstance(host["pve_version"], str) and host["pve_version"].startswith("pve-manager/9."),
            "Proxmox VE 9 version evidence required")
    require(host["iommu_enabled"] is True, "IOMMU must be enabled")
    require(type(host["ksm_run"]) is int and host["ksm_run"] == 0, "KSM run must be zero")
    require(type(host["ksm_pages_shared"]) is int and host["ksm_pages_shared"] == 0,
            "KSM pages_shared must be zero after unmerge")
    require(host["datacenter_firewall_enabled"] is True, "Proxmox datacenter firewall must be enabled")
    require(host["storage_encryption_active"] is True, "encrypted-at-rest storage evidence required")

    vm = exact_keys(root["vm"], {"type", "machine", "bios", "balloon", "usb_mappings", "hostpci", "snapshots", "pending_changes", "saved_state"}, "vm")
    require(vm["type"] == "qemu", "full QEMU VM required; LXC is prohibited")
    require(vm["machine"] == "q35" and vm["bios"] == "ovmf", "q35 plus OVMF required")
    require(vm["balloon"] == 0, "memory ballooning must be disabled")
    require(vm["usb_mappings"] == [], "USB device mappings are prohibited; pass a controller with hostpci")
    require(vm["snapshots"] == [], "VM snapshots are prohibited")
    require(vm["pending_changes"] == {}, "pending VM configuration must be resolved")
    require(vm["saved_state"] is False, "suspend or managed-save state is prohibited")
    require(isinstance(vm["hostpci"], list) and len(vm["hostpci"]) == 1, "exactly one dedicated USB controller is required")
    controller = exact_keys(vm["hostpci"][0], {"pci_address", "physical_port", "iommu_group_members", "vfio_bound"}, "hostpci controller")
    require(re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", controller["pci_address"]) is not None, "invalid PCI address")
    require(isinstance(controller["physical_port"], str) and controller["physical_port"].strip(), "physical port label required")
    require(controller["iommu_group_members"] == 1 and controller["vfio_bound"] is True, "controller must be isolated and vfio-bound")

    cluster = exact_keys(root["cluster"], {
        "ha_managed", "replication_jobs", "backup_jobs_including_vmid", "live_migration_allowed",
        "policy_guard_timer_enabled", "policy_guard_enforce_stop", "policy_guard_interval_seconds",
        "policy_guard_last_result_sha256",
    }, "cluster")
    require(cluster["ha_managed"] is False, "Proxmox HA is prohibited")
    require(cluster["replication_jobs"] == [], "Proxmox replication is prohibited")
    require(cluster["backup_jobs_including_vmid"] == [], "VM backup jobs are prohibited")
    require(cluster["live_migration_allowed"] is False, "live migration is prohibited")
    require(cluster["policy_guard_timer_enabled"] is True, "Proxmox policy guard timer must be enabled")
    require(cluster["policy_guard_enforce_stop"] is True, "Proxmox policy guard must enforce quarantine")
    require(type(cluster["policy_guard_interval_seconds"]) is int
            and 1 <= cluster["policy_guard_interval_seconds"] <= 15,
            "Proxmox policy guard interval must be at most 15 seconds")
    require(isinstance(cluster["policy_guard_last_result_sha256"], str)
            and SHA256.fullmatch(cluster["policy_guard_last_result_sha256"]),
            "policy guard result digest required")

    guest = exact_keys(root["guest"], {"core_dumps_disabled", "hibernation_disabled", "swap_disabled_or_encrypted", "runtime_credentials_excluded_from_backup", "direct_token_clients_absent", "kms_service_unprivileged", "credential_tpm2_pcrs"}, "guest")
    for name, value in guest.items():
        if name == "credential_tpm2_pcrs":
            continue
        require(value is True, f"guest control not proven: {name}")
    # THE PCR POLICY THE PIN CREDENTIALS ARE SEALED TO, AS RECORDED AT COMMISSIONING.
    #
    # PIN-CUSTODY.md required binding the sealed PIN credentials to measured-boot PCRs and
    # recording the policy, and nothing recorded it or checked it. Its own example command passed
    # no --tpm2-pcrs at all. This makes the RECORD mandatory and well-formed: an explicit,
    # non-empty set of TPM2 PCR indices, signed with the rest of the evidence.
    #
    # WHAT THIS CANNOT SEE: whether the credential blob installed on the guest is actually sealed to
    # this set. That is a property of a file inside the guest, and this verifier reads a signed
    # description of the guest. It proves the policy was chosen and recorded, not that it was applied.
    pcrs = guest["credential_tpm2_pcrs"]
    require(isinstance(pcrs, list) and pcrs, "credential PCR policy must be a non-empty list: an empty set seals to no boot state")
    require(all(type(index) is int and 0 <= index <= 23 for index in pcrs),
            "credential PCR policy must list TPM2 PCR indices 0-23")
    require(len(set(pcrs)) == len(pcrs), "credential PCR policy lists a PCR twice")

    token = exact_keys(root["token"], {"logical_device_id", "manufacturer_serial", "public_fingerprint", "cryptographic_identity_verified_in_guest", "immutable_policy_verified_in_guest"}, "token")
    require(isinstance(token["logical_device_id"], str) and token["logical_device_id"].strip(), "logical device ID required")
    require(isinstance(token["manufacturer_serial"], str) and token["manufacturer_serial"].strip(), "manufacturer serial required")
    require(isinstance(token["public_fingerprint"], str) and SHA256.fullmatch(token["public_fingerprint"]), "public fingerprint required")
    require(token["cryptographic_identity_verified_in_guest"] is True, "guest cryptographic identity verification required")
    require(token["immutable_policy_verified_in_guest"] is True, "guest immutable policy verification required")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--site-config", type=Path)
    parser.add_argument("--allow-unsigned-example", action="store_true")
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit as error:
        return int(error.code)
    try:
        raw = args.evidence.read_bytes()
        document = load_evidence(raw)
        official_example = Path(__file__).with_name("evidence.example.json").resolve()
        if args.allow_unsigned_example:
            require(args.evidence.resolve() == official_example,
                    "--allow-unsigned-example is valid only for the repository synthetic example")
            require(args.signature is None and args.public_key is None,
                    "do not combine unsigned-example mode with signature arguments")
            require(args.site_config is None, "do not combine unsigned-example mode with a site config")
            now = None
        else:
            require(args.signature is not None and args.public_key is not None and args.site_config is not None,
                    "detached evidence signature, public key, and reviewed site config are required")
            site = validate_config(load_json(args.site_config))
            require(isinstance(document, dict)
                    and document.get("site") == site["site"]
                    and document.get("node") == site["node"]
                    and document.get("vmid") == site["vmid"],
                    "evidence site, node, or VMID does not match the reviewed site config")
            description = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(args.public_key), "-text_pub", "-noout"],
                capture_output=True, text=True,
            )
            require(description.returncode == 0
                    and "ASN1 OID: prime256v1" in description.stdout
                    and "Public-Key: (256 bit)" in description.stdout,
                    "commissioning evidence key must be an ECDSA P-256 public key")
            encoded = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(args.public_key), "-outform", "DER"],
                capture_output=True,
            )
            require(encoded.returncode == 0, "cannot encode commissioning evidence public key")
            fingerprint = hashlib.sha256(encoded.stdout).hexdigest()
            require(fingerprint == site["controls"]["commissioning_evidence_public_key_sha256"],
                    "commissioning evidence key does not match the reviewed fingerprint")
            checked = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(args.public_key),
                 "-signature", str(args.signature), str(args.evidence)],
                capture_output=True, text=True,
            )
            require(checked.returncode == 0, "detached evidence signature verification failed")
            now = datetime.datetime.now(datetime.timezone.utc)
        validate(document, now=now)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, InvalidEvidence) as error:
        print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(f"VALID: {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
