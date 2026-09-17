#!/usr/bin/env python3
"""Continuously detect prohibited Proxmox state around a KMS VM."""

from __future__ import annotations

import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable
from urllib.parse import quote
import uuid

try:
    from deploy.proxmox.provision import load_json, validate_config
except ModuleNotFoundError:  # Installed host bundle keeps the two reviewed modules adjacent.
    from provision import load_json, validate_config


MAX_RESPONSE_BYTES = 1024 * 1024


class PolicyCheckError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyCheckError(message)


def _json_without_duplicates(raw: str) -> object:
    require(len(raw.encode("utf-8")) <= MAX_RESPONSE_BYTES, "Proxmox API response exceeds 1 MiB")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate Proxmox API field: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique)
    except json.JSONDecodeError as error:
        raise PolicyCheckError("Proxmox API returned invalid JSON") from error


class PVEClient:
    """Small argv-only pvesh client. It never invokes a shell."""

    def __init__(self, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run):
        self.runner = runner

    def get(self, path: str, **params: object) -> object:
        argv = ["pvesh", "get", path]
        for key, value in sorted(params.items()):
            argv.extend([f"--{key.replace('_', '-')}", str(value)])
        argv.extend(["--output-format", "json"])
        completed = self.runner(argv, capture_output=True, text=True)
        require(completed.returncode == 0, f"Proxmox API GET failed: {path}")
        return _json_without_duplicates(completed.stdout)

    def stop(self, node: str, vmid: int) -> None:
        path = f"/nodes/{node}/qemu/{vmid}/status/stop"
        completed = self.runner(
            ["pvesh", "create", path, "--skiplock", "1"], capture_output=True, text=True
        )
        require(completed.returncode == 0, "failed to request emergency VM stop")

    def disable_autostart(self, node: str, vmid: int) -> None:
        path = f"/nodes/{node}/qemu/{vmid}/config"
        completed = self.runner(
            ["pvesh", "set", path, "--onboot", "0"], capture_output=True, text=True
        )
        require(completed.returncode == 0, "failed to disable VM autostart")


def _list(value: object, label: str) -> list[Any]:
    require(isinstance(value, list), f"invalid {label} response")
    return value


def _dict(value: object, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"invalid {label} response")
    return value


def _item_dict(value: object, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"invalid item in {label} response")
    return value


def _backup_job_includes(pve: Any, job_id: str, vmid: int) -> bool:
    encoded = quote(job_id, safe="")
    root = _dict(pve.get(f"/cluster/backup/{encoded}/included_volumes"), "backup inclusion")
    guests = _list(root.get("children"), "backup inclusion children")
    for raw_guest in guests:
        guest = _item_dict(raw_guest, "backup inclusion children")
        guest_id = guest.get("id")
        require(type(guest_id) is int, "backup inclusion guest has invalid VMID")
        if guest_id == vmid:
            return True
    return False


def inspect(config_document: object, pve: Any) -> dict[str, Any]:
    """Read all relevant live state and return a fail-closed policy result."""
    config = validate_config(config_document)
    vmid = config["vmid"]
    expected_node = config["node"]
    violations: list[str] = []

    resources = _list(pve.get("/cluster/resources", type="vm"), "cluster resources")
    matches = []
    for raw_resource in resources:
        resource = _item_dict(raw_resource, "cluster resources")
        if resource.get("vmid") == vmid:
            matches.append(resource)
    require(len(matches) == 1, "configured VMID must resolve to exactly one QEMU VM")
    resource = matches[0]
    require(resource.get("type") == "qemu", "configured VMID is not a QEMU VM")
    actual_node = resource.get("node")
    require(isinstance(actual_node, str) and actual_node, "VM location is absent")
    status = resource.get("status")
    require(status in {"running", "stopped"}, "VM status is invalid")
    if actual_node != expected_node:
        violations.append(f"unexpected-node:{actual_node}")

    base = f"/nodes/{actual_node}/qemu/{vmid}"
    vm_config = _dict(pve.get(f"{base}/config"), "VM config")
    pending = _list(pve.get(f"{base}/pending"), "VM pending config")
    snapshots = _list(pve.get(f"{base}/snapshot"), "VM snapshots")
    runtime = _dict(pve.get(f"{base}/status/current"), "VM runtime")

    if vm_config.get("vmstate"):
        violations.append("saved-memory-state")
    if "lock" in vm_config:
        lock = vm_config["lock"]
        require(isinstance(lock, str) and lock, "VM operation lock is invalid")
        violations.append(f"operation-lock:{lock}")
    for raw_entry in pending:
        entry = _item_dict(raw_entry, "VM pending config")
        key = entry.get("key")
        require(isinstance(key, str) and key, "pending config key is invalid")
        if "pending" in entry or entry.get("delete", 0) != 0:
            violations.append(f"pending-config:{key}")
    for raw_snapshot in snapshots:
        snapshot = _item_dict(raw_snapshot, "VM snapshots")
        name = snapshot.get("name")
        require(isinstance(name, str) and name, "snapshot name is invalid")
        if name != "current":
            violations.append(f"snapshot:{name}")

    runtime_status = runtime.get("status")
    require(runtime_status in {"running", "stopped"}, "runtime VM status is invalid")
    require(runtime_status == status, "cluster and node VM status disagree")
    qmp_status = runtime.get("qmpstatus")
    if runtime_status == "running" and qmp_status != "running":
        require(isinstance(qmp_status, str) and qmp_status, "running VM lacks QMP state")
        violations.append(f"qmp-state:{qmp_status}")
    elif runtime_status == "stopped" and qmp_status not in (None, "stopped"):
        require(isinstance(qmp_status, str) and qmp_status, "stopped VM has invalid QMP state")
        violations.append(f"qmp-state:{qmp_status}")

    required_tags = {"regalia-kms", "no-backup", "no-ha"}
    tags = vm_config.get("tags")
    actual_tags = set(tags.split(";")) if isinstance(tags, str) else set()
    for missing in sorted(required_tags - actual_tags):
        violations.append(f"missing-warning-tag:{missing}")
    expected = config["controller"]["pci_address"]
    expected_fields = {
        "bios": vm_config.get("bios") == "ovmf",
        "machine": vm_config.get("machine") == "q35",
        "balloon": vm_config.get("balloon") == 0,
        "hotplug": vm_config.get("hotplug") in (0, "0"),
        "numa": vm_config.get("numa") == 0,
        "hostpci0": isinstance(vm_config.get("hostpci0"), str)
        and vm_config["hostpci0"].split(",", 1)[0] == expected,
        "usb-mapping": not any(key.startswith("usb") for key in vm_config),
        "additional-hostpci": not any(
            key.startswith("hostpci") and key != "hostpci0" for key in vm_config
        ),
    }
    for field, matches in expected_fields.items():
        if not matches:
            violations.append(f"config-drift:{field}")

    ha_resources = _list(pve.get("/cluster/ha/resources"), "HA resources")
    for raw_ha in ha_resources:
        ha = _item_dict(raw_ha, "HA resources")
        sid = ha.get("sid")
        require(isinstance(sid, str) and sid, "HA resource SID is invalid")
        if sid in {str(vmid), f"vm:{vmid}"}:
            violations.append(f"ha-resource:{sid}")

    replications = _list(pve.get("/cluster/replication"), "replication jobs")
    for raw_job in replications:
        job = _item_dict(raw_job, "replication jobs")
        job_id = job.get("id")
        guest = job.get("guest")
        require(isinstance(job_id, str) and job_id, "replication job ID is invalid")
        require(type(guest) is int, "replication guest VMID is invalid")
        if guest == vmid:
            violations.append(f"replication-job:{job_id}")

    backup_jobs = _list(pve.get("/cluster/backup"), "backup jobs")
    for raw_job in backup_jobs:
        job = _item_dict(raw_job, "backup jobs")
        job_id = job.get("id")
        require(isinstance(job_id, str) and job_id, "backup job ID is invalid")
        if _backup_job_includes(pve, job_id, vmid):
            violations.append(f"backup-job:{job_id}")

    return {
        "schema": "regalia.proxmox-policy-check/v1",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "site": config["site"],
        "vmid": vmid,
        "expected_node": expected_node,
        "actual_node": actual_node,
        "status": status,
        "compliant": not violations,
        "violations": sorted(set(violations)),
    }


def _quarantine(pve: Any, node: str, vmid: int, status: str) -> tuple[bool, bool, bool]:
    autostart_disabled = False
    stop_requested = False
    incomplete = False
    try:
        pve.disable_autostart(node, vmid)
        autostart_disabled = True
    except Exception:  # A failed first control must never suppress the independent emergency stop.
        incomplete = True
    if status != "stopped":
        try:
            pve.stop(node, vmid)
            stop_requested = True
        except Exception:  # Preserve both outcomes without leaking middleware details to evidence.
            incomplete = True
    return autostart_disabled, stop_requested, incomplete


def run(config_document: object, pve: Any, *, enforce_stop: bool) -> dict[str, Any]:
    try:
        result = inspect(config_document, pve)
    except PolicyCheckError:
        if not enforce_stop:
            raise
        config = validate_config(config_document)
        actual_node = config["node"]
        status = "unknown"
        try:
            resources = pve.get("/cluster/resources", type="vm")
            if isinstance(resources, list):
                matches = [item for item in resources if isinstance(item, dict)
                           and item.get("vmid") == config["vmid"] and item.get("type") == "qemu"]
                if len(matches) == 1:
                    if isinstance(matches[0].get("node"), str) and matches[0]["node"]:
                        actual_node = matches[0]["node"]
                    if matches[0].get("status") in {"running", "stopped"}:
                        status = matches[0]["status"]
        except Exception:  # Best-effort recovery continues against the reviewed node below.
            pass
        autostart_disabled, stop_requested, quarantine_incomplete = _quarantine(
            pve, actual_node, config["vmid"], status
        )
        violations = ["inspection-incomplete"]
        if quarantine_incomplete:
            violations.append("quarantine-incomplete")
        return {
            "schema": "regalia.proxmox-policy-check/v1",
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "site": config["site"], "vmid": config["vmid"], "expected_node": config["node"],
            "actual_node": actual_node, "status": status, "compliant": False,
            "violations": violations, "autostart_disabled": autostart_disabled,
            "stop_requested": stop_requested,
        }
    result["autostart_disabled"] = False
    result["stop_requested"] = False
    if enforce_stop and not result["compliant"]:
        disabled, stopped, incomplete = _quarantine(
            pve, result["actual_node"], result["vmid"], result["status"]
        )
        result["autostart_disabled"] = disabled
        result["stop_requested"] = stopped
        if incomplete:
            result["violations"] = sorted(set(result["violations"] + ["quarantine-incomplete"]))
    return result


def write_result(path: Path, result: dict[str, Any]) -> None:
    if path.is_symlink():
        raise PolicyCheckError(f"refusing symlink result target: {path}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(result, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--enforce-stop", action="store_true")
    parser.add_argument("--output", type=Path)
    try:
        args = parser.parse_args(argv[1:])
        result = run(load_json(args.config), PVEClient(), enforce_stop=args.enforce_stop)
        if args.output is not None:
            write_result(args.output, result)
    except (OSError, subprocess.SubprocessError, ValueError, PolicyCheckError) as error:
        print(json.dumps({"schema": "regalia.proxmox-policy-check/v1", "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["compliant"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
