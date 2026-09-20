#!/usr/bin/env python3
"""Render or apply a fail-closed Proxmox KMS VM definition."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
PCI = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$")
VENDOR_DEVICE = re.compile(r"^[0-9a-f]{4}:[0-9a-f]{4}$")
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
TOP = {
    "schema_version", "site", "node", "vmid", "name", "image", "compute",
    "storage", "network", "controller", "cloud_init", "controls",
}


class InvalidConfig(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidConfig(message)


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    missing, unknown = keys - set(value), set(value) - keys
    require(not missing and not unknown,
            f"{label} fields mismatch: missing={sorted(missing)} unknown={sorted(unknown)}")
    return value


def nonempty(value: object, label: str) -> str:
    require(isinstance(value, str) and value.strip() == value and value, f"invalid {label}")
    return value


def integer(value: object, low: int, high: int, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
            f"invalid {label}")
    return value


def cidrs(values: object, label: str) -> list[ipaddress.IPv4Network]:
    require(isinstance(values, list) and values, f"{label} must be a non-empty list")
    result = []
    for value in values:
        require(isinstance(value, str), f"invalid {label} entry")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise InvalidConfig(f"invalid {label} entry: {value}") from error
        require(isinstance(network, ipaddress.IPv4Network), f"{label} must contain IPv4 networks")
        result.append(network)
    require(len(result) == len(set(result)), f"duplicate {label} entry")
    return result


def endpoints(values: object, label: str) -> list[dict[str, Any]]:
    require(isinstance(values, list) and values, f"{label} must be a non-empty list")
    result = []
    for index, value in enumerate(values):
        item = exact(value, {"cidr", "port"}, f"{label}[{index}]")
        networks = cidrs([item["cidr"]], f"{label}[{index}].cidr")
        result.append({"network": networks[0], "port": integer(item["port"], 1, 65535, f"{label}[{index}].port")})
    return result


def validate_config(document: object) -> dict[str, Any]:
    root = exact(document, TOP, "config")
    require(type(root["schema_version"]) is int and root["schema_version"] == 2, "unsupported config schema")
    nonempty(root["site"], "site")
    nonempty(root["node"], "node")
    integer(root["vmid"], 100, 999_999_999, "vmid")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", nonempty(root["name"], "name")) is not None,
            "invalid VM name")

    image = exact(root["image"], {"host_path", "sha256"}, "image")
    require(Path(nonempty(image["host_path"], "image.host_path")).is_absolute(), "image.host_path must be absolute")
    require(isinstance(image["sha256"], str) and SHA256.fullmatch(image["sha256"]), "invalid image.sha256")

    compute = exact(root["compute"], {"cores", "memory_mib", "cpu"}, "compute")
    integer(compute["cores"], 2, 64, "compute.cores")
    integer(compute["memory_mib"], 2048, 262_144, "compute.memory_mib")
    require(nonempty(compute["cpu"], "compute.cpu") in {"x86-64-v2-AES", "x86-64-v3"}, "unapproved CPU model")

    storage = exact(root["storage"], {"pool", "zfs_dataset", "disk_gib"}, "storage")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", nonempty(storage["pool"], "storage.pool")) is not None,
            "invalid storage.pool")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{1,254}",
                         nonempty(storage["zfs_dataset"], "storage.zfs_dataset")) is not None,
            "invalid storage.zfs_dataset")
    integer(storage["disk_gib"], 16, 1024, "storage.disk_gib")

    network = exact(root["network"], {
        "bridge", "vlan", "mac", "guest_ipv4", "gateway_ipv4", "kms_port", "ssh_port",
        "client_cidrs", "admin_cidrs", "monitoring_cidrs", "audit_sinks", "ntp_sinks",
    }, "network")
    require(re.fullmatch(r"vmbr[0-9]{1,4}", nonempty(network["bridge"], "network.bridge")) is not None,
            "invalid network.bridge")
    integer(network["vlan"], 1, 4094, "network.vlan")
    require(isinstance(network["mac"], str) and MAC.fullmatch(network["mac"].lower()), "invalid network MAC")
    first_mac_octet = int(network["mac"].split(":", 1)[0], 16)
    require(first_mac_octet & 0b11 == 0b10, "network MAC must be locally administered and unicast")
    try:
        guest = ipaddress.ip_interface(network["guest_ipv4"])
        gateway = ipaddress.ip_address(network["gateway_ipv4"])
    except (ValueError, TypeError) as error:
        raise InvalidConfig("invalid guest or gateway IPv4 address") from error
    require(isinstance(guest, ipaddress.IPv4Interface) and isinstance(gateway, ipaddress.IPv4Address),
            "guest and gateway must use IPv4")
    require(gateway in guest.network and gateway != guest.ip, "gateway must be a distinct address in the guest subnet")
    integer(network["kms_port"], 1024, 65535, "network.kms_port")
    integer(network["ssh_port"], 1, 65535, "network.ssh_port")
    require(network["kms_port"] != network["ssh_port"], "KMS and SSH ports must be distinct")

    groups = {
        "client": cidrs(network["client_cidrs"], "network.client_cidrs"),
        "admin": cidrs(network["admin_cidrs"], "network.admin_cidrs"),
        "monitoring": cidrs(network["monitoring_cidrs"], "network.monitoring_cidrs"),
    }
    for left_name, left in groups.items():
        for right_name, right in groups.items():
            if left_name >= right_name:
                continue
            require(not any(a.overlaps(b) for a in left for b in right),
                    f"network role overlap between {left_name} and {right_name}")
    endpoints(network["audit_sinks"], "network.audit_sinks")
    endpoints(network["ntp_sinks"], "network.ntp_sinks")

    controller = exact(root["controller"], {"pci_address", "vendor_device", "physical_port"}, "controller")
    require(isinstance(controller["pci_address"], str) and PCI.fullmatch(controller["pci_address"]),
            "invalid controller.pci_address")
    require(isinstance(controller["vendor_device"], str) and VENDOR_DEVICE.fullmatch(controller["vendor_device"]),
            "invalid controller.vendor_device")
    nonempty(controller["physical_port"], "controller.physical_port")

    cloud = exact(root["cloud_init"], {"user", "ssh_public_key_file"}, "cloud_init")
    require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", nonempty(cloud["user"], "cloud_init.user")) is not None,
            "invalid cloud-init user")
    require(Path(nonempty(cloud["ssh_public_key_file"], "cloud_init.ssh_public_key_file")).is_absolute(),
            "cloud_init.ssh_public_key_file must be absolute")

    controls = exact(root["controls"], {
        "disable_host_ksm", "prohibit_snapshots_backups_ha_replication", "dedicated_admin_ownership_accepted",
        "commissioning_evidence_public_key_sha256",
    }, "controls")
    require(controls["disable_host_ksm"] is True, "host-wide KSM disablement must be accepted")
    require(controls["prohibit_snapshots_backups_ha_replication"] is True,
            "snapshot, backup, HA, and replication prohibition must be accepted")
    require(controls["dedicated_admin_ownership_accepted"] is True,
            "dedicated administrative ownership must be accepted")
    require(isinstance(controls["commissioning_evidence_public_key_sha256"], str)
            and SHA256.fullmatch(controls["commissioning_evidence_public_key_sha256"]),
            "invalid commissioning evidence public-key fingerprint")
    return root


def image_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def firewall_text(config: dict[str, Any]) -> str:
    network = config["network"]
    lines = [
        "[OPTIONS]", "enable: 1", "policy_in: DROP", "policy_out: DROP",
        "log_level_in: warning", "log_level_out: warning", "", "[RULES]",
    ]
    for source in network["client_cidrs"]:
        lines.append(f"IN ACCEPT -source {source} -p tcp -dport {network['kms_port']}")
    for source in network["monitoring_cidrs"]:
        lines.append(f"IN ACCEPT -source {source} -p tcp -dport {network['kms_port']}")
    for source in network["admin_cidrs"]:
        lines.append(f"IN ACCEPT -source {source} -p tcp -dport {network['ssh_port']}")
    for endpoint in network["audit_sinks"]:
        lines.append(f"OUT ACCEPT -dest {endpoint['cidr']} -p tcp -dport {endpoint['port']}")
    for endpoint in network["ntp_sinks"]:
        lines.append(f"OUT ACCEPT -dest {endpoint['cidr']} -p udp -dport {endpoint['port']}")
    return "\n".join(lines) + "\n"


def build_plan(document: object, *, verify_image: bool) -> dict[str, Any]:
    config = validate_config(document)
    image = Path(config["image"]["host_path"])
    if verify_image:
        require(image.is_file() and not image.is_symlink(), "image must be a regular non-symlink file")
        require(image_digest(image) == config["image"]["sha256"], "image SHA-256 mismatch")
    vmid = str(config["vmid"])
    compute, storage, network, controller, cloud = (
        config["compute"], config["storage"], config["network"], config["controller"], config["cloud_init"])
    create = [
        "qm", "create", vmid, "--name", config["name"], "--machine", "q35", "--bios", "ovmf",
        "--ostype", "l26", "--cores", str(compute["cores"]), "--memory", str(compute["memory_mib"]),
        "--balloon", "0", "--cpu", compute["cpu"], "--scsihw", "virtio-scsi-single",
        "--agent", "enabled=1,fstrim_cloned_disks=1,type=virtio", "--onboot", "1",
        "--startup", "order=10,up=60,down=120", "--tablet", "0", "--serial0", "socket",
        "--vga", "serial0", "--protection", "1", "--sockets", "1", "--numa", "0", "--hotplug", "0",
        "--tags", "regalia-kms;no-backup;no-ha",
    ]
    set_args = [
        "qm", "set", vmid,
        "--scsi0", f"{storage['pool']}:0,import-from={image},discard=on,iothread=1,ssd=1",
        "--efidisk0", f"{storage['pool']}:1,efitype=4m,pre-enrolled-keys=1",
        "--ide2", f"{storage['pool']}:cloudinit",
        "--boot", "order=scsi0",
        "--net0", f"virtio={network['mac'].lower()},bridge={network['bridge']},firewall=1,tag={network['vlan']}",
        "--ipconfig0", f"ip={network['guest_ipv4']},gw={network['gateway_ipv4']},ip6=manual",
        "--ciuser", cloud["user"], "--sshkeys", cloud["ssh_public_key_file"],
        "--hostpci0", f"{controller['pci_address']},pcie=1,rombar=0",
    ]
    return {
        "schema": "regalia.proxmox-plan/v1", "proxmox_major": 9,
        "site": config["site"], "node": config["node"],
        "vmid": config["vmid"], "vm_type": "qemu", "image_sha256": config["image"]["sha256"],
        "controller": controller, "storage_dataset": storage["zfs_dataset"],
        "commissioning_evidence_public_key_sha256":
            config["controls"]["commissioning_evidence_public_key_sha256"],
        "qm_create": create, "qm_set": set_args,
        "qm_resize": ["qm", "resize", vmid, "scsi0", f"{storage['disk_gib']}G"],
        "firewall": firewall_text(config),
        "postconditions": [
            "host KSM run=0 and pages_shared=0", "VM absent from HA and replication",
            "VM absent from every backup job", "no snapshots or pending configuration",
            "live migration prohibited by operator role and commissioning policy",
            "guest role and token identity commissioning pass",
        ],
    }


def load_json(path: Path) -> object:
    raw = path.read_bytes()
    require(len(raw) <= 128 * 1024, "config exceeds 128 KiB")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


def host_preflight(config: dict[str, Any]) -> None:
    require(os.geteuid() == 0, "--apply must run as root on the Proxmox node")
    require(socket.gethostname().split(".")[0] == config["node"], "configured node does not match this host")
    version = subprocess.run(["pveversion"], capture_output=True, text=True)
    require(version.returncode == 0 and version.stdout.startswith("pve-manager/9."),
            "this provisioner requires Proxmox VE major version 9")
    firewall = subprocess.run(
        ["pvesh", "get", "/cluster/firewall/options", "--output-format", "json"],
        capture_output=True, text=True,
    )
    require(firewall.returncode == 0, "cannot read Proxmox datacenter firewall state")
    try:
        firewall_enabled = json.loads(firewall.stdout).get("enable")
    except (json.JSONDecodeError, AttributeError) as error:
        raise InvalidConfig("invalid Proxmox datacenter firewall response") from error
    require(firewall_enabled in (1, True, "1"), "Proxmox datacenter firewall is not enabled")
    require(Path("/sys/kernel/mm/ksm/run").is_file(), "host KSM control is unavailable")
    storage = subprocess.run(
        ["pvesh", "get", f"/storage/{config['storage']['pool']}", "--output-format", "json"],
        capture_output=True, text=True,
    )
    try:
        storage_config = json.loads(storage.stdout)
    except json.JSONDecodeError as error:
        raise InvalidConfig("invalid Proxmox storage response") from error
    require(storage.returncode == 0 and isinstance(storage_config, dict)
            and storage_config.get("type") == "zfspool"
            and storage_config.get("pool") == config["storage"]["zfs_dataset"],
            "configured Proxmox storage does not map to the required ZFS dataset")
    zfs = subprocess.run(
        ["zfs", "get", "-H", "-o", "value", "encryptionroot,keystatus", config["storage"]["zfs_dataset"]],
        capture_output=True, text=True,
    )
    values = zfs.stdout.splitlines()
    require(zfs.returncode == 0 and len(values) == 2 and values[0] != "-" and values[1] == "available",
            "configured ZFS dataset is not encrypted and unlocked")
    pci = Path("/sys/bus/pci/devices") / config["controller"]["pci_address"]
    require(pci.is_dir(), "dedicated PCI controller is absent")
    vendor = (pci / "vendor").read_text().strip().removeprefix("0x")
    device = (pci / "device").read_text().strip().removeprefix("0x")
    require(f"{vendor}:{device}" == config["controller"]["vendor_device"], "PCI vendor/device mismatch")
    group = pci / "iommu_group" / "devices"
    require(group.is_dir() and len(list(group.iterdir())) == 1, "PCI controller does not have an isolated IOMMU group")
    require((pci / "driver").resolve().name == "vfio-pci", "PCI controller is not bound to vfio-pci")
    ssh_key = Path(config["cloud_init"]["ssh_public_key_file"])
    require(ssh_key.is_file() and not ssh_key.is_symlink(), "commissioning SSH public key is absent")
    text = ssh_key.read_text().strip()
    require(text.startswith("ssh-ed25519 ") and "PRIVATE" not in text, "only an Ed25519 public key is accepted")


def disable_ksm() -> None:
    unit = """[Unit]
Description=Disable and unmerge KSM for Regalia KMS guests
Before=pve-guests.service

[Service]
Type=oneshot
ExecStart=/bin/sh -ec 'test -w /sys/kernel/mm/ksm/run; echo 2 > /sys/kernel/mm/ksm/run; echo 0 > /sys/kernel/mm/ksm/run; test \"$(cat /sys/kernel/mm/ksm/run)\" = 0; test \"$(cat /sys/kernel/mm/ksm/pages_shared)\" = 0'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path("/etc/systemd/system/regalia-disable-ksm.service")
    unit_path.write_text(unit, encoding="utf-8")
    os.chmod(unit_path, 0o644)
    subprocess.run(["systemctl", "disable", "--now", "ksmtuned.service"], check=False)
    subprocess.run(["systemctl", "mask", "ksmtuned.service"], check=True)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "regalia-disable-ksm.service"], check=True)


def apply(config: dict[str, Any], plan: dict[str, Any]) -> None:
    host_preflight(config)
    existing = subprocess.run(["qm", "status", str(config["vmid"])], capture_output=True)
    require(existing.returncode != 0, "VMID already exists; provisioning never mutates an existing VM")
    disable_ksm()
    subprocess.run(plan["qm_create"], check=True)
    try:
        subprocess.run(plan["qm_set"], check=True)
        subprocess.run(plan["qm_resize"], check=True)
        firewall = Path(f"/etc/pve/firewall/{config['vmid']}.fw")
        require(not firewall.exists(), "VM firewall file already exists")
        firewall.write_text(plan["firewall"], encoding="utf-8")
        subprocess.run(["qm", "start", str(config["vmid"])], check=True)
    except Exception:
        subprocess.run(["qm", "stop", str(config["vmid"])], check=False)
        raise


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-site")
    args = parser.parse_args(argv[1:])
    try:
        document = load_json(args.config)
        config = validate_config(document)
        plan = build_plan(config, verify_image=args.apply)
        if args.apply:
            require(args.output is not None, "--apply requires --output so the reviewed plan exists before mutation")
            require(args.confirm_site == config["site"], "--confirm-site must exactly match the configured site")
        rendered = json.dumps(plan, sort_keys=True, indent=2) + "\n"
        if args.output:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            fd = os.open(args.output, flags, 0o644)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
        if args.apply:
            apply(config, plan)
        if not args.output:
            print(rendered, end="")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, InvalidConfig) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
