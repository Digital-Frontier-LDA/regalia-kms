#!/usr/bin/env python3
"""Install the Proxmox KMS policy guard and its enforcing systemd timer."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from deploy.proxmox.provision import load_json, validate_config


SERVICE = """[Unit]
Description=Enforce Proxmox isolation policy for KMS VM %i
After=pve-cluster.service
Requires=pve-cluster.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/libexec/regalia-proxmox/policy_guard.py /etc/regalia/proxmox/%i.json --enforce-stop --output /var/lib/regalia-proxmox-policy/%i.json
User=root
Group=root
StateDirectory=regalia-proxmox-policy
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectSystem=strict
ReadOnlyPaths=/etc/pve /etc/regalia/proxmox
UMask=0077
TimeoutStartSec=45s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=regalia-proxmox-policy
"""

TIMER = """[Unit]
Description=Continuously enforce Proxmox isolation policy for KMS VM %i

[Timer]
OnBootSec=30s
OnUnitActiveSec=15s
AccuracySec=1s
RandomizedDelaySec=0
Persistent=true
Unit=regalia-proxmox-policy@%i.service

[Install]
WantedBy=timers.target
"""


class InstallError(RuntimeError):
    pass


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise InstallError(f"refusing symlink target: {path}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def install(config_path: Path, *, root: Path = Path("/")) -> dict[str, object]:
    config = validate_config(load_json(config_path))
    source = Path(__file__).resolve().parent
    libexec = root / "usr/local/libexec/regalia-proxmox"
    configuration = root / f"etc/regalia/proxmox/{config['vmid']}.json"
    systemd = root / "etc/systemd/system"
    canonical = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _write(libexec / "policy_guard.py", (source / "policy_guard.py").read_bytes(), 0o755)
    _write(libexec / "provision.py", (source / "provision.py").read_bytes(), 0o644)
    _write(configuration, canonical, 0o600)
    _write(systemd / "regalia-proxmox-policy@.service", SERVICE.encode("utf-8"), 0o644)
    _write(systemd / "regalia-proxmox-policy@.timer", TIMER.encode("utf-8"), 0o644)
    return {"vmid": config["vmid"], "configuration": str(configuration)}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--confirm-vmid", type=int, required=True)
    try:
        args = parser.parse_args(argv[1:])
        if os.geteuid() != 0:
            raise InstallError("installation must run as root on a Proxmox node")
        config = validate_config(load_json(args.config))
        if args.confirm_vmid != config["vmid"]:
            raise InstallError("--confirm-vmid does not match the configured VMID")
        result = install(args.config)
        instance = str(result["vmid"])
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(
            ["systemctl", "enable", "--now", f"regalia-proxmox-policy@{instance}.timer"], check=True
        )
        subprocess.run(["systemctl", "start", f"regalia-proxmox-policy@{instance}.service"], check=True)
    except (OSError, subprocess.SubprocessError, ValueError, InstallError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
