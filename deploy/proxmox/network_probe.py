#!/usr/bin/env python3
"""Run the same positive/negative TCP matrix from each commissioned network zone."""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import socket
import sys

try:
    from deploy.proxmox.provision import InvalidConfig, load_json, validate_config
except ModuleNotFoundError:  # Direct execution from the repository path.
    from provision import InvalidConfig, load_json, validate_config


def expected_ports(config: dict, role: str) -> dict[int, bool]:
    network = config["network"]
    kms, ssh = network["kms_port"], network["ssh_port"]
    return {
        "client": {kms: True, ssh: False},
        "monitoring": {kms: True, ssh: False},
        "admin": {kms: False, ssh: True},
        "unauthorized": {kms: False, ssh: False},
    }[role]


def connect(source: str, target: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((target, port), timeout=timeout, source_address=(source, 0)):
            return True, "connected"
    except (TimeoutError, ConnectionRefusedError, OSError) as error:
        return False, f"{type(error).__name__}: {error}"


def require_local_address(source: str) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((source, 0))
    except OSError as error:
        raise InvalidConfig(f"--source-ip is not owned by this probe host: {source}") from error


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--role", required=True, choices=("client", "monitoring", "admin", "unauthorized"))
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args(argv[1:])
    try:
        config = validate_config(load_json(args.config))
        source = ipaddress.ip_address(args.source_ip)
        require_ipv4 = isinstance(source, ipaddress.IPv4Address) and not source.is_unspecified
        if not require_ipv4:
            raise InvalidConfig("--source-ip must be a specific IPv4 address owned by this probe host")
        require_local_address(str(source))
        if not 0.1 <= args.timeout <= 30:
            raise InvalidConfig("timeout must be between 0.1 and 30 seconds")
        target = str(ipaddress.ip_interface(config["network"]["guest_ipv4"]).ip)
        results = []
        passed = True
        for port, expected_open in expected_ports(config, args.role).items():
            observed_open, detail = connect(str(source), target, port, args.timeout)
            matched = observed_open is expected_open
            passed = passed and matched
            results.append({
                "port": port, "expected": "open" if expected_open else "closed",
                "observed": "open" if observed_open else "closed", "matched": matched, "detail": detail,
            })
        report = {
            "schema": "regalia.proxmox-network-probe/v1", "site": config["site"], "role": args.role,
            "source_ip": str(source), "target_ip": target,
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "passed": passed, "results": results,
        }
        print(json.dumps(report, sort_keys=True))
        return 0 if passed else 1
    # ValueError, not the three subclasses it used to name. `ipaddress.ip_address("10.0.0.300")`
    # and `ip_interface` on a malformed guest address raise plain ValueError, which fell through as
    # a traceback and exit 1 — and exit 1 is this tool's documented "the firewall does not match"
    # result. An operator typo in --source-ip therefore read as a firewall finding, which is the
    # one confusion a probe like this must not create. InvalidConfig and json.JSONDecodeError are
    # both ValueError subclasses, so the refusals that already worked keep working.
    except (OSError, ValueError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
