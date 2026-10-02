#!/usr/bin/env python3
"""Check the bare-metal KMS host's firewall from one network zone: the same positive/negative TCP matrix
the site config promises (deploy/baremetal/sitecfg.py, rendered by firewall.py).

    python3 -Es deploy/baremetal/network_probe.py site.json --role client --source-ip 198.51.100.20

Run it once from a machine in each zone. Exit 0 when every port is exactly as open or closed as the
config says, 1 when the firewall differs, 2 when the probe itself is refused (bad config or source).

  client, monitoring   kms_port open, ssh_port closed
  admin                ssh_port open, kms_port closed
  unauthorized         both closed
"""
import argparse
import datetime
import errno
import ipaddress
import json
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitecfg  # noqa: E402

ROLES = ("client", "monitoring", "admin", "unauthorized")


def expected_ports(cfg, role):
    kms, ssh = cfg["kms_port"], cfg["ssh_port"]
    return {"client": {kms: True, ssh: False}, "monitoring": {kms: True, ssh: False},
            "admin": {kms: False, ssh: True}, "unauthorized": {kms: False, ssh: False}}[role]


def role_matches_source(cfg, role, source):
    """A probe claiming a role must run from that zone; 'unauthorized' from none of them."""
    zones = {"client": cfg["client_cidrs"], "monitoring": cfg["monitoring_cidrs"], "admin": cfg["admin_cidrs"]}
    inside = {r: any(source in ipaddress.ip_network(n) for n in nets) for r, nets in zones.items()}
    return not any(inside.values()) if role == "unauthorized" else inside[role]


# What a firewall's drop or reject looks like from the probe: a timeout, a reset/refusal, or an ICMP
# host-unreachable (admin-prohibited). Anything else (no route, no such local address, an invalid
# argument) is a failure of the probe host, not evidence about the KMS firewall.
CLOSED_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, errno.EHOSTUNREACH, errno.ETIMEDOUT}


class ProbeFailure(Exception):
    pass


def connect(source, target, port, timeout):
    try:
        with socket.create_connection((target, port), timeout=timeout, source_address=(source, 0)):
            return True, "connected"
    except socket.timeout:
        return False, "timeout (dropped)"
    except OSError as error:
        if error.errno in CLOSED_ERRNOS:
            return False, "%s: %s" % (type(error).__name__, error)
        raise ProbeFailure("%s on port %d: %s (a local routing or socket failure, not a firewall answer)"
                           % (errno.errorcode.get(error.errno, error.errno), port, error))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("config")
    ap.add_argument("--role", required=True, choices=ROLES)
    ap.add_argument("--source-ip", required=True)
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args(argv)
    try:
        cfg = sitecfg.load(args.config)
        source = ipaddress.ip_address(args.source_ip)
        if not isinstance(source, ipaddress.IPv4Address) or source.is_unspecified:
            raise sitecfg.InvalidSite("--source-ip must be a specific IPv4 address owned by this probe host")
        if not role_matches_source(cfg, args.role, source):
            raise sitecfg.InvalidSite("--source-ip %s is not in the %s zone of the site config" % (source, args.role))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((str(source), 0))
        if not 0.1 <= args.timeout <= 30:
            raise sitecfg.InvalidSite("timeout must be between 0.1 and 30 seconds")
    except (OSError, ValueError) as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 2
    results, passed = [], True
    for port, want in expected_ports(cfg, args.role).items():
        try:
            got, detail = connect(str(source), cfg["host_ipv4"], port, args.timeout)
        except ProbeFailure as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 2
        passed = passed and got is want
        results.append({"port": port, "expected": "open" if want else "closed",
                        "observed": "open" if got else "closed", "matched": got is want, "detail": detail})
    print(json.dumps({"schema": "regalia.baremetal-network-probe/v1", "site": cfg["site"], "role": args.role,
                      "source_ip": str(source), "target_ip": cfg["host_ipv4"],
                      "checked_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "passed": passed, "results": results}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
