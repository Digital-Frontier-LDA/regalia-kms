"""The bare-metal KMS host's site configuration: its address, its two listening ports and who may reach
them, and the only destinations it may reach (ADR-0002 D21/D22). Strict: every field required, no other
allowed, every address a valid IPv4 network. firewall.py renders the host's nftables ruleset from it and
network_probe.py checks the result from each zone, so the two can never describe different policies.

    {
      "schema": "regalia.baremetal-site/v1",
      "site": "site-a",
      "host_ipv4": "192.0.2.10",
      "kms_port": 8443, "ssh_port": 22,
      "client_cidrs": ["198.51.100.0/24"],          # may reach kms_port
      "monitoring_cidrs": ["203.0.113.128/32"],     # may reach kms_port (health, metrics)
      "admin_cidrs": ["203.0.113.0/28"],            # may reach ssh_port, and ping
      "outbound": [                                  # the ONLY destinations the host may reach
        {"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514},
        {"name": "ntp", "cidr": "203.0.113.193/32", "proto": "udp", "port": 123}
      ]
    }
"""
import ipaddress
import json
import re

SCHEMA = "regalia.baremetal-site/v1"
KEYS = ("schema", "site", "host_ipv4", "kms_port", "ssh_port", "client_cidrs", "monitoring_cidrs", "admin_cidrs",
        "outbound")
OUTBOUND_KEYS = ("name", "cidr", "proto", "port")


class InvalidSite(ValueError):
    pass


def require(cond, message):
    if not cond:
        raise InvalidSite(message)


def _port(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535,
            "%s must be a port number 1-65535" % label)
    return value


def _networks(value, label):
    require(isinstance(value, list) and value, "%s must be a non-empty list of IPv4 CIDRs" % label)
    out = []
    for c in value:
        try:
            net = ipaddress.ip_network(c, strict=True)
        except (TypeError, ValueError) as error:
            raise InvalidSite("%s: %r is not an IPv4 network (%s)" % (label, c, error))
        require(net.version == 4, "%s: %s is not IPv4" % (label, c))
        require(net.prefixlen > 0, "%s: %s would allow every address" % (label, c))
        out.append(str(net))
    require(len(set(out)) == len(out), "%s lists a network twice" % label)
    return out


def validate(doc):
    require(isinstance(doc, dict), "the site config must be a JSON object")
    missing, unknown = set(KEYS) - set(doc), set(doc) - set(KEYS)
    require(not missing and not unknown, "site fields mismatch: missing=%s unknown=%s" % (sorted(missing), sorted(unknown)))
    require(doc["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(doc["site"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", doc["site"]),
            "site must be a short lowercase name")
    try:
        host = ipaddress.IPv4Address(doc["host_ipv4"])
    except (TypeError, ValueError):
        raise InvalidSite("host_ipv4 must be an IPv4 address")
    require(not (host.is_unspecified or host.is_loopback or host.is_multicast), "host_ipv4 must be a host address")
    kms, ssh = _port(doc["kms_port"], "kms_port"), _port(doc["ssh_port"], "ssh_port")
    require(kms != ssh, "kms_port and ssh_port must differ")
    cfg = {"schema": SCHEMA, "site": doc["site"], "host_ipv4": str(host), "kms_port": kms, "ssh_port": ssh,
           "client_cidrs": _networks(doc["client_cidrs"], "client_cidrs"),
           "monitoring_cidrs": _networks(doc["monitoring_cidrs"], "monitoring_cidrs"),
           "admin_cidrs": _networks(doc["admin_cidrs"], "admin_cidrs"), "outbound": []}
    # The zones carry different permissions (admin: SSH only; client and monitoring: the KMS port only),
    # so an address in both would be allowed both and fail the probe matrix: admin must not overlap them.
    for a in cfg["admin_cidrs"]:
        for c in cfg["client_cidrs"] + cfg["monitoring_cidrs"]:
            require(not ipaddress.ip_network(a).overlaps(ipaddress.ip_network(c)),
                    "admin network %s overlaps the KMS-caller network %s: zones must be disjoint" % (a, c))
    require(isinstance(doc["outbound"], list) and doc["outbound"], "outbound must list the audit and NTP sinks at least")
    names = set()
    for i, o in enumerate(doc["outbound"]):
        require(isinstance(o, dict) and set(o) == set(OUTBOUND_KEYS), "outbound[%d] needs exactly %s" % (i, list(OUTBOUND_KEYS)))
        require(isinstance(o["name"], str) and re.fullmatch(r"[a-z0-9-]{1,32}", o["name"]) and o["name"] not in names,
                "outbound[%d].name must be a unique short name" % i)
        names.add(o["name"])
        require(o["proto"] in ("tcp", "udp"), "outbound[%d].proto must be tcp or udp" % i)
        cfg["outbound"].append({"name": o["name"], "cidr": _networks([o["cidr"]], "outbound[%d].cidr" % i)[0],
                                "proto": o["proto"], "port": _port(o["port"], "outbound[%d].port" % i)})
    require({"audit", "ntp"} <= names, "outbound must include the 'audit' and 'ntp' sinks")
    return cfg


def _unique(pairs):
    """json object_pairs_hook: a repeated key is refused at every level. json.load would keep only the
    last value, so a second admin_cidrs could silently replace the SSH allowlist."""
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate field %r in the site config" % k)
        out[k] = v
    return out


def load(path):
    with open(path, encoding="utf-8") as f:
        try:
            return validate(json.load(f, object_pairs_hook=_unique))
        except json.JSONDecodeError as error:
            raise InvalidSite("not valid JSON: %s" % error)
