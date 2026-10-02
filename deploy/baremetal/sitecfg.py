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
      ],
      "boot_mesh": null                              # a single-site host; or, in a three-site cluster (#66):
    }

    "boot_mesh": {
      "node_id": "lisbon",                           # this host's node ID in the membership manifest
      "interface": "wg-unlock",                      # the running host's WireGuard interface for unlock requests
      "listen_port": 51820,                          # its UDP port, reachable from the peers' declared addresses only
      "address": "10.89.0.1",                        # this node's address inside the tunnel
      "unlock_port": 7443,                           # TCP, inside the tunnel only: deploy/baremetal/unlock.py's serve()
      "peers": [                                     # the other nodes: where each is, outside and inside the tunnel
        {"node_id": "porto", "underlay": "198.51.100.7", "address": "10.89.0.2"},
        {"node_id": "faro", "underlay": "198.51.100.9", "address": "10.89.0.3"}
      ]
    }

WHO is a WireGuard peer, and with which key, is never in this file: it comes from the signed membership
manifest (deploy/baremetal/bootnet.py). This file says only where the nodes are.
"""
import ipaddress
import json
import re

SCHEMA = "regalia.baremetal-site/v1"
KEYS = ("schema", "site", "host_ipv4", "kms_port", "ssh_port", "client_cidrs", "monitoring_cidrs", "admin_cidrs",
        "outbound", "boot_mesh")
OUTBOUND_KEYS = ("name", "cidr", "proto", "port")
MESH_KEYS = ("node_id", "interface", "listen_port", "address", "unlock_port", "peers")
MESH_PEER_KEYS = ("node_id", "underlay", "address")
NODE_ID = r"[a-z0-9][a-z0-9-]{0,31}"


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
    cfg["boot_mesh"] = _boot_mesh(doc["boot_mesh"], cfg)
    return cfg


def _address(value, label):
    try:
        address = ipaddress.IPv4Address(value)
    except (TypeError, ValueError):
        raise InvalidSite("%s must be an IPv4 address" % label)
    require(not (address.is_unspecified or address.is_loopback or address.is_multicast), "%s must be a host address" % label)
    return str(address)


def _boot_mesh(mesh, cfg):
    """The addresses of the boot mesh (#66), or None for a single-site host. Every address is one host;
    no two nodes share one, inside or outside the tunnel; the tunnel's addresses are not the host's own."""
    if mesh is None:
        return None
    require(isinstance(mesh, dict) and set(mesh) == set(MESH_KEYS), "boot_mesh must be null or hold exactly %s" % list(MESH_KEYS))
    require(isinstance(mesh["node_id"], str) and re.fullmatch(NODE_ID, mesh["node_id"]), "boot_mesh.node_id is not a node ID")
    require(isinstance(mesh["interface"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,14}", mesh["interface"]),
            "boot_mesh.interface must be an interface name of at most 15 characters")
    listen, unlock = _port(mesh["listen_port"], "boot_mesh.listen_port"), _port(mesh["unlock_port"], "boot_mesh.unlock_port")
    require(unlock not in (cfg["kms_port"], cfg["ssh_port"]), "boot_mesh.unlock_port must differ from kms_port and ssh_port")
    out = {"node_id": mesh["node_id"], "interface": mesh["interface"], "listen_port": listen, "unlock_port": unlock,
           "address": _address(mesh["address"], "boot_mesh.address"), "peers": []}
    require(isinstance(mesh["peers"], list) and 1 <= len(mesh["peers"]) <= 8, "boot_mesh.peers must list 1 to 8 nodes")
    nodes, inside, outside = {out["node_id"]}, {out["address"]}, {cfg["host_ipv4"]}
    require(out["address"] != cfg["host_ipv4"], "boot_mesh.address is the tunnel's address, not host_ipv4")
    for i, peer in enumerate(mesh["peers"]):
        require(isinstance(peer, dict) and set(peer) == set(MESH_PEER_KEYS), "boot_mesh.peers[%d] needs exactly %s" % (i, list(MESH_PEER_KEYS)))
        require(isinstance(peer["node_id"], str) and re.fullmatch(NODE_ID, peer["node_id"]) and peer["node_id"] not in nodes,
                "boot_mesh.peers[%d].node_id must be another node's ID, listed once" % i)
        entry = {"node_id": peer["node_id"], "underlay": _address(peer["underlay"], "boot_mesh.peers[%d].underlay" % i),
                 "address": _address(peer["address"], "boot_mesh.peers[%d].address" % i)}
        require(entry["address"] not in inside and entry["underlay"] not in outside and entry["address"] not in outside
                and entry["underlay"] not in inside, "boot_mesh.peers[%d]: no two nodes share an address, inside or outside the tunnel" % i)
        nodes.add(entry["node_id"]), inside.add(entry["address"]), outside.add(entry["underlay"])
        out["peers"].append(entry)
    return out


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
