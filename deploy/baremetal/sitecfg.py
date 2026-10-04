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
        {"name": "dns", "cidr": "203.0.113.194/32", "proto": "udp", "port": 53}
      ],
      "time": {"nts": [                              # authenticated time (#303): NTS servers only, at least two, from
        {"name": "nts.netnod.se", "cidrs": ["194.58.200.0/24"]},   # independent operators (three ride out one);
        {"name": "ptbtime1.ptb.de", "cidrs": ["192.53.103.0/24"]}, # each by the name its certificate carries, and the
        {"name": "time.cloudflare.com", "cidrs": ["162.159.200.0/24"]}   # addresses (/24 or narrower) it may answer from:
      ]},                                            #   NTS-KE (TCP 4460) and NTP (UDP 123) go there and nowhere else
      "boot_mesh": null,                             # a single-site host; or, in a three-site cluster (#66):
      "service_mesh": null                           # and, with a boot_mesh, the tunnel regalia-sync uses (#80)
    }

    "boot_mesh": {
      "node_id": "lisbon",                           # this host's node ID in the membership manifest
      "interface": "wg-unlock",                      # the running host's WireGuard interface for unlock requests
      "listen_port": 51820,                          # its UDP port, reachable from the peers' declared addresses only
      "address": "10.89.0.1",                        # this node's address inside the tunnel
      "unlock_port": 7443,                           # TCP, inside the tunnel only: deploy/baremetal/unlock.py's serve()
      "nic_mac": "52:54:00:12:34:56",                # the initrd's network card, by its MAC address (lower case): its
                                                     #   name can differ between the installed system and the initrd
      "prefix": 24,                                  # host_ipv4's prefix length on that card, in the initrd
      "gateway": "192.0.2.1",                        # the initrd's gateway to the peers' underlays, inside that
                                                     #   prefix; null: every underlay is on the link (wg-boot
                                                     #   then routes by default on the card), which this file
                                                     #   cannot show: network_probe.py checks reachability
      "peers": [                                     # the other nodes: where each is, outside and inside the tunnel
        {"node_id": "porto", "underlay": "198.51.100.7", "address": "10.89.0.2"},
        {"node_id": "faro", "underlay": "198.51.100.9", "address": "10.89.0.3"}
      ]
    }

    "service_mesh": {                                # needs a boot_mesh: the node ID and the peers' underlays are its
      "interface": "wg-svc",                         # the WireGuard interface of the running services (regalia-sync)
      "listen_port": 51821,                          # its UDP port, ONE for the whole mesh: every node listens on this
                                                     #   number, and it is reachable from the peers' addresses only
      "sync_port": 7444,                             # TCP, inside the tunnel only: deploy/baremetal/sync.py
      "authority": null                              # or where the revocation authority is, and its WireGuard key:
    }                                                #   {"key": "<64 hex>", "underlay": "203.0.113.50", "port": 51821}

Inside the service tunnel every address is in SERVICE_PREFIX and is derived from a node's WireGuard key
(deploy/baremetal/wgsvc.py), so this file names none of them.

WHO is a WireGuard peer, and with which key, is never in this file: it comes from the signed membership
manifest (deploy/baremetal/bootnet.py, wgsvc.py). This file says only where the nodes are. The one key
here is the revocation authority's, which is not a node of the manifest.
"""
import ipaddress
import json
import re

SCHEMA = "regalia.baremetal-site/v1"
KEYS = ("schema", "site", "host_ipv4", "kms_port", "ssh_port", "client_cidrs", "monitoring_cidrs", "admin_cidrs",
        "outbound", "time", "boot_mesh", "service_mesh")
TIME_KEYS = ("nts",)
NTS_KEYS = ("name", "cidrs")
NTS_MINIMUM, NTS_MAXIMUM = 2, 8        # authtime.MINIMUM agreeing sources; a bound on what is rendered
NTS_PORTS = (("tcp", 4460), ("udp", 123))   # NTS-KE, then NTP: rendered from `time` only, never an `outbound` entry
NTS_SERVER = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"      # a host name, or an IPv4 address
OUTBOUND_KEYS = ("name", "cidr", "proto", "port")
MESH_KEYS = ("node_id", "interface", "listen_port", "address", "unlock_port", "nic_mac", "prefix", "gateway", "peers")
MAC = r"[0-9a-f]{2}(:[0-9a-f]{2}){5}"
MESH_PEER_KEYS = ("node_id", "underlay", "address")
SERVICE_KEYS = ("interface", "listen_port", "sync_port", "authority")
SERVICE_AUTHORITY_KEYS = ("key", "underlay", "port")
NODE_EXPORTER_PORT = 9100                  # node_exporter, from monitoring_cidrs only, behind mutual TLS (#305)
SERVICE_PREFIX = "fd72:6567:6c61::/48"     # every address inside the service tunnel (wgsvc.PREFIX: a test holds them equal)
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
    require(NODE_EXPORTER_PORT not in (kms, ssh), "kms_port and ssh_port must not be %d, node_exporter's (#305)" % NODE_EXPORTER_PORT)
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
    cfg["outbound"] = _outbound(doc["outbound"])
    cfg["time"] = _time(doc["time"])
    cfg["boot_mesh"] = _boot_mesh(doc["boot_mesh"], cfg)
    cfg["service_mesh"] = _service_mesh(doc["service_mesh"], cfg)
    return cfg


def _outbound(outbound):
    """The only destinations the host may reach: each a unique short name, one network, a protocol and a port; the
    audit sink among them; never the time ports (rendered from `time` alone)."""
    require(isinstance(outbound, list) and outbound, "outbound must list the audit sink at least")
    names, out = set(), []
    for i, o in enumerate(outbound):
        require(isinstance(o, dict) and set(o) == set(OUTBOUND_KEYS), "outbound[%d] needs exactly %s" % (i, list(OUTBOUND_KEYS)))
        require(isinstance(o["name"], str) and re.fullmatch(r"[a-z0-9-]{1,32}", o["name"]) and o["name"] not in names,
                "outbound[%d].name must be a unique short name" % i)
        names.add(o["name"])
        require(o["proto"] in ("tcp", "udp"), "outbound[%d].proto must be tcp or udp" % i)
        require((o["proto"], o["port"]) not in NTS_PORTS, "outbound[%d] opens %s/%s: time traffic is rendered from `time` "
                "(NTS only, to its servers), never opened here: no plain-NTP fallback" % (i, o["proto"], o["port"]))
        out.append({"name": o["name"], "cidr": _networks([o["cidr"]], "outbound[%d].cidr" % i)[0],
                    "proto": o["proto"], "port": _port(o["port"], "outbound[%d].port" % i)})
    require("audit" in names, "outbound must include the 'audit' sink")
    return out


def _time(time_):
    """The NTS servers (#303): NTS_MINIMUM to NTS_MAXIMUM, distinct names, each with one to four IPv4 networks no
    wider than /24, from which it may answer. chrony.conf (authtime.conf), node.json's time_servers (enrol) and
    the firewall's time rules are all rendered from this, so the names chrony uses and the names authtime
    judges cannot differ. That the servers belong to independent operators is the site's claim."""
    require(isinstance(time_, dict) and set(time_) == set(TIME_KEYS), "time must hold exactly %s" % list(TIME_KEYS))
    servers = time_["nts"]
    require(isinstance(servers, list) and NTS_MINIMUM <= len(servers) <= NTS_MAXIMUM,
            "time.nts must list %d to %d NTS servers (three, from three operators, ride out one)" % (NTS_MINIMUM, NTS_MAXIMUM))
    out = []
    for i, server in enumerate(servers):
        label = "time.nts[%d]" % i
        require(isinstance(server, dict) and set(server) == set(NTS_KEYS), "%s needs exactly %s" % (label, list(NTS_KEYS)))
        require(isinstance(server["name"], str) and len(server["name"]) <= 253 and re.fullmatch(NTS_SERVER, server["name"]),
                "%s.name must be a host name (the one its certificate carries)" % label)
        require(isinstance(server["cidrs"], list) and 1 <= len(server["cidrs"]) <= 4, "%s.cidrs must list one to four networks" % label)
        cidrs = _networks(server["cidrs"], label + ".cidrs")
        require(all(ipaddress.ip_network(c).prefixlen >= 24 for c in cidrs), "%s.cidrs: no wider than /24: the host reaches "
                "those servers only" % label)
        out.append({"name": server["name"], "cidrs": cidrs})
    names = [s["name"] for s in out]
    require(len(set(names)) == len(names), "time.nts lists a server twice")
    return {"nts": out}


def _address(value, label):
    require(isinstance(value, str), "%s must be an IPv4 address, as text" % label)     # IPv4Address(True) is 0.0.0.1
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise InvalidSite("%s must be an IPv4 address" % label)
    require(not (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or address.is_reserved),
            "%s must be a host address" % label)
    return str(address)


def _boot_mesh(mesh, cfg):
    """The addresses of the boot mesh (#66), or None for a single-site host. Every address is one host;
    no two nodes share one, inside or outside the tunnel; the tunnel's addresses are not the host's own."""
    if mesh is None:
        return None
    require(isinstance(mesh, dict) and set(mesh) == set(MESH_KEYS), "boot_mesh must be null or hold exactly %s" % list(MESH_KEYS))
    require(isinstance(mesh["node_id"], str) and re.fullmatch(NODE_ID, mesh["node_id"]), "boot_mesh.node_id is not a node ID")
    # Its own WireGuard interface, by name: the firewall trusts what arrives on it to come from a peer's
    # key. Named after a physical interface, the unlock rule would open the port on the wire.
    require(isinstance(mesh["interface"], str) and re.fullmatch(r"wg-[a-z0-9-]{1,12}", mesh["interface"]) and mesh["interface"] != "wg-boot",
            "boot_mesh.interface must be a WireGuard interface of its own, named wg-… (at most 15 characters, and not wg-boot, the initrd's)")
    listen, unlock = _port(mesh["listen_port"], "boot_mesh.listen_port"), _port(mesh["unlock_port"], "boot_mesh.unlock_port")
    require(unlock not in (cfg["kms_port"], cfg["ssh_port"], NODE_EXPORTER_PORT),
            "boot_mesh.unlock_port must differ from kms_port, ssh_port and node_exporter's %d" % NODE_EXPORTER_PORT)
    out = {"node_id": mesh["node_id"], "interface": mesh["interface"], "listen_port": listen, "unlock_port": unlock,
           "address": _address(mesh["address"], "boot_mesh.address"), "peers": []}
    # Where the initrd's own traffic goes (#66, regalia.boot-env): its card by MAC address (an interface name
    # can differ between the installed system and the initrd, and a wrong one strands the host), the prefix
    # host_ipv4 has on it, and the gateway to the peers, if any. A unicast card address, never all zeros.
    require(isinstance(mesh["nic_mac"], str) and re.fullmatch(MAC, mesh["nic_mac"]) and mesh["nic_mac"] != "00:00:00:00:00:00"
            and not int(mesh["nic_mac"][:2], 16) & 1, "boot_mesh.nic_mac must be a unicast MAC address, lower case and colon-separated")
    require(isinstance(mesh["prefix"], int) and not isinstance(mesh["prefix"], bool) and 1 <= mesh["prefix"] <= 32,
            "boot_mesh.prefix must be a prefix length from 1 to 32")
    out.update(nic_mac=mesh["nic_mac"], prefix=mesh["prefix"], gateway=None)
    if mesh["gateway"] is not None:
        gateway = _address(mesh["gateway"], "boot_mesh.gateway")
        link = ipaddress.IPv4Network("%s/%d" % (cfg["host_ipv4"], mesh["prefix"]), strict=False)
        require(ipaddress.IPv4Address(gateway) in link and gateway != cfg["host_ipv4"],
                "boot_mesh.gateway must be another address inside %s (host_ipv4 and its prefix), or null" % link)
        require(link.prefixlen >= 31 or gateway not in (str(link.network_address), str(link.broadcast_address)),
                "boot_mesh.gateway must be a host of %s, not its network or broadcast address" % link)
        out["gateway"] = gateway
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
                and entry["underlay"] not in inside and entry["address"] != entry["underlay"],
                "boot_mesh.peers[%d]: no two nodes share an address, inside or outside the tunnel, and no address is both" % i)
        nodes.add(entry["node_id"]), inside.add(entry["address"]), outside.add(entry["underlay"])
        out["peers"].append(entry)
    # A tunnel address inside a zone would carry that zone's permission into the tunnel: the KMS port or
    # SSH, for whoever holds a boot key. The zones and the tunnel are disjoint. (The firewall also drops
    # everything else that arrives on the mesh interface; this refuses the configuration that needs it.)
    zones = [(k, n) for k in ("client_cidrs", "monitoring_cidrs", "admin_cidrs") for n in cfg[k]] + [("outbound", o["cidr"]) for o in cfg["outbound"]]
    for address in sorted(inside):
        for zone, network in zones:
            require(ipaddress.ip_address(address) not in ipaddress.ip_network(network),
                    "the tunnel address %s is inside %s (%s): the tunnel and the zones must be disjoint" % (address, zone, network))
    return out


def _service_mesh(mesh, cfg):
    """The service tunnel (#80), or None. It names an interface and two ports of its own, and where the
    revocation authority is. The nodes are the boot mesh's: this host's ID and the peers' underlays."""
    if mesh is None:
        return None
    boot = cfg["boot_mesh"]
    require(boot is not None, "service_mesh needs a boot_mesh: the node ID and the peers' addresses are its")
    require(isinstance(mesh, dict) and set(mesh) == set(SERVICE_KEYS), "service_mesh must be null or hold exactly %s" % list(SERVICE_KEYS))
    # An interface of its own, as the boot mesh's: the firewall trusts what arrives on it to have come through
    # WireGuard. The same name as the boot mesh's would put the two planes' rules on one interface.
    require(isinstance(mesh["interface"], str) and re.fullmatch(r"wg-[a-z0-9-]{1,12}", mesh["interface"])
            and mesh["interface"] not in ("wg-boot", boot["interface"]),
            "service_mesh.interface must be a WireGuard interface of its own, named wg-… (at most 15 characters; not wg-boot, "
            "and not the boot mesh's)")
    listen, sync = _port(mesh["listen_port"], "service_mesh.listen_port"), _port(mesh["sync_port"], "service_mesh.sync_port")
    require(listen != boot["listen_port"], "service_mesh.listen_port must differ from boot_mesh.listen_port: two interfaces, two ports")
    require(sync not in (cfg["kms_port"], cfg["ssh_port"], boot["unlock_port"], NODE_EXPORTER_PORT),
            "service_mesh.sync_port must differ from kms_port, ssh_port, boot_mesh.unlock_port and node_exporter's %d: one number, "
            "one service" % NODE_EXPORTER_PORT)
    out = {"interface": mesh["interface"], "listen_port": listen, "sync_port": sync, "authority": None}
    authority = mesh["authority"]
    if authority is not None:
        require(isinstance(authority, dict) and set(authority) == set(SERVICE_AUTHORITY_KEYS),
                "service_mesh.authority must be null or hold exactly %s" % list(SERVICE_AUTHORITY_KEYS))
        require(isinstance(authority["key"], str) and re.fullmatch(r"[0-9a-f]{64}", authority["key"]),
                "service_mesh.authority.key must be a WireGuard public key, 64 lowercase hex characters")
        underlay = _address(authority["underlay"], "service_mesh.authority.underlay")
        taken = {cfg["host_ipv4"], boot["address"]} | {p["underlay"] for p in boot["peers"]} | {p["address"] for p in boot["peers"]}
        require(underlay not in taken, "service_mesh.authority.underlay is a node's address: the authority is another host")
        # The zone rules match on addresses alone. An authority inside a zone would also be handed that
        # zone's port on the wire (the KMS port, or SSH), which nothing about "authority" says.
        for zone, network in [(k, n) for k in ("client_cidrs", "monitoring_cidrs", "admin_cidrs") for n in cfg[k]] + [("outbound", o["cidr"]) for o in cfg["outbound"]]:
            require(ipaddress.ip_address(underlay) not in ipaddress.ip_network(network),
                    "service_mesh.authority.underlay %s is inside %s (%s): the authority is not a client, a monitor, an admin or a sink" % (underlay, zone, network))
        out["authority"] = {"key": authority["key"], "underlay": underlay, "port": _port(authority["port"], "service_mesh.authority.port")}
    return out


def _unique(pairs):
    """json object_pairs_hook: a repeated key is refused at every level. json.load would keep only the
    last value, so a second admin_cidrs could silently replace the SSH allowlist."""
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate field %r in the site config" % k)
        out[k] = v
    return out


# ---- the revocation authority's host (#324) ----
# The authority host serves no KMS port and is in no boot mesh: its own address, who may reach SSH and node_exporter,
# where it may send (the audit sink), and its NTS servers. Its tunnel (where the nodes are, its WireGuard and sync
# ports) is authority.json's, and WHICH nodes are peers is the signed manifest's (firewall.render_authority).
AUTHORITY_SCHEMA = "regalia.authority-site/v1"
AUTHORITY_KEYS = ("schema", "site", "host_ipv4", "ssh_port", "monitoring_cidrs", "admin_cidrs", "outbound", "time")


def validate_authority(doc):
    """The authority host's site file, with the node's own checks for every field they share."""
    require(isinstance(doc, dict), "the authority site config must be a JSON object")
    missing, unknown = set(AUTHORITY_KEYS) - set(doc), set(doc) - set(AUTHORITY_KEYS)
    require(not missing and not unknown, "authority site fields mismatch: missing=%s unknown=%s" % (sorted(missing), sorted(unknown)))
    require(doc["schema"] == AUTHORITY_SCHEMA, "schema must be %s" % AUTHORITY_SCHEMA)
    require(isinstance(doc["site"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", doc["site"]), "site must be a short lowercase name")
    try:
        host = ipaddress.IPv4Address(doc["host_ipv4"])
    except (TypeError, ValueError):
        raise InvalidSite("host_ipv4 must be an IPv4 address")
    require(not (host.is_unspecified or host.is_loopback or host.is_multicast), "host_ipv4 must be a host address")
    ssh = _port(doc["ssh_port"], "ssh_port")
    require(ssh != NODE_EXPORTER_PORT, "ssh_port must not be %d, node_exporter's (#305)" % NODE_EXPORTER_PORT)
    cfg = {"schema": AUTHORITY_SCHEMA, "site": doc["site"], "host_ipv4": str(host), "ssh_port": ssh,
           "monitoring_cidrs": _networks(doc["monitoring_cidrs"], "monitoring_cidrs"), "admin_cidrs": _networks(doc["admin_cidrs"], "admin_cidrs")}
    for a in cfg["admin_cidrs"]:                  # the zones carry different permissions, as on a node
        for c in cfg["monitoring_cidrs"]:
            require(not ipaddress.ip_network(a).overlaps(ipaddress.ip_network(c)),
                    "admin network %s overlaps the monitoring network %s: zones must be disjoint" % (a, c))
    cfg["outbound"] = _outbound(doc["outbound"])
    cfg["time"] = _time(doc["time"])
    return cfg


def load_authority(path):
    with open(path, encoding="utf-8") as f:
        try:
            return validate_authority(json.load(f, object_pairs_hook=_unique))
        except json.JSONDecodeError as error:
            raise InvalidSite("not valid JSON: %s" % error)


def load(path):
    with open(path, encoding="utf-8") as f:
        try:
            return validate(json.load(f, object_pairs_hook=_unique))
        except json.JSONDecodeError as error:
            raise InvalidSite("not valid JSON: %s" % error)
