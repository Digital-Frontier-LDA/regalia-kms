#!/usr/bin/env python3
"""The boot mesh: the WireGuard and firewall configuration an unlock request travels over (#66, Phase 6 of
#59; THREE-SITE-THREAT-MODEL.md, attacker case 1).

The unlock exchange (unlock.py) needs no secrecy from its transport. What the network adds is WHO CAN
REACH a peer's unlock port at all: only a node whose WireGuard key the peer's current manifest lists, and
only from an address the site declared.

TWO SIDES, TWO KEYS (THREE-SITE-SECRETS.md):

  the booting node   in its initrd, interface wg-boot, with its WG-BOOT private key (sealed to its TPM).
                     Its WireGuard peers are the nodes that may AUTHORIZE, by their wg_service_pub, each
                     at its declared address. boot_wg_conf(), boot_ruleset().
  the running peer   interface `boot_mesh.interface` (wg-unlock), with its WG-SERVICE private key (on its
                     encrypted root). Its WireGuard peers are the nodes that may REQUEST, by their
                     wg_boot_pub. peer_wg_conf(); its firewall is firewall.py's, with the two boot-mesh
                     openings.

WHERE each node is (addresses, ports) comes from the site config (sitecfg.py, `boot_mesh`). WHO is a peer
and with which key comes from the signed membership manifest, and from nothing else: a node the manifest
no longer lets request disappears from every peer's WireGuard list the moment that peer takes the
manifest, and its packets are then not even answered.

WHAT IT IS NOT. WG-BOOT is a transport identity, never an authorization. Its key is sealed to the TPM
under PCR 7 and the signed PCR 11 policy, which cannot retire a boot image, so a retired but signed image
still brings the tunnel up and reaches a peer's unlock port. It is refused there, at attestation, against
current measurements. A peer must not treat "it came in over the boot mesh" as proof of anything.

THE PRIVATE KEY IS NOT IN THE RENDERED TEXT, AND MUST BE IN WHAT IS APPLIED. `wg setconf` and
`wg syncconf` replace the whole interface configuration: given a file with no PrivateKey they UNSET the
interface's key, and the host then answers no handshake at all (measured, e2e/wg-boot-netns.sh). So
whoever applies a rendered configuration adds the key in memory, with_key(), and pipes the result:
`wg syncconf IF /dev/stdin`. The key is never written beside the configuration.

NOT HERE: the systemd units that run this in an initrd and on a host, sealing the WG-BOOT key, and
writing these files after each accepted manifest. Proven by behaviour in network namespaces
(e2e/wg-boot-netns.sh), not on a host.
"""
import base64

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

BOOT_INTERFACE = "wg-boot"      # the booting node's interface, in the initrd only
TABLE = "regalia_boot"


def _mesh(cfg):
    require(cfg.get("boot_mesh") is not None, "the site config has no boot_mesh: this is a single-site host")
    return cfg["boot_mesh"]


def _key(hex_key):
    return base64.b64encode(bytes.fromhex(hex_key)).decode()


def _others(cfg, manifest, action):
    """The other nodes the manifest lets do `action`, with their manifest entry and their addresses.
    A node the manifest lets act and the site config has no address for is a refusal, not an omission:
    the path would be missing with nothing saying why."""
    mesh, nodes = _mesh(cfg), membership.validate(manifest)
    require(mesh["node_id"] in nodes, "%s is not in the manifest" % mesh["node_id"])
    where = {p["node_id"]: p for p in mesh["peers"]}
    out = []
    for node_id, node in nodes.items():
        if node_id == mesh["node_id"] or not membership.may(manifest, node_id, action):
            continue
        require(node_id in where, "the site config has no boot-mesh address for %s, which the manifest lets %s" % (node_id, action))
        out.append((node, where[node_id]))
    return mesh, sorted(out, key=lambda item: item[0]["node_id"])


def peer_wg_conf(cfg, manifest):
    """The running host's `wg setconf` text: it listens, and knows the nodes that may be unlocked by their
    WG-BOOT keys, each at its tunnel address. A host that may not authorize knows nobody."""
    mesh = _mesh(cfg)
    text = "[Interface]\nListenPort = %d\n" % mesh["listen_port"]
    if not membership.may(manifest, mesh["node_id"], "authorize"):
        require(mesh["node_id"] in membership.validate(manifest), "%s is not in the manifest" % mesh["node_id"])
        return text
    for node, where in _others(cfg, manifest, "request")[1]:
        text += "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n" % (node["node_id"], _key(node["wg_boot_pub"]), where["address"])
    return text


def boot_wg_conf(cfg, manifest):
    """The booting node's `wg setconf` text: the nodes that may authorize, by their WG-SERVICE keys, each
    at its declared address and nowhere else."""
    mesh, peers = _others(cfg, manifest, "authorize")
    require(peers, "the manifest leaves %s no peer that may authorize" % mesh["node_id"])
    text = "[Interface]\n"
    for node, where in peers:
        text += "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\nEndpoint = %s:%d\n" % (
            node["node_id"], _key(node["wg_service_pub"]), where["address"], where["underlay"], mesh["listen_port"])
    return text


def unlock_endpoints(cfg, manifest):
    """{peer: "address:port"} inside the tunnel: what unlock.boot_config takes as `endpoints`."""
    mesh, peers = _others(cfg, manifest, "authorize")
    return {node["node_id"]: "%s:%d" % (where["address"], mesh["unlock_port"]) for node, where in peers}


def with_key(conf, private_key):
    """`conf` (peer_wg_conf or boot_wg_conf) with the interface's private key (base64, as `wg genkey`
    writes it), for `wg setconf` or `wg syncconf` on standard input. Never for a file."""
    key = private_key.strip() if isinstance(private_key, str) else ""
    try:
        valid = len(base64.b64decode(key, validate=True)) == 32
    except ValueError:
        valid = False
    require(valid, "the private key is not a WireGuard key")
    require(conf.startswith("[Interface]\n") and "PrivateKey" not in conf, "this is not a configuration rendered here")
    return "[Interface]\nPrivateKey = %s\n%s" % (key, conf[len("[Interface]\n"):])


def _set(values):
    return "{ %s }" % ", ".join(values)


def boot_ruleset(cfg, manifest):
    """The booting node's nftables ruleset, for its initrd: default deny in both directions. Out: WireGuard
    to the peers' declared addresses, and the unlock port inside the tunnel. In: replies. No SSH, no KMS
    port, no other destination: the node has no root filesystem yet and nothing else to say."""
    mesh, peers = _others(cfg, manifest, "authorize")
    require(peers, "the manifest leaves %s no peer that may authorize" % mesh["node_id"])
    return """# Generated by deploy/baremetal/bootnet.py for %(node)s under manifest epoch %(epoch)d. Do not edit by hand.
table inet %(table)s
delete table inet %(table)s
table inet %(table)s {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
    ip daddr %(underlays)s udp dport %(listen)d accept comment "WireGuard, to the peers' declared addresses"
    oifname "%(interface)s" ip saddr %(address)s ip daddr %(addresses)s tcp dport %(unlock)d accept comment "unlock requests, inside the tunnel"
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
}
""" % {"node": mesh["node_id"], "epoch": manifest["epoch"], "table": TABLE, "interface": BOOT_INTERFACE, "address": mesh["address"],
       "listen": mesh["listen_port"], "unlock": mesh["unlock_port"],
       "underlays": _set([where["underlay"] for _, where in peers]), "addresses": _set([where["address"] for _, where in peers])}
