#!/usr/bin/env python3
"""Render the bare-metal KMS host's nftables ruleset from its site config (deploy/baremetal/sitecfg.py).

    tmp="$(mktemp /etc/nftables.d/.regalia-kms.XXXXXX)"      # not *.nft: never included half-written
    python3 deploy/baremetal/firewall.py site.json > "$tmp" && nft -c -f "$tmp" && nft -f "$tmp" \
      && mv -f "$tmp" /etc/nftables.d/regalia-kms.nft || rm -f "$tmp"      (README.md: the full sequence)

One table, `inet regalia_kms`, default-deny in BOTH directions:
  input   loopback; established/related; kms_port from client and monitoring CIDRs; ssh_port and ping
          from admin CIDRs; the ICMP errors path MTU discovery needs; nothing else (IPv6 dropped)
  output  loopback; established/related; each `outbound` destination on its one port and protocol;
          nothing else: a compromised process cannot open a connection anywhere else
  forward dropped (the host routes nothing)

With a `boot_mesh` (three-site, #66), two more openings, and nothing else:
  input   WireGuard (UDP listen_port) from the peers' declared addresses only: a node that holds a valid
          key and sits anywhere else gets no handshake (THREE-SITE-THREAT-MODEL.md, attacker case 1);
          and unlock_port, only inside the tunnel, only from the peers' tunnel addresses, only to this
          host's. EVERYTHING ELSE that arrives on the mesh interface is dropped before the zone rules are
          reached: no SSH and no KMS port inside the tunnel, whatever addresses the packet carries.
The WireGuard peers themselves (which keys) come from the manifest: deploy/baremetal/bootnet.py.

With a `service_mesh` (#80), the only IPv6 this host carries, and only on that interface:
  input   WireGuard (UDP listen_port) from the peers' declared addresses and the authority's; and
          sync_port inside the tunnel, only between addresses of the tunnel's own prefix
          (sitecfg.SERVICE_PREFIX: every address there is derived from a WireGuard key, wgsvc.py), with
          the answers to this host's own requests. EVERYTHING ELSE on the service interface is dropped,
          IPv4 and IPv6, before any other rule: no KMS port and no SSH inside this tunnel either.
  output  WireGuard to the peers and the authority; this host's requests to sync_port inside the tunnel,
          and its answers; nothing else leaves on the service interface.
IPv6 on every other interface stays dropped, in both directions.

host_probe.py measures the loaded table (firewall_default_deny); network_probe.py checks the result
from each zone. The rendered text is deterministic, so a reviewed copy can be compared byte for byte.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sitecfg  # noqa: E402

TABLE = "regalia_kms"


def _set(nets):
    return "{ %s }" % ", ".join(nets)


def render(cfg):
    kms, ssh = cfg["kms_port"], cfg["ssh_port"]
    callers = cfg["client_cidrs"] + [n for n in cfg["monitoring_cidrs"] if n not in cfg["client_cidrs"]]
    mesh, mesh_rules = cfg["boot_mesh"], ""
    if mesh:
        # After "ct state established,related accept": what reaches this rule begins a connection, and a
        # connection begins with a SYN and nothing else (see the service mesh below for why).
        mesh_rules = (
            "    iifname \"%s\" ip daddr %s tcp dport %d ip saddr %s tcp flags & (fin | syn | rst | ack) == syn ct state new accept comment \"boot mesh: a new unlock request, inside the tunnel\"\n"
            "    iifname \"%s\" drop comment \"boot mesh: nothing else inside the tunnel\"\n"
            "    ip daddr %s udp dport %d ip saddr %s accept comment \"boot mesh: WireGuard, from the peers' declared addresses\"\n"
            % (mesh["interface"], mesh["address"], mesh["unlock_port"], _set([p["address"] + "/32" for p in mesh["peers"]]), mesh["interface"],
               cfg["host_ipv4"], mesh["listen_port"], _set([p["underlay"] + "/32" for p in mesh["peers"]])))
    service, service_in, service_out, service_udp_in, service_udp_out = cfg["service_mesh"], "", "", "", ""
    if service:
        # Before the IPv6 drop: the service tunnel is the one place IPv6 is carried. Each group ends in a
        # drop for the whole interface, so no later rule (a zone, a sink) can match inside the tunnel.
        # A connection starts with a SYN and nothing else: conntrack would otherwise take a stray
        # mid-stream segment for a new connection and let it reach the stack.
        name, prefix, port = service["interface"], sitecfg.SERVICE_PREFIX, service["sync_port"]
        service_in = (
            "    iifname \"%s\" ip6 saddr %s ip6 daddr %s tcp dport %d tcp flags & (fin | syn | rst | ack) == syn ct state new accept comment \"service mesh: a new sync request, inside the tunnel\"\n"
            "    iifname \"%s\" ip6 saddr %s ip6 daddr %s tcp dport %d ct state established accept comment \"service mesh: the rest of a sync request\"\n"
            "    iifname \"%s\" ip6 saddr %s ip6 daddr %s tcp sport %d ct state established accept comment \"service mesh: answers to this host's requests\"\n"
            "    iifname \"%s\" drop comment \"service mesh: nothing else inside the tunnel\"\n"
            % (name, prefix, prefix, port, name, prefix, prefix, port, name, prefix, prefix, port, name))
        service_out = (
            "    oifname \"%s\" ip6 saddr %s ip6 daddr %s tcp dport %d tcp flags & (fin | syn | rst | ack) == syn ct state new accept comment \"service mesh: a new sync request of this host's\"\n"
            "    oifname \"%s\" ip6 saddr %s ip6 daddr %s tcp dport %d ct state established accept comment \"service mesh: the rest of it\"\n"
            "    oifname \"%s\" ip6 saddr %s ip6 daddr %s tcp sport %d ct state established accept comment \"service mesh: this host's answers\"\n"
            "    oifname \"%s\" drop comment \"service mesh: nothing else leaves by the tunnel\"\n"
            % (name, prefix, prefix, port, name, prefix, prefix, port, name, prefix, prefix, port, name))
        underlays = _set([p["underlay"] + "/32" for p in mesh["peers"]])
        service_udp_in = ("    ip daddr %s udp dport %d ip saddr %s accept comment \"service mesh: WireGuard, from the peers' declared addresses\"\n"
                          % (cfg["host_ipv4"], service["listen_port"], underlays))
        service_udp_out = ("    ip daddr %s udp dport %d accept comment \"service mesh: WireGuard, to the peers\"\n"
                           % (underlays, service["listen_port"]))
        if service["authority"]:
            a = service["authority"]
            service_udp_in += ("    ip daddr %s udp dport %d ip saddr %s accept comment \"service mesh: WireGuard, from the authority\"\n"
                               % (cfg["host_ipv4"], service["listen_port"], a["underlay"]))
            service_udp_out += ("    ip daddr %s udp dport %d accept comment \"service mesh: WireGuard, to the authority\"\n"
                                % (a["underlay"], a["port"]))
    out_rules = "\n".join(
        "    ip daddr %s %s dport %d accept comment \"%s\"" % (o["cidr"], o["proto"], o["port"], o["name"])
        for o in cfg["outbound"])
    return """# Generated by deploy/baremetal/firewall.py from the %(site)s site config. Do not edit by hand.
table inet %(table)s
delete table inet %(table)s
table inet %(table)s {
  chain input {
    type filter hook input priority filter; policy drop;
    iif "lo" accept
%(service_in)s    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
%(mesh_rules)s%(service_udp_in)s    ip daddr %(host)s tcp dport %(kms)d ip saddr %(callers)s accept comment "kms: clients and monitoring"
    ip daddr %(host)s tcp dport %(ssh)d ip saddr %(admins)s accept comment "ssh: admin only"
    ip saddr %(admins)s icmp type echo-request accept comment "ping: admin only"
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
%(service_out)s    meta nfproto ipv6 drop
    ct state invalid drop
    ct state established,related accept
%(service_udp_out)s%(out_rules)s
    icmp type { destination-unreachable, time-exceeded } accept comment "path MTU discovery"
  }
}
""" % {"site": cfg["site"], "table": TABLE, "host": cfg["host_ipv4"], "kms": kms, "ssh": ssh,
       "callers": _set(callers), "admins": _set(cfg["admin_cidrs"]), "out_rules": out_rules, "mesh_rules": mesh_rules,
       "service_in": service_in, "service_out": service_out, "service_udp_in": service_udp_in, "service_udp_out": service_udp_out}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("config", help="the site config JSON")
    args = ap.parse_args(argv)
    try:
        cfg = sitecfg.load(args.config)
    except (OSError, sitecfg.InvalidSite) as error:
        print("REFUSED: %s" % error, file=sys.stderr)
        return 2
    sys.stdout.write(render(cfg))
    return 0


if __name__ == "__main__":
    sys.exit(main())
