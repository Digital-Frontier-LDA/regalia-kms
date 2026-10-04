"""deploy/baremetal/sitecfg.py and firewall.py: a strict site config, and a deterministic default-deny
nftables ruleset rendered from it. Behaviour is proven separately in network namespaces
(e2e/baremetal-firewall-netns.sh); these pin the config contract and the rendered text."""
import copy
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from deploy.baremetal import firewall, sitecfg

EXAMPLE = Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "site.example.json"


class SiteConfig(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(EXAMPLE.read_text())

    def test_the_example_is_valid(self):
        self.assertEqual(sitecfg.validate(self.doc)["site"], "site-a")

    def test_refusals(self):
        cases = {
            "unknown field": (lambda d: d.__setitem__("extra", 1), "fields mismatch"),
            "missing field": (lambda d: d.pop("admin_cidrs"), "fields mismatch"),
            "wide-open network": (lambda d: d.__setitem__("client_cidrs", ["0.0.0.0/0"]), "every address"),
            "host bits set": (lambda d: d.__setitem__("admin_cidrs", ["203.0.113.4/28"]), "not an IPv4 network"),
            "IPv6": (lambda d: d.__setitem__("client_cidrs", ["2001:db8::/64"]), "not IPv4"),
            "same ports": (lambda d: d.__setitem__("ssh_port", 8443), "must differ"),
            "bool port": (lambda d: d.__setitem__("kms_port", True), "port number"),
            "no audit sink": (lambda d: d.__setitem__("outbound", d["outbound"][1:]), "'audit' sink"),
            # #303: time is NTS only, rendered from `time`; never a side door in `outbound`
            "plain NTP outbound": (lambda d: d["outbound"].append({"name": "ntp", "cidr": "203.0.113.193/32", "proto": "udp", "port": 123}),
                                   "no plain-NTP fallback"),
            "NTS-KE outbound": (lambda d: d["outbound"].append({"name": "ke", "cidr": "203.0.113.193/32", "proto": "tcp", "port": 4460}),
                                "rendered from `time`"),
            "no time": (lambda d: d.pop("time"), "fields mismatch"),
            "one NTS server": (lambda d: d["time"].__setitem__("nts", d["time"]["nts"][:1]), "2 to 8 NTS servers"),
            "nine NTS servers": (lambda d: d["time"].__setitem__("nts", [{"name": "nts%d.example.net" % i, "cidrs": ["192.0.2.%d/32" % i]}
                                                                          for i in range(9)]), "2 to 8 NTS servers"),
            "a server twice": (lambda d: d["time"]["nts"][1].__setitem__("name", d["time"]["nts"][0]["name"]), "twice"),
            "a server name with a newline": (lambda d: d["time"]["nts"][0].__setitem__("name", "a.se\nserver evil.example"), "host name"),
            "an upper-case name": (lambda d: d["time"]["nts"][0].__setitem__("name", "Time.Cloudflare.com"), "host name"),
            "a /16 for a server": (lambda d: d["time"]["nts"][0].__setitem__("cidrs", ["194.58.0.0/16"]), "no wider than /24"),
            "no address for a server": (lambda d: d["time"]["nts"][0].__setitem__("cidrs", []), "one to four"),
            "an extra key in time": (lambda d: d["time"].__setitem__("pool", []), "exactly"),
            "an extra key in a server": (lambda d: d["time"]["nts"][0].__setitem__("key", "x"), "exactly"),
            "bad proto": (lambda d: d["outbound"][0].__setitem__("proto", "icmp"), "tcp or udp"),
            "kms on node_exporter's port": (lambda d: d.__setitem__("kms_port", 9100), "node_exporter's"),
            "loopback host": (lambda d: d.__setitem__("host_ipv4", "127.0.0.1"), "host address"),
            "duplicate net": (lambda d: d.__setitem__("client_cidrs", ["198.51.100.0/24", "198.51.100.0/24"]), "twice"),
            "admin overlaps clients": (lambda d: d.__setitem__("admin_cidrs", ["198.51.100.16/28"]), "must be disjoint"),
            "admin overlaps monitoring": (lambda d: d.__setitem__("admin_cidrs", ["203.0.113.128/25"]), "must be disjoint"),
        }
        for label, (breakit, why) in cases.items():
            with self.subTest(label):
                d = copy.deepcopy(self.doc)
                breakit(d)
                with self.assertRaises(sitecfg.InvalidSite) as ctx:
                    sitecfg.validate(d)
                self.assertIn(why, str(ctx.exception))


class DuplicateKeys(unittest.TestCase):
    def test_a_repeated_key_is_refused_at_every_level(self):
        import tempfile
        text = EXAMPLE.read_text()
        cases = (text.replace('"admin_cidrs":', '"admin_cidrs": ["0.0.0.1/32"], "admin_cidrs":', 1),
                 text.replace('"proto": "tcp",', '"proto": "tcp", "proto": "udp",', 1))
        for bad in cases:
            with self.subTest(), tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                f.write(bad)
            with self.assertRaises(sitecfg.InvalidSite) as ctx:
                sitecfg.load(f.name)
            self.assertIn("duplicate field", str(ctx.exception))
            Path(f.name).unlink()


class ProbeErrors(unittest.TestCase):
    """A probe-host failure must never read as 'the port is closed'."""

    def test_no_route_is_a_refusal_not_a_closed_port(self):
        import errno
        from unittest import mock
        from deploy.baremetal import network_probe
        err = OSError(errno.ENETUNREACH, "Network is unreachable")
        with mock.patch.object(network_probe.socket, "create_connection", side_effect=err):
            with self.assertRaises(network_probe.ProbeFailure):
                network_probe.connect("203.0.113.66", "192.0.2.10", 8443, 1)
        for e in (OSError(errno.ECONNREFUSED, "refused"), OSError(errno.EHOSTUNREACH, "unreachable"),
                  network_probe.socket.timeout()):
            with self.subTest(e=e), mock.patch.object(network_probe.socket, "create_connection", side_effect=e):
                self.assertEqual(network_probe.connect("203.0.113.66", "192.0.2.10", 8443, 1)[0], False)

    def test_main_exits_2_when_the_probe_host_has_no_route(self):
        import errno
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock
        from deploy.baremetal import network_probe
        err = OSError(errno.ENETUNREACH, "Network is unreachable")
        with mock.patch.object(network_probe.socket, "create_connection", side_effect=err), \
                mock.patch.object(network_probe.socket.socket, "bind", return_value=None), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as e:
            rc = network_probe.main([str(EXAMPLE), "--role", "unauthorized", "--source-ip", "203.0.113.66"])
        self.assertEqual(rc, 2, out.getvalue() + e.getvalue())
        self.assertIn("not a firewall answer", e.getvalue())


class Render(unittest.TestCase):
    def setUp(self):
        self.cfg = sitecfg.validate(json.loads(EXAMPLE.read_text()))
        self.text = firewall.render(self.cfg)

    def test_deterministic(self):
        self.assertEqual(self.text, firewall.render(sitecfg.validate(json.loads(EXAMPLE.read_text()))))

    def test_every_chain_defaults_to_drop(self):
        for hook in ("input", "forward", "output"):
            self.assertIn("type filter hook %s priority filter; policy drop;" % hook, self.text)

    def test_each_port_only_from_its_zones(self):
        self.assertIn("tcp dport 8443 ip saddr { 198.51.100.0/24, 203.0.113.128/32 } accept", self.text)
        self.assertIn("tcp dport 22 ip saddr { 203.0.113.0/28 } accept", self.text)

    def test_outbound_only_to_declared_sinks(self):
        self.assertIn('ip daddr 203.0.113.192/32 tcp dport 6514 accept comment "audit"', self.text)
        self.assertIn('ip daddr 203.0.113.194/32 udp dport 53 accept comment "dns"', self.text)
        # #303: each NTS server on NTS-KE and NTP, to its own networks and nowhere else
        for name, net in (("nts.netnod.se", "194.58.200.0/24"), ("ptbtime1.ptb.de", "192.53.103.0/24"), ("time.cloudflare.com", "162.159.200.0/24")):
            self.assertIn('ip daddr { %s } tcp dport 4460 accept comment "time: %s, NTS-KE"' % (net, name), self.text)
            self.assertIn('ip daddr { %s } udp dport 123 accept comment "time: %s, NTP"' % (net, name), self.text)
        self.assertEqual(self.text.count(" dport "), 11)   # kms, node metrics, ssh, audit, dns, and 2 per NTS server: nothing else opens
        # #305: node_exporter from the monitoring zone only, to this host's address only
        self.assertIn('ip daddr 192.0.2.10 tcp dport 9100 ip saddr { 203.0.113.128/32 } accept comment "node metrics: monitoring only (#305)"', self.text)
        self.assertEqual(self.text.count("dport 9100"), 1)
        self.assertEqual(self.text.count("dport 123 "), 3)  # NTP only to the three NTS servers
        self.assertNotIn("ip6", self.text)                 # a single-site host carries no IPv6 at all
        self.assertEqual(self.text.count("meta nfproto ipv6 drop"), 2)

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nft_accepts_the_syntax(self):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=self.text, capture_output=True, text=True)
        if "Operation not permitted" in r.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN here")
        self.assertEqual(r.returncode, 0, r.stderr)


def meshed(authority=None, **service):
    """The example site as node a of a three-site cluster, with the boot mesh and the service mesh."""
    doc = json.loads(EXAMPLE.read_text())
    doc["host_ipv4"] = "192.0.2.10"
    doc["boot_mesh"] = {"node_id": "a", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
                        "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None,
                        "peers": [{"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"},
                                  {"node_id": "c", "underlay": "192.0.2.30", "address": "10.89.0.3"}]}
    doc["service_mesh"] = dict({"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": authority}, **service)
    return doc


AUTHORITY = {"key": "5e" * 32, "underlay": "192.0.2.50", "port": 51821}


class ServiceMesh(unittest.TestCase):
    """The tunnel regalia-sync uses (#80): the one place this host carries IPv6, and only the sync port."""

    def test_the_service_mesh_is_null_or_exact(self):
        self.assertIsNone(sitecfg.validate(json.loads(EXAMPLE.read_text()))["service_mesh"])
        self.assertEqual(sitecfg.validate(meshed())["service_mesh"], {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444, "authority": None})
        self.assertEqual(sitecfg.validate(meshed(AUTHORITY))["service_mesh"]["authority"], AUTHORITY)
        cases = {
            "absent": (lambda d: d.pop("service_mesh"), "fields mismatch"),
            "without a boot mesh": (lambda d: d.__setitem__("boot_mesh", None), "service_mesh needs a boot_mesh"),
            "not an object": (lambda d: d.__setitem__("service_mesh", []), "service_mesh must be null or hold exactly"),
            "unknown field": (lambda d: d["service_mesh"].__setitem__("psk", "x"), "service_mesh must be null or hold exactly"),
            "missing field": (lambda d: d["service_mesh"].pop("authority"), "service_mesh must be null or hold exactly"),
            "a physical interface": (lambda d: d["service_mesh"].__setitem__("interface", "eth0"), "a WireGuard interface of its own"),
            "the loopback": (lambda d: d["service_mesh"].__setitem__("interface", "lo"), "a WireGuard interface of its own"),
            "the initrd's interface": (lambda d: d["service_mesh"].__setitem__("interface", "wg-boot"), "a WireGuard interface of its own"),
            "the boot mesh's interface": (lambda d: d["service_mesh"].__setitem__("interface", "wg-unlock"), "a WireGuard interface of its own"),
            "an interface with a quote": (lambda d: d["service_mesh"].__setitem__("interface", 'wg-" accept'), "a WireGuard interface of its own"),
            "an interface too long": (lambda d: d["service_mesh"].__setitem__("interface", "wg-service-tunnel"), "a WireGuard interface of its own"),
            "an interface that is no text": (lambda d: d["service_mesh"].__setitem__("interface", 7), "a WireGuard interface of its own"),
            "the boot mesh's UDP port": (lambda d: d["service_mesh"].__setitem__("listen_port", 51820), "must differ from boot_mesh.listen_port"),
            "port 0": (lambda d: d["service_mesh"].__setitem__("listen_port", 0), "service_mesh.listen_port must be a port number"),
            "a port as true": (lambda d: d["service_mesh"].__setitem__("sync_port", True), "service_mesh.sync_port must be a port number"),
            "sync on the KMS port": (lambda d: d["service_mesh"].__setitem__("sync_port", 8443), "one number, one service"),
            "sync on the SSH port": (lambda d: d["service_mesh"].__setitem__("sync_port", 22), "one number, one service"),
            "sync on the unlock port": (lambda d: d["service_mesh"].__setitem__("sync_port", 7443), "one number, one service"),
            "an authority that is a list": (lambda d: d["service_mesh"].__setitem__("authority", []), "authority must be null or hold exactly"),
            "an authority with more": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, psk="x")), "authority must be null or hold exactly"),
            "an authority key in capitals": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, key="5E" * 32)), "a WireGuard public key"),
            "an authority key too short": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, key="5e" * 31)), "a WireGuard public key"),
            "an authority key in base64": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, key="A" * 43 + "=")), "a WireGuard public key"),
            "an authority key that is no text": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, key=None)), "a WireGuard public key"),
            "an authority at a host name": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="authority.example")), "authority.underlay must be an IPv4 address"),
            "an authority at this host": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="192.0.2.10")), "is a node's address"),
            "an authority at a peer": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="192.0.2.20")), "is a node's address"),
            "an authority at a tunnel address": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="10.89.0.2")), "is a node's address"),
            "an authority among the clients": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="198.51.100.9")), "is inside client_cidrs"),
            "an authority among the admins": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="203.0.113.4")), "is inside admin_cidrs"),
            "an authority that is the monitor": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="203.0.113.128")), "is inside monitoring_cidrs"),
            "an authority that is the audit sink": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, underlay="203.0.113.192")), "is inside outbound"),
            "an authority port 0": (lambda d: d["service_mesh"].__setitem__("authority", dict(AUTHORITY, port=0)), "authority.port must be a port number"),
        }
        for label, (breakit, why) in cases.items():
            with self.subTest(label):
                d = meshed(dict(AUTHORITY))
                breakit(d)
                with self.assertRaises(sitecfg.InvalidSite) as ctx:
                    sitecfg.validate(d)
                self.assertIn(why, str(ctx.exception))

    def rules(self, authority=None):
        text = firewall.render(sitecfg.validate(meshed(authority)))
        chains = {name: body for name, body in re.findall(r"chain (\w+) \{\n(.*?)\n  \}", text, re.S)}
        return text, [line.strip() for line in chains["input"].splitlines()], [line.strip() for line in chains["output"].splitlines()]

    def test_ipv6_is_carried_only_on_the_service_interface_only_within_its_prefix_only_for_the_sync_port(self):
        text, incoming, outgoing = self.rules()
        prefix = "fd72:6567:6c61::/48"
        syn = "tcp flags & (fin | syn | rst | ack) == syn ct state new accept"
        between = "ip6 saddr %s ip6 daddr %s" % (prefix, prefix)
        wanted_in = ['iifname "wg-svc" %s tcp dport 7444 %s comment "service mesh: a new sync request, inside the tunnel"' % (between, syn),
                     'iifname "wg-svc" %s tcp dport 7444 ct state established accept comment "service mesh: the rest of a sync request"' % between,
                     'iifname "wg-svc" %s tcp sport 7444 ct state established accept comment "service mesh: answers to this host\'s requests"' % between,
                     'iifname "wg-svc" drop comment "service mesh: nothing else inside the tunnel"']
        wanted_out = ['oifname "wg-svc" %s tcp dport 7444 %s comment "service mesh: a new sync request of this host\'s"' % (between, syn),
                      'oifname "wg-svc" %s tcp dport 7444 ct state established accept comment "service mesh: the rest of it"' % between,
                      'oifname "wg-svc" %s tcp sport 7444 ct state established accept comment "service mesh: this host\'s answers"' % between,
                      'oifname "wg-svc" drop comment "service mesh: nothing else leaves by the tunnel"']
        # straight after loopback, in this order, and BEFORE the drop of all other IPv6
        self.assertEqual(incoming[1:6], ["iif \"lo\" accept"] + wanted_in)
        self.assertEqual(incoming[6], "meta nfproto ipv6 drop")
        self.assertEqual(outgoing[1:6], ["oif \"lo\" accept"] + wanted_out)
        self.assertEqual(outgoing[6], "meta nfproto ipv6 drop")
        # a connection is new only with a SYN and nothing else: exactly one rule per direction takes "new" here,
        # the boot mesh's unlock rule is the third, and every rule that takes "new" asks for the lone SYN
        self.assertEqual(text.count("ct state new"), 3)
        self.assertEqual([line for line in text.splitlines() if "ct state new" in line and syn not in line], [])
        # nothing else in the ruleset speaks IPv6, and nothing else names the interface
        self.assertEqual(text.count("ip6 "), 12)
        self.assertEqual(text.count('"wg-svc"'), 8)
        self.assertEqual(text.count("meta nfproto ipv6 drop"), 2)
        # every chain still defaults to drop, and the zone rules are as they were
        for hook in ("input", "forward", "output"):
            self.assertIn("type filter hook %s priority filter; policy drop;" % hook, text)
        self.assertIn("tcp dport 8443 ip saddr { 198.51.100.0/24, 203.0.113.128/32 } accept", text)

    def test_wireguard_itself_only_with_the_peers_declared_addresses_and_the_authority_s(self):
        text, incoming, outgoing = self.rules()
        self.assertIn('ip daddr 192.0.2.10 udp dport 51821 ip saddr { 192.0.2.20/32, 192.0.2.30/32 } accept comment "service mesh: WireGuard, from the peers\' declared addresses"', incoming)
        self.assertIn('ip daddr { 192.0.2.20/32, 192.0.2.30/32 } udp dport 51821 accept comment "service mesh: WireGuard, to the peers"', outgoing)
        self.assertNotIn("192.0.2.50", text)                                    # no authority configured: no rule for one
        text, incoming, outgoing = self.rules(dict(AUTHORITY, port=51900))
        self.assertIn('ip daddr 192.0.2.10 udp dport 51821 ip saddr 192.0.2.50 accept comment "service mesh: WireGuard, from the authority"', incoming)
        self.assertIn('ip daddr 192.0.2.50 udp dport 51900 accept comment "service mesh: WireGuard, to the authority"', outgoing)
        self.assertEqual(text.count("192.0.2.50"), 2)

    def test_the_prefix_is_the_tunnel_s(self):
        """sitecfg names the prefix because firewall.py renders from the site config alone; wgsvc derives the
        addresses. They must be the same network."""
        try:
            from deploy.baremetal import wgsvc
        except ImportError:
            self.skipTest("wgsvc.py is not on this branch yet (#80 step 2)")
        self.assertEqual(str(wgsvc.PREFIX), sitecfg.SERVICE_PREFIX)

    def test_a_boot_mesh_without_a_service_mesh_renders_as_before(self):
        doc = meshed()
        doc["service_mesh"] = None
        text = firewall.render(sitecfg.validate(doc))
        self.assertNotIn("ip6 ", text)
        self.assertNotIn("51821", text)
        self.assertIn('iifname "wg-unlock" drop', text)

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nft_accepts_the_syntax_with_both_meshes(self):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=firewall.render(sitecfg.validate(meshed(AUTHORITY))), capture_output=True, text=True)
        if "Operation not permitted" in r.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN here")
        self.assertEqual(r.returncode, 0, r.stderr)



AUTHORITY_EXAMPLE = EXAMPLE.with_name("authority-site.example.json")


class AuthorityHost(unittest.TestCase):
    """#324: the revocation authority's host, default-deny both ways, from its own site file, authority.json and the
    signed manifest it holds."""
    def setUp(self):
        self.site = sitecfg.validate_authority(json.loads(AUTHORITY_EXAMPLE.read_text()))
        self.cfg = {"listen_port": 51821, "sync_port": 7444, "time_servers": ["nts.netnod.se", "time.cloudflare.com"],
                    "underlays": {"a": "192.0.2.10", "b": "192.0.2.20", "c": "192.0.2.30"}}
        self.manifest = {"epoch": 4, "nodes": [{"node_id": "a", "state": "ACTIVE"}, {"node_id": "b", "state": "MAINTENANCE"},
                                                {"node_id": "c", "state": "ACTIVE"}]}

    def text(self, manifest=None):
        return firewall.render_authority(self.site, self.cfg, manifest or self.manifest)

    def test_the_site_file_is_checked_as_a_node_s_fields_are(self):
        doc = json.loads(AUTHORITY_EXAMPLE.read_text())
        for label, change, reason in (
                ("a KMS port: the authority serves none", {"kms_port": 8443}, "unknown=['kms_port']"),
                ("a mesh: its tunnel is authority.json's", {"service_mesh": None}, "unknown=['service_mesh']"),
                ("no audit sink", {"outbound": [{"name": "dns", "cidr": "203.0.113.194/32", "proto": "udp", "port": 53}]}, "must include the 'audit' sink"),
                ("plain NTP opened by hand", {"outbound": doc["outbound"] + [{"name": "ntp", "cidr": "0.0.0.0/0", "proto": "udp", "port": 123}]},
                 "no plain-NTP fallback"),
                ("ssh on node_exporter's port", {"ssh_port": 9100}, "must not be 9100"),
                ("admin overlapping monitoring", {"admin_cidrs": ["203.0.113.128/25"]}, "zones must be disjoint"),
                ("a wide NTS network", {"time": {"nts": [{"name": "nts.netnod.se", "cidrs": ["194.58.0.0/16"]},
                                                          {"name": "time.cloudflare.com", "cidrs": ["162.159.200.0/24"]}]}}, "/24")):
            with self.subTest(label):
                with self.assertRaises(sitecfg.InvalidSite) as caught:
                    sitecfg.validate_authority(dict(doc, **change))
                self.assertIn(reason, str(caught.exception))

    def test_default_deny_both_ways_and_each_opening_from_its_zone(self):
        text = self.text()
        for hook in ("input", "forward", "output"):
            self.assertIn("type filter hook %s priority filter; policy drop;" % hook, text)
        self.assertIn('ip daddr 203.0.113.50 tcp dport 9100 ip saddr { 203.0.113.128/32 } accept comment "node metrics: monitoring only (#305)"', text)
        self.assertIn('ip daddr 203.0.113.50 tcp dport 22 ip saddr { 203.0.113.0/28 } accept comment "ssh: admin only"', text)
        self.assertIn('ip daddr 203.0.113.192/32 tcp dport 6514 accept comment "audit"', text)
        for name, net in (("nts.netnod.se", "194.58.200.0/24"), ("time.cloudflare.com", "162.159.200.0/24")):
            self.assertIn('ip daddr { %s } tcp dport 4460 accept comment "time: %s, NTS-KE"' % (net, name), text)
            self.assertIn('ip daddr { %s } udp dport 123 accept comment "time: %s, NTP"' % (net, name), text)
        # WireGuard from and to the nodes; sync in; metrics; ssh; audit; 2 per NTS server: nothing else opens
        self.assertEqual(text.count(" dport ") + text.count(" sport "), 2 + 2 + 1 + 1 + 1 + 4 + 1)
        self.assertNotIn("kms", text.lower().replace("regalia-kms", ""))
        self.assertEqual(text, self.text())                                    # deterministic

    def test_the_tunnel_takes_sync_requests_and_sends_only_answers(self):
        """sync.Server only: the authority asks nobody, so nothing starts a connection out of the tunnel."""
        text = self.text()
        self.assertIn('iifname "wg-svc" ip6 saddr fd72:6567:6c61::/48 ip6 daddr fd72:6567:6c61::/48 tcp dport 7444 tcp flags', text)
        self.assertIn('oifname "wg-svc" ip6 saddr fd72:6567:6c61::/48 ip6 daddr fd72:6567:6c61::/48 tcp sport 7444 ct state established accept', text)
        self.assertNotIn('oifname "wg-svc" ip6 saddr fd72:6567:6c61::/48 ip6 daddr fd72:6567:6c61::/48 tcp dport', text)
        self.assertIn('oifname "wg-svc" drop', text)
        self.assertIn('iifname "wg-svc" drop', text)

    def test_the_nodes_are_the_manifest_s_and_a_stolen_one_drops_out(self):
        text = self.text()
        self.assertIn('ip daddr 203.0.113.50 udp dport 51821 ip saddr { 192.0.2.10/32, 192.0.2.20/32, 192.0.2.30/32 } accept', text)
        self.assertIn('ip daddr { 192.0.2.10/32, 192.0.2.20/32, 192.0.2.30/32 } udp dport 51821 accept', text)
        stolen = dict(self.manifest, epoch=5, nodes=[dict(n, state="REVOKED_STOLEN") if n["node_id"] == "b" else n for n in self.manifest["nodes"]])
        text = self.text(stolen)
        self.assertNotIn("192.0.2.20", text)
        self.assertIn("membership epoch 5", text)
        # a node of the manifest with no underlay here, and an underlay of a node the manifest does not name: neither opens
        self.cfg["underlays"] = {"a": "192.0.2.10", "z": "192.0.2.99"}
        self.assertNotIn("192.0.2.99", self.text())
        self.assertNotIn("192.0.2.30", self.text())
        # no node at all: no WireGuard rule (an empty set is not valid nft), the rest unchanged
        self.cfg["underlays"] = {}
        self.assertNotIn("udp dport 51821", self.text())

    def test_chrony_and_the_firewall_must_name_the_same_servers(self):
        self.cfg["time_servers"] = ["nts.netnod.se", "ptbtime1.ptb.de"]
        with self.assertRaises(sitecfg.InvalidSite) as caught:
            self.text()
        self.assertIn("are not authority.json's time_servers", str(caught.exception))

    def test_the_copies_of_shared_names_are_held_equal(self):
        from deploy.baremetal import membership, wgsvc
        self.assertEqual(firewall.TERMINAL, membership.TERMINAL)
        self.assertEqual(firewall.AUTHORITY_INTERFACE, wgsvc.INTERFACE)

    def test_apply_loads_only_what_nft_accepted_and_installs_it_whole(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        calls = []

        def nft(code):
            def run(argv, **kw):
                calls.append(argv[:2])
                return subprocess.CompletedProcess(argv, code if argv[1] == "-c" else 0, "", "syntax error" if code else "")
            return run
        with self.assertRaises(sitecfg.InvalidSite):
            firewall.apply_authority(self.text(), nft(1), d)
        self.assertEqual((calls, os.listdir(d)), ([["nft", "-c"]], []))
        calls.clear()
        firewall.apply_authority(self.text(), nft(0), d)
        self.assertEqual((calls, os.listdir(d)), ([["nft", "-c"], ["nft", "-f"]], [firewall.AUTHORITY_RULES]))
        with open(os.path.join(d, firewall.AUTHORITY_RULES)) as f:
            self.assertEqual(f.read(), self.text())

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nft_accepts_the_syntax(self):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=self.text(), capture_output=True, text=True)
        if "Operation not permitted" in r.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN here")
        self.assertEqual(r.returncode, 0, r.stderr)

if __name__ == "__main__":
    unittest.main()
