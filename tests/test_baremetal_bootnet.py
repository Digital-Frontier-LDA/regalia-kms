"""deploy/baremetal/bootnet.py and the site config's boot_mesh (#66, Phase 6): who is a WireGuard peer of
whom comes from the manifest, where each node is comes from the site config, and the rendered text is
deterministic. Behaviour is proven in network namespaces (e2e/wg-boot-netns.sh); these pin the contract."""
import base64
import copy
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from deploy.baremetal import bootnet, firewall, sitecfg
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt

EXAMPLE = Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "site.example.json"
WHERE = {"a": ("192.0.2.10", "10.89.0.1"), "b": ("198.51.100.7", "10.89.0.2"), "c": ("198.51.100.9", "10.89.0.3")}


def site(node="a", **mesh):
    doc = json.loads(EXAMPLE.read_text())
    doc["host_ipv4"] = WHERE[node][0]
    doc["boot_mesh"] = dict({"node_id": node, "interface": "wg-unlock", "listen_port": 51820, "address": WHERE[node][1], "unlock_port": 7443,
                             "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None,
                             "peers": [{"node_id": n, "underlay": u, "address": t} for n, (u, t) in WHERE.items() if n != node]}, **mesh)
    return doc


def b64(hex_key):
    return base64.b64encode(bytes.fromhex(hex_key)).decode()


SYN = "tcp flags & (fin | syn | rst | ack) == syn ct state new accept"   # the beginning of a connection, and nothing else

class Case(unittest.TestCase):
    def setUp(self):
        self.cfg = sitecfg.validate(site())
        self.m1 = hbt.manifest()
        self.keys = {n["node_id"]: n for n in self.m1["nodes"]}

    def refused(self, reason, fn, *args, error=m.Refused):
        with self.assertRaises(error) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Mesh(Case):
    def test_the_booting_node_knows_the_peers_that_may_authorize_by_their_service_keys_at_their_declared_addresses(self):
        text = bootnet.boot_wg_conf(self.cfg, self.m1)
        self.assertEqual(text, "[Interface]\n"
                         "\n[Peer]\n# b\nPublicKey = %s\nAllowedIPs = 10.89.0.2/32\nEndpoint = 198.51.100.7:51820\n"
                         "\n[Peer]\n# c\nPublicKey = %s\nAllowedIPs = 10.89.0.3/32\nEndpoint = 198.51.100.9:51820\n"
                         % (b64(self.keys["b"]["wg_service_pub"]), b64(self.keys["c"]["wg_service_pub"])))
        self.assertNotIn(b64(self.keys["b"]["wg_boot_pub"]), text)
        self.assertEqual(text, bootnet.boot_wg_conf(sitecfg.validate(site()), hbt.manifest()))       # deterministic
        self.assertEqual(bootnet.unlock_endpoints(self.cfg, self.m1), {"b": "10.89.0.2:7443", "c": "10.89.0.3:7443"})
        # a peer that may not authorize is not asked, not dialled, and not allowed out to
        for state in ("MAINTENANCE", "DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"):
            with self.subTest(state):
                manifest = hbt.manifest(c=state)
                self.assertNotIn("# c", bootnet.boot_wg_conf(self.cfg, manifest))
                self.assertEqual(bootnet.unlock_endpoints(self.cfg, manifest), {"b": "10.89.0.2:7443"})
                self.assertNotIn("198.51.100.9", bootnet.boot_ruleset(self.cfg, manifest))
        self.refused("the manifest leaves a no peer that may authorize", bootnet.boot_wg_conf, self.cfg, hbt.manifest(b="QUARANTINED", c="RETIRED"))
        self.refused("the manifest leaves a no peer that may authorize", bootnet.boot_ruleset, self.cfg, hbt.manifest(b="QUARANTINED", c="RETIRED"))

    def test_the_running_peer_knows_the_nodes_that_may_be_unlocked_by_their_boot_keys(self):
        cfg = sitecfg.validate(site("b"))
        text = bootnet.peer_wg_conf(cfg, self.m1)
        self.assertEqual(text, "[Interface]\nListenPort = 51820\n"
                         "\n[Peer]\n# a\nPublicKey = %s\nAllowedIPs = 10.89.0.1/32\n"
                         "\n[Peer]\n# c\nPublicKey = %s\nAllowedIPs = 10.89.0.3/32\n"
                         % (b64(self.keys["a"]["wg_boot_pub"]), b64(self.keys["c"]["wg_boot_pub"])))
        self.assertNotIn("Endpoint", text)                           # it answers; it never dials a booting node
        caller = bootnet.caller_of(cfg, self.m1)
        self.assertEqual([caller(a) for a in ("10.89.0.1", "10.89.0.3", "10.89.0.2", "198.51.100.9", "10.89.0.9")], ["a", "c", None, None, None])
        self.assertIsNone(bootnet.caller_of(cfg, hbt.manifest(a="REVOKED_STOLEN"))("10.89.0.1"))
        self.assertNotIn(b64(self.keys["a"]["wg_service_pub"]), text)
        # a node that may no longer be unlocked leaves the list with the manifest that says so
        self.assertIn("# a", bootnet.peer_wg_conf(cfg, hbt.manifest(a="MAINTENANCE")))
        for state in ("DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"):
            with self.subTest(state):
                self.assertNotIn("# a", bootnet.peer_wg_conf(cfg, hbt.manifest(a=state)))
        # and a host that may not authorize knows nobody at all
        for state in ("MAINTENANCE", "DRAINING", "QUARANTINED", "REVOKED_STOLEN"):
            with self.subTest("the peer itself is " + state):
                self.assertEqual(bootnet.peer_wg_conf(cfg, hbt.manifest(b=state)), "[Interface]\nListenPort = 51820\n")

    def test_no_private_key_and_no_unknown_node_is_ever_rendered(self):
        for text in (bootnet.boot_wg_conf(self.cfg, self.m1), bootnet.peer_wg_conf(self.cfg, self.m1), bootnet.boot_ruleset(self.cfg, self.m1)):
            self.assertNotIn("PrivateKey", text)
        # the key is added only by whoever applies the text, in memory
        key = base64.b64encode(bytes(range(32))).decode()
        applied = bootnet.with_key(bootnet.peer_wg_conf(self.cfg, self.m1), key + "\n")
        self.assertTrue(applied.startswith("[Interface]\nPrivateKey = %s\nListenPort = 51820\n\n[Peer]\n" % key))
        self.assertEqual(bootnet.with_key(bootnet.boot_wg_conf(self.cfg, self.m1), key).count("PrivateKey"), 1)
        for bad in ("", "not a key", key[:-4], None, key + key):
            self.refused("the private key is not a WireGuard key", bootnet.with_key, bootnet.boot_wg_conf(self.cfg, self.m1), bad)
        self.refused("this is not a configuration rendered here", bootnet.with_key, applied, key)
        self.refused("this is not a configuration rendered here", bootnet.with_key, "[Peer]\n", key)
        self.refused("the site config has no boot_mesh: this is a single-site host", bootnet.boot_wg_conf,
                     sitecfg.validate(json.loads(EXAMPLE.read_text())), self.m1)
        # the manifest lets c authorize, and the site config does not say where c is
        short = site()
        short["boot_mesh"]["peers"] = short["boot_mesh"]["peers"][:1]
        for render in (bootnet.boot_wg_conf, bootnet.boot_ruleset, bootnet.unlock_endpoints):
            self.refused("the site config has no boot-mesh address for c, which the manifest lets authorize", render, sitecfg.validate(short), self.m1)
        self.refused("the site config has no boot-mesh address for c, which the manifest lets request", bootnet.peer_wg_conf, sitecfg.validate(short), self.m1)
        self.refused("x is not in the manifest", bootnet.boot_wg_conf, sitecfg.validate(site(node_id="x")), self.m1)
        self.refused("x is not in the manifest", bootnet.peer_wg_conf, sitecfg.validate(site(node_id="x")), self.m1)
        self.refused("manifest fields mismatch", bootnet.boot_wg_conf, self.cfg, {"schema": m.SCHEMA})

    def test_the_initrd_ruleset_denies_by_default_and_opens_two_things(self):
        text = bootnet.boot_ruleset(self.cfg, self.m1)
        for hook in ("input", "forward", "output"):
            self.assertIn("type filter hook %s priority filter; policy drop;" % hook, text)
        self.assertIn('ip daddr { 198.51.100.7, 198.51.100.9 } udp dport 51820 accept', text)
        self.assertIn('oifname "wg-boot" ip saddr 10.89.0.1 ip daddr { 10.89.0.2, 10.89.0.3 } tcp dport 7443 %s comment' % SYN, text)
        self.assertEqual(text.count(" dport "), 2)                    # WireGuard and the unlock port: nothing else opens
        self.assertEqual(text.count("meta nfproto ipv6 drop"), 2)
        self.assertNotIn(" 22 ", text)
        self.assertNotIn("8443", text)

    def test_the_running_hosts_firewall_opens_the_mesh_to_declared_addresses_only(self):
        text = firewall.render(sitecfg.validate(site("b")))
        self.assertIn("ip daddr 198.51.100.7 udp dport 51820 ip saddr { 192.0.2.10/32, 198.51.100.9/32 } accept", text)
        unlock_rule = 'iifname "wg-unlock" ip daddr 10.89.0.2 tcp dport 7443 ip saddr { 10.89.0.1/32, 10.89.0.3/32 } %s comment' % SYN
        self.assertIn(unlock_rule, text)
        # everything else that arrives inside the tunnel is dropped BEFORE the zone rules: a packet from a
        # tunnel address to the host's own address never reaches the KMS or SSH rule, whatever the zones say
        order = [text.index(rule) for rule in ("ct state established,related accept", unlock_rule, 'iifname "wg-unlock" drop',
                                               "tcp dport 8443", "tcp dport 22", "icmp type echo-request")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(text.count(" dport "), 6)                    # kms, ssh, audit, ntp, and the two of the mesh
        self.assertEqual(text.count("7443"), 1)                       # the unlock port is open inside the tunnel and nowhere else
        plain = firewall.render(sitecfg.validate(json.loads(EXAMPLE.read_text())))
        self.assertNotIn("boot mesh", plain)
        self.assertEqual(plain.count(" dport "), 4)

    @unittest.skipUnless(shutil.which("nft", path="/usr/sbin:/sbin:/usr/bin"), "nft not installed")
    def test_nft_accepts_both_rulesets(self):
        nft = shutil.which("nft", path="/usr/sbin:/sbin:/usr/bin")
        for text in (bootnet.boot_ruleset(self.cfg, self.m1), firewall.render(sitecfg.validate(site("b")))):
            r = subprocess.run([nft, "-c", "-f", "-"], input=text, capture_output=True, text=True)
            if "Operation not permitted" in r.stderr:
                self.skipTest("nft -c needs CAP_NET_ADMIN here")
            self.assertEqual(r.returncode, 0, r.stderr)


class SiteMesh(Case):
    def test_the_initrd_card_prefix_and_gateway(self):
        self.assertEqual({k: self.cfg["boot_mesh"][k] for k in ("nic_mac", "prefix", "gateway")}, {"nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None})
        routed = sitecfg.validate(site(prefix=24, gateway="192.0.2.1"))["boot_mesh"]
        self.assertEqual((routed["prefix"], routed["gateway"]), (24, "192.0.2.1"))
        self.assertEqual(sitecfg.validate(site(prefix=31, gateway="192.0.2.11"))["boot_mesh"]["gateway"], "192.0.2.11")   # a /31: both addresses are hosts

    def test_the_boot_mesh_is_null_or_exact(self):
        self.assertIsNone(sitecfg.validate(json.loads(EXAMPLE.read_text()))["boot_mesh"])
        self.assertEqual(self.cfg["boot_mesh"]["peers"][0], {"node_id": "b", "underlay": "198.51.100.7", "address": "10.89.0.2"})
        peers = site()["boot_mesh"]["peers"]
        cases = {
            "absent": (lambda d: d.pop("boot_mesh"), "fields mismatch"),
            "not an object": (lambda d: d.__setitem__("boot_mesh", []), "boot_mesh must be null or hold exactly"),
            "unknown field": (lambda d: d["boot_mesh"].__setitem__("psk", "x"), "boot_mesh must be null or hold exactly"),
            "node id": (lambda d: d["boot_mesh"].__setitem__("node_id", "Lisbon"), "boot_mesh.node_id is not a node ID"),
            "interface": (lambda d: d["boot_mesh"].__setitem__("interface", "wg-unlock-too-long"), "a WireGuard interface of its own"),
            "interface quote": (lambda d: d["boot_mesh"].__setitem__("interface", 'wg-" accept'), "a WireGuard interface of its own"),
            "a physical interface": (lambda d: d["boot_mesh"].__setitem__("interface", "eth0"), "a WireGuard interface of its own"),
            "loopback interface": (lambda d: d["boot_mesh"].__setitem__("interface", "lo"), "a WireGuard interface of its own"),
            "the initrd's interface": (lambda d: d["boot_mesh"].__setitem__("interface", "wg-boot"), "not wg-boot"),
            "tunnel inside the client zone": (lambda d: d.__setitem__("client_cidrs", ["10.0.0.0/8"]), "the tunnel address 10.89.0.1 is inside client_cidrs (10.0.0.0/8)"),
            "tunnel inside the admin zone": (lambda d: d.__setitem__("admin_cidrs", ["10.89.0.0/28"]), "is inside admin_cidrs"),
            "tunnel inside monitoring": (lambda d: d.__setitem__("monitoring_cidrs", ["10.89.0.3/32"]), "the tunnel address 10.89.0.3 is inside monitoring_cidrs"),
            "tunnel is a sink": (lambda d: d["outbound"][0].__setitem__("cidr", "10.89.0.2/32"), "is inside outbound"),
            "address not text": (lambda d: d["boot_mesh"].__setitem__("address", True), "must be an IPv4 address, as text"),
            "address a number": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("underlay", 167772161), "must be an IPv4 address, as text"),
            "broadcast": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("address", "255.255.255.255"), "must be a host address"),
            "link-local": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("underlay", "169.254.1.1"), "must be a host address"),
            "one address for both": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("address", "198.51.100.7"), "no address is both"),
            "port": (lambda d: d["boot_mesh"].__setitem__("listen_port", 0), "boot_mesh.listen_port must be a port"),
            "unlock on the KMS port": (lambda d: d["boot_mesh"].__setitem__("unlock_port", 8443), "must differ from kms_port and ssh_port"),
            "address": (lambda d: d["boot_mesh"].__setitem__("address", "10.89.0.0/24"), "boot_mesh.address must be an IPv4 address"),
            "address is the host's": (lambda d: d["boot_mesh"].__setitem__("address", "192.0.2.10"), "the tunnel's address, not host_ipv4"),
            "no peers": (lambda d: d["boot_mesh"].__setitem__("peers", []), "must list 1 to 8 nodes"),
            "peer field": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("key", "x"), "peers[0] needs exactly"),
            "itself": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("node_id", "a"), "another node's ID, listed once"),
            "twice": (lambda d: d["boot_mesh"].__setitem__("peers", [peers[0], peers[0]]), "another node's ID, listed once"),
            "shared tunnel address": (lambda d: d["boot_mesh"]["peers"][1].__setitem__("address", "10.89.0.2"), "no two nodes share an address"),
            "shared underlay": (lambda d: d["boot_mesh"]["peers"][1].__setitem__("underlay", "198.51.100.7"), "no two nodes share an address"),
            "the host's own underlay": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("underlay", "192.0.2.10"), "no two nodes share an address"),
            "IPv6 underlay": (lambda d: d["boot_mesh"]["peers"][0].__setitem__("underlay", "2001:db8::7"), "underlay must be an IPv4 address"),
            # the initrd's card, prefix and gateway (#66, regalia.boot-env)
            "no nic_mac": (lambda d: d["boot_mesh"].pop("nic_mac"), "boot_mesh must be null or hold exactly"),
            "a MAC in upper case": (lambda d: d["boot_mesh"].__setitem__("nic_mac", "52:54:00:AB:CD:01"), "nic_mac must be a unicast MAC"),
            "a MAC with dashes": (lambda d: d["boot_mesh"].__setitem__("nic_mac", "52-54-00-12-34-56"), "nic_mac must be a unicast MAC"),
            "an interface name": (lambda d: d["boot_mesh"].__setitem__("nic_mac", "eno1"), "nic_mac must be a unicast MAC"),
            "a multicast MAC": (lambda d: d["boot_mesh"].__setitem__("nic_mac", "01:00:5e:00:00:01"), "nic_mac must be a unicast MAC"),
            "an all-zero MAC": (lambda d: d["boot_mesh"].__setitem__("nic_mac", "00:00:00:00:00:00"), "nic_mac must be a unicast MAC"),
            "prefix 0": (lambda d: d["boot_mesh"].__setitem__("prefix", 0), "prefix must be a prefix length from 1 to 32"),
            "prefix 33": (lambda d: d["boot_mesh"].__setitem__("prefix", 33), "prefix must be a prefix length from 1 to 32"),
            "prefix true": (lambda d: d["boot_mesh"].__setitem__("prefix", True), "prefix must be a prefix length from 1 to 32"),
            "prefix as text": (lambda d: d["boot_mesh"].__setitem__("prefix", "24"), "prefix must be a prefix length from 1 to 32"),
            "a gateway off the link": (lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.3.1"), "gateway must be another address inside 192.0.2.0/24"),
            "the host as its gateway": (lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.10"), "gateway must be another address inside"),
            "the network as gateway": (lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.0"), "not its network or broadcast address"),
            "the broadcast as gateway": (lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.255"), "not its network or broadcast address"),
            "a gateway under /32": (lambda d: d["boot_mesh"].update(gateway="192.0.2.1"), "gateway must be another address inside 192.0.2.10/32"),
            "a gateway as a network": (lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.2.1/24"), "boot_mesh.gateway must be an IPv4 address"),
        }
        for label, (breakit, why) in cases.items():
            with self.subTest(label):
                doc = copy.deepcopy(site())
                breakit(doc)
                self.refused(why, sitecfg.validate, doc, error=sitecfg.InvalidSite)


if __name__ == "__main__":
    unittest.main()
