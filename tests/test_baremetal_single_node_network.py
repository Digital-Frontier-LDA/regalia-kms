"""The single-node network shape (regalia-kms-dx7.6, docs/design/single-node.md 4.5, 4.9): the site config's boot mesh
whose one peer is the owner (no node peer, no service mesh), the running host's firewall with no boot-mesh opening and no
empty set, no wg-svc, the initrd's boot mesh to the owner by the manifest's owner_wg_pub, and each shape accepted only
under its own profile: multi-node is unchanged. Test keys and documentation addresses only."""
import base64
import json
import pathlib
import shutil
import subprocess
import unittest
import unittest.mock

import tests.test_baremetal_node as tn
from deploy.baremetal import bootcreds, bootnet, firewall, membership as m, node, sitecfg, wgsvc
from tests.test_baremetal_membership_v4 import manifest4, nodes4
from tests.test_baremetal_membership_v5 import OWNER_WG, manifest5, one, single5

EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "site.example.json"
OWNER = {"underlay": "203.0.113.50", "address": "10.89.0.9"}


def single_site(**mesh):
    doc = json.loads(EXAMPLE.read_text())
    doc["host_ipv4"] = "192.0.2.10"
    doc["boot_mesh"] = dict({"node_id": "a", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
                             "nic_mac": "52:54:00:12:34:56", "prefix": 32, "gateway": None, "peers": [], "owner": dict(OWNER)}, **mesh)
    doc["service_mesh"] = None
    return doc


def multi_site():
    doc = single_site(peers=[{"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"},
                             {"node_id": "c", "underlay": "192.0.2.30", "address": "10.89.0.3"}])
    del doc["boot_mesh"]["owner"]
    doc["service_mesh"] = {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444}
    return doc


class Refuses(unittest.TestCase):
    def refused(self, reason, fn, *args):
        with self.assertRaises((m.Refused, sitecfg.InvalidSite)) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class SiteShape(Refuses):
    def test_the_single_node_shape_is_valid_and_its_profile_is_single_node(self):
        cfg = sitecfg.validate(single_site())
        self.assertEqual((cfg["boot_mesh"]["peers"], cfg["boot_mesh"]["owner"], cfg["service_mesh"]), ([], OWNER, None))
        self.assertEqual(sitecfg.profile(cfg), sitecfg.SINGLE_NODE)
        self.assertEqual(sitecfg.profile(sitecfg.validate(multi_site())), sitecfg.MULTI_NODE)
        self.assertIsNone(sitecfg.profile(sitecfg.validate(json.loads(EXAMPLE.read_text()))))

    def test_a_multi_node_boot_mesh_still_needs_one_to_eight_peers_and_names_no_owner(self):
        doc = multi_site()
        doc["boot_mesh"]["peers"] = []
        self.refused("boot_mesh.peers must list 1 to 8 nodes", sitecfg.validate, doc)
        self.assertNotIn("owner", sitecfg.validate(multi_site())["boot_mesh"])      # its normal form, so its PCR 12, unchanged

    def test_each_other_single_node_shape_is_refused(self):
        peer = {"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"}
        cases = [("a single-node boot_mesh lists no peers: its one peer is the owner", single_site(peers=[peer])),
                 ("boot_mesh.owner needs exactly ['underlay', 'address']", single_site(owner=dict(OWNER, key="x"))),
                 ("boot_mesh.owner needs exactly", single_site(owner={"underlay": OWNER["underlay"]})),
                 ("boot_mesh.owner: no two ends share an address", single_site(owner=dict(OWNER, underlay="192.0.2.10"))),
                 ("boot_mesh.owner: no two ends share an address", single_site(owner=dict(OWNER, address="10.89.0.1"))),
                 ("boot_mesh.owner: no two ends share an address", single_site(owner=dict(OWNER, address=OWNER["underlay"]))),
                 ("boot_mesh.owner.underlay must be a host address", single_site(owner=dict(OWNER, underlay="127.0.0.1"))),
                 ("the tunnel and the zones must be disjoint", single_site(owner=dict(OWNER, address="198.51.100.9")))]
        for reason, doc in cases:
            with self.subTest(reason):
                self.refused(reason, sitecfg.validate, doc)

    def test_the_owner_s_unlock_port_may_be_a_port_this_host_serves_and_a_peer_s_may_not(self):
        """Nothing listens on unlock_port on a single-node host: it is the owner's port, at the owner's address."""
        self.assertEqual(sitecfg.validate(single_site(unlock_port=8443))["boot_mesh"]["unlock_port"], 8443)
        doc = multi_site()
        doc["boot_mesh"]["unlock_port"] = 8443
        self.refused("boot_mesh.unlock_port must differ from kms_port", sitecfg.validate, doc)

    def test_a_single_node_host_has_no_service_mesh(self):
        doc = single_site()
        doc["service_mesh"] = {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444}
        self.refused("a single-node host has no service_mesh: no wg-svc", sitecfg.validate, doc)

    def test_each_shape_only_under_its_own_profile(self):
        single, multi = sitecfg.validate(single_site()), sitecfg.validate(multi_site())
        sitecfg.require_profile(single, m.SINGLE_NODE)
        sitecfg.require_profile(multi, m.MULTI_NODE)
        self.refused("the site configuration is for a single-node host and the manifest is multi-node", sitecfg.require_profile, single, m.MULTI_NODE)
        self.refused("the site configuration is for a multi-node host and the manifest is single-node", sitecfg.require_profile, multi, m.SINGLE_NODE)


class Firewall(unittest.TestCase):
    def setUp(self):
        self.text = firewall.render(sitecfg.validate(single_site()))

    def test_no_boot_mesh_opening_no_empty_set_and_no_wg_svc(self):
        self.assertNotIn("{  }", self.text)
        self.assertNotIn("{ }", self.text)
        self.assertNotIn("boot mesh", self.text)
        self.assertNotIn("wg-unlock", self.text)
        self.assertNotIn("service mesh", self.text)
        self.assertNotIn("udp dport 51820", self.text)
        self.assertIn("ip daddr 192.0.2.10 tcp dport 8443", self.text)          # the KMS port, as on any host
        # the very ruleset of a host with no boot mesh: nothing of the mesh reaches the running host's table
        self.assertEqual(self.text, firewall.render(sitecfg.validate(dict(single_site(), boot_mesh=None))))

    def test_a_multi_node_host_keeps_its_two_meshes(self):
        text = firewall.render(sitecfg.validate(multi_site()))
        self.assertIn("boot mesh: WireGuard, from the peers' declared addresses", text)
        self.assertIn("service mesh: a new sync request", text)

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nft_accepts_the_single_node_ruleset(self):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=self.text, capture_output=True, text=True)
        if r.returncode != 0 and "Operation not permitted" in r.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN here")
        self.assertEqual(r.returncode, 0, r.stderr)


class BootMesh(Refuses):
    def setUp(self):
        self.cfg, self.single = sitecfg.validate(single_site()), single5(1, "")

    def test_the_initrd_s_one_peer_is_the_owner_by_the_manifest_s_key(self):
        key = base64.b64encode(bytes.fromhex(OWNER_WG)).decode()
        self.assertEqual(bootnet.boot_wg_conf(self.cfg, self.single),
                         "[Interface]\n\n[Peer]\n# owner\nPublicKey = %s\nAllowedIPs = 10.89.0.9/32\nEndpoint = 203.0.113.50:51820\n" % key)
        self.assertEqual(bootnet.unlock_endpoints(self.cfg, self.single), {"owner": "10.89.0.9:7443"})
        ruleset = bootnet.boot_ruleset(self.cfg, self.single)
        self.assertIn("ip daddr { 203.0.113.50 } udp dport 51820 accept", ruleset)
        self.assertIn('oifname "wg-boot" ip saddr 10.89.0.1 ip daddr { 10.89.0.9 } tcp dport 7443', ruleset)

    def test_a_rotated_owner_key_is_the_one_rendered(self):
        rotated = single5(1, "", owner_wg_pub="0d" * 32)
        self.assertIn("PublicKey = %s" % base64.b64encode(bytes([13] * 32)).decode(), bootnet.boot_wg_conf(self.cfg, rotated))

    def test_the_owner_s_side_knows_the_node_by_its_boot_key(self):
        node = one("a")
        self.assertEqual(bootnet.owner_wg_conf(self.cfg, self.single), "[Interface]\nListenPort = 51820\n\n[Peer]\n# a\nPublicKey = %s\n"
                         "AllowedIPs = 10.89.0.1/32\n" % base64.b64encode(bytes.fromhex(node["wg_boot_pub"])).decode())
        revoked = single5(2, m.digest(self.single), nodes=[one("a", "REVOKED_STOLEN")])
        self.assertEqual(bootnet.owner_wg_conf(self.cfg, revoked), "[Interface]\nListenPort = 51820\n")      # it knows nobody

    def test_the_running_host_is_nobody_s_unlock_peer(self):
        self.refused("a single-node host is nobody's unlock peer: no wg-unlock on it", bootnet.peer_wg_conf, self.cfg, self.single)
        self.refused("a single-node host is nobody's unlock peer", bootnet.caller_of, self.cfg, self.single)

    def test_multi_node_still_needs_its_node_peers(self):
        """The single-node site under a multi-node manifest, and a multi-node site under a single-node manifest, are refused."""
        three = manifest5(1, "", nodes4())
        for fn in (bootnet.boot_wg_conf, bootnet.boot_ruleset, bootnet.unlock_endpoints):
            with self.subTest(fn.__name__):
                self.refused("the site configuration is for a single-node host and the manifest is multi-node", fn, self.cfg, three)
                self.refused("the site configuration is for a single-node host and the manifest is multi-node", fn, self.cfg, manifest4(1, "", nodes4()))
                self.refused("the site configuration is for a multi-node host and the manifest is single-node", fn,
                             sitecfg.validate(multi_site()), self.single)
        self.refused("owner_wg_conf is the single-node profile's", bootnet.owner_wg_conf, sitecfg.validate(multi_site()), three)

    def test_a_multi_node_boot_mesh_is_as_before(self):
        cfg, three = sitecfg.validate(multi_site()), manifest5(1, "", nodes4())
        self.assertEqual(sorted(bootnet.unlock_endpoints(cfg, three)), ["b", "c"])
        self.assertIn("# b\nPublicKey", bootnet.boot_wg_conf(cfg, three))

    def test_the_site_document_carries_the_owner_and_reads_back(self):
        raw = bootcreds.site_document(self.cfg, "/dev/disk/by-partlabel/regalia-root")
        site, _ = bootcreds.read_site(raw)
        self.assertEqual(site["boot_mesh"]["owner"], OWNER)
        self.refused("a single-node host's boot credentials are not rendered yet", bootcreds.render, self.single, site, "/dev/x")


class SingleNodeHost(tn.Case):
    """node.py on a single-node host: the site loads with no service mesh, wg-apply makes no interface (no wg-svc, no
    wg-unlock) under a single-node manifest and refuses the shape under a multi-node one, and sync has no peer to pull from."""

    def setUp(self):
        super().setUp()
        self.site = dict(tn.SITE, boot_mesh=dict(tn.SITE["boot_mesh"], peers=[], owner=dict(OWNER)), service_mesh=None)
        with open(self.cfg["site"], "w") as f:
            json.dump(self.site, f)

    def applying(self, manifest):
        """A node whose verified manifest is `manifest` (the chain's store and anchor are test_baremetal_node's own tests)."""
        host = tn.Host(self.tpm, None)
        n = self.node(run=host)
        host.site, n.manifest = n.site, (lambda: manifest)
        return host, n

    def test_wg_apply_makes_no_interface(self):
        host, n = self.applying(single5(1, ""))
        self.assertEqual(node.wg_apply(n), 1)
        self.assertEqual([c for c in host.calls if c[0] in ("ip", "wg")], [])
        self.assertEqual(n.sources(n.manifest()), {})

    def test_the_single_node_site_under_a_multi_node_manifest_is_refused(self):
        host, n = self.applying(manifest5(1, "", nodes4()))
        self.refused("the site configuration is for a single-node host and the manifest is multi-node", node.wg_apply, n)
        self.assertEqual([c for c in host.calls if c[0] in ("ip", "wg")], [])

    def sync_for(self, manifest):
        """node.Sync's pull round and run, on this node, with the store and the publication played."""
        host, n = self.applying(manifest)
        n.documents = lambda: None
        s = object.__new__(node.Sync)
        s.node, s.store, s.freshness, s.trail, s.published_calls = n, None, None, (lambda event: None), []
        s.manifest = lambda: manifest
        s.publish = lambda: s.published_calls.append(1) or True
        return s

    def test_a_round_with_no_peer_still_publishes_the_chain(self):
        s = self.sync_for(single5(1, ""))
        with unittest.mock.patch.object(node.sync, "Client"):
            self.assertTrue(s.pull_round())
        self.assertEqual(s.published_calls, [1])

    def test_sync_refuses_a_site_of_the_other_profile_before_publishing_or_binding(self):
        s = self.sync_for(manifest5(1, "", nodes4()))
        self.refused("the site configuration is for a single-node host and the manifest is multi-node", s.run, lambda: True)
        self.assertEqual(s.published_calls, [])

    def test_a_multi_node_site_still_needs_its_service_mesh(self):
        with open(self.cfg["site"], "w") as f:
            json.dump(dict(tn.SITE, service_mesh=None), f)
        self.refused("this is not a node of a three-site cluster, nor a single-node host", self.node)


class NoWgSvc(Refuses):
    def test_no_wg_svc_under_single_node(self):
        self.refused("no wg-svc under the single-node profile (epoch 1): one node has no peer to sync with", wgsvc.conf, single5(1, ""), "a", {})
        self.assertIn("[Peer]", wgsvc.conf(manifest5(1, "", nodes4()), "a", {}))       # multi-node: as before


if __name__ == "__main__":
    unittest.main()
