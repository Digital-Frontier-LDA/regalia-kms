"""e2e/lib/threenode.py by topology (regalia-kms-dx7.10, docs/design/single-node.md 8): the fixture of the three-node
scenarios also builds ONE node (Cluster(topology="single-node"), e2e/one-node.py). Unit tests on a Cluster with no machine
behind it, so the topology's guards are held here and not only by a scenario that needs a runner:

  * a single-node cluster is one node, refused at any other size before anything is made;
  * the heartbeat wait (_beaten) is the heartbeat rule's threshold: two counting nodes under v4, as before, one under
    single-node, where a lone node signs its own;
  * #76's replacement (a running peer takes the epoch) is refused under single-node, by name, before anything is read;
  * a single-node site configuration is dx7.6's shape (sitecfg): no node peer, the owner's machine as the boot mesh's one
    peer, no service mesh; the three-node one is what it was;
  * a single-node host has no peer path: enrol() takes the owner's, and refuses a peer;
  * the genesis console (Cluster.acknowledge) types the phrase the shipped prompt names, and the tool accepts it."""
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode  # noqa: E402
from deploy.baremetal import manifest as manifest_tool  # noqa: E402
from deploy.baremetal import membership, sitecfg  # noqa: E402
from tests.test_baremetal_membership_v4 import manifest4  # noqa: E402
from tests.test_baremetal_membership_v5 import one, single5  # noqa: E402


def three():
    return manifest4(1, "", [one("a", i=0), one("b", i=1), one("c", i=2)])


class Fixture(unittest.TestCase):
    def cluster(self, **kw):
        """A Cluster with no machine behind it: its constructor's environment changes undone after the test."""
        work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        patch = unittest.mock.patch.dict(os.environ, {})
        patch.start()
        self.addCleanup(patch.stop)
        with unittest.mock.patch.object(threenode.tpmdiag, "versions", return_value="TPM stack: (not read in a unit test)"):
            return threenode.Cluster(work, **kw)


class Names(Fixture):
    def test_each_topology_has_its_default_size(self):
        self.assertEqual(threenode.topology_names(membership.MULTI_NODE), ("a", "b", "c"))
        self.assertEqual(threenode.topology_names(membership.SINGLE_NODE), ("a",))
        self.assertEqual(list(self.cluster().nodes), ["a", "b", "c"])
        self.assertEqual(list(self.cluster(topology=membership.SINGLE_NODE).nodes), ["a"])

    def test_a_single_node_cluster_of_another_size_is_refused_before_anything_is_made(self):
        for names in (("a", "b"), ("a", "b", "c"), ()):
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, r"a single-node cluster is one node, not %d" % len(names)):
                self.cluster(topology=membership.SINGLE_NODE, names=names)

    def test_an_unknown_topology_is_refused(self):
        with self.assertRaisesRegex(ValueError, "topology is multi-node or single-node"):
            threenode.topology_names("two-node")

    def test_only_a_single_node_cluster_has_the_owner_s_machine(self):
        alone = self.cluster(topology=membership.SINGLE_NODE)
        self.assertIsNone(self.cluster().owner)
        self.assertEqual((alone.owner.ns, alone.owner.underlay, alone.owner.boot_address), ("e2e3-owner", "192.0.2.200", "10.89.0.20"))
        self.assertNotIn("owner", alone.nodes)          # never a member: no TPM, no services


class Beaten(Fixture):
    """_beaten waits for the nodes' own heartbeat when as many counting nodes run as the heartbeat rule's threshold."""

    def waits(self, manifest, running):
        cluster = self.cluster(topology=membership.profile(manifest))
        waited = []
        with unittest.mock.patch.object(cluster, "running", side_effect=lambda name: name in running), \
                unittest.mock.patch.object(cluster, "fresh", side_effect=lambda names, epoch, timeout: waited.append(sorted(names)) or {n: True for n in names}):
            cluster._beaten(manifest)
        return waited

    def test_the_need_is_the_heartbeat_rule_s_threshold(self):
        self.assertEqual(threenode.heartbeat_need(three()), 2)
        self.assertEqual(threenode.heartbeat_need(single5(1, "")), 1)

    def test_three_nodes_wait_with_two_running_and_not_with_one(self):
        self.assertEqual(self.waits(three(), {"a", "b"}), [["a", "b"]])
        self.assertEqual(self.waits(three(), {"a"}), [])

    def test_a_lone_single_node_waits_for_its_own_heartbeat(self):
        self.assertEqual(self.waits(single5(1, ""), {"a"}), [["a"]])

    def test_a_single_node_not_running_waits_for_nothing(self):
        self.assertEqual(self.waits(single5(1, ""), set()), [])


class Replacement(Fixture):
    def test_a_single_node_replacement_is_refused_by_name(self):
        with self.assertRaisesRegex(RuntimeError, r"replacing a by a2 is refused under the single-node profile \(epoch 1\): no running "
                                    r"peer can take the epoch; a single-node replacement is a restore from the owner's chain"):
            threenode.refuse_replacement(single5(1, ""), "a", "a2")

    def test_a_multi_node_replacement_passes_the_guard(self):
        self.assertIsNone(threenode.refuse_replacement(three(), "c", "c2"))

    def test_the_cluster_refuses_before_it_reads_anything(self):
        cluster = self.cluster(topology=membership.SINGLE_NODE)
        cluster.manifest = single5(1, "")
        with self.assertRaisesRegex(RuntimeError, "refused under the single-node profile"):
            cluster.replacement("a", "a2")             # nothing else is set up: the guard is first


class Site(Fixture):
    def test_a_single_node_site_is_dx7_6_s_shape_with_the_owner_as_the_one_peer(self):
        cluster = self.cluster(topology=membership.SINGLE_NODE)
        site = sitecfg.validate(cluster.site_config(cluster.nodes["a"]))
        self.assertEqual(sitecfg.profile(site), sitecfg.SINGLE_NODE)
        self.assertEqual(site["boot_mesh"]["peers"], [])
        self.assertEqual(site["boot_mesh"]["owner"], {"underlay": "192.0.2.200", "address": "10.89.0.20"})
        self.assertIsNone(site["service_mesh"])

    def test_a_three_node_site_names_the_other_nodes_and_its_service_mesh(self):
        cluster = self.cluster()
        site = sitecfg.validate(cluster.site_config(cluster.nodes["a"]))
        self.assertEqual(sitecfg.profile(site), sitecfg.MULTI_NODE)
        self.assertEqual([p["node_id"] for p in site["boot_mesh"]["peers"]], ["b", "c"])
        self.assertNotIn("owner", site["boot_mesh"])
        self.assertEqual(site["service_mesh"]["interface"], "wg-svc")


class Enrol(Fixture):
    def test_a_single_node_host_takes_the_owner_s_path(self):
        cluster = self.cluster(topology=membership.SINGLE_NODE)
        with unittest.mock.patch.object(cluster, "enrol_owner", return_value={"path_epoch": 1, "keyslot": 1}) as owner:
            self.assertEqual(cluster.enrol("a"), {"path_epoch": 1, "keyslot": 1})
        owner.assert_called_once_with("a")

    def test_a_single_node_host_refuses_a_peer_path(self):
        cluster = self.cluster(topology=membership.SINGLE_NODE)
        with unittest.mock.patch.object(cluster, "enrol_owner") as owner, \
                self.assertRaisesRegex(RuntimeError, r"a single-node host has no peer path \(b\): its one path is the owner's"):
            cluster.enrol("a", peers=["b"])
        owner.assert_not_called()


class Acknowledgement(Fixture):
    def test_the_console_types_the_phrase_the_shipped_prompt_names(self):
        cluster = self.cluster(topology=membership.SINGLE_NODE)
        said = []
        manifest_tool.acknowledge_single_node(cluster.acknowledge, said.append)     # refused unless the phrase is exact
        limits = manifest_tool.single_node_limits()
        self.assertEqual(said[0], limits[:-1] if limits.endswith("\n") else limits)
        phrase = manifest_tool.ACKNOWLEDGEMENT % manifest_tool.SINGLE_NODE_LIMITS_SHA256[:8]
        self.assertEqual(cluster.acknowledge("type, to accept these limits: %s\n> " % phrase), phrase)
        self.assertTrue(any(phrase in line for line in cluster.genesis_said))


class RevokeImport(unittest.TestCase):
    def test_the_import_hands_the_typed_shutdown_phrase_to_revoke_commit(self):
        """The owner's import on the node (revoke.py import, as its sync unit) passes what was typed for a shutdown to
        revoke.commit, which refuses the only node's revocation without it; a multi-node import hands none (None)."""
        code = threenode.Cluster.REVOKE_IMPORT
        self.assertIn("revoke.commit(n, d['full'], node.Trail(n.path('sync-audit.jsonl'), 'sync'), shutdown=d.get('shutdown'))", code)


if __name__ == "__main__":
    unittest.main()
