"""regalia-node enrol commit's anchor step (#190): the membership epoch anchor and the heartbeat counter
defined, and the store committed with the whole chain, so the anchor stands at its last epoch; resumed, it
takes over nothing it cannot prove is this chain's. On the fake TPM of the node tests (the swtpm-backed
membership tests cover HighWater itself)."""
import copy
import json
import os

from deploy.baremetal import enrol, measurements
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import node as node_module
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_node as nt
import tests.test_baremetal_replacement as rt

# the measurements the chain commits to: in the node's store before the anchor step (commit puts it there, #332)
DOC = {"schema": measurements.SCHEMA, "name": "anchor-tests",
       "nodes": {n: {"accepted": [{"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}]} for n in "abc"}}
P1 = measurements.version(DOC)


def committing(man):
    return dict(man, policy_version=P1)


class Anchor(nt.Case):
    def setUp(self):
        super().setUp()
        self.path = self.d + "/etc/node.json"
        with open(self.path, "w") as f:
            json.dump(self.cfg, f)
        enrol.store_documents(self.cfg["state_dir"], DOC, chown=False)

    def chain(self, n):
        envs, prev = [], None
        for epoch in range(1, n + 1):
            man = committing(hbt.manifest(epoch, m.digest(prev) if prev else ""))
            envs.append(rt.sign(man))
            prev = man
        return envs

    def anchor(self, chain):
        return enrol.anchor_and_store(self.path, chain, run=self.tpm)

    def test_a_fresh_enrolment_anchors_the_chain_at_its_last_epoch(self):
        chain = self.chain(3)
        epoch, digest = self.anchor(chain)
        self.assertEqual((epoch, digest), (3, m.digest(chain[-1]["manifest"])))
        node = self.node()
        self.assertEqual(node.anchor().value(), 3)
        self.assertEqual(node.anchor().record(), (3, digest))
        self.assertEqual(node.store().load()["epoch"], 3)
        counter = node.freshness().counter
        self.assertNotEqual(counter._tpm("nvreadpublic", counter.index).returncode, 0, "the counter is the heartbeat step's")
        # again, as a resumed run: nothing changes
        self.assertEqual(self.anchor(chain), (3, digest))
        self.assertEqual(node.anchor().value(), 3)

    def late_chain(self):
        """epoch 1 without this node, epoch 2 (root-signed) adding it: a node joining a running network."""
        me = self.cfg["node_id"]
        first = committing(hbt.manifest())
        first["nodes"] = [n for n in first["nodes"] if n["node_id"] != me]
        second = dict(copy.deepcopy(first), epoch=2, prev_digest=m.digest(first))
        second["nodes"] = [hbt.node(me, "ACTIVE", 0)] + second["nodes"]
        return [rt.sign(first), rt.sign(second)]

    def test_no_node_gets_a_counter_from_the_anchor_step(self):
        """#190, d9's read: whatever epoch first names it, its counter is defined by the first-heartbeat step."""
        for chain in (self.late_chain(), ):
            self.anchor(chain)
            counter = self.node().freshness().counter
            self.assertNotEqual(counter._tpm("nvreadpublic", counter.index).returncode, 0)

    def test_a_longer_chain_continues_a_shorter_enrolment(self):
        chain = self.chain(3)
        self.anchor(chain[:1])
        self.assertEqual(self.anchor(chain)[0], 3)

    def test_a_store_of_another_chain_is_refused_and_left(self):
        self.anchor(self.chain(1))
        other = hbt.manifest()
        other["policy_version"] = "p2"
        with self.assertRaisesRegex(enrol.Refused, "not the beginning of this one"):
            self.anchor([rt.sign(other)])
        self.assertEqual(self.node().store().load()["policy_version"], P1)

    def test_indices_without_a_store_are_taken_only_as_define_leaves_them(self):
        node = self.node()
        node.anchor().define()                      # an enrolment stopped before its first commit
        self.assertEqual(self.anchor(self.chain(2))[0], 2)
        # ... but an anchor that has moved, with no store, is somebody else's
        os.unlink(node.path("membership.json"))
        with self.assertRaisesRegex(enrol.Refused, "not an enrolment stopped before its first commit"):
            self.anchor(self.chain(2))
        self.assertEqual(node.anchor().value(), 2)

    def test_the_signing_counter_is_defined_at_zero_and_taken_only_as_left(self):
        """#199: enrolment defines the node's signing counter at 0; a resumed run takes it as it left it; a signing counter
        someone else moved is refused before the first write."""
        node = self.node()
        self.anchor(self.chain(2))
        signing = node_module.signing_counter(node.cfg, node.run)
        self.assertEqual(signing.value(), 0)
        self.assertEqual(self.anchor(self.chain(2))[0], 2)                       # resumed: left as it is
        self.assertEqual(signing.value(), 0)
        # another enrolment's TPM where the signing counter moved: refused, nothing written
        self.setUp()
        node = self.node()
        moved = hb.Counter(node.cfg["nv_signing"], node.tcti, node.run, lock_path=node.path("other.lock"))
        moved.define()
        moved.advance(3)
        with self.assertRaisesRegex(enrol.Refused, "the signing counter's indices"):
            self.anchor(self.chain(1))
        self.assertFalse(os.path.exists(node.path("membership.json")))

    def test_the_activation_counter_is_defined_at_zero_and_taken_only_as_left(self):
        """#432: enrolment defines the node's activation counter at 0 as it does the signing counter; one someone else moved
        is refused before the first write."""
        node = self.node()
        self.anchor(self.chain(2))
        activation = node_module.activation_counter(node.cfg, node.run)
        self.assertEqual(activation.value(), 0)
        self.assertEqual(self.anchor(self.chain(2))[0], 2)                       # resumed: left as it is
        self.assertEqual(activation.value(), 0)
        self.setUp()
        node = self.node()
        moved = hb.Counter(node.cfg["nv_activation"], node.tcti, node.run, lock_path=node.path("other.lock"))
        moved.define()
        moved.advance(2)
        with self.assertRaisesRegex(enrol.Refused, "the activation counter's indices"):
            self.anchor(self.chain(1))
        self.assertFalse(os.path.exists(node.path("membership.json")))

    def test_a_heartbeat_counter_already_moved_is_refused(self):
        node = self.node()
        held = node.freshness().counter
        # someone else's counter at the node's index: laid down as any tool would, not by the node's definer
        counter = hb.Counter(held.index, node.tcti, node.run, lock_path=held.lock_path)
        counter.define()
        counter.advance(5)
        with self.assertRaisesRegex(enrol.Refused, "heartbeat counter"):
            self.anchor(self.chain(1))
        # refused before the first write: no anchor defined, no store committed (CodeRabbit on #256)
        self.assertFalse(os.path.exists(node.path("membership.json")))
        hw = node.anchor()
        self.assertEqual([i for i in hw._indices() if hw._tpm("nvreadpublic", i).returncode == 0], [])


if __name__ == "__main__":
    import unittest
    unittest.main()


class Documents(Anchor):
    def test_the_anchor_step_needs_the_last_epochs_measurements_and_moves_nothing_without_them(self):
        """#332: the chain's last epoch commits to a document the store does not hold: refused before the store is
        written or the anchor is defined (#242: the definer's policy comes from that document, so the refusal comes
        before the first write)."""
        chain = self.chain(2)
        other = dict(DOC, name="anchor-tests-2")
        last = dict(chain[1]["manifest"], policy_version=measurements.version(other))
        chain = [chain[0], rt.sign(last)]
        with self.assertRaisesRegex(m.Refused, "epoch 2 commits to measurements %s, which this node does not hold" % measurements.version(other)):
            self.anchor(chain)
        hw = self.node().anchor()                                        # nothing written: no anchor index, no store
        self.assertEqual([i for i in hw._indices() if hw._tpm("nvreadpublic", i).returncode == 0], [])
        self.assertFalse(os.path.exists(self.node().path("membership.json")))
        enrol.store_documents(self.cfg["state_dir"], other, chown=False)
        self.assertEqual(self.anchor(chain)[0], 2)
