"""regalia-node enrol commit's anchor step (#190): the membership epoch anchor and the heartbeat counter
defined, and the store committed with the whole chain, so the anchor stands at its last epoch; resumed, it
takes over nothing it cannot prove is this chain's. On the fake TPM of the node tests (the swtpm-backed
membership tests cover HighWater itself)."""
import copy
import json
import os

from deploy.baremetal import enrol
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_node as nt
import tests.test_baremetal_replacement as rt


class Anchor(nt.Case):
    def setUp(self):
        super().setUp()
        self.path = self.d + "/etc/node.json"
        with open(self.path, "w") as f:
            json.dump(self.cfg, f)

    def chain(self, n):
        envs, prev = [], None
        for epoch in range(1, n + 1):
            man = hbt.manifest(epoch, m.digest(prev) if prev else "")
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
        self.assertEqual(node.freshness().counter.value(), 0)
        # again, as a resumed run: nothing changes
        self.assertEqual(self.anchor(chain), (3, digest))
        self.assertEqual(node.anchor().value(), 3)

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
        self.assertEqual(self.node().store().load()["policy_version"], "p1")

    def test_indices_without_a_store_are_taken_only_as_define_leaves_them(self):
        node = self.node()
        node.anchor().define()                      # an enrolment stopped before its first commit
        self.assertEqual(self.anchor(self.chain(2))[0], 2)
        # ... but an anchor that has moved, with no store, is somebody else's
        os.unlink(node.path("membership.json"))
        with self.assertRaisesRegex(enrol.Refused, "not an enrolment stopped before its first commit"):
            self.anchor(self.chain(2))
        self.assertEqual(node.anchor().value(), 2)

    def test_a_heartbeat_counter_already_moved_is_refused(self):
        node = self.node()
        counter = node.freshness().counter
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
