"""deploy/baremetal/deliver.py (#199): signed manifests given to one running node, now that no authority host takes the
root's epochs: committed in order through the node's own Store (membership's rules decide), its documents put by digest,
the chain republished, one trail event; nothing it holds already, and nothing the Store refuses."""
import json
import os
import shutil
import tempfile
import unittest

from deploy.baremetal import deliver, measurements, membership as m, node
import tests.test_baremetal_heartbeat as hbt
from tests.test_baremetal_membership import ROOT, ROOT_PUB, sign, manifest, three


class FakeNode:
    def __init__(self, d):
        self.d = d
        self.hw = m.HighWater("0x1500016", lock_path=d + "/hw.lock", run=hbt.FakeTpm())
        self.hw.define()

    def store(self):
        return m.Store(self.d + "/membership.json", ROOT_PUB, self.hw)

    def documents(self):
        return measurements.Documents(self.d + "/" + measurements.STORE_DIR)

    def path(self, name):
        return os.path.join(self.d, name)


class Deliver(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.node, self.events = FakeNode(self.d), []
        self.m1 = manifest(1, "", three())
        self.e1 = sign(self.m1, ROOT)
        self.node.store().commit(self.e1)
        self.m2 = manifest(2, m.digest(self.m1), three())
        self.e2 = sign(self.m2, ROOT)
        self.m3 = manifest(3, m.digest(self.m2), three())
        self.e3 = sign(self.m3, ROOT)

    def test_the_newer_epochs_of_a_chain_are_committed_in_order_and_published(self):
        self.assertEqual(deliver.deliver(self.node, [self.e1, self.e2, self.e3], [], self.events.append), 3)
        self.assertEqual(self.node.store().load()["epoch"], 3)
        with open(self.node.path(node.PUBLISHED)) as f:
            self.assertEqual([e["manifest"]["epoch"] for e in json.load(f)], [1, 2, 3])
        self.assertEqual((self.events[-1]["event"], self.events[-1]["outcome"], self.events[-1]["epoch"]), ("deliver", "ALLOW", 3))

    def test_nothing_newer_and_what_the_store_refuses_are_refused_and_recorded(self):
        with self.assertRaisesRegex(m.Refused, "holds epoch 1 already"):
            deliver.deliver(self.node, [self.e1], [], self.events.append)
        forged = dict(self.e2, signature=dict(self.e2["signature"], sig=sign(self.m3, ROOT)["signature"]["sig"]))
        with self.assertRaises(m.Refused):
            deliver.deliver(self.node, [forged], [], self.events.append)
        self.assertEqual(self.node.store().load()["epoch"], 1)
        self.assertEqual([e["outcome"] for e in self.events], ["DENY", "DENY"])
        with self.assertRaisesRegex(m.Refused, "non-empty list"):
            deliver.deliver(self.node, [], [], self.events.append)


if __name__ == "__main__":
    unittest.main()
