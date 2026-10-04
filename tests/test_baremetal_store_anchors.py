"""membership.Store(anchors=False) (#66 B3, the ESP advance): the node's sync writes the chain to disk and never moves the
TPM anchor; the root ESP advance writes the boot chain to the ESP first, then anchors. Here: the store's side."""
import shutil
import tempfile
import unittest

from deploy.baremetal import membership as m
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import ROOT, ROOT_PUB, manifest, sign, three


def chain(n):
    """The signed envelopes of epochs 1..n, each chained to the one before."""
    envelopes, prev = [], ""
    for epoch in range(1, n + 1):
        man = manifest(epoch, prev, three(), policy="p%d" % epoch)
        envelopes.append(sign(man, ROOT))
        prev = m.digest(man)
    return envelopes


class SyncNeverMovesTheAnchor(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm)
        self.hw.define()
        self.chain = chain(4)
        # the node as enrolment leaves it: epoch 1 on disk and anchored
        m.Store(self.d + "/membership.json", ROOT_PUB, self.hw).commit(self.chain[0])
        self.assertEqual(self.hw.value(), 1)

    def store(self, anchors=False):
        return m.Store(self.d + "/membership.json", ROOT_PUB, self.hw, anchors=anchors)

    def test_commit_and_load_write_the_disk_only(self):
        sync = self.store()
        for envelope in self.chain[1:]:
            sync.commit(envelope)
        self.assertEqual(self.hw.value(), 1, "sync moved the TPM anchor")
        self.assertEqual(sync.load()["epoch"], 4)                    # a chain ahead of the anchor is read, not anchored
        self.assertEqual(self.hw.value(), 1)
        self.assertEqual([e["manifest"]["epoch"] for e in sync.envelopes(2)], [3, 4])
        self.assertEqual(self.hw.value(), 1)
        # what the ESP advance does once the ESP holds epoch 4: an anchoring store (or HighWater.anchor) moves it
        self.assertEqual(self.store(anchors=True).load()["epoch"], 4)
        self.assertEqual(self.hw.value(), 4)

    def test_a_rollback_and_a_substitution_are_refused_all_the_same(self):
        sync = self.store()
        sync.commit(self.chain[1])
        self.store(anchors=True).load()                              # anchored at 2
        with open(self.d + "/membership.json", "wb") as f:           # a restored disk: epoch 1 only
            f.write(m.canonical(self.chain[:1]))
        with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
            sync.load()
        other = chain(2)
        other[1] = sign(manifest(2, m.digest(other[0]["manifest"]), three(), policy="forked"), ROOT)
        with open(self.d + "/membership.json", "wb") as f:           # a substituted epoch 2 (the anchored one is recorded)
            f.write(m.canonical(other))
        with self.assertRaisesRegex(m.Refused, "CONFLICT"):
            sync.load()
        self.assertEqual(self.hw.value(), 2)

    def test_sync_never_runs_further_ahead_than_the_jump_bound(self):
        """The initrd and HighWater.advance() refuse a jump above MAX_JUMP: sync stops at it rather than leave a chain the
        ESP advance could never anchor."""
        self.hw.MAX_JUMP = 2
        sync = self.store()
        sync.commit(self.chain[1])
        sync.commit(self.chain[2])                                   # 3, two above the anchor at 1: the bound
        with self.assertRaisesRegex(m.Refused, "epoch 4 is 3 above the TPM high-water: the jump exceeds the bound 2"):
            sync.commit(self.chain[3])
        self.assertEqual((self.hw.value(), sync.load()["epoch"]), (1, 3))

    def test_restore_writes_the_disk_and_leaves_the_anchor(self):
        sync = self.store()
        self.assertEqual(sync.restore(self.chain[:3])["epoch"], 3)
        self.assertEqual(self.hw.value(), 1)

    def test_an_anchoring_store_is_unchanged(self):
        """The default (enrolment, the authority, reanchor, the ESP advance) still anchors on commit and on load."""
        anchoring = self.store(anchors=True)
        anchoring.commit(self.chain[1])
        self.assertEqual(self.hw.value(), 2)


if __name__ == "__main__":
    unittest.main()
