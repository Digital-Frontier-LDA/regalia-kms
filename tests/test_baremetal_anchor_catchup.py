"""#361 C4 on a software TPM: a node's catch-up. The measurements document's `rotations` for the node (K_A's single-use
increment approvals, one per retire) take its rotation counter R up to G_pub, in order; until R has, the node writes and
signs nothing (require_current). Refused, with R as it was: a missing entry, an entry for another node, and a node not
yet booted on an image approved at G_pub (local no-stranding)."""
import os
import shutil
import subprocess
import unittest

from deploy.baremetal import anchorpolicy as ap
from deploy.baremetal import membership as m
from tests.test_baremetal_anchor_approvals import K_A, POINT
import tests.test_baremetal_anchor_writes as aw     # the module: its test class is not run again here


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_policyauthorize") or os.environ.get("REGALIA_EXPECT_SWTPM") == "1",
                     "needs swtpm and tpm2-tools")
class CatchUp(unittest.TestCase):
    tpm = aw.CompositeSession.tpm
    approval = aw.CompositeSession.approval
    increment = aw.CompositeSession.increment

    def setUp(self):
        aw.CompositeSession.setUp(self)
        self.g = self.r["value"]

    def run_(self, argv, **kw):
        return subprocess.run(argv, env=self.env, **kw)

    def R(self):
        return ap.read_rotation(ap.ROTATION_INDEX, self.run_)

    def rotations(self, *froms, node_id="a"):
        return [{"from": n, "signature": ap.increment_document(K_A, POINT, node_id, n)["signature"]} for n in froms]

    def catch_up(self, rotations, booted):
        return ap.catch_up(ap.ROTATION_INDEX, POINT, "a", rotations, booted, self.run_)

    def test_a_node_offline_across_two_retires_catches_up_in_order(self):
        old = self.approval()
        self.assertEqual(self.increment(old).returncode, 0)
        rotations = self.rotations(self.g, self.g + 1)
        with self.assertRaisesRegex(m.Refused, r"rotation counter is %d, below the published %d: it bumps first" % (self.g, self.g + 2)):
            ap.require_current(ap.ROTATION_INDEX, "a", rotations, self.run_)
        self.assertEqual(self.catch_up(rotations, self.g + 2), self.g + 2)
        ap.require_current(ap.ROTATION_INDEX, "a", rotations, self.run_)
        with self.assertRaises(m.Refused):                    # G's approval no longer opens the anchor's index
            self.increment(old)
        self.assertEqual(self.increment(self.approval(generation=self.g + 2)).returncode, 0)
        self.assertEqual(self.catch_up(rotations, self.g + 2), self.g + 2)     # again: nothing to do, nothing replayed

    def test_a_missing_entry_bumps_nothing(self):
        with self.assertRaisesRegex(m.Refused, r"a's rotation counter is %d and the document's rotations start at %d: an entry is "
                                    r"missing, nothing is bumped" % (self.g, self.g + 1)):
            self.catch_up(self.rotations(self.g + 1), self.g + 2)
        self.assertEqual(self.R(), self.g)

    def test_a_node_not_booted_on_the_new_approvals_keeps_its_old_one(self):
        old = self.approval()
        with self.assertRaisesRegex(m.Refused, r"a is booted on an image whose approvals are at generation %d, below the published "
                                    r"%d: bumping would leave it no approval to write with" % (self.g, self.g + 1)):
            self.catch_up(self.rotations(self.g), self.g)
        self.assertEqual(self.R(), self.g)
        self.assertEqual(self.increment(old).returncode, 0)  # still writes on the approval it has

    def test_another_node_s_increment_is_refused_before_the_tpm(self):
        with self.assertRaisesRegex(m.Refused, r"K_A's approval of a's rotation counter from %d does not verify under the K_A it names" % self.g):
            self.catch_up(self.rotations(self.g, node_id="b"), self.g + 1)
        self.assertEqual(self.R(), self.g)

    def test_the_rotations_form(self):
        for name, rotations, reason in (("a gap", [{"from": 1, "signature": "00"}, {"from": 3, "signature": "00"}],
                                         r"rotations\[1\].from is 3, not 2: a retire moves R by exactly 1"),
                                        ("an extra field", [{"from": 1, "signature": "00", "at": 1}], r"rotations\[0\] is not \{from, signature\}"),
                                        ("not a list", {}, "rotations is not a list")):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, reason):
                ap.published(rotations)
        self.assertIsNone(ap.published([]))


if __name__ == "__main__":
    unittest.main()
