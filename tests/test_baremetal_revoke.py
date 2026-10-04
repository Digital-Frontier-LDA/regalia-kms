"""A restrictive change without the root (#199 step 4b, deploy/baremetal/revoke.py and owner.sign_manifest): two nodes,
each confirmed at its own console, or the owner alone off the nodes; membership's quorum rules decide, before any
signature and again at the commit into a real Store."""
import os
import shutil
import tempfile
import unittest

from deploy.baremetal import membership as m
from deploy.baremetal import owner, revoke
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import ROOT, ROOT_PUB, sign
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, STRANGER, manifest4, nodes4, p256_sig, pub
from tests.test_baremetal_owner import OwnerKey

T0 = 1790000000


def signer_of(node_id):
    return lambda message: p256_sig(NODE_KEYS[node_id], message)


class Revoke(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.m1 = manifest4(1, "", nodes4())
        self.typed = None

    def confirm(self, text):
        self.shown = text
        return self.typed

    def type_for(self, manifest):
        _, digest = revoke.shown(self.m1, manifest)
        self.typed = "%d %s" % (manifest["epoch"], digest[:8])

    def half(self, target="c", state="QUARANTINED", by="a"):
        nxt = revoke.candidate(self.m1, target, state, T0)
        return {"manifest": nxt, "reason": "seen on the wrong network",
                "signatures": [dict(revoke.node_signature(by, signer_of(by), nxt), key=pub(NODE_KEYS[by]))]}

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_the_candidate_is_the_next_manifest_with_one_node_restricted(self):
        nxt = revoke.candidate(self.m1, "c", "REVOKED_STOLEN", T0)
        self.assertEqual((nxt["epoch"], nxt["prev_digest"], [n["state"] for n in nxt["nodes"]]),
                         (2, m.digest(self.m1), ["ACTIVE", "ACTIVE", "REVOKED_STOLEN"]))
        self.refused("anything else is the root's", revoke.candidate, self.m1, "c", "ACTIVE", T0)
        self.refused("x is not in the manifest", revoke.candidate, self.m1, "x", "QUARANTINED", T0)
        quarantined = manifest4(1, "", nodes4(c="QUARANTINED"))
        self.refused("c is already QUARANTINED", revoke.candidate, quarantined, "c", "QUARANTINED", T0)
        self.refused("needs a regalia.membership/v4 manifest", revoke.candidate, dict(self.m1, schema=m.SCHEMA_V3), "c", "QUARANTINED", T0)

    def test_two_nodes_each_at_its_console_revoke_and_a_store_commits_it(self):
        half = self.half()
        enough, parties = revoke.met(self.m1, {"manifest": half["manifest"], "signatures": half["signatures"]})
        self.assertEqual((enough, parties), (False, {"a"}), "one node alone met a rule")
        self.type_for(half["manifest"])
        full = revoke.cosign(self.m1, half, "b", pub(NODE_KEYS["b"]), signer_of("b"), self.confirm)
        self.assertIn("c: ACTIVE -> QUARANTINED", self.shown)
        self.assertIn("seen on the wrong network", self.shown)
        envelope = {"manifest": full["manifest"], "signatures": full["signatures"]}
        self.assertEqual(revoke.met(self.m1, envelope), (True, {"a", "b"}))
        # the store takes it, as every node's will when it pulls it
        hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=FakeTpm())
        hw.define()
        store = m.Store(self.d + "/membership.json", ROOT_PUB, hw)
        store.commit(sign(self.m1, ROOT))
        self.assertEqual(store.commit(envelope)["epoch"], 2)
        self.assertEqual(store.load()["nodes"][2]["state"], "QUARANTINED")

    def test_the_second_node_signs_nothing_it_did_not_confirm_or_should_not(self):
        half = self.half()
        signed = []

        def counting(message):
            signed.append(message)
            return signer_of("b")(message)
        for typed in (None, "2", "3 %s" % revoke.shown(self.m1, half["manifest"])[1][:8], "2 00000000"):
            with self.subTest(typed=typed):
                self.typed = typed
                self.refused("are not this revocation's: nothing is signed", revoke.cosign, self.m1, half, "b", pub(NODE_KEYS["b"]), counting, self.confirm)
        self.type_for(half["manifest"])
        self.refused("a has signed this revocation already", revoke.cosign, self.m1, half, "a", pub(NODE_KEYS["a"]), signer_of("a"), self.confirm)
        forged = dict(half, signatures=[dict(half["signatures"][0], sig=p256_sig(NODE_KEYS["a"], b"another message"))])
        self.refused("does not verify", revoke.cosign, self.m1, forged, "b", pub(NODE_KEYS["b"]), counting, self.confirm)
        # a node that no longer counts (b quarantined at the current epoch) signs nothing
        b_out = manifest4(1, "", nodes4(b="QUARANTINED"))
        self.refused("b does not count toward any revocation rule", revoke.cosign, b_out, half, "b", pub(NODE_KEYS["b"]), counting, self.confirm)
        # a revocation for another epoch than this node's next
        later = manifest4(2, m.digest(self.m1), nodes4())
        self.refused("CONFLICT: a different manifest at epoch 2", revoke.cosign, later, half, "b", pub(NODE_KEYS["b"]), counting, self.confirm)
        self.assertEqual(signed, [])

    def test_the_owner_alone_off_the_nodes(self):
        nxt = revoke.candidate(self.m1, "b", "REVOKED_STOLEN", T0)
        proposal = {"manifest": nxt, "signatures": [], "reason": "laptop bag stolen"}
        self.type_for(nxt)
        key = OwnerKey(OWNER_KEYS[2])
        envelope = owner.sign_manifest(self.m1, proposal, lambda: key, self.confirm, say=lambda text: None)
        self.assertEqual(revoke.met(self.m1, {"manifest": nxt, "signatures": envelope["signatures"]}), (True, {m.OWNER}))
        self.assertEqual(m.accept(self.m1, {"manifest": nxt, "signatures": envelope["signatures"]}, ROOT_PUB)["epoch"], 2)
        # a key that is not the owner's, a proposal already signed, and anything permissive: nothing signed
        stranger = OwnerKey(STRANGER)
        self.refused("is not one of the manifest's owner_keys", owner.sign_manifest, self.m1, proposal, lambda: stranger, self.confirm)
        self.refused("not an unsigned revocation proposal", owner.sign_manifest, self.m1, dict(proposal, signatures=envelope["signatures"]),
                     lambda: key, self.confirm)
        quarantined = manifest4(1, "", nodes4(c="QUARANTINED"))
        restore = dict(quarantined, epoch=2, prev_digest=m.digest(quarantined), nodes=nodes4())
        self.refused("widens capabilities; only the root can do that", owner.sign_manifest, quarantined,
                     {"manifest": restore, "signatures": [], "reason": "back"}, lambda: key, self.confirm)
        self.assertEqual((len(key.signed), stranger.signed), (1, []))


if __name__ == "__main__":
    unittest.main()
