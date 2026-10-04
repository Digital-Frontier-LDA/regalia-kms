"""The owner's co-signature of a heartbeat for a hand recovery (#199 step 4a, deploy/baremetal/owner.py): proposed and
signed by the node as regalia-sync, shown and confirmed before the owner's key signs, and taken into the node's
Freshness under the owner's one-hour cap. Each node is beat's test node (a fake TPM and a software signing key); the
owner's key is a software Ed25519 key standing in for the YubiKey (Pkcs11Signer's Ed25519 path is tested against
SoftHSM in test_baremetal_authority)."""
import unittest

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from deploy.baremetal import owner
from tests.test_baremetal_beat import Case
from tests.test_baremetal_membership_v4 import OWNER_KEYS, STRANGER, manifest4, nodes4, pub


class FakeStore:
    def __init__(self, case):
        self.case = case

    def load(self):
        return self.case.man


class FakeNode:
    """What owner.propose and owner.accept use of a node.Node."""

    def __init__(self, case, node_id):
        self.case, self.node_id, self.parts = case, node_id, case.nodes[node_id]

    def store(self):
        return FakeStore(self.case)

    def freshness(self):
        return self.parts.freshness

    def clock(self):
        return self.case.clock


class OwnerKey:
    """A stand-in for authority.Pkcs11Signer(alg="ed25519"): public() needs no PIN; every sign() is counted."""

    def __init__(self, key):
        self.key, self.signed = key, []

    def public(self):
        return pub(self.key)

    def sign(self, message):
        self.signed.append(message)
        return self.key.sign(message)


class Owner(Case):
    def setUp(self):
        super().setUp()
        self.a = FakeNode(self, "a")
        self.key = OwnerKey(OWNER_KEYS[1])
        self.typed, self.said = None, []

    def confirm(self, text):
        self.said.append(text)
        return self.typed

    def proposed(self):
        return owner.propose(self.a, self.nodes["a"].signer, self.events.append)

    def test_a_node_opened_by_hand_and_the_owner_make_a_heartbeat_for_an_hour(self):
        proposal = self.proposed()
        body = proposal["heartbeat"]
        self.assertEqual((body["sequence"], hb.parse_time(body["expires_at"], "e") - hb.parse_time(body["issued_at"], "i")), (1, 3600))
        _, digest = owner.shown(body)
        self.typed = "%d %s" % (body["epoch"], digest[:8].upper())
        envelope = owner.owner_sign(proposal, self.man, lambda: self.key, self.confirm, say=self.said.append)
        self.assertIn("SHA-256 %s" % digest, self.said[0])
        self.assertEqual([s["party"] for s in envelope["signatures"]], ["a", m.OWNER])
        self.assertEqual(owner.accept(self.a, envelope, self.events.append), 3600)
        self.assertEqual(self.nodes["a"].freshness.held(), envelope)
        # the other two take it from a by pull, as any heartbeat
        for n in ("b", "c"):
            self.nodes[n].freshness.accept(envelope, self.man)
        self.assertEqual([(e["event"], e["outcome"]) for e in self.events], [("owner-beat-propose", "ALLOW"), ("owner-beat", "ALLOW")])

    def test_nothing_is_signed_unless_the_operator_typed_this_heartbeat(self):
        proposal = self.proposed()
        body = proposal["heartbeat"]
        _, digest = owner.shown(body)
        for typed in (None, "", "%d" % body["epoch"], "%d %s" % (body["epoch"] + 1, digest[:8]), "%d %s" % (body["epoch"], digest[1:9]),
                      "%d %s" % (body["epoch"], digest[:7]), "%d %s extra" % (body["epoch"], digest[:8])):
            with self.subTest(typed=typed):
                self.typed = typed
                self.refused("are not this heartbeat's: nothing is signed", owner.owner_sign, proposal, self.man, lambda: self.key, self.confirm)
        self.assertEqual(self.key.signed, [])

    def test_a_key_that_is_not_the_owners_is_refused_before_anything_is_shown(self):
        proposal = self.proposed()
        stranger = OwnerKey(STRANGER)
        self.refused("is not one of the manifest's owner_keys: nothing is signed", owner.owner_sign, proposal, self.man, lambda: stranger, self.confirm)
        self.assertEqual((self.said, stranger.signed), ([], []))
        later = manifest4(2, m.digest(self.man), nodes4())
        self.refused("is not for this node's current manifest (epoch 2)", owner.owner_sign, proposal, later, lambda: self.key, self.confirm)

    def test_the_node_takes_only_its_own_proposal_with_the_owner_and_never_beyond_the_hour(self):
        proposal = self.proposed()
        body = proposal["heartbeat"]
        sig = {"party": m.OWNER, "key": self.key.public(), "sig": self.key.key.sign(hb.DOMAIN + m.canonical(body)).hex()}
        for reason, signatures in (("in that order", [sig] + proposal["signatures"]), ("in that order", proposal["signatures"])):
            with self.subTest(reason):
                self.refused(reason, owner.accept, self.a, dict(proposal, signatures=signatures), self.events.append)
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        # a six-hour body with the owner's signature: the cap is heartbeat.verify's, whatever was proposed
        long = dict(body, sequence=2, expires_at=owner.beat.stamp(hb.parse_time(body["issued_at"], "i") + 21600))
        mine = self.nodes["a"].signer(long, self.man)
        theirs = {"party": m.OWNER, "key": self.key.public(), "sig": self.key.key.sign(hb.DOMAIN + m.canonical(long)).hex()}
        self.refused("a heartbeat the owner signed lives at most 3600 s", owner.accept, self.a, {"heartbeat": long, "signatures": [mine, theirs]},
                     self.events.append)
        self.assertIsNone(self.nodes["a"].freshness.held())

    def test_only_a_counting_node_under_v4_proposes(self):
        self.man = manifest4(1, "", nodes4(a="QUARANTINED"))
        self.refused("a does not count toward heartbeat_signers", self.proposed)
        self.man = dict(self.man, schema=m.SCHEMA)
        self.refused("only under a regalia.membership/v4 manifest", self.proposed)
        self.assertEqual(self.nodes["a"].signing.value(), 0)


if __name__ == "__main__":
    unittest.main()
