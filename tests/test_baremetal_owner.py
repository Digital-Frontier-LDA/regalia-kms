"""The owner's co-signature of a heartbeat for a hand recovery (#199 step 4a, deploy/baremetal/owner.py): proposed and
signed by the node as regalia-sync, shown and confirmed before the owner's key signs, and taken into the node's
Freshness under the owner's one-hour cap. Each node is beat's test node (a fake TPM and a software signing key); the
owner's key is a software Ed25519 key standing in for the YubiKey (Pkcs11Signer's Ed25519 path is tested against
SoftHSM in test_baremetal_p11sign)."""
import contextlib
import hashlib
import json
import unittest
import unittest.mock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from deploy.baremetal import owner, recover, trails
from tests.test_baremetal_beat import Case
from tests.test_baremetal_membership_v4 import OWNER_KEYS, STRANGER, manifest4, nodes4, pub
from tests.test_baremetal_membership_v5 import MULTI, manifest5, single5


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
    """A stand-in for p11sign.Pkcs11Signer(alg="ed25519"): public() needs no PIN; every sign() is counted."""

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

    def test_a_rule_that_does_not_name_the_owner_is_refused_and_a_v5_rule_that_does_proposes(self):
        # decision Q2 (regalia-kms-dx7): a single-node node signs its own heartbeats, {1, [n]}; the owner's beat is refused
        self.man = single5(1, "", nodes4(b="RETIRED", c="RETIRED"))
        m.validate(self.man)   # a valid single-node manifest: the refusal below is the owner rule's, not the format's
        self.assertEqual(self.man["heartbeat_signers"], {"threshold": 1, "parties": ["a"]})
        self.refused("the owner co-signs heartbeats only when heartbeat_signers names the owner: under epoch 1", self.proposed)
        self.assertEqual(self.nodes["a"].signing.value(), 0)
        self.man = manifest5(1, "", nodes4(), MULTI)
        self.assertEqual(self.proposed()["heartbeat"]["sequence"], 1)


class SingleNodeRecovery(unittest.TestCase):
    """sign_recovery under a single-node tip (docs/design/single-node.md 4.7): the collector is mandatory,
    the statement is v2 with collector_epoch, and for recount also collector_sequence."""

    def setUp(self):
        import tests.test_baremetal_membership_v5 as v5
        from tests.test_baremetal_membership import ROOT, ROOT_PUB, sign
        import deploy.baremetal.membership as mm
        self.v5 = v5
        self.ROOT = ROOT
        self.ROOT_PUB = ROOT_PUB
        self._sign_fn = sign
        self.key = OwnerKey(OWNER_KEYS[0])
        # a single-node chain at epoch 3, root-signed, with the owner key in owner_keys
        self.chain = []
        cur = None
        for e in range(1, 4):
            man = v5.single5(e, mm.digest(cur) if cur else "")
            man["owner_keys"] = [{"alg": "ed25519", "key": pub(OWNER_KEYS[0])}]
            env = self._sign_fn(man, ROOT)
            cur = mm.accept(cur, env, ROOT_PUB)
            self.chain.append(env)
        self.record = [{"epoch": 1, "digest": mm.digest(self.chain[0]["manifest"]), "verified": True}]
        self.now = 1000
        self.issued = 1000
        self.typed = None
        self.said = []

    def confirm(self, text):
        self.said.append(text)
        return self.typed

    def do_sign(self, purpose="recover", witnesses=None, collector_sequence=None, counter_epoch=None):
        self.typed = None
        self.said = []
        from deploy.baremetal import recover
        tip = recover.verify_chain(self.chain, self.ROOT_PUB)
        want = "%s a 3 %s" % (purpose, m.digest(tip)[:8])
        # under single-node, the "no collector" suffix is absent
        self.typed = want
        if witnesses:
            mock_ctx = contextlib.ExitStack()
            mock_ctx.enter_context(
                unittest.mock.patch("deploy.baremetal.recover.witness_epoch", return_value=1))
            # witness_sequence is called for recount; for recover/reanchor it is not, so patch it
            # to a no-op that returns 0 so the test can pass an explicit collector_sequence
            mock_ctx.enter_context(
                unittest.mock.patch("deploy.baremetal.recover.witness_sequence", return_value=0))
        else:
            mock_ctx = contextlib.ExitStack()
            mock_ctx.enter_context(
                unittest.mock.patch("deploy.baremetal.recover.witness_epoch",
                                    side_effect=AssertionError("should not be called")))
            mock_ctx.enter_context(
                unittest.mock.patch("deploy.baremetal.recover.witness_sequence",
                                    side_effect=AssertionError("should not be called")))
        with mock_ctx:
            return owner.sign_recovery(self.chain, self.ROOT_PUB, self.record, purpose, "a", "s-1",
                                       lambda: self.key, self.confirm, self.now,
                                       witnesses=witnesses, counter_epoch=counter_epoch,
                                       say=self.said.append, issued=self.issued,
                                       collector_sequence=collector_sequence)

    def test_single_node_requires_witness(self):
        """Under single-node the collector is mandatory: no witness, no statement."""
        from deploy.baremetal import membership as mm
        self.assertRaisesRegex(mm.Refused, "audit collector is mandatory",
                               self.do_sign, "recover", witnesses=None)
        self.assertEqual(self.key.signed, [])

    def test_single_node_statement_has_collector_epoch(self):
        """Under single-node with a witness, the statement is v2 and carries collector_epoch."""
        from deploy.baremetal import recover
        signed = self.do_sign("recover", witnesses=[(None, None, None, None, None)])
        st = signed["statement"]
        self.assertIn("collector_epoch", st)
        self.assertEqual(st["collector_epoch"], 1)
        # v2 prefix
        msg = recover.message(st)
        self.assertIn(b"v2", msg)

    def test_single_node_recount_requires_collector_sequence(self):
        """A recount statement under single-node derives collector_sequence from the witness
        (the do_sign helper mocks witness_sequence to return 0, so the statement carries 0)."""
        from deploy.baremetal import recover
        signed = self.do_sign("recount", witnesses=[(None, None, None, None, None)], collector_sequence=None)
        st = signed["statement"]
        self.assertIn("collector_sequence", st)
        self.assertEqual(st["collector_sequence"], 0)
        raw = recover.message(st)
        self.assertTrue(raw.startswith(b"regalia-recount/v2\0"))

    def test_single_node_recount_with_collector_sequence(self):
        """A recount statement under single-node with a witness and collector_sequence is v2 with both fields."""
        from deploy.baremetal import recover
        signed = self.do_sign("recount", witnesses=[(None, None, None, None, None)], collector_sequence=42)
        st = signed["statement"]
        self.assertEqual(st["collector_epoch"], 1)
        self.assertEqual(st["collector_sequence"], 42)
        msg = recover.message(st)
        self.assertIn(b"v2", msg)

    def test_single_node_recount_derives_collector_sequence_from_the_witness(self):
        """A recount under single-node with no collector_sequence given derives it from the witness itself
        (recover.witness_sequence over the same exports the epoch came from), never from the operator
        (review defcc750, finding 2). A real collector receipt is verified, so the derivation is witnessed.

        The epoch is also derived from the same witness: witness_epoch returns the highest epoch ALLOW in
        the export. The export has epoch=3 for every beat-propose event, so witness_epoch returns 3.
        The statement must carry collector_epoch=3 and collector_sequence=7 (the highest sequence)."""
        from deploy.baremetal import recover
        T0 = 1790000000
        collector = Ed25519PrivateKey.generate()
        keys = [pub(collector)]
        out, chain = [], trails.LINE_CHAIN_START
        for i, sequence in enumerate((3, 1, 7)):
            line = json.dumps({"event": "beat-propose", "outcome": "ALLOW", "sequence": sequence,
                               "epoch": 3, "at": T0 + i}, sort_keys=True)
            raw = line.encode() + b"\n"
            out.append({"sequence": i + 1, "detail": {"line": line, "line_sha256": hashlib.sha256(raw).hexdigest()}})
            chain = trails.line_chain(chain, raw)
        preimage = ("%s\n%s\n%s\n%d\n%s\n%s\n%s" % (trails.RECEIPT_DOMAIN, "id" * 32, "site-a.sync", len(out),
                                                   "e" * 64, hashlib.sha256(raw).hexdigest(), chain)).encode()
        receipt = {"sequence": len(out), "event_hash": "e" * 64,
                   "line_sha256": hashlib.sha256(raw).hexdigest(), "line_chain": chain,
                   "signature": collector.sign(preimage).hex()}
        witness = (out, receipt, keys, "id" * 32, "site-a.sync")
        # witness_epoch and witness_sequence both run against the real receipt; no mocks
        from deploy.baremetal import recover
        tip = recover.verify_chain(self.chain, self.ROOT_PUB)
        self.typed = "recount a 3 %s" % m.digest(tip)[:8]
        signed = owner.sign_recovery(self.chain, self.ROOT_PUB, self.record, "recount", "a", "s-1",
                                     lambda: self.key, self.confirm, self.now,
                                     witnesses=[witness], counter_epoch=None,
                                     say=self.said.append, issued=self.issued,
                                     collector_sequence=None)
        st = signed["statement"]
        self.assertEqual(st["collector_epoch"], 3)
        self.assertEqual(st["collector_sequence"], 7)
        raw = recover.message(st)
        self.assertTrue(raw.startswith(b"regalia-recount/v2\0"))

    def test_multi_node_keeps_v1_and_no_collector_escape(self):
        """Under a multi-node tip, v1 statements are accepted and the 'no collector' escape works."""
        from tests.test_baremetal_membership import sign, ROOT, ROOT_PUB
        import deploy.baremetal.membership as mm
        import tests.test_baremetal_membership_v5 as v5
        # a multi-node chain at epoch 3
        chain = []
        cur = None
        for e in range(1, 4):
            man = v5.manifest5(e, mm.digest(cur) if cur else "", v5.nodes4())
            man["owner_keys"] = [{"alg": "ed25519", "key": pub(OWNER_KEYS[0])}]
            env = self._sign_fn(man, ROOT)
            cur = mm.accept(cur, env, ROOT_PUB)
            chain.append(env)
        record = [{"epoch": 1, "digest": mm.digest(chain[0]["manifest"]), "verified": True}]
        from deploy.baremetal import recover
        tip = recover.verify_chain(chain, ROOT_PUB)
        self.typed = "recover a 3 %s no collector" % m.digest(tip)[:8]
        signed = owner.sign_recovery(chain, ROOT_PUB, record, "recover", "a", "s-1",
                                     lambda: self.key, self.confirm, self.now,
                                     witnesses=None, say=self.said.append, issued=self.issued)
        st = signed["statement"]
        self.assertNotIn("collector_epoch", st)
        msg = recover.message(st)
        self.assertIn(b"v1", msg)


if __name__ == "__main__":
    unittest.main()
