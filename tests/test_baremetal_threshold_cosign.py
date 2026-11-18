"""Threshold-driven co-signing (regalia-kms-dx7.4, docs/design/single-node.md 3.2 and 4.4): heartbeats, activation leases
and revocations collect threshold - 1 co-signatures from the manifest's own rule, never a literal one. Under the
single-node profile that is none: the node signs its own heartbeat and activation lease, and asks no one. A synthetic
threshold-3 rule makes every proposer collect two. Revoking the only node is a shutdown of the KMS: `revoke import`
says so, asks for a typed phrase, and the commit records it in the trail."""
import json
import os
import tempfile
import types
import unittest

from deploy.baremetal import activation as act
from deploy.baremetal import beat, heartbeat_watch, owner, revoke
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from tests.test_baremetal_activation import Counter
from tests.test_baremetal_beat import Case as BeatCase
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import POLICY, ROOT, ROOT_PUB, sign
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, manifest4, nodes4, p256_sig, pub
from tests.test_baremetal_membership_v5 import single5
from tests.test_baremetal_owner import OwnerKey
from tests.test_baremetal_revoke import PolicyWritten, signer_of

T0 = 1790000000
THREE = ["a", "b", "c"]


def nobody(*args):
    raise AssertionError("a single-node proposer asked a peer: %r" % (args[:1],))


class Heartbeats(BeatCase):
    def proposer(self, n, asked=None):
        def ask(peer, body, signature):
            if asked is not None:
                asked.append(peer)
            if peer in self.down:
                raise m.Refused("%s did not answer (TimeoutError)" % peer)
            return self.nodes[peer].cosign(self.man, n, body, signature)
        return beat.Proposer(n, lambda: self.man, self.nodes[n].freshness, self.clock, self.nodes[n].signer, ask, self.events.append,
                             rand=lambda: 0.0)

    def setUp(self):
        super().setUp()
        self.down = set()

    def test_single_node_signs_its_own_heartbeat_and_the_watch_stays_green(self):
        self.man = single5(1, "")
        self.assertEqual(beat.cosigners_needed(self.man), 0)
        a = self.nodes["a"]
        proposer = beat.Proposer("a", lambda: self.man, a.freshness, self.clock, a.signer, nobody, self.events.append, rand=lambda: 0.0)
        envelope = proposer.step()
        self.assertEqual(([s["party"] for s in envelope["signatures"]], envelope["heartbeat"]["sequence"]), (["a"], 1))
        self.assertEqual(a.freshness.held(), envelope)
        self.assertEqual((self.events[-1]["outcome"], self.events[-1]["cosigner"]), ("ALLOW", ""))
        # the watch reads it live, and warns of nothing
        reading = heartbeat_watch.reading(a.freshness, self.man)
        self.assertTrue(reading["live"], reading)
        self.assertEqual(heartbeat_watch.decide(reading, {}, self.now)[0], None)
        # and it keeps beating, one interval later, on its own counter
        self.now += beat.BEAT_INTERVAL_S
        self.assertEqual(proposer.step()["heartbeat"]["sequence"], 2)
        self.assertTrue(heartbeat_watch.reading(a.freshness, self.man)["live"])

    def test_three_nodes_still_take_exactly_one_co_signer(self):
        asked = []
        envelope = self.proposer("a", asked).step()
        self.assertEqual(([s["party"] for s in envelope["signatures"]], asked), (["a", "b"], ["b"]))

    def test_a_threshold_3_rule_collects_two_co_signatures(self):
        self.man = manifest4(1, "", nodes4(), heartbeat_signers={"threshold": 3, "parties": THREE + [m.OWNER]})
        m.validate(self.man)
        self.assertEqual(beat.cosigners_needed(self.man), 2)
        envelope = self.proposer("a").step()
        self.assertEqual([s["party"] for s in envelope["signatures"]], ["a", "b", "c"])
        self.assertEqual(self.events[-1]["cosigner"], "b,c")
        self.assertEqual(self.nodes["a"].freshness.held(), envelope)

    def test_a_threshold_3_rule_with_one_co_signer_is_refused_and_nothing_is_held(self):
        self.man = manifest4(1, "", nodes4(), heartbeat_signers={"threshold": 3, "parties": THREE + [m.OWNER]})
        self.down.add("c")
        self.assertIsNone(self.proposer("a").step())
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertIn("1 of the 2 co-signatures needed for sequence 1 (c: c did not answer", self.events[-1]["reason"])
        self.assertIsNone(self.nodes["a"].freshness.held())

    def test_a_co_signature_that_does_not_count_is_that_peer_s_refusal(self):
        def ask(peer, body, signature):
            sig = self.nodes[peer].cosign(self.man, "a", body, signature)
            return dict(sig, sig=p256_sig(NODE_KEYS[peer], b"another message")) if peer == "b" else sig
        a = self.nodes["a"]
        envelope = beat.Proposer("a", lambda: self.man, a.freshness, self.clock, a.signer, ask, self.events.append, rand=lambda: 0.0).step()
        self.assertEqual([s["party"] for s in envelope["signatures"]], ["a", "c"])


class Activation(unittest.TestCase):
    def node(self, name, counter=None, started=T0 - 3600):
        rec = act.GrantRecord(counter or Counter(), os.path.join(self.d, "%s-grant.json" % name), started)
        return act.Signer(name, rec, lambda raw, k=NODE_KEYS[name]: p256_sig(k, raw), pub(NODE_KEYS[name]))

    def clock(self, at=T0, authenticated=True):
        return lambda: (at, authenticated)

    def ask_from(self, signers, caller="a", asked=None, at=T0):
        def ask(peer, body):
            if asked is not None:
                asked.append(peer)
            return act.cosign(self.m3, peer, caller, body, self.clock(at), signers[peer], lambda: True)
        return ask

    def setUp(self):
        self.d = self.enterContext(tempfile.TemporaryDirectory())
        self.m1 = manifest4(1, "", nodes4())
        self.m3 = manifest4(1, "", nodes4(), activation_signers={"threshold": 3, "parties": list(THREE)})
        m.validate(self.m3)

    def test_single_node_signs_its_own_activation_lease(self):
        man = single5(1, "")
        self.assertEqual(act.cosigners_needed(man), 0)
        a, events = self.node("a"), []
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, man, self.clock(), a, nobody, ["b", "c"], events.append)
        self.assertEqual([s["party"] for s in env["signatures"]], ["a"])
        self.assertEqual(act.verify(env, man)["activation_epoch"], 1)

    def test_a_threshold_3_rule_collects_two_co_signatures(self):
        a, b, c = self.node("a"), self.node("b"), self.node("c")
        self.assertEqual(act.cosigners_needed(self.m3), 2)
        asked, events = [], []
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m3, self.clock(), a, self.ask_from({"b": b, "c": c}, asked=asked),
                          ["b", "c"], events.append)
        self.assertEqual(([s["party"] for s in env["signatures"]], asked), (["a", "b", "c"], ["b", "c"]))
        self.assertEqual(act.verify(env, self.m3)["activation_epoch"], 1)
        self.assertEqual((events[-1]["outcome"], events[-1]["peer"]), ("ALLOW", "b, c"))
        self.assertEqual((a.record.counter.v, b.record.counter.v, c.record.counter.v), (1, 1, 1))

    def test_a_threshold_3_rule_with_one_co_signer_signs_nothing_on_the_proposer(self):
        a, b = self.node("a"), self.node("b")
        events = []

        def ask(peer, body):
            if peer == "c":
                raise m.Refused("c did not answer")
            return self.ask_from({"b": b})(peer, body)
        with self.assertRaises(m.Refused) as caught:
            act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m3, self.clock(), a, ask, ["b", "c"], events.append)
        self.assertIn("c: c did not answer", str(caught.exception))
        self.assertEqual((events[-1]["outcome"], a.record.counter.v), ("DENY", 0))

    def test_a_co_signature_that_does_not_count_is_never_signed_on(self):
        a, b, c = self.node("a"), self.node("b"), self.node("c")
        good = self.ask_from({"b": b, "c": c})

        def ask(peer, body):
            sig = good(peer, body)
            return dict(sig, sig=p256_sig(NODE_KEYS["b"], b"another message")) if peer == "b" else sig
        with self.assertRaises(m.Refused):
            act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m3, self.clock(), a, ask, ["b", "c"], lambda e: None)
        self.assertEqual(a.record.counter.v, 0)             # the proposer recorded nothing on a co-signature that did not count

    def test_three_nodes_still_take_exactly_one_co_signer(self):
        a, b, c = self.node("a"), self.node("b"), self.node("c")
        self.assertEqual(act.cosigners_needed(self.m1), 1)
        asked = []

        def ask(peer, body):
            asked.append(peer)
            return act.cosign(self.m1, peer, "a", body, self.clock(), {"b": b, "c": c}[peer], lambda: True)
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, ask, ["b", "c"], lambda e: None)
        self.assertEqual(([s["party"] for s in env["signatures"]], asked), (["a", "b"], ["b"]))

    def test_each_other_node_is_asked_once_and_the_proposer_never(self):
        a, c = self.node("a"), self.node("c")
        asked = []

        def ask(peer, body):
            asked.append(peer)
            if peer != "c":
                raise m.Refused("%s did not answer" % peer)
            return act.cosign(self.m1, peer, "a", body, self.clock(), c, lambda: True)
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, ask, ["a", "b", "b", "c"], lambda e: None)
        self.assertEqual(([s["party"] for s in env["signatures"]], asked), (["a", "c"], ["b", "c"]))


class Revocation(unittest.TestCase):
    def setUp(self):
        self.d = self.enterContext(tempfile.TemporaryDirectory())
        self.typed = None

    def confirm(self, text):
        return self.typed

    def node_signed(self, current, nxt, *by):
        return {"manifest": nxt, "signatures": [dict(revoke.node_signature(n, signer_of(n), nxt), key=pub(NODE_KEYS[n])) for n in by]}

    def owner_signed(self, current, nxt):
        _, digest = revoke.shown(current, nxt)
        self.typed = "%d %s" % (nxt["epoch"], digest[:8])
        out = owner.sign_manifest(current, {"manifest": nxt, "signatures": [], "reason": "stolen"}, lambda: OwnerKey(OWNER_KEYS[2]),
                                  self.confirm, say=lambda text: None)
        return {"manifest": nxt, "signatures": out["signatures"]}

    def test_three_nodes_need_one_more_after_the_first(self):
        m1 = manifest4(1, "", nodes4())
        nxt = revoke.candidate(m1, "c", "QUARANTINED", T0)
        self.assertEqual(revoke.still_needed(m1, self.node_signed(m1, nxt, "a")), 1)
        self.assertEqual(revoke.still_needed(m1, self.node_signed(m1, nxt, "a", "b")), 0)

    def test_a_threshold_3_rule_needs_three_nodes(self):
        m3 = manifest4(1, "", nodes4(), revocation_signers=[{"threshold": 3, "parties": list(THREE)}, {"threshold": 1, "parties": [m.OWNER]}])
        m.validate(m3)
        nxt = revoke.candidate(m3, "c", "QUARANTINED", T0)
        self.assertEqual([revoke.still_needed(m3, self.node_signed(m3, nxt, *THREE[:k])) for k in (1, 2, 3)], [2, 1, 0])
        self.assertEqual(revoke.met(m3, self.node_signed(m3, nxt, "a", "b"))[0], False)
        # with c quarantined already, a and b alone can never meet it
        m3q = manifest4(1, "", nodes4(c="QUARANTINED"), revocation_signers=m3["revocation_signers"])
        self.assertIsNone(revoke.still_needed(m3q, self.node_signed(m3q, revoke.candidate(m3q, "b", "QUARANTINED", T0), "a")))

    def test_only_the_sole_node_s_revocation_is_a_shutdown(self):
        one = single5(1, "")
        for state in revoke.RESTRICTIVE:
            with self.subTest(state):
                self.assertEqual(revoke.shutdown_of(one, revoke.candidate(one, "a", state, T0)), "a")
        m1 = manifest4(1, "", nodes4())
        self.assertIsNone(revoke.shutdown_of(m1, revoke.candidate(m1, "c", "REVOKED_STOLEN", T0)))
        # under three nodes even the last live node's revocation is not this profile's shutdown (unchanged behaviour)
        last = manifest4(1, "", nodes4(b="RETIRED", c="RETIRED"))
        self.assertIsNone(revoke.shutdown_of(last, revoke.candidate(last, "a", "REVOKED_STOLEN", T0)))
        self.assertTrue(revoke.shutdown_said("a", "  shut down the KMS on a\n"))
        for typed in (None, "", "shut down the KMS", "shut down the KMS on b", "SHUT DOWN THE KMS ON A", "yes"):
            self.assertFalse(revoke.shutdown_said("a", typed), typed)

    def sole(self):
        one = single5(1, "")
        return one, self.owner_signed(one, revoke.candidate(one, "a", "REVOKED_STOLEN", T0))

    def test_import_says_it_is_a_shutdown_and_asks_for_the_phrase(self):
        one, envelope = self.sole()
        said, prompts, runs = [], [], []

        def run(argv, **kw):
            runs.append(json.loads(kw["input"]))
            return types.SimpleNamespace(returncode=0, stdout='{"epoch": 2}\n', stderr="")
        for typed in (None, "yes", "shut down the KMS on b"):
            with self.subTest(typed=typed):
                with self.assertRaises(m.Refused) as caught:
                    revoke.committed("/x/node.json", one, envelope, lambda p: (prompts.append(p), typed)[1], say=said.append, run=run)
                self.assertIn("nothing is committed", str(caught.exception))
        self.assertEqual(runs, [])
        self.assertIn("THIS IS A SHUTDOWN OF THE KMS", said[0])
        self.assertIn('"shut down the KMS on a"', prompts[0])
        epoch = revoke.committed("/x/node.json", one, envelope, lambda p: "shut down the KMS on a", say=said.append, run=run)
        self.assertEqual((epoch, runs[-1]["shutdown"], set(runs[-1])), (2, "shut down the KMS on a", {"manifest", "signatures", "shutdown"}))

    def test_a_revocation_that_is_no_shutdown_asks_nothing(self):
        m1 = manifest4(1, "", nodes4())
        envelope = self.owner_signed(m1, revoke.candidate(m1, "c", "REVOKED_STOLEN", T0))
        runs = []

        def run(argv, **kw):
            runs.append(json.loads(kw["input"]))
            return types.SimpleNamespace(returncode=0, stdout='{"epoch": 2}\n', stderr="")
        self.assertEqual(revoke.committed("/x/node.json", m1, envelope, nobody, say=nobody, run=run), 2)
        self.assertNotIn("shutdown", runs[-1])

    def store(self, first):
        hw = PolicyWritten("0x1500016", lock_path=self.d + "/hw.lock", run=FakeTpm(), define_policy=POLICY)
        hw.define()
        store = m.Store(self.d + "/membership.json", ROOT_PUB, hw)
        store.commit(sign(first, ROOT))
        return types.SimpleNamespace(store=lambda: store, path=lambda name: os.path.join(self.d, name)), store

    def test_the_commit_requires_the_phrase_and_records_it_in_the_trail(self):
        one, envelope = self.sole()
        node, store = self.store(one)
        trail = []
        for typed in (None, "shut down the KMS on b"):
            with self.subTest(typed=typed):
                with self.assertRaises(m.Refused) as caught:
                    revoke.commit(node, envelope, trail.append, typed)
                self.assertIn("is a shutdown of the KMS", str(caught.exception))
                self.assertEqual((trail[-1]["outcome"], store.load()["epoch"]), ("DENY", 1))
        nxt = revoke.commit(node, envelope, trail.append, "shut down the KMS on a")
        self.assertEqual((nxt["epoch"], nxt["nodes"][0]["state"]), (2, "REVOKED_STOLEN"))
        self.assertEqual((trail[-1]["outcome"], trail[-1]["shutdown"], trail[-1]["signers"]), ("ALLOW", "shut down the KMS on a", [m.OWNER]))


if __name__ == "__main__":
    unittest.main()
