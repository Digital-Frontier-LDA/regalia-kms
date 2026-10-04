"""Heartbeats signed by the nodes (#199 step 3, deploy/baremetal/beat.py): a node signs a number once (its signing
counter first), co-signs only what it would itself accept, and the nodes take turns at proposing by rank. Each node
here has its own fake TPM (its heartbeat counter and its signing counter) and a software P-256 signing key."""
import json
import os
import shutil
import tempfile
import unittest

from deploy.baremetal import beat, sync
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, manifest4, nodes4, p256_sig, pub

T0 = hbt.T0


class Parts:
    """One node: its fake TPM, heartbeat counter and Freshness, signing counter and Signer."""

    def __init__(self, case, node_id):
        self.case, self.node_id = case, node_id
        tpm = hbt.FakeTpm()
        self.counter = hb.Counter("0x1500018", lock_path="%s/%s-hb.lock" % (case.d, node_id), run=tpm)
        self.counter.define()
        self.signing = hb.Counter("0x150001c", lock_path="%s/%s-sign.lock" % (case.d, node_id), run=tpm)
        self.signing.define()
        self.freshness = hb.Freshness(self.counter, case.clock, case.ticks, "%s/%s-freshness.json" % (case.d, node_id))
        self.signs = []                     # every message this node's key was asked to sign

        def sign(message):
            if case.sign_fails.get(node_id):
                raise m.Refused("tpm2_sign failed")
            self.signs.append(message)
            return p256_sig(NODE_KEYS[node_id], message)
        self.signer = beat.Signer(node_id, self.signing, sign, pub(NODE_KEYS[node_id]))

    def cosign(self, manifest, caller, body, signature):
        return beat.cosign(manifest, self.node_id, caller, body, signature, self.freshness, self.case.clock, self.signer)


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.now, self.authenticated, self.sign_fails = T0, True, {}
        self.man = manifest4(1, "", nodes4())
        self.nodes = {n: Parts(self, n) for n in ("a", "b", "c")}
        self.events = []

    def clock(self):
        return self.now, self.authenticated

    def ticks(self):
        return int((self.now - T0) * 1000) + 5000

    def body(self, sequence=1, issued=None, lifetime=21600, man=None, **change):
        man = man or self.man
        issued = self.now if issued is None else issued
        out = {"schema": hb.SCHEMA, "epoch": man["epoch"], "sequence": sequence, "issued_at": beat.stamp(issued),
               "expires_at": beat.stamp(issued + lifetime), "manifest_digest": m.digest(man)}
        out.update(change)
        return out

    def proposal(self, proposer, body):
        return {"party": proposer, "key": pub(NODE_KEYS[proposer]), "sig": p256_sig(NODE_KEYS[proposer], hb.DOMAIN + m.canonical(body))}

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Cosign(Case):
    def test_a_proposal_co_signed_is_a_heartbeat_every_node_accepts(self):
        body = self.body()
        theirs = self.nodes["b"].cosign(self.man, "a", body, self.proposal("a", body))
        envelope = {"heartbeat": body, "signatures": [self.proposal("a", body), theirs]}
        self.assertEqual(hb.verify(envelope, self.man), body)
        self.assertEqual(self.nodes["b"].signing.value(), 1)
        self.assertEqual(self.nodes["b"].counter.value(), 0, "co-signing moved the heartbeat counter: the heartbeat would be a replay to b")
        for n in ("a", "b", "c"):
            self.nodes[n].freshness.accept(envelope, self.man)

    def test_a_number_is_signed_once_and_reserved_before_the_signature(self):
        b, body = self.nodes["b"], self.body(sequence=5)
        b.cosign(self.man, "a", body, self.proposal("a", body))
        other = self.body(sequence=5, issued=self.now + 1)               # another body under the same number
        self.refused("is not above this node's signing counter 5: a number is signed once", b.cosign, self.man, "c", other, self.proposal("c", other))
        # a signature that fails after the number was reserved: the number is spent, never signed later
        self.sign_fails["b"] = True
        third = self.body(sequence=6)
        self.refused("tpm2_sign failed", b.cosign, self.man, "a", third, self.proposal("a", third))
        self.assertEqual(b.signing.value(), 6)
        self.sign_fails["b"] = False
        self.refused("a number is signed once", b.cosign, self.man, "a", third, self.proposal("a", third))
        self.assertEqual(len(b.signs), 1)

    def test_two_signers_racing_for_one_number_sign_it_once(self):
        """regalia-kms-1e's read: the counter's own lock decides, so two signatures at one number cannot both be made,
        whichever thread gets there first (the proposer and a beat-sign request, in one sync process)."""
        import threading
        b, results, start = self.nodes["b"], [], threading.Barrier(2)

        def sign(body):
            start.wait()
            try:
                results.append(b.signer(body, self.man))
            except m.Refused as refused:
                results.append(refused)
        threads = [threading.Thread(target=sign, args=(self.body(sequence=4, issued=self.now + i),)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(type(r).__name__ for r in results), ["Refused", "dict"])
        self.assertEqual((b.signing.value(), len(b.signs)), (4, 1))

    def test_only_what_it_would_itself_accept(self):
        b = self.nodes["b"]
        cases = [
            ("for another manifest (epoch 2", self.body(epoch=2), "a"),
            ("for another manifest (epoch 1, 0000000000000000...)", self.body(manifest_digest="00" * 32), "a"),
            ("lives 21601 s, more than the manifest's 21600 s", self.body(lifetime=21601), "a"),
            ("301 s from this node's authenticated time", self.body(issued=self.now + 301), "a"),
            ("-301 s from this node's authenticated time", self.body(issued=self.now - 301), "a"),
            ("sequence jump 1001 exceeds the bound 1000", self.body(sequence=1001), "a"),
        ]
        for reason, body, caller in cases:
            with self.subTest(reason):
                self.refused(reason, b.cosign, self.man, caller, body, self.proposal(caller, body))
        self.assertEqual(b.signing.value(), 0, "a refused proposal spent a number")
        # its own held heartbeat: nothing at or below it
        body = self.body(sequence=3)
        b.freshness.accept({"heartbeat": body, "signatures": [self.proposal("a", body), self.proposal("c", body)]}, self.man)
        again = self.body(sequence=3, issued=self.now + 2)
        self.refused("REPLAY: sequence 3 is not above this node's heartbeat counter 3", b.cosign, self.man, "a", again, self.proposal("a", again))

    def test_who_asks_and_who_signs(self):
        b, body = self.nodes["b"], self.body()
        self.refused("is not signed by c, who sent it", b.cosign, self.man, "c", body, self.proposal("a", body))
        forged = dict(self.proposal("a", body), sig=self.proposal("a", self.body(sequence=2))["sig"])
        self.refused("does not verify", b.cosign, self.man, "a", body, forged)
        self.refused("is not a's signing_key", b.cosign, self.man, "a", body, dict(self.proposal("a", body), key=pub(NODE_KEYS["c"])))
        quarantined = manifest4(1, "", nodes4(a="QUARANTINED"))
        qbody = self.body(man=quarantined)
        self.refused("a does not count toward heartbeat_signers", b.cosign, quarantined, "a", qbody, self.proposal("a", qbody))
        stolen = manifest4(1, "", nodes4(b="REVOKED_STOLEN"))
        sbody = self.body(man=stolen)
        self.refused("b does not count toward heartbeat_signers under epoch 1: it co-signs nothing", b.cosign, stolen, "a", sbody, self.proposal("a", sbody))
        self.authenticated = False
        self.refused("time is not authenticated", b.cosign, self.man, "a", body, self.proposal("a", body))
        self.assertEqual(b.signing.value(), 0)

    def test_a_signer_whose_key_the_manifest_does_not_name_reserves_nothing(self):
        b = self.nodes["b"]
        b.signer.key = pub(NODE_KEYS["c"])
        body = self.body()
        self.refused("this node's signing key is not the one the manifest at epoch 1 gives b", b.cosign, self.man, "a", body, self.proposal("a", body))
        self.assertEqual(b.signing.value(), 0)


class Proposing(Case):
    def setUp(self):
        super().setUp()
        self.down = set()
        self.proposers = {n: beat.Proposer(n, lambda: self.man, p.freshness, self.clock, p.signer, self.asker(n), self.events.append,
                                           rand=lambda: 0.0) for n, p in self.nodes.items()}

    def asker(self, proposer):
        def ask(peer, body, signature):
            if peer in self.down:
                raise m.Refused("%s did not answer (TimeoutError)" % peer)
            return self.nodes[peer].cosign(self.man, proposer, body, signature)
        return ask

    def spread(self, envelope):
        for n, p in self.nodes.items():
            if n not in self.down and p.freshness.held() != envelope:
                p.freshness.accept(envelope, self.man)

    def test_rank_decides_who_proposes_and_the_next_takes_over(self):
        # nothing held: the first rank goes at once, the others two and four minutes later
        self.assertEqual({n: p.due(self.man, self.now) for n, p in self.proposers.items()},
                         {"a": self.now, "b": self.now + 120, "c": self.now + 240})
        first = self.proposers["a"].step()
        self.assertEqual(first["heartbeat"]["sequence"], 1)
        self.assertEqual([s["party"] for s in first["signatures"]], ["a", "b"])
        self.assertIsNone(self.proposers["b"].step(), "b proposed although a just had")
        self.spread(first)
        # the next beat is a's, 900 s after the last issue
        self.now += 899
        self.assertIsNone(self.proposers["a"].step())
        self.now += 1
        second = self.proposers["a"].step()
        self.assertEqual(second["heartbeat"]["sequence"], 2)
        self.spread(second)
        # a goes down: b takes over two minutes after a's slot, and asks c
        self.down.add("a")
        self.now += 900
        self.assertIsNone(self.proposers["b"].step())
        self.now += 120
        third = self.proposers["b"].step()
        self.assertEqual((third["heartbeat"]["sequence"], [s["party"] for s in third["signatures"]]), (3, ["b", "c"]))
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")

    def test_one_node_alone_signs_nothing_and_backs_off(self):
        self.down |= {"b", "c"}
        self.assertIsNone(self.proposers["a"].step())
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertIn("no node co-signed sequence 1", self.events[-1]["reason"])
        self.assertIsNone(self.nodes["a"].freshness.held())
        # its number is spent; it tries again after 60 s, then 120 s
        self.assertEqual(self.nodes["a"].signing.value(), 1)
        self.now += 59
        self.assertIsNone(self.proposers["a"].step())
        self.assertEqual(len(self.events), 1)
        self.now += 1
        self.proposers["a"].step()
        self.assertEqual((len(self.events), self.nodes["a"].signing.value()), (2, 2))
        self.now += 119
        self.proposers["a"].step()
        self.assertEqual(len(self.events), 2)
        # b comes back: the next attempt is co-signed, above the numbers spent, and the jump is accepted
        self.down.discard("b")
        self.now += 1
        envelope = self.proposers["a"].step()
        self.assertEqual(envelope["heartbeat"]["sequence"], 3)
        self.spread(envelope)

    def test_a_new_epoch_is_beaten_at_once(self):
        first = self.proposers["a"].step()
        self.spread(first)
        self.now += 60
        # a revocation: c quarantined at epoch 2. a holds no heartbeat for it, so it proposes now, and c is not asked
        self.man = manifest4(2, m.digest(self.man), nodes4(c="QUARANTINED"))
        self.down.add("b")
        self.assertIsNone(self.proposers["a"].step())
        self.assertIn("no node co-signed sequence 2 (b: b did not answer (TimeoutError))", self.events[-1]["reason"])
        self.down.discard("b")
        self.now += 60
        envelope = self.proposers["a"].step()
        self.assertEqual((envelope["heartbeat"]["epoch"], envelope["heartbeat"]["sequence"]), (2, 3))

    def test_a_shorter_interval_scales_the_takeover_jitter_and_retry(self):
        fast = beat.Proposer("b", lambda: self.man, self.nodes["b"].freshness, self.clock, self.nodes["b"].signer, self.asker("b"),
                             self.events.append, interval=600, rand=lambda: 0.99)
        self.assertEqual((fast.scaled(beat.TAKEOVER_S), fast.scaled(beat.JITTER_S), fast.scaled(beat.RETRY_FIRST_S)), (80, 20, 40))
        self.assertEqual(fast.due(self.man, self.now), self.now + 80 + 19)        # rank 1, nothing held: one takeover, the jitter
        self.assertEqual(self.proposers["b"].scaled(beat.TAKEOVER_S), 120)

    def test_the_owner_never_proposes_and_a_node_not_counted_never_does(self):
        man = manifest4(1, "", nodes4(c="RETIRED"))
        self.assertEqual(beat.counting_nodes(man), ["a", "b"])
        self.assertIsNone(self.proposers["c"].due(man, self.now))
        self.assertNotIn(m.OWNER, beat.counting_nodes(self.man))
        self.assertEqual(len(OWNER_KEYS), 3)


class FakeStore:
    def __init__(self, manifest):
        self.manifest = manifest

    def load(self):
        return self.manifest

    def envelopes(self, after_epoch=0):
        return [{"manifest": self.manifest}][after_epoch:]


class OverSync(Case):
    """beat-sign through sync.Server and sync.Client: the tunnel names the caller, and the op has its own rate."""

    def test_beat_sign_over_the_wire(self):
        wg = {n["node_id"]: n["wg_service_pub"] for n in self.man["nodes"]}
        at = {"addr-" + k: v for k, v in wg.items()}
        b = self.nodes["b"]
        server = sync.Server("b", FakeStore(self.man), b.freshness, None, None, lambda man, source: at[source], self.events.append,
                             sync.Buckets(clock=lambda: 0.0), cosigner=b.cosign)
        client = sync.Client("a", FakeStore(self.man), self.nodes["a"].freshness, {"b": lambda raw: server.handle(raw, "addr-a")}, self.events.append)
        body = self.body()
        theirs = client.beat_sign("b", body, self.proposal("a", body))
        self.assertEqual(hb.verify({"heartbeat": body, "signatures": [self.proposal("a", body), theirs]}, self.man), body)
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")
        # c's tunnel sending a's proposal: refused by name
        mallory = sync.Client("c", FakeStore(self.man), self.nodes["c"].freshness, {"b": lambda raw: server.handle(raw, "addr-c")}, self.events.append)
        second = self.body(sequence=2)
        self.refused("not signed by c, who sent it", mallory.beat_sign, "b", second, self.proposal("a", second))
        # six a minute, then refused before the TPM is touched
        for i in range(3, 8):
            body = self.body(sequence=i)
            client.beat_sign("b", body, self.proposal("a", body))
        body = self.body(sequence=8)
        self.refused("RATE", client.beat_sign, "b", body, self.proposal("a", body))
        self.assertEqual(b.signing.value(), 7)
        # a node without a cosigner (a source that signs nothing) refuses
        plain = sync.Server("b", FakeStore(self.man), b.freshness, None, None, lambda man, source: at[source], self.events.append)
        lone = sync.Client("a", FakeStore(self.man), self.nodes["a"].freshness, {"b": lambda raw: plain.handle(raw, "addr-a")}, self.events.append)
        self.refused("co-signs no heartbeats", lone.beat_sign, "b", body, self.proposal("a", body))
        self.assertTrue(all(isinstance(json.dumps(e), str) for e in self.events))


if __name__ == "__main__":
    unittest.main()
