"""deploy/baremetal/convergence.py (#69, Phase 9): how a revoking manifest reaches every peer, and what each
peer decides before and after it has it. PoC 9.1-9.4 as decisions, with the bound for each case.

The transport is a function in this file (two nodes exchange summaries and envelopes); the real one is #80.
Fixtures are those of the replacement and lease tests; the last class runs catch-up on two software TPMs."""
import copy
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from deploy.baremetal import convergence, lease, replacement
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt
import tests.test_baremetal_replacement as rt

ROOT = hbt.pub(hbt.ROOT)


def exchange(receiver, sender):
    """The stand-in for one message from `sender` to `receiver` (a lease request, say): the summary rides
    along, and a receiver that is behind fetches and applies what it lacks. Returns where it stood."""
    standing = convergence.compare(receiver, convergence.summary(sender))
    if standing == "behind":
        convergence.catch_up(receiver, convergence.missing(sender, convergence.summary(receiver)))
    return standing


class Case(rt.Case):
    """a, b, c ACTIVE at epoch 1. b and c each hold the chain in a Store anchored to their own TPM counter,
    and a heartbeat for epoch 1. `authority` is the revocation authority's own copy of the chain."""

    def store(self, name):
        anchor = m.HighWater("0x1500016", lock_path=os.path.join(self.d, name + "-hw.lock"), run=hbt.FakeTpm())
        anchor.define()
        return m.Store(os.path.join(self.d, name + "-membership.json"), ROOT, anchor)

    def setUp(self):
        super().setUp()
        self.e1 = rt.sign(self.m1)
        self.stores = {name: self.store(name) for name in ("b", "c", "authority")}
        for store in self.stores.values():
            store.commit(self.e1)
        self.events = []

    def revoke(self, previous, state="REVOKED_STOLEN", node="a"):
        """The next manifest, signed by the REVOCATION key (no root ceremony), published by the authority."""
        nodes = [self.entry(n, state if n == node else next(x["state"] for x in previous["nodes"] if x["node_id"] == n)) for n in ("a", "b", "c")]
        envelope = rt.sign(self.chain(previous, nodes), hbt.REVOKE, "revocation")
        self.stores["authority"].commit(envelope)
        return envelope

    def heartbeat(self, manifest):
        self.sequence += 1
        return hbt.beat(manifest, self.sequence, issued=self.now)

    def publish(self, to):
        """The authority's bundle for one peer: what it lacks, and a heartbeat for the authority's manifest."""
        authority = self.stores["authority"]
        return convergence.apply_bundle(self.stores[to], self.peers[to]["freshness"],
                                        convergence.bundle(authority, convergence.summary(self.stores[to]), self.heartbeat(authority.load())))

    def unlock(self, peer, requester="a", session=lt.SESSION):
        """Peer `peer` decides, by ITS manifest, whether to unlock `requester`; audited."""
        manifest, p = self.stores[peer].load(), self.peers[peer]
        evidence = self.evidence(p["attester"], manifest, session) if m.may(manifest, requester, "request") and requester == "a" else None
        return convergence.audited(self.events.append, "unlock", manifest, requester, peer,
                                   lambda: replacement.may_unlock(manifest, peer, requester, session, evidence, p["attester"], p["freshness"]))

    def last(self):
        return {k: self.events[-1][k] for k in ("event", "epoch", "subject", "peer", "outcome")}


class Exchange(Case):
    """summary, compare, missing, catch_up, apply_bundle."""

    def test_a_summary_names_the_current_manifest(self):
        self.assertEqual(convergence.summary(self.stores["b"]), {"epoch": 1, "manifest_digest": m.digest(self.m1)})
        self.assertEqual(convergence.summary(self.store("new")), {"epoch": 0, "manifest_digest": ""})
        for label, reason, bad in (("extra field", "summary fields mismatch", {"epoch": 1, "manifest_digest": "00" * 32, "site": "x"}),
                                   ("negative", "summary.epoch must be an integer >= 0", {"epoch": -1, "manifest_digest": ""}),
                                   ("boolean", "summary.epoch must be an integer >= 0", {"epoch": True, "manifest_digest": "00" * 32}),
                                   ("digest", "summary.manifest_digest must be 64 lowercase hex", {"epoch": 1, "manifest_digest": "x"}),
                                   ("digest without a manifest", "a node with no manifest has no digest", {"epoch": 0, "manifest_digest": "00" * 32})):
            with self.subTest(label):
                self.refused(reason, convergence.compare, self.stores["b"], bad)

    def test_compare_tells_a_node_where_it_stands(self):
        b, c, new = self.stores["b"], self.stores["c"], self.store("new")
        self.assertEqual(convergence.compare(b, convergence.summary(c)), "same")
        e2 = self.revoke(self.m1)
        b.commit(e2)
        self.assertEqual(convergence.compare(c, convergence.summary(b)), "behind")
        self.assertEqual(convergence.compare(b, convergence.summary(c)), "ahead")
        self.assertEqual(convergence.compare(b, convergence.summary(new)), "ahead")
        self.assertEqual(convergence.compare(new, convergence.summary(new)), "same")
        self.assertEqual(convergence.compare(new, convergence.summary(b)), "behind")

    def test_two_manifests_for_one_epoch_are_a_conflict_not_a_choice(self):
        b, c = self.stores["b"], self.stores["c"]
        b.commit(self.revoke(self.m1))
        rival = rt.sign(self.chain(self.m1, [self.entry("a"), self.entry("b"), self.entry("c", "DRAINING")]), hbt.REVOKE, "revocation")
        c.commit(rival)                                  # validly signed, chained to epoch 1: the authority signed twice
        for one, other in ((b, c), (c, b)):
            self.refused("CONFLICT: the peer holds a different manifest at epoch 2", convergence.compare, one, convergence.summary(other))
            self.refused("CONFLICT", convergence.missing, one, convergence.summary(other))
        self.refused("CONFLICT: a different manifest at epoch 2", convergence.catch_up, c, b.envelopes(1))
        self.assertEqual(c.load()["nodes"][2]["state"], "DRAINING")          # nothing was applied
        # a fork below the tip is seen too: b moves on to epoch 3, c still presents its epoch-2 manifest
        b.commit(self.revoke(b.load(), "DRAINING", "c"))
        self.refused("CONFLICT: the peer holds a different manifest at epoch 2", convergence.compare, b, convergence.summary(c))
        self.refused("CONFLICT: a different manifest at epoch 2", convergence.catch_up, c, b.envelopes(1))

    def test_missing_is_what_the_other_side_lacks_and_only_what_this_side_has(self):
        b, c = self.stores["b"], self.stores["c"]
        e2 = self.revoke(self.m1, "QUARANTINED")
        e3 = self.revoke(e2["manifest"])
        b.commit(e2)
        b.commit(e3)
        self.assertEqual(convergence.missing(b, convergence.summary(c)), [e2, e3])
        self.assertEqual(convergence.missing(b, convergence.summary(b)), [])
        self.assertEqual(convergence.missing(b, convergence.NOT_ENROLLED), [self.e1, e2, e3])
        self.refused("this node is behind the peer (epoch 3): it has nothing to offer it", convergence.missing, c, convergence.summary(b))
        handed = convergence.missing(b, convergence.summary(c))
        handed[0]["manifest"]["nodes"][0]["state"] = "ACTIVE"                # a copy: the store is not touched,
        self.assertEqual(b.chain[1], e2)                                     # not even the chain it holds in memory
        self.assertEqual(b.envelopes(1)[0], e2)

    def test_store_envelopes_verifies_and_anchors_as_load_does(self):
        b = self.stores["b"]
        with open(b.path, "rb") as f:
            epoch_1 = f.read()
        b.commit(self.revoke(self.m1))
        self.assertEqual([e["manifest"]["epoch"] for e in b.envelopes()], [1, 2])
        self.assertEqual([e["manifest"]["epoch"] for e in b.envelopes(1)], [2])
        self.assertEqual(b.envelopes(2), [])
        self.assertEqual(b.envelopes(9), [])
        for bad in (-1, True, "1", None):
            with self.subTest(bad=bad):
                self.refused("after_epoch must be an integer >= 0", b.envelopes, bad)
        with open(b.path, "wb") as f:
            f.write(epoch_1)                             # the disk rolled back to epoch 1
        self.refused("ROLLBACK: the membership on disk is epoch 1 but the TPM high-water is 2", b.load)
        self.refused("ROLLBACK: the membership on disk is epoch 1 but the TPM high-water is 2", b.envelopes)
        self.refused("ROLLBACK", convergence.summary, b)
        self.refused("ROLLBACK", convergence.missing, b, convergence.NOT_ENROLLED)

    def test_catch_up_applies_in_order_skips_what_is_held_and_stops_at_the_first_refusal(self):
        b, c = self.stores["b"], self.stores["c"]
        e2 = self.revoke(self.m1, "QUARANTINED")
        e3 = self.revoke(e2["manifest"])
        self.assertEqual(convergence.catch_up(c, [e2, e3])["epoch"], 3)                    # two epochs at once
        self.assertEqual(c.hw.value(), 3)                                                  # and the TPM anchor followed
        self.assertEqual(convergence.catch_up(c, [self.e1, e2, e3])["epoch"], 3)           # delivered again, from the start: nothing changes
        self.refused("epoch 3 does not follow 1", convergence.catch_up, b, [e3, e2])       # out of order
        self.assertEqual(b.load()["epoch"], 1)
        forged = copy.deepcopy(e3)
        forged["manifest"]["nodes"][0]["state"] = "ACTIVE"
        self.refused("signature does not verify", convergence.catch_up, b, [e2, forged])   # good, then bad
        self.assertEqual(b.load()["epoch"], 2)                                             # the good one stays
        unsigned_by_root = rt.sign(self.chain(e3["manifest"], [self.entry("a"), self.entry("b"), self.entry("c")]), hbt.REVOKE, "revocation")
        self.refused("tombstone: a is REVOKED_STOLEN", convergence.catch_up, c, [unsigned_by_root])   # nobody un-revokes through catch-up
        # an envelope for an epoch already held is authenticated too: the same manifest with a broken or foreign signature is refused
        for label, reason, change in (("a corrupted signature", "signature does not verify", lambda e: e["signature"].update(sig="00" * 64)),
                                      ("a stranger's key as root", "names a root key that is not the pinned root", lambda e: e["signature"].update(signer="root", key=hbt.pub(hbt.OTHER))),
                                      ("an extra field", "envelope fields mismatch", lambda e: e.update(note="x"))):
            with self.subTest(label):
                resent = copy.deepcopy(e2)
                change(resent)
                self.refused(reason, convergence.catch_up, c, [resent])
        self.refused("signature does not verify", convergence.catch_up, c, [dict(self.e1, signature=dict(self.e1["signature"], sig="11" * 64))])
        self.assertEqual(convergence.summary(c)["epoch"], 3)
        for label, reason, bad in (("not a list", "at most 1000 envelopes at a time", e2), ("too many", "at most 1000 envelopes at a time", [e2] * 1001),
                                   ("not an envelope", "an envelope must hold a manifest", ["x"]), ("no manifest", "an envelope must hold a manifest", [{"signature": {}}])):
            with self.subTest(label):
                self.refused(reason, convergence.catch_up, b, bad)

    def test_a_bundle_brings_the_manifests_then_the_heartbeat(self):
        e2 = self.revoke(self.m1)
        b, fresh = self.stores["b"], self.peers["b"]["freshness"]
        alone = self.heartbeat(e2["manifest"])
        # the new heartbeat alone tells a peer it is behind, and changes nothing
        self.refused("the heartbeat is for epoch 2, the current manifest is epoch 1", fresh.accept, alone, b.load())
        self.refused("the heartbeat is for epoch 2, the current manifest is epoch 1", convergence.apply_bundle, b, fresh, {"envelopes": [], "heartbeat": alone})
        self.assertEqual(b.load()["epoch"], 1)
        now_at, left = convergence.apply_bundle(b, fresh, convergence.bundle(self.stores["authority"], convergence.summary(b), alone))
        self.assertEqual((now_at["epoch"], left), (2, hb.MAX_LIFETIME))
        self.assertEqual(fresh.check(b.load()), hb.MAX_LIFETIME)
        # delivered again: the manifests are held already, and the heartbeat's sequence is spent
        self.refused("REPLAY", convergence.apply_bundle, b, fresh, {"envelopes": [self.e1, e2], "heartbeat": alone})
        self.assertEqual(fresh.check(b.load()), hb.MAX_LIFETIME)
        self.refused("bundle fields mismatch", convergence.apply_bundle, b, fresh, {"envelopes": []})
        self.refused("a heartbeat cannot be taken before the first manifest", convergence.apply_bundle, self.store("new"), fresh, {"envelopes": [], "heartbeat": alone})

    def test_a_node_far_behind_catches_up_in_chunks_and_gets_the_heartbeat_with_the_last(self):
        authority, c, fresh = self.stores["authority"], self.stores["c"], self.peers["c"]["freshness"]
        previous = self.m1
        for state in ("DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"):      # epochs 2 to 5
            previous = self.revoke(previous, state)["manifest"]
        beat = self.heartbeat(previous)
        self.assertEqual(len(convergence.missing(authority, convergence.summary(c))), 4)
        self.assertEqual([e["manifest"]["epoch"] for e in convergence.missing(authority, convergence.summary(c), limit=3)], [2, 3, 4])
        rounds = []
        while convergence.compare(c, convergence.summary(authority)) == "behind":
            sent = convergence.bundle(authority, convergence.summary(c), beat, limit=3)
            now_at, left = convergence.apply_bundle(c, fresh, sent)
            rounds.append((len(sent["envelopes"]), sent["heartbeat"] is not None, now_at["epoch"], left))
        self.assertEqual(rounds, [(3, False, 4, None), (1, True, 5, hb.MAX_LIFETIME)])
        self.assertEqual(fresh.check(c.load()), hb.MAX_LIFETIME)
        for bad in (0, 1001, True, "3"):
            with self.subTest(limit=bad):
                self.refused("limit must be 1 to 1000", convergence.missing, authority, convergence.summary(c), bad)

    def test_exposure_is_the_life_left_in_the_heartbeat(self):
        c, fresh = self.stores["c"], self.peers["c"]["freshness"]
        self.assertEqual(convergence.exposure(c, fresh), hb.MAX_LIFETIME - 60)
        self.assertEqual(convergence.exposure(c, fresh, running=True), hb.MAX_LIFETIME - 60 + lease.MAX_LIFETIME)
        self.later(hb.MAX_LIFETIME)
        self.assertEqual(convergence.exposure(c, fresh), 0)
        self.assertEqual(convergence.exposure(c, fresh, running=True), lease.MAX_LIFETIME)   # a lease it issued just before is still out
        self.assertEqual(convergence.exposure(self.stores["authority"], self.peer("b", "-none")["freshness"]), 0)   # no heartbeat at all

    def test_every_decision_leaves_one_event_naming_the_epoch(self):
        self.assertGreater(self.unlock("b"), 0)
        self.assertEqual(self.events, [{"event": "unlock", "epoch": 1, "manifest_digest": m.digest(self.m1), "subject": "a", "peer": "b",
                                        "outcome": "ALLOW", "reason": ""}])
        self.refused("z may not be unlocked under epoch 1", self.unlock, "b", "z")
        self.assertEqual(self.events[-1], {"event": "unlock", "epoch": 1, "manifest_digest": m.digest(self.m1), "subject": "z", "peer": "b",
                                           "outcome": "DENY", "reason": "z may not be unlocked under epoch 1"})
        self.assertEqual(len(self.events), 2)
        # a reason is cut to printable ASCII and bounded; other exceptions are not swallowed or logged as decisions

        def refuse():
            raise m.Refused("bad\x00input\n\x1b[31m" + "x" * 500)
        self.refused("bad", convergence.audited, self.events.append, "unlock\n", None, "a\x07", "b", refuse)
        self.assertEqual(self.events[-1]["reason"], "bad?input??[31m" + "x" * 225)
        self.assertEqual((self.events[-1]["event"], self.events[-1]["subject"], self.events[-1]["epoch"], self.events[-1]["manifest_digest"]), ("unlock?", "a?", 0, ""))
        with self.assertRaises(ZeroDivisionError):
            convergence.audited(self.events.append, "unlock", self.m1, "a", "b", lambda: 1 / 0)
        self.assertEqual(len(self.events), 3)


class Theft(Case):
    """Node a is stolen: its hardware, disks and keys intact."""

    def test_poc_9_1_a_peer_with_the_revoking_manifest_refuses_the_stolen_node_at_once(self):
        self.assertGreater(self.unlock("b"), 0)                              # before: b would unlock a
        self.revoke(self.m1)                                                 # a is off; the revocation key publishes REVOKED_STOLEN
        now_at, _ = self.publish("b")
        self.assertEqual(now_at["epoch"], 2)
        self.refused("a may not be unlocked under epoch 2", self.unlock, "b")                # a boots, hardware intact, and asks
        self.assertEqual(self.last(), {"event": "unlock", "epoch": 2, "subject": "a", "peer": "b", "outcome": "DENY"})
        p, manifest = self.peers["b"], self.stores["b"].load()
        self.refused("a may not serve under epoch 2: no lease", lease.issue, manifest, "b", self.holder.request(), p["attester"], None, p["freshness"], p["signer"])
        self.assertGreater(hb.authorize(manifest, "b", "c", p["freshness"]), 0)             # the others are untouched

    def test_poc_9_2_a_stale_requester_cannot_bring_its_old_manifest_back(self):
        e2 = self.revoke(self.m1)
        self.publish("b")
        b, stolen = self.stores["b"], self.store("a")
        stolen.commit(self.e1)                                               # what a still holds: epoch 1, itself ACTIVE
        self.assertEqual(convergence.compare(b, convergence.summary(stolen)), "ahead")       # b decides by its own manifest
        self.assertEqual(convergence.catch_up(b, stolen.envelopes())["epoch"], 2)            # a's chain is a prefix of b's: nothing to take
        self.refused("epoch 1 does not follow 2", b.commit, self.e1)
        restored = rt.sign(self.chain(e2["manifest"], [self.entry("a"), self.entry("b"), self.entry("c")]), hbt.REVOKE, "revocation")
        self.refused("tombstone: a is REVOKED_STOLEN", convergence.catch_up, b, [restored])  # nor can anyone un-revoke it
        self.refused("a may not be unlocked under epoch 2", self.unlock, "b")

    def test_poc_9_3_a_revoked_node_vouches_for_nobody(self):
        self.revoke(self.m1)
        self.publish("b")
        self.publish("c")
        manifest, c = self.stores["c"].load(), self.peers["c"]
        # a claims to authorize b's unlock, and signs b a lease with its own, genuine AK
        self.refused("a may not authorize under epoch 2", hb.authorize, manifest, "a", "b", c["freshness"])
        by_a = lt.sign(dict(self.body(manifest), node_id="b", ak_name=self.keys["b"].ak_name, issuer="a"), self.keys["a"])
        self.refused("a may not authorize under epoch 2", convergence.audited, self.events.append, "lease-verify", manifest, "b", "c",
                     lambda: lease.verify(by_a, manifest, self.now))
        self.assertEqual(self.last(), {"event": "lease-verify", "epoch": 2, "subject": "b", "peer": "c", "outcome": "DENY"})

    def test_poc_9_4_a_partitioned_peer_helps_until_its_heartbeat_expires_and_refuses_the_moment_it_catches_up(self):
        b, c = self.stores["b"], self.stores["c"]
        running = self.issue("c")                                            # a was running, vouched for by c
        self.holder.install(running, self.m1)
        e2 = self.revoke(self.m1, "QUARANTINED")                             # two epochs while c is cut off
        self.revoke(e2["manifest"])
        self.publish("b")
        self.assertEqual(b.load()["epoch"], 3)
        self.refused("a may not be unlocked under epoch 3", self.unlock, "b")
        # c is partitioned: it still trusts a, for exactly as long as its heartbeat lives
        self.assertEqual(c.load()["epoch"], 1)
        bound = convergence.exposure(c, self.peers["c"]["freshness"])
        self.assertEqual(bound, hb.MAX_LIFETIME - 60)
        self.assertGreater(self.unlock("c"), 0)
        self.assertEqual(self.last()["outcome"], "ALLOW")                    # the exposure, recorded
        self.later(bound - 1)
        self.assertEqual(self.unlock("c"), 1)
        self.later(1)
        self.refused("EXPIRED: the heartbeat expired", self.unlock, "c")     # ... and not a second longer
        self.assertEqual(convergence.exposure(c, self.peers["c"]["freshness"]), 0)

    def test_poc_9_4_connected_peers_converge_in_one_exchange(self):
        b, c = self.stores["b"], self.stores["c"]
        self.holder.install(self.issue("c"), self.m1)                        # a is running under c's lease
        e2 = self.revoke(self.m1, "QUARANTINED")
        self.revoke(e2["manifest"])
        self.publish("b")
        self.assertGreater(self.unlock("c"), 0)                              # c has not heard yet
        # the authority's heartbeat for epoch 3 reaches c without the manifests: refused, and c knows it is behind
        late = self.heartbeat(b.load())
        self.refused("the heartbeat is for epoch 3, the current manifest is epoch 1", self.peers["c"]["freshness"].accept, late, c.load())
        # one message from b (its own lease renewal, say) is enough
        self.assertEqual(exchange(c, b), "behind")
        self.assertEqual((c.load()["epoch"], c.hw.value()), (3, 3))
        self.assertEqual(exchange(c, b), "same")
        self.assertEqual(exchange(b, c), "same")
        # c issues nothing now, but the lease it gave a before catching up is still out: the bound says so
        self.assertEqual(convergence.exposure(c, self.peers["c"]["freshness"]), 0)
        self.assertEqual(convergence.exposure(c, self.peers["c"]["freshness"], running=True), lease.MAX_LIFETIME)
        # with the manifest: refused at once, although c holds no heartbeat for epoch 3 yet
        self.refused("a may not be unlocked under epoch 3", self.unlock, "c")
        self.refused("a may not serve under epoch 3", self.holder.check, c.load())
        self.refused("a may not serve under epoch 3: no lease", lease.issue, c.load(), "c", self.holder.request(), self.peers["c"]["attester"], None,
                     self.peers["c"]["freshness"], self.peers["c"]["signer"])
        # and c itself authorizes nobody until a heartbeat for epoch 3 arrives: it fails closed, then recovers
        self.refused("the heartbeat is for epoch 1, the current manifest is epoch 3", hb.authorize, c.load(), "c", "b", self.peers["c"]["freshness"])
        self.peers["c"]["freshness"].accept(late, c.load())
        self.assertGreater(hb.authorize(c.load(), "c", "b", self.peers["c"]["freshness"]), 0)
        # the stolen node, still running on a lease c gave it before: it runs out at the lease's expiry
        self.assertGreater(self.holder.check(self.m1), 0)
        self.later(lease.MAX_LIFETIME)
        self.refused("EXPIRED: the runtime lease expired", self.holder.check, self.m1)

    def test_restrictive_revocation_needs_no_root_and_cannot_restore_trust(self):
        envelope = self.revoke(self.m1)
        self.assertEqual(envelope["signature"]["signer"], "revocation")
        stolen_then_back = rt.sign(self.chain(self.m1, [self.entry("a", "QUARANTINED"), self.entry("b"), self.entry("c")]), hbt.REVOKE, "revocation")
        store = self.store("q")
        store.commit(self.e1)
        store.commit(stolen_then_back)
        back = rt.sign(self.chain(stolen_then_back["manifest"], [self.entry("a"), self.entry("b"), self.entry("c")]), hbt.REVOKE, "revocation")
        self.refused("widens capabilities; only the root can do that", convergence.catch_up, store, [back])
        added = rt.sign(self.chain(stolen_then_back["manifest"], [self.entry("a", "QUARANTINED"), self.entry("b"), self.entry("c"), self.entry("a2")]), hbt.REVOKE, "revocation")
        self.refused("a revocation key cannot add or remove nodes", convergence.catch_up, store, [added])


class OnSwtpm(unittest.TestCase):
    """Peers b and c on two software TPMs: each one's epoch anchor and heartbeat counter are real TPM NV
    counters. Where the tools are provisioned (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""

    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_nvdefine", "tpm2_nvincrement", "tpm2_readclock")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm and tpm2-tools are expected here and were not found")
            self.skipTest("needs swtpm and tpm2-tools")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.now = lt.T0 + 60
        clock = lambda: (self.now, True)
        self.stores, self.fresh = {}, {}
        for name in ("b", "c"):
            state, sock = "%s/tpm-%s" % (self.d, name), "%s/%s.sock" % (self.d, name)
            os.makedirs(state)
            subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + sock,
                            "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                            "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
            time.sleep(0.5)
            with open("%s/%s.pid" % (self.d, name)) as f:
                self.addCleanup(os.kill, int(f.read()), 15)
            tcti = "swtpm:path=" + sock
            anchor = m.HighWater("0x1500016", tcti=tcti, lock_path="%s/%s-hw.lock" % (self.d, name))
            anchor.define()
            self.stores[name] = m.Store("%s/%s-membership.json" % (self.d, name), ROOT, anchor)
            counter = hb.Counter("0x1500018", tcti=tcti, lock_path="%s/%s-seq.lock" % (self.d, name))
            counter.define()
            self.fresh[name] = hb.Freshness(counter, clock, hbt.simulated_ticks(self, tcti), "%s/%s-freshness.json" % (self.d, name))

    def manifest(self, previous=None, **states):
        return {"schema": m.SCHEMA, "epoch": previous["epoch"] + 1 if previous else 1, "prev_digest": m.digest(previous) if previous else "",
                "policy_version": "p1", "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                "nodes": [hbt.node(n, states.get(n, "ACTIVE"), i) for i, n in enumerate(("a", "b", "c"))]}

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_a_partitioned_peer_catches_up_through_the_chain_and_its_tpm_anchor_follows(self):
        b, c = self.stores["b"], self.stores["c"]
        m1 = self.manifest()
        e1 = rt.sign(m1)
        for name in ("b", "c"):
            self.stores[name].commit(e1)
            self.fresh[name].accept(hbt.beat(m1, 1), m1)
        self.assertGreater(hb.authorize(c.load(), "c", "a", self.fresh["c"]), 0)
        # a is stolen: two revocation-signed manifests reach b in a bundle; c is cut off
        m2 = self.manifest(m1, a="QUARANTINED")
        m3 = self.manifest(m2, a="REVOKED_STOLEN")
        e2, e3 = (rt.sign(x, hbt.REVOKE, "revocation") for x in (m2, m3))
        beat3 = hbt.beat(m3, 2, issued=self.now)
        now_at, left = convergence.apply_bundle(b, self.fresh["b"], {"envelopes": [e2, e3], "heartbeat": beat3})
        self.assertEqual((now_at["epoch"], b.hw.value(), left), (3, 3, hb.MAX_LIFETIME))
        self.refused("a may not be unlocked under epoch 3", hb.authorize, b.load(), "b", "a", self.fresh["b"])
        # c, partitioned: still helps, for the life left in its heartbeat; the new heartbeat alone is refused
        self.assertEqual(convergence.exposure(c, self.fresh["c"]), hb.MAX_LIFETIME - 60)
        self.assertGreater(hb.authorize(c.load(), "c", "a", self.fresh["c"]), 0)
        self.refused("the heartbeat is for epoch 3, the current manifest is epoch 1", self.fresh["c"].accept, beat3, c.load())
        with open(c.path, "rb") as f:
            stale_disk = f.read()
        # c reconnects: one exchange with b
        self.assertEqual(exchange(c, b), "behind")
        self.assertEqual((c.load()["epoch"], c.hw.value()), (3, 3))          # its own TPM counter moved with the chain
        self.refused("a may not be unlocked under epoch 3", hb.authorize, c.load(), "c", "a", self.fresh["c"])
        self.fresh["c"].accept(beat3, c.load())
        self.assertGreater(hb.authorize(c.load(), "c", "b", self.fresh["c"]), 0)
        # c's disk put back to before the revocation: its TPM refuses, for the manifest and for everything built on it
        with open(c.path, "wb") as f:
            f.write(stale_disk)
        self.refused("ROLLBACK: the membership on disk is epoch 1 but the TPM high-water is 3", c.load)
        self.refused("ROLLBACK", convergence.summary, c)
        self.refused("ROLLBACK", convergence.missing, c, convergence.NOT_ENROLLED)
        # recovery: fetch the chain from b again
        os.unlink(c.path)
        self.refused("ROLLBACK", c.load)
        with open(c.path, "wb") as f:
            f.write(m.canonical(b.envelopes()))
        self.assertEqual(c.load()["epoch"], 3)


if __name__ == "__main__":
    unittest.main()
