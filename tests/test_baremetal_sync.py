"""deploy/baremetal/sync.py (#80): the transport between running nodes. Who a message came from is the
WireGuard key the current manifest pins; how much is accepted is bounded; every decision is one audit event.

The tunnel is a table here (`identify`: source address -> WireGuard key); the kernel's answer and real
WireGuard are step 2. Fixtures are those of the convergence tests: b and c hold the chain and a heartbeat."""
import json
import os
import socket
import threading
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, convergence, lease, sync
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_convergence as ct
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt
import tests.test_baremetal_replacement as rt

ADDRESS = {"a": "fd72:6567:616c::a", "b": "fd72:6567:616c::b", "c": "fd72:6567:616c::c", "a2": "fd72:6567:616c::a2"}


class Held:
    """The revocation authority's side: it holds its latest heartbeat and issues no leases."""

    def __init__(self):
        self.envelope = None

    def held(self):
        return self.envelope


class Case(ct.Case):
    def setUp(self):
        super().setUp()
        self.keys_at = {ADDRESS[n["node_id"]]: n["wg_service_pub"] for n in self.m1["nodes"]}
        self.keys_at[ADDRESS["a2"]] = self.entry("a2")["wg_service_pub"]
        self.tick = 0.0
        self.servers = {name: self.server(name) for name in ("b", "c")}
        self.authority = Held()
        self.servers["authority"] = sync.Server(convergence.AUTHORITY, self.stores["authority"], self.authority, None, None,
                                                self.identify, self.events.append, sync.Buckets(clock=lambda: self.tick), clock=lambda: self.now)
        # node a's own store and freshness, and its asking side
        self.stores["a"] = self.store("a")
        self.own = self.peer("a", tag="-own")["freshness"]
        self.client = self.client_of("a", self.stores["a"], self.own)

    def identify(self, manifest, source):
        m.require(source in self.keys_at, "no WireGuard peer owns %s" % source)
        return self.keys_at[source]

    def server(self, name):
        p = self.peers[name]
        return sync.Server(name, self.stores[name], p["freshness"], p["attester"], p["signer"], self.identify, self.events.append,
                           sync.Buckets(clock=lambda: self.tick), clock=lambda: self.now)

    def client_of(self, name, store, freshness, sources=("b", "c", "authority")):
        transports = {(convergence.AUTHORITY if s == "authority" else s): self.wire(s, name) for s in sources}
        return sync.Client(name, store, freshness, transports, self.events.append)

    def wire(self, server, caller):
        return lambda raw: self.servers[server].handle(raw, ADDRESS[caller])

    def ask(self, server, caller="a", raw=None, **message):
        """One request as `caller`'s tunnel address; the decoded answer."""
        if raw is None:
            raw = m.canonical(message)
        return json.loads(self.servers[server].handle(raw, ADDRESS.get(caller, caller)))

    def pull(self, server, caller="a", summary=None, sequence=0):
        return self.ask(server, caller, v=1, op="pull", summary=summary or dict(convergence.NOT_ENROLLED), sequence=sequence)

    def refusal(self, reason, answer):
        self.assertEqual((answer["v"], answer["ok"], sorted(answer)), (1, False, ["ok", "refused", "v"]), answer)
        self.assertIn(reason, answer["refused"])

    def last(self):
        return self.events[-1]

    def denied(self, reason, answer):
        """A caller this node did not identify, or will not talk to: told "refused" and nothing more; the
        reason is in the trail."""
        self.assertEqual(answer, {"v": 1, "ok": False, "refused": "refused"})
        self.assertEqual(self.last()["outcome"], "DENY")
        self.assertIn(reason, self.last()["reason"])

    def quote(self, nonce, manifest, session=lt.SESSION, node="a"):
        """Node a's fresh quote over a nonce a peer issued."""
        key = b"ephemeral key of boot " + bytes.fromhex(session)
        signed = self.keys[node].signer(ek_name=self.keys[node].ek_name)(
            attest.qualifying_data(node, manifest["epoch"], bytes.fromhex(session), key, bytes.fromhex(nonce)))
        return {"ephemeral_public": key.hex(), "nonce": nonce, "quote": signed["quote"], "signature": signed["sig"]}

    def advance(self, epochs, store="authority", **change):
        """`epochs` more root-signed manifests in the authority's chain; returns the last."""
        manifest = self.stores[store].load()
        for _ in range(epochs):
            manifest = dict(self.chain(manifest, manifest["nodes"]), **change)
            self.stores[store].commit(rt.sign(manifest))
        return manifest


class Identity(Case):
    def test_the_caller_is_the_node_the_current_manifest_pins_the_tunnel_s_key_to(self):
        answer = self.pull("b")
        self.assertEqual((answer["ok"], [e["manifest"]["epoch"] for e in answer["bundle"]["envelopes"]]), (True, [1]))
        self.assertEqual(self.last(), {"event": "sync-pull", "epoch": 1, "manifest_digest": m.digest(self.m1), "subject": "a", "peer": "b",
                                       "outcome": "ALLOW", "reason": ""})
        self.assertEqual(sync.peer_of(self.m1, self.entry("c")["wg_service_pub"]), "c")
        self.assertEqual(sync.peer_of(self.m1, self.entry("c")["wg_boot_pub"], "wg_boot_pub"), "c")

    def test_an_address_no_wireguard_peer_owns_is_refused_and_recorded_by_its_address(self):
        self.denied("no WireGuard peer owns 2001:db8::1", self.pull("b", caller="2001:db8::1"))
        self.assertEqual((self.last()["subject"], self.last()["outcome"], self.last()["event"]), ("2001:db8::1", "DENY", "sync"))

    def test_a_key_the_current_manifest_does_not_pin_is_refused(self):
        self.denied("the tunnel's key is not pinned to a node by the current manifest (epoch 1)", self.pull("b", caller="a2"))
        self.keys_at[ADDRESS["a"]] = self.entry("a")["wg_boot_pub"]                 # the boot key is not the service key
        self.denied("not pinned to a node", self.pull("b"))
        for bad in ("", "zz" * 32, "AB" * 32, "ab" * 31, None, 7):
            with self.subTest(key=bad):
                self.keys_at[ADDRESS["a"]] = bad
                self.denied("the tunnel's key", self.pull("b"))
        twice = dict(self.m1, nodes=self.m1["nodes"] + [dict(self.entry("a2"), wg_service_pub=self.entry("a")["wg_service_pub"])])
        with self.assertRaises(m.Refused):
            sync.peer_of(twice, self.entry("a")["wg_service_pub"])                   # never chosen between

    def test_a_revoked_node_is_refused_at_the_next_request_though_its_tunnel_is_still_up(self):
        self.assertTrue(self.pull("b")["ok"])
        revoking = self.revoke(self.m1)
        self.stores["b"].commit(revoking)                                           # b has the manifest; nothing touched the tunnel table
        self.denied("a is REVOKED_STOLEN under epoch 2", self.pull("b"))            # and it is not told why: it is no longer a peer
        self.assertEqual((self.last()["epoch"], self.last()["subject"], self.last()["outcome"]), (2, "a", "DENY"))
        self.denied("a is REVOKED_STOLEN", self.ask("b", v=1, op="lease-nonce", node_id="a"))
        self.assertTrue(self.pull("c")["ok"])                                       # c has not heard: its own manifest decides for it

    def test_a_retired_node_gets_nothing_and_a_quarantined_one_may_still_learn(self):
        retired = self.accept(self.m1, self.replaced())
        self.stores["b"].commit(rt.sign(retired))
        self.denied("a is RETIRED under epoch 2", self.pull("b"))
        self.assertTrue(self.pull("b", caller="a2")["ok"])                          # its replacement is a node now
        quarantined = self.revoke(self.m1, state="QUARANTINED")
        self.stores["c"].commit(quarantined)
        self.assertTrue(self.pull("c")["ok"])
        self.refusal("a may not serve", self.lease_over("c"))

    def lease_over(self, server):
        nonce = self.ask(server, v=1, op="lease-nonce", node_id="a")
        if not nonce["ok"]:
            return nonce
        manifest = self.stores[server].load()
        return self.ask(server, v=1, op="lease", request=self.holder.request(), evidence=self.quote(nonce["nonce"], manifest))

    def test_a_message_that_names_a_node_must_name_the_node_the_tunnel_identified(self):
        self.refusal("the request names a; the tunnel is c's", self.ask("b", caller="c", v=1, op="lease-nonce", node_id="a"))
        self.assertEqual((self.last()["subject"], self.last()["event"]), ("c", "sync-lease-nonce"))
        nonce = self.ask("b", v=1, op="lease-nonce", node_id="a")["nonce"]
        request, evidence = self.holder.request(), self.quote(nonce, self.m1)
        self.refusal("the request names a; the tunnel is c's", self.ask("b", caller="c", v=1, op="lease", request=request, evidence=evidence))
        self.assertTrue(self.ask("b", v=1, op="lease", request=request, evidence=evidence)["ok"])   # the same message from a's tunnel
        for odd in ("\x1b[31m", ["a"], None, 5):
            self.refusal("the request names", self.ask("b", v=1, op="lease-nonce", node_id=odd))

    def test_a_node_does_not_ask_itself(self):
        self.denied("a node does not ask itself", self.pull("b", caller="b"))

    def test_what_this_node_holds_is_not_told_to_a_caller_it_did_not_identify(self):
        """The store's own refusal, and this node's epoch, are for the trail. Found by an independent read:
        an address nobody owns was told "ROLLBACK: ... the TPM high-water is 3"."""
        def rolled_back():
            raise m.Refused("ROLLBACK: the membership on disk is epoch 1 but the TPM high-water is 3; fetch the chain from a peer")
        with unittest.mock.patch.object(self.stores["b"], "load", rolled_back):
            for caller in ("2001:db8::1", "a"):
                self.denied("ROLLBACK", self.pull("b", caller=caller))
        self.denied("epoch 1", self.pull("b", caller="a2"))                         # an unpinned key does not learn the epoch

class Bounds(Case):
    def test_exact_fields_a_version_and_a_known_operation(self):
        good = {"v": 1, "op": "pull", "summary": dict(convergence.NOT_ENROLLED), "sequence": 0}
        self.assertTrue(self.ask("b", **good)["ok"])
        for label, reason, message in (
                ("an unknown field", "pull fields mismatch", dict(good, more=1)),
                ("a missing field", "pull fields mismatch", {k: v for k, v in good.items() if k != "sequence"}),
                ("no version", "version must be 1", {k: v for k, v in good.items() if k != "v"}),
                ("another version", "version must be 1", dict(good, v=2)),
                ("a version as text", "version must be 1", dict(good, v="1")),
                ("a version as true", "version must be 1", dict(good, v=True)),
                ("an unknown operation", "unknown operation", dict(good, op="push")),
                ("an operation that is no text", "unknown operation", dict(good, op=["pull"])),
                ("a private method", "unknown operation", dict(good, op="decide")),
                ("no operation", "unknown operation", {"v": 1}),
                ("a summary with more", "summary fields mismatch", dict(good, summary=dict(convergence.NOT_ENROLLED, more=1))),
                ("a negative sequence", "sequence must be an integer >= 0", dict(good, sequence=-1)),
                ("a sequence as true", "sequence must be an integer >= 0", dict(good, sequence=True)),
                ("a sequence as text", "sequence must be an integer >= 0", dict(good, sequence="0")),
                ("lease-nonce with more", "lease-nonce fields mismatch", {"v": 1, "op": "lease-nonce", "node_id": "a", "more": 1}),
                ("lease with no evidence", "lease fields mismatch", {"v": 1, "op": "lease", "request": {}}),
                ("a lease request that is a list", "request and evidence are objects", {"v": 1, "op": "lease", "request": [], "evidence": {}}),
                ("evidence that is text", "request and evidence are objects", {"v": 1, "op": "lease", "request": {}, "evidence": "x"}),
                ("evidence with more", "evidence fields mismatch", {"v": 1, "op": "lease", "request": self.holder.request(),
                                                                     "evidence": dict(self.quote("00" * 32, self.m1), more=1)})):
            with self.subTest(label):
                before = len(self.events)
                self.refusal(reason, self.ask("b", **message))
                self.assertEqual((len(self.events) - before, self.last()["outcome"], self.last()["subject"]), (1, "DENY", "a"))

    def test_what_is_not_one_json_object_is_refused(self):
        for label, reason, raw in (
                ("not JSON", "not valid JSON", b"pull"), ("empty", "not valid JSON", b""), ("a list", "version must be 1", b"[1]"),
                ("a duplicate field", "duplicate field", b'{"v":1,"v":1,"op":"pull"}'), ("a float", "floats are not allowed", b'{"v":1.0}'),
                ("not bytes", "at most 65536 bytes", "text"),
                ("too large", "at most 65536 bytes", b'{"v":1,"op":"pull","pad":"' + b"x" * sync.MAX_REQUEST + b'"}')):
            with self.subTest(label):
                self.refusal(reason, json.loads(self.servers["b"].handle(raw, ADDRESS["a"])))
        deep = json.loads(self.servers["b"].handle(b"[" * 30000 + b"]" * 30000, ADDRESS["a"]))    # no stack trace, no crash
        self.assertFalse(deep["ok"])
        self.assertEqual(self.last()["outcome"], "DENY")

    def test_an_address_has_twenty_requests_a_minute_and_over_it_costs_this_node_nothing(self):
        for _ in range(20):
            self.assertTrue(self.pull("b")["ok"])
        with unittest.mock.patch.object(self.stores["b"], "load", wraps=self.stores["b"].load) as loads:
            self.denied("RATE: more than 20 address requests in 60 s from %s" % ADDRESS["a"], self.pull("b"))
            self.assertEqual((self.last()["event"], self.last()["subject"]), ("sync", ADDRESS["a"]))
            before = len(self.events)
            for _ in range(500):                                                    # a flood: answered, and that is all
                self.assertEqual(self.pull("b"), {"v": 1, "ok": False, "refused": "refused"})
            self.assertEqual((loads.call_count, len(self.events) - before), (0, 0))   # no manifest read, no TPM, no event
        self.assertTrue(self.pull("b", caller="c", summary=convergence.summary(self.stores["c"]))["ok"])   # c has its own bucket
        self.assertTrue(self.pull("c")["ok"])                                       # and c's server its own count of a
        self.tick += 3
        self.assertTrue(self.pull("b")["ok"])                                       # one request every three seconds refills
        self.assertEqual(self.pull("b")["refused"], "refused")
        self.assertEqual(len(self.events) - before, 3)                              # c's pull and a's two: the refusal is still inside the reported minute
        self.tick += 60
        for _ in range(20):
            self.pull("b")
        self.denied("(501 more refused since the last report)", self.pull("b"))     # the next minute's report carries the count
        self.tick += 3600
        for _ in range(21):
            last = self.pull("b")
        self.assertEqual(last["refused"], "refused")                                # the bucket does not grow past its size

    def test_a_revoked_node_whose_tunnel_is_still_up_cannot_drive_this_node(self):
        """Found by an independent read: refused callers reached no bucket, so each request cost a chain
        verification, TPM reads and an audit event, without limit."""
        self.stores["b"].commit(self.revoke(self.m1))
        with unittest.mock.patch.object(self.stores["b"], "load", wraps=self.stores["b"].load) as loads:
            for _ in range(500):
                self.assertEqual(self.pull("b")["refused"], "refused")
        self.assertEqual(loads.call_count, 20)
        self.assertEqual(len([e for e in self.events if e["subject"] in ("a", ADDRESS["a"])]), 21)   # twenty denials by name, one RATE report
        self.keys_at["2001:db8::9"] = "77" * 32                                     # a WireGuard peer the manifest does not pin
        before = len(self.events)
        for _ in range(500):
            self.pull("b", caller="2001:db8::9")
        self.assertEqual(len(self.events) - before, 21)

    def test_a_node_has_twenty_requests_a_minute_whatever_address_it_comes_from_and_six_may_ask_for_a_lease(self):
        self.keys_at["fd72:6567:616c::a:2"] = self.entry("a")["wg_service_pub"]      # a second address of node a's key
        for _ in range(20):
            self.assertTrue(self.pull("b")["ok"])
        self.denied("RATE: more than 20 any requests in 60 s from a", self.pull("b", caller="fd72:6567:616c::a:2"))
        self.assertEqual(self.last()["subject"], "a")
        self.tick += 3600
        for _ in range(6):
            self.assertTrue(self.ask("b", v=1, op="lease-nonce", node_id="a")["ok"])
        self.refusal("RATE: more than 6 lease requests in 60 s from a", self.ask("b", v=1, op="lease-nonce", node_id="a"))   # identified: told why
        self.assertTrue(self.pull("b")["ok"])                                       # the lease limit does not stop a pull
        self.tick += 3600
        nonces = [self.ask("b", v=1, op="lease-nonce", node_id="a")["nonce"] for _ in range(3)]
        for nonce in nonces:                                                        # three nonces and three leases: six
            self.assertTrue(self.ask("b", v=1, op="lease", request=self.holder.request(), evidence=self.quote(nonce, self.m1))["ok"])
        nonce = self.peers["b"]["attester"].nonce("a").hex()                        # a seventh, with a nonce b did issue
        self.refusal("RATE: more than 6 lease requests", self.ask("b", v=1, op="lease", request=self.holder.request(), evidence=self.quote(nonce, self.m1)))

    def test_the_buckets_forget_idle_callers_and_refuse_when_full_of_busy_ones(self):
        buckets = sync.Buckets(clock=lambda: self.tick)
        with unittest.mock.patch.object(sync, "MAX_BUCKETS", 3):
            for name in ("x", "y", "z"):
                buckets.take(name, "address")
            self.refused("RATE: too many callers at once", buckets.take, "w", "address")
            buckets.take("x", "address")                                            # a caller already known is still served
            self.tick += 61                                                         # the three are idle: forgotten for a newcomer
            buckets.take("w", "address")
            self.assertEqual(sorted(k[0] for k in buckets.state), ["w"])

    def test_a_bundle_is_at_most_64_envelopes_and_a_node_far_behind_catches_up_in_rounds(self):
        self.advance(130)
        self.stores["b"].restore(self.stores["authority"].envelopes())
        self.beat(self.stores["b"].load(), peers=("b",), issued=self.now)
        first = self.pull("b")
        self.assertEqual(([e["manifest"]["epoch"] for e in first["bundle"]["envelopes"]], first["bundle"]["heartbeat"], first["summary"]["epoch"]),
                         (list(range(1, 65)), None, 131))
        now_at, fresh = self.client.pull("b")
        self.assertEqual((now_at["epoch"], fresh), (131, hb.MAX_LIFETIME))
        rounds = [e for e in self.events if e["event"] == "sync-apply"]
        self.assertEqual([(e["epoch"], e["outcome"], e["subject"], e["peer"]) for e in rounds],
                         [(0, "ALLOW", "a", "b"), (64, "ALLOW", "a", "b"), (128, "ALLOW", "a", "b")])
        self.assertEqual(self.own.check(self.stores["a"].load()), hb.MAX_LIFETIME)

    def test_an_answer_is_at_most_a_mebibyte_so_large_manifests_come_fewer_at_a_time(self):
        padding = [("%064x" % i) for i in range(1, 3000)]                                       # about 200 KiB a manifest
        self.advance(7, revocation_keys=[hbt.pub(hbt.REVOKE)] + padding)
        self.stores["b"].restore(self.stores["authority"].envelopes())
        raw = self.servers["b"].handle(m.canonical({"v": 1, "op": "pull", "summary": dict(convergence.NOT_ENROLLED), "sequence": 0}), ADDRESS["a"])
        self.assertLessEqual(len(raw), sync.MAX_ANSWER)
        answer = json.loads(raw)
        got = [e["manifest"]["epoch"] for e in answer["bundle"]["envelopes"]]
        self.assertEqual((got, answer["bundle"]["heartbeat"]), (list(range(1, len(got) + 1)), None))
        self.assertTrue(1 <= len(got) < 8)
        self.assertEqual(self.client.pull("b")[0]["epoch"], 8)                                 # and the rounds still get there


class Pull(Case):
    def test_a_node_behind_gets_the_manifests_and_the_heartbeat_together(self):
        now_at, fresh = self.client.pull("b")
        self.assertEqual((now_at, fresh), ({"epoch": 1, "manifest_digest": m.digest(self.m1)}, hb.MAX_LIFETIME - 60))
        revoked = self.revoke(self.m1, node="c")["manifest"]
        self.stores["b"].restore(self.stores["authority"].envelopes())
        self.later(100)
        self.beat(revoked, peers=("b",), issued=self.now)
        self.assertEqual(self.client.pull("b"), ({"epoch": 2, "manifest_digest": m.digest(revoked)}, hb.MAX_LIFETIME))
        self.assertEqual(self.own.check(self.stores["a"].load()), hb.MAX_LIFETIME)

    def test_a_heartbeat_the_caller_already_holds_is_not_sent_again(self):
        self.client.pull("b")
        del self.events[:]
        self.assertEqual(self.client.pull("b"), (convergence.summary(self.stores["a"]), None))    # nothing new: no replay refusal
        self.assertEqual(self.client.pull("c"), (convergence.summary(self.stores["a"]), None))    # c holds the same heartbeat
        self.assertEqual([e["outcome"] for e in self.events], ["ALLOW"] * 4)
        self.later(3600)
        self.beat(self.m1, peers=("c",), issued=self.now)                                          # the authority reached c only
        self.assertEqual(self.client.pull("b")[1], None)
        self.assertEqual(self.client.pull("c")[1], hb.MAX_LIFETIME)                                # a newer one travels peer to peer
        answer = self.pull("c", summary=convergence.summary(self.stores["a"]), sequence=2)
        self.assertIsNone(answer["bundle"]["heartbeat"])
        self.assertEqual(self.pull("c", summary=convergence.summary(self.stores["a"]), sequence=1)["bundle"]["heartbeat"]["heartbeat"]["sequence"], 2)

    def test_a_peer_passes_on_only_a_heartbeat_for_the_manifest_it_holds(self):
        self.stores["b"].commit(self.revoke(self.m1, node="c"))                                    # b moved on; its heartbeat is for epoch 1
        answer = self.pull("b")
        self.assertEqual(([e["manifest"]["epoch"] for e in answer["bundle"]["envelopes"]], answer["bundle"]["heartbeat"]), ([1, 2], None))
        now_at, fresh = self.client.pull("b")
        self.assertEqual((now_at["epoch"], fresh), (2, None))
        self.refused("no heartbeat is held", self.own.check, self.stores["a"].load())              # caught up, and authorizes nobody yet

    def test_a_caller_that_is_ahead_is_answered_not_refused(self):
        self.client.pull("b")
        self.stores["a"].commit(self.revoke(self.m1, node="c"))
        answer = self.pull("b", summary=convergence.summary(self.stores["a"]))
        self.assertEqual((answer["ok"], answer["summary"]["epoch"], answer["bundle"]), (True, 1, {"envelopes": [], "heartbeat": None}))
        self.assertEqual(self.last()["outcome"], "ALLOW")

    def test_an_unsigned_summary_proves_nothing_and_a_signed_envelope_proves_the_conflict(self):
        """Found by an independent read: any node could have this peer record "two manifests were signed for
        one epoch; record an incident" by SAYING it held another digest. A summary is unsigned. The peer
        now answers with its own chain from that epoch; a caller that really holds another signed manifest
        proves the conflict itself."""
        claimed = self.pull("b", summary={"epoch": 1, "manifest_digest": "ab" * 32})
        self.assertEqual((claimed["ok"], [e["manifest"]["epoch"] for e in claimed["bundle"]["envelopes"]], claimed["bundle"]["heartbeat"]),
                         (True, [1], None))
        self.assertEqual((self.last()["outcome"], self.last()["reason"]), ("ALLOW", ""))    # no incident on a claim
        self.assertEqual(self.client.pull("b")[0]["epoch"], 1)
        # a real fork: a holds one signed manifest at epoch 2, b another
        fork = rt.sign(self.chain(self.m1, [self.entry("a"), self.entry("b"), self.entry("c", "DRAINING")]))
        self.stores["a"].commit(fork)
        self.stores["b"].commit(self.revoke(self.m1, node="c"))
        with self.assertRaises(m.Refused) as caught:
            self.client.pull("b")
        self.assertIn("CONFLICT: a different manifest at epoch 2: two manifests were signed for one epoch", str(caught.exception))
        self.assertEqual((self.last()["event"], self.last()["outcome"], self.last()["subject"], self.last()["peer"]), ("sync-apply", "DENY", "a", "b"))
        self.assertEqual(convergence.summary(self.stores["a"])["manifest_digest"], m.digest(fork["manifest"]))   # and a keeps what it holds

    def test_the_authority_is_a_source_like_any_other_and_issues_no_leases(self):
        revoked = self.revoke(self.m1, node="c")["manifest"]
        self.sequence += 1
        self.authority.envelope = hbt.beat(revoked, self.sequence, issued=self.now)
        now_at, fresh = self.client.pull(convergence.AUTHORITY)
        self.assertEqual((now_at["epoch"], fresh), (2, hb.MAX_LIFETIME))
        self.assertEqual((self.last()["peer"], self.last()["subject"]), (convergence.AUTHORITY, "a"))
        self.refusal("this source issues no leases", self.ask("authority", v=1, op="lease-nonce", node_id="a"))
        self.refusal("this source issues no leases", self.ask("authority", v=1, op="lease", request=self.holder.request(),
                                                               evidence=self.quote("00" * 32, revoked)))

    def test_a_source_that_holds_no_heartbeat_still_hands_over_the_manifests(self):
        self.revoke(self.m1, node="c")
        self.assertIsNone(self.authority.held())
        answer = self.pull("authority")
        self.assertEqual(([e["manifest"]["epoch"] for e in answer["bundle"]["envelopes"]], answer["bundle"]["heartbeat"]), ([1, 2], None))
        self.assertEqual(self.last()["outcome"], "ALLOW")

    def test_a_node_with_no_manifest_answers_nobody(self):
        self.servers["x"] = sync.Server("b", self.store("empty"), self.peers["b"]["freshness"], None, None, self.identify, self.events.append)
        self.denied("this node holds no manifest", self.pull("x"))
        self.assertEqual((self.last()["epoch"], self.last()["manifest_digest"], self.last()["subject"]), (0, "", ADDRESS["a"]))

    def test_a_heartbeat_that_has_expired_is_not_passed_on(self):
        """Found by an independent read: the peer handed on a heartbeat its own check called EXPIRED, and
        every pull from it then raised at the caller."""
        self.assertIsNotNone(self.pull("b")["bundle"]["heartbeat"])
        self.later(hb.MAX_LIFETIME)
        self.refused("EXPIRED", self.peers["b"]["freshness"].check, self.m1)
        answer = self.pull("b")
        self.assertEqual((answer["ok"], answer["bundle"]["heartbeat"], len(answer["bundle"]["envelopes"])), (True, None, 1))
        self.assertEqual(self.client.pull("b"), ({"epoch": 1, "manifest_digest": m.digest(self.m1)}, None))   # no refusal at the caller
        self.assertEqual(self.pull("b", summary=convergence.summary(self.stores["a"]))["bundle"]["heartbeat"], None)

class Lying(Case):
    """A source can delay. It cannot make the node accept what the authority did not sign."""

    def source(self, answer):
        self.client.transports["liar"] = lambda raw: m.canonical(answer) if not isinstance(answer, bytes) else answer
        return "liar"

    def answer(self, envelopes, heartbeat=None, **more):
        return dict({"v": 1, "ok": True, "summary": {"epoch": 9, "manifest_digest": "ab" * 32},
                     "bundle": {"envelopes": envelopes, "heartbeat": heartbeat}}, **more)

    def refused_pull(self, reason, source, event="sync-apply"):
        with self.assertRaises(m.Refused) as caught:
            self.client.pull(source)
        self.assertIn(reason, str(caught.exception))
        self.assertEqual((self.last()["event"], self.last()["outcome"]), (event, "DENY"))
        self.assertIn(reason, self.last()["reason"])

    def test_a_forged_manifest_a_stale_heartbeat_and_a_malformed_answer_change_nothing(self):
        self.client.pull("b")
        held = convergence.summary(self.stores["a"])
        forged = rt.sign(self.chain(self.m1, [self.entry("a"), self.entry("b"), self.entry("c", "REVOKED_STOLEN")]), hbt.OTHER, "revocation")
        old = hbt.beat(self.m1, 1, issued=self.now - 2 * hb.MAX_LIFETIME)
        other = hbt.beat(self.m1, 9, key=hbt.OTHER)
        for label, reason, answer, *where in (
                ("a manifest signed by a stranger", "the signing revocation key is not named by the current manifest", self.answer([forged])),
                ("an expired heartbeat", "EXPIRED", self.answer([], old), "sync-heartbeat"),
                ("a heartbeat signed by a stranger", "not a revocation key named by the current manifest", self.answer([], other), "sync-heartbeat"),
                ("a heartbeat that is no object", "envelope", self.answer([], "soon"), "sync-heartbeat"),
                ("too many envelopes", "at most 64 envelopes", self.answer([self.e1] * 65)),
                ("envelopes that are no list", "at most 64 envelopes", self.answer({"0": self.e1})),
                ("a bundle with more", "bundle fields mismatch", dict(self.answer([]), bundle={"envelopes": [], "heartbeat": None, "more": 1})),
                ("an answer with more", "pull answer fields mismatch", self.answer([], more=1)),
                ("no summary", "pull answer fields mismatch", {"v": 1, "ok": True, "bundle": {"envelopes": [], "heartbeat": None}}),
                ("a bad summary", "summary.epoch", dict(self.answer([]), summary={"epoch": -1, "manifest_digest": ""})),
                ("another version", "the answer's version must be 1", dict(self.answer([]), v=2)),
                ("neither ok nor refused", "neither ok nor refused", dict(self.answer([]), ok="yes")),
                ("a refusal with more", "refusal fields mismatch", {"v": 1, "ok": False, "refused": "no", "more": 1}),
                ("a refusal", "the source refused: go away", {"v": 1, "ok": False, "refused": "go away"}),
                ("not JSON", "not valid JSON", b"<html>"),
                ("too large", "the answer exceeds 1048576 bytes", b" " * (sync.MAX_ANSWER + 1))):
            with self.subTest(label):
                self.refused_pull(reason, self.source(answer), *where)
                self.assertEqual(convergence.summary(self.stores["a"]), held)
                self.assertNotIn("had moved", self.last()["reason"])                  # nothing moved, and the refusal does not say it did
        self.assertEqual(self.own.check(self.stores["a"].load()), hb.MAX_LIFETIME - 60)            # the heartbeat it had is untouched

    def test_a_heartbeat_handed_to_a_node_with_no_manifest_is_refused_by_name(self):
        self.assertEqual(convergence.summary(self.stores["a"])["epoch"], 0)
        self.refused_pull("a heartbeat cannot be taken before the first manifest", self.source(self.answer([], hbt.beat(self.m1, 1, issued=self.now))),
                          "sync-heartbeat")
        self.assertEqual(convergence.summary(self.stores["a"])["epoch"], 0)

    def test_a_source_that_does_not_answer_is_a_refusal_and_an_unknown_source_is_not_asked(self):
        def down(raw):
            raise ConnectionRefusedError("down")

        def slow(raw):
            raise TimeoutError("slow")
        for transport, reason in ((down, "liar did not answer (ConnectionRefusedError)"), (slow, "liar did not answer (TimeoutError)")):
            self.client.transports["liar"] = transport
            self.refused_pull(reason, "liar")
        self.refused_pull("'nobody' is not a configured source", "nobody")

    def test_a_source_that_always_has_more_ends_at_the_round_limit(self):
        calls = []

        def endless(raw):
            calls.append(raw)
            return m.canonical(self.answer([self.e1]))
        self.client.transports["liar"] = endless
        now_at, fresh = self.client.pull("liar")           # the same envelope again and again: verified, the same, no progress
        self.assertEqual((now_at["epoch"], len(calls)), (1, sync.MAX_ROUNDS))

    def test_an_answer_that_breaks_the_code_reading_it_is_a_recorded_refusal_not_an_exception(self):
        """Found by an independent read: a deeply nested answer raised RecursionError out of pull, and an
        envelope whose node state is a list raised TypeError, with no audit event. A loop that catches
        Refused, as the docstring invites, died on one bad answer."""
        self.client.pull("b")
        held = convergence.summary(self.stores["a"])
        deep = b"[" * 30000 + b"]" * 30000
        odd = rt.sign(dict(self.chain(self.m1, self.m1["nodes"]), nodes=[dict(self.entry("a"), state=["ACTIVE"]), self.entry("b"), self.entry("c")]))
        for label, answer in (("a deeply nested answer", deep),
                              ("a deeply nested bundle", b'{"v":1,"ok":true,"summary":{"epoch":1,"manifest_digest":"' + b"ab" * 32
                               + b'"},"bundle":' + deep + b"}"),
                              ("a node state that is a list", self.answer([odd])),
                              ("a node state that is an object", self.answer([dict(odd, manifest=dict(odd["manifest"], nodes=[dict(self.entry("a"), state={})]))]))):
            with self.subTest(label):
                before = len(self.events)
                with self.assertRaises(m.Refused):                      # a Refused, whatever the code underneath raised
                    self.client.pull(self.source(answer))
                self.assertEqual((len(self.events) - before, self.last()["event"], self.last()["outcome"]), (1, "sync-apply", "DENY"))
                self.assertEqual(convergence.summary(self.stores["a"]), held)
        self.client.transports["liar"] = lambda raw: deep
        with self.assertRaises(m.Refused) as caught:
            self.client.renewer("liar", self.quote)(self.holder.request())
        self.assertIn("could not be read (RecursionError)", str(caught.exception))

        def broken_quote(nonce, manifest):
            raise KeyError("tpm")
        with self.assertRaises(m.Refused):
            self.client.renewer("b", broken_quote)(self.holder.request())

    def test_a_round_that_moved_the_membership_and_was_then_refused_says_so(self):
        """Found by an independent read: manifests are durable as each is accepted, so a round could commit a
        revocation and then be refused on its heartbeat, and the only event was a DENY at the OLD epoch."""
        self.client.pull("b")
        e2 = self.revoke(self.m1, node="c")
        m2 = e2["manifest"]
        del self.events[:]
        self.refused_pull("signature fields mismatch", self.source(self.answer([e2], {"heartbeat": {}, "signature": {}})), "sync-heartbeat")
        self.assertEqual([(e["event"], e["outcome"], e["epoch"]) for e in self.events], [("sync-apply", "ALLOW", 1), ("sync-heartbeat", "DENY", 2)])
        self.assertEqual(convergence.summary(self.stores["a"])["epoch"], 2)          # the trail and the store agree: it moved
        # a later envelope refused after an earlier one was accepted: one DENY, and it says how far it got
        e3 = rt.sign(self.chain(m2, [self.entry("a", "DRAINING"), self.entry("b"), self.entry("c", "REVOKED_STOLEN")]), hbt.REVOKE, "revocation")
        forged = rt.sign(self.chain(e3["manifest"], e3["manifest"]["nodes"]), hbt.OTHER, "revocation")
        del self.events[:]
        self.refused_pull("(the membership had moved from epoch 2 to 3 before this)", self.source(self.answer([e3, forged])))
        self.assertEqual(convergence.summary(self.stores["a"])["epoch"], 3)

class Leases(Case):
    def test_a_lease_is_asked_for_and_issued_over_the_transport(self):
        self.client.pull("b")
        renew = self.client.renewer("b", self.quote)
        envelope = renew(self.holder.request())
        self.assertEqual(self.holder.install(envelope, self.m1), lease.MAX_LIFETIME)
        self.assertEqual((envelope["lease"]["issuer"], envelope["lease"]["node_id"]), ("b", "a"))
        kinds = [(e["event"], e["outcome"], e["subject"], e["peer"]) for e in self.events[-2:]]
        self.assertEqual(kinds, [("sync-lease-nonce", "ALLOW", "a", "b"), ("sync-lease", "ALLOW", "a", "b")])

    def test_a_quote_over_another_nonce_or_by_another_node_is_refused_by_the_peer(self):
        self.client.pull("b")
        with self.assertRaises(m.Refused) as caught:
            self.client.renewer("b", lambda nonce, manifest: self.quote("11" * 32, manifest))(self.holder.request())
        self.assertIn("the source refused", str(caught.exception))
        self.assertEqual((self.last()["event"], self.last()["outcome"]), ("sync-lease", "DENY"))
        with self.assertRaises(m.Refused):
            self.client.renewer("b", lambda nonce, manifest: self.quote(nonce, manifest, node="c"))(self.holder.request())

    def test_a_revoked_node_gets_no_lease_from_a_peer_that_knows(self):
        self.client.pull("b")
        self.stores["b"].commit(self.revoke(self.m1, state="QUARANTINED"))
        self.beat(self.stores["b"].load(), peers=("b",), issued=self.now)
        with self.assertRaises(m.Refused) as caught:
            self.client.renewer("b", self.quote)(self.holder.request())
        self.assertIn("the source refused: a may not serve under epoch 2", str(caught.exception))

    def test_a_malformed_nonce_from_a_source_is_refused(self):
        self.client.transports["liar"] = lambda raw: m.canonical({"v": 1, "ok": True, "nonce": "zz"})
        with self.assertRaises(m.Refused) as caught:
            self.client.renewer("liar", self.quote)(self.holder.request())
        self.assertIn("nonce", str(caught.exception))


class Recording(Case):
    def test_a_failure_inside_the_node_is_a_refusal_with_no_detail_and_is_recorded(self):
        def broken(node_id):
            raise RuntimeError("/var/lib/regalia/attest.json: disk error at sector 7")
        self.servers["b"].attester = type("Broken", (), {"nonce": staticmethod(broken)})()
        answer = self.ask("b", v=1, op="lease-nonce", node_id="a")
        self.assertEqual(answer, {"v": 1, "ok": False, "refused": "this node could not answer (RuntimeError)"})
        self.assertEqual((self.last()["event"], self.last()["outcome"], self.last()["reason"]),
                         ("sync-lease-nonce", "DENY", "this node could not answer (RuntimeError)"))

    def test_an_answer_that_would_not_fit_is_refused_not_sent(self):
        huge = {"envelopes": [], "heartbeat": {"pad": "x" * sync.MAX_ANSWER}}
        with unittest.mock.patch.object(sync.Server, "_fit", staticmethod(lambda bundle_of: huge)):
            raw = self.servers["b"].handle(m.canonical({"v": 1, "op": "pull", "summary": dict(convergence.NOT_ENROLLED), "sequence": 0}), ADDRESS["a"])
        self.assertLess(len(raw), 200)
        self.refusal("the answer would exceed 1048576 bytes", json.loads(raw))

    def test_nothing_is_answered_that_could_not_be_recorded(self):
        def full(event):
            raise OSError("the journal is full")

        def refusing(event):                              # a sink that fails with the library's own refusal type
            raise m.Refused("the audit file is full")
        for sink in (full, refusing):
            with self.subTest(sink=sink.__name__):
                self.servers["b"].sink = sink
                with self.assertRaises(sync.SinkFailed):   # for an accepted request, and for one that would be refused
                    self.pull("b")
                with self.assertRaises(sync.SinkFailed):
                    self.ask("b", v=1, op="lease-nonce", node_id="c")

    def test_every_request_is_exactly_one_event(self):
        del self.events[:]
        self.pull("b")
        self.pull("b", caller="nowhere")
        self.ask("b", v=1, op="lease-nonce", node_id="c")
        self.ask("b", raw=b"{")
        self.assertEqual([(e["event"], e["outcome"], e["subject"]) for e in self.events],
                         [("sync-pull", "ALLOW", "a"), ("sync", "DENY", "nowhere"), ("sync-lease-nonce", "DENY", "a"), ("sync", "DENY", "a")])
        self.assertTrue(all(sorted(e) == ["epoch", "event", "manifest_digest", "outcome", "peer", "reason", "subject"] for e in self.events))


class Sockets(Case):
    """serve and tcp_transport on the loopback: the framing, the size limit, the deadline, the connection
    limits. The source address is 127.0.0.1 here; in production it is a tunnel address."""

    def setUp(self):
        super().setUp()
        self.keys_at["127.0.0.1"] = self.entry("a")["wg_service_pub"]
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.05)
        self.port, self.stopped = self.listener.getsockname()[1], False
        self.thread = threading.Thread(target=sync.serve, args=(self.servers["b"], self.listener, lambda: self.stopped),
                                       kwargs={"deadline": 1.0}, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.stopped = True
        self.thread.join(5)
        self.listener.close()

    def test_a_pull_and_a_lease_over_real_connections(self):
        client = sync.Client("a", self.stores["a"], self.own, {"b": sync.tcp_transport("127.0.0.1", self.port)}, self.events.append)
        self.assertEqual(client.pull("b")[0]["epoch"], 1)
        envelope = client.renewer("b", self.quote)(self.holder.request())
        self.assertEqual(self.holder.install(envelope, self.m1), lease.MAX_LIFETIME)
        self.assertIn(("sync-lease", "ALLOW", "a"), [(e["event"], e["outcome"], e["subject"]) for e in self.events])

    def test_a_request_over_the_limit_is_refused_without_being_read_to_the_end(self):
        answer = json.loads(sync.tcp_transport("127.0.0.1", self.port)(b"x" * (sync.MAX_REQUEST + 1)))
        self.assertIn("at most 65536 bytes", answer["refused"])
        # Far over the limit the server stops reading and closes: the caller gets the refusal, or a reset
        # if its own unsent bytes were still on the way. Either way one DENY is recorded and nothing else.
        del self.events[:]
        try:
            raw = sync.tcp_transport("127.0.0.1", self.port)(b"x" * (sync.MAX_REQUEST * 40))
            self.assertIn("at most 65536 bytes", json.loads(raw)["refused"])
        except OSError:
            pass
        time.sleep(0.3)
        self.assertEqual([(e["outcome"], e["reason"]) for e in self.events], [("DENY", "a request is at most 65536 bytes")])

    def drops(self):
        return [(e["subject"], e["outcome"], e["reason"]) for e in self.events if e["event"] == "sync-drop"]

    def test_a_caller_that_never_finishes_its_request_is_dropped_at_the_deadline(self):
        with socket.create_connection(("127.0.0.1", self.port)) as conn:
            conn.sendall(b'{"v":1,')
            conn.settimeout(5)
            started = time.monotonic()
            self.assertEqual(conn.recv(100), b"")                                   # closed, unanswered
            self.assertLess(time.monotonic() - started, 4)
        time.sleep(0.2)
        self.assertEqual(self.drops(), [("127.0.0.1", "DENY", "no complete request within 1 s")])   # no request was decided; the drop is recorded
        self.assertEqual([e for e in self.events if e["event"] != "sync-drop"], [])

    def test_a_caller_that_drips_its_request_is_dropped_at_the_same_deadline(self):
        """The deadline is for the whole request, not for each read: a byte every 300 ms would otherwise hold
        a place for as long as the caller liked."""
        with socket.create_connection(("127.0.0.1", self.port)) as conn:
            started, closed = time.monotonic(), None
            try:
                for _ in range(20):
                    conn.sendall(b" ")
                    time.sleep(0.3)
            except OSError:
                closed = time.monotonic() - started
            if closed is None:
                conn.settimeout(1)
                closed = time.monotonic() - started if conn.recv(10) == b"" else None
        self.assertIsNotNone(closed)
        self.assertLess(closed, 3)                                                  # twenty drips would have taken six seconds
        self.assertEqual(len(self.drops()), 1)

    def test_a_caller_that_never_reads_its_answer_gives_its_place_back_at_the_deadline(self):
        class Flood:
            def handle(self, raw, source):
                return b" " * (64 * 1024 * 1024)                                    # far more than the socket buffers hold

            def dropped(self, source, reason):
                pass
        listener = socket.create_server(("127.0.0.1", 0))
        listener.settimeout(0.05)
        stopped = []
        thread = threading.Thread(target=sync.serve, args=(Flood(), listener, lambda: bool(stopped)),
                                  kwargs={"deadline": 1.0, "per_address": 1}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stopped.append(1), thread.join(5), listener.close()))
        port = listener.getsockname()[1]
        silent = socket.create_connection(("127.0.0.1", port))
        self.addCleanup(silent.close)
        silent.sendall(b"{}")
        silent.shutdown(socket.SHUT_WR)                                             # a whole request, and then it reads nothing
        time.sleep(0.3)
        self.assertEqual(self.complete(port), b"")                                  # its place is taken while the answer is being sent
        time.sleep(2.0)                                                             # past the deadline for sending it
        self.assertEqual(self.complete(port)[:4], b"    ")                          # the place is free again

    def complete(self, port=None):
        """A whole request on a new connection; what came back (b"" when it was closed unanswered)."""
        with socket.create_connection(("127.0.0.1", port or self.port)) as conn:
            conn.settimeout(5)
            try:
                conn.sendall(b"{}")
                conn.shutdown(socket.SHUT_WR)
                answer = conn.recv(4096)
            except OSError:      # the server had already closed it: reset, or no longer connected
                return b""
        time.sleep(0.2)          # the place is given back just after the answer is sent, not before
        return answer

    def serving(self, **limits):
        """Another serve loop on a port of its own, with these limits; its port."""
        listener = socket.create_server(("127.0.0.1", 0))
        listener.settimeout(0.05)
        stopped = []
        thread = threading.Thread(target=sync.serve, args=(self.servers["b"], listener, lambda: bool(stopped)), kwargs=limits, daemon=True)
        thread.start()
        self.addCleanup(lambda: (stopped.append(1), thread.join(5), listener.close()))
        return listener.getsockname()[1]

    def hold(self, port):
        """A connection that sends nothing: it occupies a place until it is closed (the deadline is far)."""
        conn = socket.create_connection(("127.0.0.1", port))
        self.addCleanup(conn.close)
        time.sleep(0.2)                                                             # accepted and counted
        return conn

    def release(self, conn):
        conn.close()
        time.sleep(0.3)                                                             # the server saw it go

    def test_two_connections_from_one_address_and_no_more(self):
        port = self.serving(deadline=60.0)
        first, second = self.hold(port), self.hold(port)
        for _ in range(4):
            self.assertEqual(self.complete(port), b"")                              # a whole request, closed unanswered
        self.release(second)                                                        # one of the two goes away
        self.assertIn(b'"ok"', self.complete(port))                                 # room for one
        third = self.hold(port)
        self.assertEqual(self.complete(port), b"")                                  # and for one only: the other is still counted
        self.release(first)
        self.release(third)
        self.hold(port)                                                             # the refused ones were never counted:
        self.assertIn(b'"ok"', self.complete(port))                                 # two at once again
        # five connections were closed unanswered: ONE event, not five (the next minute's would carry the count)
        self.assertEqual(self.drops(), [("127.0.0.1", "DENY", "over the connection limit (8 in all, 2 from one address)")])

    def test_drops_are_reported_once_a_minute_with_the_count(self):
        server = self.servers["b"]
        for _ in range(7):
            server.dropped("127.0.0.9", "over the connection limit")
        self.assertEqual(self.drops(), [("127.0.0.9", "DENY", "over the connection limit")])
        self.tick += 61
        server.dropped("127.0.0.9", "over the connection limit")
        self.assertEqual(self.drops()[-1], ("127.0.0.9", "DENY", "over the connection limit (6 more dropped since the last report)"))
        server.dropped("127.0.0.8", "no complete request within 10 s")                # another address: its own report
        self.assertEqual(len(self.drops()), 3)
        server.sink = lambda event: (_ for _ in ()).throw(OSError("full"))
        self.tick += 61
        with self.assertRaises(sync.SinkFailed):
            server.dropped("127.0.0.9", "over the connection limit")                  # serve() swallows this; the method does not hide it

    def test_no_more_connections_in_all_than_the_limit(self):
        port = self.serving(deadline=60.0, connections=3, per_address=10)
        held = [self.hold(port) for _ in range(3)]
        self.assertEqual(self.complete(port), b"")
        self.release(held.pop())
        self.assertIn(b'"ok"', self.complete(port))

    def test_the_transport_reads_no_more_than_an_answer_may_be(self):
        flood = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(flood.close)

        def pour():
            conn, _ = flood.accept()
            with conn:
                try:
                    while conn.recv(4096):      # the whole request first, as a server does
                        pass
                    conn.sendall(b" " * (sync.MAX_ANSWER * 3))
                except OSError:
                    pass
        threading.Thread(target=pour, daemon=True).start()
        raw = sync.tcp_transport("127.0.0.1", flood.getsockname()[1])(b"{}")
        self.assertEqual(len(raw), sync.MAX_ANSWER + 1)                             # one byte over: enough to refuse it
        with self.assertRaises(m.Refused):
            sync._answer(raw, "pull")


if __name__ == "__main__":
    unittest.main()
