"""Replacing a node and keeping its retired hardware out (#76, Phase 16): membership's tombstone rule,
deploy/baremetal/replacement.py, and every decision a peer makes about the old and the new hardware.

The TPM identities are OpenSSL P-256 keys (the fixtures of tests/test_baremetal_lease.py); the last class
runs the replacement on three software TPMs: the old node, the new one, and a peer."""
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, lease, replacement
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt

SESSION, OLD_SESSION = "a2" * 32, lt.SESSION
MEASURED = {"tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}


def sign(manifest, key=hbt.ROOT, signer="root"):
    return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                "sig": key.sign(m.DOMAIN + m.canonical(manifest)).hex()}}


class Case(lt.Case):
    """m1: a, b, c ACTIVE. m2: the root replaces a by a2 (new EK, AK, WireGuard keys, HSM serial)."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keys["a2"] = lt.Key(cls.keydir, "a2", 9)
        cls.keys["x"] = lt.Key(cls.keydir, "x", 12)

    def entry(self, node_id, state="ACTIVE", n=None, **override):
        n = ("a", "b", "c", "a2", "x").index(node_id) if n is None else n
        return dict({"node_id": node_id, "state": state, "ek_name": self.keys[node_id].ek_name, "ak_name": self.keys[node_id].ak_name,
                     "wg_boot_pub": ("%02x" % (0x70 + n)) * 32, "wg_service_pub": ("%02x" % (0xa0 + n)) * 32,
                     "hsm_serials": ["DENK04041%02d" % n]}, **override)

    def chain(self, previous, nodes):
        return dict(self.manifest(previous["epoch"] + 1, m.digest(previous)), nodes=nodes)

    def replaced(self, state="RETIRED", previous=None):
        return self.chain(previous or self.m1, [self.entry("a", state), self.entry("b"), self.entry("c"), self.entry("a2")])

    def accept(self, current, candidate, key=hbt.ROOT, signer="root"):
        return m.accept(current, sign(candidate, key, signer), hbt.pub(hbt.ROOT))

    def setUp(self):
        super().setUp()
        self.m2 = self.accept(self.m1, self.replaced())


class Tombstones(Case):
    """membership.accept(): retirement is terminal for every signer, so an identity is never recycled."""

    def test_poc_16_the_root_replaces_a_node_and_a_revocation_key_can_only_retire_it(self):
        replacement.check_replacement(self.m1, self.m2, "a", "a2")
        self.assertEqual((m.may(self.m2, "a", "request"), m.may(self.m2, "a", "serve"), m.may(self.m2, "a", "authorize")), (False,) * 3)
        self.assertEqual((m.may(self.m2, "a2", "request"), m.may(self.m2, "a2", "serve"), m.may(self.m2, "a2", "authorize")), (True,) * 3)
        self.refused("a revocation key cannot add or remove nodes", self.accept, self.m1, self.replaced(), hbt.REVOKE, "revocation")
        retired_only = self.chain(self.m1, [self.entry("a", "RETIRED"), self.entry("b"), self.entry("c")])
        self.assertEqual(self.accept(self.m1, retired_only, hbt.REVOKE, "revocation")["epoch"], 2)

    def test_a_tombstone_cannot_be_dropped_altered_or_revived_by_any_signer(self):
        rest = [self.entry("b"), self.entry("c"), self.entry("a2")]
        for terminal in ("RETIRED", "REVOKED_STOLEN"):
            current = self.accept(self.m1, self.replaced(terminal))
            with self.subTest(terminal, path="dropped"):
                self.refused("tombstone: a is %s and must stay in every later manifest" % terminal, self.accept, current, self.chain(current, rest))
            for state in ("ACTIVE", "MAINTENANCE", "DRAINING", "QUARANTINED"):
                with self.subTest(terminal, path="revived as " + state):
                    self.refused("tombstone: a is %s, which is terminal for every signer (%s refused)" % (terminal, state),
                                 self.accept, current, self.chain(current, [self.entry("a", state)] + rest))
            for field, value in (("ek_name", self.keys["x"].ek_name), ("ak_name", self.keys["x"].ak_name), ("wg_boot_pub", "ee" * 32),
                                 ("wg_service_pub", "ef" * 32), ("hsm_serials", ["DENK0499999"]), ("hsm_serials", [])):
                with self.subTest(terminal, path="altered " + field):   # freeing an identity by rewriting the tombstone
                    self.refused("tombstone: a is %s and its %s cannot change" % (terminal, field), self.accept, current,
                                 self.chain(current, [self.entry("a", terminal, **{field: value})] + rest))
        # nor in the very manifest that retires the node: the tombstone holds the hardware as it was
        for terminal in ("RETIRED", "REVOKED_STOLEN"):
            for field, value in (("ek_name", self.keys["x"].ek_name), ("ak_name", self.keys["x"].ak_name), ("wg_boot_pub", "ee" * 32),
                                 ("wg_service_pub", "ef" * 32), ("hsm_serials", ["DENK0499999"])):
                with self.subTest(terminal, path="rewritten while retiring: " + field):
                    for key, signer in ((hbt.ROOT, "root"), (hbt.REVOKE, "revocation")):
                        retiring = self.chain(self.m1, [self.entry("a", terminal, **{field: value}), self.entry("b"), self.entry("c")])
                        with self.assertRaises(m.Refused) as caught:
                            self.accept(self.m1, retiring, key, signer)
                        if signer == "root":
                            self.assertIn("tombstone: a becomes %s and its %s cannot change in the same manifest" % (terminal, field), str(caught.exception))
        stolen = self.accept(self.m1, self.replaced("REVOKED_STOLEN"))
        self.refused("tombstone: a is REVOKED_STOLEN, which is terminal for every signer (RETIRED refused)", self.accept, stolen,
                     self.chain(stolen, [self.entry("a", "RETIRED")] + rest))
        # the one move a tombstone makes: retired hardware that is later stolen, by either signer
        for key, signer in ((hbt.ROOT, "root"), (hbt.REVOKE, "revocation")):
            with self.subTest(signer=signer):
                self.assertEqual(self.accept(self.m2, self.chain(self.m2, [self.entry("a", "REVOKED_STOLEN")] + rest), key, signer)["epoch"], 3)
        # and the revocation key is held to the same rule as the root
        self.refused("tombstone: a is RETIRED", self.accept, self.m2, self.chain(self.m2, [self.entry("a", "QUARANTINED")] + rest),
                     hbt.REVOKE, "revocation")

    def test_no_node_is_removed_it_can_only_be_retired(self):
        """A node removed outright would leave no tombstone, and its identities could be enrolled again."""
        for state in ("ACTIVE", "MAINTENANCE", "DRAINING", "QUARANTINED"):
            with self.subTest(state=state):
                current = self.accept(self.m1, self.chain(self.m1, [self.entry("a", state), self.entry("b"), self.entry("c")]))
                removed = self.chain(current, [self.entry("b"), self.entry("c")])
                self.refused("tombstone: a cannot be removed; retire it instead", self.accept, current, removed)
                # nor removed while new hardware is enrolled under another name in the same manifest
                self.refused("tombstone: a cannot be removed; retire it instead", self.accept, current,
                             self.chain(current, [self.entry("b"), self.entry("c"), self.entry("a2")]))
                # a mistaken enrollment is corrected by retiring it: it stays, and its identities stay unusable
                retired = self.accept(current, self.chain(current, [self.entry("a", "RETIRED"), self.entry("b"), self.entry("c")]))
                self.refused("already used (ek_name of a)", self.accept, retired,
                             self.chain(retired, [self.entry("a", "RETIRED"), self.entry("b"), self.entry("c"), self.entry("x", ek_name=self.entry("a")["ek_name"])]))
        # a revocation key could never remove a node; it now gets the same answer as the root
        self.refused("tombstone: a cannot be removed; retire it instead", self.accept, self.m1,
                     self.chain(self.m1, [self.entry("b"), self.entry("c")]), hbt.REVOKE, "revocation")
        # through the stored chain as well
        tpm = hbt.FakeTpm()
        anchor = m.HighWater("0x1500016", lock_path=os.path.join(self.d, "hw.lock"), run=tpm)
        anchor.define()
        store = m.Store(os.path.join(self.d, "membership.json"), hbt.pub(hbt.ROOT), anchor)
        store.commit(sign(self.m1))
        self.refused("tombstone: a cannot be removed; retire it instead", store.commit, sign(self.chain(self.m1, [self.entry("b"), self.entry("c")])))
        self.assertEqual(store.load()["epoch"], 1)

    def test_no_identity_of_retired_hardware_is_ever_enrolled_again(self):
        """The root re-enrols the EK, the AK, a WireGuard key or the HSM serial of the retired node under a
        new node ID: the tombstone is still there, so the uniqueness rule sees it."""
        tombstone, rest = self.entry("a", "RETIRED"), [self.entry("b"), self.entry("c"), self.entry("a2")]
        old = self.entry("a")
        for field, reason in (("ek_name", "ek_name of x is already used (ek_name of a)"), ("ak_name", "ak_name of x is already used (ak_name of a)"),
                              ("wg_boot_pub", "wg_boot_pub of x is already used (wg_boot_pub of a)"),
                              ("wg_service_pub", "wg_service_pub of x is already used (wg_service_pub of a)"),
                              ("hsm_serials", "HSM DENK0404100 is listed twice")):
            with self.subTest(field=field):
                self.refused(reason, self.accept, self.m2, self.chain(self.m2, [tombstone] + rest + [self.entry("x", **{field: old[field]})]))
        # across roles too: the retired EK as someone's AK, the retired boot key as someone's service key
        self.refused("already used (ek_name of a)", self.accept, self.m2,
                     self.chain(self.m2, [tombstone] + rest + [self.entry("x", ak_name=old["ek_name"])]))
        self.refused("already used (wg_boot_pub of a)", self.accept, self.m2,
                     self.chain(self.m2, [tombstone] + rest + [self.entry("x", wg_service_pub=old["wg_boot_pub"])]))
        # the node ID is taken as well: new hardware under the old name would have to rewrite the tombstone
        self.refused("tombstone: a is RETIRED", self.accept, self.m2, self.chain(self.m2, [self.entry("a", "ACTIVE", n=4, ek_name=self.keys["x"].ek_name,
                                                                                               ak_name=self.keys["x"].ak_name)] + rest))
        self.refused("duplicate node_id 'a'", self.accept, self.m2, self.chain(self.m2, [tombstone] + rest + [self.entry("a", n=4)]))
        # not in two steps either: the drop is what is refused, at the epoch that tries it
        self.assertEqual(self.accept(self.m2, self.chain(self.m2, [tombstone] + rest + [self.entry("x")]))["epoch"], 3)

    def test_the_stored_chain_enforces_it_too(self):
        tpm = hbt.FakeTpm()
        anchor = m.HighWater("0x1500016", lock_path=os.path.join(self.d, "hw.lock"), run=tpm)
        anchor.define()
        store = m.Store(os.path.join(self.d, "membership.json"), hbt.pub(hbt.ROOT), anchor)
        store.commit(sign(self.m1))
        store.commit(sign(self.m2))
        revived = self.chain(self.m2, [self.entry("a"), self.entry("b"), self.entry("c"), self.entry("a2")])
        self.refused("tombstone: a is RETIRED", store.commit, sign(revived))
        self.assertEqual(store.load()["epoch"], 2)
        # and old a's own, older manifest is not taken back
        with self.assertRaises(m.Refused):
            store.commit(sign(self.m1))

    def test_check_replacement_refuses_anything_that_is_not_exactly_a_replacement(self):
        a, b, c, a2 = self.entry("a", "RETIRED"), self.entry("b"), self.entry("c"), self.entry("a2")
        old = self.entry("a")
        for label, reason, nodes, ids in (
                ("the old node still active", "a must stay listed, as RETIRED or REVOKED_STOLEN", [old, b, c, a2], ("a", "a2")),
                ("the new node cannot do anything", "a2 must be enrolled in a state that can do something", [a, b, c, self.entry("a2", "QUARANTINED")], ("a", "a2")),
                ("the new node is not there", "a2 must be enrolled", [a, b, c], ("a", "a2")),
                ("the new ID is an existing node", "c is already a node", [a, b, c, a2], ("a", "c")),
                ("the old ID is unknown", "z is not in the current manifest", [a, b, c, a2], ("z", "a2")),
                ("a second node added", "a replacement adds a2 and nothing else", [a, b, c, a2, self.entry("x")], ("a", "a2")),
                ("another node changed", "a replacement does not change c", [a, b, self.entry("c", "DRAINING"), a2], ("a", "a2")),
                ("the retired entry altered", "the retired entry of a must keep its identities", [self.entry("a", "RETIRED", hsm_serials=[]), b, c, a2], ("a", "a2"))):
            with self.subTest(label):
                self.refused(reason, replacement.check_replacement, self.m1, self.chain(self.m1, nodes), *ids)
        # reuse, checked against a manifest validate() alone would pass: the old entry rewritten to free the identity
        for field in ("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials"):
            with self.subTest(reused=field):
                freed = self.entry("a", "RETIRED", **{field: self.entry("x")[field]})
                candidate = self.chain(self.m1, [freed, b, c, self.entry("a2", **{field: old[field]})])
                m.validate(candidate)
                self.refused("a2 reuses an identity the manifest already lists", replacement.check_replacement, self.m1, candidate, "a", "a2")
        again = self.chain(self.m2, [a, b, c, a2, self.entry("x")])       # the tombstone named as "the old node" a second time
        self.refused("a is already RETIRED: it was replaced before", replacement.check_replacement, self.m2, again, "a", "x")
        self.refused("the replacement must be the next manifest: epoch 2", replacement.check_replacement, self.m1, dict(self.m2, epoch=3), "a", "a2")
        self.refused("the replacement must be the next manifest: epoch 2", replacement.check_replacement, self.m1, dict(self.m2, prev_digest="00" * 32), "a", "a2")
        self.refused("a replacement does not change policy_version", replacement.check_replacement, self.m1, dict(self.m2, policy_version="p2"), "a", "a2")
        self.refused("a replacement does not change revocation_keys", replacement.check_replacement, self.m1, dict(self.m2, revocation_keys=[]), "a", "a2")
        replacement.check_replacement(self.m1, self.accept(self.m1, self.replaced("REVOKED_STOLEN")), "a", "a2")


class Decisions(Case):
    """Under the replacement manifest, every decision a peer makes: the new node passes, the old hardware does not."""

    def setUp(self):
        super().setUp()
        self.old_holder = self.holder                    # node a, running since before the replacement
        self.old_lease = self.issue("b")
        self.old_holder.install(self.old_lease, self.m1)
        self.beat(self.m2)                               # b and c hold the new manifest and a heartbeat for it
        for name in ("b", "c"):                          # ... and rebuild their attestation policy from it
            policy = replacement.attest_policy(self.m2, {n: MEASURED for n in ("a", "a2", "b", "c")}, peer_id=name)
            attester = attest.Verifier(policy, os.path.join(self.d, name + "-attest-m2.json"), now=lambda: self.now)
            with open(attester.state_path, "w") as f:
                json.dump({"schema": attest.STATE_SCHEMA, "nonces": {},
                           "nodes": {n: {"ak_public": self.keys[n].ak_public.hex()} for n in ("a2", "c")}}, f)
            self.peers[name]["attester"] = attester
        self.new_holder = lease.Holder("a2", SESSION, self.clock, lambda: self.ticks, os.path.join(self.d, "a2-lease.json"))

    def quote(self, attester, node_id, signed_by, session=SESSION, ek_of=None):
        nonce = attester.nonce(node_id)
        key = b"ephemeral key of boot " + bytes.fromhex(session)
        signed = self.keys[signed_by].signer(ek_name=self.keys[ek_of or signed_by].ek_name)(
            attest.qualifying_data(node_id, self.m2["epoch"], bytes.fromhex(session), key, nonce))
        return {"ephemeral_public": key.hex(), "nonce": nonce.hex(), "quote": signed["quote"], "signature": signed["sig"]}

    def test_the_attestation_policy_is_the_manifest_s(self):
        policy = replacement.attest_policy(self.m2, {n: MEASURED for n in ("a", "a2", "b", "c")}, peer_id="b")
        self.assertEqual(sorted(policy["nodes"]), ["a2", "c"])           # not the retired a, not the peer itself
        self.assertEqual(policy["nodes"]["a2"], dict(MEASURED, ek_name=self.keys["a2"].ek_name))
        before = replacement.attest_policy(self.m1, {n: MEASURED for n in ("a", "b", "c")}, peer_id="b")
        self.assertEqual(sorted(before["nodes"]), ["a", "c"])
        maintenance = self.chain(self.m2, [self.entry("a", "RETIRED"), self.entry("b"), self.entry("c", "MAINTENANCE"), self.entry("a2", "DRAINING")])
        self.assertEqual(sorted(replacement.attest_policy(maintenance, {"a2": MEASURED, "c": MEASURED}, "b")["nodes"]), ["a2", "c"])
        self.refused("no reference measurements for a2, which the manifest lets attest", replacement.attest_policy, self.m2, {"c": MEASURED}, "b")
        self.refused("measurements of c fields mismatch", replacement.attest_policy, self.m2, {"a2": MEASURED, "c": dict(MEASURED, ek_name="x")}, "b")
        self.refused("attestation policy is refused", replacement.attest_policy, self.m2, {"a2": MEASURED, "c": dict(MEASURED, pcrs={})}, "b")
        self.refused("measurements must map", replacement.attest_policy, self.m2, None)
        alone = self.chain(self.m2, [self.entry("a", "RETIRED"), self.entry("b"), self.entry("c", "QUARANTINED"), self.entry("a2", "RETIRED")])
        self.refused("leaves no node this peer could attest", replacement.attest_policy, alone, {}, "b")

    def test_poc_16_3_the_new_node_is_unlocked_holds_a_lease_and_vouches_for_others(self):
        b = self.peers["b"]
        self.assertGreater(replacement.may_unlock(self.m2, "b", "a2", SESSION, self.quote(b["attester"], "a2", "a2"), b["attester"], b["freshness"]), 0)
        request = self.new_holder.request()
        envelope = lease.issue(self.m2, "b", request, b["attester"], self.quote(b["attester"], "a2", "a2"), b["freshness"], b["signer"])
        self.assertEqual(self.new_holder.install(envelope, self.m2), 300)
        self.assertEqual(self.new_holder.check(self.m2), 300)
        self.assertTrue(m.may(self.m2, "a2", "authorize"))
        # a lease signed by a2's AK, as issuer, is good: the new node is a full peer
        by_a2 = lt.sign(dict(self.body(self.m2), node_id="c", ak_name=self.keys["c"].ak_name, issuer="a2"), self.keys["a2"])
        self.assertEqual(lease.verify(by_a2, self.m2, self.now), 300)

    def test_poc_16_5_the_old_hardware_is_refused_by_every_decision(self):
        for terminal in ("RETIRED", "REVOKED_STOLEN"):
            with self.subTest(terminal):
                self.refuse_old_hardware(self.m2 if terminal == "RETIRED" else self.chain(
                    self.m2, [self.entry("a", "REVOKED_STOLEN"), self.entry("b"), self.entry("c"), self.entry("a2")]))

    def refuse_old_hardware(self, manifest):
        if manifest is not self.m2:
            manifest = self.accept(self.m2, manifest)
            self.beat(manifest, issued=self.now)
        b = self.peers["b"]
        attester, freshness, epoch = b["attester"], b["freshness"], manifest["epoch"]
        # attestation: the peer no longer knows node a
        for call in (lambda: attester.nonce("a"), lambda: attester.challenge("a", lt.b2(b"ek"), self.keys["a"].ak_public)):
            with self.assertRaises(attest.Refused) as caught:
                call()
            self.assertIn("unknown node", str(caught.exception))
        # unlock: as itself, and as the new node with its own (old) TPM
        self.refused("a may not be unlocked under epoch %d" % epoch, replacement.may_unlock, manifest, "b", "a", OLD_SESSION, None, attester, freshness)
        self.refused("a may not authorize under epoch %d" % epoch, replacement.may_unlock, manifest, "a", "c", SESSION, None, attester, freshness)
        self.m2, saved = manifest, self.m2               # quotes below are over this manifest's epoch
        try:
            self.refused("attestation is refused: the quote's signature does not verify", replacement.may_unlock, manifest, "b", "a2", SESSION,
                         self.quote(attester, "a2", "a"), attester, freshness)
            self.refused("attestation is refused: the quote's signer is not the enrolled AK under the recorded EK", replacement.may_unlock,
                         manifest, "b", "a2", SESSION, self.quote(attester, "a2", "a2", ek_of="a"), attester, freshness)
            # leases: none issued to it, none it holds still stands, none it signs counts
            self.refused("a may not serve under epoch %d: no lease" % epoch, lease.issue, manifest, "b", self.old_holder.request(), attester, None, freshness, b["signer"])
            as_new = {"node_id": "a2", "session_id": SESSION, "nonce": "33" * 32}
            self.refused("attestation is refused: the quote's signature does not verify", lease.issue, manifest, "b", as_new, attester,
                         self.quote(attester, "a2", "a"), freshness, b["signer"])
        finally:
            self.m2 = saved
        self.refused("a may not serve under epoch %d" % epoch, self.old_holder.check, manifest)
        self.refused("a may not serve under epoch %d" % epoch, lease.verify, self.old_lease, manifest, self.now)
        body = dict(self.body(manifest), node_id="c", ak_name=self.keys["c"].ak_name)
        self.refused("a may not authorize under epoch %d" % epoch, lease.verify, lt.sign(dict(body, issuer="a"), self.keys["a"]), manifest, self.now)
        self.refused("not signed by the AK the manifest names for a2", lease.verify, lt.sign(dict(body, issuer="a2"), self.keys["a"]), manifest, self.now)
        stolen_name = dict(self.body(manifest), node_id="a2", ak_name=self.keys["a"].ak_name)
        self.refused("the lease names another AK than the manifest's for a2", lease.verify, lt.sign(stolen_name, self.keys["b"]), manifest, self.now)
        # and its own, older manifest does not come back
        self.refused("does not follow", self.accept, manifest, self.m1)

    def test_may_unlock_needs_a_fresh_quote_for_this_request(self):
        b = self.peers["b"]
        args = (b["attester"], b["freshness"])
        self.refused("has not re-attested", replacement.may_unlock, self.m2, "b", "a2", SESSION, None, *args)
        self.refused("session_id must be 64 lowercase hex", replacement.may_unlock, self.m2, "b", "a2", "x", self.quote(b["attester"], "a2", "a2"), *args)
        used = self.quote(b["attester"], "a2", "a2")
        replacement.may_unlock(self.m2, "b", "a2", SESSION, used, *args)
        self.refused("attestation is refused: the nonce is not outstanding", replacement.may_unlock, self.m2, "b", "a2", SESSION, used, *args)
        # evidence made for another session, another node, or another peer, through may_unlock itself
        self.refused("attestation is refused: the quote is not bound to this transcript", replacement.may_unlock, self.m2, "b", "a2", "0c" * 32,
                     self.quote(b["attester"], "a2", "a2"), *args)
        for_c = self.quote(b["attester"], "c", "a2")                     # the peer's nonce for c, quoted by a2's TPM
        self.refused("attestation is refused: the nonce was issued to another node", replacement.may_unlock, self.m2, "b", "a2", SESSION, for_c, *args)
        own_nonce = dict(self.quote(b["attester"], "a2", "a2"), nonce="5a" * 32)   # a nonce the requester picked itself
        self.refused("attestation is refused: the nonce is not outstanding", replacement.may_unlock, self.m2, "b", "a2", SESSION, own_nonce, *args)
        to_c = self.quote(self.peers["c"]["attester"], "a2", "a2")       # an answer to peer c's nonce, shown to b
        self.refused("attestation is refused: the nonce is not outstanding", replacement.may_unlock, self.m2, "b", "a2", SESSION, to_c, *args)
        self.assertNotIn("nonce", inspect.signature(replacement.may_unlock).parameters)   # nothing requester-chosen stands for freshness
        self.authenticated = False
        self.refused("time is not authenticated", replacement.may_unlock, self.m2, "b", "a2", SESSION, self.quote(b["attester"], "a2", "a2"), *args)
        self.authenticated = True

    def test_a_heartbeat_that_expires_during_the_attestation_gives_no_unlock(self):
        b = self.peers["b"]
        self.later(hb.MAX_LIFETIME - 120)                # the heartbeat for m2 has a minute left
        left = b["freshness"].check(self.m2)
        self.assertEqual(left, 60)
        evidence = self.quote(b["attester"], "a2", "a2")
        real = b["attester"].verify

        def slow(*args, **kw):
            self.assertEqual(kw, {"phase": "initrd"})    # a disk key is asked for from the initrd
            verdict = real(*args, **kw)
            self.later(left + 1)                         # ... and the verification outlasts it
            return verdict
        b["attester"].verify = slow
        self.refused("EXPIRED: the heartbeat expired", replacement.may_unlock, self.m2, "b", "a2", SESSION, evidence, b["attester"], b["freshness"])


class OnSwtpm(unittest.TestCase):
    """Three software TPMs: the old node a, its replacement a2, and peer b. Where the tools are provisioned
    (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""

    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools and openssl")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pids, self.tcti, self.names = [], {}, {}
        self.addCleanup(lambda: [os.kill(pid, 15) for pid in self.pids])
        for i, name in enumerate(("a", "a2", "b")):
            self.tcti[name] = self.boot(name)
            os.mkdir("%s/%s" % (self.d, name))
            self.on(name, attest.node_init, "%s/%s" % (self.d, name))
            self.names[name] = {k: attest.name_of(attest.public_area(lt.slurp("%s/%s/%s.pub" % (self.d, name, k)), k)).hex() for k in ("ek", "ak")}
        self.now = lt.T0 + 60
        self.clock = lambda: (self.now, True)
        self.m1 = self.manifest(1, "", [self.entry("a", 0), self.entry("b", 1)])
        counter = hb.Counter("0x1500018", tcti=self.tcti["b"], lock_path=self.d + "/lock")
        counter.define()
        self.freshness = hb.Freshness(counter, self.clock, hbt.simulated_ticks(self, self.tcti["b"]), self.d + "/freshness.json")
        self.sequence = 0
        self.beat(self.m1)
        self.signer = lease.TpmSigner(tcti=self.tcti["b"])
        firmware = attest.parse_quote(self.quote("a", "a", "00" * 32, "00" * 32, 1)[0])["firmware_version"]
        self.measured = {"tpm_firmware_version": firmware, "pcrs": {"7": "00" * 32}}

    def boot(self, name):
        state, sock = "%s/tpm-%s" % (self.d, name), "%s/%s.sock" % (self.d, name)
        os.makedirs(state)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
        time.sleep(0.5)
        with open("%s/%s.pid" % (self.d, name)) as f:
            self.pids.append(int(f.read()))
        return "swtpm:path=" + sock

    def on(self, tpm, fn, *args):
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI=self.tcti[tpm]):
            return fn(*args)

    def entry(self, name, n, state="ACTIVE", node_id=None):
        return {"node_id": node_id or name, "state": state, "ek_name": self.names[name]["ek"], "ak_name": self.names[name]["ak"],
                "wg_boot_pub": ("%02x" % (0x70 + n)) * 32, "wg_service_pub": ("%02x" % (0xa0 + n)) * 32, "hsm_serials": ["DENK04041%02d" % n]}

    def manifest(self, epoch, prev, nodes):
        return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-09-21T09:00:00Z",
                "revocation_keys": [hbt.pub(hbt.REVOKE)], "nodes": nodes}

    def beat(self, manifest):
        self.sequence += 1
        self.freshness.accept(hbt.beat(manifest, self.sequence, issued=self.now), manifest)

    def quote(self, tpm, node_id, session, nonce, epoch):
        """The TPM `tpm` quotes as `node_id`: its own name, or the one it pretends to."""
        paths = (self.d + "/q.msg", self.d + "/q.sig")
        self.on(tpm, attest.node_quote, node_id, epoch, bytes.fromhex(session), b"ephemeral key of boot " + bytes.fromhex(session),
                bytes.fromhex(nonce), [7], *paths)
        return tuple(lt.slurp(p) for p in paths)

    def attester(self, manifest, tag):
        measurements = {node["node_id"]: self.measured for node in manifest["nodes"]}
        return attest.Verifier(replacement.attest_policy(manifest, measurements, peer_id="b"), "%s/attest-%s.json" % (self.d, tag))

    def enroll(self, attester, node_id, tpm, ek_of=None, ak_of=None, replace=False):
        """MakeCredential for the EK and AK presented, ActivateCredential on `tpm`."""
        credential = attester.challenge(node_id, lt.slurp("%s/%s/ek.pub" % (self.d, ek_of or tpm)), lt.slurp("%s/%s/ak.pub" % (self.d, ak_of or tpm)), replace)
        cred, secret = "%s/cred-%s-%s" % (self.d, node_id, tpm), "%s/secret-%s-%s-%d" % (self.d, node_id, tpm, len(os.listdir(self.d)))
        with open(cred, "wb") as f:
            f.write(credential)
        self.on(tpm, attest.node_activate, cred, secret)
        return attester.enroll(node_id, lt.slurp(secret))

    def evidence(self, attester, tpm, node_id, session, manifest):
        nonce = attester.nonce(node_id)
        quote, signature = self.quote(tpm, node_id, session, nonce.hex(), manifest["epoch"])
        return {"ephemeral_public": (b"ephemeral key of boot " + bytes.fromhex(session)).hex(), "nonce": nonce.hex(),
                "quote": quote.hex(), "signature": signature.hex()}

    def refused(self, reason, fn, *args, error=m.Refused):
        with self.assertRaises(error) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_a_node_is_replaced_and_its_old_hardware_is_refused(self):
        root = hbt.pub(hbt.ROOT)
        # before: a is enrolled with b, unlocked, and holds a lease
        before = self.attester(self.m1, "m1")
        self.enroll(before, "a", "a")
        self.assertGreater(replacement.may_unlock(self.m1, "b", "a", OLD_SESSION, self.evidence(before, "a", "a", OLD_SESSION, self.m1), before, self.freshness), 0)
        old_holder = lease.Holder("a", OLD_SESSION, self.clock, hbt.simulated_ticks(self, self.tcti["a"]), self.d + "/a-lease.json")
        old_lease = lease.issue(self.m1, "b", old_holder.request(), before, self.evidence(before, "a", "a", OLD_SESSION, self.m1), self.freshness, self.signer)
        old_holder.install(old_lease, self.m1)

        # 16.1-16.4: one root-signed manifest retires a and enrolls a2, a new TPM
        m2 = m.accept(self.m1, sign(self.manifest(2, m.digest(self.m1), [self.entry("a", 0, "RETIRED"), self.entry("b", 1), self.entry("a2", 2)])), root)
        replacement.check_replacement(self.m1, m2, "a", "a2")
        self.beat(m2)
        after = self.attester(m2, "m2")
        self.assertEqual(sorted(after.nodes), ["a2"])

        # 16.3: a2 enrolls its AK under its EK, is unlocked, and holds a lease signed by b's TPM
        self.assertEqual(self.enroll(after, "a2", "a2").hex(), self.names["a2"]["ak"])
        self.assertGreater(replacement.may_unlock(m2, "b", "a2", SESSION, self.evidence(after, "a2", "a2", SESSION, m2), after, self.freshness), 0)
        holder = lease.Holder("a2", SESSION, self.clock, hbt.simulated_ticks(self, self.tcti["a2"]), self.d + "/a2-lease.json")
        envelope = lease.issue(m2, "b", holder.request(), after, self.evidence(after, "a2", "a2", SESSION, m2), self.freshness, self.signer)
        self.assertEqual(holder.install(envelope, m2), 300)

        # 16.5: old a, hardware intact, historical credentials valid
        self.refused("unknown node", after.nonce, "a", error=attest.Refused)                                   # it is not attested as itself
        self.refused("unknown node", after.challenge, "a", lt.slurp(self.d + "/a/ek.pub"), lt.slurp(self.d + "/a/ak.pub"), error=attest.Refused)
        self.refused("the EK is not the one recorded for this node at intake", after.challenge, "a2",          # nor as a2, with its own EK
                     lt.slurp(self.d + "/a/ek.pub"), lt.slurp(self.d + "/a/ak.pub"), error=attest.Refused)
        # nor with a2's EK and its own AK: a2's enrollment stands, and even if an operator let it be replaced,
        # the old TPM cannot open a credential made for a2's EK
        self.refused("the node already has an enrolled AK", self.enroll, after, "a2", "a", "a2", "a", error=attest.Refused)
        self.refused("this TPM does not hold the EK and AK the credential was made for", self.enroll, after, "a2", "a", "a2", "a", True, error=attest.Refused)
        self.refused("attestation is refused: the quote's signature does not verify", replacement.may_unlock, m2, "b", "a2", SESSION,
                     self.evidence(after, "a", "a2", SESSION, m2), after, self.freshness)                      # a quote from the old TPM, as a2
        self.refused("a may not be unlocked under epoch 2", replacement.may_unlock, m2, "b", "a", OLD_SESSION, None, after, self.freshness)
        self.refused("a may not serve under epoch 2: no lease", lease.issue, m2, "b", old_holder.request(), after, None, self.freshness, self.signer)
        self.refused("a may not serve under epoch 2", old_holder.check, m2)
        self.refused("a may not serve under epoch 2", lease.verify, old_lease, m2, self.now)
        vouching = {"schema": lease.SCHEMA, "node_id": "a2", "ak_name": self.names["a2"]["ak"], "issuer": "a", "epoch": 2,
                    "manifest_digest": m.digest(m2), "session_id": SESSION, "nonce": "44" * 32,
                    "issued_at": hbt.stamp(self.now), "expires_at": hbt.stamp(self.now + 300)}
        old_tpm = lease.TpmSigner(tcti=self.tcti["a"])
        self.refused("a may not authorize under epoch 2", lease.verify, {"lease": vouching, "signature": old_tpm(lease.signed_digest(vouching))}, m2, self.now)
        as_b = dict(vouching, issuer="b")
        self.refused("not signed by the AK the manifest names for b", lease.verify, {"lease": as_b, "signature": old_tpm(lease.signed_digest(as_b))}, m2, self.now)

        # recycling, with the real TPM names: the retired EK or AK under a new node ID, the tombstone dropped, the node revived
        for label, reason, nodes in (
                ("the retired EK", "already used (ek_name of a)", [self.entry("a", 0, "RETIRED"), self.entry("b", 1), self.entry("a2", 2),
                                                                   dict(self.entry("a2", 3, node_id="a3"), ek_name=self.names["a"]["ek"], ak_name="000b" + "c3" * 32)]),
                ("the retired AK", "already used (ak_name of a)", [self.entry("a", 0, "RETIRED"), self.entry("b", 1), self.entry("a2", 2),
                                                                   dict(self.entry("a2", 3, node_id="a3"), ak_name=self.names["a"]["ak"], ek_name="000b" + "c4" * 32)]),
                ("the tombstone dropped", "tombstone: a is RETIRED and must stay", [self.entry("b", 1), self.entry("a2", 2)]),
                ("the node revived", "tombstone: a is RETIRED, which is terminal for every signer", [self.entry("a", 0), self.entry("b", 1), self.entry("a2", 2)])):
            with self.subTest(label):
                self.refused(reason, m.accept, m2, sign(self.manifest(3, m.digest(m2), nodes)), root)


if __name__ == "__main__":
    unittest.main()
