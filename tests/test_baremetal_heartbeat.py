"""deploy/baremetal/heartbeat.py (#69, Phase 9): a peer authorizes only while it holds a live heartbeat for
its current manifest, judged against authenticated time, with the sequence in a TPM NV counter.

The first classes run with the TPM faked at the tpm2-tools boundary (so Counter's own code runs); the last
runs the same rollback and replay cases on swtpm."""
import copy
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m

T0 = 1790000000   # 2026-09-21T13:33:20Z
ROOT, REVOKE, OTHER = (Ed25519PrivateKey.generate() for _ in range(3))


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def node(nid, state, n):
    return {"node_id": nid, "state": state, "ek_name": "000b" + ("%02x" % (0x10 + n)) * 32,
            "ak_name": "000b" + ("%02x" % (0x40 + n)) * 32, "wg_boot_pub": ("%02x" % (0x70 + n)) * 32,
            "wg_service_pub": ("%02x" % (0xa0 + n)) * 32, "hsm_serials": ["DENK04041%02d" % n]}


def manifest(epoch=1, prev="", keys=None, **states):
    return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1",
            "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [pub(REVOKE)] if keys is None else keys,
            "nodes": [node(n, states.get(n, "ACTIVE"), i) for i, n in enumerate(("a", "b", "c"))]}


def beat(man, sequence, issued=T0, lifetime=hb.MAX_LIFETIME, key=REVOKE, domain=hb.DOMAIN, **override):
    body = {"schema": hb.SCHEMA, "epoch": man["epoch"], "sequence": sequence, "issued_at": stamp(issued),
            "expires_at": stamp(issued + lifetime), "manifest_digest": m.digest(man)}
    body.update(override)
    return {"heartbeat": body, "signature": {"key": pub(key), "sig": key.sign(domain + m.canonical(body)).hex()}}


class FakeTpm:
    """tpm2-tools as Counter calls them: NV counters with the real first-increment rule."""

    def __init__(self):
        self.counters, self.highest_deleted, self.broken = {}, 0, False

    def __call__(self, argv, **kw):
        tool, index = argv[0], argv[1]
        ok = lambda out=b"": subprocess.CompletedProcess(argv, 0, out, b"")
        if self.broken or (tool != "tpm2_nvdefine" and index not in self.counters):
            return subprocess.CompletedProcess(argv, 1, b"", b"the TPM said no")
        if tool == "tpm2_nvdefine":
            self.counters[index] = None
            return ok()
        value = self.counters[index]
        if tool == "tpm2_nvreadpublic":
            flags = "ownerwrite|authwrite|nt=0x1|ownerread|authread" + ("" if value is None else "|written")
            return ok(("%s:\n  attributes:\n    friendly: %s\n    value: 0x60016\n  size: 8\n" % (index, flags)).encode())
        if tool == "tpm2_nvread":
            return ok(value.to_bytes(8, "big")) if value is not None else subprocess.CompletedProcess(argv, 1, b"", b"0x14a")
        if tool == "tpm2_nvincrement":
            self.counters[index] = self.highest_deleted + 1 if value is None else value + 1
            return ok()
        raise AssertionError(argv)


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.counter = hb.Counter("0x1500017", run=self.tpm)
        self.counter.define()
        self.now, self.authenticated, self.ticks = T0 + 60, True, 5000
        self.state = os.path.join(self.d, "freshness.json")
        self.f = hb.Freshness(self.counter, lambda: (self.now, self.authenticated), lambda: self.ticks, self.state)
        self.m1 = manifest()

    def later(self, seconds):
        """Real time and the TPM clock both move on."""
        self.now += seconds
        self.ticks += seconds * 1000

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Heartbeats(Case):
    def test_a_live_heartbeat_for_the_current_manifest_lets_the_peer_authorize(self):
        self.refused("no heartbeat is held", self.f.check, self.m1)
        self.assertEqual(self.f.accept(beat(self.m1, 1), self.m1), hb.MAX_LIFETIME - 60)
        self.assertEqual(self.counter.value(), 1)
        self.later(3600)
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 3660)
        self.assertEqual(hb.authorize(self.m1, "b", "a", self.f), hb.MAX_LIFETIME - 3660)

    def test_it_expires(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME - 61)
        self.assertEqual(self.f.check(self.m1), 1)
        self.later(1)
        self.refused("EXPIRED", self.f.check, self.m1)
        self.refused("EXPIRED", hb.authorize, self.m1, "b", "a", self.f)
        self.refused("EXPIRED", self.f.accept, beat(self.m1, 2), self.m1)                  # an old one, never seen: still expired
        self.assertEqual(self.counter.value(), 1)
        self.f.accept(beat(self.m1, 2, issued=self.now - 10), self.m1)                      # the next one restores it
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 10)

    def test_a_heartbeat_lives_at_most_24_hours_whatever_the_signer_wrote(self):
        self.refused("at most 24 hours", self.f.accept, beat(self.m1, 1, lifetime=hb.MAX_LIFETIME + 1), self.m1)
        self.refused("expires_at must be after issued_at", self.f.accept, beat(self.m1, 1, lifetime=0), self.m1)
        self.refused("issued in the future", self.f.accept, beat(self.m1, 1, issued=self.now + hb.FUTURE_SKEW + 1), self.m1)
        self.f.accept(beat(self.m1, 1, issued=self.now + hb.FUTURE_SKEW), self.m1)

    def test_a_heartbeat_for_another_manifest_is_refused(self):
        m2 = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        other_same_epoch = manifest(c="DRAINING")
        self.refused("for epoch 2, the current manifest is epoch 1", self.f.accept, beat(m2, 1), self.m1)
        self.refused("another manifest (digest mismatch)", self.f.accept, beat(other_same_epoch, 1), self.m1)
        self.refused("another manifest (digest mismatch)", self.f.accept, beat(self.m1, 1, manifest_digest="00" * 32), self.m1)
        self.assertEqual(self.counter.value(), 0)
        self.assertFalse(os.path.exists(self.state))

    def test_poc_9_4_a_peer_that_moved_to_a_new_epoch_needs_a_heartbeat_for_it(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        m2 = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.refused("for epoch 1, the current manifest is epoch 2", self.f.check, m2)
        self.refused("for epoch 1", hb.authorize, m2, "b", "c", self.f)
        self.f.accept(beat(m2, 2), m2)
        self.assertGreater(hb.authorize(m2, "b", "c", self.f), 0)
        self.refused("for epoch 2, the current manifest is epoch 1", self.f.check, self.m1)   # and the old manifest is not served by it

    def test_only_a_revocation_key_named_by_the_current_manifest_signs_heartbeats(self):
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(self.m1, 1, key=OTHER), self.m1)
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(self.m1, 1, key=ROOT), self.m1)
        # the root replaced the revocation key: the old key's heartbeats stop counting, held or new
        self.f.accept(beat(self.m1, 1), self.m1)
        m2 = manifest(2, m.digest(self.m1), keys=[pub(OTHER)])
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(m2, 2), m2)
        self.f.accept(beat(m2, 2, key=OTHER), m2)
        dropped = manifest(3, m.digest(m2), keys=[])
        self.refused("not a revocation key named by the current manifest", self.f.check, dropped)

    def test_a_signature_must_be_over_this_heartbeat_under_the_heartbeat_domain(self):
        good = beat(self.m1, 1)
        altered = copy.deepcopy(good)
        altered["heartbeat"]["expires_at"] = stamp(T0 + hb.MAX_LIFETIME - 1)
        self.refused("signature does not verify", self.f.accept, altered, self.m1)
        self.refused("signature does not verify", self.f.accept, beat(self.m1, 1, domain=m.DOMAIN), self.m1)
        self.refused("signature does not verify", self.f.accept, beat(self.m1, 1, domain=b""), self.m1)
        self.assertNotEqual(hb.DOMAIN, m.DOMAIN)

    def test_malformed_heartbeats_are_refused(self):
        good = beat(self.m1, 1)
        for label, reason, change in (
                ("unknown field", "fields mismatch", lambda e: e["heartbeat"].update(note="x")),
                ("missing field", "fields mismatch", lambda e: e["heartbeat"].pop("sequence")),
                ("schema", "schema must be", lambda e: e["heartbeat"].update(schema="regalia.heartbeat/v0")),
                ("sequence 0", "sequence must be an integer >= 1", lambda e: e["heartbeat"].update(sequence=0)),
                ("sequence true", "sequence must be an integer >= 1", lambda e: e["heartbeat"].update(sequence=True)),
                ("epoch text", "epoch must be an integer >= 1", lambda e: e["heartbeat"].update(epoch="1")),
                ("local time", "issued_at must be UTC", lambda e: e["heartbeat"].update(issued_at="2026-09-21T13:33:20+02:00")),
                ("no such date", "expires_at is not a real date", lambda e: e["heartbeat"].update(expires_at="2026-02-30T00:00:00Z")),
                ("digest", "manifest_digest must be 64 lowercase hex", lambda e: e["heartbeat"].update(manifest_digest="AB" * 32)),
                ("signer field", "signature fields mismatch", lambda e: e["signature"].update(signer="revocation")),
                ("short signature", "signature.sig must be 128 lowercase hex", lambda e: e["signature"].update(sig="00")),
                ("envelope", "envelope fields mismatch", lambda e: e.update(manifest={}))):
            with self.subTest(label):
                envelope = copy.deepcopy(good)
                change(envelope)
                self.refused(reason, self.f.accept, envelope, self.m1)
        self.refused("envelope must be an object", self.f.accept, [good], self.m1)


class Time(Case):
    def test_unauthenticated_time_fails_closed(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.f.accept, beat(self.m1, 1), self.m1)
        self.assertEqual(self.counter.value(), 0)
        self.authenticated = True
        self.f.accept(beat(self.m1, 1), self.m1)
        self.authenticated = False
        self.refused("time is not authenticated", self.f.check, self.m1)
        self.refused("time is not authenticated", hb.authorize, self.m1, "b", "a", self.f)
        for not_true in (1, "yes", None):   # only the value True authenticates
            self.authenticated = not_true
            self.refused("time is not authenticated", self.f.check, self.m1)
        self.authenticated = True
        self.assertGreater(self.f.check(self.m1), 0)

    def test_the_clock_going_backwards_is_refused(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(7200)
        self.f.check(self.m1)
        self.now -= 3600                         # the time source now says an hour earlier; the TPM clock did not move
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.refused("the clock went backwards", self.f.accept, beat(self.m1, 2), self.m1)
        self.now += 3600
        self.assertGreater(self.f.check(self.m1), 0)

    def test_an_expired_heartbeat_cannot_be_revived_by_setting_the_clock_back(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME)
        self.refused("EXPIRED", self.f.check, self.m1)
        self.now = T0 + 120                      # back to when the heartbeat was live
        self.refused("the clock went backwards", self.f.check, self.m1)

    def test_the_tpm_clock_raises_the_floor_between_checks(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.ticks += 1000 * 1000                # the TPM counted 1000 s; the time source claims only 100 s passed
        self.now += 100
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += 750 - 100                    # 85% of the TPM's 1000 s is the floor; 5 s of step-back are allowed
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += 100
        self.assertGreater(self.f.check(self.m1), 0)

    def test_a_small_correction_and_a_tpm_clock_reset_are_tolerated(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.now -= hb.STEP_BACK                 # an NTP correction
        self.assertGreater(self.f.check(self.m1), 0)
        self.now -= 1                            # the floor did not follow the correction down
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += hb.STEP_BACK + 1
        self.ticks = 3                           # the TPM clock restarted low (a power loss, a cleared TPM)
        self.later(600)
        self.assertGreater(self.f.check(self.m1), 0)
        self.now -= 300                          # and the floor still holds from the last reading
        self.refused("the clock went backwards", self.f.check, self.m1)

    def test_a_clock_that_returns_no_time_is_refused(self):
        for bad in (None, "1790000000", -1, True):
            with self.subTest(bad=bad):
                self.now = bad
                self.refused("the clock returned no time", self.f.check, self.m1)


class Sequence(Case):
    def test_a_sequence_at_or_below_the_counter_is_refused(self):
        self.f.accept(beat(self.m1, 5), self.m1)
        self.assertEqual(self.counter.value(), 5)
        with open(self.state, "rb") as f:
            before = f.read()
        self.refused("REPLAY: sequence 5 is not above the TPM counter 5", self.f.accept, beat(self.m1, 5, issued=T0 + 30), self.m1)
        self.refused("REPLAY: sequence 4 is not above the TPM counter 5", self.f.accept, beat(self.m1, 4), self.m1)
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)   # a refused heartbeat never reaches the disk
        # and the counter itself refuses, whoever calls it
        self.refused("REPLAY: sequence 5 is not above the TPM counter 5", self.counter.advance, 5)
        self.refused("REPLAY: sequence 1 is not above the TPM counter 5", self.counter.advance, 1)
        self.refused("sequence jump 1001 exceeds the bound 1000: anomaly", self.counter.advance, 1006)
        self.assertEqual(self.counter.value(), 5)
        self.assertEqual(self.f.accept(beat(self.m1, 6), self.m1), hb.MAX_LIFETIME - 60)
        self.assertEqual(self.counter.value(), 6)

    def test_a_disk_rolled_back_to_an_older_heartbeat_is_refused_by_the_counter(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            snapshot = f.read()
        self.later(600)
        self.f.accept(beat(self.m1, 2, issued=self.now), self.m1)
        with open(self.state, "wb") as f:
            f.write(snapshot)                    # the disk restored; heartbeat 1 is still signed and unexpired
        self.refused("ROLLBACK: the heartbeat on disk is sequence 1 but the TPM counter is 2", self.f.check, self.m1)
        self.refused("ROLLBACK", hb.authorize, self.m1, "b", "a", self.f)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 1), self.m1)                    # nor can it be fed in again
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2, issued=self.now), self.m1)   # the lost one is gone too
        self.f.accept(beat(self.m1, 3, issued=self.now), self.m1)                           # recovery: the next heartbeat
        self.assertGreater(self.f.check(self.m1), 0)

    def test_a_crash_between_the_disk_and_the_counter_is_finished_by_the_next_check(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        real = self.counter.advance
        self.counter.advance = lambda sequence: (_ for _ in ()).throw(OSError("power lost"))
        with self.assertRaises(OSError):
            self.f.accept(beat(self.m1, 2), self.m1)
        self.counter.advance = real
        self.assertEqual(self.counter.value(), 1)          # the disk holds 2, the counter 1
        self.assertGreater(self.f.check(self.m1), 0)
        self.assertEqual(self.counter.value(), 2)          # finished
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2), self.m1)

    def test_an_anomalous_jump_is_refused_and_nothing_is_written(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            before = f.read()
        self.refused("exceeds the bound 1000: anomaly", self.f.accept, beat(self.m1, 1002), self.m1)
        self.assertEqual(self.counter.value(), 1)
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)
        self.f.accept(beat(self.m1, 1001), self.m1)
        self.assertEqual(self.counter.value(), 1001)

    def test_a_tpm_failure_is_never_read_as_zero(self):
        self.f.accept(beat(self.m1, 3), self.m1)
        self.tpm.broken = True
        self.refused("cannot be read", self.counter.value)
        self.refused("cannot be read", self.f.check, self.m1)
        self.refused("cannot be read", self.f.accept, beat(self.m1, 4), self.m1)
        self.tpm.broken = False
        self.refused("cannot be read", hb.Counter("0x1500099", run=self.tpm).value)   # an index nobody defined
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 60)

    def test_only_a_counter_index_counts(self):
        def ordinary(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, b"0x1500017:\n  attributes:\n    friendly: ownerwrite|ownerread|written\n", b"")
        self.refused("is not a counter", hb.Counter("0x1500017", run=ordinary).value)
        self.refused("unexpected tpm2_nvreadpublic output", hb.Counter("0x1500017", run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b"")).value)

    def test_a_counter_cannot_be_rewound_by_deleting_it(self):
        """A TPM starts a new counter above the highest value any deleted counter held."""
        self.tpm.highest_deleted = 40
        fresh = hb.Counter("0x1500020", run=self.tpm)
        fresh.define()
        self.assertEqual(fresh.value(), 0)
        f = hb.Freshness(fresh, lambda: (self.now, True), lambda: self.ticks, os.path.join(self.d, "f2.json"))
        self.refused("already past sequence 7", f.accept, beat(self.m1, 7), self.m1)
        self.assertEqual(fresh.value(), 41)
        self.refused("REPLAY", f.accept, beat(self.m1, 41), self.m1)
        f.accept(beat(self.m1, 42), self.m1)

    def test_a_counter_that_does_not_move_is_refused(self):
        stuck = FakeTpm()
        counter = hb.Counter("0x1500017", run=lambda argv, **kw: stuck(argv) if argv[0] != "tpm2_nvincrement" else subprocess.CompletedProcess(argv, 0, b"", b""))
        counter.define()
        self.refused("did not advance", counter.advance, 1)
        stuck.broken = True
        self.refused("cannot define", counter.define)

    def test_a_failed_increment_or_read_of_a_written_counter_is_a_refusal(self):
        self.counter.advance(2)

        def failing(tool, result):
            return lambda argv, **kw: result(argv) if argv[0] == tool else self.tpm(argv)
        no = lambda argv: subprocess.CompletedProcess(argv, 1, b"", b"no")
        short = lambda argv: subprocess.CompletedProcess(argv, 0, b"\x00\x02", b"")
        self.refused("cannot increment the NV counter", hb.Counter("0x1500017", run=failing("tpm2_nvincrement", no)).advance, 3)
        self.refused("cannot be read", hb.Counter("0x1500017", run=failing("tpm2_nvread", no)).value)
        self.refused("cannot be read", hb.Counter("0x1500017", run=failing("tpm2_nvread", short)).value)
        self.assertEqual(self.counter.value(), 2)


class State(Case):
    def test_the_state_file_is_strict_and_small(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state) as f:
            good = json.load(f)
        self.assertEqual(sorted(good), ["envelope", "floor"])
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        for label, reason, doc in (("unknown field", "freshness state fields mismatch", dict(good, extra=1)),
                                   ("floor field", "floor fields mismatch", dict(good, floor={"time": 1})),
                                   ("negative floor", "floor must be integers", dict(good, floor={"time": -1, "tpm_clock": 0})),
                                   ("float floor", "floats are not allowed", None)):
            with self.subTest(label):
                with open(self.state, "w") as f:
                    f.write(json.dumps(doc) if doc else '{"envelope": null, "floor": {"time": 1.5, "tpm_clock": 0}}')
                self.refused(reason, self.f.check, self.m1)
        with open(self.state, "w") as f:
            f.write(" " * (hb.MAX_BYTES + 1))
        self.refused("oversized", self.f.check, self.m1)

    def test_a_floor_lowered_on_disk_only_weakens_the_floor_never_the_expiry(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME)
        with open(self.state) as f:
            state = json.load(f)
        state["floor"] = None
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.refused("EXPIRED", self.f.check, self.m1)

    def test_the_state_is_durable_before_the_counter_moves(self):
        order = []
        real_fsync, real_advance = os.fsync, self.counter.advance
        self.counter.advance = lambda sequence: (order.append("counter"), real_advance(sequence))[1]
        with unittest.mock.patch.object(hb.os, "fsync", side_effect=lambda fd: (order.append("dir" if os.path.isdir("/proc/self/fd/%d" % fd) else "file"), real_fsync(fd))[1]):
            self.f.accept(beat(self.m1, 1), self.m1)
        self.assertEqual(order, ["file", "dir", "counter"])


class Decision(Case):
    """hb.authorize: the membership matrix and the freshness, together (PoC 9.1 and 9.3, in software)."""

    def test_poc_9_1_a_revoked_node_is_not_unlocked_by_a_current_peer(self):
        revoked = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.f.accept(beat(revoked, 1), revoked)
        self.refused("a may not be unlocked under epoch 2", hb.authorize, revoked, "b", "a", self.f)
        self.assertGreater(hb.authorize(revoked, "b", "c", self.f), 0)

    def test_poc_9_3_a_revoked_or_non_active_peer_authorizes_nobody(self):
        for state in ("REVOKED_STOLEN", "RETIRED", "QUARANTINED", "MAINTENANCE", "DRAINING"):
            with self.subTest(state=state):
                man = manifest(2, m.digest(self.m1), a=state)
                self.refused("a may not authorize under epoch 2", hb.authorize, man, "a", "b", self.f)
        self.refused("z may not authorize", hb.authorize, self.m1, "z", "a", self.f)
        self.refused("z may not be unlocked", hb.authorize, self.m1, "b", "z", self.f)

    def test_a_node_does_not_authorize_itself_and_an_eligible_pair_still_needs_freshness(self):
        self.refused("no heartbeat is held", hb.authorize, self.m1, "b", "a", self.f)
        self.f.accept(beat(self.m1, 1), self.m1)
        self.refused("a node does not authorize itself", hb.authorize, self.m1, "b", "b", self.f)
        maintenance = manifest(c="MAINTENANCE")
        self.f2 = hb.Freshness(self.counter, lambda: (self.now, True), lambda: self.ticks, self.state)
        self.f2.accept(beat(maintenance, 2), maintenance)
        self.assertGreater(hb.authorize(maintenance, "b", "c", self.f2), 0)   # a node in MAINTENANCE may be unlocked


class OnSwtpm(unittest.TestCase):
    """The real Counter and TpmClock on a software TPM, on a private unix socket. Where the TPM tools are
    provisioned (REGALIA_EXPECT_SWTPM=1: e2e/heartbeat-swtpm.sh, CI) a missing one is a failure, not a skip."""

    def setUp(self):
        if not (shutil.which("swtpm") and shutil.which("tpm2_nvdefine") and shutil.which("tpm2_readclock")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm and tpm2-tools are expected here and were not found")
            self.skipTest("needs swtpm and tpm2-tools")
        self.d = tempfile.mkdtemp(dir="/tmp")   # short: a unix socket path is at most 107 bytes
        self.addCleanup(shutil.rmtree, self.d, True)
        os.mkdir(self.d + "/tpm")
        sock = self.d + "/s"
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d + "/tpm", "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=" + self.d + "/pid"], check=True, capture_output=True)
        time.sleep(0.5)
        with open(self.d + "/pid") as f:
            self.addCleanup(os.kill, int(f.read()), 15)
        self.tcti = "swtpm:path=" + sock
        self.epochs = m.HighWater("0x1500016", tcti=self.tcti)
        self.epochs.define()
        self.counter = hb.Counter("0x1500017", tcti=self.tcti)
        self.counter.define()
        self.now = T0 + 60
        self.state = self.d + "/freshness.json"
        self.f = hb.Freshness(self.counter, lambda: (self.now, True), hb.TpmClock(tcti=self.tcti), self.state)
        self.m1 = manifest()

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_the_sequence_counter_is_its_own_index_and_refuses_replay_and_rollback(self):
        self.assertEqual(self.counter.value(), 0)
        self.epochs.advance(3)                                  # the epoch counter moves on its own
        self.assertEqual(self.counter.value(), 0)
        self.assertEqual(self.f.accept(beat(self.m1, 1), self.m1), hb.MAX_LIFETIME - 60)
        with open(self.state, "rb") as f:
            snapshot = f.read()
        self.f.accept(beat(self.m1, 4), self.m1)                # a missed heartbeat or two: the counter is raised to 4
        self.assertEqual(self.counter.value(), 4)
        self.assertEqual(self.epochs.value(), 3)
        self.refused("REPLAY: sequence 4 is not above the TPM counter 4", self.f.accept, beat(self.m1, 4), self.m1)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2), self.m1)
        with open(self.state, "wb") as f:
            f.write(snapshot)                                   # the disk rolled back to heartbeat 1
        self.refused("ROLLBACK: the heartbeat on disk is sequence 1 but the TPM counter is 4", self.f.check, self.m1)
        self.f.accept(beat(self.m1, 5), self.m1)
        self.assertGreater(hb.authorize(self.m1, "b", "a", self.f), 0)

    def test_the_counter_survives_a_tpm_restart_and_cannot_be_rewound_by_deleting_it(self):
        self.f.accept(beat(self.m1, 7), self.m1)
        env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        subprocess.run(["tpm2_shutdown", "-c"], check=True, capture_output=True, env=env)
        subprocess.run(["tpm2_startup", "-c"], check=True, capture_output=True, env=env)
        self.assertEqual(self.counter.value(), 7)
        subprocess.run(["tpm2_nvundefine", "0x1500017", "-C", "o"], check=True, capture_output=True, env=env)
        self.refused("cannot be read", self.f.check, self.m1)   # no counter: no decision
        self.counter.define()
        self.assertEqual(self.counter.value(), 0)               # it reads as new,
        self.refused("already past sequence 3", self.f.accept, beat(self.m1, 3), self.m1)   # but it will not count from below
        self.assertGreater(self.counter.value(), 7)

    def test_the_tpm_clock_runs_forward_and_an_unreachable_tpm_is_a_refusal(self):
        clock = hb.TpmClock(tcti=self.tcti)
        first = clock()
        time.sleep(0.3)
        self.assertGreater(clock(), first)
        self.f.accept(beat(self.m1, 1), self.m1)
        self.now -= 3600
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.refused("the TPM clock cannot be read", hb.TpmClock(tcti="swtpm:path=" + self.d + "/absent"))
        self.refused("cannot be read", hb.Counter("0x1500017", tcti="swtpm:path=" + self.d + "/absent").value)


if __name__ == "__main__":
    unittest.main()
