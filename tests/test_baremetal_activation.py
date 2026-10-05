"""deploy/baremetal/activation.py (#432): activation by quorum. Two of the three nodes normally (any two such pairs
share a node, whose grant record refuses an overlap); the owner only on the recovery path, with the other node
parties stopped in the current manifest, never alone; each node's grant record counted on its TPM, standing only
while it matches, and busy for the recovery wait after a start without it."""
import os
import pathlib
import re
import shutil
import tempfile
import threading
import time
import unittest

from deploy.baremetal import activation as act, beat, heartbeat, lease as runtime_lease, membership as m
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, STRANGER, manifest4, nodes4, p256_sig, pub

T0 = 1790000000
RULE = {"threshold": 2, "parties": ["a", "b", "c", m.OWNER]}       # genesis's (manifest.py)


stamp = beat.stamp


def lease(man, **over):
    out = {"schema": act.SCHEMA, "node_id": "a", "site": "site-a", "registry_digest": "sha256:" + "ab" * 32,
           "activation_epoch": 7, "manifest_epoch": man["epoch"], "manifest_digest": m.digest(man),
           "not_before": stamp(T0), "expires_at": stamp(T0 + 600)}
    out.update(over)
    return out


def signed(body, *parties):
    raw = act.message(body)
    sigs = []
    for party in parties:
        if party == m.OWNER:
            sigs.append({"party": m.OWNER, "key": pub(OWNER_KEYS[0]), "sig": OWNER_KEYS[0].sign(raw).hex()})
        else:
            sigs.append({"party": party, "key": pub(NODE_KEYS[party]), "sig": p256_sig(NODE_KEYS[party], raw)})
    return {"lease": body, "signatures": sigs}


class Case(unittest.TestCase):
    def setUp(self):
        self.m1 = manifest4(1, "", nodes4(), activation_signers=dict(RULE))

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Format(Case):
    def test_its_own_domain_and_the_one_bound_shared_with_the_go_gate(self):
        raw = act.message(lease(self.m1))
        self.assertTrue(raw.startswith(b"regalia-activation/v2\0"))
        for other in (m.DOMAIN, heartbeat.DOMAIN, runtime_lease.DOMAIN):
            self.assertFalse(raw.startswith(other))
        gate = (pathlib.Path(__file__).resolve().parents[1] / "internal" / "fencing" / "gate.go").read_text()
        minutes = int(re.search(r"const MaxLeaseDuration = (\d+) \* time\.Minute", gate).group(1))
        self.assertEqual(act.MAX_LEASE_S, minutes * 60)
        self.assertEqual(act.RECOVERY_WAIT_S, max(act.MAX_LEASE_S, runtime_lease.MAX_LIFETIME) + act.SKEW_S)

    def test_what_a_lease_may_not_be(self):
        cases = [("lives at most 600", dict(expires_at=stamp(T0 + 601))), ("expires_at must be after", dict(expires_at=stamp(T0))),
                 ("site must be a registry site", dict(site="a")), ("registry_digest must be", dict(registry_digest="ab" * 32)),
                 ("activation_epoch must be", dict(activation_epoch=0)), ("activation_epoch must be", dict(activation_epoch=True)),
                 ("recovery.fenced must be printable", dict(recovery={"fenced": "x" * 513, "quarantine_epoch": 1})),
                 ("recovery.fenced must be printable", dict(recovery={"fenced": "off\n", "quarantine_epoch": 1})),
                 ("the quarantine epoch is above", dict(recovery={"fenced": "b and c off until epoch 2", "quarantine_epoch": 2}))]
        for reason, over in cases:
            with self.subTest(reason):
                self.refused(reason, act.validate, lease(self.m1, **over))


class Quorum(Case):
    def test_two_of_the_three_nodes_activate_and_one_never_does(self):
        body = lease(self.m1)
        self.assertEqual(act.verify(signed(body, "a", "b"), self.m1), body)
        self.assertEqual(act.verify(signed(body, "b", "c"), self.m1), body)        # the subject need not sign
        self.refused("1 of the nodes signed (a); activation needs 2", act.verify, signed(body, "a"), self.m1)

    def test_the_owner_counts_only_on_the_recovery_path(self):
        body = lease(self.m1)
        self.refused("counts only on the recovery path", act.verify, signed(body, "a", m.OWNER), self.m1)
        self.refused("the owner alone never activates", act.verify, signed(lease(self.m1, recovery={"fenced": "x", "quarantine_epoch": 1}), m.OWNER), self.m1)
        self.refused("a recovery block without the owner", act.verify,
                     signed(lease(self.m1, recovery={"fenced": "x", "quarantine_epoch": 1}), "a", "b"), self.m1)

    def test_recovery_needs_every_other_node_party_stopped_in_the_current_manifest(self):
        """{a, b} and {c, owner} do not intersect: the owner's path is open only once a and b no longer count."""
        rec = {"fenced": "a and b are powered off and will not rejoin until they hold epoch 2", "quarantine_epoch": 2}
        m2 = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        body = lease(m2, node_id="c", site="site-c", recovery=rec)
        self.assertEqual(act.verify(signed(body, "c", m.OWNER), m2)["node_id"], "c")
        m2b = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), activation_signers=dict(RULE))
        body = lease(m2b, node_id="c", site="site-c", recovery=rec)
        self.refused("b is not", act.verify, signed(body, "c", m.OWNER), m2b)

    def test_an_older_lease_is_counted_under_the_current_signers(self):
        """No serving gap at an epoch change; a node the current manifest stopped counting is not counted."""
        body = lease(self.m1)
        m2 = manifest4(2, m.digest(self.m1), nodes4(), activation_signers=dict(RULE))
        self.assertEqual(act.verify(signed(body, "a", "b"), m2), body)
        m2q = manifest4(2, m.digest(self.m1), nodes4(b="QUARANTINED"), activation_signers=dict(RULE))
        self.refused("activation needs 2", act.verify, signed(body, "a", "b"), m2q)
        self.refused("newer than this node's 1", act.verify, signed(lease(m2), "a", "b"), self.m1)
        other = manifest4(1, "", nodes4(c="DRAINING"), activation_signers=dict(RULE))
        self.refused("another manifest at epoch 1", act.verify, signed(lease(other), "a", "b"), self.m1)

    def test_a_forged_or_foreign_signature_is_refused_never_counted(self):
        body = lease(self.m1)
        env = signed(body, "a", "b")
        env["signatures"][1] = dict(env["signatures"][1], key=pub(STRANGER), sig=p256_sig(STRANGER, act.message(body)))
        with self.assertRaises(m.Refused):
            act.verify(env, self.m1)
        heartbeat_sig = signed(body, "a", "b")
        heartbeat_sig["signatures"][1]["sig"] = p256_sig(NODE_KEYS["b"], heartbeat.DOMAIN + m.canonical(body))
        with self.assertRaises(m.Refused):
            act.verify(heartbeat_sig, self.m1)


class Counter:
    def __init__(self, value=0, absent=False):
        self.v, self.absent = value, absent

    def value(self):
        if self.absent:
            raise m.Refused("cannot read NV index 0x1500019: the index is not defined")
        return self.v

    def advance(self, n, allowance=None):
        assert n > self.v and n - self.v <= (allowance or 1)
        self.v = n


class Record(Case):
    def setUp(self):
        super().setUp()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.path = os.path.join(self.d, "activation-grant.json")

    def granted(self, counter, started=T0 - 3600):
        rec = act.GrantRecord(counter, self.path, started)
        _, expires = rec.check(lease(self.m1), T0)
        rec.record(lease(self.m1), expires)
        return rec

    def test_a_grant_is_counted_recorded_and_then_binds_the_next(self):
        counter = Counter()
        rec = self.granted(counter)
        self.assertEqual(counter.v, 1)
        self.assertEqual(rec.state(T0)[0], {"grants": 1, "activation_epoch": 7, "site": "site-a", "node_id": "a", "expires_at": T0 + 600})
        self.refused("an epoch is granted once", rec.check, lease(self.m1), T0 + 10)
        rec.check(lease(self.m1, activation_epoch=8, not_before=stamp(T0 + 10), expires_at=stamp(T0 + 610)), T0 + 10)   # same site: may overlap
        self.refused("OVERLAP: this node granted site site-a on a until", rec.check,
                     lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(T0 + 300), expires_at=stamp(T0 + 900)), T0 + 300)
        # past the expiry but within the skew margin: still refused (the two Gates' clocks differ); after it, granted
        self.refused("skew margin", rec.check, lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(T0 + 600),
                                                     expires_at=stamp(T0 + 1200)), T0 + 600)
        free = T0 + 600 + act.SKEW_S
        rec.check(lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(free), expires_at=stamp(free + 600)), free)

    def test_the_same_site_on_another_node_is_a_second_signer_not_a_renewal(self):
        """d9: a lease for site S on node a and one for S on node c are two active signers for one key."""
        rec = self.granted(Counter())                       # site-a on a, until T0 + 600
        self.refused("OVERLAP", rec.check, lease(self.m1, node_id="c", activation_epoch=8, not_before=stamp(T0 + 60),
                                                  expires_at=stamp(T0 + 660)), T0 + 60)
        rec.check(lease(self.m1, activation_epoch=8, not_before=stamp(T0 + 60), expires_at=stamp(T0 + 660)), T0 + 60)   # renewal: a, site-a

    def test_a_record_that_does_not_stand_makes_the_node_busy_for_the_wait(self):
        counter = Counter()
        self.granted(counter)
        counter.v = 2                                         # the disk restored to an older record: 1 grant, the TPM says 2
        later = act.GrantRecord(counter, self.path, started=T0 + 100)
        self.refused("does not stand", later.check, lease(self.m1, activation_epoch=8, not_before=stamp(T0 + 200), expires_at=stamp(T0 + 800)), T0 + 200)
        free = T0 + 100 + act.RECOVERY_WAIT_S
        later.check(lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(free), expires_at=stamp(free + 600)), free)
        os.unlink(self.path)                                  # and lost: the same
        self.refused("does not stand", act.GrantRecord(counter, self.path, started=free).check,
                     lease(self.m1, activation_epoch=9, not_before=stamp(free), expires_at=stamp(free + 600)), free)

    def test_a_node_that_never_granted_waits_too_and_an_absent_index_signs_nothing(self):
        rec = act.GrantRecord(Counter(), self.path, started=T0)
        self.refused("does not stand", rec.check, lease(self.m1), T0)
        rec2 = act.GrantRecord(Counter(absent=True), self.path, started=T0 - 3600)
        self.refused("the index is not defined", rec2.check, lease(self.m1), T0)

    def test_time_bounds(self):
        rec = act.GrantRecord(Counter(), self.path, started=T0 - 3600)
        self.refused("ahead of this node's authenticated time", rec.check, lease(self.m1, not_before=stamp(T0 + 61), expires_at=stamp(T0 + 600)), T0)
        self.refused("already expired", rec.check, lease(self.m1), T0 + 600)


class SignerSide(Record):
    def test_the_signer_checks_its_key_its_rule_and_its_manifest_then_records_then_signs(self):
        counter = Counter()
        rec = act.GrantRecord(counter, self.path, started=T0 - 3600)
        signer = act.Signer("a", rec, lambda raw: p256_sig(NODE_KEYS["a"], raw), pub(NODE_KEYS["a"]))
        sig = signer(lease(self.m1), self.m1, T0)
        self.assertEqual((sig["party"], counter.v), ("a", 1))
        self.assertEqual(act.verify({"lease": lease(self.m1), "signatures": [sig, signed(lease(self.m1), "b")["signatures"][0]]}, self.m1)["site"], "site-a")
        wrong = act.Signer("a", rec, lambda raw: "00", pub(STRANGER))
        self.refused("this node's signing key is not", wrong, lease(self.m1, activation_epoch=8), self.m1, T0)
        m2 = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), activation_signers=dict(RULE))
        self.refused("does not count toward activation", signer, lease(m2, activation_epoch=8), m2, T0)
        self.refused("only for its own current manifest", signer, lease(self.m1, activation_epoch=8),
                     manifest4(2, m.digest(self.m1), nodes4(), activation_signers=dict(RULE)), T0)
        self.assertEqual(counter.v, 1)                        # nothing refused moved the counter


class Issuance(Record):
    """The proposer is the node to be activated; one other node co-signs over sync, after its own checks."""

    def node(self, name, counter=None, started=T0 - 3600):
        path = os.path.join(self.d, "%s-grant.json" % name)
        rec = act.GrantRecord(counter or Counter(), path, started)
        return act.Signer(name, rec, lambda raw, k=NODE_KEYS[name]: p256_sig(k, raw), pub(NODE_KEYS[name]))

    def clock(self, at=T0, authenticated=True):
        return lambda: (at, authenticated)

    def test_a_node_proposes_its_own_activation_and_a_peer_co_signs_it(self):
        a, b = self.node("a"), self.node("b")
        events = []

        def ask(peer, body):
            return act.cosign(self.m1, peer, "a", body, self.clock(), b, lambda: True)
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, ask, ["b"], events.append)
        self.assertEqual([s["party"] for s in env["signatures"]], ["a", "b"])
        self.assertEqual(act.verify(env, self.m1)["activation_epoch"], 1)
        self.assertEqual((a.record.counter.v, b.record.counter.v, events[-1]["outcome"]), (1, 1, "ALLOW"))

    def test_what_a_co_signer_refuses(self):
        b = self.node("b")
        body = lease(self.m1, activation_epoch=1)
        cases = [("has not pulled from every node", dict(synced=lambda: False)),
                 ("time is not authenticated", dict(clock=self.clock(authenticated=False))),
                 ("a node proposes only its own", dict(caller="c")),
                 ("does not count toward activation", dict(me="d"))]
        for reason, over in cases:
            with self.subTest(reason):
                args = dict(manifest=self.m1, me="b", caller="a", lease=body, clock=self.clock(), signer=b, synced=lambda: True)
                args.update(over)
                self.refused(reason, act.cosign, *args.values())
        self.refused("a recovery lease is the owner's", act.cosign, self.m1, "b", "a",
                     dict(body, recovery={"fenced": "x", "quarantine_epoch": 1}), self.clock(), b, lambda: True)
        self.assertEqual(b.record.counter.v, 0)               # nothing refused was granted

    def test_a_partition_minority_cannot_activate_a_second_site(self):
        """b granted a; c proposes site-c while a's lease runs: b refuses (OVERLAP), and with b the only other
        counting party reachable from c, c is not activated."""
        a, b, c = self.node("a"), self.node("b"), self.node("c")
        act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a,
                    lambda peer, body: act.cosign(self.m1, peer, "a", body, self.clock(), b, lambda: True), ["b"], lambda e: None)
        events = []
        with self.assertRaises(m.Refused) as caught:
            act.propose("c", "site-c", "sha256:" + "ab" * 32, self.m1, self.clock(T0 + 60), c,
                        lambda peer, body: act.cosign(self.m1, peer, "c", body, self.clock(T0 + 60), b, lambda: True), ["b"], events.append)
        self.assertIn("OVERLAP", str(caught.exception))
        self.assertEqual(events[-1]["outcome"], "DENY")

    def test_one_retry_above_the_co_signer_s_last_grant_never_a_loop(self):
        a, b = self.node("a"), self.node("b")
        b.record.record(lease(self.m1, activation_epoch=40), T0 + 600)        # b granted a at epoch 40, a's record lost
        asked = []

        def ask(peer, body):
            asked.append(body["activation_epoch"])
            return act.cosign(self.m1, peer, "a", body, self.clock(), b, lambda: True)
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, ask, ["b"], lambda e: None)
        self.assertEqual((asked, env["lease"]["activation_epoch"]), ([1, 41], 41))

    def test_a_refused_probe_costs_the_proposer_nothing_so_a_renews_through_c_when_b_fails(self):
        """ed's scenario: a active with b; standby c probes and is refused (b holds a's grant). c recorded nothing, so
        when b goes down a renews through c."""
        a, b, c = self.node("a"), self.node("b"), self.node("c")
        cos = lambda me, caller, signer, at: (lambda peer, body: act.cosign(self.m1, me, caller, body, self.clock(at), signer, lambda: True))
        act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, cos("b", "a", b, T0), ["b"], lambda e: None)
        with self.assertRaises(m.Refused):
            act.propose("c", "site-c", "sha256:" + "ab" * 32, self.m1, self.clock(T0 + 60), c, cos("b", "c", b, T0 + 60), ["b"], lambda e: None)
        self.assertEqual(c.record.counter.v, 0)               # the probe recorded nothing on c
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(T0 + 120), a, cos("c", "a", c, T0 + 120), ["c"], lambda e: None)
        self.assertEqual([s["party"] for s in env["signatures"]], ["a", "c"])

    def test_two_requests_at_once_for_different_sites_get_one_grant(self):
        """d9's race: the record's check and write are one step under the grant lock."""
        b = self.node("b")
        orig = b.record.check

        def slow_check(body, now):
            out = orig(body, now)
            time.sleep(0.2)                                   # widen the window between check and record
            return out
        b.record.check = slow_check
        results = []

        def ask(caller, site):
            try:
                act.cosign(self.m1, "b", caller, lease(self.m1, node_id=caller, site=site, activation_epoch=1), self.clock(), b, lambda: True)
                results.append("ALLOW")
            except m.Refused as refused:
                results.append(str(refused))
        threads = [threading.Thread(target=ask, args=("a", "site-a")), threading.Thread(target=ask, args=("c", "site-c"))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count("ALLOW"), 1, results)
        self.assertEqual(b.record.counter.v, 1)

    def test_the_proposer_s_own_late_refusal_is_recorded_in_its_trail(self):
        """d9: a's record moved between the advisory pre-check and its own signature: a DENY line, then Refused."""
        a, b = self.node("a"), self.node("b")
        events = []

        def ask(peer, body):
            sig = act.cosign(self.m1, peer, "a", body, self.clock(), b, lambda: True)
            a.record.record(lease(self.m1, site="site-x", activation_epoch=99), T0 + 600)   # a co-signed another site meanwhile
            return sig
        with self.assertRaises(m.Refused):
            act.propose("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(), a, ask, ["b"], events.append)
        self.assertEqual(events[-1]["outcome"], "DENY")
        self.assertIn("co-signed by b, refused by this node's own record", events[-1]["reason"])



class OwnerKey:
    def __init__(self, key):
        self.key = key

    def public(self):
        return pub(self.key)

    def sign(self, raw):
        return self.key.sign(raw)


class RecoveryPath(Record):
    """The owner and one node, only once the other node parties stopped counting, after the wait, with the line typed."""
    node, clock = Issuance.node, Issuance.clock               # the helpers only, not Issuance's tests

    def setUp(self):
        super().setUp()
        self.m2 = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        self.shown = []

    def owner_half(self, typed=None, tip=None, record=None, now=None, journal=0, key=OWNER_KEYS[0], witness=None):
        tip = tip or self.m2
        record = record if record is not None else {"activation_epoch": 40, "expires_at": T0}
        now = now if now is not None else T0 + act.RECOVERY_WAIT_S
        want = typed if typed is not None else "activate c site-c %d" % (max(record.get("activation_epoch", 0), journal) + 1)
        return act.owner_recovery_lease(tip, "c", "site-c", "sha256:" + "ab" * 32, record, journal, "powered off at the PDU", now,
                                        lambda text: (self.shown.append(text), want)[1], lambda: OwnerKey(key), witness_latest=witness)

    def test_the_owner_and_the_survivor_activate_it_and_the_gate_accepts(self):
        env = self.owner_half(journal=55)
        self.assertEqual(env["lease"]["activation_epoch"], 56)                # above the daemon's journal head (ed)
        self.assertIn("they will not rejoin until they hold epoch 2", env["lease"]["recovery"]["fenced"])
        self.assertIn("NOT consulted", self.shown[0])
        c = self.node("c")
        done = act.recovery_cosign(self.m2, "c", env, self.clock(T0 + act.RECOVERY_WAIT_S), c)
        self.assertEqual(sorted(s["party"] for s in done["signatures"]), ["c", m.OWNER])
        self.assertEqual(act.verify(done, self.m2)["node_id"], "c")

    def test_what_the_owner_s_tool_refuses_with_nothing_signed(self):
        m2b = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), activation_signers=dict(RULE))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.refused("quarantine b first", lambda: self.owner_half(tip=m2b))
        self.refused("wait until", lambda: self.owner_half(now=T0 + act.RECOVERY_WAIT_S - 1))
        self.refused("wait until", lambda: self.owner_half(witness=T0 + 100))     # the collector knows a later grant
        self.refused("not this activation's", lambda: self.owner_half(typed="activate c site-c 1"))
        self.refused("not one of the tip manifest's owner_keys", lambda: self.owner_half(key=Ed25519PrivateKey.generate()))
        self.refused("does not count toward activation", act.owner_recovery_lease, self.m2, "a", "site-a", "sha256:" + "ab" * 32,
                     {}, 0, "x", T0 + 9999, lambda t: "", lambda: OwnerKey(OWNER_KEYS[0]))

    def test_what_the_survivor_refuses(self):
        env = self.owner_half()
        now = T0 + act.RECOVERY_WAIT_S
        self.refused("is for c, not this node (a)", act.recovery_cosign, self.m2, "a", env, self.clock(now), self.node("a"))
        forged = dict(env, signatures=[dict(env["signatures"][0], sig=OWNER_KEYS[1].sign(b"other").hex(), key=pub(OWNER_KEYS[1]))])
        with self.assertRaises(m.Refused):
            act.recovery_cosign(self.m2, "c", forged, self.clock(now), self.node("c"))
        # a "recovery" lease signed by a node instead of the owner is refused BEFORE the survivor records anything
        c0 = self.node("c")
        by_node = {"lease": env["lease"], "signatures": signed(env["lease"], "a")["signatures"]}
        self.refused("must carry the owner's signature", act.recovery_cosign, self.m2, "c", by_node, self.clock(now), c0)
        self.assertEqual(c0.record.counter.v, 0)
        # the survivor's own LIVE grant record still binds when the owner's export was stale: it granted site-a on a
        # until later than the export said
        stale = self.owner_half(record={"activation_epoch": 60, "expires_at": T0})
        c = self.node("c")
        c.record.record(lease(self.m1, activation_epoch=60, expires_at=stamp(now + 300), not_before=stamp(now - 200)), now + 300)
        self.refused("OVERLAP", act.recovery_cosign, self.m2, "c", stale, self.clock(now), c)


class OwnerCommand(unittest.TestCase):
    def test_sign_activation_runs_off_the_nodes_and_takes_no_attestation_on_its_command_line(self):
        from unittest import mock
        from deploy.baremetal import owner
        argv = ["sign-activation", "--chain", "c.json", "--root-key", "00" * 32, "--survivor", "c", "--site", "site-c",
                "--registry-digest", "sha256:" + "ab" * 32, "--record", "r.json", "--journal-head", "0", "--out", "o.json",
                "--module", "/x.so", "--serial", "1"]
        with mock.patch.object(owner.os.path, "exists", return_value=True), mock.patch("sys.stderr") as err:
            self.assertEqual(owner.main(argv), 1)
        self.assertIn("this is a KMS node", "".join(str(c) for c in err.write.call_args_list))
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            owner.main(argv + ["--how", "powered off"])           # the attestation is typed at the terminal only


if __name__ == "__main__":
    unittest.main()
