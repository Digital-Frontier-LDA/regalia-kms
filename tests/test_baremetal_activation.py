"""deploy/baremetal/activation.py (#432): activation by quorum. Two of the three nodes normally (any two such pairs
share a node, whose grant record refuses an overlap); the owner only on the recovery path, with the other node
parties stopped in the current manifest, never alone; each node's grant record counted on its TPM, standing only
while it matches, and busy for the recovery wait after a start without it."""
import contextlib
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
                 ("the recovery block fields mismatch", dict(recovery={"fenced": "x", "quarantine_epoch": 1}))]
        for reason, over in cases:
            with self.subTest(reason):
                self.refused(reason, act.validate, lease(self.m1, **over))


class Quorum(Case):
    def test_two_of_the_three_nodes_activate_and_one_never_does(self):
        body = lease(self.m1)
        self.assertEqual(act.verify(signed(body, "a", "b"), self.m1), body)
        self.assertEqual(act.verify(signed(body, "b", "c"), self.m1), body)        # the subject need not sign
        self.refused("1 of the nodes signed (a); activation needs 2", act.verify, signed(body, "a"), self.m1)

    def test_the_owner_never_signs_a_lease(self):
        """The owner counts only through a recovery authorization (RecoveryPath), never as a lease signer."""
        body = lease(self.m1)
        self.refused("never a lease", act.verify, signed(body, "a", m.OWNER), self.m1)
        self.refused("never a lease", act.verify, signed(body, m.OWNER), self.m1)

    def test_recovery_needs_every_other_node_party_stopped_in_the_current_manifest(self):
        """{a, b} and {c, owner} do not intersect: the owner's authorization counts only once a and b no longer count."""
        m2b = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), activation_signers=dict(RULE))
        auth = {"schema": act.AUTH_SCHEMA, "node_id": "c", "site": "site-c", "registry_digest": "sha256:" + "ab" * 32,
                "quarantine_epoch": 2, "quarantine_digest": m.digest(m2b), "not_before": stamp(T0), "expires_at": stamp(T0 + 3600),
                "fenced": "a, b: off; they will not rejoin until they hold epoch 2"}
        rec = {"authorization": auth, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                                    "sig": OWNER_KEYS[0].sign(act.authorization_message(auth)).hex()}}
        body = lease(m2b, node_id="c", site="site-c", recovery=rec)
        self.refused("b is not", act.verify, signed(body, "c"), m2b)

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
        auth = {"schema": act.AUTH_SCHEMA, "node_id": "a", "site": "site-a", "registry_digest": "sha256:" + "ab" * 32,
                "quarantine_epoch": 1, "quarantine_digest": m.digest(self.m1), "not_before": stamp(T0), "expires_at": stamp(T0 + 3600),
                "fenced": "x"}
        rec = {"authorization": auth, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]), "sig": "00" * 64}}
        self.refused("a recovery lease is the owner's", act.cosign, self.m1, "b", "a", dict(body, recovery=rec), self.clock(), b, lambda: True)
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
    """#432 amendment 5: one owner authorization, then the survivor renews its own leases alone, while the current manifest
    IS the quarantine manifest. Every binding (node, site, registry, window, epoch) is refused when broken."""
    node, clock = Issuance.node, Issuance.clock

    def setUp(self):
        super().setUp()
        self.m2 = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        self.shown, self.events = [], []
        self.now = T0 + act.RECOVERY_WAIT_S

    def authorize(self, typed=None, tip=None, record=None, now=None, key=OWNER_KEYS[0], witness=None, life=None, survivor="c"):
        tip = tip or self.m2
        record = record if record is not None else {"activation_epoch": 40, "expires_at": T0}
        now = now if now is not None else self.now
        expires = act._stamp(now + (life if life is not None else tip["recovery_authorization_max_s"]))
        want = typed if typed is not None else "authorize %s site-c %d until %s" % (survivor, tip["epoch"], expires)
        return act.owner_recovery_authorization(tip, survivor, "site-c", "sha256:" + "ab" * 32, record, "powered off at the PDU", now,
                                                lambda text: (self.shown.append(text), want)[1], lambda: OwnerKey(key),
                                                life_s=life, witness_latest=witness)

    def survivor(self):
        c = self.node("c")
        return c

    def test_one_touch_then_the_survivor_renews_alone_and_the_gate_accepts(self):
        signed = self.authorize()
        self.assertIn("they will not rejoin until they hold epoch 2", signed["authorization"]["fenced"])
        self.assertIn("NOT consulted", self.shown[0])
        c = self.survivor()
        self.assertEqual(act.install_authorization(self.m2, "c", signed, self.clock(self.now), c.record)["node_id"], "c")
        first = act.self_renew("c", self.m2, self.clock(self.now), c, signed, self.events.append)
        self.assertEqual([x["party"] for x in first["signatures"]], ["c"])          # no owner signature on the lease
        self.assertEqual(act.verify(first, self.m2)["node_id"], "c")
        later = self.now + 5 * 24 * 3600                                           # days later, no touch
        again = act.self_renew("c", self.m2, self.clock(later), c, signed, self.events.append)
        self.assertEqual(again["lease"]["activation_epoch"], first["lease"]["activation_epoch"] + 1)
        self.assertEqual(act.verify(again, self.m2)["site"], "site-c")
        self.assertEqual([e["event"] for e in self.events], ["activation-recovery", "activation-recovery"])
        end = heartbeat.parse_time(signed["authorization"]["expires_at"], "e")
        self.refused("has expired", act.self_renew, "c", self.m2, self.clock(end), c, signed, self.events.append)

    def test_a_new_epoch_ends_it_everywhere(self):
        signed = self.authorize()
        c = self.survivor()
        lease_env = act.self_renew("c", self.m2, self.clock(self.now), c, signed, lambda e: None)
        m3 = manifest4(3, m.digest(self.m2), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        self.refused("a new epoch ends it", act.verify, lease_env, m3)
        self.refused("a new epoch ends it", act.install_authorization, m3, "c", signed, self.clock(self.now), c.record)
        self.refused("a new epoch ends it", act.self_renew, "c", m3, self.clock(self.now), c, signed, lambda e: None)

    def test_every_binding_of_the_lease_to_the_authorization_is_enforced(self):
        """d9, 24: the authorization is not "this node may activate any site"."""
        signed = self.authorize()
        c = self.survivor()
        good = act.self_renew("c", self.m2, self.clock(self.now), c, signed, lambda e: None)

        def resigned(**over):
            body = dict(good["lease"], **over)
            return {"lease": body, "signatures": signed_by_c(body)}

        def signed_by_c(body):
            return [{"party": "c", "key": pub(NODE_KEYS["c"]), "sig": p256_sig(NODE_KEYS["c"], act.message(body))}]
        self.refused("the lease names c, site site-x", act.verify, resigned(site="site-x"), self.m2)
        self.refused("the lease names c, site site-c", act.verify, resigned(registry_digest="sha256:" + "cd" * 32), self.m2)
        self.refused("not inside the recovery authorization's", act.verify,
                     resigned(not_before=act._stamp(self.now - 3600), expires_at=act._stamp(self.now - 3000)), self.m2)
        other = dict(good["lease"], node_id="a")                     # a's lease under c's authorization, signed by a
        self.refused("may not serve", act.verify, {"lease": other, "signatures": [{"party": "a", "key": pub(NODE_KEYS["a"]),
                     "sig": p256_sig(NODE_KEYS["a"], act.message(other))}]}, self.m2)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        outsider = Ed25519PrivateKey.generate()                      # an Ed25519 key in no owner_keys
        stranger = dict(signed, signature={"party": m.OWNER, "key": pub(outsider), "sig": outsider.sign(act.authorization_message(signed["authorization"])).hex()})
        with self.assertRaises(m.Refused):                           # a key not in the manifest's owner_keys
            act.verify({"lease": dict(good["lease"], recovery=stranger), "signatures": signed_by_c(dict(good["lease"], recovery=stranger))}, self.m2)
        owner_on_lease = {"lease": good["lease"], "signatures": good["signatures"] + [{"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                          "sig": OWNER_KEYS[0].sign(act.message(good["lease"])).hex()}]}
        self.refused("never a lease", act.verify, owner_on_lease, self.m2)

    def test_an_authorization_must_be_the_owner_s_within_the_cap_and_its_lease_the_survivor_s(self):
        signed = self.authorize()
        c = self.survivor()
        good = act.self_renew("c", self.m2, self.clock(self.now), c, signed, lambda e: None)
        auth = signed["authorization"]
        # the authorization signed by a node's key (c's own), not the owner's
        by_node = {"authorization": auth, "signature": {"party": "c", "key": pub(NODE_KEYS["c"]),
                                                        "sig": p256_sig(NODE_KEYS["c"], act.authorization_message(auth))}}
        self.refused("is not the owner's", act.install_authorization, self.m2, "c", by_node, self.clock(self.now), c.record)
        # an authorization the owner signed for longer than the manifest allows (built by hand: the tool refuses to)
        long = dict(auth, expires_at=act._stamp(heartbeat.parse_time(auth["not_before"], "n") + 604801))
        too_long = {"authorization": long, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                                         "sig": OWNER_KEYS[0].sign(act.authorization_message(long)).hex()}}
        self.refused("more than the manifest's recovery_authorization_max_s", act.install_authorization, self.m2, "c", too_long,
                     self.clock(self.now), c.record)
        # c's lease under c's authorization, but signed by a (quarantined: it does not count) instead of c
        body = good["lease"]
        by_a = {"lease": body, "signatures": [{"party": "a", "key": pub(NODE_KEYS["a"]), "sig": p256_sig(NODE_KEYS["a"], act.message(body))}]}
        self.refused("is signed by the survivor c", act.verify, by_a, self.m2)

    def test_the_owner_s_record_closes_an_epoch_and_names_every_issue(self):
        """d9: once an epoch after the recovery stated recovery_ends_by, the owner's tool issues nothing for it again."""
        signed = self.authorize()
        self.assertEqual(act.issued_line(signed), {"event": "issued", "quarantine_epoch": 2, "node_id": "c", "site": "site-c",
                                                   "expires_at": heartbeat.parse_time(signed["authorization"]["expires_at"], "e")})
        act.issuable([act.issued_line(signed)], 2)
        self.refused("no authorization is issued for epoch 2", act.issuable,
                     [{"event": "closed", "through_epoch": 2, "recovery_ends_by": 1}], 2)
        act.issuable([{"event": "closed", "through_epoch": 2, "recovery_ends_by": 1}], 5)      # a later recovery: issuable

    def test_what_the_owner_s_tool_refuses(self):
        m2b = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), activation_signers=dict(RULE))
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.refused("quarantine b first", lambda: self.authorize(tip=m2b))
        self.refused("come back at", lambda: self.authorize(now=T0 + act.RECOVERY_WAIT_S - 1))
        self.refused("come back at", lambda: self.authorize(witness=T0 + 100))
        self.refused("not this authorization's", lambda: self.authorize(typed="authorize c site-c 2 until never"))
        self.refused("not one of the tip manifest's owner_keys", lambda: self.authorize(key=Ed25519PrivateKey.generate()))
        self.refused("lives at most 604800", lambda: self.authorize(life=604801))
        self.refused("does not count toward activation", lambda: self.authorize(survivor="a"))

    def test_the_survivor_installs_only_its_own_on_its_own_clock(self):
        """d9: the wait is the survivor's, on its authenticated clock and its own record, whatever the laptop said."""
        signed = self.authorize(record={"activation_epoch": 0, "expires_at": 0})       # a stale export: the laptop sees no grant
        c = self.survivor()
        c.record.record(lease(self.m1, site="site-c", node_id="c", activation_epoch=60, not_before=stamp(self.now - 100),
                              expires_at=stamp(self.now + 300)), self.now + 300)        # but c granted itself until later
        self.refused("may be installed from", act.install_authorization, self.m2, "c", signed, self.clock(self.now), c.record)
        later = self.now + 300 + act.RECOVERY_WAIT_S
        act.install_authorization(self.m2, "c", signed, self.clock(later), c.record)
        self.refused("is for c, not a", act.install_authorization, self.m2, "a", signed, self.clock(later), self.node("a").record)
        self.refused("time is not authenticated", act.install_authorization, self.m2, "c", signed, self.clock(later, False), c.record)

    def test_self_renewal_still_goes_through_the_grant_record(self):
        signed = self.authorize()
        c = self.survivor()
        # c co-signed site-a on a, and that grant runs: the authorization does not let c overlap it
        c.record.record(lease(self.m1, activation_epoch=60, not_before=stamp(self.now - 100), expires_at=stamp(self.now + 300)), self.now + 300)
        self.refused("OVERLAP", act.self_renew, "c", self.m2, self.clock(self.now), c, signed, lambda e: None)


class OwnerCommand(unittest.TestCase):
    def test_sign_activation_runs_off_the_nodes_and_takes_no_attestation_on_its_command_line(self):
        from unittest import mock
        from deploy.baremetal import owner
        argv = ["sign-activation", "--chain", "c.json", "--root-key", "00" * 32, "--survivor", "c", "--site", "site-c",
                "--registry-digest", "sha256:" + "ab" * 32, "--record", "r.json", "--state-dir", "/nonexistent", "--out", "o.json",
                "--module", "/x.so", "--serial", "1"]
        with mock.patch.object(owner.os.path, "exists", return_value=True), mock.patch("sys.stderr") as err:
            self.assertEqual(owner.main(argv), 1)
        self.assertIn("this is a KMS node", "".join(str(c) for c in err.write.call_args_list))
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            owner.main(argv + ["--how", "powered off"])           # the attestation is typed at the terminal only


class OverSync(Record):
    """activate-sign through sync.Server and sync.Client: the tunnel names the caller, who may only ask for its own lease,
    and the op has its own rate class, spent before the TPM is touched."""
    node, clock = Issuance.node, Issuance.clock

    def test_activate_sign_over_the_wire(self):
        from deploy.baremetal import sync
        from tests.test_baremetal_beat import FakeStore
        wg = {n["node_id"]: n["wg_service_pub"] for n in self.m1["nodes"]}
        at = {"addr-" + k: v for k, v in wg.items()}
        b, events = self.node("b"), []
        activator = lambda man, caller, body: act.cosign(man, "b", caller, body, self.clock(), b, lambda: True)
        server = sync.Server("b", FakeStore(self.m1), None, None, None, lambda man, source: at[source], events.append,
                             sync.Buckets(clock=lambda: 0.0), activator=activator)
        client = sync.Client("a", FakeStore(self.m1), None, {"b": lambda raw: server.handle(raw, "addr-a")}, events.append)
        body = lease(self.m1, activation_epoch=1)
        theirs = client.activate_sign("b", body)
        self.assertEqual(theirs["party"], "b")
        a_sig = signed(body, "a")["signatures"][0]
        self.assertEqual(act.verify({"lease": body, "signatures": [a_sig, theirs]}, self.m1), body)
        # c's tunnel asking for a's lease: refused by name, nothing granted
        mallory = sync.Client("c", FakeStore(self.m1), None, {"b": lambda raw: server.handle(raw, "addr-c")}, events.append)
        self.refused("a node proposes only its own", mallory.activate_sign, "b", lease(self.m1, activation_epoch=2))
        self.assertEqual(b.record.counter.v, 1)
        # six a minute from one caller (the class), then refused before the TPM is touched
        for i in range(2, 7):                                  # a's 2nd to 6th request this minute
            with contextlib.suppress(m.Refused):
                client.activate_sign("b", lease(self.m1, activation_epoch=i))
        self.refused("RATE", client.activate_sign, "b", lease(self.m1, activation_epoch=9))
        # a node without an activator signs nothing
        plain = sync.Server("b", FakeStore(self.m1), None, None, None, lambda man, source: at[source], events.append)
        lone = sync.Client("a", FakeStore(self.m1), None, {"b": lambda raw: plain.handle(raw, "addr-a")}, events.append)
        self.refused("co-signs no activations", lone.activate_sign, "b", body)


class BootRule(unittest.TestCase):
    """d9's rule on node.Sync: after a start, no co-signature until every other node that may authorize has answered a
    pull, or the node holds an epoch newer than the one it started with."""

    def sync_(self, man, pulled=(), boot_epoch=1):
        from deploy.baremetal import node as node_module
        s = node_module.Sync.__new__(node_module.Sync)
        s.node = type("N", (), {"node_id": "b"})()
        s.manifest, s.pulled, s.boot_epoch = (lambda: man), set(pulled), boot_epoch
        return s

    def test_synced_only_once_every_authorizing_peer_answered_or_the_epoch_moved(self):
        m1 = manifest4(1, "", nodes4(), activation_signers=dict(RULE))
        self.assertFalse(self.sync_(m1).synced())
        self.assertFalse(self.sync_(m1, pulled={"a"}).synced())                 # c not heard from: two fenced nodes stay silent
        self.assertTrue(self.sync_(m1, pulled={"a", "c"}).synced())
        m2 = manifest4(2, m.digest(m1), nodes4(c="QUARANTINED"), activation_signers=dict(RULE))
        self.assertTrue(self.sync_(m2, pulled={"a"}, boot_epoch=2).synced())     # c may not authorize: not waited for
        self.assertTrue(self.sync_(m2, boot_epoch=1).synced())                  # a newer epoch than at the start


class Readmission(unittest.TestCase):
    """#432 amendment 5, rule 6 (d9): a node that counts again waits until every authorizing peer, the survivor included,
    is seen at or past that epoch, then RECOVERY_WAIT_S; a survivor still on the epoch before holds it back."""

    def chain(self):
        m1 = manifest4(1, "", nodes4(), activation_signers=dict(RULE))
        m2 = manifest4(2, m.digest(m1), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        m3 = manifest4(3, m.digest(m2), nodes4(), activation_signers=dict(RULE))        # a and b re-admitted
        return [m1, m2, m3]

    def test_the_epoch_a_node_counts_again(self):
        ms = self.chain()
        self.assertEqual((act.readmission_epoch(ms, "a"), act.readmission_epoch(ms, "c")), (3, None))
        self.assertIsNone(act.readmission_epoch(ms[:2], "a"))                # still quarantined
        self.assertIsNone(act.readmission_epoch(ms[:1], "a"))                # genesis: no transition

    def sync_(self, peer_epochs, clock, d):
        from deploy.baremetal import node as node_module
        ms = self.chain()
        s = node_module.Sync.__new__(node_module.Sync)
        s.node = type("N", (), {"node_id": "a", "clock": lambda self: clock, "path": lambda self, leaf: os.path.join(d, leaf)})()
        s.store = type("S", (), {"manifests": ms, "load": lambda self: ms[-1]})()
        s.manifest, s.peer_epochs = (lambda: ms[-1]), dict(peer_epochs)
        return s

    def test_held_back_by_a_survivor_still_on_the_old_epoch_then_the_wait_then_clear(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        now = [T0]
        clock = lambda: (now[0], True)
        s = self.sync_({"b": 3, "c": 2}, clock, d)                           # c, the survivor, still at epoch 2
        self.assertFalse(s.readmitted())
        now[0] = T0 + 3 * act.RECOVERY_WAIT_S                                # however long c stays behind, a waits
        self.assertFalse(s.readmitted())
        now[0] = T0
        s.peer_epochs["c"] = 3                                               # c took the re-admitting epoch: it stops
        self.assertFalse(s.readmitted())                                     # seen all at T0: the wait starts
        now[0] = T0 + act.RECOVERY_WAIT_S - 1
        self.assertFalse(s.readmitted())
        now[0] = T0 + act.RECOVERY_WAIT_S
        self.assertTrue(s.readmitted())
        restarted = self.sync_({}, clock, d)                                 # a restart: the cleared state is kept
        self.assertTrue(restarted.readmitted())

    def test_a_survivor_quarantined_at_the_exit_is_waited_out_until_recovery_ends_by(self):
        """d9's hole: c, the survivor, partitioned and quarantined in the restoring epoch, may never answer; a and b wait
        until recovery_ends_by + RECOVERY_WAIT_S instead of overlapping c's self-renewals."""
        from deploy.baremetal import node as node_module
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        m1 = manifest4(1, "", nodes4(), activation_signers=dict(RULE))
        m2 = manifest4(2, m.digest(m1), nodes4(a="QUARANTINED", b="QUARANTINED"), activation_signers=dict(RULE))
        ends = T0 + 7 * 24 * 3600
        m3 = manifest4(3, m.digest(m2), nodes4(c="QUARANTINED"), activation_signers=dict(RULE), recovery_ends_by=ends)
        ms = [m1, m2, m3]
        self.assertEqual(act.recovery_survivors(ms, 3), {"c"})
        m3b = manifest4(3, m.digest(m2), nodes4(a="QUARANTINED", b="QUARANTINED", c="QUARANTINED"), activation_signers=dict(RULE))
        m4b = manifest4(4, m.digest(m3b), nodes4(c="QUARANTINED"), activation_signers=dict(RULE), recovery_ends_by=ends)
        self.assertEqual(act.recovery_survivors([m1, m2, m3b, m4b], 4), {"c"})    # d9: N alone, N+1 nobody, N+2 back
        now = [T0]
        s = node_module.Sync.__new__(node_module.Sync)
        s.node = type("N", (), {"node_id": "a", "clock": lambda self: (lambda: (now[0], True)), "path": lambda self, leaf: os.path.join(d, leaf)})()
        s.store = type("S", (), {"manifests": ms, "load": lambda self: ms[-1]})()
        s.manifest, s.peer_epochs = (lambda: m3), {"b": 3}                    # c never answers
        self.assertFalse(s.readmitted())
        now[0] = ends - 1
        self.assertFalse(s.readmitted())                                     # however long until the owner's last authorization ends
        now[0] = ends
        self.assertFalse(s.readmitted())                                     # then the usual wait, from there
        now[0] = ends + act.RECOVERY_WAIT_S
        self.assertTrue(s.readmitted())
        # had c answered at epoch 3, nothing but the usual wait: the survivor seen has stopped
        d2 = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d2, True)
        now[0] = T0
        s.node = type("N", (), {"node_id": "a", "clock": lambda self: (lambda: (now[0], True)), "path": lambda self, leaf: os.path.join(d2, leaf)})()
        s.peer_epochs = {"b": 3, "c": 3}
        self.assertFalse(s.readmitted())
        now[0] = T0 + act.RECOVERY_WAIT_S
        self.assertTrue(s.readmitted())


class Running(Record):
    """Step 2d: only the holder renews, at half-life, never an expired lease; promotion is the operator's and waits for
    the co-signers' grants; release stops the renewals; under an installed authorization the survivor renews alone."""
    node, clock = Issuance.node, Issuance.clock

    def setUp(self):
        super().setUp()
        self.state = os.path.join(self.d, "state")
        os.mkdir(self.state)
        self.a, self.b, self.c = self.node("a"), self.node("b"), self.node("c")

    def ask_from(self, caller, at):
        signers = {"b": self.b, "c": self.c, "a": self.a}
        return lambda peer, body: act.cosign(self.m1, peer, caller, body, self.clock(at), signers[peer], lambda: True)

    def test_promote_then_renew_at_half_life_only(self):
        env = act.promote("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(T0), self.a, self.ask_from("a", T0), ["b"],
                          self.state, lambda e: None)
        self.assertEqual(act.read_json(os.path.join(self.state, act.LEASE_FILE)), env)
        step = lambda at: act.renewal_step("a", self.m1, self.clock(at), self.a, self.ask_from("a", at), ["b"], self.state, lambda e: None)
        self.assertEqual(step(T0 + 299)["renewed"], False)                     # more than half left
        got = step(T0 + 300)
        self.assertEqual((got["holder"], got["renewed"], got["expires"]), (True, True, T0 + 900))
        self.assertEqual(act.read_json(os.path.join(self.state, act.LEASE_FILE))["lease"]["activation_epoch"], 2)

    def test_no_probing_no_expired_renewal_and_release_lapses(self):
        step = lambda node, at: act.renewal_step(node, self.m1, self.clock(at), getattr(self, node), self.ask_from(node, at), ["b"],
                                                 self.state, lambda e: None)
        self.assertEqual(step("c", T0), {"holder": False, "expires": None, "recovery": False, "renewed": False})   # no lease: nothing
        act.promote("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(T0), self.a, self.ask_from("a", T0), ["b"], self.state, lambda e: None)
        self.assertEqual(step("c", T0 + 400)["renewed"], False)               # a's lease, not c's: c never proposes
        self.assertEqual(step("a", T0 + 600)["renewed"], False)               # expired: promote's, not the timer's
        open(os.path.join(self.state, act.RELEASE_FILE), "w").close()
        self.assertEqual(step("a", T0 + 400)["renewed"], False)               # released: it lapses

    def test_a_second_site_s_promotion_waits_and_says_until_when(self):
        act.promote("a", "site-a", "sha256:" + "ab" * 32, self.m1, self.clock(T0), self.a, self.ask_from("a", T0), ["b"], self.state, lambda e: None)
        other = os.path.join(self.d, "c-state")
        os.mkdir(other)
        with self.assertRaises(m.Refused) as caught:
            act.promote("c", "site-c", "sha256:" + "ab" * 32, self.m1, self.clock(T0 + 60), self.c, self.ask_from("c", T0 + 60), ["b"],
                        other, lambda e: None)
        self.assertEqual(act.waited_until(caught.exception), T0 + 600 + act.SKEW_S)
        later = T0 + 600 + 2 * act.SKEW_S
        env = act.promote("c", "site-c", "sha256:" + "ab" * 32, self.m1, self.clock(later), self.c, self.ask_from("c", later), ["b"],
                          other, lambda e: None)
        self.assertEqual(env["lease"]["site"], "site-c")

    def test_under_an_installed_authorization_the_survivor_renews_alone(self):
        rp = RecoveryPath("setUp")
        rp.setUp()
        signed = rp.authorize()
        act.install_authorization(rp.m2, "c", signed, rp.clock(rp.now), rp.survivor().record)
        state = os.path.join(rp.d, "c-state")
        os.mkdir(state)
        c = rp.survivor()
        first = act.self_renew("c", rp.m2, rp.clock(rp.now), c, signed, lambda e: None)
        act.write_json(os.path.join(state, act.LEASE_FILE), first)
        act.write_json(os.path.join(state, act.RECOVERY_FILE), signed)
        got = act.renewal_step("c", rp.m2, rp.clock(rp.now + 300), c, None, [], state, lambda e: None)
        self.assertEqual((got["recovery"], got["renewed"]), (True, True))
        m3 = manifest4(3, m.digest(rp.m2), nodes4(), activation_signers=dict(RULE))         # a and b back: the authorization ends
        ended = act.renewal_step("c", m3, rp.clock(rp.now + 600), c, None, [], state, lambda e: None)
        self.assertEqual((ended["recovery"], ended["renewed"]), (False, False))
        self.assertIn("no node co-signed", ended["failed"])                  # back on the normal path, nobody to co-sign: recorded


class Commands(unittest.TestCase):
    """The operator's commands: typed at root's console, the work handed to regalia-sync with an argv its half parses
    (#386's lesson), never as root; the busy window from this boot's sync start only."""

    def test_the_hand_over_argv_reaches_the_sync_half_and_never_runs_as_root(self):
        from unittest import mock
        import pwd
        seen = []

        def run(argv, **kw):
            seen.append(argv)
            return mock.Mock(returncode=0, stdout='{"released": true}\n', stderr="")
        self.assertEqual(act._run_as_sync("/etc/regalia/node.json", "_release", {}, run=run), {"released": True})
        argv = seen[0][seen[0].index("deploy.baremetal.activation") + 1:]
        self.assertEqual(argv, ["--config", "/etc/regalia/node.json", "_release"])
        with mock.patch.object(act.os, "geteuid", return_value=0), mock.patch.object(pwd, "getpwnam", return_value=mock.Mock(pw_uid=990)), \
                mock.patch("sys.stderr") as err:
            self.assertEqual(act.main(argv), 1)
        self.assertIn("runs as regalia-sync only", "".join(str(c) for c in err.write.call_args_list))
        with mock.patch.object(act.os, "geteuid", return_value=1000), mock.patch("sys.stderr"):
            self.assertEqual(act.main(["--config", "/x.json", "release"]), 2)

    def test_the_busy_window_starts_at_this_boot_s_sync_start_only(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with self.assertRaisesRegex(m.Refused, "has not started under authenticated time in this boot"):
            act.sync_started(d, boot="boot-2")
        act.write_json(os.path.join(d, act.STARTED_FILE), {"boot_id": "boot-1", "started": T0})
        self.assertEqual(act.sync_started(d, boot="boot-1"), T0)
        with self.assertRaisesRegex(m.Refused, "in this boot"):
            act.sync_started(d, boot="boot-2")                              # a stale file from an earlier boot


if __name__ == "__main__":
    unittest.main()
