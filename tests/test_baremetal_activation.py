"""deploy/baremetal/activation.py (#432): activation by quorum. Two of the three nodes normally (any two such pairs
share a node, whose grant record refuses an overlap); the owner only on the recovery path, with the other node
parties stopped in the current manifest, never alone; each node's grant record counted on its TPM, standing only
while it matches, and busy for the recovery wait after a start without it."""
import os
import pathlib
import re
import shutil
import tempfile
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
        self.assertEqual(rec.state(T0)[0], {"grants": 1, "activation_epoch": 7, "site": "site-a", "expires_at": T0 + 600})
        self.refused("an epoch is granted once", rec.check, lease(self.m1), T0 + 10)
        rec.check(lease(self.m1, activation_epoch=8, not_before=stamp(T0 + 10), expires_at=stamp(T0 + 610)), T0 + 10)   # same site: may overlap
        self.refused("OVERLAP: this node granted site site-a until", rec.check,
                     lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(T0 + 300), expires_at=stamp(T0 + 900)), T0 + 300)
        rec.check(lease(self.m1, site="site-b", activation_epoch=8, not_before=stamp(T0 + 600), expires_at=stamp(T0 + 1200)), T0 + 600)

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


if __name__ == "__main__":
    unittest.main()
