"""deploy/baremetal/spendaudit.py (ADR-0002 D32, D25): the collector pairs every approval-gated signature with exactly
one committed spend. Built on the opstate vector's own entries (tests/vectors/make-opstate-v1.py: its keys, sessions,
approver sets and signed spends), so the spends here are the ones the Go verifier decides alike."""
import copy
import importlib.util
import pathlib
import unittest

from deploy.baremetal import membership as m, opstate
from deploy.baremetal import spendaudit as sa

_spec = importlib.util.spec_from_file_location("make_opstate_v1", pathlib.Path(__file__).parent / "vectors" / "make-opstate-v1.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

GATED = lambda event: event.get("purpose") == "sign"                       # noqa: E731  the policy: "sign" needs approvals


class Pairing(unittest.TestCase):
    def setUp(self):
        self.approvals = [gen.approval(gen.S, "alice"), gen.approval(gen.S, "bob")]
        self.entry = dict(gen.S, approvals_sha256=opstate.approvals_digest(self.approvals))
        self.key = opstate.key_for(self.entry)
        value = gen.by_node(self.entry)
        session = gen.session()
        self.watched = {self.key: {"value": value, "mod_revision": 7, "arrived": gen.NOW}}
        self.event = {"request_id": "r-1", "timestamp": "2026-10-05T12:00:03.25Z", "decision": "allow", "outcome": "success",
                      "principal": self.entry["principal"], "object_id": self.entry["object_id"], "purpose": self.entry["purpose"],
                      "verified_approvers": ["alice", "bob"],
                      "detail": {"spend": {"key": self.key, "mod_revision": 7, "entry_sha256": opstate.entry_digest(self.entry), "value": value},
                                 "session": {"key": opstate.session_key_path(session), "value": gen.vouched(session, signer="a-new")},
                                 "payload_sha256": self.entry["payload_sha256"], "approvals": self.approvals}}

    def check(self, streams=None, watched=False):
        return sa.check(streams if streams is not None else {"a": [self.event]}, gen.CHAIN, GATED, gen.APPROVER_SETS,
                        self.watched if watched is False else watched)

    def refused(self, reason, **kw):
        with self.assertRaises(m.Refused) as caught:
            self.check(**kw)
        self.assertIn(reason, str(caught.exception))

    def changed(self, change):
        event = copy.deepcopy(self.event)
        change(event)
        return {"a": [event]}

    def test_a_signature_and_its_spend_pair(self):
        self.assertEqual(self.check(), {"signatures": 1, "watched": 1, "burned": []})
        # a replayed backlog (no live watch): the line verifies against the chain alone
        self.assertEqual(self.check(watched=None), {"signatures": 1, "watched": 0, "burned": []})

    def test_a_spend_no_signature_names_is_a_burn_counted_not_a_fault(self):
        """62's case: a spend whose sign then failed (or whose lease lapsed, may_sign) writes no signature line."""
        ungated = dict(self.event, purpose="seal", detail=None)
        denied = dict(self.event, decision="deny", outcome="policy-quota", detail=None)
        failed = dict(self.event, outcome="backend-failed", detail=None)
        self.assertEqual(self.check(streams={"a": [ungated, denied, failed]}), {"signatures": 0, "watched": 1, "burned": [self.key]})

    def test_a_gated_signature_that_names_no_spend(self):
        self.refused("request r-1: an approval-gated signature whose audit line names no spend",
                     streams=self.changed(lambda e: e.pop("detail")))

    def test_the_carried_spend_verifies_against_the_chain_alone(self):
        self.refused("request r-1's line carries no session entry for its spend's key",
                     streams=self.changed(lambda e: e["detail"].pop("session")))
        other = gen.session(key=gen.SESSION_A_PUB, issued_at="2026-10-05T12:30:00Z")          # vouched only after the spend
        self.refused("no verified session entry names that key for a",
                     streams=self.changed(lambda e: e["detail"].update(session={"key": opstate.session_key_path(other), "value": gen.vouched(other, signer="a-new")})))
        self.refused("request r-1's spend entry does not hash to its entry_sha256",
                     streams=self.changed(lambda e: e["detail"]["spend"].update(entry_sha256="ee" * 32)))

    def test_the_watch_cross_checks_what_etcd_committed(self):
        self.refused("carries the spend %s, which the collector never saw committed" % self.key, watched={})
        self.refused("request r-1 carries %s at revision 7; etcd committed another entry or revision (8)" % self.key,
                     watched={self.key: dict(self.watched[self.key], mod_revision=8)})
        self.refused("s from this reader's clock when it arrived", watched={self.key: dict(self.watched[self.key], arrived=gen.NOW + 3600)})

    def test_the_signature_is_made_inside_its_spend_s_lifetime(self):
        for when in ("2026-10-05T11:58:59Z", "2026-10-05T12:15:01Z"):
            with self.subTest(when):
                self.refused("request r-1 was signed on a at %s, outside [2026-10-05T12:00:00Z - 60 s, 2026-10-05T12:00:00Z + 900 s] of its "
                             "spend" % when, streams=self.changed(lambda e: e.update(timestamp=when)))
        # 62: a step of the node's own clock backwards between reserve and record, within SKEW_S, is not a fault
        self.assertEqual(self.check(streams=self.changed(lambda e: e.update(timestamp="2026-10-05T11:59:01Z")))["signatures"], 1)

    def test_the_detail_is_measured_as_go_writes_it(self):
        """62: Go's json.Marshal writes UTF-8 raw and escapes <, > and &; membership.canonical escapes non-ASCII instead."""
        self.assertEqual(sa._go_json_len({"p": "é<"}), len('{"p":"é\\u003c"}'.encode()))
        self.assertLess(sa._go_json_len({"p": "é" * 100}), len(m.canonical({"p": "é" * 100})))

    def test_signed_on_another_node_than_the_spend_names(self):
        self.refused("request r-1 was signed on b under a spend %s committed for a" % self.key, streams={"b": [self.event]})

    def test_the_signature_is_the_spend_s_request(self):
        for field, value in (("principal", "spiffe://regalia/ci/other"), ("object_id", "other-key"), ("purpose", "sign2")):
            with self.subTest(field):
                gated = dict(self.event, **{field: value})
                with self.assertRaisesRegex(m.Refused, "request r-1's %s is %r; its spend's is" % (field, value)):
                    sa.check({"a": [gated]}, gen.CHAIN, lambda e: True, gen.APPROVER_SETS, self.watched)
        self.refused("request r-1's payload_sha256 is %r; its spend's is" % ("dd" * 32),
                     streams=self.changed(lambda e: e["detail"].update(payload_sha256="dd" * 32)))

    def test_the_approvals_are_the_spend_s_and_the_recorded_approvers(self):
        self.refused("request r-1 recorded approvers ['alice']; the approvals behind its spend are ['alice', 'bob']'s",
                     streams=self.changed(lambda e: e.update(verified_approvers=["alice"])))
        self.refused("these are not the approvals the spend counted",
                     streams=self.changed(lambda e: e["detail"].update(approvals=self.approvals[:1])))

    def test_one_spend_two_signatures_even_across_servers_and_without_the_watch(self):
        second = dict(self.event, request_id="r-2")
        self.refused("the spend %s is named by two signatures: r-1 and r-2" % self.key, streams={"a": [self.event, second]}, watched=None)

    def test_a_detail_over_the_daemon_s_bound(self):
        self.refused("request r-1's detail is over %d bytes" % sa.MAX_DETAIL,
                     streams=self.changed(lambda e: e["detail"].update(padding="x" * sa.MAX_DETAIL)))

if __name__ == "__main__":
    unittest.main()


class Vectors(unittest.TestCase):
    """tests/vectors/spendaudit-v1.json, which the Go side decides alike: replayed here, and current with its maker."""

    def test_every_case_is_decided_as_the_vector_says(self):
        import json
        from tests.test_baremetal_opstate import restored
        with open(pathlib.Path(__file__).parent / "vectors" / "spendaudit-v1.json") as f:
            doc = restored(json.load(f))
        gated = lambda e: e.get("purpose") in doc["gated_purposes"]                            # noqa: E731
        self.assertGreaterEqual(len(doc["cases"]), 10)
        for c in doc["cases"]:
            with self.subTest(c["name"]):
                try:
                    sa.check(c["streams"], doc["chain"], gated, doc["approver_sets"], c["watched"])
                    self.assertTrue(c["accept"], "accepted, but the vector refuses it")
                except m.Refused as refused:
                    self.assertFalse(c["accept"], "refused (%s), but the vector accepts it" % refused)
                    self.assertIn(c["reason"], str(refused))

    def test_the_vector_is_current_with_its_maker(self):
        """Not byte for byte: the session entries' P-256 signatures are randomized. Each case's name, verdict and refusal
        words must be what the maker decides now (its own run asserts them)."""
        import json
        import subprocess
        import sys
        here = pathlib.Path(__file__).parent / "vectors"
        made = json.loads(subprocess.run([sys.executable, "-Es", "-B", str(here / "make-spendaudit-v1.py")], capture_output=True, check=True).stdout)
        held = json.loads((here / "spendaudit-v1.json").read_text())
        summary = lambda doc: [(c["name"], c["accept"], c["reason"]) for c in doc["cases"]]           # noqa: E731
        self.assertEqual(summary(made), summary(held), "tests/vectors/spendaudit-v1.json is stale: regenerate it with make-spendaudit-v1.py")
