#!/usr/bin/env python3
"""The D25 collector check's vector (deploy/baremetal/spendaudit.py, ADR-0002 D32), for the Go side to decide alike
(regalia-kms-ed's lane):

    python3 -Es tests/vectors/make-spendaudit-v1.py > tests/vectors/spendaudit-v1.json

Built on the opstate vector's own keys, chain, sessions, approver sets and signed spends (make-opstate-v1.py), so a
spend here is one the opstate verifier accepts. Each case: the servers' audit streams, the spends the collector
watched (or null for a replayed backlog), whether the check accepts, and the words its refusal must contain. Public
keys are written as "public"/"session_public", as the opstate vector writes them."""
import copy
import importlib.util
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from deploy.baremetal import membership as m, opstate, spendaudit  # noqa: E402

_spec = importlib.util.spec_from_file_location("make_opstate_v1", os.path.join(os.path.dirname(os.path.abspath(__file__)), "make-opstate-v1.py"))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

GATED_PURPOSES = ["sign"]                      # the policy's approval-gated purposes, for these cases
APPROVALS = [gen.approval(gen.S, "alice"), gen.approval(gen.S, "bob")]
ENTRY = dict(gen.S, approvals_sha256=opstate.approvals_digest(APPROVALS))
KEY = opstate.key_for(ENTRY)
VALUE = gen.by_node(ENTRY)
SESSION = gen.session()
WATCHED = {KEY: {"value": VALUE, "mod_revision": 7, "arrived": gen.NOW}}
EVENT = {"request_id": "r-1", "timestamp": "2026-10-05T12:00:03.25Z", "decision": "allow", "outcome": "success",
         "principal": ENTRY["principal"], "object_id": ENTRY["object_id"], "purpose": ENTRY["purpose"], "verified_approvers": ["alice", "bob"],
         "detail": {"spend": {"key": KEY, "mod_revision": 7, "entry_sha256": opstate.entry_digest(ENTRY), "value": VALUE},
                    "session": {"key": opstate.session_key_path(SESSION), "value": gen.vouched(SESSION, signer="a-new")},
                    "payload_sha256": ENTRY["payload_sha256"], "approvals": APPROVALS}}
CASES = []


def event(**change):
    e = copy.deepcopy(EVENT)
    for k, v in change.items():
        if k.startswith("detail."):
            e["detail"][k[len("detail."):]] = v
        else:
            e[k] = v
    return e


def case(name, streams, accept, reason="", watched=WATCHED):
    CASES.append({"name": name, "streams": streams, "watched": watched, "accept": accept, "reason": reason})


case("a signature and its spend pair", {"a": [EVENT]}, True)
case("a replayed backlog: the line verifies against the chain alone", {"a": [EVENT]}, True, watched=None)
case("a spend whose sign failed is a burn, counted, not a fault",
     {"a": [event(outcome="backend-failed", detail=None), event(purpose="seal", detail=None)]}, True)
case("a gated signature that names no spend", {"a": [event(detail=None)]}, False, "an approval-gated signature whose audit line names no spend")
case("no session entry for the spend's key", {"a": [event(**{"detail.session": None})]}, False, "carries no session entry")
case("the spend's entry is not the one its digest names",
     {"a": [event(**{"detail.spend": dict(EVENT["detail"]["spend"], entry_sha256="ee" * 32)})]}, False, "does not hash to its entry_sha256")
case("a spend the collector never saw committed", {"a": [EVENT]}, False, "which the collector never saw committed", watched={})
case("committed at another revision", {"a": [EVENT]}, False, "etcd committed another entry or revision",
     watched={KEY: dict(WATCHED[KEY], mod_revision=8)})
case("a backdated spend, seen arriving an hour after its at", {"a": [EVENT]}, False, "from this reader's clock when it arrived",
     watched={KEY: dict(WATCHED[KEY], arrived=gen.NOW + 3600)})
case("signed before its spend", {"a": [event(timestamp="2026-10-05T11:59:59Z")]}, False, "outside [")
case("signed after the request's life", {"a": [event(timestamp="2026-10-05T12:15:01Z")]}, False, "outside [")
case("signed on another server than the spend names", {"b": [EVENT]}, False, "committed for a")
case("another payload than the spend's", {"a": [event(**{"detail.payload_sha256": "dd" * 32})]}, False, "payload_sha256 is")
case("the recorded approvers are not the spend's", {"a": [event(verified_approvers=["alice"])]}, False, "recorded approvers")
case("the approvals carried are not the ones the spend counted", {"a": [event(**{"detail.approvals": APPROVALS[:1]})]}, False,
     "these are not the approvals the spend counted")
case("one spend, two signatures, without the watch", {"a": [EVENT, event(request_id="r-2")]}, False, "is named by two signatures",
     watched=None)


def decide(c):
    try:
        got = spendaudit.check(c["streams"], gen.CHAIN, lambda e: e.get("purpose") in GATED_PURPOSES, gen.APPROVER_SETS, c["watched"])
        return True, got
    except m.Refused as refused:
        return False, str(refused)


def main():
    for c in CASES:
        got, why = decide(c)
        assert got == c["accept"] and (got or c["reason"] in why), (c["name"], why)
        c["python_reason"] = why if not got else ""
        c["result"] = why if got else None
    doc = {"schema": "regalia.spendaudit-vectors/v1", "chain": gen.CHAIN, "approver_sets": gen.APPROVER_SETS,
           "gated_purposes": GATED_PURPOSES, "max_detail": spendaudit.MAX_DETAIL, "max_request_life_s": opstate.MAX_REQUEST_LIFE_S,
           "cases": CASES}
    json.dump(gen.composed(copy.deepcopy(doc)), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
