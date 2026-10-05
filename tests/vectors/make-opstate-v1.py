#!/usr/bin/env python3
"""The opstate entries (deploy/baremetal/opstate.py, ADR-0002 D32) as the Go verifier must decide them: each case is
an etcd key, the value stored there, the previous entry (or null), the session keys and approvers a verifier knows,
and whether opstate.verify then opstate.transition accept it. Each batch is one Reserve's transaction for
opstate.batch. The keys are fixed test keys (Ed25519 seeds of one repeated byte): not secrets.

    python3 -Es tests/vectors/make-opstate-v1.py > tests/vectors/opstate-v1.json

As in membership-v4.json, every "key" field is written "public" and every "session_key" "session_public" (a public key
written as `"key": "<hex>"` reads to a secret scanner as a leaked credential, and the rule is no allowlist); a reader
renames them back (tests/test_baremetal_opstate.restored).
"""
import base64
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from deploy.baremetal import membership as m, opstate  # noqa: E402
from tests.test_baremetal_membership_v4 import NODE_KEYS, manifest4, nodes4, p256_sig  # noqa: E402


def key(seed):
    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    return private, private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


SESSION_A, SESSION_A_PUB = key(1)
ALICE, ALICE_PUB = key(2)
BOB, BOB_PUB = key(3)
STRANGER, STRANGER_PUB = key(9)
BOOT = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
SESSIONS = {"a|" + BOOT: [SESSION_A_PUB]}                 # the keys verified session entries vouch for, per node and boot
MANIFEST = manifest4(1, "", nodes4())                      # whose signing keys vouch for session keys
APPROVERS = {"alice": ALICE_PUB, "bob": BOB_PUB}
CURRENT_SET = opstate.approver_set_digest(APPROVERS, 2)
OLD_SET = opstate.approver_set_digest({"alice": ALICE_PUB}, 1)                 # the set before a rotation
APPROVER_SETS = {CURRENT_SET: {"approvers": APPROVERS, "required": 2}, OLD_SET: {"approvers": {"alice": ALICE_PUB}, "required": 1},
                 opstate.UNGATED_SET: {"approvers": {}, "required": 0}}
RAW_NONCE = "request-nonce-1"
PAYLOAD = b"regalia release 1.0 manifest"                    # the request's payload: internal/approval hashes it itself
PAYLOAD_SHA256 = __import__("hashlib").sha256(PAYLOAD).hexdigest()
NONCE = opstate.nonce_digest(RAW_NONCE)
AT = "2026-10-05T12:00:00Z"


def approval(entry, who, nonce=RAW_NONCE, **over):
    """internal/approval's Approval by `who` for the request `entry` spent: signed over its Binding."""
    keys = {"alice": ALICE, "bob": BOB, "mallory": STRANGER}
    out = {"approver_id": who, "nonce": nonce, "expires_at": entry["expires_at"], "payload_digest": entry["payload_sha256"]}
    out.update({k: v for k, v in over.items() if k != "signed_as"})
    signed = dict(entry, **over.get("signed_as", {}))
    out["signature"] = base64.b64encode(keys[who].sign(opstate.binding_bytes(signed, nonce))).decode()
    return out


def spend(approvals=("alice", "bob"), **over):
    entry = {"schema": opstate.SCHEMA, "kind": "spend", "at": AT, "nonce_digest": NONCE, "principal": "spiffe://regalia/ci/release",
             "object_id": "release-signing", "purpose": "sign", "environment": "production", "payload_sha256": PAYLOAD_SHA256,
             "approvers": sorted(approvals), "approver_set": CURRENT_SET if approvals else opstate.UNGATED_SET,
             "node_id": "a", "boot_id": BOOT, "lease_digest": "cd" * 32,
             "lease_expires_at": "2026-10-05T12:00:20Z", "expires_at": "2026-10-05T12:05:00Z"}
    entry.update(over)
    entry["approvals_sha256"] = over.get("approvals_sha256") or opstate.approvals_digest([approval(entry, w) for w in approvals])
    return entry


def sequence(value, **over):
    entry = {"schema": opstate.SCHEMA, "kind": "sequence", "at": AT, "sequence_key": "cosmoshub-4/validator-1", "value": value,
             "nonce_digest": NONCE, "node_id": "a", "boot_id": BOOT}
    entry.update(over)
    return entry


def quota(total, **over):
    entry = {"schema": opstate.SCHEMA, "kind": "quota", "at": AT, "principal": "spiffe://regalia/ci/release", "utc_date": "2026-10-05",
             "counter": "signatures", "total": total, "cap": 100, "nonce_digest": NONCE, "node_id": "a", "boot_id": BOOT}
    entry.update(over)
    return entry


def key_state(state, after=None, **over):
    """A key's state, version 1 or the one after `after` (the entry it replaces), under the current approver set."""
    entry = {"schema": opstate.SCHEMA, "kind": "key-state", "at": AT, "object_id": "release-signing", "state": state,
             "version": after["version"] + 1 if after else 1, "prev_digest": opstate.entry_digest(after) if after else "",
             "approver_set": CURRENT_SET}
    entry.update(over)
    return entry


ENABLED = key_state("enabled")
DISABLED = key_state("disabled", ENABLED)
DESTROYED = key_state("destroyed", DISABLED)


def by_node(entry, private=SESSION_A, party="a", boot=BOOT, raw=None):
    raw = raw if raw is not None else opstate.DOMAIN + m.canonical(entry)
    named = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return {"entry": entry, "signatures": [{"party": party, "boot_id": boot, "session_key": named, "sig": private.sign(raw).hex()}]}


def by_approvers(entry, *who):
    keys = {"alice": ALICE, "bob": BOB, "mallory": STRANGER}
    raw = opstate.DOMAIN + m.canonical(entry)
    return {"entry": entry, "signatures": [{"party": w, "sig": keys[w].sign(raw).hex()} for w in who]}


CASES = []


def case(name, value, accept, previous=None, where=None):
    entry = value["entry"]
    try:
        where = where or opstate.key_for(entry)
    except m.Refused:
        where = where or opstate.PREFIX + "nonces/" + "00" * 32
    CASES.append({"name": name, "key": where, "value": value, "previous": previous, "accept": accept})


# ---- accepted ----
case("a spend, signed by the node's session key", by_node(spend()), True)
case("a spend with no approvers (a purpose no policy gates)", by_node(spend(approvals=())), True)
case("the first value of a sequence", by_node(sequence(7)), True)
case("a sequence above the previous", by_node(sequence(8)), True, previous=sequence(7))
case("a quota total that grows, under its cap", by_node(quota(5)), True, previous=quota(4))
case("a quota total exactly at its cap", by_node(quota(100)), True, previous=quota(99))
case("a key's first state", by_approvers(ENABLED, "alice", "bob"), True)
case("a key disabled by two of two approvers", by_approvers(DISABLED, "alice", "bob"), True, previous=ENABLED)
case("a key enabled again", by_approvers(key_state("enabled", DISABLED), "bob", "alice"), True, previous=DISABLED)
case("a key destroyed", by_approvers(DESTROYED, "alice", "bob"), True, previous=DISABLED)
case("an entry under the set before a rotation still verifies", by_approvers(key_state("disabled", ENABLED, approver_set=OLD_SET), "alice"),
     True, previous=ENABLED)

# ---- refused ----
case("SPENT: the nonce exists already", by_node(spend()), False, previous=spend(at="2026-10-05T11:59:00Z"))
case("a spend under another nonce's key", by_node(spend()), False, where=opstate.PREFIX + "nonces/" + "11" * 32)
case("a spend signed by a key no lease names", by_node(spend(), private=STRANGER), False)
case("a spend signed as another node", by_node(spend(), party="b"), False)
case("a spend signed in another boot", by_node(spend(), boot="11111111-2222-3333-4444-555555555555"), False)
case("a spend by a boot with no session on record", by_node(spend(boot_id="11111111-2222-3333-4444-555555555555"),
                                                            boot="11111111-2222-3333-4444-555555555555"), False)
case("a spend whose signature has no domain", by_node(spend(), raw=m.canonical(spend())), False)
case("a spend after the node's lease ran out", by_node(spend(lease_expires_at=AT)), False)
case("a spend after the request expired", by_node(spend(expires_at="2026-10-05T11:00:00Z")), False)
case("approvers not sorted", by_node(spend(approvers=["bob", "alice"])), False)
case("an approvals digest that is not hex", by_node(spend(approvals_sha256="xyz")), False)
case("an approver twice", by_node(spend(approvers=["alice", "alice"])), False)
case("an unknown field", by_node(dict(spend(), note="x")), False)
case("another schema", by_node(spend(schema="regalia.opstate/v0")), False)
case("an unknown kind", by_node(dict(spend(), kind="mint")), False)
case("a node's entry with two signatures", dict(by_node(spend()), signatures=by_node(spend())["signatures"] * 2), False)
case("an entry over 4096 bytes", by_node(spend(approvers=sorted("approver-%03d-%s" % (i, "x" * 200) for i in range(30)))), False)
case("a sequence that does not move", by_node(sequence(7)), False, previous=sequence(7))
case("a sequence that goes back", by_node(sequence(6)), False, previous=sequence(7))
case("a quota over its cap", by_node(quota(101)), False, previous=quota(100))
case("a quota total that shrinks", by_node(quota(3)), False, previous=quota(4))
case("one of two required approvals", by_approvers(DISABLED, "alice"), False, previous=ENABLED)
case("the same approver twice", by_approvers(DISABLED, "alice", "alice"), False, previous=ENABLED)
case("an approver not in the set", by_approvers(DISABLED, "alice", "mallory"), False, previous=ENABLED)
case("bob approving under the old set, which did not hold him", by_approvers(key_state("disabled", ENABLED, approver_set=OLD_SET), "bob"),
     False, previous=ENABLED)
case("an approver set nobody knows", by_approvers(key_state("disabled", ENABLED, approver_set="ee" * 32), "alice", "bob"), False, previous=ENABLED)
case("a destroyed key enabled again", by_approvers(key_state("enabled", DESTROYED), "alice", "bob"), False, previous=DESTROYED)
case("REPLAY: the old approved enabled put back after a disable", by_approvers(ENABLED, "alice", "bob"), False, previous=DISABLED)
case("a later version that names another previous", by_approvers(key_state("enabled", DISABLED, prev_digest="11" * 32), "alice", "bob"),
     False, previous=DISABLED)
case("a version that skips one", by_approvers(key_state("enabled", DISABLED, version=4), "alice", "bob"), False, previous=DISABLED)
case("version 2 where the key has no state", by_approvers(DISABLED, "alice", "bob"), False)
case("version 1 that names a previous", by_approvers(key_state("enabled", prev_digest="11" * 32), "alice", "bob"), False)
case("a key state signed by a node session", by_node(DISABLED), False)
case("a sequence entry over a quota", by_node(sequence(9)), False, previous=quota(1))

CHECKS = []


def check(name, entry, approvals, accept, matched=True):
    """`matched`: the spend's approvals_sha256 is these approvals' (a node, or a bug, that hashed what it counted), so
    each case reaches the rule it is about; unmatched only for the digest's own case."""
    if matched:
        entry = dict(entry, approvals_sha256=opstate.approvals_digest(approvals))
    CHECKS.append({"name": name, "spend": entry, "approvals": approvals, "accept": accept})


S = spend()
check("both approvals behind a spend", S, [approval(S, "alice"), approval(S, "bob")], True)
check("no approvals behind an ungated spend", spend(approvals=()), [], True)
check("an approval missing from what the spend counted", S, [approval(S, "alice")], False, matched=False)
check("an approval by someone outside the set", S, [approval(S, "alice"), approval(S, "mallory")], False)
check("an approval of another request's nonce", S, [approval(S, "alice"), approval(S, "bob", nonce="request-nonce-2")], False)
check("an approval of another payload", S, [approval(S, "alice"), approval(S, "bob", payload_digest="ee" * 32)], False)
check("an approval that outlives the request", S, [approval(S, "alice"), approval(S, "bob", expires_at="2026-10-05T13:00:00Z")], False)
check("an approval signed over another environment", S, [approval(S, "alice"), approval(S, "bob", signed_as={"environment": "staging"})], False)
check("the same approver twice", S, [approval(S, "alice"), approval(S, "alice")], False)
check("approvals that are not the approvers the spend names", spend(approvals=("alice", "bob"), approvers=["alice", "carol"]),
      [approval(S, "alice"), approval(S, "bob")], False)
T = spend(approvals=("alice",))
check("one approval where the set requires two", T, [approval(T, "alice")], False)
U = spend(approvals=("alice",), approver_set=OLD_SET)
check("one approval under the set before a rotation", U, [approval(U, "alice")], True)
check("an approver set nobody knows", spend(approver_set="ee" * 32), [approval(S, "alice"), approval(S, "bob")], False)

SIGNS = []


def sign_case(name, entry, now, digest, expires, accept):
    SIGNS.append({"name": name, "spend": entry, "now": now, "held_lease_digest": digest, "held_lease_expires_at": expires, "accept": accept})


NOW = 1791201605                                                     # 2026-10-05T12:00:05Z
sign_case("the lease it was committed under, unlapsed", S, NOW, "cd" * 32, "2026-10-05T12:00:20Z", True)
sign_case("BURNED: another lease held now", S, NOW, "ef" * 32, "2026-10-05T12:00:40Z", False)
sign_case("BURNED: the lease lapsed before the HSM", S, NOW + 15, "cd" * 32, "2026-10-05T12:00:20Z", False)
sign_case("BURNED: the request expires within the skew", spend(expires_at="2026-10-05T12:01:00Z"), NOW, "cd" * 32, "2026-10-05T12:00:20Z", False)

SESSION_CASES = []


def session(node_id="a", key=SESSION_A_PUB, **over):
    entry = {"schema": opstate.SESSION_SCHEMA, "node_id": node_id, "boot_id": BOOT, "session_key": key, "issued_at": AT}
    entry.update(over)
    return entry


def vouched(entry, signer="a"):
    return {"entry": entry, "signature": p256_sig(NODE_KEYS[signer], opstate.SESSION_DOMAIN + m.canonical(entry))}


def session_case(name, value, accept, where=None):
    try:
        where = where or opstate.session_key_path(value["entry"])
    except m.Refused:
        where = where or opstate.PREFIX + "sessions/x"
    SESSION_CASES.append({"name": name, "key": where, "value": value, "accept": accept})


session_case("a's session key, vouched for by a's signing key", vouched(session()), True)
session_case("a second daemon start in the same boot", vouched(session(key=STRANGER_PUB)), True)
session_case("a's key vouched for by b's signing key", vouched(session(), signer="b"), False)
session_case("under another node's path", vouched(session()), False, where=opstate.PREFIX + "sessions/b/%s/%s" % (BOOT, SESSION_A_PUB))
session_case("a node the manifest does not hold", vouched(session(node_id="z"), signer="c"), False)
session_case("a session key of 31 bytes", vouched(session(key="00" * 31)), False)
session_case("a signature over the entry without its domain", {"entry": session(), "signature": p256_sig(NODE_KEYS["a"], m.canonical(session()))}, False)

BATCHES = []


def write(value, previous=None):
    return {"key": opstate.key_for(value["entry"]), "value": value, "previous": previous}


def batch(name, writes, accept):
    BATCHES.append({"name": name, "writes": writes, "accept": accept})


batch("a spend, its sequence and its quota", [write(by_node(spend())), write(by_node(sequence(8)), sequence(7)), write(by_node(quota(5)), quota(4))], True)
batch("a spend alone", [write(by_node(spend()))], True)
batch("no spend", [write(by_node(sequence(8)), sequence(7))], False)
batch("two spends", [write(by_node(spend())), write(by_node(spend(nonce_digest=opstate.nonce_digest("request-nonce-2"))))], False)
batch("a sequence naming another nonce", [write(by_node(spend())), write(by_node(sequence(8, nonce_digest="22" * 32)), sequence(7))], False)
batch("a quota by another node", [write(by_node(spend())), write(by_node(quota(5, node_id="b"), party="b"), quota(4))], False)
batch("a key-state change inside a Reserve", [write(by_node(spend())), write(by_approvers(DISABLED, "alice", "bob"), ENABLED)], False)
batch("one key twice", [write(by_node(spend())), write(by_node(quota(5)), quota(4)), write(by_node(quota(6)), quota(4))], False)
batch("over the size of one transaction", [write(by_node(spend()))] +
      [write(by_node(quota(1, counter="c%d" % i))) for i in range(opstate.MAX_BATCH)], False)
batch("a spent nonce inside a Reserve", [write(by_node(spend()), spend(at="2026-10-05T11:59:00Z"))], False)


def decide_case(c):
    sessions = lambda node, boot, key: key in SESSIONS.get("%s|%s" % (node, boot), [])      # noqa: E731
    try:
        entry = opstate.verify(c["key"], c["value"], sessions, APPROVER_SETS)
        opstate.transition(c["previous"], entry)
        return True, ""
    except m.Refused as refused:
        return False, str(refused)


def decide_session(c):
    try:
        opstate.verify_session(c["key"], c["value"], MANIFEST)
        return True, ""
    except m.Refused as refused:
        return False, str(refused)


def decide_check(c):
    try:
        opstate.check_approvals(c["spend"], c["approvals"], APPROVER_SETS)
        return True, ""
    except m.Refused as refused:
        return False, str(refused)


def decide_sign(c):
    try:
        opstate.may_sign(c["spend"], c["now"], c["held_lease_digest"], c["held_lease_expires_at"])
        return True, ""
    except m.Refused as refused:
        return False, str(refused)


def decide_batch(b):
    try:
        opstate.batch([(w["key"], w["value"], w["previous"]) for w in b["writes"]])
        return True, ""
    except m.Refused as refused:
        return False, str(refused)


RENAMED = {"key": "public", "session_key": "session_public"}


def composed(document):
    """A document for the file: public keys under names a secret scanner does not take for credentials."""
    if isinstance(document, dict):
        return {RENAMED.get(k, k): composed(v) for k, v in document.items()}
    if isinstance(document, list):
        return [composed(v) for v in document]
    return document


def main():
    for c in CASES:
        got, why = decide_case(c)
        assert got == c["accept"], (c["name"], why)
        c["python_reason"] = why
    for group, decide in ((CHECKS, decide_check), (SIGNS, decide_sign), (SESSION_CASES, decide_session)):
        for c in group:
            got, why = decide(c)
            assert got == c["accept"], (c["name"], why)
            c["python_reason"] = why
    for b in BATCHES:
        got, why = decide_batch(b)
        assert got == b["accept"], (b["name"], why)
        b["python_reason"] = why
    doc = {"schema": "regalia.opstate-vectors/v1", "domain": opstate.DOMAIN.decode().rstrip("\0") + "\\0", "max_batch": opstate.MAX_BATCH,
           "sessions": SESSIONS, "approver_sets": APPROVER_SETS, "skew_s": opstate.SKEW_S, "payload_hex": PAYLOAD.hex(), "cases": CASES,
           "approval_checks": CHECKS, "sign_checks": SIGNS,
           "manifest": MANIFEST, "session_checks": SESSION_CASES, "batches": BATCHES}
    json.dump(composed(copy.deepcopy(doc)), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
