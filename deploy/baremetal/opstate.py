#!/usr/bin/env python3
"""The operational state the three servers share through etcd (ADR-0002 D32, #432): the entry format, the key each
entry lives under, and its verification. etcd orders and replicates; it never decides. It is crash-tolerant, not
Byzantine-tolerant, so EVERY ENTRY CARRIES ITS OWN AUTHORIZATION and every server verifies it before acting on it:
an entry that does not verify is unavailable, never taken for its previous value.

    value = {"entry": {"schema": "regalia.opstate/v1", "kind": ..., ...}, "signatures": [...]}

signed over DOMAIN + canonical(entry): opstate's own domain, so no heartbeat, lease or manifest signature is ever one.

KINDS, and the key under /regalia/v1/ each lives at (key_for):

  spend      nonces/<sha256(nonce)>               a request's nonce consumed, once, before the HSM signs. It is what
             makes an approval single-use (approvers sign Binding{object, purpose, environment, nonce, expiry,
             payload}), and binds the D25 facts (regalia-kms-1e): the nonce digest, principal, object, purpose,
             environment, payload SHA-256, the approver IDs counted, the ONE node that signs, that node's lease
             (digest and expiry; a lapse burns the spend) and the Binding's expiry (compaction keeps the key until
             then). Created only: Txn If version == 0.
  sequence   seq/<sha256(sequence_key)>           a per-key high-water mark (a chain's sign height or sequence). Each
             value is above the one it replaces: Txn If value == previous.
  quota      quota/<sha256(principal)>/<utc_date>/<sha256(counter)>   a principal's running total for the day, at
             most its cap.
  key-state  keys/<sha256(object_id)>/state       enabled, disabled or destroyed; destroyed is final.

Names inside a key are hashed: a principal is a SPIFFE ID, and a "/" in a name must not make two keys one.

WHO SIGNS. spend, sequence and quota: the node that reserved them, with its per-boot session key. The daemon makes
that key at each start; the node's TPM-quoted runtime lease names it (lease v2, regalia-kms-95), and
sessions/<node>/<boot_id> keeps that lease, so a verifier resolves (node_id, boot_id) to the key long after the lease
ran out (`sessions`, the caller's resolver). key-state: approvers under D25, `required` of the `approvers` key set
(Ed25519, as internal/approval verifies), or the owner as one of them.

ONE RESERVE IS ONE TRANSACTION: a spend, its sequence and its quota counters, at most MAX_BATCH entries (etcd's
--max-txn-ops is 128), all or nothing (batch()). Transactions that lose a race are retried at most RETRIES times
with a fresh read, then refused: fail closed, one round trip each.

tests/vectors/opstate-v1.json (tests/vectors/make-opstate-v1.py) holds the cases; the Go verifier decides each alike.
"""
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from deploy.baremetal import heartbeat, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.opstate/v1"
DOMAIN = b"regalia-opstate/v1\0"
PREFIX = "/regalia/v1/"
KINDS = ("spend", "sequence", "quota", "key-state")
KEY_STATES = ("enabled", "disabled", "destroyed")
MAX_BATCH = 64                # entries in one Reserve's transaction; etcd allows 128 operations
RETRIES = 3                   # a transaction that lost a race: read again and retry, at most this often, then refuse
MAX_ENTRY_BYTES = 4096
MAX_APPROVERS = 64            # internal/approval.MaxApprovals
NAME = re.compile(r"[\x21-\x7e]{1,256}")        # a principal, object, purpose, environment, counter or sequence key
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
BOOT_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
NODE_SIGNED = ("spend", "sequence", "quota")

COMMON = ("schema", "kind", "at")
FIELDS = {
    "spend": COMMON + ("nonce_digest", "principal", "object_id", "purpose", "environment", "payload_sha256", "approvers",
                       "node_id", "boot_id", "lease_digest", "lease_expires_at", "expires_at"),
    "sequence": COMMON + ("sequence_key", "value", "nonce_digest", "node_id", "boot_id"),
    "quota": COMMON + ("principal", "utc_date", "counter", "total", "cap", "nonce_digest", "node_id", "boot_id"),
    "key-state": COMMON + ("object_id", "state"),
}


def _name(value, label):
    require(isinstance(value, str) and NAME.fullmatch(value) is not None, "%s must be 1 to 256 printable characters, no space" % label)


def _count(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2 ** 63, "%s must be an integer from 0" % label)


def nonce_digest(nonce):
    """The key a request's nonce is spent under: SHA-256 of its UTF-8 bytes, hex."""
    require(isinstance(nonce, str) and nonce, "a nonce is a non-empty string")
    return hashlib.sha256(nonce.encode()).hexdigest()


def validate(entry):
    """Schema only. Returns the entry's kind."""
    require(isinstance(entry, dict), "the entry must be an object")
    require(entry.get("kind") in KINDS, "kind must be one of %s" % ", ".join(KINDS))
    kind = entry["kind"]
    membership.exact(entry, FIELDS[kind], "the %s entry" % kind)
    require(entry["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    heartbeat.parse_time(entry["at"], "at")
    require(len(membership.canonical(entry)) <= MAX_ENTRY_BYTES, "the entry is over %d bytes" % MAX_ENTRY_BYTES)
    if kind in NODE_SIGNED:
        require(isinstance(entry["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", entry["node_id"]) is not None,
                "node_id must be a node ID")
        require(isinstance(entry["boot_id"], str) and BOOT_ID.fullmatch(entry["boot_id"]) is not None, "boot_id must be a boot UUID")
        membership.hex_field(entry["nonce_digest"], 64, "nonce_digest")
    if kind == "spend":
        for k in ("principal", "object_id", "purpose", "environment"):
            _name(entry[k], k)
        membership.hex_field(entry["payload_sha256"], 64, "payload_sha256")
        membership.hex_field(entry["lease_digest"], 64, "lease_digest")
        approvers = entry["approvers"]
        require(isinstance(approvers, list) and len(approvers) <= MAX_APPROVERS, "approvers must be a list of at most %d" % MAX_APPROVERS)
        for a in approvers:
            _name(a, "an approver ID")
        require(approvers == sorted(set(approvers)), "approvers must be sorted, each once")
        at = heartbeat.parse_time(entry["at"], "at")
        require(heartbeat.parse_time(entry["lease_expires_at"], "lease_expires_at") > at, "the signing node's lease had run out when it spent")
        require(heartbeat.parse_time(entry["expires_at"], "expires_at") > at, "the request had expired when it was spent")
    elif kind == "sequence":
        _name(entry["sequence_key"], "sequence_key")
        _count(entry["value"], "value")
    elif kind == "quota":
        _name(entry["principal"], "principal")
        require(isinstance(entry["utc_date"], str) and DATE.fullmatch(entry["utc_date"]) is not None, "utc_date must be YYYY-MM-DD")
        heartbeat.parse_time(entry["utc_date"] + "T00:00:00Z", "utc_date")
        _name(entry["counter"], "counter")
        _count(entry["total"], "total")
        _count(entry["cap"], "cap")
        require(entry["total"] <= entry["cap"], "the total %d is over the cap %d" % (entry["total"], entry["cap"]))
    else:
        _name(entry["object_id"], "object_id")
        require(entry["state"] in KEY_STATES, "state must be one of %s" % ", ".join(KEY_STATES))
    return kind


def _h(name):
    return hashlib.sha256(name.encode()).hexdigest()


def key_for(entry):
    """The etcd key the entry lives under (validated first)."""
    kind = validate(entry)
    if kind == "spend":
        return PREFIX + "nonces/" + entry["nonce_digest"]
    if kind == "sequence":
        return PREFIX + "seq/" + _h(entry["sequence_key"])
    if kind == "quota":
        return PREFIX + "quota/%s/%s/%s" % (_h(entry["principal"]), entry["utc_date"], _h(entry["counter"]))
    return PREFIX + "keys/%s/state" % _h(entry["object_id"])


def message(entry):
    validate(entry)
    return DOMAIN + membership.canonical(entry)


def _ed25519(key_hex, sig_hex, raw, label):
    membership.hex_field(key_hex, 64, "%s key" % label)
    membership.hex_field(sig_hex, 128, "%s signature" % label)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(bytes.fromhex(sig_hex), raw)
    except (InvalidSignature, ValueError):
        raise Refused("%s signature does not verify" % label)


def verify(key, value, sessions, approvers=None, required=0):
    """The entry stored at etcd key `key` as `value`, if it verifies, else Refused (and the entry is unavailable).
    `sessions(node_id, boot_id)` returns that boot's session key (64 hex), or None when no verified lease named one.
    `approvers` ({approver ID: Ed25519 key hex}) and `required` judge a key-state entry (D25)."""
    membership.exact(value, ("entry", "signatures"), "the opstate value")
    entry, signatures = value["entry"], value["signatures"]
    require(key == key_for(entry), "the entry belongs under %s, not %s" % (key_for(entry), key))
    raw = message(entry)
    require(isinstance(signatures, list) and signatures, "the entry carries no signature")
    if entry["kind"] in NODE_SIGNED:
        require(len(signatures) == 1, "a node's entry carries exactly one signature")
        sig = signatures[0]
        membership.exact(sig, ("party", "boot_id", "sig"), "the node's signature")
        require(sig["party"] == entry["node_id"] and sig["boot_id"] == entry["boot_id"],
                "the entry is signed as %s, boot %s; it names %s, boot %s" % (sig["party"], sig["boot_id"], entry["node_id"], entry["boot_id"]))
        session = sessions(entry["node_id"], entry["boot_id"])
        require(session is not None, "no verified lease names a session key for %s in boot %s" % (entry["node_id"], entry["boot_id"]))
        _ed25519(session, sig["sig"], raw, "%s's session" % entry["node_id"])
        return entry
    require(isinstance(required, int) and required >= 1 and approvers, "a key-state change needs an approver set and a threshold")
    require(len(signatures) <= MAX_APPROVERS, "at most %d approvals" % MAX_APPROVERS)
    counted = set()
    for sig in signatures:
        membership.exact(sig, ("party", "sig"), "an approval")
        party = sig["party"]
        require(isinstance(party, str) and party in approvers, "%s is not an approver" % membership.printable(party))
        require(party not in counted, "%s approved twice" % party)
        _ed25519(approvers[party], sig["sig"], raw, "%s's approval" % party)
        counted.add(party)
    require(len(counted) >= required, "%d of %d required approvals" % (len(counted), required))
    return entry


def transition(previous, entry):
    """Whether `entry` may replace `previous` (None: the key does not exist), both verified. What etcd's compare
    cannot say: the transaction already requires the previous value to be what was read."""
    kind = entry["kind"]
    if previous is None:
        return
    require(previous["kind"] == kind, "a %s entry cannot replace a %s entry" % (kind, previous["kind"]))
    if kind == "spend":
        raise Refused("SPENT: the nonce %s was spent by %s at %s" % (entry["nonce_digest"][:16], previous["node_id"], previous["at"]))
    if kind == "sequence":
        require(entry["value"] > previous["value"], "the sequence %s is at %d; %d is not above it" % (entry["sequence_key"], previous["value"], entry["value"]))
    elif kind == "quota":
        require(entry["total"] > previous["total"], "a quota total only grows within its day (%d, then %d)" % (previous["total"], entry["total"]))
    else:
        require(previous["state"] != "destroyed", "the key %s is destroyed: its state is final" % entry["object_id"])


def batch(writes):
    """One Reserve's transaction, [(key, value, previous entry or None)], every value already verified (verify()): at most MAX_BATCH, each key once, and one
    spend that every other entry names by its nonce digest. Returns the spend's nonce digest."""
    require(isinstance(writes, list) and 0 < len(writes) <= MAX_BATCH, "a transaction holds 1 to %d entries" % MAX_BATCH)
    keys = [k for k, _, _ in writes]
    require(len(set(keys)) == len(keys), "a transaction writes each key once")
    spends = [v["entry"] for _, v, _ in writes if v["entry"].get("kind") == "spend"]
    require(len(spends) == 1, "a transaction holds exactly one spend (%d here)" % len(spends))
    digest = spends[0]["nonce_digest"]
    for _, value, previous in writes:
        entry = value["entry"]
        require(entry.get("kind") != "key-state", "a key-state change is its own transaction, never part of a Reserve")
        require(entry["nonce_digest"] == digest and entry["node_id"] == spends[0]["node_id"],
                "every entry of a Reserve names its spend's nonce and node")
        transition(previous, entry)
    return digest
