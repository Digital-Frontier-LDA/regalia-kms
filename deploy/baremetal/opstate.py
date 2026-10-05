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
  key-state  keys/<sha256(object_id)>/state       enabled, disabled or destroyed; destroyed is final. A chain: each
             entry names its version (previous + 1, the first 1) and the SHA-256 of the entry it replaces, both signed,
             so an old approved entry cannot be put back after a newer one (regalia-kms-ed on #488).

Names inside a key are hashed: a principal is a SPIFFE ID, and a "/" in a name must not make two keys one.

WHO SIGNS. spend, sequence and quota: the node that reserved them, with its daemon's session key, made at each daemon
start and named in its TPM-quoted runtime lease (lease v2, regalia-kms-95). The node's signature names the key, and the
key is vouched for by a SESSION entry (regalia-kms-ed's design): {node_id, boot_id, session_key, issued_at}, signed once
per daemon start by the node's manifest-pinned signing_key (domain SESSION_DOMAIN), at
sessions/<node>/<boot_id>/<session_key>, created only and never deleted. verify_session checks it against the CURRENT
manifest's key, as the etcd certificate binding is checked; `sessions` is the caller's resolver over verified ones. key-state: approvers under D25 (Ed25519, as internal/approval verifies),
`required` of a set the entry names by its digest (approver_set_digest), so an entry signed under an earlier set still
verifies after the set is rotated: the verifier keeps every set by digest (`approver_sets`), as it keeps manifests.

THE APPROVALS BEHIND A SPEND (regalia-kms-1e's D25 read of #488). The spend names the approver set it was judged under
(approver_set: the digest, as key-state; an ungated purpose is UNGATED_SET, no approvers) and the SHA-256 of the
approvals actually counted (approvals_sha256, approvals_digest). The signer's audit line carries those approvals, so a
collector re-verifies them (check_approvals): each internal/approval Approval signed by its approver over the request's
Binding (binding_bytes, internal/approval.CanonicalBytes), the threshold met, and exactly the IDs the spend names.
Without that, the one-spend check would prove single use, not that the approvals existed.

AT SIGN (may_sign, in this module so Python and Go decide it alike): the node still holds the very lease the spend
names, unlapsed, and the request expires more than SKEW_S from now. A spend whose lease lapsed before the HSM signed
is burned: the request is approved again.

THE TIE between a Reserve's entries is the spend's nonce_digest and node_id, written in one transaction: they share its
mod_revision, which is what a collector pairs them by.

DELETION. Nothing deletes under /regalia/v1/ but etcd's own lease expiry, for spends whose request has expired and
quota days that are over (an etcd role grants the daemons put, never delete, there). A spend's etcd lease lives
gc_ttl(spend) = (expires_at - at) + SKEW_S: etcd's leases run on its leader's clock, which may be ahead of the
signer's, and the key must outlive the request, or a replay of its nonce would be taken after the key vanished (1e).
sessions/<node>/<boot_id> is never deleted: every spend and audit line that names a session key must stay verifiable. A key-state entry is never
collected: a reader that has seen a key's state refuses its absence, and a version 1 entry after a later one is a
replay.

ONE RESERVE IS ONE TRANSACTION: a spend, its sequence and its quota counters, at most MAX_BATCH entries (etcd's
--max-txn-ops is 128), all or nothing (batch()). Transactions that lose a race are retried at most RETRIES times
with a fresh read, then refused: fail closed, one round trip each.

tests/vectors/opstate-v1.json (tests/vectors/make-opstate-v1.py) holds the cases; the Go verifier decides each alike.
"""
import base64
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
# the longest a request may still be spendable after it is spent (expires_at - at). A lone survivor's full scope
# (#432, the owner's one-server decision) waits attested_at + MAX_REQUEST_LIFE_S + SKEW_S, so every request the
# fenced far side could have spent before the owner attested it fenced has expired (regalia-kms-1e): a cap Reserve
# enforces, or there would be nothing to wait out
MAX_REQUEST_LIFE_S = 900
NAME = re.compile(r"[\x21-\x7e]{1,256}")        # a principal, object, purpose, environment, counter or sequence key
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
BOOT_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
NODE_SIGNED = ("spend", "sequence", "quota")

COMMON = ("schema", "kind", "at")
FIELDS = {
    "spend": COMMON + ("nonce_digest", "principal", "object_id", "purpose", "environment", "payload_sha256", "approvers",
                       "approver_set", "approvals_sha256", "node_id", "boot_id", "lease_digest", "lease_expires_at", "expires_at"),
    "sequence": COMMON + ("sequence_key", "value", "nonce_digest", "node_id", "boot_id"),
    "quota": COMMON + ("principal", "utc_date", "counter", "total", "cap", "nonce_digest", "node_id", "boot_id"),
    "key-state": COMMON + ("object_id", "state", "version", "prev_digest", "approver_set"),
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
        membership.hex_field(entry["approver_set"], 64, "approver_set")
        membership.hex_field(entry["approvals_sha256"], 64, "approvals_sha256")
        at = heartbeat.parse_time(entry["at"], "at")
        require(heartbeat.parse_time(entry["lease_expires_at"], "lease_expires_at") > at, "the signing node's lease had run out when it spent")
        expires = heartbeat.parse_time(entry["expires_at"], "expires_at")
        require(expires > at, "the request had expired when it was spent")
        require(expires - at <= MAX_REQUEST_LIFE_S, "the request stays spendable %d s after it is spent, more than %d s: refused (a lone "
                "survivor's wait is bounded by this)" % (expires - at, MAX_REQUEST_LIFE_S))
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
        require(isinstance(entry["version"], int) and not isinstance(entry["version"], bool) and 1 <= entry["version"] < 2 ** 63,
                "version must be an integer from 1")
        if entry["version"] == 1:
            require(entry["prev_digest"] == "", "the first state of a key replaces nothing (prev_digest \"\")")
        else:
            membership.hex_field(entry["prev_digest"], 64, "prev_digest")
        membership.hex_field(entry["approver_set"], 64, "approver_set")
    return kind


def approver_set_digest(approvers, required):
    """The digest a spend or a key-state entry names its approver set by: {approver ID: Ed25519 key hex} and the
    threshold. A purpose no approval gates is the empty set with threshold 0 (UNGATED_SET)."""
    return hashlib.sha256(membership.canonical({"approvers": approvers, "required": required})).hexdigest()


UNGATED_SET = approver_set_digest({}, 0)
SKEW_S = 60                   # between a signer's authenticated clock and etcd's leader: lease expiry and sign margins
APPROVAL_FIELDS = ("approver_id", "nonce", "expires_at", "payload_digest", "signature")     # internal/approval.Approval


SESSION_SCHEMA = "regalia.opstate-session/v1"
SESSION_DOMAIN = b"regalia-opstate-session/v1\0"
SESSION_FIELDS = ("schema", "node_id", "boot_id", "session_key", "issued_at")


def session_key_path(entry):
    """Where a session entry lives: one per daemon start (several in one boot)."""
    membership.exact(entry, SESSION_FIELDS, "the session entry")
    require(entry["schema"] == SESSION_SCHEMA, "schema must be %s" % SESSION_SCHEMA)
    require(isinstance(entry["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", entry["node_id"]) is not None, "node_id must be a node ID")
    require(isinstance(entry["boot_id"], str) and BOOT_ID.fullmatch(entry["boot_id"]) is not None, "boot_id must be a boot UUID")
    membership.hex_field(entry["session_key"], 64, "session_key")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["session_key"]))
    except ValueError:
        raise Refused("session_key is not an Ed25519 public key") from None
    heartbeat.parse_time(entry["issued_at"], "issued_at")
    return PREFIX + "sessions/%s/%s/%s" % (entry["node_id"], entry["boot_id"], entry["session_key"])


def session_message(entry):
    session_key_path(entry)
    return SESSION_DOMAIN + membership.canonical(entry)


def _signing_key(manifest, node_id):
    node = membership.validate(manifest).get(node_id)
    if node is None or "signing_key" not in node:
        return None
    return membership.typed_key(node["signing_key"], "%s's signing_key" % node_id, membership.SIGNING_KEY_ALGS)


def verify_session(key, value, chain):
    """The session at `key`, if the signing_key its node held WHEN IT WAS ISSUED signed it: (entry, valid_until), else
    Refused. `chain` is the verified membership chain, oldest first. The key in force at the session's issued_at is the
    newest manifest's issued at or before it (regalia-kms-1e on #492: judged by the CURRENT key alone, a key rotated
    later would make every earlier spend of that node unverifiable). The session vouches only until its node's key was
    replaced (`valid_until`: the issued_at of the first later manifest naming another key for the node, or None): a key
    replaced because it leaked cannot vouch for a session dated back before the replacement and be used after it, since
    verify() takes an entry only inside its session's window. Not judged by the node's state: a node revoked later keeps
    its earlier spends verifiable (their nonces stay spent); whether it may serve NOW is its lease's question."""
    membership.exact(value, ("entry", "signature"), "the session value")
    entry = value["entry"]
    require(key == session_key_path(entry), "the session entry belongs under %s, not %s" % (session_key_path(entry), key))
    require(isinstance(chain, list) and chain, "a session is judged against the membership chain")
    issued = heartbeat.parse_time(entry["issued_at"], "issued_at")
    at = [m for m in chain if heartbeat.parse_time(m["issued_at"], "a manifest's issued_at") <= issued]
    require(at, "%s's session is dated before the first manifest" % entry["node_id"])
    in_force = _signing_key(at[-1], entry["node_id"])
    require(in_force is not None, "%s had no signing key at epoch %d, when its session is dated" % (entry["node_id"], at[-1]["epoch"]))
    membership.verify_revocation(*in_force, session_message(entry), value["signature"], "%s's session entry" % entry["node_id"])
    later = [m for m in chain[chain.index(at[-1]) + 1:] if _signing_key(m, entry["node_id"]) != in_force]
    return entry, (later[0]["issued_at"] if later else None)


def approvals_digest(approvals):
    """What a spend names as approvals_sha256: SHA-256 of the canonical list of the approvals counted, by approver ID."""
    return hashlib.sha256(membership.canonical(sorted(approvals, key=lambda a: a.get("approver_id", "")))).hexdigest()


def binding_bytes(spend, nonce):
    """What every approver signed: internal/approval.Binding.CanonicalBytes for the request this spend consumed (its
    nonce in clear, from the approvals; its expiry whole seconds, as RFC 3339 writes them)."""
    lines = ["regalia-approval-v2\n"]
    for field in (spend["object_id"], spend["purpose"], spend["environment"], nonce, spend["expires_at"], spend["payload_sha256"]):
        raw = field.encode()
        lines.append("%d:" % len(raw) + field + "\n")
    return "".join(lines).encode()


def check_approvals(spend, approvals, approver_sets):
    """The collector's check that the approvals a spend names existed (1e on #488): `approvals` (from the signer's audit
    line) hash to approvals_sha256; each is an internal/approval Approval for this request (its nonce, its payload, an
    expiry not after the request's), signed by its approver under the set the spend names, once; the threshold met;
    the IDs exactly the spend's approvers. Returns the approver IDs, or Refused."""
    validate(spend)
    require(spend["kind"] == "spend", "only a spend has approvals")
    require(isinstance(approvals, list) and len(approvals) <= MAX_APPROVERS, "approvals must be a list of at most %d" % MAX_APPROVERS)
    require(approvals_digest(approvals) == spend["approvals_sha256"], "these are not the approvals the spend counted (approvals_sha256)")
    named = (approver_sets or {}).get(spend["approver_set"])
    require(named is not None and approver_set_digest(named["approvers"], named["required"]) == spend["approver_set"],
            "the approver set %s is not one this verifier knows" % spend["approver_set"][:16])
    counted = []
    for a in approvals:
        membership.exact(a, APPROVAL_FIELDS, "an approval")
        who = a["approver_id"]
        require(who in named["approvers"] and who not in counted, "%s is not an approver of the set, or counted twice" % membership.printable(who))
        require(isinstance(a["nonce"], str) and nonce_digest(a["nonce"]) == spend["nonce_digest"], "%s approved another request's nonce" % who)
        require(a["payload_digest"] == spend["payload_sha256"], "%s approved another payload" % who)
        expires = heartbeat.parse_time(a["expires_at"], "an approval's expires_at")
        require(expires <= heartbeat.parse_time(spend["expires_at"], "expires_at"), "%s's approval outlives the request" % who)
        require(expires > heartbeat.parse_time(spend["at"], "at"), "%s's approval had expired when the request was spent" % who)
        try:
            sig = base64.b64decode(a["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(named["approvers"][who])).verify(sig, binding_bytes(spend, a["nonce"]))
        except (InvalidSignature, ValueError):
            raise Refused("%s's approval does not verify over the request's binding" % who) from None
        counted.append(who)
    require(len(counted) >= named["required"], "%d of %d required approvals" % (len(counted), named["required"]))
    require(sorted(counted) == spend["approvers"], "the spend names %s; the approvals are %s's" % (spend["approvers"], sorted(counted)))
    return sorted(counted)


def may_sign(spend, now, held_lease_digest, held_lease_expires_at):
    """At sign, after the spend committed and before the HSM is used: the node still holds the very lease the spend
    names, unlapsed at `now` (its authenticated seconds), and the request expires more than SKEW_S from now. Refused
    otherwise: the spend is burned and the request approved again."""
    validate(spend)
    require(spend["kind"] == "spend", "only a spend is signed under")
    # both expiries are the lease envelope's own text (the spend copied it), so they compare as strings
    require(held_lease_digest == spend["lease_digest"] and held_lease_expires_at == spend["lease_expires_at"],
            "BURNED: this node no longer holds the lease the spend was committed under")
    require(now < heartbeat.parse_time(spend["lease_expires_at"], "lease_expires_at"), "BURNED: the lease the spend names has lapsed")
    require(now + SKEW_S < heartbeat.parse_time(spend["expires_at"], "expires_at"),
            "BURNED: the request expires within %d s: its spend's key might be collected before it" % SKEW_S)


def gc_ttl(spend):
    """The etcd lease a spend's key is written with, in seconds: it outlives the request by SKEW_S on any leader's clock."""
    validate(spend)
    return heartbeat.parse_time(spend["expires_at"], "expires_at") - heartbeat.parse_time(spend["at"], "at") + SKEW_S


def entry_digest(entry):
    """What the next key-state entry names as prev_digest."""
    return hashlib.sha256(membership.canonical(entry)).hexdigest()


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


def verify(key, value, sessions, approver_sets=None):
    """The entry stored at etcd key `key` as `value`, if it verifies, else Refused (and the entry is unavailable).
    Called on every read; fresh() is the check at arrival that makes an entry's `at` real time.
    `sessions(node_id, boot_id, session_key, at)` is true when a verified session entry (verify_session) names that key
    for that node and boot and `at` (the entry's) lies in its window: from its issued_at, before its valid_until. A
    daemon start makes a key, so one boot may have several.
    `approver_sets` ({digest: {"approvers": {ID: Ed25519 key hex}, "required": n}}, every set the policy has had)
    judges a key-state entry (D25) by the set it names."""
    membership.exact(value, ("entry", "signatures"), "the opstate value")
    entry, signatures = value["entry"], value["signatures"]
    require(key == key_for(entry), "the entry belongs under %s, not %s" % (key_for(entry), key))
    raw = message(entry)
    require(isinstance(signatures, list) and signatures, "the entry carries no signature")
    if entry["kind"] in NODE_SIGNED:
        require(len(signatures) == 1, "a node's entry carries exactly one signature")
        sig = signatures[0]
        membership.exact(sig, ("party", "boot_id", "session_key", "sig"), "the node's signature")
        require(sig["party"] == entry["node_id"] and sig["boot_id"] == entry["boot_id"],
                "the entry is signed as %s, boot %s; it names %s, boot %s" % (sig["party"], sig["boot_id"], entry["node_id"], entry["boot_id"]))
        membership.hex_field(sig["session_key"], 64, "the signature's session_key")
        require(sessions(entry["node_id"], entry["boot_id"], sig["session_key"], entry["at"]),
                "no verified session entry names that key for %s in boot %s at %s" % (entry["node_id"], entry["boot_id"], entry["at"]))
        _ed25519(sig["session_key"], sig["sig"], raw, "%s's session" % entry["node_id"])
        return entry
    named = (approver_sets or {}).get(entry["approver_set"])
    require(named is not None, "the approver set %s is not one this verifier knows" % entry["approver_set"][:16])
    approvers, required = named["approvers"], named["required"]
    require(approver_set_digest(approvers, required) == entry["approver_set"], "the approver set held under %s is not that set"
            % entry["approver_set"][:16])
    require(isinstance(required, int) and not isinstance(required, bool) and required >= 1 and approvers,
            "a key-state change needs an approver set and a threshold")
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


def fresh(entry, now):
    """At the moment a reader observes an entry's creation (its watch, or a co-signer acting on it), Refused unless the
    entry's `at` is within SKEW_S of the reader's authenticated `now`. A session window bounds `at`, but `at` is signed
    by the session key itself: a replaced key that vouched for a backdated session could also backdate its entries into
    that window (regalia-kms-1e on #492). Judged on arrival, the window bounds real time, not claimed time. A collector
    judges `at` likewise against the time it saw the entry's create revision arrive."""
    validate(entry)
    at = heartbeat.parse_time(entry["at"], "at")
    require(abs(now - at) <= SKEW_S, "the entry is dated %s, %d s from this reader's clock when it arrived (more than %d s): refused"
            % (entry["at"], int(now - at), SKEW_S))


def transition(previous, entry):
    """Whether `entry` may replace `previous` (None: the key does not exist), both verified. What etcd's compare
    cannot say: the transaction already requires the previous value to be what was read."""
    kind = entry["kind"]
    if previous is None:
        require(kind != "key-state" or entry["version"] == 1, "the key %s has no state on record; version %d replaces one"
                % (entry.get("object_id"), entry.get("version", 0)))
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
        require(entry["version"] == previous["version"] + 1 and entry["prev_digest"] == entry_digest(previous),
                "REPLAY: the key %s is at version %d; this entry is version %d over another state" % (entry["object_id"], previous["version"], entry["version"]))


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
