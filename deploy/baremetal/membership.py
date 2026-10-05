#!/usr/bin/env python3
"""Signed cluster membership with rollback-safe epochs (#68, Phase 8 of #59).

A manifest names every node, its identities and its state. Peers decide who may be unlocked, who may
authorize an unlock and who may serve from the newest manifest they have accepted, never from what a
node claims (THREE-SITE-THREAT-MODEL.md S2, ADR-0002 D23).

    envelope = {"manifest": {...}, "signature": {"signer": "root" | "revocation", "key": "<hex Ed25519 public key>",
                                                 "sig": "<hex Ed25519 signature>"}}
             | {"manifest": {...}, "signatures": [{"party": "<node_id>" | "owner", "key": "<hex>", "sig": "<hex>"}, ...]}  (v4)

    manifest = {"schema": "regalia.membership/v1" | ... | "regalia.membership/v4", "epoch": <int >= 1>,
                "prev_digest": "<64 hex, or "" at epoch 1>",
                "policy_version": "<text>", "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
                "heartbeat_max_lifetime_s": <int> (v2 only),
                "revocation_keys": ["<hex Ed25519 public key>" | {"alg": "ecdsa-p256", "key": "<hex>"}, ...],
                "nodes": [{"node_id": ..., "state": ..., "ek_name": ..., "ak_name": ..., "wg_boot_pub": ...,
                           "wg_service_pub": ..., "hsm_serials": [...],
                           "ssh_host_pub": ... (v2; absent from a node retired before it had one)}]}

Signed message: b"regalia-membership/v1\\0" + canonical JSON of the manifest (sorted keys, no spaces,
ASCII). Parsing refuses duplicate keys, unknown or missing fields, floats and non-ASCII names, so one
document has exactly one meaning. The prefix names the envelope format and is the same for both schemas;
the schema is a field of the signed manifest.

Schemas (#143). v2 is v1 plus two required fields.
  * A node field, `ssh_host_pub`: the node's SSH host key, a raw Ed25519 public key as 64 lowercase hex.
    It is an identity like the others: unique by value across every node and every role, unchangeable
    by a revocation key, and kept by a tombstone. It is required of every node that is not RETIRED or
    REVOKED_STOLEN. A node retired under v1 has no host key on record, and its hardware may be gone:
    its tombstone keeps exactly the fields it had, in v2 manifests too, and nothing is invented for
    it. A node retired under v2 keeps the key it had.
  * A manifest field, `heartbeat_max_lifetime_s` (#69): the longest life a heartbeat may have under this
    manifest, in seconds, from one hour to HEARTBEAT_HARD_MAX_S (seven days, a constant here that no
    manifest can exceed). It is the window in which a partitioned peer still helps a node revoked
    elsewhere, so it is the root's to set, like the policy version: a revocation key cannot change it.
    There is no default: it is in the signed manifest, or the manifest is invalid.
v3 is v2 with typed keys (below).

Schema v4 (#199: the three nodes and the owner sign; there is no authority host and no revocation key).
v3's fields without `revocation_keys`, and:
  * a node field, `signing_key`: {"alg": "ecdsa-p256", "key": <130 hex>}, a key in the node's own TPM that
    signs only in an approved image's booted phase (PolicyAuthorize of the system-phase PCR key, #242). An
    identity like ssh_host_pub: unique across every node, every role and the owner's keys, set only by the
    root, kept by a tombstone. Every node that is not RETIRED or REVOKED_STOLEN has one; a node retired
    before v4 keeps the fields it had;
  * `owner_keys`: one to eight typed keys, {"alg": "ed25519", "key": <64 hex>} (the approval YubiKeys'
    OpenPGP applet, #126) or ecdsa-p256, together ONE party named "owner". The key's touch policy is
    "fixed" (D26, rc#111: always required, and unchangeable without deleting the key), so an owner
    signature comes from a present human, never a daemon: a setting of the token, which no signature
    shows, and which the ceremony enforces. No owner key (nor any signing_key) may be a pinned root key
    (accept() refuses it): one device is never both the payload root and a quorum party;
  * `owner_heartbeat_lifetime_s`: the longest life of a heartbeat whose counting signatures include the
    owner's (an emergency credential), from 300 s to heartbeat_max_lifetime_s. Such a heartbeat is always
    the owner AND at least one node: the heartbeat threshold is at least 2 and the owner is one party
    however many of its keys sign, so no rule admits the owner alone;
  * `heartbeat_signers`: {"threshold", "parties"}, the parties node IDs or "owner";
  * `activation_signers`: the same form, for activation leases (#199: a node quorum, signed by the nodes
    once the lease side lands; in the format now so that it needs no further schema);
  * `revocation_signers`: one to four such rules, any one of which signs a restrictive change;
  * `anchor_policy_key`: {"alg": "ecdsa-p256", "key": <130 hex>}, K_A, the anchor-policy authority (#361): an offline
    Shamir software key (D28) under whose PolicyAuthorize every node's anchor, counters and signing key are defined at
    enrolment (anchorpolicy.py). Set at genesis and NEVER changed, by any signer, the root included: a node's TPM
    objects name it, so a new one is a new genesis. Distinct from every other key here and from the pinned root;
  * `card_record`: {"sequence", "digest"}, the card ceremony's record (cardrecord.py, #405) that names owner_keys:
    its sequence (an integer from 1) and the SHA-256 of its canonical form (64 hex). Only the root changes it; when
    it changes its sequence rises, and owner_keys change only together with it.
  THE FLOORS ARE THE FORMAT'S: the heartbeat and activation thresholds are at least 2, a revocation rule that names a node
  needs at least 2, and only a rule naming the owner alone may be 1; no threshold exceeds its parties.
  A quorum-signed envelope is {"manifest", "signatures": [{"party", "key", "sig"}, ...]}: every signature
  over the same DOMAIN + canonical(manifest), by the key the CURRENT manifest gives that party and verified
  the way that key's entry says (P-256 low-S for a node, Ed25519 for the owner), all verifying, no party twice. A RETIRED, REVOKED_STOLEN or QUARANTINED node does not count. A quorum
  may make only the changes a revocation key could (restrictive), and changes none of the signer fields.
  The move to v4 is one root-signed step, after every verifier has learnt it; revocation_keys end there.
Each manifest is
validated under the schema it names, so a chain that starts at v1 and moves to v2 verifies from epoch 1.
The schema only moves forward, and only in a ROOT-signed manifest: v1 may be followed by v1 or v2, v2
only by v2, and a revocation key cannot change it. A first manifest may be either.

Transition rules (accept(current, candidate)):
  * the epoch rises by exactly one and prev_digest is the digest of the current manifest: a strict hash
    chain, so two different manifests at one epoch (a conflict) cannot both be accepted, and a node that
    missed manifests catches up by verifying the chain in order (accept_chain);
  * the ROOT key (pinned, offline) may enroll, replace, change identities, change the revocation keys
    and restore trust. Two things it cannot do (below): remove a node, and revive a retired one;
  * a REVOCATION key (named by the root in the current manifest) may only make RESTRICTIVE changes:
    the same nodes, identities, policy version and revocation keys, and each node's capabilities a
    subset of what they were;
  * NO NODE IS EVER REMOVED, by any signer: a node leaves service by being retired, and a mistaken
    enrollment is corrected the same way, so the identities a node holds WHEN IT IS RETIRED are never
    forgotten. This is not a history of every identity: the root may rotate a live node's AK or
    WireGuard keys, and the values it replaces are then no longer listed;
  * RETIREMENT IS TERMINAL, for every signer: a RETIRED or REVOKED_STOLEN node stays in every later
    manifest as a tombstone (the same node_id, identities and HSM serials; RETIRED may only become
    REVOKED_STOLEN). Its hardware can then never be enrolled again, under any name: the uniqueness rule
    sees the tombstone. The manifest therefore grows by one entry per retired node, for ever, and that is
    intended. Hardware that may return belongs in MAINTENANCE or QUARANTINED, which the root can reverse;
  * the TPM-backed high-water mark (HighWater) anchors the accepted epoch AND which manifest it was: a
    counter for the epoch, and beside it a record of (epoch, SHA-256 of the manifest at that epoch). Store
    keeps the signed chain on disk, refuses at load a chain older than the high-water (a restored disk)
    or one whose manifest at the anchored epoch is not the recorded one (a substituted disk); either is
    recovered by fetching the chain from a peer. After each durable commit it advances the counter, then
    writes the record.

Capabilities by state (the #59 matrix): ACTIVE serves, requests bootstrap and authorizes peers;
MAINTENANCE only requests; DRAINING only serves; QUARANTINED, RETIRED and REVOKED_STOLEN nothing.
"""
import contextlib
import copy
import datetime
import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SCHEMA = "regalia.membership/v1"
SCHEMA_V2 = "regalia.membership/v2"
# v3 is v2 with TYPED keys allowed (an {"alg": ...} entry, ECDSA P-256 for keys held on a Nitrokey, whose
# PKCS#11 has no EdDSA). Gated behind its own version so that a verifier that knows only Ed25519 (the
# initrd's Go accept() until it is ported) refuses the whole manifest rather than misreading a key: the
# switch is one root-signed step, after every verifier that will see it has learnt v3.
SCHEMA_V3 = "regalia.membership/v3"
# v4 (#199: no authority host) drops the revocation keys. Heartbeats and restrictive changes are signed by a
# QUORUM of parties the manifest names: each node by a key in its own TPM (signing_key), and the owner by any
# one of the approval keys (owner_keys). See "Schema v4" in the docstring.
SCHEMA_V4 = "regalia.membership/v4"
SCHEMAS = (SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4)          # in order: a chain never goes back
HEARTBEAT_MIN_S, HEARTBEAT_HARD_MAX_S = 3600, 7 * 24 * 3600      # what a v2 manifest may set as heartbeat_max_lifetime_s
OWNER_HEARTBEAT_MIN_S = 300                                      # the least a v4 manifest may set as owner_heartbeat_lifetime_s
OWNER = "owner"                                                  # the owner's party name in a v4 signer rule (never a node_id)
HEARTBEAT_FLOOR = NODE_RULE_FLOOR = 2                            # no single party keeps a cluster alive or revokes alone,
                                                                 # except the owner's own revocation rule (1 of owner)
MAX_OWNER_KEYS, MAX_RULES, MAX_SIGNATURES = 8, 4, 16
# the bench's tokens, never a production node's token nor a ceremony card (ADR-0002 D28.5, D30): the Nitrokeys of regalia's
# tools/hsm-staging-registry.json and DENK0400664 (dead), the staging Pico HSMs, and the staging YubiKeys
# (regalia-ceremony's BENCH_YUBIKEYS). One list for every reader here; a YubiKey in each form a node's hsm_serials pins
# it (decimal, OpenPGP 0006%08d). The destructive drills' STAGING_SERIALS default (e2e/pkcs11-*.sh) is the live part of
# it, the Nitrokeys but the dead one and the Picos: a test holds the two equal.
BENCH_NITROKEYS = ("DENK0404144", "DENK0404380", "DENK0404547", "DENK0400664")
BENCH_NITROKEYS_DEAD = ("DENK0400664",)
BENCH_PICOS = ("ESP2202E14A", "ESP41D722E2")
BENCH_YUBIKEYS = ("36345471", "36344616", "35718625")
BENCH_TOKENS = frozenset(BENCH_NITROKEYS + BENCH_PICOS + BENCH_YUBIKEYS + tuple("0006%08d" % int(s) for s in BENCH_YUBIKEYS))
DOMAIN = b"regalia-membership/v1\0"
MAX_BYTES = 256 * 1024
MAX_CHAIN_BYTES = 64 * 1024 * 1024
CAPABILITIES = {
    "ACTIVE": frozenset({"serve", "request", "authorize"}),
    "MAINTENANCE": frozenset({"request"}),
    "DRAINING": frozenset({"serve"}),
    "QUARANTINED": frozenset(), "RETIRED": frozenset(), "REVOKED_STOLEN": frozenset(),
}
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")   # [0-9], never \d: ASCII only
MANIFEST_KEYS = ("schema", "epoch", "prev_digest", "policy_version", "issued_at", "revocation_keys", "nodes")
NODE_KEYS = ("node_id", "state", "ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials")
IDENTITY_KEYS = ("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub")
V2_MANIFEST_KEYS = MANIFEST_KEYS + ("heartbeat_max_lifetime_s",)
V2_NODE_KEYS = NODE_KEYS + ("ssh_host_pub",)
V2_IDENTITY_KEYS = IDENTITY_KEYS + ("ssh_host_pub",)
SIGNER_FIELDS = ("owner_heartbeat_lifetime_s", "owner_keys", "heartbeat_signers", "activation_signers", "revocation_signers")
# #361/#405: K_A (immutable, every signer) and the card ceremony's record that names owner_keys (the root's)
V4_ONLY_FIELDS = ("anchor_policy_key", "card_record")
MAX_CARD_SEQUENCE = 2 ** 31 - 1                                  # exact in every JSON reader
SINGLE_RULES = ("heartbeat_signers", "activation_signers")       # one rule each; revocation_signers is a list of them
V4_MANIFEST_KEYS = tuple(k for k in V2_MANIFEST_KEYS if k != "revocation_keys") + SIGNER_FIELDS + V4_ONLY_FIELDS
V4_NODE_KEYS = V2_NODE_KEYS + ("signing_key",)
# What only the root may change: a quorum (or a v1-v3 revocation key) leaves every one as it was.
ROOT_FIELDS = ("policy_version", "revocation_keys", "heartbeat_max_lifetime_s") + SIGNER_FIELDS + ("card_record",)
# A node that is retired, revoked or quarantined is named in a signer rule but does not count.
NOT_COUNTING = ("RETIRED", "REVOKED_STOLEN", "QUARANTINED")


class Refused(Exception):
    pass


class Unusable(Refused):
    """The TPM answered, and what it holds cannot serve as this node's anchor: an index that is not
    defined or is not of the right kind, no valid record, a counter and a record that are out of step.
    Distinct from a TPM that did not answer (a plain Refused): only this is what re-anchoring repairs."""


@contextlib.contextmanager
def _exclusive(lock_path):
    """An exclusive flock held for the block: every read-modify-write of the anchor or the stored
    chain is serialized across processes on the host."""
    import os
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def require(cond, message):
    if not cond:
        raise Refused(message)


def require_anchor(cond, message):
    if not cond:
        raise Unusable(message)


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate field %r" % k)
        out[k] = v
    return out


def _no_float(text):
    raise Refused("floats are not allowed (%s)" % text)


def load(raw, limit=MAX_BYTES):
    require(isinstance(raw, (bytes, str)) and len(raw) <= limit, "a document is at most %d bytes here" % limit)
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    except ValueError as error:
        raise Refused("not valid JSON: %s" % error)
    except RecursionError:
        raise Refused("not valid JSON: nested too deeply")


NAME_LIMIT = 240          # a name in an audit event or a message: a node ID, a host, a source
REASON_LIMIT = 4096       # the reason of a refusal: a PCR refusal names every differing value (attest.differences)


def printable(text, limit=NAME_LIMIT):
    """`text` as one line of printable ASCII for an audit trail or a log, cut at `limit` characters: what a
    caller or a node supplied cannot inject a line break or a terminal escape. One helper, so the trails
    of convergence, admission and authtime cut alike."""
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:limit]


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(manifest):
    return hashlib.sha256(canonical(manifest)).hexdigest()


def exact(value, keys, label):
    require(isinstance(value, dict), "%s must be an object" % label)
    missing, unknown = set(keys) - set(value), set(value) - set(keys)
    require(not missing and not unknown, "%s fields mismatch: missing=%s unknown=%s" % (label, sorted(missing), sorted(unknown)))


def hex_field(value, n, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % n, value) is not None, "%s must be %d lowercase hex" % (label, n))


# ---- revocation keys: Ed25519, or ECDSA P-256 (the HSM's: its PKCS#11 has no EdDSA) ----
#
# A manifest's revocation_keys entry is either a bare 64-hex string, an Ed25519 key for ever, or
# {"alg": "ecdsa-p256", "key": "<130 hex: 04 || X || Y>"}. THE ALGORITHM COMES FROM THE ENTRY ONLY, never from
# a signature or the message: a signature names its key by that key's hex, and is verified the way the
# manifest's entry for that hex says. A malformed entry (an unknown alg, a point not on the curve, the
# wrong length) makes the manifest invalid when it is validated, not when something is verified with it.
# ECDSA signs SHA-256 over the same domain-separated bytes as Ed25519; the signature is r || s, 64 bytes,
# and only the low-S form is accepted (the signer normalises). Introducing a P-256 key is a root-signed
# change, like any change to revocation_keys. A node whose code predates this refuses a manifest with a
# typed entry (fail closed): every node is upgraded before the root introduces one.
# Two entries are distinct by their key hex: a P-256 point and a bare 64-hex string equal to its X
# coordinate are two keys in two algorithms, each verified its own way, and neither stands in for the other.
REVOCATION_ALGS = ("ed25519", "ecdsa-p256")
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def revocation_entry(entry, label="a revocation key"):
    """(alg, key hex) of one revocation_keys entry, or Refused."""
    if isinstance(entry, str):
        hex_field(entry, 64, label)
        return "ed25519", entry
    exact(entry, ("alg", "key"), label)
    require(entry["alg"] in REVOCATION_ALGS[1:], "%s: alg must be one of %s" % (label, ", ".join(REVOCATION_ALGS[1:])))
    hex_field(entry["key"], 130, "%s: an ecdsa-p256 key (04 || X || Y)" % label)
    require(entry["key"].startswith("04"), "%s: an ecdsa-p256 key must be an uncompressed point" % label)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(entry["key"]))
    except ValueError:
        raise Refused("%s: not a point on P-256" % label) from None
    return entry["alg"], entry["key"]


def root_entries(root, label="the root key"):
    """The pinned root: one entry or a non-empty list of them, each a bare 64-hex Ed25519 key or a typed
    {"alg", "key"} entry (#156: the root on an offline Nitrokey). Returns [(alg, key hex), ...]."""
    entries = root if isinstance(root, list) else [root]
    require(entries and len(entries) <= 8, "the root is one key or a list of one to eight")
    out = [revocation_entry(entry, label) for entry in entries]
    require(len({k for _, k in out}) == len(out), "the root keys must be distinct")
    return out


SIGNING_KEY_ALGS, OWNER_KEY_ALGS, ANCHOR_POLICY_KEY_ALGS = ("ecdsa-p256",), ("ed25519", "ecdsa-p256"), ("ecdsa-p256",)


def typed_key(entry, label, algs):
    """(alg, key hex) of a TYPED entry ({"alg", "key"}) whose alg is one of `algs`. A v4 node's signing_key
    is ecdsa-p256 (a TPM has no Ed25519); an owner key is ed25519 (the approval YubiKeys' OpenPGP applet,
    #126) or ecdsa-p256. Never a bare string: the algorithm is always written beside the key."""
    require(isinstance(entry, dict), "%s must be a typed key {\"alg\", \"key\"}" % label)
    exact(entry, ("alg", "key"), label)
    require(entry["alg"] in algs, "%s: alg must be one of %s" % (label, ", ".join(algs)))
    if entry["alg"] != "ed25519":
        return revocation_entry(entry, label)
    hex_field(entry["key"], 64, "%s: an ed25519 key" % label)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["key"]))
    except ValueError:
        raise Refused("%s: not an Ed25519 public key" % label) from None
    return "ed25519", entry["key"]


def revocation_alg(manifest, key):
    """The algorithm the manifest's revocation_keys give for `key` (its hex), or None if it names none. A v4
    manifest has no revocation keys: nothing is signed by one under it."""
    for entry in manifest.get("revocation_keys", ()):
        alg, hexkey = revocation_entry(entry)
        if hexkey == key:
            return alg
    return None


def verify_revocation(alg, key, message, sig, what):
    """A revocation key's signature over `message`, the way its manifest entry's `alg` says."""
    hex_field(sig, 128, "%s signature" % what)
    raw = bytes.fromhex(sig)
    try:
        if alg == "ed25519":
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(raw, message)
            return
        require(alg == "ecdsa-p256", "unknown revocation key algorithm %r" % (alg,))
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        require(0 < r < P256_ORDER and 0 < s <= P256_ORDER // 2, "the %s signature is not a low-S P-256 signature" % what)
        public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(key))
        public.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise Refused("the %s signature does not verify" % what) from None


def identity_keys(node):
    """The identity fields a validated node entry carries: v1's four, ssh_host_pub from v2, and signing_key
    from v4."""
    return (V2_IDENTITY_KEYS if "ssh_host_pub" in node else IDENTITY_KEYS) + (("signing_key",) if "signing_key" in node else ())


def identity_value(node, k):
    """An identity as one comparable value: the field itself, or a typed key's hex (signing_key)."""
    return node[k]["key"] if k == "signing_key" else node[k]


def rename_party(rules, old_id, new_id):
    """A v4 signer rule (or list of rules) with `old_id` named `new_id` instead: what a replacement may do to
    them, and nothing else (replacement.py)."""
    if rules is None:
        return None
    swap = lambda rule: dict(rule, parties=[new_id if p == old_id else p for p in rule["parties"]])
    return [swap(r) for r in rules] if isinstance(rules, list) else swap(rules)


def _signer_rules(manifest, by_id, seen):
    """A v4 manifest's signer fields: the owner's keys, the owner's heartbeat bound, and the rules. The
    floors are the format's, so no root-signed manifest can lower a threshold into danger."""
    owners = manifest["owner_keys"]
    require(isinstance(owners, list) and 1 <= len(owners) <= MAX_OWNER_KEYS, "owner_keys must be a list of one to %d keys" % MAX_OWNER_KEYS)
    for i, entry in enumerate(owners):
        key = typed_key(entry, "owner_keys[%d]" % i, OWNER_KEY_ALGS)[1]
        require(key not in seen, "owner_keys[%d] is already used (%s)" % (i, seen.get(key)))
        seen[key] = "owner_keys[%d]" % i
    owner_life = manifest["owner_heartbeat_lifetime_s"]
    require(isinstance(owner_life, int) and not isinstance(owner_life, bool)
            and OWNER_HEARTBEAT_MIN_S <= owner_life <= manifest["heartbeat_max_lifetime_s"],
            "owner_heartbeat_lifetime_s must be an integer from %d to heartbeat_max_lifetime_s" % OWNER_HEARTBEAT_MIN_S)

    def rule(value, label, owner_alone):
        exact(value, ("threshold", "parties"), label)
        parties = value["parties"]
        require(isinstance(parties, list) and parties and all(isinstance(p, str) for p in parties), "%s.parties must be a non-empty list of names" % label)
        require(len(set(parties)) == len(parties), "%s.parties must be distinct" % label)
        for p in parties:
            require(p == OWNER or p in by_id, "%s names %r, which is neither a node of this manifest nor %s" % (label, p, OWNER))
        t = value["threshold"]
        require(isinstance(t, int) and not isinstance(t, bool), "%s.threshold must be an integer" % label)
        least = 1 if owner_alone and parties == [OWNER] else (NODE_RULE_FLOOR if owner_alone else HEARTBEAT_FLOOR)
        require(least <= t <= len(parties), "%s.threshold must be from %d to the number of its parties (%d)" % (label, least, len(parties)))

    for name in SINGLE_RULES:
        rule(manifest[name], name, owner_alone=False)
    rules = manifest["revocation_signers"]
    require(isinstance(rules, list) and 1 <= len(rules) <= MAX_RULES, "revocation_signers must be a list of one to %d rules" % MAX_RULES)
    for i, r in enumerate(rules):
        rule(r, "revocation_signers[%d]" % i, owner_alone=True)
    # K_A (#361): a P-256 key, as tpm2_loadexternal loads it, and no other key of this manifest (checked last, after the
    # nodes' identities and owner_keys: `seen` holds them all)
    key = typed_key(manifest["anchor_policy_key"], "anchor_policy_key", ANCHOR_POLICY_KEY_ALGS)[1]
    require(key not in seen, "anchor_policy_key is already used (%s)" % seen.get(key))
    record = manifest["card_record"]
    exact(record, ("sequence", "digest"), "card_record")
    seq = record["sequence"]
    require(type(seq) is int and 1 <= seq <= MAX_CARD_SEQUENCE, "card_record.sequence must be an integer from 1 to %d" % MAX_CARD_SEQUENCE)
    hex_field(record["digest"], 64, "card_record.digest")


def counting_parties(current, message, signatures, what):
    """The parties whose signatures over `message` count under the CURRENT v4 manifest. Every signature must
    name a party of that manifest with the key it gives that party (a node's signing_key, or one of
    owner_keys), and must verify the way that key's entry says (a quorum may mix algorithms: P-256 nodes,
    an Ed25519 owner). A party named twice is refused, never counted once. A node that is
    RETIRED, REVOKED_STOLEN or QUARANTINED does not count, though its signature must still verify.
    The same rule for manifests (here) and heartbeats (heartbeat.py)."""
    require(current is not None and current["schema"] == SCHEMA_V4,
            "a %s signed by a quorum needs a current %s manifest naming its signers" % (what, SCHEMA_V4))
    require(isinstance(signatures, list) and 1 <= len(signatures) <= MAX_SIGNATURES,
            "signatures must be a list of one to %d signatures" % MAX_SIGNATURES)
    nodes, owners = validate(current), {key: alg for alg, key in (typed_key(e, "owner_keys", OWNER_KEY_ALGS) for e in current["owner_keys"])}
    named, counting = set(), set()
    for i, sig in enumerate(signatures):
        exact(sig, ("party", "key", "sig"), "signatures[%d]" % i)
        party = sig["party"]
        require(isinstance(party, str) and party not in named, "signatures[%d]: party %r is named twice or is not a name" % (i, party))
        named.add(party)
        require(isinstance(sig["key"], str) and re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{130}", sig["key"]) is not None,
                "signatures[%d].key must be 64 or 130 lowercase hex" % i)
        if party == OWNER:
            require(sig["key"] in owners, "signatures[%d]: the key is not one of the current manifest's owner_keys" % i)
            alg = owners[sig["key"]]                         # from the manifest's entry, never from the signature
        else:
            require(party in nodes and "signing_key" in nodes[party], "signatures[%d]: %r is not a node of the current manifest with a signing_key" % (i, party))
            require(sig["key"] == nodes[party]["signing_key"]["key"], "signatures[%d]: the key is not %s's signing_key" % (i, party))
            alg = nodes[party]["signing_key"]["alg"]
        verify_revocation(alg, sig["key"], message, sig["sig"], "%s (signatures[%d], %s)" % (what, i, party))
        if party == OWNER or nodes[party]["state"] not in NOT_COUNTING:
            counting.add(party)
    return counting


def meets(rule, parties):
    """Whether the counting `parties` meet one signer rule ({"threshold", "parties"})."""
    return len(parties & set(rule["parties"])) >= rule["threshold"]


def validate(manifest):
    """Schema and uniqueness. Returns the manifest's nodes by ID."""
    require(isinstance(manifest, dict), "manifest must be an object")
    require(manifest.get("schema") in SCHEMAS, "schema must be %s" % " or ".join(SCHEMAS))
    fourth = manifest["schema"] == SCHEMA_V4
    second = manifest["schema"] in (SCHEMA_V2, SCHEMA_V3, SCHEMA_V4)        # v3 and v4 have v2's fields
    exact(manifest, V4_MANIFEST_KEYS if fourth else V2_MANIFEST_KEYS if second else MANIFEST_KEYS, "manifest")
    node_keys = V4_NODE_KEYS if fourth else V2_NODE_KEYS if second else NODE_KEYS
    # A tombstone keeps exactly the fields it had: one retired under an earlier schema may lack what later
    # schemas added (ssh_host_pub from v2, signing_key from v4), and nothing is invented for it.
    tombstone_shapes = (V4_NODE_KEYS, V2_NODE_KEYS, NODE_KEYS)[(V4_NODE_KEYS, V2_NODE_KEYS, NODE_KEYS).index(node_keys):]
    if second:
        life = manifest["heartbeat_max_lifetime_s"]
        require(isinstance(life, int) and HEARTBEAT_MIN_S <= life <= HEARTBEAT_HARD_MAX_S,
                "heartbeat_max_lifetime_s must be an integer from %d to %d" % (HEARTBEAT_MIN_S, HEARTBEAT_HARD_MAX_S))
    e = manifest["epoch"]
    require(isinstance(e, int) and not isinstance(e, bool) and e >= 1, "epoch must be an integer >= 1")
    if e == 1:
        require(manifest["prev_digest"] == "", "epoch 1 has no previous manifest (prev_digest \"\")")
    else:
        hex_field(manifest["prev_digest"], 64, "prev_digest")
    require(isinstance(manifest["policy_version"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", manifest["policy_version"]),
            "policy_version must be a short name")
    try:
        # the form first, in ASCII digits at full width: strptime alone takes "2026-1-3T1:2:3Z" and a year in
        # any script's digits, which the pre-root Go reader refuses (#66)
        if not (isinstance(manifest["issued_at"], str) and UTC_TIME.fullmatch(manifest["issued_at"])):
            raise ValueError
        datetime.datetime.strptime(manifest["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise Refused("issued_at must be UTC, YYYY-MM-DDTHH:MM:SSZ")
    if not fourth:
        keys = manifest["revocation_keys"]
        require(isinstance(keys, list), "revocation_keys must be a list")
        named = [revocation_entry(k, "revocation_keys[%d]" % i)[1] for i, k in enumerate(keys)]
        require(len(set(named)) == len(named), "revocation_keys must be distinct")
        require(manifest["schema"] == SCHEMA_V3 or all(isinstance(k, str) for k in keys),
                "a typed revocation key ({\"alg\": ...}) needs schema %s" % SCHEMA_V3)
    nodes = manifest["nodes"]
    require(isinstance(nodes, list) and nodes, "nodes must be a non-empty list")
    by_id, seen = {}, {}
    for i, node in enumerate(nodes):
        # the entries that may lack later fields: tombstones (the transition rules keep them as they were)
        shape = next((s for s in tombstone_shapes if isinstance(node, dict) and node.get("state") in TERMINAL and set(node) == set(s)), node_keys)
        exact(node, shape, "nodes[%d]" % i)
        require(isinstance(node["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node["node_id"]),
                "nodes[%d].node_id must be a short lowercase name" % i)
        require(not fourth or node["node_id"] != OWNER, "nodes[%d]: %r is the owner's party name under %s, never a node_id" % (i, OWNER, SCHEMA_V4))
        require(node["node_id"] not in by_id, "duplicate node_id %r" % node["node_id"])
        require(isinstance(node["state"], str) and node["state"] in CAPABILITIES, "nodes[%d].state %r is not a known state" % (i, node["state"]))
        hex_field(node["ek_name"], 68, "nodes[%d].ek_name" % i)
        hex_field(node["ak_name"], 68, "nodes[%d].ak_name" % i)
        hex_field(node["wg_boot_pub"], 64, "nodes[%d].wg_boot_pub" % i)
        hex_field(node["wg_service_pub"], 64, "nodes[%d].wg_service_pub" % i)
        if "ssh_host_pub" in node:
            hex_field(node["ssh_host_pub"], 64, "nodes[%d].ssh_host_pub" % i)
        if "signing_key" in node:
            typed_key(node["signing_key"], "nodes[%d].signing_key" % i, SIGNING_KEY_ALGS)
        require(isinstance(node["hsm_serials"], list) and all(isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9]{1,32}", s)
                                                             for s in node["hsm_serials"]), "nodes[%d].hsm_serials" % i)
        # No identity may belong to two nodes: a substituted TPM, key or token would otherwise pass as another.
        # Compared by value across roles: one WireGuard key cannot be a boot key and a service key, on
        # one node or two, one TPM name cannot be an EK and an AK, and an SSH host key is no other key.
        for k in identity_keys(node):
            value = identity_value(node, k)
            require(value not in seen, "%s of %s is already used (%s)" % (k, node["node_id"], seen.get(value)))
            seen[value] = "%s of %s" % (k, node["node_id"])
        for s in node["hsm_serials"]:
            require(("hsm", s) not in seen, "HSM %s is listed twice" % s)
            seen[("hsm", s)] = node["node_id"]
        by_id[node["node_id"]] = node
    if fourth:
        _signer_rules(manifest, by_id, seen)
    return by_id


def _apart_from_root(manifest, root_key):
    """A v4 manifest's party keys (owner_keys, every signing_key) are none of the pinned root's: one device is
    never both the payload root and a quorum party (D28). Only accept() knows the root, so it is checked here."""
    if manifest["schema"] != SCHEMA_V4:
        return
    roots = {key for _, key in root_entries(root_key)}
    keys = [("owner_keys[%d]" % i, e["key"]) for i, e in enumerate(manifest["owner_keys"])]
    keys += [("signing_key of %s" % n["node_id"], n["signing_key"]["key"]) for n in manifest["nodes"] if "signing_key" in n]
    keys += [("anchor_policy_key", manifest["anchor_policy_key"]["key"])]
    for label, key in keys:
        require(key not in roots, "%s is a pinned root key: the payload root is never a quorum party" % label)


def verify_envelope(envelope, root_key, current=None):
    """The manifest inside an envelope, if its signature is by the pinned root key or by a revocation key
    named in the CURRENT manifest (never one named by the candidate itself), or, under v4, by a quorum of the
    parties the CURRENT manifest names: one of its revocation_signers rules met (counting_parties). Returns
    (manifest, signer), the signer "root", "revocation" or "quorum"."""
    if isinstance(envelope, dict) and "signatures" in envelope:
        exact(envelope, ("manifest", "signatures"), "envelope")
        manifest = envelope["manifest"]
        validate(manifest)
        _apart_from_root(manifest, root_key)
        parties = counting_parties(current, DOMAIN + canonical(manifest), envelope["signatures"], "manifest")
        require(any(meets(rule, parties) for rule in current["revocation_signers"]),
                "the manifest's signatures meet no revocation_signers rule of the current manifest (counting: %s)" % (", ".join(sorted(parties)) or "none"))
        return manifest, "quorum"
    exact(envelope, ("manifest", "signature"), "envelope")
    sig = envelope["signature"]
    exact(sig, ("signer", "key", "sig"), "signature")
    require(sig["signer"] in ("root", "revocation"), "signer must be root or revocation")
    require(isinstance(sig["key"], str) and re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{130}", sig["key"]) is not None,
            "signature.key must be 64 or 130 lowercase hex")
    hex_field(sig["sig"], 128, "signature.sig")
    if sig["signer"] == "root":
        algs = [alg for alg, key in root_entries(root_key) if key == sig["key"]]
        require(algs, "the signature names a root key that is not the pinned root")
        alg = algs[0]                                    # from the pinned entry, never from the signature
    else:
        alg = revocation_alg(current, sig["key"]) if current is not None else None
        require(alg is not None, "the signing revocation key is not named by the current manifest")
    manifest = envelope["manifest"]
    validate(manifest)
    _apart_from_root(manifest, root_key)
    require(alg == "ed25519" or manifest["schema"] in (SCHEMA_V3, SCHEMA_V4), "a manifest signed by a typed (%s) key needs schema %s"
            % (alg, " or ".join((SCHEMA_V3, SCHEMA_V4))))
    try:
        verify_revocation(alg, sig["key"], DOMAIN + canonical(manifest), sig["sig"], "manifest")
    except Refused:
        raise Refused("the manifest signature does not verify") from None
    return manifest, sig["signer"]


def _restrictive(current, candidate, signer="revocation"):
    """A revocation-signed (v1-v3) or quorum-signed (v4) change: identities, policy, keys and signer rules
    unchanged; capabilities only shrink. (The schema too: accept() has already refused a schema change that
    the root did not sign.)"""
    who = "a revocation key" if signer == "revocation" else "a revocation quorum"
    names = {"policy_version": "the policy version", "revocation_keys": "the revocation keys"}
    for k in ROOT_FIELDS:
        require(candidate.get(k) == current.get(k), "%s cannot change %s" % (who, names.get(k, k)))
    old, new = validate(current), validate(candidate)
    require(set(old) == set(new), "%s cannot add or remove nodes" % who)
    for nid, node in new.items():
        require(set(node) == set(old[nid]), "%s cannot add or drop fields of %s" % (who, nid))
        for k in identity_keys(node) + ("hsm_serials",):
            require(node[k] == old[nid][k], "%s cannot change %s of %s" % (who, k, nid))
        require(CAPABILITIES[node["state"]] <= CAPABILITIES[old[nid]["state"]],
                "%s: %s -> %s widens capabilities; only the root can do that" % (nid, old[nid]["state"], node["state"]))


TERMINAL = ("RETIRED", "REVOKED_STOLEN")


def _tombstones(current, candidate):
    """No node ever leaves the manifest, and retirement is terminal, for EVERY signer, the root included.
    A node can only be retired, never removed. A node that is RETIRED or REVOKED_STOLEN
    stays in every later manifest as a tombstone: the same node_id, identities and HSM serials (as they
    were BEFORE it was retired: the retiring manifest cannot change them either), and a state that only
    moves from RETIRED to REVOKED_STOLEN. With the tombstone always present, validate()'s
    uniqueness rule refuses any reuse of its EK, AK, WireGuard keys, SSH host key, HSM serials or node ID,
    for ever. An entry that is, or becomes, a tombstone has exactly the FIELDS it had: a node retired
    under v1 is never given an ssh_host_pub, and one retired under v2 never loses it."""
    old, new = validate(current), validate(candidate)
    for nid, node in old.items():
        if node["state"] not in TERMINAL:
            # No node leaves the list except as a tombstone: a node removed outright would leave nothing
            # behind, and its identities could be enrolled again. A mistaken enrollment is retired.
            require(nid in new, "tombstone: %s cannot be removed; retire it instead" % nid)
            # The manifest that retires a node must record the hardware as it was: identities rewritten in
            # the same step would leave the real ones free and protect the substitutes for ever.
            if new[nid]["state"] in TERMINAL:
                require(set(new[nid]) == set(node), "tombstone: %s becomes %s and its fields cannot change in the same manifest "
                        "(ssh_host_pub is neither added nor dropped)" % (nid, new[nid]["state"]))
                for k in identity_keys(node) + ("hsm_serials",):
                    require(new[nid][k] == node[k], "tombstone: %s becomes %s and its %s cannot change in the same manifest"
                            % (nid, new[nid]["state"], k))
            continue
        require(nid in new, "tombstone: %s is %s and must stay in every later manifest (its identities are never reused)"
                % (nid, node["state"]))
        require(set(new[nid]) == set(node), "tombstone: %s is %s and its fields cannot change (ssh_host_pub is neither added "
                "nor dropped)" % (nid, node["state"]))
        for k in identity_keys(node) + ("hsm_serials",):
            require(new[nid][k] == node[k], "tombstone: %s is %s and its %s cannot change" % (nid, node["state"], k))
        require(new[nid]["state"] == node["state"] or (node["state"], new[nid]["state"]) == ("RETIRED", "REVOKED_STOLEN"),
                "tombstone: %s is %s, which is terminal for every signer (%s refused); hardware that may return "
                "belongs in MAINTENANCE or QUARANTINED" % (nid, node["state"], new[nid]["state"]))


def accept(current, envelope, root_key):
    """The next manifest, if `envelope` may follow `current` (None at enrollment, where only a
    root-signed epoch-1 manifest is accepted)."""
    candidate, signer = verify_envelope(envelope, root_key, current)
    return transition(current, candidate, signer)


def transition(current, candidate, signer):
    """accept()'s rules for an already-verified candidate and its signer ("root", "revocation" or "quorum").
    The manifest signer (manifest.py, #156) runs them BEFORE a signature exists, so nothing a node would
    refuse is ever signed; accept() runs them after verifying one. One set of rules for both."""
    require(signer in ("root", "revocation", "quorum"), "signer must be root, revocation or quorum")
    validate(candidate)
    if current is None:
        require(signer == "root" and candidate["epoch"] == 1, "the first manifest must be the root-signed epoch 1")
        return candidate
    if candidate["epoch"] == current["epoch"]:
        if digest(candidate) == digest(current):
            return current                 # the same manifest delivered again: nothing changes
        raise Refused("CONFLICT: a different manifest at epoch %d: record an incident" % candidate["epoch"])
    require(candidate["epoch"] == current["epoch"] + 1,
            "epoch %d does not follow %d (fetch the missing manifests and accept them in order)" % (candidate["epoch"], current["epoch"]))
    require(candidate["prev_digest"] == digest(current), "prev_digest does not chain to the current manifest")
    if candidate["schema"] != current["schema"]:
        require(SCHEMAS.index(candidate["schema"]) > SCHEMAS.index(current["schema"]), "schema %s cannot follow %s: the schema "
                "only moves forward" % (candidate["schema"], current["schema"]))
        require(signer == "root", "only the root can change the schema (%s to %s)" % (current["schema"], candidate["schema"]))
    _tombstones(current, candidate)        # every signer: the one rule the root cannot override
    if current["schema"] == candidate["schema"] == SCHEMA_V4:
        # K_A is named by every node's TPM objects (#361): no signer changes it; a new K_A is a new genesis. (v3 -> v4,
        # root-signed, is where it is first set.)
        require(candidate["anchor_policy_key"] == current["anchor_policy_key"], "anchor_policy_key is set at genesis "
                "and never changes, for any signer: every node's TPM objects are defined under it (a new one is a new genesis)")
    if signer != "root":
        _restrictive(current, candidate, signer)
    elif current["schema"] == candidate["schema"] == SCHEMA_V4:
        _card_record_rules(current, candidate)
    return candidate


def _card_record_rules(current, candidate):
    """The root's own v4 rules for card_record (#405): a new card record has a higher sequence, and owner_keys, which
    the card ceremony's record names, change only with a new one. (A quorum changes neither: ROOT_FIELDS.)"""
    old, new = current["card_record"], candidate["card_record"]
    if new != old:
        require(new["sequence"] > old["sequence"], "card_record changes only to a later card ceremony's record (sequence %d "
                "after %d)" % (new["sequence"], old["sequence"]))
    elif candidate["owner_keys"] != current["owner_keys"]:
        raise Refused("owner_keys change only with a new card_record: the card ceremony's record names them")


def accept_chain(current, envelopes, root_key):
    for env in envelopes:
        current = accept(current, env, root_key)
    return current


def may(manifest, node_id, action):
    """Whether node_id may `serve`, `request` (be unlocked) or `authorize` (give a contribution)."""
    node = validate(manifest).get(node_id)
    return bool(node) and action in CAPABILITIES[node["state"]]


class HighWater:
    """The highest accepted epoch, held in the TPM outside restorable disk state. `check(disk_epoch)`
    refuses a disk manifest older than the high-water (a restored disk, or a crash between `advance`
    and the disk write); recovery is to fetch the chain from a peer up to at least that value.

    A TPM_NT_COUNTER's first increment lands at the highest value any counter on that TPM ever held,
    so the epoch is `counter - base`: `define()` defines the counter, increments it once, and stores
    where it landed in a second, write-once index (writedefine, then write-locked). After that every
    increment is exactly +1. Deleting the counter fails closed (`value` refuses) and a redefined one
    starts above the old value. Deleting and redefining the base index needs owner authorization on
    the running host, which this anchor does not defend against (it defends against a restored disk).

    THE RECORD. The counter says how far this node got, not by which chain: two validly signed chains can
    reach one epoch if a key signed twice for it. So the TPM also holds
    `epoch (u64, big-endian) || SHA-256(canonical manifest at that epoch)`. `define()` creates it at epoch
    0 with an all-zero digest. Only Store writes it, through `anchor()`, and always AFTER the counter: for
    each epoch the counter is incremented, then the record written. The record's epoch is therefore the
    counter's, or one below it after a crash between the two; `anchor()` and `verify()` accept exactly
    those two, compare the digest with the chain they are given, and refuse anything else (another epoch,
    another digest, no record at all). In the crash window the manifest AT the counter's epoch is not yet
    recorded: `pinned()` is False until `anchor()` has repaired it.

    TWO SLOTS, so that a power cut cannot strand the node. The record is kept in two ordinary indices of
    48 bytes, each `epoch || digest || tag` (the tag is 8 bytes of a SHA-256 over the other 40). A write
    goes to the slot that is not valid or, when both are, to the older one: never to the newest valid
    slot. A write cut half-way leaves that slot with a tag that does not match; it is ignored, and the
    other slot still holds the record for the epoch before, which is the crash window above. THE record
    is the valid slot with the higher epoch. Only when NEITHER slot is valid, or an index is gone, is
    there nothing to go by: that fails closed, and the way back is `Store.reanchor()`
    (reanchor.py; MEMBERSHIP-RECOVERY.md), never a silent return to trusting the epoch alone.
    THE LIMIT, STATED PLAINLY. Writes to all four indices need the TPM's OWNER authorization. That is a
    protection only if the owner hierarchy has an authorization value: with the empty one a TPM has from the
    factory, anyone who can open the TPM device (root, the tss group) has owner authorization, and can rewrite
    the counter, the base and the record. Today this code itself uses the owner hierarchy with no password,
    so it needs the empty value. The anchor therefore defends against a restored or substituted DISK, and
    against nothing that can talk to the TPM. That is the decided trust boundary (#190): owner authorization
    stays empty, and who may open /dev/tpmrm0 (root, a tss group holding only these units) is the gate. See
    MEMBERSHIP-RECOVERY.md.

    THE FORMAT ON THE TPM, for any other reader (the initrd reads it too). For counter index C (0x1500016
    for membership):
      * C: TPM_NT_COUNTER, 8 bytes, attributes ownerread|ownerwrite|authread.
      * C + 1, the base: ordinary, 8 bytes, ownerread|ownerwrite|authread|writedefine; written
        once and write-locked. The epoch is (counter - base), both read as unsigned 64-bit big-endian; a
        counter below its base is refused.
      * C + 4 and C + 5, the record slots: ordinary, EXACTLY 48 bytes, ownerread|ownerwrite|authread.
      * EXACTLY THESE ATTRIBUTES, apart from "written" and the base's write lock: counter 0x60012, base
        0x62002 (and write-locked), slots 0x60002 (and not write-locked), or the policy-written layout below.
        A reader refuses any mask other than these two layouts: that covers authwrite, ppwrite and writeall
        (others could write the index), policywrite without this node's approved-image policy, a missing
        ownerread (the owner could not read it), and locks that clear at startup.
      * OR THE POLICY-WRITTEN LAYOUT (#242), index by index: the counter 0x6001A and a slot 0x6000A (the same
        plus policywrite), with authPolicy = PolicyAuthorize(system-phase PCR key) = the node's configured
        approved-image policy (HighWater(policy=...)). Such an index with any other authPolicy, or on a node
        with no policy configured, is Unusable ("the anchor's write policy is not this node's approved-image
        policy"), which a re-anchor repairs. The base is never policy-written. A signed PolicyPCR cannot also
        restrict the command code, so a session that satisfies the policy may write or increment the index;
        it can neither delete it (no policydelete) nor lock it (no writedefine or write_stclear on these).
        STATED LIMIT (#242, d9): the COUNTER is policy-writable too, not owner-only. Root on an approved, booted
        image can increment it past the chain, or write a slot: a refusal the node inflicts on itself (the
        chain no longer reaches the high-water), which recount and re-anchoring repair. It is never a rollback:
        nothing lowers the counter, and a slot written out of step with it is refused as inconsistent.
        WHO WRITES HOW (B2b): a DEFINER (enrolment, a re-anchor, a recount, a first heartbeat) chooses the layout
        of new indices explicitly (HighWater(define_policy=...): the node's policy when its signed measurements
        name a system-phase key for it, else owner-written), and its own writes at definition are the owner's,
        so a re-anchor from a recovery boot (no approved image) works. Every later write of a policy-written
        index (an advance, the record of an advance, a crash's repair) goes through a policy session for this
        boot's approved image (signkey.policy_session), never the owner.
        Reads are open (authread):
        nothing here is secret, and every reader reads with the index's own empty authorization (nvread
        <index> -C <index>), never the owner's, so a reader works whatever the owner authorization is (#242).
        A slot holds  epoch (8 bytes, unsigned big-endian) || digest (32 bytes) || tag (8 bytes),  where
        digest is the SHA-256 of the canonical JSON of the manifest at that epoch (membership.digest; 32 zero
        bytes at epoch 0) and  tag = SHA-256(b"regalia-membership-record/v1\x00" || epoch || digest)[0:8].
        A slot is a record when its index is written and its tag matches; otherwise (never written, or a
        cut write) it holds no record. C + 2 and C + 3 are another counter's (the heartbeat's).
      * THE record is the valid slot with the highest epoch. Two valid slots at that epoch must name the
        same digest. No valid slot is NO RECORD. A slot index that is missing, not ordinary, or not 48
        bytes is not a record slot at all.
      * The anchor is usable when the counter and base read and the record's epoch is the counter's
        epoch or the one below it. A chain is the anchored one when its manifest digest at the record's
        epoch is the record's digest. (HighWater.verify(lock=False) is that check, for readers that cannot
        take the writer's lock.)
    The vectors of tests/test_baremetal_membership.py (RecordWrites.test_a_slot_is_a_record_only_if_its_tag_matches,
    and slot_bytes) pin this layout.
    """

    MAX_JUMP = 1000
    RECORD = True                        # heartbeat.Counter is this counter without the record
    RECORD_BYTES, ZERO = 48, "00" * 32
    RECORD_TAG = b"regalia-membership-record/v1\0"
    NT_MASK, NT_COUNTER, NT_ORDINARY = 0xF0, 0x10, 0x00
    WRITTEN, WRITELOCKED = 0x20000000, 0x800
    OWNERWRITE, AUTHWRITE, POLICYWRITE, OWNERREAD, AUTHREAD = 0x2, 0x4, 0x8, 0x20000, 0x40000
    # The attributes this software defines, exactly, apart from the two that change with use (written, and the
    # base's write lock). Anything else (authwrite, policywrite, ppwrite, writeall, no ownerread, read or write
    # locks that clear at startup, ...) is not this anchor's index: comparing the whole mask refuses them all.
    STATE = WRITTEN | WRITELOCKED
    ATTRIBUTES = {"counter": 0x00060012, "base": 0x00062002, "slot": 0x00060002}
    # The policy-written layout (#242): the counter and the slots are ALSO written through their authPolicy,
    # PolicyAuthorize(system-phase PCR key), so an approved image's booted system writes them with no owner
    # authorization. Only with the node's own approved-image policy: an index of this layout whose authPolicy
    # is anything else is Unusable. The base is written once, at definition, and has no policy in either layout.
    POLICY_ATTRIBUTES = {"counter": 0x0006001A, "slot": 0x0006000A}

    def __init__(self, index, tcti=None, run=subprocess.run, base_index=None, lock_path=None, record_indices=None, policy=None,
                 image_key=None, signatures=None, define_policy=None, owner_auth=None):
        """`policy`: the node's approved-image write policy, PolicyAuthorize(system-phase PCR key), as 64 hex
        (the digest a policy-written index must hold as its authPolicy), or a function that returns it (the
        node's: measurements.approved_image_policy over its signed chain and the running image's key), called
        only when a policy-written index is met and at most once. None on a node that has none. A function that
        cannot establish the policy refuses (Refused): a TPM-side question is never answered by a guess.
        `image_key`: a function that returns the running image's system-phase PCR public key (PEM), the key whose
        signature authorizes a run-time write of a policy-written index (signkey.policy_session); `signatures` the
        boot's parsed tpm2-pcr-signature.json, for a test (default: the boot's own). Both only for policy writes.
        `define_policy`: what a DEFINER lays down (enrolment, a re-anchor, a recount): the approved-image policy (64 hex,
        or a function that returns it) under which new counter and slot indices are defined in the policy-written
        layout; None defines them owner-written. Never implied by `policy`, which is what a reader expects: the
        node's services read and write the anchor and never define it. A definer's policy is also what it reads by,
        unless `policy` is given.
        `owner_auth`: the TPM's owner authorization (ownerauth.Auth, from the node's envelope, or a function that returns
        one), for the OWNER-authorized calls only: a definition, a redefinition, an owner-written index's write, an
        nvundefine (#242 step C). None: the owner authorization is empty (a lab TPM). Resolved once, at its first use,
        and passed through ownerauth's one channel (a pipe fd), never on the command line."""
        self.index, self.run, self.env = index, run, ({"TPM2TOOLS_TCTI": tcti} if tcti else None)
        if policy is not None and not callable(policy):
            hex_field(policy, 64, "the approved-image write policy")
        if define_policy is not None and not callable(define_policy):
            hex_field(define_policy, 64, "the approved-image write policy to define under")
        if policy is None and define_policy is not None:
            # a definer reads by what it lays down: through the SAME single resolution, never asked twice
            policy = (lambda: self._defining_policy()) if callable(define_policy) else define_policy
        self._policy_source, self._policy = policy, (policy if not callable(policy) else None)
        self._image_key, self._signatures, self._define_policy = image_key, signatures, define_policy
        self._policy_asked = False
        self._owner_auth = owner_auth
        self.base_index = base_index or "0x%x" % (int(index, 16) + 1)
        # index + 2 and + 3 are left to the heartbeat's pair (0x1500018/0x1500019 beside 0x1500016)
        self.record_indices = tuple(record_indices or ("0x%x" % (int(index, 16) + 4), "0x%x" % (int(index, 16) + 5))) if self.RECORD else ()
        require(len(self.record_indices) in (0, 2) and len(set(self.record_indices)) == len(self.record_indices), "the record takes two different NV indices")
        # Two processes advancing at once could both increment and push the counter past any manifest.
        self.lock_path = lock_path or "/run/lock/regalia-highwater-%s.lock" % self.index

    def _tpm(self, *args, **kw):
        import os
        env = dict(os.environ, **self.env) if self.env else None
        return self.run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=env, **kw)

    def _owner(self, tool, index, *args, input=None):
        """An OWNER-authorized call: `-C o` and the owner authorization through ownerauth's one channel (#242 C)."""
        from deploy.baremetal import ownerauth         # here: ownerauth imports this module
        self._owner_auth = ownerauth.resolve(self._owner_auth)     # a function is called once: its answer replaces it
        with ownerauth.owner_call(self._owner_auth) as (argv, kw):
            done = self._tpm(tool, index, *argv, *args, input=input, **kw)
        if done.returncode != 0 and ownerauth.AUTH_FAILURE.search(ownerauth._tail(done.stderr)):
            require(self._owner_auth is not None, "the TPM's owner authorization is set and none was given: give this node's "
                    "(gpg --decrypt ownerauth-<node>.yk.gpg | ... --ownerauth ownerauth.record.json, #242)")
            raise Refused("the TPM refused the owner authorization given: it is not this TPM's (another node's envelope?)")
        return done

    def _defined(self):
        """The NV indices the TPM says it holds. Refused when the TPM does not answer: then nothing is known
        about the anchor, and that is neither "usable" nor "unusable"."""
        r = self._tpm("getcap", "handles-nv-index")
        require(r.returncode == 0, "the TPM does not answer (tpm2_getcap handles-nv-index failed): the high-water anchor is "
                "unavailable (fail closed)")
        return {int(found, 16) for found in re.findall(rb"0x[0-9A-Fa-f]+", r.stdout)}

    def _public(self, index):
        """(TPMA_NV mask, size) of an index. Unusable if the TPM says the index is not defined; Refused if it
        could not be read for any other reason (no TPM, a tool that failed)."""
        r = self._tpm("nvreadpublic", index)
        if r.returncode != 0:
            missing = int(index, 16) not in self._defined()
            raise (Unusable if missing else Refused)("cannot read NV index %s: the high-water anchor is unavailable (fail closed): %s"
                                                     % (index, "the index is not defined" if missing else "the TPM lists it and did not give it"))
        found = re.search(rb"attributes:\s*\n\s*friendly:[^\n]*\n\s*value:\s*0x([0-9A-Fa-f]+)", r.stdout)
        size = re.search(rb"(?m)^\s*size:\s*([0-9]+)\s*$", r.stdout)
        require(found is not None and size is not None, "unparseable nvreadpublic output for %s" % index)
        return int(found.group(1), 16), int(size.group(1))

    def _attributes(self, index):
        return self._public(index)[0]

    @property
    def policy(self):
        """This node's approved-image write policy (64 hex), or None: resolved from a function at most once."""
        if self._policy is None and callable(self._policy_source) and not self._policy_asked:
            policy = self._policy_source()          # None: this node has none (its approved images are not signed)
            if policy is not None:
                hex_field(policy, 64, "the approved-image write policy")
            self._policy, self._policy_asked = policy, True
        return self._policy

    # #242 B2b: the words an index of each kind is defined with, in each layout (the base has no policy in either)
    OWNER_WORDS = {"counter": "nt=counter|ownerread|ownerwrite|authread", "slot": "ownerread|ownerwrite|authread",
                   "base": "ownerread|ownerwrite|authread|writedefine"}
    POLICY_WORDS = {"counter": "nt=counter|policywrite|ownerwrite|authread|ownerread", "slot": "policywrite|ownerwrite|authread|ownerread"}

    def _nvdefine(self, index, size, kind):
        """Define one index of this anchor: the counter and the record slots in the policy-written layout when the
        definer gave a policy (define_policy, #242), with that policy as their authPolicy; otherwise, and the base
        always, owner-written. They keep ownerwrite either way, so a re-anchor from a recovery boot (no approved
        image, no policy session) still writes them with the owner's authorization."""
        policy = self._defining_policy() if kind in self.POLICY_WORDS else None
        if policy is not None:                  # None from a function: no policy for this node, owner-written
            hex_field(policy, 64, "the approved-image write policy to define under")
            with tempfile.TemporaryDirectory(prefix="regalia-highwater-") as d:
                path = os.path.join(d, "policy")
                with open(path, "wb") as f:
                    f.write(bytes.fromhex(policy))
                return self._owner("nvdefine", index, "-s", str(size), "-a", self.POLICY_WORDS[kind], "-L", path)
        return self._owner("nvdefine", index, "-s", str(size), "-a", self.OWNER_WORDS[kind])

    def _defining_policy(self):
        """The definer's policy (define_policy), resolved once: every index of one definition is laid down alike."""
        if callable(self._define_policy):
            self._define_policy = self._define_policy()      # None: owner-written
        return self._define_policy

    def _write(self, tool, index, *args, input=None, owner=False):
        """A run-time write (nvincrement, nvwrite) of an index of this anchor, as its layout says: with the owner's
        authorization when it is owner-written or `owner` is asked (a definition, a re-anchor), else through a policy
        session for this boot's approved image (signkey.policy_session: PolicyPCR of PCR 11, PolicyAuthorize with the
        system-phase key's signature), the key first required to be the one this node's policy names."""
        if owner or not self._attributes(index) & self.POLICYWRITE:
            return self._owner(tool, index, *args, input=input)
        from deploy.baremetal import signkey         # here: signkey imports this module
        require(callable(self._image_key), "NV index %s is written by policy and this anchor has no image key to open a policy "
                "session with" % index)
        pem = self._image_key()
        require(signkey.policy(pem).hex() == self.policy, "the running image's PCR key is not the one this node's write policy names: "
                "NV index %s is not written" % index)
        tcti = (self.env or {}).get("TPM2TOOLS_TCTI")
        with signkey.policy_session(pem, tcti, self.run, self._signatures) as session:
            return self._tpm(tool, index, "-C", index, "-P", "session:" + session, *args, input=input)

    def _auth_policy(self, index):
        """An index's authPolicy as tpm2_nvreadpublic reports it (64 lowercase hex), or "" when it has none."""
        r = self._tpm("nvreadpublic", index)
        require(r.returncode == 0, "cannot read NV index %s: the high-water anchor is unavailable (fail closed)" % index)
        found = re.search(rb"(?m)^\s*authorization policy:\s*([0-9A-Fa-f]*)\s*$", r.stdout)
        return found.group(1).decode().lower() if found else ""

    def _read8(self, index):
        r = self._tpm("nvread", index, "-C", index, "-s", "8")
        require(r.returncode == 0 and len(r.stdout) == 8, "cannot read 8 bytes from NV index %s" % index)
        return int.from_bytes(r.stdout, "big")

    def define(self):
        with _exclusive(self.lock_path):
            return self._define(0, self.ZERO)

    def _indices(self):
        return (self.index, self.base_index) + self.record_indices

    def indices(self):
        """Every NV index this anchor occupies, as integers: for a check that two anchors do not overlap."""
        return {int(i, 16) for i in self._indices()}

    def _define(self, epoch, manifest_digest):
        """Defines the whole anchor AT `epoch`, recording `manifest_digest` (none of its indices may exist)."""
        for index in self._indices():
            require(self._tpm("nvreadpublic", index).returncode != 0, "NV index %s already exists" % index)
        base = self._define_counter(epoch)
        for index in self.record_indices:
            r = self._nvdefine(index, self.RECORD_BYTES, "slot")
            require(r.returncode == 0, "cannot define the record index %s" % index)
        for _ in self.record_indices:            # each write takes the slot that is not valid, else the older one
            self._write_record(epoch, manifest_digest, owner=True)
        return base

    def _define_counter(self, epoch):
        """The counter and its base, the counter reading `epoch` from the moment the base exists: the base is
        written as (where the counter landed) - epoch, the counter raised first on a TPM where it lands below."""
        r = self._nvdefine(self.index, 8, "counter")
        require(r.returncode == 0, "cannot define the NV counter %s" % self.index)
        require(self._owner("nvincrement", self.index).returncode == 0, "cannot increment the NV counter")
        landed = self._read8(self.index)
        while landed < epoch:                    # a TPM that never held a counter this high: the base cannot be negative
            require(self._owner("nvincrement", self.index).returncode == 0, "cannot increment the NV counter")
            landed = self._read8(self.index)
        base = landed - epoch
        r = self._nvdefine(self.base_index, 8, "base")
        require(r.returncode == 0, "cannot define the base index %s" % self.base_index)
        r = self._owner("nvwrite", self.base_index, "-i", "-", input=base.to_bytes(8, "big"))
        require(r.returncode == 0, "cannot write the base index")
        require(self._owner("nvwritelock", self.base_index).returncode == 0, "cannot write-lock the base index")
        return base

    def redefine(self, epoch, manifest_digest):
        """Define this anchor anew AT `epoch`, recording `manifest_digest`: the TPM half of a re-anchor. It
        needs owner authorization and replaces the counter, so nothing calls it but Store.reanchor(), after
        the chain was verified against everything the TPM still holds and written to disk.

        THE NEW RECORD GOES IN FIRST: before the counter, and before any slot whose attributes are wrong (and
        which is replaced) is deleted. Store.reanchor has already checked the chain against everything the TPM
        holds (remains(), whatever the attributes), so the new record's epoch is at least every epoch held,
        and writing it over ANY slot lowers nothing. In order:
          1. into a slot this software defined (the one with no valid record, else the older), if there is one;
          2. each other slot that is missing or has the wrong attributes is deleted, defined, and written at once;
          3. the counter and its base are deleted and defined again at `epoch`;
          4. any slot not yet holding the new record is written.
        In step 2 a MISSING slot is defined and written first (nothing to lose), so the new record is in the TPM
        before any defined slot is deleted; among wrong slots, the one holding nothing, else the lower record,
        goes first. Interrupted anywhere, the node holds what it held, or the new record beside a counter not in
        step with it (unusable, a floor at `epoch`), or the finished anchor. One case is weaker, stated: when
        BOTH slots are defined with wrong attributes, the first deleted (the lower) is gone before anything new
        is in the TPM; a cut there loses that lower record, while the higher one, and the counter, remain."""
        hex_field(manifest_digest, 64, "a manifest digest")
        with _exclusive(self.lock_path):
            data = self.slot_bytes(epoch, manifest_digest)
            defined = self._defined()
            good = [index for index in self.record_indices if int(index, 16) in defined and self._is_slot(index)]
            written = set()
            if good:
                held = {index: self._slot(index) for index in good}
                first = min(good, key=lambda index: (held[index] is not None, held[index] or (0, "")))
                self._put(first, data, epoch, manifest_digest)
                written.add(first)
            # a MISSING slot first (nothing to lose), then wrong ones holding nothing, then the lower record first
            rest = [index for index in self.record_indices if index not in written and index not in good]
            rest.sort(key=lambda index: (int(index, 16) in defined, self._held(index) if int(index, 16) in defined else None or (-1, "")))
            for index in rest:
                if int(index, 16) in defined:
                    require(self._owner("nvundefine", index).returncode == 0, "cannot delete NV index %s" % index)
                r = self._nvdefine(index, self.RECORD_BYTES, "slot")
                require(r.returncode == 0, "cannot define the record index %s" % index)
                self._put(index, data, epoch, manifest_digest)
                written.add(index)
            for index in (self.index, self.base_index):
                if int(index, 16) in defined:
                    require(self._owner("nvundefine", index).returncode == 0, "cannot delete NV index %s" % index)
            base = self._define_counter(epoch)
            for index in self.record_indices:
                if index not in written:
                    self._put(index, data, epoch, manifest_digest)
            return base

    def _held(self, index):
        """The valid record a defined slot holds whatever its attributes, (-1, "") for none: what remains() reads."""
        a, size = self._public(index)
        if a & self.NT_MASK != self.NT_ORDINARY or size != self.RECORD_BYTES or not a & self.WRITTEN:
            return (-1, "")
        data = self._read_any(index, self.RECORD_BYTES, a)
        held_epoch, held = int.from_bytes(data[:8], "big"), data[8:40].hex()
        return (held_epoch, held) if data == self.slot_bytes(held_epoch, held) else (-1, "")

    def _put(self, index, data, epoch, manifest_digest):
        r = self._owner("nvwrite", index, "-i", "-", input=data)
        require(r.returncode == 0, "cannot write the record index %s" % index)
        require(self._slot(index) == (epoch, manifest_digest), "the record index %s did not take the write" % index)

    def _is_slot(self, index):
        """Whether `index` is a record slot as this software defines one, which redefine() keeps and writes into:
        ordinary, RECORD_BYTES long, of either layout (_as_defined), not write-locked. Anything else holds no
        record this anchor can use, and is replaced rather than left to make every attempt fail."""
        attributes, size = self._public(index)
        if size != self.RECORD_BYTES or attributes & self.NT_MASK != self.NT_ORDINARY:
            return False
        try:
            self._as_defined(index, attributes, "slot")
        except Unusable:
            return False
        return True

    def _as_defined(self, index, attributes, kind):
        """The index has exactly the attributes this software gives an index of that kind, in one of its two
        layouts: written with the owner's authorization only, or (#242, counter and slots) also through its
        authPolicy, which must then be this node's approved-image policy. Either way readable by the owner and
        by its own empty authorization, no authwrite or ppwrite, no locks that come and go."""
        want, mask = self.ATTRIBUTES[kind], attributes & ~self.STATE
        if mask == self.POLICY_ATTRIBUTES.get(kind):
            held, policy = self._auth_policy(index), self.policy
            require_anchor(policy is not None and held == policy,
                           "the anchor's write policy is not this node's approved-image policy: NV index %s is written by policy %s, %s"
                           % (index, held or "(none)", "and this node has none configured" if policy is None else "not " + policy))
        else:
            require_anchor(mask == want, "NV index %s does not have this anchor's attributes (0x%x, not 0x%x): it can be written or read "
                           "otherwise than this software defines" % (index, mask, want))
        if kind == "base":
            require_anchor(attributes & self.WRITELOCKED, "base index %s is not write-locked" % index)
        else:
            require_anchor(not attributes & self.WRITELOCKED, "NV index %s is write-locked: no record can be written to it" % index)

    def _base(self):
        """Checks both indices' attributes and returns the base (one call per value/advance/check)."""
        a, a_size = self._public(self.index)
        require_anchor(a & self.NT_MASK == self.NT_COUNTER and a & self.WRITTEN, "NV index %s is not a written counter" % self.index)
        self._as_defined(self.index, a, "counter")
        require_anchor(a_size == 8, "NV index %s is %d bytes, not 8" % (self.index, a_size))
        b, b_size = self._public(self.base_index)
        require_anchor(b & self.NT_MASK == self.NT_ORDINARY and b & self.WRITTEN and b & self.WRITELOCKED,
                 "base index %s is not written and write-locked" % self.base_index)
        self._as_defined(self.base_index, b, "base")
        # a base of another size is not this anchor's (Unusable, which a re-anchor repairs), not a TPM that failed
        require_anchor(b_size == 8, "NV index %s is %d bytes, not 8" % (self.base_index, b_size))
        return self._read8(self.base_index)

    def _epoch(self, base):
        counter = self._read8(self.index)
        require_anchor(counter >= base, "the NV counter %d is below its base %d" % (counter, base))
        return counter - base

    def value(self):
        return self._epoch(self._base())

    def advance(self, epoch):
        with _exclusive(self.lock_path):
            return self._advance(epoch)

    def _advance(self, epoch, digest_of=None):
        base = self._base()
        now = self._epoch(base)
        require(epoch >= now, "refusing to accept epoch %d below the TPM high-water %d" % (epoch, now))
        require(epoch - now <= self.MAX_JUMP, "epoch jump %d exceeds the bound %d: anomaly" % (epoch - now, self.MAX_JUMP))
        while now < epoch:
            r = self._write("nvincrement", self.index)
            require(r.returncode == 0, "cannot increment the NV counter")
            nxt = self._epoch(base)
            require(nxt == now + 1, "the NV counter did not advance by one (%d -> %d)" % (now, nxt))
            now = nxt
            if digest_of:
                self._write_record(now, digest_of(now))
        return now

    @classmethod
    def slot_bytes(cls, epoch, manifest_digest):
        """What a record slot holds: epoch || digest || tag."""
        hex_field(manifest_digest, 64, "a manifest digest")
        body = epoch.to_bytes(8, "big") + bytes.fromhex(manifest_digest)
        return body + hashlib.sha256(cls.RECORD_TAG + body).digest()[:8]

    def _slot(self, index):
        """(epoch, digest) held by one record slot, or None when what it holds is not a record (never
        written, or a write that was cut: the tag does not match). An index that is not defined, is not an
        ordinary index or is not exactly RECORD_BYTES long is Unusable: that is not what a power cut leaves.
        One that is as it should be and still cannot be read is Refused: the TPM, not the anchor."""
        a, size = self._public(index)
        require_anchor(a & self.NT_MASK == self.NT_ORDINARY, "record index %s is not an ordinary index" % index)
        require_anchor(size == self.RECORD_BYTES, "record index %s is %d bytes, not %d" % (index, size, self.RECORD_BYTES))
        self._as_defined(index, a, "slot")
        if not a & self.WRITTEN:
            return None
        r = self._tpm("nvread", index, "-C", index, "-s", str(self.RECORD_BYTES))
        require(r.returncode == 0 and len(r.stdout) == self.RECORD_BYTES, "cannot read %d bytes from the record index %s: the anchor "
                "is unavailable (fail closed)" % (self.RECORD_BYTES, index))
        epoch, held = int.from_bytes(r.stdout[:8], "big"), r.stdout[8:40].hex()
        return (epoch, held) if r.stdout == self.slot_bytes(epoch, held) else None

    def _slots(self):
        require(self.record_indices, "this counter keeps no record")
        return [self._slot(index) for index in self.record_indices]

    def _record(self):
        valid = [slot for slot in self._slots() if slot is not None]
        require_anchor(valid, "NO RECORD: neither record slot (%s) holds a valid record: the anchor cannot tell which chain this node "
                 "accepted (fail closed); re-anchor it (MEMBERSHIP-RECOVERY.md)" % ", ".join(self.record_indices))
        newest = max(valid)
        require_anchor(all(slot == newest for slot in valid if slot[0] == newest[0]), "the two record slots name different manifests at "
                 "epoch %d: the anchor is inconsistent (fail closed)" % newest[0])
        return newest

    def _write_record(self, epoch, manifest_digest, owner=False):
        data = self.slot_bytes(epoch, manifest_digest)
        slots = self._slots()
        # the slot that holds no record, else the older one (the first when they are equal): the newest
        # valid record is never the one being overwritten, so a cut write cannot lose it
        target = min(range(len(slots)), key=lambda i: (slots[i] is not None, slots[i] or (0, "")))
        index = self.record_indices[target]
        r = self._write("nvwrite", index, "-i", "-", input=data, owner=owner)
        require(r.returncode == 0, "cannot write the record index %s" % index)
        require(self._slot(index) == (epoch, manifest_digest), "the record index %s did not take the write" % index)

    def _in_step(self, hw):
        """The record, which must be for the counter's epoch or the one below."""
        epoch, held = self._record()
        require_anchor(epoch in (hw, hw - 1), "the TPM record is for epoch %d but the TPM high-water is %d: the anchor is inconsistent "
                 "(fail closed)" % (epoch, hw))
        return epoch, held

    def _verify(self, hw, digest_of, repair):
        """The record against a chain (`digest_of(epoch)` is its manifest digest there, ZERO at epoch 0)."""
        epoch, held = self._in_step(hw)
        require(held == digest_of(epoch), "CONFLICT: the manifest at epoch %d is not the one this node's TPM recorded: a substituted "
                "chain is never anchored; record an incident" % epoch)
        if epoch != hw and repair:           # a crash after the counter moved and before the record was written
            self._write_record(hw, digest_of(hw))

    def unusable(self):
        """None while the anchor can do its work: the counter reads, and the record is valid and at the
        counter's epoch or one below. Otherwise the reason, as text, when the ANCHOR is what is wrong (an
        index not defined or not of the right kind, no valid record, counter and record out of step): what
        Store.reanchor() is for. A TPM that does not answer, or a read that fails on an index that is as it
        should be, is neither: that raises Refused, and re-anchoring is not the remedy."""
        with _exclusive(self.lock_path):
            try:
                self._in_step(self._epoch(self._base()))
            except Unusable as reason:
                return str(reason)
            return None

    def _read_any(self, index, size, attributes):
        """The index's bytes, read with its own authorization (authread) or, failing that, the owner's: for
        remains(), which must see what an index holds whatever else is wrong with it. Refused if neither reads."""
        r = self._tpm("nvread", index, "-C", index, "-s", str(size))
        if (r.returncode != 0 or len(r.stdout) != size) and attributes & self.OWNERREAD:
            r = self._owner("nvread", index, "-s", str(size))
        require(r.returncode == 0 and len(r.stdout) == size, "cannot read %d bytes from NV index %s: what the anchor holds cannot "
                "be known (fail closed)" % (size, index))
        return r.stdout

    def remains(self):
        """What the TPM still holds of this anchor, each part by itself and WHATEVER ITS ATTRIBUTES: (the
        counter's epoch or None, every slot that holds a valid record). A re-anchor may forget none of it, and
        it deletes indices whose attributes are wrong, so their contents must count here first: reading more
        can only raise the floor, which fails closed. An index that is not defined, not written or of the
        wrong type or size holds nothing. Refused if the TPM does not answer, or an index cannot be read."""
        with _exclusive(self.lock_path):
            defined = self._defined()
            epoch = None
            if int(self.index, 16) in defined and int(self.base_index, 16) in defined:
                (a, a_size), (b, b_size) = self._public(self.index), self._public(self.base_index)
                if a & self.NT_MASK == self.NT_COUNTER and a & self.WRITTEN and b & self.WRITTEN and (a_size, b_size) == (8, 8):
                    counter = int.from_bytes(self._read_any(self.index, 8, a), "big")
                    base = int.from_bytes(self._read_any(self.base_index, 8, b), "big")
                    epoch = counter - base if counter >= base else None
            records = []
            for index in self.record_indices:
                if int(index, 16) not in defined:
                    continue
                held = self._held(index)
                if held[0] >= 0:
                    records.append(held)
            return epoch, records

    def record(self):
        """(epoch, manifest digest) as last written: the valid slot with the higher epoch."""
        with _exclusive(self.lock_path):
            return self._record()

    def slots(self):
        """What each record slot holds, in index order: (epoch, digest), or None for a slot that holds no record."""
        with _exclusive(self.lock_path):
            return self._slots()

    def pinned(self):
        """Whether the record names the manifest AT the high-water epoch (False in the crash window, where
        it still names the one before): only then does the TPM alone tell two chains of that length apart."""
        with _exclusive(self.lock_path):
            return self._record()[0] == self._epoch(self._base())

    def verify(self, digest_of, lock=True):
        """Refuses a chain that is not the anchored one; changes nothing. Returns the high-water epoch.

        lock=False is for a reader that cannot take the writer's lock (a service under another user, with
        the lock's directory read-only to it). It reads without serializing against Store: a commit in
        progress shows as the crash window (counter moved, record one behind) or as one slot being written
        (its tag does not match yet), both of which this accepts as it accepts them after a crash. A
        refusal from a lock-free read can be a commit racing it: read again before acting on it."""
        if not lock:
            base = self._base()
            hw = self._epoch(base)
            self._verify(hw, digest_of, repair=False)
            # a redefinition between the reads would pair the old base with the new counter; two in quick
            # succession could bring the base back, so the counter is compared too
            again = self._base()
            require((again, self._epoch(again)) == (base, hw), "this host's TPM anchor changed during the read: read again")
            return hw
        with _exclusive(self.lock_path):
            hw = self._epoch(self._base())
            self._verify(hw, digest_of, repair=False)
            return hw

    def anchor(self, epoch, digest_of):
        """Store's way to move the anchor to `epoch` of a chain it has verified and made durable: the chain
        must be the recorded one (a record one epoch behind the counter is repaired), then for every epoch up
        to `epoch` the counter is incremented and the record written, in that order."""
        with _exclusive(self.lock_path):
            self._verify(self._epoch(self._base()), digest_of, repair=True)
            return self._advance(epoch, digest_of)

    def check(self, disk_epoch):
        """The disk epoch must EQUAL the high-water: older is a rollback, newer was never anchored
        (Store.load anchors a verified newer chain with advance() first)."""
        hw = self.value()
        require(disk_epoch >= hw, "ROLLBACK: the manifest on disk is epoch %d but the TPM high-water is %d; "
                "fetch the chain from a peer" % (disk_epoch, hw))
        require(disk_epoch == hw, "epoch %d on disk is not anchored (TPM high-water %d)" % (disk_epoch, hw))
        return hw


class Store:
    """The node's accepted membership: the whole signed chain from epoch 1 in one file, anchored to a
    HighWater. This is the only API a node should use to read or change its membership.

    Both hold an exclusive lock (path + ".lock"), and HighWater serializes its own read/increment
    sequences, so concurrent callers cannot interleave.

    load()            verifies the chain from the pinned root, refuses it if it is older than the TPM
                      high-water (a restored or deleted file: ROLLBACK) or if its manifest at the anchored
                      epoch is not the one the TPM recorded (a substituted file, even of the same length:
                      CONFLICT), anchors a verified newer chain (a crash after the disk write), and returns
                      the current manifest (None before enrollment).
    envelopes(n)      the signed envelopes above epoch n, verified and anchored as load() does: what a
                      peer at epoch n lacks (convergence.py).
    restore(chain)    replaces the stored chain by one fetched whole from a peer, when load() refuses with
                      ROLLBACK or CONFLICT: verified from the root, at least as new as the TPM high-water,
                      the recorded manifest at the recorded epoch, and a continuation of what is on disk.
    reanchor(chain)   gives the node a new TPM anchor and installs the chain under it, when the anchor
                      itself is unusable and restore() must refuse too. An operator's decision, taken on
                      two other nodes that agree (reanchor.py; MEMBERSHIP-RECOVERY.md).
    commit(envelope)  accepts the next manifest onto the loaded chain, writes the file durably
                      (temp file, fsync, rename, fsync of the directory), THEN increments the TPM counter,
                      THEN writes the TPM record; a crash between any two is completed by the next load(),
                      never strands the node.

    The two crash windows, with hw the counter's epoch. After the disk write and before the counter: the
    disk is one epoch ahead, the record names the manifest at hw, and load() anchors the newer manifest.
    After the counter and before the record: the record names the manifest at hw - 1, which must match,
    and load() writes the record for hw. In that second window the manifest at hw is vouched for by the
    disk alone (pinned() is False): convergence.recover then asks for two sources, as it did before the
    record existed.
    """

    def __init__(self, path, root_key, highwater, documents=None):
        """`documents(manifest)`, when given, refuses (raises Refused) unless the document that manifest commits to is
        held (measurements.Documents.require_for, #332): no epoch is committed, nor the TPM anchor moved to it,
        without the reference values to judge it by. Generic here: membership does not know what a document is."""
        self.path, self.root_key, self.hw, self.documents = path, root_key, highwater, documents
        self.lock_path = path + ".lock"

    @staticmethod
    def _digests(manifests):
        """digest_of for HighWater: the chain's manifest digest at an epoch it reaches, ZERO at epoch 0."""
        return lambda epoch: digest(manifests[epoch - 1]) if epoch else HighWater.ZERO

    def pinned(self):
        """Whether the TPM names the manifest at the anchored epoch: one source is then enough to restore."""
        return self.hw.pinned()

    def _read_chain(self):
        try:
            with open(self.path, "rb") as f:
                raw = f.read(MAX_CHAIN_BYTES + 1)
        except FileNotFoundError:
            return []
        chain = load(raw, limit=MAX_CHAIN_BYTES)
        require(isinstance(chain, list) and chain, "the membership file must hold a non-empty list of envelopes")
        return chain

    def load(self):
        with _exclusive(self.lock_path):
            return self._load()

    def _load(self):
        chain = self._read_chain()
        current, manifests = None, []
        for envelope in chain:
            nxt = accept(current, envelope, self.root_key)
            require(nxt is not current, "the stored chain repeats epoch %d" % nxt["epoch"])
            manifests.append(nxt)
            current = nxt
        epoch = current["epoch"] if current else 0
        hw = self.hw.value()
        require(epoch >= hw, "ROLLBACK: the membership on disk is epoch %d but the TPM high-water is %d; "
                "fetch the chain from a peer" % (epoch, hw))
        # the recorded manifest, or refused; then a record or a counter left behind by a crash is completed
        self.hw.anchor(epoch, self._digests(manifests))
        self.hw.check(epoch)
        self.chain, self.manifests = chain, manifests
        return current

    def envelopes(self, after_epoch=0):
        """The signed envelopes above `after_epoch`, in order: what a peer at that epoch lacks. Verified and
        anchored exactly as load() does (a rolled-back file is refused here too), and returned as copies."""
        require(isinstance(after_epoch, int) and not isinstance(after_epoch, bool) and after_epoch >= 0, "after_epoch must be an integer >= 0")
        with _exclusive(self.lock_path):
            self._load()
            return copy.deepcopy(self.chain[after_epoch:])

    def restore(self, envelopes):
        """Replace the stored chain by one fetched whole from a peer: the recovery when load() refuses
        with ROLLBACK (the disk was restored to an older chain, or the file was lost). The fetched chain is
        verified from the pinned root at epoch 1, must reach at least the TPM high-water, must hold the
        manifest the TPM recorded at the recorded epoch, and must continue whatever valid chain is still on
        disk (a different manifest at an epoch held there is a CONFLICT, also when it is the disk that was
        substituted: the operator records the incident and removes the file). Written durably, then
        anchored; returns the current manifest.

        One source is enough when pinned(): the record then names the manifest at the anchored epoch, and
        the hash chain fixes every manifest below it. When it is not (a crash between counter and record),
        the fetched manifest at the anchored epoch is checked only through the one before it."""
        with _exclusive(self.lock_path):
            require(isinstance(envelopes, list) and envelopes, "a chain to restore is a non-empty list of envelopes")
            require(len(canonical(envelopes)) <= MAX_CHAIN_BYTES, "the chain to restore is oversized")
            current, manifests = None, []
            for envelope in envelopes:
                nxt = accept(current, envelope, self.root_key)
                require(nxt is not current, "the fetched chain repeats epoch %d" % nxt["epoch"])
                manifests.append(nxt)
                current = nxt
            hw = self.hw.value()
            require(current["epoch"] >= hw, "the fetched chain ends at epoch %d, below the TPM high-water %d: "
                    "fetch from a peer that is not behind" % (current["epoch"], hw))
            # before anything is written: advance() would refuse this jump AFTER the file was replaced,
            # leaving a disk ahead of the TPM that load() could never anchor
            require(current["epoch"] - hw <= self.hw.MAX_JUMP, "the fetched chain ends at epoch %d, %d above the TPM high-water: "
                    "the jump exceeds the bound %d: anomaly" % (current["epoch"], current["epoch"] - hw, self.hw.MAX_JUMP))
            # also before anything is written: a chain that is not the anchored one never reaches the disk
            self.hw.verify(self._digests(manifests))
            self._continues_disk(envelopes)
            if self.documents is not None:              # #332: the epoch restored to is judged by its own document
                self.documents(current)
            self._write(copy.deepcopy(envelopes))
            self.hw.anchor(current["epoch"], self._digests(manifests))
            self.hw.check(current["epoch"])
            self.chain, self.manifests = copy.deepcopy(envelopes), manifests
            return current

    def reanchor(self, envelopes):
        """Give this node a NEW anchor and install a chain under it: the recovery when the anchor itself is
        unusable (no valid record, an index not defined, counter and record out of step), which no chain
        from a peer can repair. It forgets what this TPM knew, so the caller must have established the
        chain from more than this node's word: reanchor.py takes it from two other nodes that agree.

        A usable anchor is never reset. A TPM that does not answer is not re-anchored either: nothing is
        known about its anchor then. And NOTHING THE TPM STILL HOLDS IS FORGOTTEN: the chain must reach the
        counter's epoch while the counter reads, must reach the epoch of every record slot that still holds
        a valid record, and must carry that slot's manifest at that epoch. The valid chain still on disk
        must agree, as for restore().

        Order: everything is verified; the chain is written durably; the anchor is redefined AT the chain's
        epoch with its manifest recorded (HighWater.redefine: no state in between is a usable anchor for any
        other chain). `reanchor_began` is set before the file is written: a failure before it has changed
        nothing; a failure after it is an operation to run again, and is reported as such."""
        self.reanchor_began = False
        with _exclusive(self.lock_path):
            require(isinstance(envelopes, list) and envelopes, "a chain to re-anchor on is a non-empty list of envelopes")
            require(len(canonical(envelopes)) <= MAX_CHAIN_BYTES, "the chain to re-anchor on is oversized")
            current, manifests = None, []
            for envelope in envelopes:
                nxt = accept(current, envelope, self.root_key)
                require(nxt is not current, "the fetched chain repeats epoch %d" % nxt["epoch"])
                manifests.append(nxt)
                current = nxt
            digest_of = self._digests(manifests)
            require(self.hw.unusable() is not None, "the TPM anchor is usable: it is not reset. A chain that is rolled back, lost or "
                    "substituted is restored under the anchor it has (restore)")
            counter, records = self.hw.remains()
            for held, what in sorted([(counter, "its counter")] * (counter is not None) + [(epoch, "a record slot") for epoch, _ in records], reverse=True):
                require(current["epoch"] >= held, "the fetched chain ends at epoch %d, below epoch %d, which this node's TPM still holds "
                        "(%s): re-anchoring does not go back" % (current["epoch"], held, what))
            for epoch, recorded in records:
                require(digest_of(epoch) == recorded, "CONFLICT: a record slot that still reads names another manifest at epoch %d than "
                        "the fetched chain: nothing is re-anchored; record an incident" % epoch)
            self._continues_disk(envelopes)
            self.reanchor_began = True
            self._write(copy.deepcopy(envelopes))
            self.hw.redefine(current["epoch"], digest_of(current["epoch"]))
            self.hw.check(current["epoch"])
            self.chain, self.manifests = copy.deepcopy(envelopes), manifests
            return current

    def _continues_disk(self, envelopes):
        """What is still on disk counts only as far as it is itself a valid chain: a corrupt or unsigned
        tail is what recovery is for, and must neither block it nor be compared."""
        held, previous = [], None
        try:
            for stored in self._read_chain():
                nxt = accept(previous, stored, self.root_key)
                if nxt is previous:
                    break
                held.append(nxt)
                previous = nxt
        except Refused:
            pass
        for mine, theirs in zip(held, envelopes):
            require(digest(mine) == digest(theirs["manifest"]), "CONFLICT: the fetched chain differs from the "
                    "stored one at epoch %d: record an incident" % mine["epoch"])
        require(len(held) <= len(envelopes), "the fetched chain is shorter than the stored one: nothing to restore")

    def commit(self, envelope, final=True):
        """Accept `envelope` as the next epoch, write it durably and move the TPM anchor to it. `final` False marks an
        epoch passed through on the way to a later one in the same batch (convergence.catch_up, enrolment): the
        `documents` check is made for the epoch a batch leaves the node at, the only one it then judges by (#332)."""
        with _exclusive(self.lock_path):        # load, write and advance as one step
            return self._commit(envelope, final)

    def _commit(self, envelope, final=True):
        current = self._load()
        nxt = accept(current, envelope, self.root_key)
        if nxt is current:
            return current
        if final and self.documents is not None:       # before the disk and the TPM: refused, nothing has moved
            self.documents(nxt)
        self._write(self.chain + [envelope])
        self.hw.anchor(nxt["epoch"], self._digests(self.manifests + [nxt]))
        self.chain, self.manifests = self.chain + [envelope], self.manifests + [nxt]
        return nxt

    def _write(self, chain):
        import os
        import tempfile
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(prefix=".membership-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(canonical(chain))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
