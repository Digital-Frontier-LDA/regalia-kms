#!/usr/bin/env python3
"""Signed cluster membership with rollback-safe epochs (#68, Phase 8 of #59).

A manifest names every node, its identities and its state. Peers decide who may be unlocked, who may
authorize an unlock and who may serve from the newest manifest they have accepted, never from what a
node claims (THREE-SITE-THREAT-MODEL.md S2, ADR-0002 D23).

    envelope = {"manifest": {...}, "signature": {"signer": "root" | "revocation", "key": "<hex Ed25519 public key>",
                                                 "sig": "<hex Ed25519 signature>"}}

    manifest = {"schema": "regalia.membership/v1", "epoch": <int >= 1>, "prev_digest": "<64 hex, or "" at epoch 1>",
                "policy_version": "<text>", "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
                "revocation_keys": ["<hex Ed25519 public key>", ...],
                "nodes": [{"node_id": ..., "state": ..., "ek_name": ..., "ak_name": ..., "wg_boot_pub": ...,
                           "wg_service_pub": ..., "hsm_serials": [...]}]}

Signed message: b"regalia-membership/v1\\0" + canonical JSON of the manifest (sorted keys, no spaces,
ASCII). Parsing refuses duplicate keys, unknown or missing fields, floats and non-ASCII names, so one
document has exactly one meaning.

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
import re
import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "regalia.membership/v1"
DOMAIN = b"regalia-membership/v1\0"
MAX_BYTES = 256 * 1024
MAX_CHAIN_BYTES = 64 * 1024 * 1024
CAPABILITIES = {
    "ACTIVE": frozenset({"serve", "request", "authorize"}),
    "MAINTENANCE": frozenset({"request"}),
    "DRAINING": frozenset({"serve"}),
    "QUARANTINED": frozenset(), "RETIRED": frozenset(), "REVOKED_STOLEN": frozenset(),
}
MANIFEST_KEYS = ("schema", "epoch", "prev_digest", "policy_version", "issued_at", "revocation_keys", "nodes")
NODE_KEYS = ("node_id", "state", "ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials")
IDENTITY_KEYS = ("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub")


class Refused(Exception):
    pass


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


def validate(manifest):
    """Schema and uniqueness. Returns the manifest's nodes by ID."""
    exact(manifest, MANIFEST_KEYS, "manifest")
    require(manifest["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    e = manifest["epoch"]
    require(isinstance(e, int) and not isinstance(e, bool) and e >= 1, "epoch must be an integer >= 1")
    if e == 1:
        require(manifest["prev_digest"] == "", "epoch 1 has no previous manifest (prev_digest \"\")")
    else:
        hex_field(manifest["prev_digest"], 64, "prev_digest")
    require(isinstance(manifest["policy_version"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", manifest["policy_version"]),
            "policy_version must be a short name")
    try:
        datetime.datetime.strptime(manifest["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise Refused("issued_at must be UTC, YYYY-MM-DDTHH:MM:SSZ")
    keys = manifest["revocation_keys"]
    require(isinstance(keys, list), "revocation_keys must be a list")
    for k in keys:
        hex_field(k, 64, "a revocation key")
    require(len(set(keys)) == len(keys), "revocation_keys must be distinct")
    nodes = manifest["nodes"]
    require(isinstance(nodes, list) and nodes, "nodes must be a non-empty list")
    by_id, seen = {}, {}
    for i, node in enumerate(nodes):
        exact(node, NODE_KEYS, "nodes[%d]" % i)
        require(isinstance(node["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node["node_id"]),
                "nodes[%d].node_id must be a short lowercase name" % i)
        require(node["node_id"] not in by_id, "duplicate node_id %r" % node["node_id"])
        require(node["state"] in CAPABILITIES, "nodes[%d].state %r is not a known state" % (i, node["state"]))
        hex_field(node["ek_name"], 68, "nodes[%d].ek_name" % i)
        hex_field(node["ak_name"], 68, "nodes[%d].ak_name" % i)
        hex_field(node["wg_boot_pub"], 64, "nodes[%d].wg_boot_pub" % i)
        hex_field(node["wg_service_pub"], 64, "nodes[%d].wg_service_pub" % i)
        require(isinstance(node["hsm_serials"], list) and all(isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9]{1,32}", s)
                                                             for s in node["hsm_serials"]), "nodes[%d].hsm_serials" % i)
        # No identity may belong to two nodes: a substituted TPM, key or token would otherwise pass as another.
        # Compared by value across roles: one WireGuard key cannot be a boot key and a service key, on
        # one node or two, and one TPM name cannot be an EK and an AK.
        for k in IDENTITY_KEYS:
            require(node[k] not in seen, "%s of %s is already used (%s)" % (k, node["node_id"], seen.get(node[k])))
            seen[node[k]] = "%s of %s" % (k, node["node_id"])
        for s in node["hsm_serials"]:
            require(("hsm", s) not in seen, "HSM %s is listed twice" % s)
            seen[("hsm", s)] = node["node_id"]
        by_id[node["node_id"]] = node
    return by_id


def verify_envelope(envelope, root_key, current=None):
    """The manifest inside an envelope, if its signature is by the pinned root key or by a revocation key
    named in the CURRENT manifest (never one named by the candidate itself). Returns (manifest, signer)."""
    exact(envelope, ("manifest", "signature"), "envelope")
    sig = envelope["signature"]
    exact(sig, ("signer", "key", "sig"), "signature")
    require(sig["signer"] in ("root", "revocation"), "signer must be root or revocation")
    hex_field(sig["key"], 64, "signature.key")
    hex_field(sig["sig"], 128, "signature.sig")
    if sig["signer"] == "root":
        require(sig["key"] == root_key, "the signature names a root key that is not the pinned root")
    else:
        require(current is not None and sig["key"] in current["revocation_keys"],
                "the signing revocation key is not named by the current manifest")
    manifest = envelope["manifest"]
    validate(manifest)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["key"])).verify(bytes.fromhex(sig["sig"]), DOMAIN + canonical(manifest))
    except (InvalidSignature, ValueError):
        raise Refused("the manifest signature does not verify")
    return manifest, sig["signer"]


def _restrictive(current, candidate):
    """A revocation-signed change: identities, policy and keys unchanged; capabilities only shrink."""
    require(candidate["policy_version"] == current["policy_version"], "a revocation key cannot change the policy version")
    require(candidate["revocation_keys"] == current["revocation_keys"], "a revocation key cannot change the revocation keys")
    old, new = validate(current), validate(candidate)
    require(set(old) == set(new), "a revocation key cannot add or remove nodes")
    for nid, node in new.items():
        for k in IDENTITY_KEYS + ("hsm_serials",):
            require(node[k] == old[nid][k], "a revocation key cannot change %s of %s" % (k, nid))
        require(CAPABILITIES[node["state"]] <= CAPABILITIES[old[nid]["state"]],
                "%s: %s -> %s widens capabilities; only the root can do that" % (nid, old[nid]["state"], node["state"]))


TERMINAL = ("RETIRED", "REVOKED_STOLEN")


def _tombstones(current, candidate):
    """No node ever leaves the manifest, and retirement is terminal, for EVERY signer, the root included.
    A node can only be retired, never removed. A node that is RETIRED or REVOKED_STOLEN
    stays in every later manifest as a tombstone: the same node_id, identities and HSM serials (as they
    were BEFORE it was retired: the retiring manifest cannot change them either), and a state that only
    moves from RETIRED to REVOKED_STOLEN. With the tombstone always present, validate()'s
    uniqueness rule refuses any reuse of its EK, AK, WireGuard keys, HSM serials or node ID, for ever."""
    old, new = validate(current), validate(candidate)
    for nid, node in old.items():
        if node["state"] not in TERMINAL:
            # No node leaves the list except as a tombstone: a node removed outright would leave nothing
            # behind, and its identities could be enrolled again. A mistaken enrollment is retired.
            require(nid in new, "tombstone: %s cannot be removed; retire it instead" % nid)
            # The manifest that retires a node must record the hardware as it was: identities rewritten in
            # the same step would leave the real ones free and protect the substitutes for ever.
            if new[nid]["state"] in TERMINAL:
                for k in IDENTITY_KEYS + ("hsm_serials",):
                    require(new[nid][k] == node[k], "tombstone: %s becomes %s and its %s cannot change in the same manifest"
                            % (nid, new[nid]["state"], k))
            continue
        require(nid in new, "tombstone: %s is %s and must stay in every later manifest (its identities are never reused)"
                % (nid, node["state"]))
        for k in IDENTITY_KEYS + ("hsm_serials",):
            require(new[nid][k] == node[k], "tombstone: %s is %s and its %s cannot change" % (nid, node["state"], k))
        require(new[nid]["state"] == node["state"] or (node["state"], new[nid]["state"]) == ("RETIRED", "REVOKED_STOLEN"),
                "tombstone: %s is %s, which is terminal for every signer (%s refused); hardware that may return "
                "belongs in MAINTENANCE or QUARANTINED" % (nid, node["state"], new[nid]["state"]))


def accept(current, envelope, root_key):
    """The next manifest, if `envelope` may follow `current` (None at enrollment, where only a
    root-signed epoch-1 manifest is accepted)."""
    candidate, signer = verify_envelope(envelope, root_key, current)
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
    _tombstones(current, candidate)        # both signers: the one rule the root cannot override
    if signer == "revocation":
        _restrictive(current, candidate)
    return candidate


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
    reach one epoch if a key signed twice for it. So a third, ordinary index holds
    `epoch (u64, big-endian) || SHA-256(canonical manifest at that epoch)`, 40 bytes. `define()` creates it
    at epoch 0 with an all-zero digest. Only Store writes it, through `anchor()`, and always AFTER the
    counter: for each epoch the counter is incremented, then the record written. The record's epoch is
    therefore the counter's, or one below it after a crash between the two; `anchor()` and `verify()`
    accept exactly those two, compare the digest with the chain they are given, and refuse anything else
    (a record that cannot be read, another epoch, another digest). In the crash window the manifest AT the
    counter's epoch is not yet recorded: `pinned()` is False until `anchor()` has repaired it.
    The same limit as the counter: owner authorization on the running host can rewrite the record. And a
    record whose write was torn by a power cut reads as neither epoch and fails closed, until an operator
    redefines the anchor.
    """

    MAX_JUMP = 1000
    RECORD = True                        # heartbeat.Counter is this counter without the record
    RECORD_BYTES, ZERO = 40, "00" * 32
    NT_MASK, NT_COUNTER, NT_ORDINARY = 0xF0, 0x10, 0x00
    WRITTEN, WRITELOCKED = 0x20000000, 0x800

    def __init__(self, index, tcti=None, run=subprocess.run, base_index=None, lock_path=None, record_index=None):
        self.index, self.run, self.env = index, run, ({"TPM2TOOLS_TCTI": tcti} if tcti else None)
        self.base_index = base_index or "0x%x" % (int(index, 16) + 1)
        # index + 2 and + 3 are left to the heartbeat's pair (0x1500018/0x1500019 beside 0x1500016)
        self.record_index = (record_index or "0x%x" % (int(index, 16) + 4)) if self.RECORD else None
        # Two processes advancing at once could both increment and push the counter past any manifest.
        self.lock_path = lock_path or "/run/lock/regalia-highwater-%s.lock" % self.index

    def _tpm(self, *args, **kw):
        import os
        env = dict(os.environ, **self.env) if self.env else None
        return self.run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=env, **kw)

    def _attributes(self, index):
        """The index's TPMA_NV mask; Refused if the index cannot be read (missing, or no TPM)."""
        r = self._tpm("nvreadpublic", index)
        require(r.returncode == 0, "cannot read NV index %s: the high-water anchor is unavailable (fail closed)" % index)
        found = re.search(rb"attributes:\s*\n\s*friendly:[^\n]*\n\s*value:\s*0x([0-9A-Fa-f]+)", r.stdout)
        require(found is not None, "unparseable nvreadpublic output for %s" % index)
        return int(found.group(1), 16)

    def _read8(self, index):
        r = self._tpm("nvread", index, "-C", "o", "-s", "8")
        require(r.returncode == 0 and len(r.stdout) == 8, "cannot read 8 bytes from NV index %s" % index)
        return int.from_bytes(r.stdout, "big")

    def define(self):
        with _exclusive(self.lock_path):
            return self._define()

    def _define(self):
        for index in filter(None, (self.index, self.base_index, self.record_index)):
            require(self._tpm("nvreadpublic", index).returncode != 0, "NV index %s already exists" % index)
        r = self._tpm("nvdefine", self.index, "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite")
        require(r.returncode == 0, "cannot define the NV counter %s" % self.index)
        require(self._tpm("nvincrement", self.index, "-C", "o").returncode == 0, "cannot increment the NV counter")
        base = self._read8(self.index)
        r = self._tpm("nvdefine", self.base_index, "-C", "o", "-s", "8", "-a", "ownerread|ownerwrite|authread|authwrite|writedefine")
        require(r.returncode == 0, "cannot define the base index %s" % self.base_index)
        r = self._tpm("nvwrite", self.base_index, "-C", "o", "-i", "-", input=base.to_bytes(8, "big"))
        require(r.returncode == 0, "cannot write the base index")
        require(self._tpm("nvwritelock", self.base_index, "-C", "o").returncode == 0, "cannot write-lock the base index")
        if self.record_index:
            r = self._tpm("nvdefine", self.record_index, "-C", "o", "-s", str(self.RECORD_BYTES), "-a", "ownerread|ownerwrite|authread|authwrite")
            require(r.returncode == 0, "cannot define the record index %s" % self.record_index)
            self._write_record(0, self.ZERO)
        return base

    def _base(self):
        """Checks both indices' attributes and returns the base (one call per value/advance/check)."""
        a = self._attributes(self.index)
        require(a & self.NT_MASK == self.NT_COUNTER and a & self.WRITTEN, "NV index %s is not a written counter" % self.index)
        b = self._attributes(self.base_index)
        require(b & self.NT_MASK == self.NT_ORDINARY and b & self.WRITTEN and b & self.WRITELOCKED,
                "base index %s is not written and write-locked" % self.base_index)
        return self._read8(self.base_index)

    def _epoch(self, base):
        counter = self._read8(self.index)
        require(counter >= base, "the NV counter %d is below its base %d" % (counter, base))
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
            r = self._tpm("nvincrement", self.index, "-C", "o")
            require(r.returncode == 0, "cannot increment the NV counter")
            nxt = self._epoch(base)
            require(nxt == now + 1, "the NV counter did not advance by one (%d -> %d)" % (now, nxt))
            now = nxt
            if digest_of:
                self._write_record(now, digest_of(now))
        return now

    def _record(self):
        require(self.record_index is not None, "this counter keeps no record")
        a = self._attributes(self.record_index)
        require(a & self.NT_MASK == self.NT_ORDINARY and a & self.WRITTEN, "record index %s is not a written ordinary index" % self.record_index)
        r = self._tpm("nvread", self.record_index, "-C", "o", "-s", str(self.RECORD_BYTES))
        require(r.returncode == 0 and len(r.stdout) == self.RECORD_BYTES, "cannot read %d bytes from the record index %s: the anchor "
                "is unavailable (fail closed)" % (self.RECORD_BYTES, self.record_index))
        return int.from_bytes(r.stdout[:8], "big"), r.stdout[8:].hex()

    def _write_record(self, epoch, manifest_digest):
        hex_field(manifest_digest, 64, "a manifest digest")
        r = self._tpm("nvwrite", self.record_index, "-C", "o", "-i", "-", input=epoch.to_bytes(8, "big") + bytes.fromhex(manifest_digest))
        require(r.returncode == 0, "cannot write the record index %s" % self.record_index)
        require(self._record() == (epoch, manifest_digest), "the record index %s did not take the write" % self.record_index)

    def _verify(self, hw, digest_of, repair):
        """The record against a chain (`digest_of(epoch)` is its manifest digest there, ZERO at epoch 0)."""
        epoch, held = self._record()
        require(epoch in (hw, hw - 1), "the TPM record is for epoch %d but the TPM high-water is %d: the anchor is inconsistent "
                "(fail closed)" % (epoch, hw))
        require(held == digest_of(epoch), "CONFLICT: the manifest at epoch %d is not the one this node's TPM recorded: a substituted "
                "chain is never anchored; record an incident" % epoch)
        if epoch != hw and repair:           # a crash after the counter moved and before the record was written
            self._write_record(hw, digest_of(hw))

    def record(self):
        """(epoch, manifest digest) as last written."""
        with _exclusive(self.lock_path):
            return self._record()

    def pinned(self):
        """Whether the record names the manifest AT the high-water epoch (False in the crash window, where
        it still names the one before): only then does the TPM alone tell two chains of that length apart."""
        with _exclusive(self.lock_path):
            return self._record()[0] == self._epoch(self._base())

    def verify(self, digest_of):
        """Refuses a chain that is not the anchored one; changes nothing. Returns the high-water epoch."""
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

    def __init__(self, path, root_key, highwater):
        self.path, self.root_key, self.hw = path, root_key, highwater
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
            # What is still on disk counts only as far as it is itself a valid chain: a corrupt or unsigned
            # tail is what recovery is for, and must neither block it nor be compared.
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
            self._write(copy.deepcopy(envelopes))
            self.hw.anchor(current["epoch"], self._digests(manifests))
            self.hw.check(current["epoch"])
            self.chain, self.manifests = copy.deepcopy(envelopes), manifests
            return current

    def commit(self, envelope):
        with _exclusive(self.lock_path):        # load, write and advance as one step
            return self._commit(envelope)

    def _commit(self, envelope):
        current = self._load()
        nxt = accept(current, envelope, self.root_key)
        if nxt is current:
            return current
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
