#!/usr/bin/env python3
"""Activation by quorum (#432, ADR-0002 D28.6 as refined on #432): which site may sign, decided by the nodes and, in
recovery only, the owner, with no separate fencing authority. This module is the lease's format, its verification
under the current membership manifest, and each node's grant record and signer. Issuance over sync, the owner's tool
and the Go Gate follow (#432 §5-§7).

THE RULE, AND WHY IT IS NOT "ANY 2 OF {a, b, c, owner}". Fencing needs mutual exclusion: no two sites active at once.
A quorum gives it only if every two quorums share a signer that keeps a durable record and refuses a conflicting
grant. {a, b} and {c, owner} share none. So:
  * NORMAL: `activation_signers`' threshold of NODE parties (2 of the 3). Any two such sets intersect, and the shared
    node's grant record (GrantRecord) refuses an overlapping lease for another site.
  * RECOVERY: the owner with fewer nodes, only with a `recovery` block: the other node parties QUARANTINED or REVOKED in
    the current manifest (verify() checks it), and a typed attestation that they are hard-fenced until they hold that
    epoch (recorded, not checkable here). The owner alone never activates.
  * Accepted risk (LIMITATIONS.md): an attestation false when made, or a fenced node rejoined before it holds the
    quarantine epoch.

    lease = {"schema": "regalia.activation/v2", "node_id", "site", "registry_digest", "activation_epoch",
             "manifest_epoch", "manifest_digest", "not_before", "expires_at"[, "recovery": {"fenced", "quarantine_epoch"}]}
    envelope = {"lease": lease, "signatures": [{"party", "key", "sig"}, ...]}     (membership.counting_parties' form)

signed over DOMAIN + canonical(lease). DOMAIN is activation's own: a heartbeat or manifest signature is never one.
"""
import contextlib
import fcntl
import json
import os
import re

from deploy.baremetal import heartbeat, lease as runtime_lease, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.activation/v2"
DOMAIN = b"regalia-activation/v2\0"
LEASE_KEYS = ("schema", "node_id", "site", "registry_digest", "activation_epoch", "manifest_epoch", "manifest_digest",
              "not_before", "expires_at")
RECOVERY_KEYS = ("fenced", "quarantine_epoch")
MAX_LEASE_S = 600                 # internal/fencing.MaxLeaseDuration (10 min): one bound, a test holds the two equal
SKEW_S = 60                       # a signer's allowance for not_before ahead of its authenticated time (the Gate has none)
# the recovery path's wait, and a node's busy window after a start without its record: any activation lease AND any
# runtime lease the cut-off side may hold has expired by then (#432, amendment 1). Derived, never a second literal.
RECOVERY_WAIT_S = max(MAX_LEASE_S, runtime_lease.MAX_LIFETIME) + SKEW_S
MAX_FENCED_BYTES = 512
SITE = re.compile(r"[a-z0-9][a-z0-9-]{2,62}")            # a registry site (>= 3 characters), not a node_id
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


# ---- the lease ----

def _epoch(value, label):
    require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value < 2 ** 63, "%s must be an integer >= 1" % label)


def validate(lease):
    """Schema only. Returns (not_before, expires) in seconds."""
    require(isinstance(lease, dict), "the activation lease is an object")
    keys = set(LEASE_KEYS) | ({"recovery"} if "recovery" in lease else set())
    membership.exact(lease, sorted(keys), "the activation lease")
    require(lease["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(lease["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", lease["node_id"]) is not None, "node_id must be a node ID")
    require(isinstance(lease["site"], str) and SITE.fullmatch(lease["site"]) is not None, "site must be a registry site name")
    require(isinstance(lease["registry_digest"], str) and DIGEST.fullmatch(lease["registry_digest"]) is not None,
            "registry_digest must be sha256:<64 hex>")
    _epoch(lease["activation_epoch"], "activation_epoch")
    _epoch(lease["manifest_epoch"], "manifest_epoch")
    membership.hex_field(lease["manifest_digest"], 64, "manifest_digest")
    start, expires = heartbeat.parse_time(lease["not_before"], "not_before"), heartbeat.parse_time(lease["expires_at"], "expires_at")
    require(start < expires, "expires_at must be after not_before")
    require(expires - start <= MAX_LEASE_S, "an activation lease lives at most %d s (this one: %d)" % (MAX_LEASE_S, expires - start))
    if "recovery" in lease:
        rec = lease["recovery"]
        membership.exact(rec, RECOVERY_KEYS, "the recovery block")
        require(isinstance(rec["fenced"], str) and rec["fenced"].strip() and len(rec["fenced"].encode()) <= MAX_FENCED_BYTES
                and rec["fenced"].isprintable(), "recovery.fenced must be printable text of at most %d bytes" % MAX_FENCED_BYTES)
        _epoch(rec["quarantine_epoch"], "recovery.quarantine_epoch")
        require(rec["quarantine_epoch"] <= lease["manifest_epoch"], "the quarantine epoch is above the lease's manifest")
    return start, expires


def message(lease):
    validate(lease)
    return DOMAIN + membership.canonical(lease)


def verify(envelope, current):
    """The lease of `envelope` if its signatures meet `current`'s activation rule (module docstring), else Refused.
    `current` is the verifier's CURRENT manifest: the lease may name an older one (no serving gap at an epoch change),
    never a newer one, and is counted under the current signers and keys, so a node the current manifest stopped
    counting (QUARANTINED, REVOKED_STOLEN, RETIRED) is not counted even on an older lease. Time is the caller's
    (the Gate, or a signer with its authenticated clock)."""
    membership.exact(envelope, ("lease", "signatures"), "the activation envelope")
    lease = envelope["lease"]
    raw = message(lease)
    require(current is not None and current["schema"] == membership.SCHEMA_V4, "activation by quorum needs a %s manifest" % membership.SCHEMA_V4)
    require(lease["manifest_epoch"] <= current["epoch"], "the lease names manifest epoch %d, newer than this node's %d"
            % (lease["manifest_epoch"], current["epoch"]))
    if lease["manifest_epoch"] == current["epoch"]:
        require(lease["manifest_digest"] == membership.digest(current), "the lease names another manifest at epoch %d" % current["epoch"])
    nodes = membership.validate(current)
    require(lease["node_id"] in nodes, "%s is not a node of the current manifest" % lease["node_id"])
    require(membership.may(current, lease["node_id"], "serve"), "%s may not serve under epoch %d" % (lease["node_id"], current["epoch"]))
    rule = current["activation_signers"]
    counted = membership.counting_parties(current, raw, envelope["signatures"], "activation lease") & set(rule["parties"])
    node_parties = {p for p in counted if p != membership.OWNER}
    if membership.OWNER not in counted:
        require("recovery" not in lease, "a recovery block without the owner's signature: refused")
        require(len(node_parties) >= rule["threshold"], "%d of the nodes signed (%s); activation needs %d"
                % (len(node_parties), ", ".join(sorted(node_parties)) or "none", rule["threshold"]))
        return lease
    # the owner counts only as the recovery path: with a node, the other node parties stopped in the CURRENT manifest
    require("recovery" in lease, "the owner's signature counts only on the recovery path (a lease with a recovery block)")
    require(node_parties, "the owner alone never activates a site")
    require(len(node_parties) + 1 >= rule["threshold"], "the owner and %d node(s) are below the threshold %d" % (len(node_parties), rule["threshold"]))
    others = [p for p in rule["parties"] if p != membership.OWNER and p not in node_parties]
    loose = [p for p in others if p in nodes and nodes[p]["state"] not in membership.NOT_COUNTING]
    require(not loose, "the recovery path needs every other node party quarantined or revoked under epoch %d; %s %s not"
            % (current["epoch"], ", ".join(loose), "is" if len(loose) == 1 else "are"))
    require(lease["recovery"]["quarantine_epoch"] <= current["epoch"], "the quarantine epoch is newer than this node's manifest")
    return lease


# ---- each node's grant record (#432 §4) ----

@contextlib.contextmanager
def _locked(path):
    """An exclusive flock on `path`, opened without following a link (d9): held across a whole grant."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


class GrantRecord:
    """What this node has co-signed. `counter` (heartbeat.Counter's value()/advance(), on nv_activation) counts THIS
    node's grants, one increment each; the disk record (`path`) holds that count with the last grant's epoch, site
    and expiry. The record stands only while its count equals the counter: a disk restored to an older record, or
    one lost, does not. The counter moves BEFORE the record is written, and the record BEFORE the signature is
    released (regalia-fence's order: a crash costs a count, never an unrecorded grant). Counting grants rather than
    holding the epoch keeps every advance a single increment, however many leases the others granted while this
    node was away.

    BUSY. When the record does not stand, this node cannot know what it granted, so it signs nothing until `started`
    (its authenticated time at THIS start, never persisted) + RECOVERY_WAIT_S: any lease it might have granted has
    expired by then. After that it signs again, and its next grant writes a record that stands. So a NEW cluster
    (every counter at 0) has every node busy for RECOVERY_WAIT_S (about 11 minutes) after its first start, and its
    first activation waits for that: correct by the rule, not a fault (d9).

    One grant at a time: Signer holds `lock_path` (beside the record, opened without following a link) across
    state, check, counter, record and signature, so two requests arriving together cannot both pass the overlap
    check on the same `last` (d9's race)."""

    def __init__(self, counter, path, started):
        self.counter, self.path, self.started = counter, path, int(started)
        self.lock_path = path + ".lock"

    def _held(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)       # never through a link (ed)
            with os.fdopen(fd, "rb") as f:
                rec = json.loads(f.read(4096))
            membership.exact(rec, ("grants", "activation_epoch", "site", "node_id", "expires_at"), "the grant record")
            return rec
        except (OSError, ValueError, Refused):
            return None

    def state(self, now):
        """(the last grant if the record stands, else None; why this node is busy, or None). The record stands when it
        holds as many grants as the counter, and at least one. Otherwise, a node that never granted included (it may be
        a new TPM, or a disk wiped together with a counter that was redefined), the node is busy for RECOVERY_WAIT_S
        after this start. A counter that cannot be read (an absent index) raises: it signs nothing (d9)."""
        held, count = self._held(), self.counter.value()
        if held is not None and count > 0 and held["grants"] == count:
            return held, None
        if now < self.started + RECOVERY_WAIT_S:
            return None, ("this node's grant record does not stand (%s on disk, %d grants on its TPM counter): it signs no "
                          "activation until %d s after its start" % (held and held.get("grants"), count, RECOVERY_WAIT_S))
        return None, None

    def check(self, lease, now):
        """Refused unless this node may co-sign `lease` now (authenticated seconds). Returns (not_before, expires)."""
        start, expires = validate(lease)
        last, busy = self.state(now)
        require(busy is None, busy or "")
        require(start <= now + SKEW_S, "not_before is %d s ahead of this node's authenticated time" % (start - now))
        require(expires > now, "the lease has already expired")
        if last is not None:
            require(lease["activation_epoch"] > last["activation_epoch"], "activation_epoch %d is not above this node's last grant, %d: "
                    "an epoch is granted once" % (lease["activation_epoch"], last["activation_epoch"]))
            # only a renewal (the same site on the same node) may overlap: the same site on ANOTHER node is two signers
            # for one key, the double signing fencing exists to stop (d9). Past the skew margin, since the old site's
            # Gate judges its expiry by its own clock and the new one's not_before by another (d9)
            if (last["site"], last.get("node_id")) != (lease["site"], lease["node_id"]):
                require(start >= last["expires_at"] + SKEW_S, "OVERLAP: this node granted site %s on %s until %d; a lease for site %s on %s "
                        "may not begin before that, and the %d s skew margin" % (last["site"], last.get("node_id"), last["expires_at"],
                                                                                lease["site"], lease["node_id"], SKEW_S))
        return start, expires

    def record(self, lease, expires):
        count = self.counter.value() + 1
        self.counter.advance(count, 1)                       # reserved first: a crash after it costs a count
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"grants": count, "activation_epoch": lease["activation_epoch"], "site": lease["site"], "node_id": lease["node_id"],
                       "expires_at": int(expires)}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        dirfd = os.open(os.path.dirname(self.path) or ".", os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)


class Signer:
    """This node's signature over an activation lease: its key checked against the manifest, the lease checked against
    its grant record, the record written, then the signature. `sign(message)` returns r || s hex (signkey.sign)."""

    def __init__(self, node_id, record, sign, key):
        self.node_id, self.record, self._sign, self.key = node_id, record, sign, key

    def __call__(self, lease, manifest, now):
        nodes = membership.validate(manifest)
        require(self.node_id in nodes and nodes[self.node_id].get("signing_key", {}).get("key") == self.key,
                "this node's signing key is not the one the manifest at epoch %d gives %s: nothing is signed" % (manifest["epoch"], self.node_id))
        require(self.node_id in manifest["activation_signers"]["parties"] and nodes[self.node_id]["state"] not in membership.NOT_COUNTING,
                "%s does not count toward activation under epoch %d: it signs no activation" % (self.node_id, manifest["epoch"]))
        require(lease["manifest_epoch"] == manifest["epoch"] and lease["manifest_digest"] == membership.digest(manifest),
                "a signer signs only for its own current manifest (epoch %d)" % manifest["epoch"])
        with _locked(self.record.lock_path):                  # one grant at a time (d9)
            _, expires = self.record.check(lease, now)
            self.record.record(lease, expires)
            return {"party": self.node_id, "key": self.key, "sig": self._sign(message(lease))}


# ---- issuance between the nodes (#432 §5): the proposer is the node to be activated; one other node co-signs ----

def _now(clock):
    seconds, authenticated = clock()
    require(authenticated is True, "time is not authenticated: no activation is signed")
    return int(seconds)


def cosign(manifest, me, caller, lease, clock, signer, synced):
    """This node's signature over the activation `lease` that `caller` (the node the tunnel identified) proposed for
    ITSELF, or Refused. The co-signer signs FIRST and the proposer only once it has (propose()): a refusal then costs
    the proposer nothing, where a recorded self-grant would block it from co-signing anyone else's renewal for a lease
    life (ed's read). Both still record before their signature leaves them, so neither can later co-sign an overlap.
    `synced()` is d9's boot rule: True once, since this boot, this node has pulled from every node its current manifest
    lets authorize, or holds a newer epoch than it booted with. Until then it co-signs nothing: two fenced nodes
    powered back on inside a partition must not activate each other on an old manifest."""
    rule = manifest["activation_signers"]
    nodes = membership.validate(manifest)
    counting = [p for p in rule["parties"] if p != membership.OWNER and p in nodes and nodes[p]["state"] not in membership.NOT_COUNTING]
    require(me in counting, "%s does not count toward activation under epoch %d: it co-signs nothing" % (me, manifest["epoch"]))
    require(caller in counting and caller != me, "%s does not count toward activation under epoch %d" % (caller, manifest["epoch"]))
    require(synced(), "since its boot this node has not pulled from every node that may authorize: it co-signs no activation yet")
    validate(lease)
    require(lease["node_id"] == caller, "%s proposes an activation for %s: a node proposes only its own" % (caller, lease["node_id"]))
    require("recovery" not in lease, "a recovery lease is the owner's (owner.py), never proposed over sync")
    return signer(lease, manifest, _now(clock))


def proposal(node_id, site, registry_digest, manifest, epoch, now):
    """A lease for this node's own activation, from now for MAX_LEASE_S, under its current manifest."""
    return {"schema": SCHEMA, "node_id": node_id, "site": site, "registry_digest": registry_digest, "activation_epoch": epoch,
            "manifest_epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest),
            "not_before": _stamp(now), "expires_at": _stamp(now + MAX_LEASE_S)}


def _stamp(seconds):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(seconds)))


def propose(node_id, site, registry_digest, manifest, clock, signer, ask, peers, trail):
    """This node's activation, the epoch one above the highest this node knows (its grant record's). Its own record is
    CHECKED first (nothing written); then one co-signer from `peers` (in order) checks, records and signs; only then does
    this node record and sign (cosign's docstring: a refusal costs the proposer nothing). A co-signer's refusal may name
    its last epoch ("last grant, N"): the proposal is retried ONCE at the highest such N + 1, never in a loop (ed).
    Returns the envelope the Gate takes, or Refused. `ask(peer, lease)` returns that peer's signature or raises Refused;
    `trail(event)` records each attempt."""
    now = _now(clock)
    last, _ = signer.record.state(now)
    epoch = (last["activation_epoch"] if last else 0) + 1
    refusals = []
    for attempt in range(2):
        lease = proposal(node_id, site, registry_digest, manifest, epoch, now)
        signer.record.check(lease, now)                       # this node's own refusal, before anyone is asked
        seen = []
        for peer in peers:
            try:
                theirs = ask(peer, lease)
            except Refused as refused:
                refusals.append("%s: %s" % (peer, refused))
                found = re.search(r"last grant, (\d+)", str(refused))
                if found:
                    seen.append(int(found.group(1)))
                continue
            own = signer(lease, manifest, now)                # recorded, then signed: a crash here costs a count
            done = {"lease": lease, "signatures": [own, theirs]}
            verify(done, manifest)
            trail({"event": "activation", "outcome": "ALLOW", "epoch": manifest["epoch"], "activation_epoch": epoch, "site": site, "peer": peer})
            return done
        if attempt or not seen or max(seen) < epoch:
            break
        epoch = max(seen) + 1
    trail({"event": "activation", "outcome": "DENY", "epoch": manifest["epoch"], "activation_epoch": epoch, "site": site,
           "reason": "; ".join(refusals)[:240]})
    raise Refused("no node co-signed this activation: %s" % "; ".join(refusals))
