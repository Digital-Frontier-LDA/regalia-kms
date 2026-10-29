#!/usr/bin/env python3
"""Heartbeats signed by the nodes themselves (#199, step 3: there is no authority host). Under a v4 manifest a
heartbeat counts when two of {a, b, c, owner} signed it (heartbeat.signed_by); here is how two nodes come to sign
one. The protocol is on #199 (comment of 2026-10-04, "Step 3, concrete protocol").

PROPOSING (Proposer, in regalia-sync's loop). The nodes whose signature counts under the current manifest's
heartbeat_signers, in ID order, take turns by rank: rank r proposes once

    now >= issued_at(held) + interval + r * takeover + jitter (0 to the jitter bound)

so the first node beats on time and the next takes over two minutes after a miss. A node that holds no heartbeat
for the current epoch (bootstrap, or a revocation just taken) drops the interval and goes at once, by rank. The
body is for the current manifest, sequence max(held, this node's signing counter) + 1, issued at authenticated
now, living the manifest's heartbeat_max_lifetime_s. The proposer signs it (Signer), asks the other counting nodes
in order (beat-sign, sync.py) until one co-signs, and takes the envelope into its own Freshness; the peers pull it
from there as they pull every heartbeat. Nobody co-signing costs the proposer one number; it tries again after
the first retry delay, doubling, at most every interval: the nodes' jump allowance absorbs the numbers spent. The
takeover, the jitter and the first retry are fixed fractions of the interval (node.json's beat_interval_s): 120 s,
30 s and 60 s at the production 900 s, and proportionally less where a test beats faster.

CO-SIGNING (cosign, behind sync.py's beat-sign). A node signs another's proposal only if: the caller the tunnel
identified is the signature's party and counts; this node counts too; the body is for this node's current manifest
(epoch and digest); issued_at is within ISSUE_SKEW_S of this node's authenticated time; it lives no longer than
the manifest allows; and its sequence is above this node's signing counter AND above the heartbeat counter its own
Freshness holds, by no more than Freshness would accept (heartbeat.allowed_jump): a node never signs what it would
itself refuse.
NOT "THE NEXT" SEQUENCE, BY DESIGN (regalia-kms-1e's read): a proposal is co-signed when it is above both counters
within allowed_jump, not only when it is held + 1. Numbers spent by proposals nobody co-signed must be skippable, and the
bound (Counter.MAX_JUMP, 1000, plus one per MIN_INTERVAL_S) is never approached at the rate they are spent (at most a
few in an outage's first minutes, then one per interval).

SIGN ONCE (Signer). Every signature this node makes, its own proposal or a co-signature, is under a sequence
first RESERVED on its own TPM NV counter (node.json's nv_signing, separate from the heartbeat counter: a node's
co-signature must not make the heartbeat a replay to itself). The counter only goes up, so no node ever signs two
bodies under one number, and two different heartbeats with one sequence would need four distinct signers; even
then each node accepts only the first one above its own heartbeat counter.
"""
import random
import time

from deploy.baremetal import heartbeat, membership

Refused, require = membership.Refused, membership.require

BEAT_INTERVAL_S = 900          # #69: a heartbeat every 15 minutes, living 6 h (the manifest's bound)
TAKEOVER_S = 120               # the next rank's delay after a missed beat, at BEAT_INTERVAL_S (scaled with the interval)
JITTER_S = 30
ISSUE_SKEW_S = 300             # a proposal's issued_at against the co-signer's authenticated time
RETRY_FIRST_S = 60


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def counting_nodes(manifest):
    """The node IDs whose signature counts toward heartbeat_signers under `manifest`, sorted: the proposers' order."""
    require(manifest.get("schema") == membership.SCHEMA_V4, "heartbeats are signed by the nodes only under a %s manifest" % membership.SCHEMA_V4)
    nodes = membership.validate(manifest)
    return sorted(p for p in manifest["heartbeat_signers"]["parties"]
                  if p != membership.OWNER and p in nodes and "signing_key" in nodes[p] and nodes[p]["state"] not in membership.NOT_COUNTING)


def held_sequence(freshness, manifest):
    """The sequence of the heartbeat this node holds if it is for `manifest`, else None."""
    held = freshness.held()
    if held is None:
        return None
    try:
        return heartbeat.verify(held, manifest)["sequence"]
    except Refused:
        return None


class Signer:
    """This node's signature over a heartbeat body: the sequence is reserved on the signing counter first.
    `counter` is a heartbeat.Counter on nv_signing; `sign(message)` returns r || s hex (signkey.sign); `key` is this
    node's signing_key point (hex), checked against the manifest before any number is reserved."""

    def __init__(self, node_id, counter, sign, key):
        self.node_id, self.counter, self._sign, self.key = node_id, counter, sign, key

    def signed(self):
        """The highest sequence this node has signed (the counter)."""
        return self.counter.value()

    def __call__(self, body, manifest):
        nodes = membership.validate(manifest)
        require(self.node_id in nodes and nodes[self.node_id].get("signing_key", {}).get("key") == self.key,
                "this node's signing key is not the one the manifest at epoch %d gives %s: nothing is signed" % (manifest["epoch"], self.node_id))
        held = self.counter.value()
        require(body["sequence"] > held, "sequence %d is not above this node's signing counter %d: a number is signed once"
                % (body["sequence"], held))
        # reserved BEFORE the signature exists: a crash after this loses the number, never signs it twice
        self.counter.advance(body["sequence"], heartbeat.MAX_ALLOWANCE)
        return {"party": self.node_id, "key": self.key, "sig": self._sign(heartbeat.DOMAIN + membership.canonical(body))}


def _now(clock):
    seconds, authenticated = clock()
    require(authenticated is True, "time is not authenticated: no heartbeat is signed")
    return int(seconds)


def cosign(manifest, me, caller, body, signature, freshness, clock, signer):
    """This node's signature over `body`, proposed by `caller` (the node the tunnel identified) with `signature`, or
    Refused. `manifest` is this node's current one; `freshness` its heartbeat.Freshness; `clock()` its authenticated
    clock ((seconds, authenticated)); `signer` its Signer."""
    order = counting_nodes(manifest)
    require(me in order, "%s does not count toward heartbeat_signers under epoch %d: it co-signs nothing" % (me, manifest["epoch"]))
    require(caller in order, "%s does not count toward heartbeat_signers under epoch %d" % (caller, manifest["epoch"]))
    issued, expires = heartbeat.validate(body)
    require(body["epoch"] == manifest["epoch"] and body["manifest_digest"] == membership.digest(manifest),
            "the proposal is for another manifest (epoch %d, %s...), this node's is epoch %d (%s...)"
            % (body["epoch"], body["manifest_digest"][:16], manifest["epoch"], membership.digest(manifest)[:16]))
    require(expires - issued <= heartbeat.max_lifetime(manifest), "the proposal lives %d s, more than the manifest's %d s"
            % (expires - issued, heartbeat.max_lifetime(manifest)))
    now = _now(clock)
    require(abs(issued - now) <= ISSUE_SKEW_S, "the proposal is issued at %s, %d s from this node's authenticated time"
            % (body["issued_at"], issued - now))
    require(isinstance(signature, dict) and signature.get("party") == caller, "the proposal is not signed by %s, who sent it" % caller)
    parties = membership.counting_parties(manifest, heartbeat.DOMAIN + membership.canonical(body), [signature], "proposal")
    require(parties == {caller}, "the proposer's signature does not count")
    # never sign what this node would itself refuse to accept (Freshness._accept's bound)
    held = freshness.counter.value()
    require(body["sequence"] > held, "REPLAY: sequence %d is not above this node's heartbeat counter %d" % (body["sequence"], held))
    allowance = heartbeat.allowed_jump(body, freshness.held(), freshness.counter.MAX_JUMP)
    require(body["sequence"] - held <= allowance, "sequence jump %d exceeds the bound %d" % (body["sequence"] - held, allowance))
    return signer(body, manifest)


class Proposer:
    """One node's turn at proposing. `manifest()` returns the current manifest; `freshness` its heartbeat.Freshness;
    `clock()` its authenticated clock; `signer` its Signer; `ask(peer, body, signature)` returns that peer's
    signature or raises Refused (sync.Client.beat_sign); `trail(event)` records each attempt."""

    def __init__(self, node_id, manifest, freshness, clock, signer, ask, trail, interval=BEAT_INTERVAL_S, rand=random.random):
        self.node_id, self.manifest, self.freshness, self.clock, self.signer = node_id, manifest, freshness, clock, signer
        self.ask, self.trail, self.interval, self.rand = ask, trail, interval, rand
        self.failures, self.not_before, self.jitter = 0, 0, None
        # when this proposer first saw a manifest it holds no heartbeat for: (digest, seconds). The ranks' turns are
        # counted from there, so the next rank takes over a turn the first one misses (not from `now`, which would
        # put every rank but the first a takeover ahead forever)
        self.first_seen = None

    def scaled(self, seconds):
        """`seconds` at the production interval, for this proposer's interval (at least 1)."""
        return max(1, seconds * self.interval // BEAT_INTERVAL_S)

    def due(self, manifest, now):
        """When this node should propose next (seconds), or None if it never does under `manifest`."""
        order = counting_nodes(manifest)
        if self.node_id not in order:
            return None
        if self.jitter is None:
            self.jitter = int(self.rand() * self.scaled(JITTER_S))
        rank = order.index(self.node_id)
        held = self.freshness.held()
        digest = membership.digest(manifest)
        if self.first_seen is None or self.first_seen[0] != digest:
            self.first_seen = (digest, now)
        base = self.first_seen[1] - self.interval       # nothing held for this manifest: go at once, by rank, from then
        try:
            body = heartbeat.verify(held, manifest) if held is not None else None
        except Refused:
            body = None
        if body is not None:
            base = heartbeat.parse_time(body["issued_at"], "issued_at")
        return max(base + self.interval + rank * self.scaled(TAKEOVER_S) + self.jitter, self.not_before)

    def step(self):
        """Propose if it is this node's turn. Returns the accepted envelope, or None."""
        manifest = self.manifest()
        now = _now(self.clock)
        when = self.due(manifest, now)
        if when is None or now < when:
            return None
        self.jitter = None                              # a new draw for the next turn
        try:
            envelope = self.propose(manifest, now)
        except Refused as refused:
            self.failures += 1
            self.not_before = now + min(self.scaled(RETRY_FIRST_S) * 2 ** (self.failures - 1), self.interval)
            self.trail({"event": "beat-propose", "outcome": "DENY", "epoch": manifest["epoch"], "reason": str(refused)[:240]})
            return None
        self.failures, self.not_before = 0, 0
        return envelope

    def propose(self, manifest, now):
        held = held_sequence(self.freshness, manifest)
        sequence = max(held or 0, self.freshness.counter.value(), self.signer.signed()) + 1
        lifetime = heartbeat.max_lifetime(manifest)
        body = {"schema": heartbeat.SCHEMA, "epoch": manifest["epoch"], "sequence": sequence, "issued_at": stamp(now),
                "expires_at": stamp(now + lifetime), "manifest_digest": membership.digest(manifest)}
        mine = self.signer(body, manifest)
        refusals = []
        for peer in [n for n in counting_nodes(manifest) if n != self.node_id]:
            try:
                theirs = self.ask(peer, body, mine)
                envelope = {"heartbeat": body, "signatures": [mine, theirs]}
                heartbeat.verify(envelope, manifest)
            except Refused as refused:
                refusals.append("%s: %s" % (peer, refused))
                continue
            self.freshness.accept(envelope, manifest)
            self.trail({"event": "beat-propose", "outcome": "ALLOW", "epoch": manifest["epoch"], "sequence": sequence,
                        "cosigner": peer, "expires_at": body["expires_at"]})
            return envelope
        raise Refused("no node co-signed sequence %d (%s)" % (sequence, "; ".join(refusals) or "no other node counts"))
