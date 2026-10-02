#!/usr/bin/env python3
"""Convergence: how a revoking manifest reaches every peer, and what each peer decides meanwhile
(#69, Phase 9 of #59; THREE-SITE-THREAT-MODEL.md, attacker cases 1 and 4).

Revocation is not instant and is not claimed to be. This module is the rule by which the nodes come to
hold the same manifest, without a transport of its own (that is #80): it defines what two nodes exchange
and what a node does with what it receives. Three rules.

  1  EVERY EXCHANGE CARRIES A SUMMARY: the sender's (epoch, manifest_digest). compare() tells the receiver
     where it stands. The sender is ahead: the receiver is BEHIND and decides nothing until it has fetched
     the envelopes it lacks and applied them, in order, through membership.Store (catch_up). The sender
     is behind: the receiver decides by its own, newer manifest, and can hand over what the sender lacks
     (missing). The same epoch with another digest, or a digest that is not the one the receiver's chain
     has at that epoch, is a CONFLICT: two manifests were signed for one epoch. Nothing is applied and an
     incident is raised. Peers already talk at every lease renewal, so two connected peers converge
     within one renewal, or one renewal per 1000 epochs the receiver is behind (MAX_ENVELOPES a message).
  2  THE HEARTBEAT FORCES IT. A heartbeat is for one manifest. After a revoking manifest the authority
     issues heartbeats for the new one only, so a peer that is behind cannot take them, and the one it
     holds runs out. The authority ships a BUNDLE, the envelopes and the heartbeat together; apply_bundle
     commits the manifests, then accepts the heartbeat for the manifest it now holds.
  3  A PEER THAT HEARS NOTHING STOPS BY ITSELF: its heartbeat expires (heartbeat.py), and from then it
     authorizes no unlock and issues no lease.

THE BOUNDS, for a node revoked as stolen:
  * a peer that holds the revoking manifest refuses it at once (unlock, lease issue, lease verify, and
    whatever it signs as an issuer);
  * peers that reach each other converge within one exchange between them (one per 1000 epochs behind);
  * a peer cut off from everyone goes on helping until its heartbeat expires: at most 24 hours and 5
    minutes after it accepted its last heartbeat (a heartbeat lives 24 hours from its issue time, and one
    issued up to 5 minutes ahead of the peer's clock is accepted: heartbeat.FUTURE_SKEW), or less if the
    authority issues shorter-lived heartbeats. exposure() is that number for a peer, now;
  * a stolen node that was running stops 300 s after its issuing peers hold the manifest (lease.py).

Nothing here weakens a check: every envelope goes through Store.commit (signature, chain, tombstones, the
TPM anchor) and every heartbeat through Freshness.accept (signer, manifest, time, the TPM counter).

audited(sink, ...) runs one decision and emits one event for it, allowed or denied, naming the epoch: the
record #69 asks for. A reason is cut to printable ASCII; none of the decisions puts a secret in one.
"""
from deploy.baremetal import lease, membership

Refused, require = membership.Refused, membership.require

MAX_ENVELOPES = 1000   # per message: a node further behind catches up in several exchanges
NOT_ENROLLED = {"epoch": 0, "manifest_digest": ""}


def validate_summary(summary):
    membership.exact(summary, ("epoch", "manifest_digest"), "summary")
    epoch = summary["epoch"]
    require(isinstance(epoch, int) and not isinstance(epoch, bool) and 0 <= epoch < 2 ** 63, "summary.epoch must be an integer >= 0")
    if epoch == 0:
        require(summary["manifest_digest"] == "", "a node with no manifest has no digest")
    else:
        membership.hex_field(summary["manifest_digest"], 64, "summary.manifest_digest")
    return summary


def summary(store):
    """What this node holds: the epoch and digest of its current manifest (epoch 0 before enrollment)."""
    manifest = store.load()
    if manifest is None:
        return dict(NOT_ENROLLED)
    return {"epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest)}


def compare(store, theirs):
    """Where this node stands against a peer's summary: "same", "behind" (fetch from the peer before
    deciding anything) or "ahead" (decide by our manifest; the peer needs missing(store, theirs)).
    Raises Refused("CONFLICT ...") when the two chains cannot both be right."""
    validate_summary(theirs)
    mine = summary(store)
    if theirs["epoch"] > mine["epoch"]:
        return "behind"
    if theirs["epoch"] == 0:
        return "same" if mine["epoch"] == 0 else "ahead"
    at_their_epoch = membership.digest(store.envelopes(theirs["epoch"] - 1)[0]["manifest"])
    require(at_their_epoch == theirs["manifest_digest"], "CONFLICT: the peer holds a different manifest at epoch %d: "
            "two manifests were signed for one epoch; record an incident" % theirs["epoch"])
    return "same" if theirs["epoch"] == mine["epoch"] else "ahead"


def missing(store, theirs, limit=MAX_ENVELOPES):
    """The envelopes a peer with summary `theirs` lacks, in order, at most `limit` of them: a peer further
    behind than that asks again from where it then stands. Refused on a CONFLICT."""
    require(isinstance(limit, int) and not isinstance(limit, bool) and 1 <= limit <= MAX_ENVELOPES, "limit must be 1 to %d" % MAX_ENVELOPES)
    standing = compare(store, theirs)
    require(standing != "behind", "this node is behind the peer (epoch %d): it has nothing to offer it" % theirs["epoch"])
    return store.envelopes(theirs["epoch"])[:limit]


def catch_up(store, envelopes):
    """Apply envelopes received from a peer or the authority, in order, through the store. An envelope for
    an epoch this node already holds is verified like any other (its signature, against the manifest
    before it) and must then be the same manifest; a different one is a CONFLICT. Each accepted manifest
    is durable and anchored before the next is looked at, so a refusal part-way leaves the node at the
    last good epoch. Returns the summary afterwards."""
    require(isinstance(envelopes, list) and len(envelopes) <= MAX_ENVELOPES, "at most %d envelopes at a time" % MAX_ENVELOPES)
    current = store.load()
    for envelope in envelopes:
        require(isinstance(envelope, dict) and isinstance(envelope.get("manifest"), dict), "an envelope must hold a manifest")
        epoch = envelope["manifest"].get("epoch")
        held = current["epoch"] if current else 0
        if isinstance(epoch, int) and not isinstance(epoch, bool) and 1 <= epoch <= held:
            around = store.envelopes(max(epoch - 2, 0))          # the manifest before it (if any), and the one held at that epoch
            before, mine = (None, around[0]) if epoch == 1 else (around[0]["manifest"], around[1])
            # authentic AND authorized, whoever resent it: the same transition rules as when it was first
            # accepted (a revocation key cannot have signed what only the root may)
            received = membership.accept(before, envelope, store.root_key)
            require(membership.digest(received) == membership.digest(mine["manifest"]),
                    "CONFLICT: a different manifest at epoch %d: two manifests were signed for one epoch; record an incident" % epoch)
            continue
        current = store.commit(envelope)
    return summary(store)


def recover(store, envelopes):
    """A node whose store refuses with ROLLBACK (its disk is older than its TPM anchor) fetches a peer's
    whole chain, peer_store.envelopes(), and installs it through Store.restore. Returns the summary."""
    store.restore(envelopes)
    return summary(store)


def bundle(store, theirs, heartbeat_envelope, limit=MAX_ENVELOPES):
    """What the authority, or a peer passing it on, sends a node with summary `theirs`: up to `limit`
    envelopes, and the heartbeat only if they bring the node to this store's current manifest (a heartbeat
    is for one manifest; a node still on the way gets None and asks again)."""
    envelopes = missing(store, theirs, limit)
    reaches_tip = theirs["epoch"] + len(envelopes) == summary(store)["epoch"]
    return {"envelopes": envelopes, "heartbeat": heartbeat_envelope if reaches_tip else None}


def apply_bundle(store, freshness, received):
    """Manifests first, then the heartbeat for the manifest this node now holds. Returns (summary, seconds
    of freshness), or (summary, None) for a bundle without a heartbeat (the node is still catching up:
    it asks again). A heartbeat for an epoch the bundle did not bring is refused by Freshness.accept."""
    membership.exact(received, ("envelopes", "heartbeat"), "bundle")
    now_at = catch_up(store, received["envelopes"])
    if received["heartbeat"] is None:
        return now_at, None
    require(now_at["epoch"] >= 1, "a heartbeat cannot be taken before the first manifest")
    return now_at, freshness.accept(received["heartbeat"], store.load())


def exposure(store, freshness, running=False):
    """For how many more seconds a node this peer's manifest still trusts could go on being helped by it, if
    the peer heard nothing from now on: the life left in its heartbeat (0 once it issues nothing more).
    For a node that is already `running`, one lease lifetime is added, ALWAYS: a lease this peer issued a
    moment before it stopped is still good for up to that long, whatever the peer holds now. An upper
    bound, not a measurement of any one lease."""
    try:
        left = freshness.check(store.load())
    except Refused:
        left = 0
    return left + (lease.MAX_LIFETIME if running else 0)


def _printable(text):
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:240]


def audited(sink, kind, manifest, subject, peer, decide):
    """Run `decide()` (it returns, or raises Refused) and hand `sink` one event for it. The event names the
    decision, the epoch and digest it was made under, who it was about and who made it, ALLOW or DENY,
    and for a denial the reason. The result or the refusal is passed on unchanged."""
    event = {"event": _printable(kind), "epoch": manifest["epoch"] if manifest else 0,
             "manifest_digest": membership.digest(manifest) if manifest else "", "subject": _printable(subject), "peer": _printable(peer)}
    try:
        result = decide()
    except Refused as refusal:
        sink(dict(event, outcome="DENY", reason=_printable(refusal)))
        raise
    sink(dict(event, outcome="ALLOW", reason=""))
    return result
