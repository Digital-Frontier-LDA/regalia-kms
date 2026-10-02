#!/usr/bin/env python3
"""The two decisions a rolling update asks for (#75, Phase 15 of #59).

An update rolls a new boot image through three nodes under three measurement documents
(measurements.py): CURRENT, then CURRENT + NEXT, then NEXT. Peers refuse a node whose image the
document does not list, so two things can go wrong by doing a right step at the wrong time:

  * rebooting a node when nobody is left to unlock it, or all nodes at once;
  * retiring CURRENT while a node still runs it.

may_reboot(...)    asked ON the node, before it reboots into NEXT. Refused unless
    1  the node may be unlocked again under the manifest (ACTIVE or MAINTENANCE);
    2  the document the manifest commits to lists a target for it (NEXT is approved);
    3  IT IS THIS NODE'S TURN. Nodes update in the order of their node IDs. Every node before this
       one must have been verified ON ITS TARGET, under this manifest epoch, BY THIS NODE'S OWN
       verifier (the record attest.py keeps each time this node re-attests a peer for a lease or an
       unlock). So the first node needs no one, the second waits until it has itself seen the first
       back on NEXT, and so on: two nodes are never down for the update at once, and three cannot
       all reboot together, whatever starts them;
    4  every other node that may authorize has vouched for this node within the lease lifetime: a
       runtime lease (lease.py) issued to this node, by that peer, under this same manifest epoch,
       still valid at the node's authenticated time. A lease is signed by the peer's TPM and is only
       issued by a peer that is ACTIVE with a live heartbeat, so it is evidence the peer was able to
       authorize minutes ago, under the same manifest and therefore the same measurements.
  `skip` names nodes the operator has taken out of the rollout (down for repair): they are neither
  waited for nor counted on. At least one authorizer must remain; a node is never its own.

retire_ready(...)  asked by the root's operator, before signing the document that drops CURRENT.
    Refused unless every node that may be unlocked or serve has been verified on its target, under
    the current epoch, by at least one OTHER node's verifier. Its input is the peers' attestation
    state files, as collected by the operator: unsigned, so this is a guard against retiring too
    early by mistake, not a security boundary. The boundary is the peers: whatever is signed, a peer
    still refuses an image its document does not list. Retiring early locks a lagging node out; it
    never lets a wrong image in.

LIMITS, stated:
  * may_reboot is a local check on the node about to reboot. An operator who reboots without asking
    is not stopped by it.
  * A lease proves the peer could authorize up to five minutes ago, not that it still can when this
    node comes back.
  * Nothing here reboots, installs an image or signs a manifest, and nothing is wired into a
    service yet. Boot counting and the automatic fallback to CURRENT are systemd-boot's, on the real
    hosts.
"""
import subprocess

from deploy.baremetal import lease, measurements, membership

Refused, require = membership.Refused, membership.require


def attesting(manifest):
    """The nodes a rollout concerns, in update order: those that may be unlocked or serve."""
    nodes = membership.validate(manifest)
    return sorted(n for n, node in nodes.items() if membership.CAPABILITIES[node["state"]] & {"request", "serve"})


def seen_on_target(state, manifest, document, node_id):
    """Whether one verifier's state (attest.py's state file, parsed) records `node_id` on its target
    set under this manifest epoch. Returns (yes, what the record says)."""
    want = {"label": measurements.target(document, node_id)["label"], "epoch": manifest["epoch"]}
    nodes = state.get("nodes") if isinstance(state, dict) else None
    record = nodes.get(node_id) if isinstance(nodes, dict) else None
    last = record.get("measurement") if isinstance(record, dict) else None
    if last == want:
        return True, "on %s at epoch %d" % (want["label"], want["epoch"])
    if not isinstance(last, dict):
        return False, "never verified"
    return False, "last verified on %r at epoch %r, not on %s at epoch %d" % (
        last.get("label"), last.get("epoch"), want["label"], want["epoch"])


def may_reboot(manifest, document, node_id, own_state, leases, now, skip=(), run=subprocess.run):
    """Whether `node_id` may reboot into its target image now. `own_state` is this node's attest.py
    state (parsed); `leases` are runtime-lease envelopes this node holds, one per peer; `now` is its
    authenticated time (heartbeat.authenticated_now). Returns {"authorizers": [...], "seconds": the
    shortest lease's time left}, or raises Refused with the reason."""
    measurements.bind(manifest, document)
    require(membership.may(manifest, node_id, "request"), "%s may not be unlocked under epoch %d: it would not come back"
            % (node_id, manifest["epoch"]))
    measurements.target(document, node_id)
    order = attesting(manifest)
    skip = set(skip)
    require(node_id not in skip, "%s cannot be skipped and rebooted" % node_id)
    require(skip <= set(order), "skip names nodes that are not in the rollout: %s" % ", ".join(sorted(skip - set(order))))
    # 3. the turn
    for earlier in order[:order.index(node_id)]:
        if earlier in skip:
            continue
        yes, said = seen_on_target(own_state, manifest, document, earlier)
        require(yes, "WAIT: it is not %s's turn. %s updates first and this node has %s. One node at a time"
                % (node_id, earlier, "not seen it back on its target (%s)" % said))
    # 4. the peers that will have to unlock this node
    authorizers = [n for n in sorted(membership.validate(manifest)) if n != node_id and n not in skip
                   and membership.may(manifest, n, "authorize")]
    require(authorizers, "no other node may authorize under epoch %d: nobody would unlock %s" % (manifest["epoch"], node_id))
    left, reasons = {}, {}
    for envelope in leases:
        try:
            seconds = lease.verify(envelope, manifest, now, run=run)
        except Refused as refusal:
            issuer = envelope.get("lease", {}).get("issuer") if isinstance(envelope, dict) and isinstance(envelope.get("lease"), dict) else None
            reasons[issuer] = str(refusal)
            continue
        body = envelope["lease"]
        if body["node_id"] != node_id:
            reasons[body["issuer"]] = "its lease is for %s" % body["node_id"]
        elif body["epoch"] != manifest["epoch"]:
            reasons[body["issuer"]] = "its lease is from epoch %d: that peer has not accepted epoch %d" % (body["epoch"], manifest["epoch"])
        else:
            left[body["issuer"]] = max(seconds, left.get(body["issuer"], 0))
    missing = [n for n in authorizers if n not in left]
    require(not missing, "WAIT: no valid lease from %s. A peer that cannot vouch for this node now may not be able to "
            "unlock it after the reboot" % "; ".join("%s (%s)" % (n, reasons.get(n, "none presented")) for n in missing))
    return {"authorizers": authorizers, "seconds": min(left[n] for n in authorizers)}


def retire_ready(manifest, document, states):
    """Whether CURRENT may be retired: every node of the rollout was verified on its target, under this
    epoch, by another node's verifier. `states` maps a peer's node ID to its attest.py state (parsed).
    Returns {node_id: the peer that saw it}, or raises Refused naming every node that is not there."""
    measurements.bind(manifest, document)
    nodes = membership.validate(manifest)
    require(isinstance(states, dict) and states, "no verifier state was given")
    unknown = sorted(set(states) - set(nodes))
    require(not unknown, "state from nodes the manifest does not list: %s" % ", ".join(unknown))
    seen, behind = {}, []
    for node_id in attesting(manifest):
        said = "no other node's state was given"
        for peer_id in sorted(states):
            if peer_id == node_id:
                continue                      # a node does not vouch for itself
            yes, said = seen_on_target(states[peer_id], manifest, document, node_id)
            if yes:
                seen[node_id] = peer_id
                break
        if node_id not in seen:
            behind.append("%s (%s)" % (node_id, said))
    require(not behind, "NOT YET: retiring now would lock out %s. Every node must be seen on its target by a peer first"
            % "; ".join(behind))
    return seen
