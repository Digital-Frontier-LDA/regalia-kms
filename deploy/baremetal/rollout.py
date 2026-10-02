#!/usr/bin/env python3
"""The two decisions a rolling update asks for (#75, Phase 15 of #59).

An update rolls a new boot image through three nodes under three measurement documents
(measurements.py): CURRENT, then CURRENT + NEXT, then NEXT. Peers refuse a node whose image the
document does not list, so two things can go wrong by doing a right step at the wrong time:

  * rebooting a node when nobody is left to unlock it, or more than one node at once;
  * retiring CURRENT while a node still runs it.

may_reboot(...)    asked ON the node, before it reboots into NEXT. Refused unless
    1  the node is ACTIVE under the manifest: it will be unlocked again, and it holds runtime leases
       now. (A node in MAINTENANCE serves nothing and holds no lease: it is rebooted by hand, and
       the rollout does not wait for this function to say so.)
    2  A ROLLOUT IS UNDER WAY FOR IT: the document the manifest commits to lists two sets for this
       node, and the node says it is NOT yet running the second (its target). A node already on its
       target has nothing to reboot for;
    3  IT IS THIS NODE'S TURN. Nodes update in the order of their node IDs. Every node before this
       one must have been verified ON ITS TARGET, under this manifest epoch, BY THIS NODE'S OWN
       verifier (the record attest.py keeps each time this node re-attests a peer for a lease or an
       unlock). With 2 and 3 together exactly one node can pass at a time: the first one, in order,
       that is not on its target, and only once everybody before it has been seen back;
    4  every other node that may authorize has vouched for this node IN ITS CURRENT BOOT, within the
       lease lifetime: a runtime lease (lease.py) issued to this node, for this boot session, by that
       peer, under this same manifest epoch, still valid at the node's authenticated time. A lease is
       signed by the peer's TPM and is only issued by a peer that is ACTIVE with a live heartbeat and
       has just re-attested the node, so it is evidence that the peer could authorize minutes ago,
       under the same manifest and the same measurements, AND that the peer's record of this node is
       of this boot. That last part is what makes "one at a time" hold when a node has fallen back: a
       lease from before the fallback is for another boot session and is refused, and a fresh one
       means the peers have seen the fallback, so the node after it waits.

  There is no "skip". A node that is down, and must not hold the others up, is taken out by a signed
  manifest that leaves it nothing to do (QUARANTINED: a revocation key can sign that): it is then
  neither waited for nor counted on, and that decision is authenticated like every other.

retire_ready(...)  asked by the root's operator, before signing the document that drops CURRENT.
    The state of EVERY node that may authorize must be given: a file left out could be the one that
    saw a node fall back. Refused unless, for every node that may be unlocked or serve, every peer
    that has seen that node under this epoch last saw it on its target, and at least one did. A node
    that booted NEXT and fell back is behind for whoever saw it last. Only the state of nodes that
    may authorize is taken, and a node's own state says nothing about itself. The input is the
    peers' attestation state files as the operator collected them: unsigned, so this is a guard
    against retiring too early by mistake, not a security boundary. The boundary is the peers:
    whatever is signed, a peer still refuses an image its document does not list. Retiring early
    locks a lagging node out; it never lets a wrong image in.

LIMITS, stated:
  * may_reboot is a local check on the node about to reboot, on that node's own word for what it
    runs and its own verifier's record of the others. An operator who reboots without asking is not
    stopped by it, and a node that lies to itself is not either.
  * A lease proves the peer could authorize up to five minutes ago, not that it still can when this
    node comes back. One remaining authorizer is accepted when the manifest leaves only one.
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


def last_seen(state, manifest, node_id):
    """What one verifier's state (attest.py's state file, parsed) records for `node_id` under THIS
    manifest epoch: the label of the set it was last verified on, or None (never seen, seen under
    another epoch, or not a record). Types are exact: an epoch of 2.0 or True is not epoch 2."""
    nodes = state.get("nodes") if isinstance(state, dict) else None
    record = nodes.get(node_id) if isinstance(nodes, dict) else None
    last = record.get("measurement") if isinstance(record, dict) else None
    if not isinstance(last, dict) or type(last.get("epoch")) is not int or not isinstance(last.get("label"), str):
        return None
    return last["label"] if last["epoch"] == manifest["epoch"] else None


def seen_on_target(state, manifest, document, node_id):
    """Whether that verifier last saw `node_id` on its target set under this epoch. (yes, what it says)."""
    want, label = measurements.target(document, node_id)["label"], last_seen(state, manifest, node_id)
    if label == want:
        return True, "on %s at epoch %d" % (want, manifest["epoch"])
    if label is None:
        return False, "not verified under epoch %d" % manifest["epoch"]
    return False, "last verified on %r at epoch %d, not on %s" % (label, manifest["epoch"], want)


def may_reboot(manifest, document, node_id, running, session_id, own_state, leases, now, run=subprocess.run):
    """Whether `node_id` may reboot into its target image now. `running` is the label of the set this
    node is running and `session_id` its current boot session (64 hex); `own_state` is this node's
    attest.py state (parsed); `leases` are runtime-lease envelopes this node holds, one per peer; `now`
    is its authenticated time (heartbeat.authenticated_now). Returns {"target": label, "authorizers": [...], "seconds": the
    shortest lease's time left}, or raises Refused with the reason."""
    sets = measurements.bind(manifest, document)
    nodes = membership.validate(manifest)
    require(node_id in nodes and nodes[node_id]["state"] == "ACTIVE",
            "%s is %s under epoch %d: only an ACTIVE node is rebooted by the rollout (it must be unlocked again, and it holds "
            "runtime leases now)" % (node_id, nodes[node_id]["state"] if node_id in nodes else "not listed", manifest["epoch"]))
    # 2. a rollout, and something to reboot for
    accepted = sets[node_id]["accepted"]
    require(len(accepted) == 2, "no update is approved for %s: the measurements list one set (%s). A reboot now would not be "
            "part of a rollout, and nothing here orders it" % (node_id, accepted[-1]["label"]))
    target = accepted[-1]["label"]
    require(isinstance(running, str) and running in [s["label"] for s in accepted],
            "%s says it runs %r, which is neither of its accepted sets (%s)" % (node_id, running, ", ".join(s["label"] for s in accepted)))
    require(running != target, "%s is already on its target (%s): nothing to reboot for" % (node_id, target))
    membership.hex_field(session_id, 64, "session_id")
    # 3. the turn
    order = attesting(manifest)
    for earlier in order[:order.index(node_id)]:
        yes, said = seen_on_target(own_state, manifest, document, earlier)
        require(yes, "WAIT: it is not %s's turn. %s updates first and this node has not seen it back on its target (%s). "
                "One node at a time" % (node_id, earlier, said))
    # 4. the peers that will have to unlock this node
    authorizers = [n for n in sorted(nodes) if n != node_id and membership.may(manifest, n, "authorize")]
    require(authorizers, "no other node may authorize under epoch %d: nobody would unlock %s" % (manifest["epoch"], node_id))
    left, reasons = {}, {}
    for envelope in leases:
        body = envelope.get("lease") if isinstance(envelope, dict) else None
        issuer = body.get("issuer") if isinstance(body, dict) else None
        issuer = issuer if isinstance(issuer, str) else None       # anything else is not a name, and not a dict key
        try:
            seconds = lease.verify(envelope, manifest, now, run=run)
        except Refused as refusal:
            if issuer is not None:
                reasons[issuer] = str(refusal)
            continue
        if body["node_id"] != node_id:
            reasons[issuer] = "its lease is for %s" % body["node_id"]
        elif body["session_id"] != session_id:
            reasons[issuer] = "its lease is for another boot session of %s: that peer has not seen this boot" % node_id
        elif body["epoch"] != manifest["epoch"]:
            reasons[issuer] = "its lease is from epoch %d: that peer has not accepted epoch %d" % (body["epoch"], manifest["epoch"])
        else:
            left[issuer] = max(seconds, left.get(issuer, 0))
    missing = [n for n in authorizers if n not in left]
    require(not missing, "WAIT: no valid lease from %s. A peer that cannot vouch for this node now may not be able to "
            "unlock it after the reboot" % "; ".join("%s (%s)" % (n, reasons.get(n, "none presented")) for n in missing))
    return {"target": target, "authorizers": authorizers, "seconds": min(left[n] for n in authorizers)}


def retire_ready(manifest, document, states):
    """Whether CURRENT may be retired. `states` maps a peer's node ID to its attest.py state (parsed).
    Returns {node_id: [the peers that last saw it on its target]}, or raises Refused naming every node
    that is not there, and who says so."""
    measurements.bind(manifest, document)
    nodes = membership.validate(manifest)
    require(isinstance(states, dict) and states, "no verifier state was given")
    unknown = sorted(set(states) - set(nodes))
    require(not unknown, "state from nodes the manifest does not list: %s" % ", ".join(unknown))
    silent = sorted(p for p in states if not membership.may(manifest, p, "authorize"))
    require(not silent, "state from nodes that may not authorize under epoch %d: %s. Only a peer that judges unlocks is a witness"
            % (manifest["epoch"], ", ".join(silent)))
    absent = sorted(n for n in nodes if membership.may(manifest, n, "authorize") and n not in states)
    require(not absent, "the state of %s is missing. Every node that may authorize is a witness: the file left out could be "
            "the one that saw a node fall back" % ", ".join(absent))
    seen, behind = {}, []
    for node_id in attesting(manifest):
        want = measurements.target(document, node_id)["label"]
        said = {peer: last_seen(states[peer], manifest, node_id) for peer in sorted(states) if peer != node_id}
        said = {peer: label for peer, label in said.items() if label is not None}
        wrong = ["%s last saw it on %r" % (peer, label) for peer, label in said.items() if label != want]
        if not said:
            behind.append("%s (no other node has verified it under epoch %d)" % (node_id, manifest["epoch"]))
        elif wrong:
            behind.append("%s (%s, not on %s)" % (node_id, "; ".join(wrong), want))
        else:
            seen[node_id] = sorted(said)
    require(not behind, "NOT YET: retiring now would lock out %s. Every node must be on its target for every peer that has "
            "seen it" % "; ".join(behind))
    return seen
