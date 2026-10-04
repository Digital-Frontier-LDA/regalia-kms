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
       unlock). With 2 and 3, and every record current, exactly one node can pass at a time: the
       first one, in order, that is not on its target, and only once everybody before it has been
       seen back. (A record is current once this node has re-attested that peer; see LIMITS.);
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

stranded(...)      asked by `propose`, before it prints any manifest whose document takes a set away
    (a retire, an abandon, an emergency). The same witnesses and the same rule as retire_ready, for
    every node that loses a set: last seen UP on a set the new document keeps, by every peer that has
    seen it, and by at least one. Otherwise `propose` refuses (NOT YET). An emergency may lock nodes
    out, but only those it names with --locked-out, exactly: the output says who, and how each comes
    back (an approved image, or its recovery key at the console). Nobody is locked out unnamed.

LIMITS, stated:
  * may_reboot is a local check on the node about to reboot, on that node's own word for what it
    runs and its own verifier's record of the others. An operator who reboots without asking is not
    stopped by it, and a node that lies to itself is not either.
  * A lease proves the peer could authorize up to five minutes ago, not that it still can when this
    node comes back. One remaining authorizer is accepted when the manifest leaves only one.
  * WHAT "ONE AT A TIME" RESTS ON, and where it stops. A peer writes its record of a node BEFORE it
    signs that node a lease (lease.issue re-attests first), and a node has one boot session per boot.
    So a lease for this boot means the ISSUER's record of this node is of this boot: a node that fell
    back cannot pass on leases from before. The turn rule, though, reads THIS node's record of the
    EARLIER node, which is refreshed only when this node next re-attests that one (at its next lease
    renewal, or when it comes back for an unlock). In between, for up to the lease lifetime, this node
    may still believe an earlier node is on its target after it fell back or went down, and pass.
    Two nodes down at once for that long is possible; three are not, since each needs the others'
    fresh leases. `own_state` must be the state file of the verifier this node issues leases with;
    it is an argument, and nothing here can check that it is.
  * Nothing here reboots, installs an image or signs a manifest, and nothing is wired into a
    service yet. Boot counting and the automatic fallback to CURRENT are systemd-boot's, on the real
    hosts.

THE COMMAND (KERNEL-UPDATE.md is the procedure it serves). Every subcommand READS: files, and with
--tpm-index this host's TPM anchor (the epoch counter and the record of the manifest it anchors). None
signs, writes state, reboots or talks to a peer; the only file one may create is the anchor's empty lock
file under /run/lock. One of them, `propose`, prints an UNSIGNED manifest for the root's operator to
check and sign.

    python3 -Es -m deploy.baremetal.rollout version   --measurements NEW.json
    python3 -Es -m deploy.baremetal.rollout transition --old OLD.json --new NEW.json [--emergency] [--dropped NODE]...
    python3 -Es -m deploy.baremetal.rollout epoch     --membership CHAIN.json --root-key HEX [--tpm-index 0x1500016 [--tcti TCTI]]
    python3 -Es -m deploy.baremetal.rollout propose   --membership CHAIN.json --root-key HEX --old OLD.json --new NEW.json
                                                  [--emergency] [--dropped NODE]... [--issued-at YYYY-MM-DDTHH:MM:SSZ]
                                                  [--state NODE=STATE.json]... [--locked-out NODE]...
    python3 -Es -m deploy.baremetal.rollout may-reboot --membership CHAIN.json --root-key HEX --measurements DOC.json
                                                  --node-id ID --running LABEL --session-id HEX
                                                  --attest-state STATE.json --lease LEASE.json... [--now SECONDS]
    python3 -Es -m deploy.baremetal.rollout retire-ready --membership CHAIN.json --root-key HEX --measurements DOC.json
                                                  --state NODE=STATE.json...
    python3 -Es -m deploy.baremetal.rollout check-replacement --membership CHAIN.json --root-key HEX --candidate MANIFEST.json
                                                  --old OLD.json --new NEW.json --old-id ID --new-id ID

CHAIN.json is the node's membership file (the signed chain membership.Store keeps); it is verified from
the root key given, every time. With --tpm-index its epoch must also EQUAL this host's TPM high-water
(the counter is read, never advanced: an older file is a rollback, a newer one has not been accepted by
the node's service yet), and its manifest at that epoch must be the one the TPM recorded (another
root-signed chain of the same length is refused with CONFLICT, as membership.Store.load refuses it; the
record is read, never repaired). Without it the output says the chain was NOT checked against the TPM,
and a restored older file, or a substituted one, would be believed.
The TPM read is the one --tcti names (default device:/dev/tpmrm0, the kernel's resource manager), never
one a TPM2TOOLS_TCTI left in the operator's shell would pick: with --tpm-index that variable is refused,
and the output names the TPM that was read.
Exit status: 0 yes, 1 refused (the reason on standard error, or in the JSON), 2 a usage error.
--json prints one JSON object instead of text.

`may-reboot` takes the time from --now (seconds, from the node's authenticated clock) or, without it,
from the system clock, and then says so: an unauthenticated clock is good enough to tell an operator
"not yet", not to decide that a lease is still valid.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

from deploy.baremetal import attest, lease, measurements, membership

Refused, require = membership.Refused, membership.require


def attesting(manifest):
    """The nodes a rollout concerns, in update order: those that may be unlocked or serve."""
    nodes = membership.validate(manifest)
    return sorted(n for n, node in nodes.items() if membership.CAPABILITIES[node["state"]] & {"request", "serve"})


def _readable(last):
    """A verifier's record of a node's last accepted quote: {"label", "epoch"} and, since the sets can be
    per boot phase, "phase" (None, or one of attest.PHASES). Types are exact."""
    return (isinstance(last, dict) and type(last.get("epoch")) is int and isinstance(last.get("label"), str)
            and (last.get("phase") is None or (isinstance(last["phase"], str) and last["phase"] in attest.PHASES)))


def _last(state, manifest, node_id):
    nodes = state.get("nodes") if isinstance(state, dict) else None
    record = nodes.get(node_id) if isinstance(nodes, dict) else None
    last = record.get("measurement") if isinstance(record, dict) else None
    if not _readable(last) or last["epoch"] != manifest["epoch"]:
        return None
    return last["label"], last.get("phase")


def last_seen(state, manifest, node_id):
    """What one verifier's state (attest.py's state file, parsed) records for `node_id` under THIS
    manifest epoch: the label of the set it was last verified on, or None (never seen, seen under
    another epoch, or not a record). Types are exact: an epoch of 2.0 or True is not epoch 2."""
    last = _last(state, manifest, node_id)
    return last[0] if last else None


def _up(target, phase):
    """Whether a sighting in `phase` shows the node UP on `target`. Where the set is per phase, only a
    quote from the booted system does: a node verified in its initrd asked for its disk, and may never
    have come up. (A record written before the phase was recorded has none, and does not count either.)
    A set with one value per PCR cannot tell the two apart, and any sighting counts, as before."""
    return phase == "system" if "phases" in target else True


def seen_on_target(state, manifest, document, node_id):
    """Whether that verifier last saw `node_id` up on its target set under this epoch. (yes, what it says)."""
    target, last = measurements.target(document, node_id), _last(state, manifest, node_id)
    want = target["label"]
    if last is None:
        return False, "not verified under epoch %d" % manifest["epoch"]
    label, phase = last
    if label != want:
        return False, "last verified on %r at epoch %d, not on %s" % (label, manifest["epoch"], want)
    if not _up(target, phase):
        return False, "last verified in the initrd of %s at epoch %d: it asked for its disk and has not been seen up since" % (want, manifest["epoch"])
    return True, "on %s at epoch %d" % (want, manifest["epoch"])


def may_reboot(manifest, document, node_id, running, session_id, own_state, leases, now, run=subprocess.run):
    """Whether `node_id` may reboot into its target image now. `running` is the label of the set this
    node is running and `session_id` its current boot session (64 hex); `own_state` is this node's
    attest.py state (parsed); `leases` are runtime-lease envelopes this node holds, one per peer; `now`
    is its authenticated time (heartbeat.authenticated_now). Returns {"target": label, "authorizers": [...], "seconds": the
    shortest lease's time left}, or raises Refused with the reason."""
    sets = measurements.bind(manifest, document)
    nodes = membership.validate(manifest)
    require(isinstance(node_id, str), "node_id is text")
    require(isinstance(leases, (list, tuple)), "leases is a list of lease envelopes")
    require(isinstance(now, (int, float)) and not isinstance(now, bool), "now is the node's authenticated time, in seconds")
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


def _witnesses(manifest, states):
    """The checks every peer state file must pass to count as a witness under `manifest` (retire_ready,
    stranded): the state of every node that may authorize, and only theirs, each a verifier's state whose
    records of the nodes of the rollout are readable and not from a later epoch. Raises Refused."""
    nodes = membership.validate(manifest)
    require(isinstance(states, dict) and states and all(isinstance(p, str) for p in states), "no verifier state was given")
    unknown = sorted(set(states) - set(nodes))
    require(not unknown, "state from nodes the manifest does not list: %s" % ", ".join(unknown))
    silent = sorted(p for p in states if not membership.may(manifest, p, "authorize"))
    require(not silent, "state from nodes that may not authorize under epoch %d: %s. Only a peer that judges unlocks is a witness"
            % (manifest["epoch"], ", ".join(silent)))
    absent = sorted(n for n in nodes if membership.may(manifest, n, "authorize") and n not in states)
    require(not absent, "the state of %s is missing. Every node that may authorize is a witness: the file left out could be "
            "the one that saw a node fall back" % ", ".join(absent))
    # ... and a file that was collected empty, or is not a verifier's state at all, is as good as left out
    hollow = sorted(p for p, state in states.items() if not (
        isinstance(state, dict) and state.get("schema") == attest.STATE_SCHEMA and isinstance(state.get("nodes"), dict)))
    require(not hollow, "the state given for %s is not an attestation verifier's state (%s, with its nodes): a failed "
            "collection is not a witness" % (", ".join(hollow), attest.STATE_SCHEMA))
    # A witness's record of a node of the rollout is readable, or it is not a witness. A record with no
    # measurement is an enrolled node not verified yet, and says nothing. One from a LATER epoch means the
    # peer holds a newer manifest than the one being judged: what it saw there is hidden from this check.
    for peer_id in sorted(states):
        for node_id in attesting(manifest):
            record = states[peer_id]["nodes"].get(node_id)
            if record is None:
                continue
            require(isinstance(record, dict), "%s's state has a record of %s that is not a record" % (peer_id, node_id))
            if "measurement" not in record:
                continue
            last = record["measurement"]
            require(_readable(last),
                    "%s's state has an unreadable measurement for %s: it cannot be counted, and it cannot be ignored" % (peer_id, node_id))
            require(last["epoch"] <= manifest["epoch"], "%s last verified %s under epoch %d, later than the manifest given "
                    "(epoch %d): use the current manifest and its document" % (peer_id, node_id, last["epoch"], manifest["epoch"]))


def retire_ready(manifest, document, states):
    """Whether CURRENT may be retired. `states` maps a peer's node ID to its attest.py state (parsed).
    Returns {node_id: [the peers that last saw it on its target]}, or raises Refused naming every node
    that is not there, and who says so."""
    measurements.bind(manifest, document)
    _witnesses(manifest, states)
    seen, behind = {}, []
    for node_id in attesting(manifest):
        target = measurements.target(document, node_id)
        want = target["label"]
        said = {peer: _last(states[peer], manifest, node_id) for peer in sorted(states) if peer != node_id}
        said = {peer: last for peer, last in said.items() if last is not None}
        # on another image, or on the target but only in its initrd: it asked for its disk, and may never have come up
        wrong = ["%s last saw it on %r" % (peer, label) if label != want else "%s last saw it in the initrd of %r, not up" % (peer, label)
                 for peer, (label, phase) in said.items() if label != want or not _up(target, phase)]
        if not said:
            behind.append("%s (no other node has verified it under epoch %d)" % (node_id, manifest["epoch"]))
        elif wrong:
            behind.append("%s (%s, not on %s)" % (node_id, "; ".join(wrong), want))
        else:
            seen[node_id] = sorted(said)
    require(not behind, "NOT YET: retiring now would lock out %s. Every node must be on its target for every peer that has "
            "seen it" % "; ".join(behind))
    return seen


DROPS = ("retire", "abandon", "replace-without-overlap")     # the transitions that take a set away from a node


def stranded(manifest, old, new, states):
    """The nodes the step from document `old` (the one `manifest` commits to) to `new` would lock out:
    {node_id: why}. A node that loses a set must have been last seen UP on a set `new` keeps, by every
    peer that has seen it under this epoch, and by at least one; otherwise it may still be running the
    set that goes, and its peers would refuse its next unlock and lease. For a retire this is
    retire_ready's rule (the kept set is the target); it applies the same way to an abandon (NEXT
    dropped while a node runs it) and to an emergency. `states` are the peers' state files, checked
    as retire_ready checks them. Nodes that leave the document, or are not unlocked and do not serve
    under `manifest`, are not judged here (see unwatched)."""
    measurements.bind(manifest, old)
    _witnesses(manifest, states)
    before, after = measurements.validate(old), measurements.validate(new)
    behind = {}
    for node_id in attesting(manifest):
        if node_id not in before or node_id not in after:
            continue
        kept = {e["label"]: e for e in after[node_id]}
        if not {e["label"] for e in before[node_id]} - set(kept):
            continue
        said = {peer: _last(states[peer], manifest, node_id) for peer in sorted(states) if peer != node_id}
        said = {peer: last for peer, last in said.items() if last is not None}
        wrong = ["%s last saw it on %r" % (peer, label) if label not in kept else "%s last saw it in the initrd of %r, not up" % (peer, label)
                 for peer, (label, phase) in said.items() if label not in kept or not _up(kept[label], phase)]
        if not said:
            behind[node_id] = "no other node has verified it under epoch %d" % manifest["epoch"]
        elif wrong:
            behind[node_id] = "%s, not on %s" % ("; ".join(wrong), " or ".join(sorted(kept)))
    return behind


def unwatched(manifest, old, new):
    """The nodes that lose a set but may neither be unlocked nor serve under `manifest` (QUARANTINED, say):
    no peer re-attests them, so nothing shows what they run. Each will be refused if it comes back on
    the set that goes."""
    before, after = measurements.validate(old), measurements.validate(new)
    watched = set(attesting(manifest))
    return sorted(n for n in set(before) & set(after) if n not in watched
                  and {e["label"] for e in before[n]} - {e["label"] for e in after[n]})

# ---- the command ----

def _read(path, limit=membership.MAX_CHAIN_BYTES):
    with open(path, "rb") as f:
        return f.read(limit + 1)


def _document(path):
    return measurements.load(_read(path, measurements.MAX_BYTES))


def _json(path, label):
    value = membership.load(_read(path, 4 * 1024 * 1024), limit=4 * 1024 * 1024)
    require(isinstance(value, dict), "%s (%s) must hold one JSON object" % (label, path))
    return value


DEFAULT_TCTI = "device:/dev/tpmrm0"
TCTI_PATTERN = r"(?:device|swtpm|mssim|tabrmd)(?::[!-~]{1,200})?"
SIMULATORS = ("swtpm", "mssim")      # accepted (the tests, a lab), and said so in the output


def _current(args):
    """(the current manifest, whether it was checked against this host's TPM high-water)."""
    if args.root_key.startswith(("{", "[")):          # a typed root (#156), as JSON
        args.root_key = json.loads(args.root_key)
    membership.root_entries(args.root_key, "--root-key")
    chain = membership.load(_read(args.membership), limit=membership.MAX_CHAIN_BYTES)
    require(isinstance(chain, list) and chain, "%s must hold a non-empty list of signed manifests" % args.membership)
    manifest, manifests = None, []
    for envelope in chain:
        accepted = membership.accept(manifest, envelope, args.root_key)
        require(accepted is not manifest, "%s repeats epoch %d" % (args.membership, accepted["epoch"]))
        manifests.append(accepted)
        manifest = accepted
    if not args.tpm_index:
        require(args.tcti is None, "--tcti names the TPM --tpm-index reads: give both, or neither")
        return manifest, False
    require(isinstance(args.tpm_index, str) and re.fullmatch(r"0x[0-9a-fA-F]{1,8}", args.tpm_index),
            "--tpm-index must be an NV index as 0x followed by 1 to 8 hex digits, e.g. 0x1500016")
    # The check is run on a peer during a recovery: a TPM2TOOLS_TCTI left in the operator's shell would point
    # it at another TPM (a simulator, another host's socket) and its answer would be believed.
    require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: unset it and name the TPM with --tcti "
            "(default %s)" % DEFAULT_TCTI)
    args.tcti = DEFAULT_TCTI if args.tcti is None else args.tcti
    require(isinstance(args.tcti, str) and re.fullmatch(TCTI_PATTERN, args.tcti),
            "--tcti must be device, swtpm, mssim or tabrmd, optionally followed by :CONFIG (printable, no spaces)")
    # READ the anchor; never advance or repair it. membership.Store.load anchors a verified newer chain
    # and completes a record a crash left behind, and that is the node's own service's to do, not an
    # operator's check.
    anchor = membership.HighWater(args.tpm_index, tcti=args.tcti)
    high_water = anchor.value()
    require(manifest["epoch"] >= high_water, "ROLLBACK: %s is at epoch %d but this host's TPM high-water is %d: the file is older "
            "than what this host has accepted; fetch the chain from a peer" % (args.membership, manifest["epoch"], high_water))
    require(manifest["epoch"] == high_water, "%s is at epoch %d, which this host has not anchored yet (TPM high-water %d): let the "
            "node's service accept it first" % (args.membership, manifest["epoch"], high_water))
    # The counter tells a shorter chain from the anchored one; only the TPM's record of the manifest digest
    # tells two root-signed chains of the SAME length apart (membership.Store.load refuses the other with
    # CONFLICT, and so must this). Both calls take HighWater's lock, which creates its lock file if absent.
    moved = "this host's TPM high-water moved during the check: run it again"

    def digest_of(epoch):
        # the node's service may commit between the two readings: the anchor then asks for an epoch this file lacks
        require(epoch <= len(manifests), moved)
        return membership.digest(manifests[epoch - 1]) if epoch else anchor.ZERO
    require(anchor.verify(digest_of) == high_water, moved)
    # No operator command completes the record: the node's service does, when it loads its membership at start.
    require(anchor.pinned(), "this host's TPM records the manifest at epoch %d, not yet the one at its high-water %d (the node's "
            "service was interrupted while accepting it): restart the node's service, which completes the record when it "
            "loads its membership" % (high_water - 1, high_water))
    return manifest, True


def _tpm(anchored, tcti):
    """What every result says of the TPM it was checked against: whether, which, and whether a simulator."""
    fields = {"checked_against_tpm": anchored}
    if anchored:
        fields["tpm"] = tcti
        if tcti.split(":")[0] in SIMULATORS:
            fields["tpm_is_a_simulator"] = True
    return fields


def _tpm_text(anchored, tcti):
    """The lines a checked result adds (the TPM through %(tpm)s: a TCTI may hold a '%')."""
    if not anchored:
        return ""
    return "\nchecked against the TPM epoch counter of %(tpm)s" + (
        "\nWARNING: that is a TPM SIMULATOR, not this host's TPM: on a KMS host this answer proves nothing"
        if tcti.split(":")[0] in SIMULATORS else "")


def _summary(manifest, anchored, tcti=None):
    return dict({"epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest), "policy_version": manifest["policy_version"],
                 "issued_at": manifest["issued_at"], "nodes": {n["node_id"]: n["state"] for n in manifest["nodes"]}}, **_tpm(anchored, tcti))


def _cmd_version(args):
    document = _document(args.measurements)
    return {"name": document["name"], "policy_version": measurements.version(document),
            "nodes": {n: [e["label"] for e in sets] for n, sets in sorted(measurements.validate(document).items())}}, \
        "%(policy_version)s  (%(name)s)"


def _cmd_transition(args):
    kind = measurements.transition(_document(args.old), _document(args.new), emergency=args.emergency, dropped=args.dropped)
    return {"transition": kind}, "%(transition)s"


def _cmd_epoch(args):
    manifest, anchored = _current(args)
    return _summary(manifest, anchored, args.tcti), "epoch %(epoch)d, measurements %(policy_version)s, manifest %(manifest_digest)s" + (
        _tpm_text(anchored, args.tcti) if anchored else "\nNOT checked against this host's TPM epoch counter (no --tpm-index): a restored older file would read the same")


def _states(items):
    states = {}
    for item in items:
        node_id, sep, path = item.partition("=")
        require(sep and node_id and path, "--state takes NODE=FILE, not %r" % item)
        require(node_id not in states, "--state names %s twice" % node_id)
        states[node_id] = _json(path, "--state %s" % node_id)
    return states


def _cmd_propose(args):
    current, anchored = _current(args)
    old, new = _document(args.old), _document(args.new)
    measurements.bind(current, old)
    kind = measurements.transition(old, new, emergency=args.emergency, dropped=args.dropped)
    require(kind != "unchanged", "the new document changes nothing: there is no manifest to propose")
    states = _states(args.state)
    checked = {}
    if kind not in DROPS:
        require(not states and not args.locked_out, "--state and --locked-out are read only when the new document takes a set "
                "away (%s); this one is: %s" % (", ".join(DROPS), kind))
    else:
        # A node still running the set that goes would be refused at its next unlock and lease, for good: the
        # root's signature cannot be taken back. So the peers' records say first that nobody runs it.
        require(states, "the new document takes a set away (%s): give --state NODE=STATE.json for every node that may authorize, "
                "so that no node still running it is locked out (rollout retire-ready reads the same files)" % kind)
        behind = stranded(current, old, new, states)
        why = "; ".join("%s (%s)" % (n, behind[n]) for n in sorted(behind))
        require(not behind or args.emergency, "NOT YET: this %s would lock out %s. Wait until every node is seen up on a set the new "
                "document keeps, or, if the set that goes must go now, propose it with --emergency and name each node it "
                "locks out with --locked-out" % (kind, why))
        named = set(args.locked_out)
        require(not named - set(behind), "--locked-out names %s, which this document does not lock out"
                % ", ".join(sorted(named - set(behind))))
        require(not set(behind) - named, "this emergency locks out %s: name each with --locked-out, so that the operator who "
                "signs it has said so" % why)
        checked = {"locked_out": sorted(behind), "not_seen": unwatched(current, old, new)}
    issued = args.issued_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    proposal = dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current),
                    policy_version=measurements.version(new), issued_at=issued)
    membership.validate(proposal)
    measurements.bind(proposal, new)
    text = "%(transition)s: UNSIGNED manifest for the root to sign (nothing here signs)\n" + json.dumps(proposal, indent=2, sort_keys=True)
    if checked.get("locked_out"):
        text += ("\nLOCKS OUT %s: once this is signed and delivered, each is refused its next unlock and lease until it boots an "
                 "image the new document approves; one that cannot is opened with its recovery key at the console "
                 "(KERNEL-UPDATE.md, \"If something goes wrong\")" % ", ".join(checked["locked_out"])).replace("%", "%%")
    if checked.get("not_seen"):
        text += ("\nNOT CHECKED: %s neither unlocks nor serves under this epoch, so no peer shows what it runs; it will be "
                 "refused if it comes back on the set that goes" % ", ".join(checked["not_seen"])).replace("%", "%%")
    return dict({"transition": kind, "unsigned_manifest": proposal, "signs_over": "regalia-membership/v1\\0 + canonical JSON of unsigned_manifest",
                 "follows": _summary(current, anchored, args.tcti)}, **checked), text


def _cmd_may_reboot(args):
    manifest, anchored = _current(args)
    leases = [_json(path, "--lease") for path in args.lease]
    authenticated = args.now is not None
    verdict = may_reboot(manifest, _document(args.measurements), args.node_id, args.running, args.session_id,
                         _json(args.attest_state, "--attest-state"), leases, args.now if authenticated else int(time.time()))
    verdict.update(node_id=args.node_id, epoch=manifest["epoch"], time_authenticated=authenticated, **_tpm(anchored, args.tcti))
    return verdict, "YES: %(node_id)s may reboot into %(target)s (vouched for by %(authorizers)s; the shortest lease has %(seconds)d s left)" + (
        "" if authenticated else "\nTIME IS THE SYSTEM CLOCK, not authenticated (no --now): do not act on a lease that is about to expire") + (
        _tpm_text(anchored, args.tcti) if anchored else "\nthe manifest was NOT checked against this host's TPM epoch counter (no --tpm-index)") + (
        "\nWait until this host is back and serving before starting the next one (KERNEL-UPDATE.md, step 3.5)")


def _cmd_retire_ready(args):
    manifest, anchored = _current(args)
    states = _states(args.state)
    seen = retire_ready(manifest, _document(args.measurements), states)
    return dict({"ready": True, "seen_on_target_by": seen, "epoch": manifest["epoch"]}, **_tpm(anchored, args.tcti)), \
        "YES: every node was last seen on its target by every peer that has seen it (epoch %(epoch)d). The state files are " \
        "unsigned: this guards against retiring too early, it is not proof" + _tpm_text(anchored, args.tcti)


def _cmd_check_replacement(args):
    current, anchored = _current(args)
    candidate = _json(args.candidate, "--candidate")
    candidate = candidate.get("manifest", candidate) if set(candidate) == {"manifest", "signature"} else candidate
    measurements.check_replacement(current, candidate, _document(args.old), _document(args.new), args.old_id, args.new_id)
    return dict({"replacement": "%s by %s" % (args.old_id, args.new_id), "epoch": candidate["epoch"], "policy_version": candidate["policy_version"]},
                **_tpm(anchored, args.tcti)), \
        "the candidate replaces %(replacement)s and changes nothing else (epoch %(epoch)d, measurements %(policy_version)s)" + _tpm_text(anchored, args.tcti)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.rollout",
                                     description="The checks of a rolling boot-image update (KERNEL-UPDATE.md). Reads; never signs.")
    parser.add_argument("--json", action="store_true", help="print one JSON object instead of text")
    sub = parser.add_subparsers(dest="command", required=True)

    def chain(c):
        c.add_argument("--membership", required=True, metavar="CHAIN.json", help="this node's membership file (the signed chain)")
        c.add_argument("--root-key", required=True, metavar="HEX", help="the pinned membership root public key (64 hex)")
        c.add_argument("--tpm-index", metavar="0x…", help="also check the chain against this host's TPM epoch counter at this NV index")
        c.add_argument("--tcti", metavar="TCTI",
                       help="the TPM --tpm-index reads (default %s); TPM2TOOLS_TCTI in the environment is refused" % DEFAULT_TCTI)

    def step(c):
        c.add_argument("--emergency", action="store_true", help="allow a compromised image to be dropped with no overlap")
        c.add_argument("--dropped", action="append", default=[], metavar="NODE", help="a node that leaves the document; repeat")

    c = sub.add_parser("version", help="the policy_version a manifest must carry to approve a measurement document")
    c.add_argument("--measurements", required=True)
    c.set_defaults(run=_cmd_version)
    c = sub.add_parser("transition", help="what a new measurement document does to the old one: approve, retire, abandon, …")
    c.add_argument("--old", required=True)
    c.add_argument("--new", required=True)
    step(c)
    c.set_defaults(run=_cmd_transition)
    c = sub.add_parser("epoch", help="the manifest this node holds: its epoch, digest and measurements version")
    chain(c)
    c.set_defaults(run=_cmd_epoch)
    c = sub.add_parser("propose", help="the UNSIGNED next manifest for a new measurement document, for the root to sign")
    chain(c)
    c.add_argument("--old", required=True, help="the document the current manifest commits to")
    c.add_argument("--new", required=True)
    c.add_argument("--issued-at", metavar="YYYY-MM-DDTHH:MM:SSZ")
    c.add_argument("--state", action="append", default=[], metavar="NODE=STATE.json",
                   help="a node's attestation verifier state, one per authorizing node: required when the document takes a set away")
    c.add_argument("--locked-out", action="append", default=[], metavar="NODE",
                   help="with --emergency: a node still running the set that goes, which this manifest locks out; repeat, name each")
    step(c)
    c.set_defaults(run=_cmd_propose)
    c = sub.add_parser("may-reboot", help="may this node reboot into its target image now?")
    chain(c)
    c.add_argument("--measurements", required=True)
    c.add_argument("--node-id", required=True)
    c.add_argument("--running", required=True, metavar="LABEL", help="the set this node is running")
    c.add_argument("--session-id", required=True, metavar="HEX", help="this boot's attested session (64 hex)")
    c.add_argument("--attest-state", required=True, help="this node's attestation verifier state")
    c.add_argument("--lease", action="append", default=[], metavar="LEASE.json", help="a runtime lease this node holds; repeat")
    c.add_argument("--now", type=int, metavar="SECONDS", help="the node's authenticated time; without it the system clock, and the output says so")
    c.set_defaults(run=_cmd_may_reboot)
    c = sub.add_parser("retire-ready", help="may CURRENT be retired? (every node seen on its target by its peers)")
    chain(c)
    c.add_argument("--measurements", required=True)
    c.add_argument("--state", action="append", default=[], metavar="NODE=STATE.json", help="a node's attestation verifier state; one per authorizing node")
    c.set_defaults(run=_cmd_retire_ready)
    c = sub.add_parser("check-replacement", help="does a candidate manifest replace one node and change nothing else?")
    chain(c)
    c.add_argument("--candidate", required=True, metavar="MANIFEST.json", help="the proposed manifest, bare or in its signed envelope")
    c.add_argument("--old", required=True)
    c.add_argument("--new", required=True)
    c.add_argument("--old-id", required=True)
    c.add_argument("--new-id", required=True)
    c.set_defaults(run=_cmd_check_replacement)

    args = parser.parse_args(argv)
    try:
        result, text = args.run(args)
    except (Refused, attest.Refused, OSError) as refusal:
        reason = "cannot read %s: %s" % (refusal.filename, refusal.strerror) if isinstance(refusal, OSError) else str(refusal)
        if args.json:
            print(json.dumps({"ok": False, "command": args.command, "refused": reason}, sort_keys=True))
        else:
            print("%s: NO: %s" % (args.command, reason), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(dict(result, ok=True, command=args.command), sort_keys=True))
    else:
        print(text % result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
