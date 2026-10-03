#!/usr/bin/env python3
"""Re-anchor: give a KMS node a new TPM anchor for its membership, when the anchor itself is unusable
(#68; MEMBERSHIP-RECOVERY.md is the procedure).

A node's TPM holds the epoch it has accepted and which manifest that was (membership.HighWater). A chain
that is rolled back, lost or substituted is restored UNDER that anchor (membership.Store.restore,
convergence.recover): the anchor decides. This command is for the other case, where the anchor cannot
decide anything: neither record slot is valid, an index is gone, the counter and the record are out of
step, or the TPM was replaced. Then every load and every restore is refused, by design, and no peer can
help. The way back is a new anchor.

A NEW ANCHOR FORGETS WHAT THE TPM KNEW. It is the one operation that resets a node's rollback protection,
so it is the one an attacker would want, and it is fenced accordingly:

  * AN OPERATOR, ON THE HOST. It is this command, run by hand. Nothing calls reanchor() from a service, and
    the code that talks to peers (convergence.py) has no re-anchor in it.
  * THE AUTHORITY AND A PEER. Whole chains from at least two sources that agree at every epoch they share.
    One of them must be the revocation authority (convergence.AUTHORITY), and the chain anchored is the
    AUTHORITY'S: two peers alone cannot re-anchor a node, and a peer that is ahead of the authority is
    refused (its newest epochs would rest on that peer alone). Every source must be one the newest
    manifest trusts, and none may be the node being re-anchored.
  * A USABLE ANCHOR IS NEVER RESET. If the counter reads and the record is valid and in step, this refuses.
  * A TPM THAT DOES NOT ANSWER IS NOT RE-ANCHORED. "The index is not defined", said by the TPM, is an
    unusable anchor. A TPM or a tool that fails says nothing about the anchor, and this refuses.
  * NOTHING THE TPM STILL HOLDS IS FORGOTTEN. The chain must reach the old counter's epoch while it reads,
    reach the epoch of every record slot that still holds a valid record, and carry that slot's manifest.
  * NEVER LESS THAN IT HELD, NEVER AN EMPTY ANCHOR. The new record is written into a record slot before the
    old counter is touched, and the new counter is defined AT the chain's epoch. No valid record slot is
    deleted. Interrupted anywhere, the node holds what it held before, or the new record beside a counter
    out of step with it (unusable), or the finished anchor: never less than it held, and never an anchor
    that would accept another chain.
  * VERIFIED FIRST. All of the above is checked before anything is changed; a refusal changes nothing.
  * TYPED, AT A TERMINAL. The operator types a phrase naming the node, the epoch and the manifest digest
    being anchored. It is a deliberate act, not a secret: what authorizes the change is the TPM's owner
    authorization.
  * RECORDED. The request, naming the epoch and manifest, is appended to the audit log before anything is
    asked or changed (without a writable log nothing is done); then the outcome: ALLOW, DENY (nothing
    changed), or INCOMPLETE (the anchor was being replaced and it did not finish: run it again).

    python3 -Es -m deploy.baremetal.reanchor --membership /var/lib/regalia/membership.json --root-key HEX \\
        --tpm-index 0x1500016 --node-id b --authority authority-chain.json --peer c=c-chain.json \\
        --audit-log /var/log/regalia/reanchor.jsonl

It needs the TPM's owner authorization, as defining the anchor did at commissioning.
"""
import argparse
import json
import os
import re
import sys
import time

from deploy.baremetal import convergence, membership

Refused, require = membership.Refused, membership.require


class Incomplete(Exception):
    """The anchor was being replaced and the operation did not finish. Not a refusal: something changed.
    Run the command again."""


class Unrecorded(Exception):
    """The re-anchor is done and its outcome could not be written to the audit log."""

    def __init__(self, summary, failure):
        super().__init__(str(failure))
        self.summary = summary


def plan(store, sources, node_id):
    """What a re-anchor would do, having verified everything that can be verified without changing anything:
    {"reason": why the anchor is unusable, "counter": the old counter's epoch or None, "records": the record
    slots that still hold a valid record, "epoch", "manifest_digest" and "manifest": the newest manifest of
    the chain to anchor, "chain": that chain (the AUTHORITY's), "sources": who gave one}."""
    require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "node_id must be a node ID")
    require(isinstance(sources, dict), "sources must map each source to the chain it gave")
    require(convergence.AUTHORITY in sources, "re-anchoring needs the revocation authority's chain: peers alone cannot re-anchor a node")
    require(len(sources) >= 2, "re-anchoring needs the authority's chain and at least one peer's (%d source given)" % len(sources))
    require(node_id not in sources, "%s cannot be a source for its own re-anchor: the peer's chain comes from another node" % node_id)
    reason = store.hw.unusable()             # Refused, not a reason, when the TPM does not answer
    require(reason is not None, "the TPM anchor is usable: it is not reset. A chain that is rolled back, lost or substituted is "
            "restored under the anchor it has (convergence.recover)")
    counter, records = store.hw.remains()
    floor = max([counter or 0] + [epoch for epoch, _ in records])
    longest, newest = convergence.agreed(store.root_key, sources, 2, floor)
    # The chain anchored is the authority's. A peer may be behind it; a peer AHEAD of it would have its
    # newest epochs vouched for by that peer alone.
    require(len(sources[convergence.AUTHORITY]) == len(longest), "a peer's chain ends at epoch %d and the authority's at epoch %d: the chain "
            "anchored must be the authority's; fetch the authority's current chain" % (len(longest), len(sources[convergence.AUTHORITY])))
    require(node_id in membership.validate(newest), "%s is not a node of the chain being anchored" % node_id)
    return {"reason": reason, "counter": counter, "records": records, "epoch": newest["epoch"], "manifest_digest": membership.digest(newest),
            "manifest": newest, "chain": sources[convergence.AUTHORITY], "sources": sorted(sources)}


def phrase(node_id, planned):
    return "re-anchor %s at epoch %d %s" % (node_id, planned["epoch"], planned["manifest_digest"][:8])


def reanchor(store, sources, node_id, typed, sink):
    """Plan, record the request, check what the operator typed, re-anchor, record the outcome. Returns
    {"epoch", "manifest_digest"} of what the node now holds.

    `sink` gets: one DENY if the plan is refused; otherwise a `reanchor-requested` event naming the epoch
    and manifest BEFORE anything is asked or changed (if that cannot be written, nothing is done), then the
    outcome: ALLOW; DENY (refused, nothing changed); or INCOMPLETE (the anchor was being replaced and it
    did not finish: Incomplete is raised, and the command is run again). `typed` is a callable given the
    plan and returning what the operator typed, so nothing is asked before the plan exists."""
    def event(kind, planned, **more):
        return dict({"event": kind, "subject": convergence._printable(node_id), "peer": "operator",
                     "epoch": planned.get("epoch", 0), "manifest_digest": planned.get("manifest_digest", ""),
                     "sources": planned.get("sources", sorted(map(str, sources)) if isinstance(sources, dict) else []),
                     "anchor_was": convergence._printable(planned.get("reason", ""))}, **more)

    try:
        planned = plan(store, sources, node_id)
    except Refused as refusal:
        sink(event("reanchor", {}, outcome="DENY", reason=convergence._printable(refusal)))
        raise
    sink(event("reanchor-requested", planned))
    store.reanchor_began = False
    try:
        require(typed(dict(planned)) == phrase(node_id, planned), "not confirmed: the phrase typed is not %r" % phrase(node_id, planned))
        store.reanchor(planned["chain"])
    except BaseException as failure:
        began = store.reanchor_began
        reason = convergence._printable(failure) or type(failure).__name__
        if not began:
            sink(event("reanchor", planned, outcome="DENY", reason=reason))
            raise
        try:
            sink(event("reanchor", planned, outcome="INCOMPLETE", reason=reason))
        except OSError as unlogged:                 # the anchor changed: say so, logged or not
            raise Incomplete("%s (and this could not be written to the audit log: %s)" % (reason, unlogged)) from failure
        raise Incomplete(reason) from failure
    summary = {"epoch": planned["epoch"], "manifest_digest": planned["manifest_digest"]}
    try:
        sink(event("reanchor", planned, outcome="ALLOW", reason=""))
    except OSError as failure:
        raise Unrecorded(summary, failure) from failure
    return summary


def _chain(path):
    with open(path, "rb") as f:
        return membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), limit=membership.MAX_CHAIN_BYTES)


def _highwater(index, tcti):
    return membership.HighWater(index, tcti=tcti)


def main(argv=None, ask=None, highwater=_highwater, tty=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage; 3 INCOMPLETE, the anchor was being replaced:
    run it again; 4 done, but the outcome could not be written to the audit log."""
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.reanchor", description=__doc__.splitlines()[0])
    ap.add_argument("--membership", required=True, help="this node's membership file")
    ap.add_argument("--root-key", required=True, help="the pinned membership root key, 64 hex")
    ap.add_argument("--tpm-index", required=True, help="the NV index of this node's epoch counter (0x1500016)")
    ap.add_argument("--node-id", required=True, help="this node's ID")
    ap.add_argument("--authority", required=True, metavar="CHAIN.json", help="the whole chain, as the revocation authority gave it")
    ap.add_argument("--peer", action="append", default=[], metavar="NODE=CHAIN.json", help="the whole chain ANOTHER node gave; at least one, repeat for more")
    ap.add_argument("--audit-log", required=True, help="the file the audit events are appended to (one JSON object a line)")
    ap.add_argument("--tcti", help="the TPM to re-anchor, as a TCTI (e.g. device:/dev/tpmrm0); default: tpm2-tools' default TPM")
    args = ap.parse_args(argv)
    # The TPM is named on the command line or is the default, never taken from the environment: a
    # TPM2TOOLS_TCTI left over in the shell would re-anchor ANOTHER TPM, which would truthfully say that the
    # indices are missing, and the audit log would record an ALLOW that did nothing to this host's anchor.
    tpm = args.tcti or "the default TPM"

    def record(event):
        line = json.dumps(dict(event, tpm=tpm, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), sort_keys=True)
        fd = os.open(args.audit_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def typed(planned):
        print("TPM: %s, NV index %s." % (tpm, args.tpm_index))
        print("This node's TPM anchor is unusable: %s" % planned["reason"])
        print("The old epoch counter %s." % ("cannot be read" if planned["counter"] is None else "reads epoch %d" % planned["counter"]))
        for epoch, held in planned["records"]:
            print("A record slot still holds epoch %d, manifest %s: the chain carries that manifest at that epoch." % (epoch, held))
        print("Sources that agree: %s." % ", ".join(planned["sources"]))
        print("The authority's chain ends at epoch %d, manifest %s:" % (planned["epoch"], planned["manifest_digest"]))
        for node in planned["manifest"]["nodes"]:
            print("    %-32s %s" % (node["node_id"], node["state"]))
        print("Re-anchoring DELETES this node's membership anchor and defines a new one on this chain.")
        print("Before you type anything: MEMBERSHIP-RECOVERY.md, \"Deciding that the sources are right\".")
        try:
            return (ask or input)("Type exactly: %s\n> " % phrase(args.node_id, planned))
        except EOFError:
            return None

    try:
        require(re.fullmatch(r"0x[0-9a-fA-F]{1,8}", args.tpm_index) is not None, "--tpm-index must be 0x and up to 8 hex digits")
        require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: name the TPM with --tcti instead, or unset it")
        membership.hex_field(args.root_key, 64, "--root-key")
        # The phrase is a deliberate act at this host's terminal, not a line in a script or a pipe. (It is not a
        # secret: what authorizes the change is the TPM's owner authorization.)
        require(ask is not None or (tty or sys.stdin.isatty)(), "the phrase must be typed at a terminal: standard input is not one")
        sources = {convergence.AUTHORITY: _chain(args.authority)}
        for item in args.peer:
            node_id, sep, path = item.partition("=")
            require(sep and node_id and path, "--peer takes NODE=CHAIN.json, not %r" % item)
            require(node_id not in sources, "--peer names %s twice" % node_id)
            sources[node_id] = _chain(path)
        store = membership.Store(args.membership, args.root_key, highwater(args.tpm_index, args.tcti))
        now_at = reanchor(store, sources, args.node_id, typed, record)
    except Incomplete as failure:
        print("reanchor: INCOMPLETE: the anchor was being replaced and it did not finish: %s\nRun this command again with the same "
              "chains. Until it completes, this node's membership does not load." % failure, file=sys.stderr)
        return 3
    except Unrecorded as failure:
        print("reanchor: DONE, but the outcome could not be written to the audit log (%s). %s now holds epoch %d, manifest %s. "
              "Record it by hand." % (failure, args.node_id, failure.summary["epoch"], failure.summary["manifest_digest"]), file=sys.stderr)
        return 4
    except (OSError, Refused) as failure:
        print("reanchor: NOT DONE, nothing was changed: %s" % failure, file=sys.stderr)
        return 1
    print("reanchor: done. %s now holds epoch %d, manifest %s, under a new anchor." % (args.node_id, now_at["epoch"], now_at["manifest_digest"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
