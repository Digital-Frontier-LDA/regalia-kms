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
  * TWO OTHER NODES. Whole chains from at least two other nodes, each one the newest manifest lets
    authorize, agreeing at every epoch, and ALL ending at the same epoch: a node that is ahead of the others
    is refused, since its newest epochs would rest on that node alone. Two nodes are the quorum everything
    else in the cluster rests on (#199: there is no authority host any more; two compromised nodes could
    already sign heartbeats and revocations, which is the accepted trade-off on #199). None may be the node
    being re-anchored.
    ONE OTHER NODE AND THE OWNER (--one-source, #387): when only one other node is left, the owner is the
    second source, by a statement signed off the nodes (owner.py sign-recovery --purpose reanchor) over that
    node's tip, for this node and this operation's session, for minutes (recover.py says what is checked). The
    TPM no longer bounds a re-anchor from below, so the owner's tool does: it refuses a tip below what the
    owner's machine signed, or below what the audit collector saw. The chain must extend the manifest this
    node's disk still holds, and no second node that may authorize may answer (else: use two).
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
        --tpm-index 0x1500016 --node-id b --peer a=a-chain.json --peer c=c-chain.json \\
        --audit-log /var/log/regalia/reanchor.jsonl

It needs the TPM's owner authorization, as defining the anchor did at commissioning.
"""
import argparse
import os
import re
import sys
import time

from deploy.baremetal import convergence, membership, ownerauth, trails

Refused, require = membership.Refused, membership.require


class Incomplete(Exception):
    """The anchor was being replaced and the operation did not finish. Not a refusal: something changed.
    Run the command again."""


class Unrecorded(Exception):
    """The re-anchor is done and its outcome could not be written to the audit log."""

    def __init__(self, summary, failure):
        super().__init__(str(failure))
        self.summary = summary


def plan(store, sources, node_id, owner=None):
    """What a re-anchor would do, having verified everything that can be verified without changing anything:
    {"reason": why the anchor is unusable, "counter": the old counter's epoch or None, "records": the record
    slots that still hold a valid record, "epoch", "manifest_digest" and "manifest": the newest manifest of
    the chain to anchor, "chain": that chain (every source's), "sources": who gave one}."""
    require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "node_id must be a node ID")
    require(isinstance(sources, dict), "sources must map each source to the chain it gave")
    if owner is None:
        require(len(sources) >= 2, "re-anchoring needs whole chains from at least two other nodes (%d source given)" % len(sources))
    else:
        require(len(sources) == 1, "--one-source takes exactly one other node's chain (%d given): with two, re-anchor from both" % len(sources))
    require(node_id not in sources, "%s cannot be a source for its own re-anchor: the peer's chain comes from another node" % node_id)
    reason = store.hw.unusable()             # Refused, not a reason, when the TPM does not answer
    require(reason is not None, "the TPM anchor is usable: it is not reset. A chain that is rolled back, lost or substituted is "
            "restored under the anchor it has (convergence.recover)")
    counter, records = store.hw.remains()
    floor = max([counter or 0] + [epoch for epoch, _ in records])
    longest, newest = convergence.agreed(store.root_key, sources, 2 if owner is None else 1, floor)
    # Every source gave the same whole chain: one AHEAD of the others would have its newest epochs vouched
    # for by that node alone.
    ends = {source: len(chain) for source, chain in sources.items()}
    require(len(set(ends.values())) == 1, "the nodes' chains end at different epochs (%s): every source must give the same whole chain; "
            "fetch each node's current chain" % ", ".join("%s at %d" % (k, v) for k, v in sorted(ends.items())))
    require(node_id in membership.validate(newest), "%s is not a node of the chain being anchored" % node_id)
    planned = {"reason": reason, "counter": counter, "records": records, "epoch": newest["epoch"], "manifest_digest": membership.digest(newest),
               "manifest": newest, "chain": longest, "sources": sorted(sources)}
    if owner is not None:
        from deploy.baremetal import recover
        recover.verify_chain(longest, store.root_key, recover.last_known(store.path, store.root_key))     # no fork of what the disk holds
        owner(newest)
        planned["sources"] = sorted(sources) + ["owner"]
    return planned


def phrase(node_id, planned):
    return "re-anchor %s at epoch %d %s" % (node_id, planned["epoch"], planned["manifest_digest"][:8])


def reanchor(store, sources, node_id, typed, sink, owner=None, prepare=None):
    """Plan, record the request, check what the operator typed, re-anchor, record the outcome. Returns
    {"epoch", "manifest_digest"} of what the node now holds.

    `sink` gets: one DENY if the plan is refused; otherwise a `reanchor-requested` event naming the epoch
    and manifest BEFORE anything is asked or changed (if that cannot be written, nothing is done), then the
    outcome: ALLOW; DENY (refused, nothing changed); or INCOMPLETE (the anchor was being replaced and it
    did not finish: Incomplete is raised, and the command is run again). `typed` is a callable given the
    plan and returning what the operator typed, so nothing is asked before the plan exists. `prepare(planned)`, if
    given, runs once the plan exists and before anything is recorded as requested, asked or changed (the define policy
    from the manifest being anchored, NodePolicies.prepare): a refusal there is a DENY with nothing changed."""
    def event(kind, planned, **more):
        return dict({"event": kind, "subject": convergence._printable(node_id), "peer": "operator",
                     "epoch": planned.get("epoch", 0), "manifest_digest": planned.get("manifest_digest", ""),
                     "sources": planned.get("sources", sorted(map(str, sources)) if isinstance(sources, dict) else []),
                     "anchor_was": convergence._printable(planned.get("reason", ""))}, **more)

    try:
        planned = plan(store, sources, node_id, owner)
    except Refused as refusal:
        sink(event("reanchor", {}, outcome="DENY", reason=convergence._printable(refusal)))
        raise
    if prepare is not None:
        try:
            prepare(planned)
        except (Refused, OSError, ValueError, KeyError) as refusal:     # a held document unreadable, an odd config: a DENY
            sink(event("reanchor", planned, outcome="DENY", reason=convergence._printable(refusal)))
            if isinstance(refusal, Refused):
                raise
            raise Refused("the re-anchor's define policy cannot be established: %s" % refusal) from refusal
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


def _highwater(index, tcti, policy=None, define_policy=None, owner_auth=None):
    return membership.HighWater(index, tcti=tcti, policy=policy, define_policy=define_policy, owner_auth=owner_auth)


def node_policy(path, node_id):
    """The approved-image write policy (#242) a policy-written anchor index is read with: from this node's own
    configuration (node.image_policy: its signed chain, the measurements document the chain commits to, and the
    running image's PCR key), resolved only if an index is written by policy. Without --node-config that is a
    refusal that says what to give, not an Unusable anchor: re-anchoring an anchor that is fine would be wrong."""
    def policy():
        require(path is not None, "this node's anchor is written by its approved-image policy (#242): give --node-config, this "
                "node's node.json, so that the policy can be established")
        from deploy.baremetal import node                  # here: node imports the services, which a re-anchor does not need
        cfg = node.load(path)
        require(cfg["node_id"] == node_id, "--node-config is %s's, not %s's" % (cfg["node_id"], node_id))
        return node.image_policy(cfg)
    return policy


class NodePolicies:
    """The policies a re-anchor reads and defines the anchor by (#242), from --node-config. The configuration is loaded
    and checked to be this node's UP FRONT (a typo, an unreadable file, another node's: refused with nothing changed).
    The define policy is resolved by `prepare`, which reanchor() calls once the plan exists and before anything is
    asked or changed, from the MANIFEST BEING ANCHORED (node.define_policy(cfg, manifest=planned tip)), never from the
    chain on disk: a node re-anchored because its state was lost has none, and an old chain on disk may commit to
    another document (regalia-kms-48 on #416). Its measurements document must be held (measurements.held): refused
    cleanly, with nothing changed, otherwise. Without --node-config: node_policy's lazy refusal for a policy-written
    index, and owner-written new indices (as before #242)."""

    def __init__(self, path, node_id):
        self.path, self.node_id, self.cfg, self.defined, self.prepared = path, node_id, None, None, False
        if path is not None:
            from deploy.baremetal import node                  # here: node imports the services, which a re-anchor does not need
            try:
                self.cfg = node.load(path)
            except (OSError, ValueError) as error:
                raise Refused("--node-config %s cannot be loaded: %s" % (path, error)) from None
            require(self.cfg["node_id"] == node_id, "--node-config is %s's, not %s's" % (self.cfg["node_id"], node_id))

    def prepare(self, planned):
        if self.cfg is not None:
            from deploy.baremetal import node
            self.defined = node.define_policy(self.cfg, manifest=planned["manifest"])
        self.prepared = True

    def define(self):
        """HighWater's define_policy: what prepare resolved (None: owner-written new indices)."""
        require(self.prepared, "the define policy is asked for before the re-anchor's plan: nothing is defined before it")
        return self.defined

    def reader(self):
        """HighWater's policy, for a HighWater that has not resolved its reader yet (it resolves it once): the planned one
        once prepare has run; before that (the plan reading a policy-written old anchor), the node's image policy from
        the chain it holds, as node_policy does, and then that value stays (after the redefinition the new indices are
        read by the define policy's own check; see the PR's limitations)."""
        if self.prepared and self.defined is not None:
            return self.defined
        return node_policy(self.path, self.node_id)()


def _owner_check(config_path, node_id, statement_path, peer):
    """recover.owner_check for this node, from its node.json, and the owner's statement file."""
    from deploy.baremetal import node, recover
    cfg = node.load(config_path)
    require(cfg["node_id"] == node_id, "--node-config is %s's, not %s's" % (cfg["node_id"], node_id))
    with open(statement_path, "rb") as f:
        signed = membership.load(f.read(65536))
    return recover.owner_check(node.Node(cfg), signed, "reanchor", peer)


def main(argv=None, ask=None, highwater=_highwater, tty=None, owner_check=_owner_check):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage; 3 INCOMPLETE, the anchor was being replaced:
    run it again; 4 done, but the outcome could not be written to the audit log."""
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.reanchor", description=__doc__.splitlines()[0])
    ap.add_argument("--membership", required=True, help="this node's membership file")
    ap.add_argument("--root-key", required=True, help="the pinned membership root key, 64 hex")
    ap.add_argument("--tpm-index", required=True, help="the NV index of this node's epoch counter (0x1500016)")
    ap.add_argument("--node-id", required=True, help="this node's ID")
    ap.add_argument("--peer", action="append", default=[], metavar="NODE=CHAIN.json", help="the whole chain ANOTHER node gave; at least two")
    ap.add_argument("--audit-log", default=trails.where("reanchor"),
                    help="the audit trail (default %(default)s, its place in trails.py's registry)")
    ap.add_argument("--tcti", help="the TPM to re-anchor, as a TCTI (e.g. device:/dev/tpmrm0); default: tpm2-tools' default TPM")
    ap.add_argument("--node-config", help="this node's node.json: needed when its anchor is written by its approved-image policy (#242)")
    ownerauth.add_arguments(ap)
    ap.add_argument("--one-source", action="store_true", help="ONE other node, the owner the second source (needs --owner-statement, --node-config)")
    ap.add_argument("--owner-statement", help="the owner's statement (owner.py sign-recovery --purpose reanchor)")
    args = ap.parse_args(argv)
    # The TPM is named on the command line or is the default, never taken from the environment: a
    # TPM2TOOLS_TCTI left over in the shell would re-anchor ANOTHER TPM, which would truthfully say that the
    # indices are missing, and the audit log would record an ALLOW that did nothing to this host's anchor.
    tpm = args.tcti or "the default TPM"

    def record(event):                 # hash-chained, whole or not at all, never through a link (trails.py, #278)
        try:
            trails.append(args.audit_log, dict(event, tpm=tpm, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        except trails.Refused as refused:  # an unwritable trail, as an OSError from the file would be
            raise OSError(str(refused)) from refused

    def typed(planned):
        print("TPM: %s, NV index %s." % (tpm, args.tpm_index))
        print("This node's TPM anchor is unusable: %s" % planned["reason"])
        print("The old epoch counter %s." % ("cannot be read" if planned["counter"] is None else "reads epoch %d" % planned["counter"]))
        for epoch, held in planned["records"]:
            print("A record slot still holds epoch %d, manifest %s: the chain carries that manifest at that epoch." % (epoch, held))
        print("Sources that agree: %s." % ", ".join(planned["sources"]))
        print("The chain ends at epoch %d, manifest %s:" % (planned["epoch"], planned["manifest_digest"]))
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
        # the owner authorization re-anchoring deletes and defines with (#242), from the node's envelope on standard
        # input, judged now; the phrase is then typed at the terminal itself
        owner_auth = ownerauth.from_arguments(args, args.root_key, args.node_id)
        if owner_auth is not None and ask is None:
            ask = ownerauth.console
        require(ask is not None or (tty or sys.stdin.isatty)(), "the phrase must be typed at a terminal: standard input is not one")
        sources = {}
        for item in args.peer:
            node_id, sep, path = item.partition("=")
            require(sep and node_id and path, "--peer takes NODE=CHAIN.json, not %r" % item)
            require(node_id not in sources, "--peer names %s twice" % node_id)
            sources[node_id] = _chain(path)
        owner = None
        if args.one_source:
            require(args.owner_statement and args.node_config, "--one-source needs --owner-statement and --node-config")
            owner = owner_check(args.node_config, args.node_id, args.owner_statement, sorted(sources)[0] if sources else "")
        # a node configuration that cannot be loaded, or another node's, refuses here; its define policy is resolved
        # from the manifest being anchored, after the plan and before anything changes (NodePolicies.prepare)
        policies = NodePolicies(args.node_config, args.node_id)
        extra = {} if owner_auth is None else {"owner_auth": owner_auth}
        store = membership.Store(args.membership, args.root_key, highwater(args.tpm_index, args.tcti, policy=policies.reader,
                                                                          define_policy=policies.define, **extra))
        now_at = reanchor(store, sources, args.node_id, typed, record, owner=owner, prepare=policies.prepare)
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
