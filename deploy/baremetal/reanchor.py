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
  * GIVEN BACK. Run as root, it writes the membership file as root; done (or INCOMPLETE), it gives that file and any
    lock it made back to the owner of the state directory (regalia-sync's, enrol._hand_over), or the node's own sync
    could not read its chain (#388). Its lock on the anchor is the node's own (highwater.lock in the state directory).

    python3 -Es -m deploy.baremetal.reanchor --membership /var/lib/regalia-sync/membership.json --root-key HEX \\
        --tpm-index 0x1500016 --tcti device:/dev/tpmrm0 --node-id b --node-config /etc/regalia/node.json \\
        --peer a=a-chain.json --peer c=c-chain.json

It needs the TPM's owner authorization, as defining the anchor did at commissioning.
"""
import argparse
import errno
import os
import re
import stat
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


def plan(store, sources, node_id):
    """What a re-anchor would do, having verified everything that can be verified without changing anything:
    {"reason": why the anchor is unusable, "counter": the old counter's epoch or None, "records": the record
    slots that still hold a valid record, "epoch", "manifest_digest" and "manifest": the newest manifest of
    the chain to anchor, "chain": that chain (every source's), "sources": who gave one}."""
    require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "node_id must be a node ID")
    require(isinstance(sources, dict), "sources must map each source to the chain it gave")
    require(len(sources) >= 2, "re-anchoring needs whole chains from at least two other nodes (%d source given)" % len(sources))
    require(node_id not in sources, "%s cannot be a source for its own re-anchor: the peer's chain comes from another node" % node_id)
    reason = store.hw.unusable()             # Refused, not a reason, when the TPM does not answer
    require(reason is not None, "the TPM anchor is usable: it is not reset. A chain that is rolled back, lost or substituted is "
            "restored under the anchor it has (convergence.recover)")
    counter, records = store.hw.remains()
    floor = max([counter or 0] + [epoch for epoch, _ in records])
    longest, newest = convergence.agreed(store.root_key, sources, 2, floor)
    # Every source gave the same whole chain: one AHEAD of the others would have its newest epochs vouched
    # for by that node alone.
    ends = {source: len(chain) for source, chain in sources.items()}
    require(len(set(ends.values())) == 1, "the nodes' chains end at different epochs (%s): every source must give the same whole chain; "
            "fetch each node's current chain" % ", ".join("%s at %d" % (k, v) for k, v in sorted(ends.items())))
    require(node_id in membership.validate(newest), "%s is not a node of the chain being anchored" % node_id)
    return {"reason": reason, "counter": counter, "records": records, "epoch": newest["epoch"], "manifest_digest": membership.digest(newest),
            "manifest": newest, "chain": longest, "sources": sorted(sources)}


def phrase(node_id, planned):
    return "re-anchor %s at epoch %d %s" % (node_id, planned["epoch"], planned["manifest_digest"][:8])


def reanchor(store, sources, node_id, typed, sink, prepare=None):
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
        planned = plan(store, sources, node_id)
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


def _highwater(index, tcti, policy=None, define_policy=None, owner_auth=None, lock_path=None):
    return membership.HighWater(index, tcti=tcti, policy=policy, define_policy=define_policy, owner_auth=owner_auth,
                                lock_path=lock_path)


def anchor_lock(membership_path):
    """The anchor's lock, where the node's own services take it (node.Node.anchor: highwater.lock in the state directory,
    which holds the membership file): a re-anchor and the node's sync then serialize on the same file."""
    return os.path.join(os.path.dirname(os.path.abspath(membership_path)), "highwater.lock")


def hand_back(membership_path, euid=os.geteuid, chown=os.fchown):
    """The membership file and the locks a re-anchor run as root may have made, given back to the owner of the directory
    that holds them (regalia-sync's state directory, enrol._hand_over): written by root, mkstemp's 0600 would leave the
    node's own sync unable to read its chain (#388). Each is opened without following a link and must be a regular file
    with one name (a hard link could name another file: regalia-sync controls the directory's entries), owned by root or
    by the directory's owner already, never a third user's; only one whose owner is not the directory's is changed, and
    only when root runs this and the directory is not root's. Returns the paths changed."""
    directory = os.path.dirname(os.path.abspath(membership_path))
    try:
        owner = os.stat(directory)
    except FileNotFoundError:                       # refused before anything was made: nothing to give back
        return []
    if euid() != 0 or owner.st_uid == 0:
        return []
    changed = []
    for path in (os.path.abspath(membership_path), os.path.abspath(membership_path) + ".lock", anchor_lock(membership_path)):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        try:
            held = os.fstat(fd)
            require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1, "%s is not a regular file with one name: it is not given back" % path)
            require(held.st_uid in (0, owner.st_uid), "%s belongs to uid %d, neither root nor the owner of %s: it is not given back"
                    % (path, held.st_uid, directory))
            if (held.st_uid, held.st_gid) != (owner.st_uid, owner.st_gid):
                chown(fd, owner.st_uid, owner.st_gid)
                changed.append(path)
        finally:
            os.close(fd)
    return changed


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


def main(argv=None, ask=None, highwater=_highwater, tty=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage; 3 INCOMPLETE, the anchor was being replaced:
    run it again; 4 done, but the outcome could not be written to the audit log; 5 done, but the membership file could not
    be given back to the owner of its directory (hand_back: the command to run is printed)."""
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
        if owner_auth is not None:
            ownerauth.measured_once()             # the value stays off the TPM bus only on measured tools (#414)
        if owner_auth is not None and ask is None:
            ask = ownerauth.console
        require(ask is not None or (tty or sys.stdin.isatty)(), "the phrase must be typed at a terminal: standard input is not one")
        sources = {}
        for item in args.peer:
            node_id, sep, path = item.partition("=")
            require(sep and node_id and path, "--peer takes NODE=CHAIN.json, not %r" % item)
            require(node_id not in sources, "--peer names %s twice" % node_id)
            sources[node_id] = _chain(path)
        # a node configuration that cannot be loaded, or another node's, refuses here; its define policy is resolved
        # from the manifest being anchored, after the plan and before anything changes (NodePolicies.prepare)
        policies = NodePolicies(args.node_config, args.node_id)
        extra = {} if owner_auth is None else {"owner_auth": owner_auth}
        store = membership.Store(args.membership, args.root_key, highwater(args.tpm_index, args.tcti, policy=policies.reader,
                                                                          define_policy=policies.define,
                                                                          lock_path=anchor_lock(args.membership), **extra))
        now_at = reanchor(store, sources, args.node_id, typed, record, prepare=policies.prepare)
    except Incomplete as failure:
        print("reanchor: INCOMPLETE: the anchor was being replaced and it did not finish: %s\nRun this command again with the same "
              "chains. Until it completes, this node's membership does not load." % failure, file=sys.stderr)
        _give_back(args.membership)
        return 3
    except Unrecorded as failure:
        print("reanchor: DONE, but the outcome could not be written to the audit log (%s). %s now holds epoch %d, manifest %s. "
              "Record it by hand." % (failure, args.node_id, failure.summary["epoch"], failure.summary["manifest_digest"]), file=sys.stderr)
        _give_back(args.membership)
        return 4
    except (OSError, Refused) as failure:
        print("reanchor: NOT DONE, nothing was changed: %s" % failure, file=sys.stderr)
        # the plan took the node's anchor lock (and the store its own) as root: one that did not exist was made 0600 by
        # root, and the node's sync could not take it (regalia-kms-1e on #391)
        _give_back(args.membership, done=False)
        return 1
    if not _give_back(args.membership):
        return 5
    print("reanchor: done. %s now holds epoch %d, manifest %s, under a new anchor." % (args.node_id, now_at["epoch"], now_at["manifest_digest"]))
    return 0


def _give_back(membership_path, done=True):
    """hand_back, said: True when every file is its directory owner's (or nothing needed it); else False, with what to do.
    A file refused for what it IS (a link, a second name, a third user's: Refused, or ELOOP from O_NOFOLLOW) gets no
    command: regalia-sync controls those entries, and a chown, even with -h, is not what a planted file needs. Any other
    failure prints the chown, with -h (never through a link) and after `--`."""
    try:
        for path in hand_back(membership_path):
            print("reanchor: %s given back to the owner of its directory" % path)
        return True
    except (OSError, Refused) as failure:
        directory = os.path.dirname(os.path.abspath(membership_path))
        what = ("the anchor is written, but the membership file or a lock" if done else
                "nothing was changed, but a lock or file this run made as root")
        if isinstance(failure, Refused) or getattr(failure, "errno", None) == errno.ELOOP:
            print("reanchor: %s could not be given back to the owner of %s: %s. It is not a regular file of root's or of the "
                  "directory's owner with one name: do NOT chown it. Look at it (ls -l %s), find out what made it, remove the "
                  "entry by name if it is not this node's, and run the command again." % (what, directory, failure, directory),
                  file=sys.stderr)
            return False
        print("reanchor: %s could not be given back to the owner of %s (%s): the node's sync cannot use it until it is. "
              "Run:  chown -h --reference=%s -- %s %s.lock %s" % (
                  what, directory, failure, directory, membership_path, membership_path, anchor_lock(membership_path)), file=sys.stderr)
        return False

if __name__ == "__main__":
    sys.exit(main())
