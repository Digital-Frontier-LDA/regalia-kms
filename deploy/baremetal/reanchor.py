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
  * THE AUTHORITY AND A PEER. Whole chains from at least two sources that agree at every epoch, and one of
    them must be the revocation authority (convergence.AUTHORITY): two peers alone cannot re-anchor a
    node. Every source must be one the newest manifest trusts.
  * A USABLE ANCHOR IS NEVER RESET. If the counter reads and the record is valid and in step, this refuses.
  * NOT A WAY BACK. While the old counter still reads, the chain must reach its epoch.
  * VERIFIED FIRST. All of the above is checked before the TPM is touched; a refusal changes nothing.
  * TYPED. The operator types a phrase naming the node, the epoch and the manifest digest being anchored.
  * RECORDED. One audit event, ALLOW or DENY with the reason, appended to the audit log before the result
    is reported.

    python3 -m deploy.baremetal.reanchor --membership /var/lib/regalia/membership.json --root-key HEX \\
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


def plan(store, sources):
    """What a re-anchor would do, having verified everything that can be verified without touching the TPM:
    {"reason": why the anchor is unusable, "old_epoch": the counter's epoch or None, "epoch", "manifest_digest"
    and "manifest": the newest manifest of the agreed chain, "chain": that chain, "sources": who gave one}."""
    require(isinstance(sources, dict), "sources must map each source to the chain it gave")
    require(convergence.AUTHORITY in sources, "re-anchoring needs the revocation authority's chain: peers alone cannot re-anchor a node")
    require(len(sources) >= 2, "re-anchoring needs the authority's chain and at least one peer's (%d source given)" % len(sources))
    reason = store.hw.unusable()
    require(reason is not None, "the TPM anchor is usable: it is not reset. A chain that is rolled back, lost or substituted is "
            "restored under the anchor it has (convergence.recover)")
    try:
        old = store.hw.value()
    except Refused:
        old = None
    chain, newest = convergence.agreed(store.root_key, sources, 2, old or 0)
    return {"reason": reason, "old_epoch": old, "epoch": newest["epoch"], "manifest_digest": membership.digest(newest),
            "manifest": newest, "chain": chain, "sources": sorted(sources)}


def phrase(node_id, planned):
    return "re-anchor %s at epoch %d %s" % (node_id, planned["epoch"], planned["manifest_digest"][:8])


def reanchor(store, sources, node_id, typed, sink):
    """Verify, check what the operator typed, re-anchor, and hand `sink` one audit event (ALLOW, or DENY with
    the reason). Returns the summary afterwards. `typed` is a callable given the plan and returning what
    the operator typed, so nothing is asked before the plan exists."""
    require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None, "node_id must be a node ID")
    planned = {}

    def decide():
        planned.update(plan(store, sources))
        require(node_id in membership.validate(planned["manifest"]), "%s is not a node of the chain being anchored" % node_id)
        require(typed(dict(planned)) == phrase(node_id, planned), "not confirmed: the phrase typed is not %r" % phrase(node_id, planned))
        store.reanchor(planned["chain"])
        return convergence.summary(store)

    return convergence.audited(lambda event: sink(dict(event, epoch=planned.get("epoch", 0), manifest_digest=planned.get("manifest_digest", ""),
                                                       sources=planned.get("sources", sorted(sources) if isinstance(sources, dict) else []),
                                                       anchor_was=planned.get("reason", ""))),
                               "reanchor", None, node_id, "operator", decide)


def _chain(path):
    with open(path, "rb") as f:
        return membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), limit=membership.MAX_CHAIN_BYTES)


def main(argv=None, ask=input, highwater=membership.HighWater):
    ap = argparse.ArgumentParser(prog="python3 -m deploy.baremetal.reanchor", description=__doc__.splitlines()[0])
    ap.add_argument("--membership", required=True, help="this node's membership file")
    ap.add_argument("--root-key", required=True, help="the pinned membership root key, 64 hex")
    ap.add_argument("--tpm-index", required=True, help="the NV index of this node's epoch counter (0x1500016)")
    ap.add_argument("--node-id", required=True, help="this node's ID")
    ap.add_argument("--authority", required=True, metavar="CHAIN.json", help="the whole chain, as the revocation authority gave it")
    ap.add_argument("--peer", action="append", default=[], metavar="NODE=CHAIN.json", help="the whole chain a peer gave; at least one, repeat for more")
    ap.add_argument("--audit-log", required=True, help="the file the audit event is appended to (one JSON object a line)")
    args = ap.parse_args(argv)

    def record(event):
        line = json.dumps(dict(event, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), sort_keys=True)
        fd = os.open(args.audit_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def typed(planned):
        print("This node's TPM anchor is unusable: %s" % planned["reason"])
        print("The old epoch counter %s." % ("cannot be read" if planned["old_epoch"] is None else "reads epoch %d" % planned["old_epoch"]))
        print("Sources that agree: %s." % ", ".join(planned["sources"]))
        print("The chain they agree on ends at epoch %d, manifest %s:" % (planned["epoch"], planned["manifest_digest"]))
        for node in planned["manifest"]["nodes"]:
            print("    %-32s %s" % (node["node_id"], node["state"]))
        print("Re-anchoring DELETES this node's membership anchor and defines a new one on this chain.")
        print("Before you type anything: MEMBERSHIP-RECOVERY.md, \"Deciding that the sources are right\".")
        return ask("Type exactly: %s\n> " % phrase(args.node_id, planned))

    try:
        require(re.fullmatch(r"0x[0-9a-fA-F]{1,8}", args.tpm_index) is not None, "--tpm-index must be 0x and up to 8 hex digits")
        membership.hex_field(args.root_key, 64, "--root-key")
        sources = {convergence.AUTHORITY: _chain(args.authority)}
        for item in args.peer:
            node_id, sep, path = item.partition("=")
            require(sep and node_id and path, "--peer takes NODE=CHAIN.json, not %r" % item)
            require(node_id not in sources, "--peer names %s twice" % node_id)
            sources[node_id] = _chain(path)
        store = membership.Store(args.membership, args.root_key, highwater(args.tpm_index))
        # first, and before the TPM is touched: an attempt leaves a trace, and a log that cannot be written stops it here
        record({"event": "reanchor-requested", "subject": args.node_id, "sources": sorted(sources)})
        now_at = reanchor(store, sources, args.node_id, typed, record)
    except (OSError, Refused) as failure:
        print("reanchor: NOT DONE: %s" % failure, file=sys.stderr)
        return 1
    print("reanchor: done. %s now holds epoch %d, manifest %s, under a new anchor." % (args.node_id, now_at["epoch"], now_at["manifest_digest"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
