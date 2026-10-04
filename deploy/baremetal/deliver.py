#!/usr/bin/env python3
"""Give a running node signed manifests it has not taken yet (#199: what `authority accept` did, before the authority host
was retired). The root's permissive changes (an image approved, a node replaced or added) are signed on the offline
laptop and reach the cluster here, on ONE node: the others pull them from it, as they pull every epoch.

    sudo python3 -Es -m deploy.baremetal.deliver --config /etc/regalia/node.json --chain CHAIN.json [--documents DOC.json ...]

CHAIN.json is a JSON list of signed envelopes (the root's, or a quorum's) from any epoch; those this node holds already
are verified again (and must be the same manifests: else CONFLICT, an incident), and the rest are committed in
order, as a sync commits a peer's (convergence.catch_up). Each --documents file is a measurement document an epoch of the
chain commits to (#332: an epoch is committed only with its document held). Nothing here judges a signature or a
transition: membership.Store.commit does, as for every epoch from a peer, so a delivery can do nothing a sync could not.

As root at the console, it reads the files; as regalia-sync (runuser, the store and the documents are its own, as
enrol's anchor step does it) it puts the documents, commits the envelopes and republishes the chain, which wg-apply's
path unit and the peers' pulls then take. Each delivery is one event in the node's sync trail (deliver).
"""
import argparse
import json
import os
import subprocess
import sys

from deploy.baremetal import measurements, membership

Refused, require = membership.Refused, membership.require

SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAX_CHAIN_BYTES = membership.MAX_CHAIN_BYTES
MAX_DOCUMENTS = 8                 # measurement documents in one delivery


def deliver(node, envelopes, documents, trail):
    """As regalia-sync: `documents` put by digest, then the envelopes applied as a sync applies a peer's
    (convergence.catch_up: in order; an epoch this node holds is verified again and must be the same manifest, else
    CONFLICT; the highest new epoch is judged by its measurements document, #332), then the chain republished. A
    refusal part-way leaves the node at the last good epoch, which is published and recorded. Returns the epoch the
    node is at."""
    from deploy.baremetal import convergence, node as node_module
    require(isinstance(envelopes, list) and envelopes and all(isinstance(e, dict) and isinstance(e.get("manifest"), dict) for e in envelopes),
            "the chain is a non-empty list of signed envelopes")
    store, held = node.store(), node.documents()
    start = store.load()["epoch"]
    reached, refusal = start, None
    try:
        for document in documents:
            held.put(document)
        require(any(isinstance(e["manifest"].get("epoch"), int) and e["manifest"]["epoch"] > start for e in envelopes),
                "this node holds epoch %d already: nothing in the chain is newer" % start)
        convergence.catch_up(store, envelopes)
    except Refused as refused:
        refusal = refused
    reached = store.load()["epoch"]
    if reached > start:                                 # what was committed is published, whatever came after it
        node_module.publish(store, node.path(node_module.PUBLISHED))
    if refusal is not None:
        trail({"event": "deliver", "outcome": "DENY", "epoch": reached, "reason": ("from epoch %d: %s" % (start, refusal))[:240]})
        raise refusal
    now = store.load()
    trail({"event": "deliver", "outcome": "ALLOW", "epoch": now["epoch"], "digest": membership.digest(now), "reason": "from epoch %d" % start})
    return now["epoch"]


def as_sync(config_path, envelopes, documents, run=subprocess.run):
    """deliver() in a process of regalia-sync with the tss group (the TPM anchor), nothing of root's environment, the
    files' contents on its standard input. Returns the epoch the node is at."""
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.deliver", "_deliver", "--config", config_path],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, input=json.dumps({"envelopes": envelopes, "documents": documents}))
    require(done.returncode == 0, "the delivery, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    return json.loads(done.stdout.strip().splitlines()[-1])["epoch"]


def main(argv=None):
    from deploy.baremetal import node as node_module
    parser = argparse.ArgumentParser(prog="deliver", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", required=True)
    sub = parser.add_subparsers(dest="op")
    sub.add_parser("_deliver")
    parser.add_argument("--chain")
    parser.add_argument("--documents", nargs="*", default=[])
    args = parser.parse_args(argv)
    try:
        if args.op == "_deliver":
            # only as regalia-sync: run as root, Store would leave membership.json root's and 0600, unreadable by the
            # service it belongs to (regalia-kms-51's read). `as_sync` is how root gets here
            import pwd
            require(os.geteuid() == pwd.getpwnam(SYNC_USER).pw_uid, "_deliver runs as %s only (deliver hands over to it with runuser)" % SYNC_USER)
            node = node_module.Node(node_module.load(args.config))
            # the chain and the documents together: each passed its own limit when root read it (3e's read)
            limit = MAX_CHAIN_BYTES + MAX_DOCUMENTS * measurements.MAX_BYTES + 65536
            given = membership.load(sys.stdin.read(limit + 1).encode(), limit)
            trail = node_module.Trail(node.path("sync-audit.jsonl"), "sync")
            print(json.dumps({"epoch": deliver(node, given["envelopes"], given["documents"], trail)}))
            return 0
        if os.geteuid() != 0:
            print("REFUSED: run as root, on the node", file=sys.stderr)
            return 2
        require(args.chain, "--chain is required")
        with open(args.chain, "rb") as f:
            envelopes = membership.load(f.read(MAX_CHAIN_BYTES + 1), MAX_CHAIN_BYTES)
        require(len(args.documents) <= MAX_DOCUMENTS, "at most %d documents in one delivery" % MAX_DOCUMENTS)
        documents = []
        for path in args.documents:
            with open(path, "rb") as f:
                documents.append(measurements.load(f.read(measurements.MAX_BYTES + 1)))
        print("DELIVERED: this node is at epoch %d; the others pull it from here" % as_sync(args.config, envelopes, documents))
    except (Refused, OSError, ValueError, KeyError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
