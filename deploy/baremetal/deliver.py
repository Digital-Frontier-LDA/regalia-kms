#!/usr/bin/env python3
"""Give a running node signed manifests it has not taken yet (#199: what `authority accept` did, before the authority host
was retired). The root's permissive changes (an image approved, a node replaced or added) are signed on the offline
laptop and reach the cluster here, on ONE node: the others pull them from it, as they pull every epoch.

    sudo python3 -Es -m deploy.baremetal.deliver --config /etc/regalia/node.json --chain CHAIN.json [--documents DOC.json ...]

CHAIN.json is a JSON list of signed envelopes (the root's, or a quorum's) from any epoch; those this node holds already
are passed over, and the rest are committed in order. Each --documents file is a measurement document an epoch of the
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


def deliver(node, envelopes, documents, trail):
    """As regalia-sync: `documents` put by digest, then every envelope above this node's epoch committed in order (the
    last one judged by its document, `final`), then the chain republished. Returns the epoch the node is at."""
    from deploy.baremetal import node as node_module
    require(isinstance(envelopes, list) and envelopes and all(isinstance(e, dict) and isinstance(e.get("manifest"), dict) for e in envelopes),
            "the chain is a non-empty list of signed envelopes")
    store, held = node.store(), node.documents()
    start = store.load()["epoch"]
    event = {"event": "deliver", "epoch": start}
    try:
        for document in documents:
            held.put(document)
        todo = [e for e in envelopes if e["manifest"].get("epoch", 0) > start]
        require(todo, "this node holds epoch %d already: nothing in the chain is newer" % start)
        for i, envelope in enumerate(todo):
            store.commit(envelope, final=i == len(todo) - 1)
    except Refused as refusal:
        trail(dict(event, outcome="DENY", reason=str(refusal)[:240]))
        raise
    node_module.publish(store, node.path(node_module.PUBLISHED))
    now = store.load()
    trail(dict(event, outcome="ALLOW", epoch=now["epoch"], digest=membership.digest(now), reason="from epoch %d" % start))
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
            node = node_module.Node(node_module.load(args.config))
            given = membership.load(sys.stdin.read(MAX_CHAIN_BYTES + 1).encode(), MAX_CHAIN_BYTES)
            trail = node_module.Trail(node.path("sync-audit.jsonl"), "sync")
            print(json.dumps({"epoch": deliver(node, given["envelopes"], given["documents"], trail)}))
            return 0
        if os.geteuid() != 0:
            print("REFUSED: run as root, on the node", file=sys.stderr)
            return 2
        require(args.chain, "--chain is required")
        with open(args.chain, "rb") as f:
            envelopes = membership.load(f.read(MAX_CHAIN_BYTES + 1), MAX_CHAIN_BYTES)
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
