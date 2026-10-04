#!/usr/bin/env python3
"""A restrictive membership change without the root (#199 step 4b; the design is on #199): a node QUARANTINED or
REVOKED_STOLEN by two nodes, each on its own local root's request, or by the owner alone. There is no authority host.

    on a first node, root at its console:
        python3 -Es -m deploy.baremetal.revoke propose --config /etc/regalia/node.json --node b --state QUARANTINED --reason "..." --out HALF.json
    on a second node, root at its console (it checks, shows, signs and commits):
        python3 -Es -m deploy.baremetal.revoke cosign  --config /etc/regalia/node.json --envelope HALF.json
    for the owner, off the nodes (regalia-kms-24):
        python3 -Es -m deploy.baremetal.revoke export  --config /etc/regalia/node.json --node b --state REVOKED_STOLEN --reason "..." --out PROPOSAL.json
        (on the owner's machine or the offline laptop: deploy.baremetal.owner sign-manifest, against the chain it holds)
        python3 -Es -m deploy.baremetal.revoke import  --config /etc/regalia/node.json --envelope SIGNED.json

WHAT IS PROPOSED. The current manifest with one node's state made more restrictive (QUARANTINED or REVOKED_STOLEN),
epoch + 1, prev_digest the current digest, issued at authenticated time; everything else unchanged. membership's
rules for a quorum-signed change decide (transition(..., "quorum"): identities, keys, policy and signer rules
unchanged, capabilities only shrink), and are run BEFORE any signature, so nothing a node would refuse is signed.

NEVER AUTOMATIC. Each node's signature comes from root at that node's console: `propose` and `cosign` are commands,
not operations a peer can ask for over the network, and `cosign` SHOWS the change (the node, its state now and after,
the reason, the epoch and the SHA-256 of what is signed) and the operator types the epoch and the digest's first eight
hex digits before the TPM signs. A node signs with its TPM signing key (signkey.py), the same key as its heartbeats
under another domain (membership.DOMAIN), and spends no heartbeat number.

COMMITTING. Once the signatures meet one of the current manifest's revocation_signers rules (two counting nodes, or
the owner alone), the envelope is committed to this node's store AS regalia-sync (runuser, as enrol does: the store
is its own) through membership.Store.commit, and the chain republished; the other nodes pull it, and the nodes' next
heartbeat is for the new epoch (beat.Proposer goes at once when it holds none for it).
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

from deploy.baremetal import beat, membership

Refused, require = membership.Refused, membership.require

RESTRICTIVE = ("QUARANTINED", "REVOKED_STOLEN")
SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def candidate(current, target, state, now):
    """The next manifest: `target` made `state`, epoch + 1, and nothing else changed; checked by membership's quorum
    rules before anybody signs it."""
    require(current is not None and current["schema"] == membership.SCHEMA_V4, "a revocation without the root needs a %s manifest" % membership.SCHEMA_V4)
    require(state in RESTRICTIVE, "a revocation sets %s: anything else is the root's" % " or ".join(RESTRICTIVE))
    nodes = membership.validate(current)
    require(target in nodes, "%s is not in the manifest at epoch %d" % (target, current["epoch"]))
    require(nodes[target]["state"] != state and nodes[target]["state"] not in membership.TERMINAL,
            "%s is already %s" % (target, nodes[target]["state"]))
    nxt = dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current), issued_at=beat.stamp(now),
               nodes=[dict(n, state=state) if n["node_id"] == target else n for n in current["nodes"]])
    membership.transition(current, nxt, "quorum")
    return nxt


def reason_ok(reason):
    require(isinstance(reason, str) and 3 <= len(reason) <= 240 and reason.isprintable(), "a revocation needs a reason (3 to 240 printable characters)")
    return reason


def shown(current, manifest, reason=None):
    """What the operator reads before a signature, and the digest whose first eight hex digits they type."""
    digest = hashlib.sha256(membership.DOMAIN + membership.canonical(manifest)).hexdigest()
    before = {n["node_id"]: n["state"] for n in current["nodes"]}
    changed = ["%s: %s -> %s" % (n["node_id"], before[n["node_id"]], n["state"]) for n in manifest["nodes"] if before.get(n["node_id"]) != n["state"]]
    text = "A REVOCATION to sign:\n  epoch      %d -> %d\n  change     %s\n%s  signs      SHA-256 %s" % (
        current["epoch"], manifest["epoch"], "; ".join(changed) or "none", "  reason     %s\n" % reason if reason else "", digest)
    return text, digest


def confirmed(manifest, digest, typed):
    words = (typed or "").strip().lower().split()
    return len(words) == 2 and words[0] == str(manifest["epoch"]) and len(words[1]) == 8 and all(c in "0123456789abcdef" for c in words[1]) \
        and digest.startswith(words[1])


def node_signature(node_id, sign, manifest):
    """This node's signature over the manifest, by its TPM signing key (`sign(message)`: r || s hex)."""
    return {"party": node_id, "key": None, "sig": sign(membership.DOMAIN + membership.canonical(manifest))}


def counts(current, node_id):
    """Whether `node_id`'s signature counts toward one of the current manifest's revocation rules."""
    nodes = membership.validate(current)
    return node_id in nodes and "signing_key" in nodes[node_id] and nodes[node_id]["state"] not in membership.NOT_COUNTING \
        and any(node_id in rule["parties"] for rule in current["revocation_signers"])


def met(current, envelope):
    """Whether the envelope's signatures meet one of the current manifest's revocation_signers rules (each signature
    checked as membership checks it; one that does not verify is a refusal, not a non-count)."""
    parties = membership.counting_parties(current, membership.DOMAIN + membership.canonical(envelope["manifest"]), envelope["signatures"], "manifest")
    return any(membership.meets(rule, parties) for rule in current["revocation_signers"]), parties


def cosign(current, envelope, node_id, key, sign, confirm):
    """Root at the second node: the half-signed `envelope` checked against THIS node's current manifest, shown and
    confirmed, then signed by this node. Returns the envelope with its signature added."""
    require(counts(current, node_id), "%s does not count toward any revocation rule under epoch %d: it signs nothing" % (node_id, current["epoch"]))
    require(isinstance(envelope, dict) and set(envelope) == {"manifest", "signatures", "reason"}, "not a half-signed revocation")
    reason_ok(envelope["reason"])
    manifest = envelope["manifest"]
    membership.transition(current, manifest, "quorum")
    require(manifest["epoch"] == current["epoch"] + 1, "the revocation is not for the next epoch of this node's manifest")
    require(all(s.get("party") != node_id for s in envelope["signatures"]), "%s has signed this revocation already" % node_id)
    met(current, {"manifest": manifest, "signatures": envelope["signatures"]})          # what is there verifies
    text, digest = shown(current, manifest, envelope["reason"])
    require(confirmed(manifest, digest, confirm(text)), "the epoch and digest typed are not this revocation's: nothing is signed")
    mine = dict(node_signature(node_id, sign, manifest), key=key)
    return dict(envelope, signatures=envelope["signatures"] + [mine])


def commit_as_sync(config_path, envelope, run=subprocess.run):
    """Store.commit of the full envelope as regalia-sync, and the chain republished. Returns the new epoch."""
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.revoke", "_commit", "--config", config_path],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, input=json.dumps({"manifest": envelope["manifest"], "signatures": envelope["signatures"]}))
    require(done.returncode == 0, "the commit, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    return json.loads(done.stdout.strip().splitlines()[-1])["epoch"]


def commit(node, envelope, trail):
    """As regalia-sync: the envelope into the store (membership's rules decide), the chain republished."""
    from deploy.baremetal import node as node_module
    store = node.store()
    event = {"event": "revoke-commit", "epoch": envelope.get("manifest", {}).get("epoch"),
             "signers": sorted(s.get("party", "?") for s in envelope.get("signatures", []) if isinstance(s, dict))}
    try:
        nxt = store.commit(envelope)
    except Refused as refusal:
        trail(dict(event, outcome="DENY", reason=str(refusal)[:240]))
        raise
    node_module.publish(store, node.path(node_module.PUBLISHED))
    trail(dict(event, outcome="ALLOW", digest=membership.digest(nxt)))
    return nxt


def main(argv=None):
    from deploy.baremetal import node as node_module
    parser = argparse.ArgumentParser(prog="revoke", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="op", required=True)
    for name in ("propose", "export"):
        p = sub.add_parser(name)
        p.add_argument("--config", required=True)
        p.add_argument("--node", required=True)
        p.add_argument("--state", required=True, choices=RESTRICTIVE)
        p.add_argument("--reason", required=True)
        p.add_argument("--out", required=True)
    for name in ("cosign", "import"):
        p = sub.add_parser(name)
        p.add_argument("--config", required=True)
        p.add_argument("--envelope", required=True)
    p = sub.add_parser("_commit")
    p.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        node = node_module.Node(node_module.load(args.config))
        if args.op == "_commit":
            envelope = membership.load(sys.stdin.read(membership.MAX_BYTES + 1).encode())
            trail = node_module.Trail(node.path("sync-audit.jsonl"), "sync")
            print(json.dumps({"epoch": commit(node, envelope, trail)["epoch"]}))
            return 0
        if os.geteuid() != 0:
            print("REFUSED: run as root, at the node's console", file=sys.stderr)
            return 2
        current = node.manifest()
        if args.op in ("propose", "export"):
            nxt = candidate(current, args.node, args.state, beat._now(node.clock()))
            out = {"manifest": nxt, "signatures": [], "reason": reason_ok(args.reason)}
            if args.op == "propose":
                require(counts(current, node.node_id), "%s does not count toward any revocation rule: it signs nothing" % node.node_id)
                signer = node_module.node_beat_signer(node)
                text, digest = shown(current, nxt, args.reason)
                print(text)
                require(confirmed(nxt, digest, input("Type the epoch and the first 8 hex digits of the SHA-256: ")),
                        "the epoch and digest typed are not this revocation's: nothing is signed")
                out["signatures"].append(dict(node_signature(node.node_id, signer._sign, nxt), key=signer.key))
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(out, f, sort_keys=True)
            print("WRITTEN: %s (%s)" % (args.out, "signed by %s; co-sign it on a second node" % node.node_id if args.op == "propose"
                                        else "unsigned; the owner signs it off the nodes"))
            return 0
        with open(args.envelope, "rb") as f:
            envelope = membership.load(f.read(membership.MAX_BYTES + 1))
        if args.op == "cosign":
            signer = node_module.node_beat_signer(node)
            envelope = cosign(current, envelope, node.node_id, signer.key, signer._sign, lambda text: (print(text), input(
                "Type the epoch and the first 8 hex digits of the SHA-256: "))[1])
        full = {"manifest": envelope["manifest"], "signatures": envelope["signatures"]}
        enough, parties = met(current, full)
        require(enough, "the signatures (%s) meet no revocation rule of the current manifest: nothing is committed"
                % (", ".join(sorted(parties)) or "none"))
        print("COMMITTED: epoch %d" % commit_as_sync(args.config, full))
    except (Refused, OSError, ValueError, KeyError, EOFError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
