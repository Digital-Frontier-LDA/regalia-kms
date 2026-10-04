#!/usr/bin/env python3
"""Membership recovery as a command (#387; MEMBERSHIP-RECOVERY.md is the procedure), and the owner as the second
source when only one other node is left (#199: 2 of {a, b, c, owner}).

    on the node, root at its console:
        python3 -Es -m deploy.baremetal.recover session --config /etc/regalia/node.json
            (prints this operation's session: a fresh nonce and the kernel's boot ID; good for SESSION_TTL seconds)
        python3 -Es -m deploy.baremetal.recover apply --config /etc/regalia/node.json --peer a=CHAIN.json [--peer c=CHAIN.json]
            [--one-source --owner-statement STATEMENT.json]
    on the owner's machine or the offline laptop (owner.py sign-recovery): the owner's statement for --one-source

WHAT IT DOES. convergence.recover, through this node's own Store, as regalia-sync (runuser, as enrol's anchor step):
a node whose store refuses (ROLLBACK, CONFLICT, or the crash window between counter and record) installs a whole
chain its peers give. While the TPM record names the anchored manifest one source is enough; in the crash window
two DIFFERENT nodes that may authorize must agree (membership's rule).

ONE SOURCE IN THE CRASH WINDOW (--one-source) only when one other node is left, and only with the OWNER as the
second source: a statement the owner signed with an approval key, off the nodes (owner.py sign-recovery), over

    PREFIX[purpose] + canonical({"purpose", "node_id", "epoch", "tip_digest", "session", "expires"})

with PREFIX "regalia-recover/v1\\0" or "regalia-reanchor/v1\\0" (never a membership or heartbeat signing input). The
node checks, before anything is changed:
  * the peer's chain verifies from the pinned root, and its tip is the statement's (epoch AND digest);
  * where this node's last known manifest survives on its disk, the chain EXTENDS it: the chain's manifest at that
    epoch has that manifest's exact digest (no fork; owner keys may still have rotated legitimately in between);
  * the owner's key is one of the TIP manifest's owner_keys (root-approved through the chain), the signature
    verifies, and the statement names THIS node, THIS operation's session (the nonce `session` printed, and this
    boot's ID: no replay into another operation or boot) and expires within SESSION_TTL, by authenticated time;
  * no second node that may authorize answers over the service tunnel (else: use two nodes);
  * the operator types the phrase naming the node, the epoch and the digest, at this console's terminal.
Each decision is one event in the node's sync trail (recover), ALLOW or DENY with the reason.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

PURPOSES = ("recover", "reanchor")
PREFIX = {"recover": b"regalia-recover/v1\0", "reanchor": b"regalia-reanchor/v1\0"}
STATEMENT_KEYS = ("purpose", "node_id", "epoch", "tip_digest", "session", "expires")
SESSION_TTL = 900                      # seconds: a statement is good for this one operation, for minutes
SESSION_FILE = "recovery-session.json"
SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAX_CHAIN_BYTES = membership.MAX_CHAIN_BYTES


# ---- the statement ----

def message(statement):
    """What the owner signs: the purpose's own prefix and the canonical statement."""
    membership.exact(statement, STATEMENT_KEYS, "the recovery statement")
    require(statement["purpose"] in PURPOSES, "the purpose is one of %s" % ", ".join(PURPOSES))
    return PREFIX[statement["purpose"]] + membership.canonical(statement)


def statement(purpose, node_id, tip, session, expires):
    return {"purpose": purpose, "node_id": node_id, "epoch": tip["epoch"], "tip_digest": membership.digest(tip),
            "session": session, "expires": int(expires)}


def session_id(session):
    """The session as the statement names it: the node's fresh nonce and its kernel boot ID."""
    return "%s:%s" % (session["nonce"], session["boot_id"])


def verify_chain(chain, root_key, last_known=None):
    """The tip manifest of `chain`, verified from the pinned root; where `last_known` (the node's last known manifest)
    is given, the chain must hold that manifest's exact digest at its epoch."""
    require(isinstance(chain, list) and chain, "the peer's chain is a non-empty list of signed envelopes")
    tip = membership.accept_chain(None, chain, root_key)
    if last_known is not None:
        epoch, digest = last_known["epoch"], membership.digest(last_known)
        require(1 <= epoch <= len(chain) and membership.digest(chain[epoch - 1]["manifest"]) == digest,
                "the peer's chain does not extend this node's last known manifest (epoch %d, %s...): a fork, not a recovery" % (epoch, digest[:16]))
    return tip


def verify_owner(tip, signed, purpose, node_id, session, now):
    """The owner's statement `signed` ({"statement", "key", "sig"}), if it is over this tip, for this node, this
    operation and purpose, unexpired, by one of the tip's owner_keys. Returns the statement."""
    membership.exact(signed, ("statement", "key", "sig"), "the owner's statement")
    st = signed["statement"]
    raw = message(st)
    require(st["purpose"] == purpose, "the statement is for %s, not %s" % (st["purpose"], purpose))
    require(st["node_id"] == node_id, "the statement is for node %s, not this node (%s)" % (st["node_id"], node_id))
    require(st["session"] == session, "the statement is for another operation (session %s): sign this one's" % st["session"])
    require((st["epoch"], st["tip_digest"]) == (tip["epoch"], membership.digest(tip)),
            "the statement is over epoch %s (%s...), not the peer's tip, epoch %d" % (st["epoch"], str(st["tip_digest"])[:16], tip["epoch"]))
    require(isinstance(st["expires"], int) and not isinstance(st["expires"], bool) and now < st["expires"] <= now + SESSION_TTL,
            "the statement has expired, or expires further ahead than %d s" % SESSION_TTL)
    owners = {e["key"]: e["alg"] for e in tip.get("owner_keys", [])}
    require(signed["key"] in owners, "the statement's key is not one of the tip manifest's owner_keys")
    membership.verify_revocation(owners[signed["key"]], signed["key"], raw, signed["sig"], "owner statement")
    return st


# ---- the witness: the external audit collector (#365) ----

def witness_epoch(export, receipt, keys, identity, stream):
    """The highest epoch the collector holds for one node's sync stream, from an export of its committed events
    (`export`: the stream's lines, each the collector's event with its trail line in detail) and the collector's
    signed receipt for its last one, verified against the pinned receipt `keys`. Refused if the export is not what
    the receipt signs (its line chain, its length, its last line)."""
    from deploy.baremetal import trails
    require(isinstance(export, list) and export, "the witness export holds no event")
    chain, top = trails.LINE_CHAIN_START, 0
    for i, event in enumerate(export):
        line = ((event.get("detail") or {}).get("line") or "").encode() + b"\n"
        require((event.get("detail") or {}).get("line_sha256") == hashlib.sha256(line).hexdigest(),
                "witness event %d does not hold the line it names" % (i + 1))
        chain = trails.line_chain(chain, line)
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("outcome") == "ALLOW" and isinstance(value.get("epoch"), int) and not isinstance(value.get("epoch"), bool):
            top = max(top, value["epoch"])
    require(receipt.get("sequence") == len(export) and receipt.get("line_chain") == chain and receipt.get("line_sha256") == hashlib.sha256(line).hexdigest(),
            "the collector's receipt is not for this export (its length, its line chain or its last line)")
    require(trails._receipt_signed(receipt, keys, identity, stream), "the collector's receipt does not verify under the pinned receipt keys")
    return top


# ---- the node ----

def new_session(path, boot_id, rand=os.urandom, now=time.time):
    """This operation's session: a fresh nonce beside the boot ID, written root-only. Returns it."""
    session = {"nonce": rand(16).hex(), "boot_id": boot_id, "issued": int(now())}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(session, f)
    return session


def held_session(path, boot_id, now=time.time):
    try:
        with open(path) as f:
            session = membership.load(f.read(4096))
    except FileNotFoundError:
        raise Refused("no recovery session on this node: run `recover session` first, and sign that one") from None
    membership.exact(session, ("nonce", "boot_id", "issued"), "the recovery session")
    require(session["boot_id"] == boot_id, "the recovery session is from another boot: make a new one")
    require(now() - session["issued"] <= SESSION_TTL, "the recovery session is older than %d s: make a new one" % SESSION_TTL)
    return session


def last_known(path, root_key):
    """The newest manifest this node's own disk still holds that verifies from the root, or None."""
    try:
        with open(path, "rb") as f:
            chain = membership.load(f.read(MAX_CHAIN_BYTES + 1), MAX_CHAIN_BYTES)
        return membership.accept_chain(None, chain, root_key)
    except (OSError, Refused, ValueError, KeyError, TypeError):
        return None


def restore(node, sources, minimum, trail):
    """As regalia-sync: convergence.recover through the node's Store. Returns the epoch it is at."""
    from deploy.baremetal import convergence, node as node_module
    event = {"event": "recover", "sources": sorted(sources), "minimum": minimum}
    try:
        now = convergence.recover(node.store(), sources, minimum=minimum)
    except Refused as refusal:
        trail(dict(event, outcome="DENY", reason=str(refusal)[:240]))
        raise
    node_module.publish(node.store(), node.path(node_module.PUBLISHED))
    trail(dict(event, outcome="ALLOW", epoch=now["epoch"]))
    return now["epoch"]


def second_node_answers(node, tip, peer):
    """Whether a node the tip lets authorize, other than `peer` and this one, answers a pull over the service tunnel."""
    from deploy.baremetal import convergence, sync
    others = [n["node_id"] for n in tip["nodes"] if n["node_id"] not in (node.node_id, peer) and membership.may(tip, n["node_id"], "authorize")]
    try:
        transports = node.sources(tip, timeout=5)
    except Exception:      # noqa: BLE001 - this node cannot even reach its tunnel: nobody answers it
        return []
    answered = []
    for name in others:
        if name in transports:
            try:
                sync.Client(node.node_id, None, None, {name: transports[name]}, lambda event: None)._ask(
                    name, "pull", summary={"epoch": 0, "digest": "00" * 32}, sequence=0)
                answered.append(name)
            except (Refused, OSError, ValueError):
                continue
    return answered


def owner_check(node, signed, purpose, peer, now=None, boot_id=None):
    """The checks this node makes of the owner's statement for a one-source `purpose` from `peer`, as a callable given
    the peer's tip (refuses, or returns the statement): this boot's session, unexpired by authenticated time, the
    statement over that tip by one of its owner_keys, and no second node that may authorize answering."""
    def check(tip):
        if boot_id is None:
            with open("/proc/sys/kernel/random/boot_id") as f:
                booted = f.read().strip()
        else:
            booted = boot_id
        seconds = now() if now else _authenticated_now(node)          # one authenticated time for the session and the statement
        session = held_session(os.path.join(node.cfg["run_dir"], SESSION_FILE), booted, now=lambda: seconds)
        st = verify_owner(tip, signed, purpose, node.node_id, session_id(session), seconds)
        answered = second_node_answers(node, tip, peer)
        require(not answered, "%s answers over the service tunnel: %s from two nodes, not with the owner" % (", ".join(answered), purpose))
        return st
    return check


def apply(config_path, peers, one_source=None, typed=None, run=subprocess.run, now=None):
    """Root at the node's console: check everything, take the operator's typed phrase, then restore as regalia-sync.
    `peers` {node: chain}; `one_source` the owner's signed statement (or None); `typed(prompt)` reads the console."""
    from deploy.baremetal import keyfd, node as node_module
    node = node_module.Node(node_module.load(config_path), run)
    root_key = node.cfg["root_key"]
    require(peers, "at least one --peer NODE=CHAIN.json")
    known = last_known(node.path("membership.json"), root_key)
    tips = {name: verify_chain(chain, root_key, known) for name, chain in peers.items()}
    if one_source is None:
        minimum = None                                  # convergence.recover's rule: 1 while the record pins, else 2
    else:
        require(len(peers) == 1, "--one-source takes exactly one --peer: with two, recover from both")
        (peer, tip), = tips.items()
        owner_check(node, one_source, "recover", peer, now)(tip)
        minimum = 1
    epoch_tip = max(tips.values(), key=lambda m: m["epoch"])
    phrase = "recover %s to epoch %d %s" % (node.node_id, epoch_tip["epoch"], membership.digest(epoch_tip)[:8])
    said = (typed or keyfd.tty_line)("Type exactly: %s\n> " % phrase)
    require(said.strip() == phrase, "the phrase typed is not this recovery's: nothing was changed")
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.recover", "_restore", "--config", config_path],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, input=json.dumps({"sources": peers, "minimum": minimum,
                                                                                    "one_source": one_source is not None}))
    require(done.returncode == 0, "the restore, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    return json.loads(done.stdout.strip().splitlines()[-1])["epoch"]


def _authenticated_now(node):
    from deploy.baremetal import heartbeat
    return heartbeat.authenticated_now(node.clock(), node.tpm_clock(), None)[0]


def main(argv=None):
    from deploy.baremetal import node as node_module
    parser = argparse.ArgumentParser(prog="recover", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="op", required=True)
    s = sub.add_parser("session", help="(root, on the node) a fresh session for this operation")
    s.add_argument("--config", required=True)
    a = sub.add_parser("apply", help="(root, at the node's console) recover this node's membership from its peers")
    a.add_argument("--config", required=True)
    a.add_argument("--peer", action="append", default=[], metavar="NODE=CHAIN.json")
    a.add_argument("--one-source", action="store_true", help="one peer, the owner the second source (needs --owner-statement)")
    a.add_argument("--owner-statement")
    r = sub.add_parser("_restore")
    r.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        if args.op == "_restore":
            import pwd
            require(os.geteuid() == pwd.getpwnam(SYNC_USER).pw_uid, "_restore runs as %s only (apply hands over to it with runuser)" % SYNC_USER)
            node = node_module.Node(node_module.load(args.config))
            given = membership.load(sys.stdin.read(4 * MAX_CHAIN_BYTES + 1).encode(), 4 * MAX_CHAIN_BYTES)
            trail = node_module.Trail(node.path("sync-audit.jsonl"), "sync")
            print(json.dumps({"epoch": restore(node, given["sources"], given["minimum"], trail)}))
            return 0
        if os.geteuid() != 0:
            print("REFUSED: run as root, at the node's console", file=sys.stderr)
            return 2
        cfg = node_module.load(args.config)
        if args.op == "session":
            with open("/proc/sys/kernel/random/boot_id") as f:
                # issued by the same authenticated time the statement is later checked by
                seconds = _authenticated_now(node_module.Node(cfg))
                session = new_session(os.path.join(cfg["run_dir"], SESSION_FILE), f.read().strip(), now=lambda: seconds)
            print("SESSION %s (good for %d s: the owner signs THIS one with owner.py sign-recovery --session)" % (session_id(session), SESSION_TTL))
            return 0
        peers = {}
        for item in args.peer:
            name, _, path = item.partition("=")
            require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name or "") is not None and path, "--peer is NODE=CHAIN.json")
            with open(path, "rb") as f:
                peers[name] = membership.load(f.read(MAX_CHAIN_BYTES + 1), MAX_CHAIN_BYTES)
        statement_doc = None
        if args.one_source:
            require(args.owner_statement, "--one-source needs --owner-statement")
            with open(args.owner_statement, "rb") as f:
                statement_doc = membership.load(f.read(65536))
        print("RECOVERED: this node is at epoch %d" % apply(args.config, peers, statement_doc))
    except (Refused, OSError, ValueError, KeyError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
