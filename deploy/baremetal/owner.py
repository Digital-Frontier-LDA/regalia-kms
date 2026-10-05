#!/usr/bin/env python3
"""The owner's co-signature of a heartbeat, for a hand recovery (#199 step 4a; the design is on #199).

    sudo python3 -Es -m deploy.baremetal.owner beat --config /etc/regalia/node.json --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \\
         --serial 35718625 --key-id 03 [--opensc-conf FILE]
    python3 -Es -m deploy.baremetal.owner sign-manifest --chain CHAIN.json --root-key ROOT --proposal PROPOSAL.json --out SIGNED.json \\
         --module ... --serial ... --key-id ...        (off the nodes: the owner's machine or the offline laptop; revoke.py)

WHEN. After a total outage, one node is opened by hand with its recovery key. It holds no live heartbeat, and no
other node is up to co-sign one, so it authorizes no unlock and the cluster stays down. The operator, at that node's
console, makes this node and the owner the two signers a v4 heartbeat needs: the node's TPM signing key and one of
the owner's approval YubiKeys (Ed25519, OpenPGP applet, through OpenSC with CKM_EDDSA). The heartbeat lives at most
the manifest's owner_heartbeat_lifetime_s (heartbeat.verify's cap; 1 h by the genesis default, which a manifest may set
from 300 s up to heartbeat_max_lifetime_s): long enough for the node to unlock the other
two, after which the nodes sign their own 6 h heartbeats again (beat.Proposer).

HOW, three steps, as `enrol` splits its work between root and regalia-sync:
  1. as regalia-sync (runuser; it owns the heartbeat state and the signing counter): `_propose` makes the body for the
     current manifest, reserves its sequence on the signing counter, signs it with the TPM key, and prints both;
  2. as root, at the console: the body is SHOWN (epoch, sequence, issue and expiry, lifetime) with the SHA-256 of what
     is signed, and the operator TYPES the epoch and the digest's first eight hex digits before the PIN is asked for
     (the YubiKey has no display: its touch proves a person is present, not what was signed; regalia-kms-24). The
     token is chosen by serial (p11sign.Pkcs11Signer, in process: the PIN is in no argv and no child's environment,
     typed with no echo) and its key must be one of the current manifest's owner_keys, checked before the PIN;
  3. as regalia-sync: `_accept` takes {heartbeat, signatures: [node, owner]} into this node's Freshness, whose
     heartbeat.verify applies the quorum and the owner's cap. Peers pull it from here.
Each step is one event in this node's sync trail (owner-beat-propose, owner-beat).

HARM BOUND, stated (regalia-kms-24): a compromised node with the owner at its console obtains at most one owner
co-signature on a heartbeat that lives at most owner_heartbeat_lifetime_s, for the manifest it already has. The owner's
key alone meets no rule that adds, restores or re-keys a node; that is the root's alone (membership's transitions).

--pin-env exists for tests only and is refused unless REGALIA_OWNER_TEST=1 is also set, as manifest.py's.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

from deploy.baremetal import beat, heartbeat, keyfd, membership

Refused, require = membership.Refused, membership.require

SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---- regalia-sync's halves ----

def propose(node, signer, trail):
    """Step 1, as regalia-sync: {"heartbeat", "signatures": [this node's]} for the current manifest, living the owner's
    lifetime. `node` is a node.Node; `signer` its beat.Signer."""
    manifest = node.store().load()
    require(manifest is not None and manifest["schema"] == membership.SCHEMA_V4, "the owner co-signs heartbeats only under a %s manifest" % membership.SCHEMA_V4)
    require(node.node_id in beat.counting_nodes(manifest), "%s does not count toward heartbeat_signers under epoch %d" % (node.node_id, manifest["epoch"]))
    freshness = node.freshness()
    now = beat._now(node.clock())
    sequence = max(beat.held_sequence(freshness, manifest) or 0, freshness.counter.value(), signer.signed()) + 1
    lifetime = manifest["owner_heartbeat_lifetime_s"]
    body = {"schema": heartbeat.SCHEMA, "epoch": manifest["epoch"], "sequence": sequence, "issued_at": beat.stamp(now),
            "expires_at": beat.stamp(now + lifetime), "manifest_digest": membership.digest(manifest)}
    mine = signer(body, manifest)
    trail({"event": "owner-beat-propose", "outcome": "ALLOW", "epoch": manifest["epoch"], "sequence": sequence, "expires_at": body["expires_at"]})
    return {"heartbeat": body, "signatures": [mine]}


def accept(node, envelope, trail):
    """Step 3, as regalia-sync: the envelope this node proposed, with the owner's signature added, into its Freshness.
    Returns the seconds it has left."""
    manifest = node.store().load()
    event = {"event": "owner-beat", "epoch": manifest["epoch"] if manifest else 0}
    try:
        require(isinstance(envelope, dict) and isinstance(envelope.get("signatures"), list), "not a heartbeat envelope")
        parties = [s.get("party") for s in envelope["signatures"] if isinstance(s, dict)]
        require(parties == [node.node_id, membership.OWNER], "the envelope must be signed by this node and the owner, in that order (it names %s)" % parties)
        event["sequence"] = envelope.get("heartbeat", {}).get("sequence")
        left = node.freshness().accept(envelope, manifest)
    except Refused as refusal:
        trail(dict(event, outcome="DENY", reason=str(refusal)[:240]))
        raise
    trail(dict(event, outcome="ALLOW", left=int(left)))
    return left


# ---- a revocation the owner signs alone, off the nodes (revoke.py export / import; regalia-kms-24) ----

def sign_manifest(current, proposal, open_signer, confirm, say=print):
    """The owner's signature over a revocation `proposal` (revoke.py export: {"manifest", "signatures": [], "reason"}),
    judged against `current`, the tip of the chain THIS machine verified from the root key (never the node's word):
    membership's quorum rules first, then shown and confirmed, then signed. Returns the envelope to import on a node."""
    from deploy.baremetal import revoke
    require(isinstance(proposal, dict) and set(proposal) == {"manifest", "signatures", "reason"} and proposal["signatures"] == [],
            "not an unsigned revocation proposal (revoke.py export)")
    manifest = proposal["manifest"]
    membership.transition(current, manifest, "quorum")
    require(manifest["epoch"] == current["epoch"] + 1, "the proposal is not for the next epoch of the chain given (%d)" % current["epoch"])
    owners = [e["key"] for e in current["owner_keys"] if e["alg"] == "ed25519"]
    signer = open_signer()
    require(signer.public() in owners, "the token's key %s... is not one of the manifest's owner_keys: nothing is signed" % signer.public()[:16])
    text, digest = revoke.shown(current, manifest, proposal["reason"])
    require(revoke.confirmed(manifest, digest, confirm(text)), "the epoch and digest typed are not this revocation's: nothing is signed")
    say("Touch the key now (it signs when touched).")
    sig = signer.sign(membership.DOMAIN + membership.canonical(manifest)).hex()
    envelope = dict(proposal, signatures=[{"party": membership.OWNER, "key": signer.public(), "sig": sig}])
    enough, _ = revoke.met(current, {"manifest": manifest, "signatures": envelope["signatures"]})
    require(enough, "the owner's signature meets no revocation rule of the current manifest")
    return envelope


# The marks of a KMS node: its configuration and its installed services. The owner's revocation signature is made off
# the nodes, so that no node's root can watch the token session (regalia-kms-24, 51's read).
NODE_MARKS = ("/etc/regalia/node.json", "/usr/lib/systemd/system/regalia-sync.service", "/etc/systemd/system/regalia-sync.service")


def off_the_nodes(marks=NODE_MARKS):
    found = [p for p in marks if os.path.exists(p)]
    require(not found, "this is a KMS node (%s): the owner signs a revocation off the nodes, on the owner's machine or the "
            "offline laptop" % ", ".join(found))


# ---- root's half ----

def shown(body):
    """What the operator reads before the touch, and the digest whose first eight hex digits they type."""
    digest = hashlib.sha256(heartbeat.DOMAIN + membership.canonical(body)).hexdigest()
    issued, expires = heartbeat.validate(body)
    text = ("A HEARTBEAT for this node and the owner to sign:\n  epoch      %d\n  sequence   %d\n  issued     %s\n  expires    %s  (lives %d s)\n"
            "  manifest   %s\n  signs      SHA-256 %s" % (body["epoch"], body["sequence"], body["issued_at"], body["expires_at"], expires - issued,
                                                         body["manifest_digest"], digest))
    return text, digest


def confirmed(body, typed):
    """The operator's typed line ("<epoch> <first 8 hex of the digest>") matches `body`."""
    _, digest = shown(body)
    words = (typed or "").strip().lower().split()
    return len(words) == 2 and words[0] == str(body["epoch"]) and re.fullmatch(r"[0-9a-f]{8}", words[1]) is not None and digest.startswith(words[1])


def owner_sign(proposal, manifest, open_signer, confirm, say=print):
    """Step 2, as root: the owner's signature over the proposal's body, after the operator confirmed it. `open_signer()`
    returns a p11sign.Pkcs11Signer with alg="ed25519" (its public key is read with no PIN); `confirm(text)` returns
    the typed line. Refused, with nothing signed, if the key is not one of the manifest's owner_keys or the line does
    not match."""
    body = proposal["heartbeat"]
    require(body["epoch"] == manifest["epoch"] and body["manifest_digest"] == membership.digest(manifest),
            "the proposal is not for this node's current manifest (epoch %d)" % manifest["epoch"])
    owners = [e["key"] for e in manifest["owner_keys"] if e["alg"] == "ed25519"]
    signer = open_signer()
    require(signer.public() in owners, "the token's key %s... is not one of the manifest's owner_keys: nothing is signed" % signer.public()[:16])
    text, _ = shown(body)
    require(confirmed(body, confirm(text)), "the epoch and digest typed are not this heartbeat's: nothing is signed")
    say("Touch the key now (it signs when touched).")
    sig = signer.sign(heartbeat.DOMAIN + membership.canonical(body)).hex()
    return dict(proposal, signatures=proposal["signatures"] + [{"party": membership.OWNER, "key": signer.public(), "sig": sig}])


def _as_sync(step, config_path, run, stdin=None):
    """`python3 -m deploy.baremetal.owner <step>` as regalia-sync with the tss group (the TPM), nothing of root's
    environment, from the package root; its last line is a JSON result."""
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.owner", step, "--config", config_path],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, input=stdin if stdin is not None else "")
    require(done.returncode == 0, "the %s step, as %s, did not finish: %s" % (step, SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    return json.loads(done.stdout.strip().splitlines()[-1])


def beat_by_hand(config_path, open_signer, confirm, run=subprocess.run, say=print):
    """The three steps, from root at the console."""
    from deploy.baremetal import node as node_module
    node = node_module.Node(node_module.load(config_path), run)
    manifest = node.manifest()                          # the published chain, verified from the root key and the anchor
    proposal = _as_sync("_propose", config_path, run)
    envelope = owner_sign(proposal, manifest, open_signer, confirm, say)
    result = _as_sync("_accept", config_path, run, stdin=json.dumps(envelope))
    say("OK: heartbeat %d accepted by this node, %d s left; the peers take it from here" % (envelope["heartbeat"]["sequence"], result["left"]))
    return envelope


def main(argv=None):
    from deploy.baremetal import node as node_module, p11sign
    parser = argparse.ArgumentParser(prog="owner", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="op", required=True)
    b = sub.add_parser("beat", help="(root, at the node's console) a heartbeat signed by this node and the owner")
    b.add_argument("--config", required=True)
    b.add_argument("--module", required=True, help="the PKCS#11 module (OpenSC's)")
    b.add_argument("--serial", required=True, help="the approval YubiKey's serial")
    b.add_argument("--key-id", help="the key's CKA_ID, hex")
    b.add_argument("--key-label", help="the key's CKA_LABEL")
    b.add_argument("--opensc-conf")
    b.add_argument("--pin-env", help="tests only (REGALIA_OWNER_TEST=1): the PIN from this environment variable")
    k = sub.add_parser("sign-manifest", help="(off the nodes) the owner's signature over a revocation proposal")
    k.add_argument("--chain", required=True, help="the signed chain this machine holds (a JSON list of envelopes)")
    k.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    k.add_argument("--proposal", required=True)
    k.add_argument("--out", required=True)
    for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                     ("--opensc-conf", {}), ("--pin-env", {})):
        k.add_argument(flag, **kw)                  # the same token options as `beat`
    v = sub.add_parser("sign-activation", help="(off the nodes) the owner's RECOVERY AUTHORIZATION (#432): one node left activates "
                       "itself, renewing its own leases, until it expires or any new epoch")
    v.add_argument("--chain", required=True, help="the surviving node's signed chain (a JSON list of envelopes)")
    v.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    v.add_argument("--survivor", required=True, help="the node to activate")
    v.add_argument("--site", required=True, help="its registry site")
    v.add_argument("--registry-digest", required=True, help="sha256:<64 hex>, the registry's digest")
    v.add_argument("--record", required=True, help="the survivor's grant record, exported from it (activation-grant.json)")
    v.add_argument("--life-s", type=int, help="the authorization's life, at most (and by default) the manifest's recovery_authorization_max_s")
    v.add_argument("--witness-latest", type=int, help="the latest activation expiry the audit collector holds, when consulted")
    v.add_argument("--out", required=True)
    for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                     ("--opensc-conf", {}), ("--pin-env", {})):
        v.add_argument(flag, **kw)
    for name in ("_propose", "_accept"):
        s = sub.add_parser(name)
        s.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        if args.op in ("_propose", "_accept"):
            node = node_module.Node(node_module.load(args.config))
            trail = node_module.Trail(node.path("sync-audit.jsonl"), "sync")
            if args.op == "_propose":
                print(json.dumps(propose(node, node_module.node_beat_signer(node), trail)))
            else:
                envelope = membership.load(sys.stdin.read(heartbeat.MAX_BYTES + 1).encode(), heartbeat.MAX_BYTES)
                print(json.dumps({"left": int(accept(node, envelope, trail))}))
            return 0
        if args.op == "beat" and os.geteuid() != 0:
            print("REFUSED: run as root, at the node's console", file=sys.stderr)
            return 2
        if args.pin_env:
            require(os.environ.get("REGALIA_OWNER_TEST") == "1", "--pin-env is for tests only (REGALIA_OWNER_TEST=1)")
            pin = lambda: os.environ[args.pin_env]      # noqa: E731
        else:
            def pin():
                # the console's terminal only, echo off; never standard input (the stdlib prompt's fallback echoes) (51's read)
                typed = keyfd.tty_secret("The approval key's PIN (not shown): ", "the PIN", limit=64)
                try:
                    return typed.decode("ascii")
                finally:
                    keyfd.zero(typed)

        def open_signer():
            return p11sign.Pkcs11Signer(args.module, args.serial, args.key_id, None, opensc_conf=args.opensc_conf, key_label=args.key_label,
                                          only_token=True, pin=pin, alg="ed25519")

        def confirm(text):
            print(text)
            return keyfd.tty_line("Type the epoch and the first 8 hex digits of the SHA-256: ")   # never standard input
        if args.op == "sign-manifest":
            off_the_nodes()
            from deploy.baremetal import manifest as manifest_tool
            root = manifest_tool.root_key(args.root_key)
            current = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), root)
            envelope = sign_manifest(current, manifest_tool.read_json(args.proposal, membership.MAX_BYTES), open_signer, confirm)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(envelope, f, sort_keys=True)
            print("WRITTEN: %s, signed by the owner; import it on a node (revoke.py import)" % args.out)
            return 0
        if args.op == "sign-activation":
            off_the_nodes()
            import time
            from deploy.baremetal import activation, manifest as manifest_tool
            root = manifest_tool.root_key(args.root_key)
            tip = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), root)
            record = manifest_tool.read_json(args.record, 4096)
            # what was done to the other nodes: typed at this terminal, recorded in the lease, never on the command line
            how = keyfd.tty_line("How are the other nodes fenced (powered off at..., cut from...)? ")

            def confirm_line(text):
                print(text)
                return keyfd.tty_line("> ")
            envelope = activation.owner_recovery_authorization(tip, args.survivor, args.site, args.registry_digest, record, how,
                                                               int(time.time()), confirm_line, open_signer, life_s=args.life_s,
                                                               witness_latest=args.witness_latest)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(envelope, f, sort_keys=True)
            print("WRITTEN: %s, the owner's recovery authorization for %s until %s (or the next epoch); install it at the "
                  "survivor's console (activation recover)" % (args.out, args.survivor, envelope["authorization"]["expires_at"]))
            return 0
        beat_by_hand(args.config, open_signer, confirm)
    except (Refused, OSError, ValueError, KeyError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
