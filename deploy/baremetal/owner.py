#!/usr/bin/env python3
"""The owner's co-signature of a heartbeat, for a hand recovery (#199 step 4a; the design is on #199).

    sudo python3 -Es -m deploy.baremetal.owner beat --config /etc/regalia/node.json --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \\
         --serial 35718625 --key-id 03 [--opensc-conf FILE]

WHEN. After a total outage, one node is opened by hand with its recovery key. It holds no live heartbeat, and no
other node is up to co-sign one, so it authorizes no unlock and the cluster stays down. The operator, at that node's
console, makes this node and the owner the two signers a v4 heartbeat needs: the node's TPM signing key and one of
the owner's approval YubiKeys (Ed25519, OpenPGP applet, through OpenSC with CKM_EDDSA). The heartbeat lives at most
the manifest's owner_heartbeat_lifetime_s (1 h, heartbeat.verify's cap): long enough for the node to unlock the other
two, after which the nodes sign their own 6 h heartbeats again (beat.Proposer).

HOW, three steps, as `enrol` splits its work between root and regalia-sync:
  1. as regalia-sync (runuser; it owns the heartbeat state and the signing counter): `_propose` makes the body for the
     current manifest, reserves its sequence on the signing counter, signs it with the TPM key, and prints both;
  2. as root, at the console: the body is SHOWN (epoch, sequence, issue and expiry, lifetime) with the SHA-256 of what
     is signed, and the operator TYPES the epoch and the digest's first eight hex digits before the PIN is asked for
     (the YubiKey has no display: its touch proves a person is present, not what was signed; regalia-kms-24). The
     token is chosen by serial (authority.Pkcs11Signer, in process: the PIN is in no argv and no child's environment,
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
import getpass
import hashlib
import json
import os
import re
import subprocess
import sys

from deploy.baremetal import beat, heartbeat, membership

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
    returns an authority.Pkcs11Signer with alg="ed25519" (its public key is read with no PIN); `confirm(text)` returns
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
    from deploy.baremetal import authority, node as node_module
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
        if os.geteuid() != 0:
            print("REFUSED: run as root, at the node's console", file=sys.stderr)
            return 2
        if args.pin_env:
            require(os.environ.get("REGALIA_OWNER_TEST") == "1", "--pin-env is for tests only (REGALIA_OWNER_TEST=1)")
            pin = lambda: os.environ[args.pin_env]      # noqa: E731
        else:
            pin = lambda: getpass.getpass("The approval key's PIN (not shown): ")      # noqa: E731

        def open_signer():
            return authority.Pkcs11Signer(args.module, args.serial, args.key_id, None, opensc_conf=args.opensc_conf, key_label=args.key_label,
                                          only_token=True, pin=pin, alg="ed25519")

        def confirm(text):
            print(text)
            require(sys.stdin.isatty() or args.pin_env, "the confirmation is typed at the console; standard input is not a terminal")
            return input("Type the epoch and the first 8 hex digits of the SHA-256, e.g. '%s 1a2b3c4d': " % "N")
        beat_by_hand(args.config, open_signer, confirm)
    except (Refused, OSError, ValueError, KeyError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
