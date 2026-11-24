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

THE OWNER AS A SINGLE-NODE HOST'S UNLOCK PEER (regalia-kms-dx7.5; ownerunlock.py), off the nodes:

    python3 -Es -m deploy.baremetal.owner contribute --chain CHAIN.json --root-key ROOT --measurements DOC.json --state DIR \\
         --request owner-path-request.json --recipient FPR --recipient FPR --envelope-out ENV.asc --wrapped-out ANSWER.json
    python3 -Es -m deploy.baremetal.owner unlock --contribution-fd 3 3< <(gpg --decrypt ENV.asc) --chain CHAIN.json --root-key ROOT \\
         --measurements DOC.json --state DIR --listen ADDRESS:PORT --module ... --serial ... --key-id ...

contribute answers the node's enrol paths (the enrolment key's fingerprint typed here, as the node's console shows it): the
contribution is minted here, encrypted to both owner cards' decryption subkeys (gpg, the envelope written first) and
wrapped to the node's one-time key. unlock answers every boot: the envelope decrypted with a card onto a pipe, the PIN of
the signing key typed once before anything is served, and one touch for each response. It answers until the operator
stops it (Ctrl-C) or for --serve-for seconds: the exchange has no acknowledgement, so a response sent ends nothing.

--pin-env exists for tests only and is refused unless REGALIA_OWNER_TEST=1 is also set, as manifest.py's.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

from deploy.baremetal import beat, heartbeat, keyfd, membership

Refused, require = membership.Refused, membership.require

SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---- regalia-sync's halves ----

def propose(node, signer, trail):
    """Step 1, as regalia-sync: {"heartbeat", "signatures": [this node's]} for the current manifest, living the owner's
    lifetime. `node` is a node.Node; `signer` its beat.Signer."""
    manifest = node.store().load()
    require(manifest is not None and manifest["schema"] in membership.QUORUM_SCHEMAS, "the owner co-signs heartbeats only under a %s manifest" % membership.SCHEMA_V4)
    require(membership.OWNER in manifest["heartbeat_signers"]["parties"],
            "the owner co-signs heartbeats only when heartbeat_signers names the owner: under epoch %d the nodes sign alone (a "
            "single-node manifest's node signs its own)" % manifest["epoch"])
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


# ---- the owner as the second source of a recovery (#387; recover.py): off the nodes ----

def sign_recovery(peer_chain, root_key, record_lines, purpose, node_id, session, open_signer, confirm, now,
                  witnesses=None, counter_epoch=None, say=print, issued=None,
                  collector_sequence=None):
    """The owner's statement over ONE peer's chain, for recover.py --one-source (or reanchor's), after the owner has judged
    its tip (regalia-kms-d9's conditions, adopted on #387). The counter does not protect a re-anchor, so this does:
      * the tip is not below the highest epoch this machine's manifest signing record (`record_lines`, manifest.py's
        signing-record.jsonl) holds a verified signature for, and the chain holds THAT manifest's exact digest there;
      * where the node's counter is still readable (`counter_epoch`), the tip is not below it;
      * every epoch above that record is SHOWN with its changes (the restrictive ones the nodes made since);
      * the external audit collector (#365) witnesses each node's highest epoch (`witnesses`: a list of
        (export, receipt, keys, identity, stream) for recover.witness_epoch): an epoch above the tip refuses; with no
        witness the operator must type "no collector" as part of the line, and the statement says so to the record;
      * the operator types the line naming the purpose, node, epoch and digest (and "no collector"), after reading
        that the record is a lower bound and being asked for any later revocation they know of.

    Under a single-node tip (the owner-chain path, docs/design/single-node.md 4.7): the collector is MANDATORY
    (decision Q4): a witness is required (no "no collector" escape), the statement is v2 with
    `collector_epoch` bound into it, and `collector_sequence` is also bound (for the recount floor).
    The statement is v2 only under single-node; multi-node keeps v1 and its "no collector" escape.

    The statement expires SESSION_TTL - 60 s after the session was `issued` (the node's authenticated time, which
    `recover session` prints), not by this machine's clock, which an offline laptop may have wrong (d9's read).
    Returns {"statement", "key", "sig"} for the node."""
    from deploy.baremetal import manifest as manifest_tool, recover
    require(purpose in recover.PURPOSES, "the purpose is one of %s" % ", ".join(recover.PURPOSES))
    tip = recover.verify_chain(peer_chain, root_key)
    is_single = membership.profile(tip) == membership.SINGLE_NODE
    signed = [line for line in record_lines if isinstance(line, dict) and line.get("verified") is True and isinstance(line.get("epoch"), int)]
    require(signed, "this machine's signing record holds no verified signature: there is no floor to judge the tip by")
    floor = max(signed, key=lambda line: line["epoch"])
    require(tip["epoch"] >= floor["epoch"], "the peer's tip (epoch %d) is below what this machine signed (epoch %d): refused, an old chain"
            % (tip["epoch"], floor["epoch"]))
    by_epoch = {e["manifest"]["epoch"]: e["manifest"] for e in peer_chain}       # verify_chain held each epoch once, in order
    require(floor["epoch"] in by_epoch and membership.digest(by_epoch[floor["epoch"]]) == floor["digest"],
            "the peer's chain does not hold, at epoch %d, the manifest this machine signed (%s...): another chain" % (floor["epoch"], floor["digest"][:16]))
    if counter_epoch is not None:
        require(tip["epoch"] >= counter_epoch, "the peer's tip (epoch %d) is below the node's counter (%d)" % (tip["epoch"], counter_epoch))
    seen = None
    if witnesses:
        seen = max(recover.witness_epoch(*w) for w in witnesses)
        require(seen <= tip["epoch"], "the audit collector saw epoch %d, above the peer's tip (epoch %d): a revocation withheld" % (seen, tip["epoch"]))
    if is_single and seen is None:
        # under single-node the collector is MANDATORY (decision Q4): no "no collector" escape
        require(False, "under single-node the audit collector is mandatory (docs/design/single-node.md 4.7, decision Q4): "
                "give a --witness (the collector's export and receipt) for this node's sync stream")
    if is_single and purpose == "recount" and collector_sequence is None:
        # for recount, the collector's sequence (beat-propose ALLOW) is also needed
        require(False, "a recount statement under single-node needs the collector's witnessed sequence: "
                "pass collector_sequence (from recover.witness_sequence)")
    lines = ["A %s of node %s%s:" % (purpose.upper(), node_id,
             ", the owner the second source" if not is_single else " from the owner's chain (single-node)"),
             "  the peer's tip       epoch %d, %s" % (tip["epoch"], membership.digest(tip)),
             "  this machine signed  up to epoch %d (%s), a LOWER BOUND: the nodes may have made restrictive changes since" % (floor["epoch"], floor["digest"]),
             "  the audit collector  %s" % ("saw at most epoch %d" % seen if seen is not None else "NOT CONSULTED: type 'no collector' below to go on"),
             "  epochs above what this machine signed:"]
    for i in range(floor["epoch"], tip["epoch"]):
        lines.append("    epoch %d: %s" % (i + 1, "; ".join(manifest_tool.diff(by_epoch[i], by_epoch[i + 1]))))
    if tip["epoch"] == floor["epoch"]:
        lines.append("    none")
    if seen is None and not is_single:
        lines.append("  WITHOUT THE COLLECTOR, a revocation two nodes signed after epoch %d is invisible here: the root never signs it,"
                     % floor["epoch"])
        lines.append("  so it is in no record this machine holds; the peer's tip may be from before it")
    lines.append("  Do you know of any later revocation? If so, stop here.")
    want = "%s %s %d %s%s" % (purpose, node_id, tip["epoch"], membership.digest(tip)[:8],
                              "" if (seen is not None or is_single) else " no collector")
    require((confirm("\n".join(lines) + "\nType exactly: %s\n> " % want) or "").strip() == want,
            "the line typed is not this %s's: nothing is signed" % purpose)
    owners = [e["key"] for e in tip.get("owner_keys", []) if e["alg"] == "ed25519"]
    signer = open_signer()
    require(signer.public() in owners, "the token's key is not one of the tip manifest's owner_keys: nothing is signed")
    st = recover.statement(purpose, node_id, tip, session, (now if issued is None else issued) + recover.SESSION_TTL - 60,
                            collector_epoch=seen if is_single else None,
                            collector_sequence=collector_sequence if (is_single and purpose == "recount") else None)
    say("Touch the key now (it signs when touched).")
    return {"statement": st, "key": signer.public(), "sig": signer.sign(recover.message(st)).hex()}


# ---- the owner as a single-node host's unlock peer (regalia-kms-dx7.5; ownerunlock.py): off the nodes ----

def contribute_path(tip, document, request, fingerprint, state_dir, fingerprints, envelope_out, wrapped_out, run=subprocess.run,
                    rand=os.urandom, say=print):
    """`owner.py contribute`: the owner path of the single-node host that wrote `request` (enrol paths), under `tip`, the
    chain this machine verified. The envelope for the two owner cards is written FIRST (gpg, `envelope_out`), then the
    wrap for the node (`wrapped_out`): a node never holds a path whose contribution the owner could not decrypt again.
    Neither output may exist. Returns the path epoch."""
    from deploy.baremetal import ownerunlock
    for path in (envelope_out, wrapped_out):
        require(not os.path.lexists(path), "%s exists already: nothing was made" % path)
    attester = ownerunlock.verifier(tip, document, os.path.join(state_dir, "attest.json"))
    issued = ownerunlock.IssuedPaths(os.path.join(state_dir, ownerunlock.ISSUED_FILE))
    wrapped, plain = ownerunlock.contribute(tip, request, fingerprint, attester, rand, issued)
    ownerunlock.gpg_encrypt(plain, fingerprints, envelope_out, run)
    del plain
    require(os.path.isfile(envelope_out), "gpg wrote no envelope at %s: nothing was given to the node" % envelope_out)
    fd = os.open(wrapped_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w") as f:
        json.dump(wrapped, f, sort_keys=True)
    say("WRITTEN: %s (keep it: both owner cards decrypt it, at every boot of %s) and %s (carry it to %s's console)"
        % (envelope_out, wrapped["target"], wrapped_out, wrapped["target"]))
    return wrapped["path_epoch"]


def listen_address(text):
    """(family, host, port) of `--listen`: `ADDRESS:PORT`, an IPv6 address in brackets."""
    import re
    import socket
    found = re.fullmatch(r"\[([0-9A-Fa-f:.]{2,45})\]:([0-9]{1,5})|([0-9.]{7,15}):([0-9]{1,5})", text or "")
    require(found is not None, "--listen is ADDRESS:PORT, an IPv6 address in brackets")
    six = found.group(1) is not None
    port = int(found.group(2) if six else found.group(4))
    require(0 <= port <= 65535, "--listen is ADDRESS:PORT, the port 0-65535")
    return (socket.AF_INET6 if six else socket.AF_INET), (found.group(1) if six else found.group(3)), port


SERVE_FOR = 1800                       # owner.py unlock answers for at most this long (s), unless --serve-for says otherwise


def serve_unlock(tip, document, state_dir, decrypted, signer, listener, say=print, serve_for=SERVE_FOR, stop=None, clock=None):
    """`owner.py unlock`: answer the single-node host's unlock requests on `listener` (a bound, listening socket on the
    boot mesh), one connection at a time, as its peer (ownerunlock.OwnerPeer).

    The exchange has no acknowledgement: a reply written in full may still never reach the node (its client may have
    given up, its connection may break), and the node then asks again. So a response SENT does not end the serving: the
    owner answers until stopped (Ctrl-C, or `stop()` true) or for `serve_for` seconds, whichever comes first, and
    stops it once the node's console shows the volume open. Each signed response is a card touch. A response whose
    sending fails is recorded (unlock-send, ERROR). `decrypted` is the envelope as gpg printed it; `signer` an owner
    key. Returns the number of signed responses written in full; refused if none was."""
    import socket
    import time
    from deploy.baremetal import ownerunlock, unlock
    clock = clock or time.monotonic
    stop = stop or (lambda: False)
    contribution = ownerunlock.read_plaintext(decrypted)
    attester = ownerunlock.verifier(tip, document, os.path.join(state_dir, "attest.json"))
    audit = lambda event: say(ownerunlock.printed_event(event))      # noqa: E731
    peer = ownerunlock.OwnerPeer(tip, attester, contribution, signer, audit)
    host, port = listener.getsockname()[:2]
    say("LISTENING for %s (path epoch %d, manifest epoch %d) on %s:%d for at most %d s; touch the key when it blinks, and stop "
        "this (Ctrl-C) once the node's console shows its volume open" % (contribution[0], contribution[1], tip["epoch"], host, port, serve_for))
    until, sent = clock() + serve_for, 0

    def halt_if_latched():
        if peer.halted:
            # the token latched its PIN: it signs nothing more, so serving on would only answer DENIED for ever. The node
            # was told DENIED and nothing else; the owner reads the token's own way out here
            say("HALTED: the owner key signs nothing more: %s" % peer.halted)
            raise Refused("the owner key signs nothing more (its PIN is latched), after %d signed response(s) sent: %s" % (sent, peer.halted))
    # No exchange starts after the window: accept waits at most what is left of it, a connection accepted after it is
    # closed unanswered, and a connection's I/O is bounded by what is left. A token operation already started (the
    # card's touch) is not interrupted: it can outlast the window by its own duration, and no more.
    while not stop() and clock() < until:
        listener.settimeout(max(min(1.0, until - clock()), 0.001))
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break                                        # the listener was closed
        with conn:
            left = until - clock()
            if left <= 0:
                break                                    # arrived after the window: closed unanswered
            reply, failed = None, False
            try:
                deadline = time.monotonic() + min(unlock.IO_TIMEOUT, left)
                conn.settimeout(max(deadline - time.monotonic(), 0.001))
                reply = peer.handle(unlock._read_all(conn, deadline))
                conn.settimeout(max(deadline - time.monotonic(), 0.001))
                conn.sendall(membership.canonical(reply))
            except OSError as error:
                if reply is not None and "response" in reply:
                    audit({"event": "unlock-send", "epoch": tip["epoch"], "manifest_digest": membership.digest(tip), "subject": contribution[0],
                           "peer": unlock.OWNER, "outcome": "ERROR", "reason": "the signed response was not sent (%s): it does not count, "
                           "and the node's next request is answered" % type(error).__name__})
                failed = True
        halt_if_latched()                                # after every connection, sent or not, before the window is looked at
        if not failed and "response" in reply:
            sent += 1
            say("SENT: signed response %d to %s, under manifest epoch %d. The node opens its disk with the first valid one it "
                "receives; if its console does not show the volume open, it asks again and is answered" % (sent, contribution[0], tip["epoch"]))
    require(sent > 0, "no signed response was sent to %s while this ran" % contribution[0])
    say("STOPPED: %d signed response(s) sent to %s" % (sent, contribution[0]))
    return sent


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
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", *membership.handover_env(),
                 sys.executable, "-Es", "-m", "deploy.baremetal.owner", step, "--config", config_path],
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
    v = sub.add_parser("sign-recovery", help="(off the nodes) the owner as the second source of a one-peer recovery, re-anchor, "
                                             "or the single-node recount floor (docs/design/single-node.md 4.7; #387)")
    v.add_argument("--chain", required=True, help="the ONE peer's signed chain, as the node exported it (for recount: this node's own chain)")
    v.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    v.add_argument("--record", required=True, help="this machine's manifest signing record (manifest.py's signing-record.jsonl)")
    v.add_argument("--purpose", required=True, choices=("recover", "reanchor", "recount"))
    v.add_argument("--node-id", required=True, help="the node being recovered")
    v.add_argument("--session", required=True, help="the session the node printed (`recover session`)")
    v.add_argument("--session-issued", type=int, required=True, help="the ISSUED time `recover session` printed (the node's authenticated time)")
    v.add_argument("--counter-epoch", type=int, help="the node's counter, where it is still readable")
    v.add_argument("--witness", action="append", default=[], metavar="EXPORT.json:RECEIPT.json",
                   help="the audit collector's export of a node's sync stream and its signed receipt")
    v.add_argument("--receipt-keys", help="the collector's pinned receipt keys (a JSON list of hex Ed25519 keys)")
    v.add_argument("--collector-identity", help="the collector's identity the receipts name")
    v.add_argument("--stream", action="append", default=[], help="the stream each --witness is of, in order (site-<node>.sync)")
    v.add_argument("--out", required=True)
    for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                     ("--opensc-conf", {}), ("--pin-env", {})):
        v.add_argument(flag, **kw)
    w = sub.add_parser("sign-survivor", help="(off the nodes) the owner's ONE authorization for a lone survivor (D32.6, survivor.py)")
    w.add_argument("--chain", required=True, help="the survivor's signed chain; its tip is the quarantine epoch")
    w.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    w.add_argument("--node-id", required=True, help="the survivor")
    w.add_argument("--how", required=True, help="how the other servers are fenced (powered off, cut off), as the attestation says it")
    w.add_argument("--life-s", type=int, help="at most, and by default, %d s" % 604800)
    w.add_argument("--scope", choices=("stateless", "full"), default="stateless",
                   help="full: stateful operations too, after the wait (the owner's one-server decision, #432)")
    w.add_argument("--fence-evidence", help="the fence step's power readback (JSON, owner.py fence); without it the fence is the typed fallback")
    w.add_argument("--inventory", help="the fence inventory the evidence is checked against (with --fence-evidence)")
    f = sub.add_parser("fence", help="(off the nodes, on the management network) power the fenced servers off through their iLOs (G1, fence.py)")
    f.add_argument("--chain", required=True, help="the survivor's signed chain: a fence is refused under the single-node profile (dx7.3)")
    f.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    f.add_argument("--inventory", required=True, help="the fence inventory: each node's iLO, pinned certificate, serial and UUID")
    f.add_argument("--node", action="append", required=True, help="a node to fence (repeat)")
    f.add_argument("--credentials-fd", type=int, required=True, help="the decrypted fence-only credentials, on a pipe (gpg --decrypt)")
    f.add_argument("--out", required=True)
    w.add_argument("--out", required=True)
    d = sub.add_parser("sign-directive", help="(off the nodes) the owner's disable-only directive during a survivor recovery")
    d.add_argument("--chain", required=True, help="the survivor's signed chain; its tip is the quarantine epoch")
    d.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    d.add_argument("--object-id", required=True)
    d.add_argument("--reason", required=True)
    d.add_argument("--out", required=True)
    for parser_ in (w, d):
        for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                         ("--opensc-conf", {}), ("--pin-env", {})):
            parser_.add_argument(flag, **kw)
    c = sub.add_parser("contribute", help="(off the nodes) a single-node host's owner path: its contribution, for the node and for both owner cards (dx7.5)")
    c.add_argument("--chain", required=True, help="the signed chain this machine holds (a JSON list of envelopes)")
    c.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    c.add_argument("--measurements", required=True, help="the measurement document the chain's tip commits to (policy_version)")
    c.add_argument("--state", required=True, help="this machine's directory for the node's verifier state (its AK, nonces, sessions)")
    c.add_argument("--request", required=True, help="owner-path-request.json, as the node's enrol paths wrote it")
    c.add_argument("--recipient", action="append", default=[], required=True,
                   help="an owner card's decryption subkey fingerprint (the card record's ownerauth_recipients); twice")
    c.add_argument("--envelope-out", required=True, help="the OpenPGP envelope to keep, for both owner cards")
    c.add_argument("--wrapped-out", required=True, help="the answer to carry to the node's console")
    u = sub.add_parser("unlock", help="(off the nodes, on the boot mesh) answer a single-node host's boot unlock as its peer (dx7.5)")
    u.add_argument("--contribution-fd", type=int, required=True,
                   help="the decrypted envelope, on a pipe: --contribution-fd 3 3< <(gpg --decrypt ENVELOPE)")
    u.add_argument("--chain", required=True, help="the signed chain this machine holds (a JSON list of envelopes)")
    u.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    u.add_argument("--measurements", required=True, help="the measurement document the chain's tip commits to (policy_version)")
    u.add_argument("--state", required=True, help="the directory contribute used for this node's verifier state")
    u.add_argument("--listen", required=True, help="ADDRESS:PORT or [IPv6]:PORT on the boot mesh (the boot configuration's owner endpoint)")
    u.add_argument("--serve-for", type=int, default=SERVE_FOR, help="answer for at most this many seconds (default %d); Ctrl-C ends it "
                   "sooner, once the node's console shows its volume open" % SERVE_FOR)
    for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                     ("--opensc-conf", {}), ("--pin-env", {})):
        u.add_argument(flag, **kw)
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
        if args.op == "fence":
            off_the_nodes()
            from deploy.baremetal import fence as fence_tool, manifest as manifest_tool
            # dx7.3: before anything is read or powered off, the profile: one node has no other server to fence
            tip = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), manifest_tool.root_key(args.root_key))
            membership.not_single_node(tip, "a fence")
            boxes = fence_tool.inventory(manifest_tool.read_json(args.inventory, 65536), args.node)
            raw = keyfd.read(args.credentials_fd, "the fence credentials")
            try:
                credentials = json.loads(bytes(raw))
            finally:
                keyfd.zero(raw)
            # the evidence file is reserved BEFORE any server is powered off: an existing path, a missing directory or no
            # permission refuses here, never after the fence ran (CodeRabbit on #516). A fence that refuses leaves no file.
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as out:
                try:
                    evidence = fence_tool.fence(boxes, args.node, credentials)
                except BaseException:
                    os.unlink(args.out)
                    raise
                json.dump(evidence, out, sort_keys=True)
            for nid, seen in sorted(evidence["nodes"].items()):
                print("FENCED: %s Off at %s and again at %s (serial %s, power restore %s)" % (nid, seen["read_at"], seen["read_again_at"],
                                                                                        seen["serial"], seen["power_restore_policy"]))
            print("WRITTEN: %s; carry it to the offline laptop: sign-survivor --fence-evidence %s --inventory <the same inventory>"
                  % (args.out, args.out))
            return 0
        if args.op == "contribute":
            off_the_nodes()
            from deploy.baremetal import manifest as manifest_tool, measurements
            tip = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), manifest_tool.root_key(args.root_key))
            with open(args.measurements, "rb") as f:
                document = measurements.load(f.read(measurements.MAX_BYTES + 1))
            request = manifest_tool.read_json(args.request, 65536)
            typed = keyfd.tty_line("The enrolment key's SHA-256, as the node's console shows it: ")   # never standard input
            contribute_path(tip, document, request, typed, args.state, args.recipient, args.envelope_out, args.wrapped_out)
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
        if args.op == "unlock":
            off_the_nodes()
            import socket
            from deploy.baremetal import manifest as manifest_tool, measurements
            # the decrypted envelope on a pipe, never a file or standard input (keyfd.read, as fence's credentials)
            raw = keyfd.read(args.contribution_fd, "the decrypted contribution")
            decrypted = bytes(raw)
            keyfd.zero(raw)
            tip = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), manifest_tool.root_key(args.root_key))
            with open(args.measurements, "rb") as f:
                document = measurements.load(f.read(measurements.MAX_BYTES + 1))
            family, host, port = listen_address(args.listen)
            # the PIN once, before anything is served: a node's request waits seconds, not for a PIN to be typed
            once = pin()
            signer = p11sign.Pkcs11Signer(args.module, args.serial, args.key_id, None, opensc_conf=args.opensc_conf, key_label=args.key_label,
                                          only_token=True, pin=lambda: once, alg="ed25519")
            require(args.serve_for > 0, "--serve-for is a number of seconds above 0")
            with socket.create_server((host, port), family=family) as listener:
                try:
                    serve_unlock(tip, document, args.state, decrypted, signer, listener, serve_for=args.serve_for)
                except KeyboardInterrupt:
                    print("STOPPED by the operator")
            return 0

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
        if args.op == "sign-recovery":
            off_the_nodes()
            from deploy.baremetal import manifest as manifest_tool
            witnesses = []
            require(len(args.stream) == len(args.witness), "one --stream for each --witness")
            if args.witness:
                require(args.receipt_keys and args.collector_identity, "--witness needs --receipt-keys and --collector-identity")
                keys = manifest_tool.read_json(args.receipt_keys, 65536)
                for pair, stream in zip(args.witness, args.stream):
                    export, _, receipt = pair.partition(":")
                    witnesses.append((manifest_tool.read_json(export, 64 * 1024 * 1024), manifest_tool.read_json(receipt, 65536),
                                      keys, args.collector_identity, stream))
            from deploy.baremetal import cardrecord
            record = cardrecord.read_signing_record(args.record)     # read whole, parsed as every reader of the log does

            def confirm_line(text):
                print(text)
                return keyfd.tty_line("> ")                 # the console's terminal, never standard input
            signed = sign_recovery(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), manifest_tool.root_key(args.root_key), record,
                                   args.purpose, args.node_id, args.session, open_signer, confirm_line, int(time.time()),
                                   witnesses=witnesses, counter_epoch=args.counter_epoch, issued=args.session_issued)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(signed, f, sort_keys=True)
            if args.purpose == "recount":
                print("WRITTEN: %s, valid until %d; give it to the node (recount --owner-statement, single-node: "
                      "docs/design/single-node.md 4.7)" % (args.out, signed["statement"]["expires"]))
            elif signed["statement"].get("collector_epoch") is not None:
                print("WRITTEN: %s, valid until %d; give it to the node (recover apply --owner-chain --owner-statement, "
                      "single-node: docs/design/single-node.md 4.7)" % (args.out, signed["statement"]["expires"]))
            else:
                print("WRITTEN: %s, valid until %d; give it to the node (recover apply --one-source --owner-statement)"
                      % (args.out, signed["statement"]["expires"]))
            return 0
        if args.op in ("sign-survivor", "sign-directive"):
            off_the_nodes()
            from deploy.baremetal import manifest as manifest_tool, survivor

            def confirm_line(text):
                print(text)
                return keyfd.tty_line("> ")                 # the console's terminal, never standard input
            tip = manifest_tool.verify_chain(manifest_tool.read_json(args.chain, 4 * 1024 * 1024), manifest_tool.root_key(args.root_key))
            if args.op == "sign-survivor":
                fence = manifest_tool.read_json(args.fence_evidence, 65536) if args.fence_evidence else None
                boxes = None
                if args.inventory:
                    from deploy.baremetal import fence as fence_tool
                    boxes = fence_tool.inventory(manifest_tool.read_json(args.inventory, 65536))
                signed = survivor.make_authorization(tip, args.node_id, args.how, int(time.time()), confirm_line, open_signer, life_s=args.life_s,
                                                     scope=args.scope, fence=fence, inventory=boxes)
                note = "valid until %s or any new epoch; install it on %s" % (signed["authorization"]["expires_at"], args.node_id)
            else:
                signed = survivor.make_directive(tip, args.object_id, args.reason, int(time.time()), confirm_line, open_signer)
                note = "disabled %s; keep it, give it to the survivor, and to the majority when it returns" % args.object_id
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(signed, f, sort_keys=True)
            print("WRITTEN: %s, %s" % (args.out, note))
            return 0
        beat_by_hand(args.config, open_signer, confirm)
    except (Refused, OSError, ValueError, KeyError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
