#!/usr/bin/env python3
"""The peer's side of a node's enrolment (#190, design steps 6 and 7): what a running node decides when a node the
manifest names asks it, over the service tunnel (sync.py), to enrol its AK and to give it a LUKS path.

    challenge(...)      the AK enrolment challenge, against the AK Name the manifest gives the caller
    contribution(...)   this peer's contribution for the caller's LUKS path, wrapped to an enrolment key the
                        caller's TPM vouched for in a quote of its current boot session

THE TRUST IS THE MANIFEST'S. The caller is the node the tunnel identified (sync.Server: its WireGuard key, pinned
by the CURRENT manifest); its EK and AK are the manifest's (Verifier.challenge with ak_name); its quote is over
its boot session, this peer's nonce (single use, expiring) and this peer's manifest epoch, in the SYSTEM phase,
against the measurements that manifest commits to; and the enrolment key is bound into that quote
(attest.transcript's binding field). Nobody types a fingerprint.

WHO GETS A CONTRIBUTION. This peer only while it may itself authorize and holds a live heartbeat (the same
freshness a lease needs: heartbeat.Freshness.live_until), and only for a node that may request an unlock.

ONE SECRET PER PATH. A path (target, path epoch) has ONE secret, minted once (unlock.Contributions.mint). A
target that asks again, because it crashed between this answer and its LUKS token, gets the SAME secret
re-wrapped to its new enrolment key, never a second one. The path epoch is the manifest's epoch, or the latest
held for the target when that is newer.

A CAPPED WRAP JOURNAL. Every wrap is recorded, per (target, boot session), before it is answered, in a 0600 file
beside the contributions; the fourth in one boot session is refused, and names the operator step. A target in a
loop cannot make this peer hand out wraps without end; a reboot (a new boot session) is a new allowance, and
each of its requests is a fresh attested one.
"""
import contextlib
import hashlib
import os
import tempfile

from deploy.baremetal import attest, lease, membership, unlock

Refused, require = membership.Refused, membership.require

WRAPS_SCHEMA = "regalia.enrol-wraps/v1"
WRAP_CAP = 3                 # wraps per (target, boot session)
SESSIONS_KEPT = 8            # boot sessions remembered per target: the oldest goes first, so the journal stays small
MAX_BYTES = 64 * 1024


class Peer:
    """What sync.Server needs to answer the enrolment operations: this node's contribution store, its wrap
    journal, `identity()` -> (EK public area, AK public area) of its own TPM, and `activate(credential)` ->
    the secret its TPM releases for a credential made to its EK and AK (attest.node_activate)."""

    def __init__(self, contributions, wraps, identity, activate):
        self.contributions, self.wraps, self.identity, self.activate = contributions, wraps, identity, activate


def challenge(attester, manifest, caller, ek_public, ak_public):
    """The AK enrolment challenge for `caller`, or None when its AK is enrolled here already as the manifest's.
    An AK whose Name is not the manifest's is refused before anything is made (Verifier.challenge, ak_name);
    a DIFFERENT AK already enrolled for the caller is refused too: that is a replacement (#76), not an enrolment."""
    nodes = membership.validate(manifest)
    require(caller in nodes, "%s is not in the manifest" % caller)
    expected = nodes[caller]["ak_name"]
    if attester.enrolled(caller) == expected and attest.ak_identity(ak_public)[0].hex() == expected:
        return None
    return attester.challenge(caller, ek_public, ak_public, replace=False, ak_name=expected)


class Wraps:
    """{target: {sha256(boot session): {"epoch": path epoch, "wraps": n, "seq": order}}}, one 0600 file, changed
    under a lock. Only the SESSIONS_KEPT latest sessions of a target are kept: a session older than that is a
    boot long past, whose own cap no longer matters (check_counters refuses its session anyway), and a journal
    that only grew would one day be too large to read and stop every enrolment."""

    def __init__(self, path):
        self.path = path

    def _read(self):
        try:
            with open(self.path, "rb") as f:
                require(os.fstat(f.fileno()).st_mode & 0o077 == 0, "%s is readable by others than its owner" % self.path)
                state = membership.load(f.read(MAX_BYTES + 1), MAX_BYTES)
        except FileNotFoundError:
            return {"schema": WRAPS_SCHEMA, "targets": {}}
        membership.exact(state, ("schema", "targets"), "wraps")
        require(state["schema"] == WRAPS_SCHEMA and isinstance(state["targets"], dict), "wraps: schema must be %s" % WRAPS_SCHEMA)
        return state

    def _write(self, state):
        directory = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".enrol-wraps-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(membership.canonical(state))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def record(self, target, session_id, epoch):
        """One more wrap for `target` in boot session `session_id` at path epoch `epoch`: recorded, or refused
        once WRAP_CAP were given in that session. Recorded BEFORE the wrap is answered."""
        session = hashlib.sha256(bytes.fromhex(session_id)).hexdigest()
        with membership._exclusive(self.path + ".lock"):
            state = self._read()
            mine = state["targets"].setdefault(target, {})
            seq = 1 + max([e.get("seq", 0) for e in mine.values()] + [0])
            entry = mine.setdefault(session, {"epoch": epoch, "wraps": 0, "seq": seq})
            require(entry["wraps"] < WRAP_CAP, "%s asked for its path %d times in this boot session: refused. The operator "
                    "reboots %s (a new boot session) or rotates its paths (regalia-node reseal)" % (target, WRAP_CAP, target))
            entry["wraps"] += 1
            entry["epoch"] = epoch
            for old in sorted(mine, key=lambda s: mine[s].get("seq", 0))[:max(0, len(mine) - SESSIONS_KEPT)]:
                del mine[old]
            self._write(state)
            return entry["wraps"]


def contribution(manifest, peer, target, session_id, evidence, binding, attester, freshness, contributions, wraps):
    """This peer's contribution for `target`'s LUKS path, wrapped to the enrolment key `binding` (DER), or Refused.
    `evidence` is the target's quote ({ephemeral_public, nonce, quote, signature}, hex) over its boot session
    `session_id`, answering a nonce this peer's `attester` issued, and binding `binding`."""
    nodes = membership.validate(manifest)
    require(membership.may(manifest, peer, "authorize"), "%s may not authorize under epoch %d" % (peer, manifest["epoch"]))
    require(target != peer, "a node is not its own peer")
    require(membership.may(manifest, target, "request"), "%s may not be unlocked under epoch %d: no path for it" % (target, manifest["epoch"]))
    freshness.live_until(manifest)                       # this peer is ACTIVE: a live heartbeat, as a lease needs
    membership.hex_field(session_id, 64, "session_id")
    require(isinstance(binding, bytes), "the enrolment key is bytes")
    unlock.recipient_key(binding)                        # RSA-3072, before any TPM or disk work for it
    lease.reattest(attester, evidence, target, session_id, manifest, nodes[target], phase="system", binding=binding)
    held = contributions.epochs(target)
    epoch = max([manifest["epoch"]] + held)
    wraps.record(target, session_id, epoch)
    secret = contributions.mint_or_get(target, epoch)       # one secret per path, even for two requests at once
    return unlock.wrap(secret, peer, target, epoch, binding)


# ---- the enrolling node's side ----

def with_peer(manifest, node_id, peer, ask, identity, activate, verifier, session, quote, local, sealed_local, device, recovery,
              run=None):
    """Enrol `node_id` with `peer`, over `ask(op, **fields)` -> the peer's answer (sync.Client._ask's shape): its AK
    into the peer's verifier and the peer's AK into this node's `verifier` (each against the manifest's AK Name),
    then this node's LUKS path from the peer. `identity()` -> (EK, AK) public areas of this node's TPM;
    `activate(credential)` -> the secret it releases; `session` = (boot session ID hex, session key bytes);
    `quote(epoch, session_id, session_key, nonce, binding)` -> evidence; `recovery` the key that opens `device`
    now (typed at the console). Returns {"path_epoch", "keyslot"}, or {"path_epoch": None, "keyslot": None,
    "existing": True} when the header already holds this peer's path. Refused at the first step that fails."""
    nodes = membership.validate(manifest)
    require(peer != node_id and peer in nodes, "%s is not another node of the manifest" % peer)
    # this node refuses a contribution from a peer its own manifest does not let authorize (revoked, quarantined)
    require(membership.may(manifest, peer, "authorize"), "%s may not authorize under epoch %d: no path from it" % (peer, manifest["epoch"]))
    mine = nodes[node_id]
    # 1. this node's AK into the peer's verifier
    ek_public, ak_public = identity()
    answer = ask("ak-challenge", ek_public=ek_public.hex(), ak_public=ak_public.hex())
    if answer["credential"] is not None:
        secret = activate(bytes.fromhex(answer["credential"]))
        require(ask("ak-enroll", secret=secret.hex())["ak_name"] == mine["ak_name"], "%s enrolled another AK than the manifest's" % peer)
    # 2. the peer's AK into this node's verifier
    if verifier.enrolled(peer) != nodes[peer]["ak_name"]:
        theirs = ask("ak-public")
        credential = verifier.challenge(peer, bytes.fromhex(theirs["ek_public"]), bytes.fromhex(theirs["ak_public"]),
                                        replace=False, ak_name=nodes[peer]["ak_name"])
        verifier.enroll(peer, bytes.fromhex(ask("ak-activate", credential=credential.hex())["secret"]))
    # 3. the path: already in the header (a rerun after the token was written), or asked for now
    meta = unlock.luks_meta(device, run) if run else unlock.luks_meta(device)
    if any(t.get("peer") == peer and t.get("target") == node_id for _, t in unlock.path_tokens(meta)):
        return {"path_epoch": None, "keyslot": None, "existing": True}
    enrolment = unlock.Enrolment(node_id)
    session_id, session_key = session
    nonce = bytes.fromhex(ask("path-nonce")["nonce"])
    evidence = quote(manifest["epoch"], session_id, session_key, nonce, enrolment.public)
    wrapped = ask("path", session_id=session_id, evidence=evidence, binding=enrolment.public.hex())["enrolment"]
    path_epoch, contribution = enrolment.open(wrapped, peer)
    # a peer that hands out an OLDER path's secret (stale, or one a since-revoked party saw) is refused before the
    # header is touched: a path is at this node's manifest epoch or above (regalia-kms-1e on #272)
    require(path_epoch >= manifest["epoch"], "%s answered path epoch %d, below this node's manifest epoch %d: refused, nothing "
            "was written to the disk" % (peer, path_epoch, manifest["epoch"]))
    slot = unlock.enrol_path(device, node_id, peer, path_epoch, local, sealed_local, contribution, recovery,
                             **({"run": run} if run else {}))
    return {"path_epoch": path_epoch, "keyslot": slot}
