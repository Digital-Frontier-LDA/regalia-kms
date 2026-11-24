#!/usr/bin/env python3
"""The owner as the unlock peer of a single-node host (regalia-kms-dx7.5; docs/design/single-node.md 4.5, decision Q1).

WHY. A host's root disk opens with its TPM AND one peer, never the TPM alone (unlock.py, #67, #135). A single-node host
has no other node: the owner's machine plays the peer in the same exchange, unchanged on the wire. Every reboot is then
attended (the cost the design accepts); the recovery key stays break-glass.

THE CONTRIBUTION. Path (n, owner) is 32 random bytes minted HERE, on the owner's machine, at enrolment. They go two
ways and are never written in clear anywhere:
  * to the node, wrapped to its one-time enrolment key (unlock.wrap, the fingerprint checked by the owner, as a peer's
    operator does: unlock.Enrolment), for the node to add its keyslot; the node keeps nothing of it (enrol.py);
  * to the owner, as an OpenPGP envelope encrypted to BOTH owner cards' decryption subkeys (ADR-0002 D30.7, as the
    ownerauth envelopes are), so that one lost card does not strand the node (Q6). Its plaintext is
    canonical {"schema": ENVELOPE_SCHEMA, "target", "path_epoch", "secret": <64 hex>} and one newline.

AT BOOT (owner.py unlock). The operator decrypts the envelope with a card (gpg's touch) onto a pipe the tool reads, which
listens on the boot mesh, where the owner is the node's only WireGuard peer (dx7.6), and answers as a peer does:
  * hello: a nonce from the owner's own attest.Verifier, only for the manifest's one node while it is ACTIVE;
  * unlock: may_unlock(), the same verification a peer makes (lease.reattest in the initrd phase, under the measurements
    the owner's verified chain commits to: an image the manifest no longer lists, PCR 11, is refused), then the
    contribution under RSA-OAEP to the boot-session key with the transcript's label, as unlock.Peer.unlock;
  * the response is signed by an owner key (Ed25519, unlock.owner_signed_message), which the node checks against the
    owner_keys its single-node boot configuration holds (unlock.verify_owner_signature).
The manifest is the tip of the chain the owner's machine verified from the pinned root, never the node's word.

THE AK. A peer enrols a node's AK with a credential challenge. The owner's machine holds no TPM and makes no such
exchange: it adopts the AK public area the node sends at enrolment only when its Name is the manifest's
(attest.Verifier.adopt), the binding the root made at intake. Each quote is still verified under it and the EK.

NO HEARTBEAT is asked of the node: the owner is present and holds the chain, and a revocation is the owner's own act.

NOT HERE: the boot mesh with the owner as its only peer (dx7.6), and the hardware run with a real card (dx7.13).
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import tempfile

from deploy.baremetal import attest, convergence, lease, measurements, membership, replacement, unlock

Refused, require = membership.Refused, membership.require

OWNER = unlock.OWNER
ENVELOPE_SCHEMA = "regalia.owner-contribution/v1"
ENVELOPE_KEYS = ("schema", "target", "path_epoch", "secret")
REQUEST_SCHEMA = "regalia.owner-path-request/v1"
REQUEST_KEYS = ("schema", "target", "enrolment_key", "ak_public")
OPENPGP_FPR = re.compile(r"[0-9A-F]{40}")
MAX_PLAINTEXT = 512


def verifier(manifest, document, state_path):
    """The owner's attest.Verifier under `manifest`: the policy from the measurement `document` that manifest commits to
    (measurements.bind refuses any other, so an image a newer document dropped is refused by digest, never by a stale
    copy), with its state (enrolled AK, nonces, boot sessions) in `state_path` on the owner's machine."""
    return attest.Verifier(replacement.attest_policy(manifest, measurements.bind(manifest, document)), state_path)


# ---- the envelope's plaintext ----

def plaintext(target, epoch, secret):
    """The bytes the owner cards' envelope holds for path (`target`, owner) at path epoch `epoch`."""
    require(isinstance(secret, bytes) and len(secret) == unlock.SECRET_BYTES, "a contribution is %d bytes" % unlock.SECRET_BYTES)
    return membership.canonical({"schema": ENVELOPE_SCHEMA, "target": unlock.node_id(target, "target"),
                                 "path_epoch": unlock.path_epoch(epoch), "secret": secret.hex()}) + b"\n"


def read_plaintext(raw):
    """(target, path epoch, secret) from what `gpg --decrypt` printed (plaintext's form, nothing else)."""
    require(isinstance(raw, (bytes, bytearray)) and 0 < len(raw) <= MAX_PLAINTEXT and raw.endswith(b"\n"),
            "the decrypted contribution is not one line of at most %d bytes: give it the decrypted envelope, nothing else" % MAX_PLAINTEXT)
    body = bytes(raw[:-1])
    doc = membership.load(body, MAX_PLAINTEXT)
    membership.exact(doc, ENVELOPE_KEYS, "the decrypted contribution")
    require(doc["schema"] == ENVELOPE_SCHEMA, "the decrypted contribution is not a %s" % ENVELOPE_SCHEMA)
    require(membership.canonical(doc) == body, "the decrypted contribution is not in canonical form")
    membership.hex_field(doc["secret"], 2 * unlock.SECRET_BYTES, "secret")
    return unlock.node_id(doc["target"], "target"), unlock.path_epoch(doc["path_epoch"]), bytes.fromhex(doc["secret"])


def recipients(fingerprints):
    """The two owner cards' decryption subkeys (40 upper-case hex each, distinct): the card record's ownerauth_recipients."""
    require(isinstance(fingerprints, (list, tuple)) and len(fingerprints) == 2, "the envelope goes to exactly the two owner cards' decryption subkeys (D30.7)")
    for f in fingerprints:
        require(isinstance(f, str) and OPENPGP_FPR.fullmatch(f) is not None, "%r is not an OpenPGP fingerprint (40 upper-case hex)" % (f,))
    require(fingerprints[0] != fingerprints[1], "the two recipients are one card")
    return list(fingerprints)


def gpg_encrypt(plain, fingerprints, out_path, run):
    """`plain` encrypted to both `fingerprints` (each named exactly, with "!", so gpg takes that subkey), written by gpg to
    `out_path`, which must not exist yet. The plaintext goes on gpg's standard input, never a file or an argument."""
    argv = ["gpg", "--batch", "--no-tty", "--trust-model", "always", "--armor", "--encrypt", "--output", out_path]
    for f in recipients(fingerprints):
        argv += ["--recipient", f + "!"]
    done = run(argv, input=plain, capture_output=True)
    require(done.returncode == 0, "gpg could not encrypt the contribution to the two owner cards (exit %d): nothing was given to the node"
            % done.returncode)


# ---- the path epochs this owner has issued: never one twice ----

ISSUED_SCHEMA = "regalia.owner-paths/v1"
ISSUED_FILE = "owner-paths.json"


class IssuedPaths:
    """{target: [path epoch, ...]}: every path epoch this owner machine has minted a contribution at, in one 0600 file
    of its --state directory, changed under a lock and replaced atomically. Public values only (no secret). A repair
    of a node's owner path under the same manifest then gets a NEW path epoch, so the envelope of the old contribution
    names an epoch the node's new token does not ask for, and is refused before anything is signed."""

    def __init__(self, path):
        self.path = path

    def _read(self):
        try:
            with open(self.path, "rb") as f:
                require(os.fstat(f.fileno()).st_mode & 0o077 == 0, "%s is readable by others than its owner" % self.path)
                state = membership.load(f.read(unlock.MAX_BYTES + 1), unlock.MAX_BYTES)
        except FileNotFoundError:
            return {"schema": ISSUED_SCHEMA, "targets": {}}
        membership.exact(state, ("schema", "targets"), "issued owner paths")
        require(state["schema"] == ISSUED_SCHEMA and isinstance(state["targets"], dict), "issued owner paths: schema must be %s" % ISSUED_SCHEMA)
        for target, epochs in state["targets"].items():
            unlock.node_id(target, "issued owner paths: %r" % (target,))
            require(isinstance(epochs, list) and all(type(e) is int and e >= 1 for e in epochs), "issued owner paths.%s: path epochs" % target)
        return state

    def _write(self, state):
        directory = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".owner-paths-")
        try:
            with os.fdopen(fd, "wb") as f:      # mkstemp: 0600 from the start
                f.write(membership.canonical(state))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
        # the rename lasts a power cut only once the directory is synced: an epoch whose record could be lost is never
        # handed out (a failure here refuses, and the epoch is not used)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def next(self, target, floor):
        """A new path epoch for `target`: at least `floor` (the manifest's epoch) and above every one issued, recorded
        BEFORE it is used, so a crash never hands the same epoch out twice."""
        with membership._exclusive(self.path + ".lock"):
            state = self._read()
            epochs = state["targets"].setdefault(target, [])
            epoch = max([floor] + [e + 1 for e in epochs])
            epochs.append(epoch)
            self._write(state)
        return epoch


# ---- enrolment: the node's request, the owner's answer ----

def path_request(target, enrolment, ak_public):
    """What a single-node host sends the owner to enrol its owner path: its one-time enrolment key (whose fingerprint
    its console shows) and its AK public area. Public values only."""
    require(isinstance(ak_public, bytes) and 0 < len(ak_public) <= 1024, "an AK public area is 1 to 1024 bytes")
    return {"schema": REQUEST_SCHEMA, "target": unlock.node_id(target, "target"), "enrolment_key": enrolment.public.hex(),
            "ak_public": ak_public.hex()}


def single_node(manifest, target, states=("ACTIVE",)):
    """`manifest` is single-node, and `target` is its node, in one of `states`. Returns the node's entry."""
    nodes = membership.validate(manifest)
    require(membership.profile(manifest) == membership.SINGLE_NODE,
            "the owner is the unlock peer only under the %s profile; epoch %d is %s" % (membership.SINGLE_NODE, manifest["epoch"],
                                                                                   membership.profile(manifest)))
    require(target in nodes, "%s is not a node of the manifest at epoch %d" % (target, manifest["epoch"]))
    require(nodes[target]["state"] in states, "%s is %s under epoch %d, not %s: the owner does not unlock it"
            % (target, nodes[target]["state"], manifest["epoch"], " or ".join(states)))
    return nodes[target]


def contribute(manifest, request, fingerprint, attester, rand, issued):
    """On the owner's machine: judge the node's `request` under the verified `manifest`, adopt its AK into the owner's
    `attester`, mint the contribution, and return (the wrap for the node, the plaintext for the owner cards' envelope).
    `fingerprint` is the enrolment key's SHA-256 as the owner read it on the node's console. The path epoch is the
    manifest's epoch, or above every one `issued` (IssuedPaths) for this target already: one contribution per path epoch."""
    membership.exact(request, REQUEST_KEYS, "the path request")
    require(request["schema"] == REQUEST_SCHEMA, "the path request is not a %s" % REQUEST_SCHEMA)
    target = unlock.node_id(request["target"], "target")
    node = single_node(manifest, target)
    der = unlock.lower_hex(request["enrolment_key"], 1024, "enrolment_key")
    ak_public = unlock.lower_hex(request["ak_public"], 1024, "ak_public")
    require(isinstance(fingerprint, str) and hmac.compare_digest(hashlib.sha256(der).hexdigest(), fingerprint.strip().lower()),
            "the enrolment key is not the one whose fingerprint was given: nothing was created")
    unlock.recipient_key(der)
    try:
        attester.adopt(target, ak_public, node["ak_name"])
    except attest.Refused as refusal:
        raise Refused("the node's AK is refused: %s" % refusal) from None
    secret = rand(unlock.SECRET_BYTES)
    require(isinstance(secret, bytes) and len(secret) == unlock.SECRET_BYTES, "the random source did not give %d bytes" % unlock.SECRET_BYTES)
    epoch = issued.next(target, manifest["epoch"])
    return unlock.wrap(secret, OWNER, target, epoch, der), plaintext(target, epoch, secret)


# ---- at boot: the owner answers as a peer ----

def may_unlock(manifest, requester, session_id, evidence, attester):
    """The owner's decision to give `requester` its contribution: the manifest is single-node and names it ACTIVE, and it
    has just proved, with a fresh quote in the initrd phase, that it is the hardware the manifest names on an image the
    manifest's measurements still list (replacement.may_unlock's verification, without a heartbeat: see the module)."""
    node = single_node(manifest, requester)
    membership.hex_field(session_id, 64, "session_id")
    lease.reattest(attester, evidence, requester, session_id, manifest, node, phase="initrd")


def attest_booted(manifest, document, state_path, node_id, session_id, evidence, attester):
    """The owner's decision that `node_id` booted, under `manifest` (regalia-kms-dx7.8, docs/design/single-node.md 4.6):
    the single-node host's update is a planned outage, and the JUDGE of the new image is the owner's tool, not the node.
    `evidence` is the quote the node printed for the owner's nonce in the BOOTED (system) phase, over the tip's
    selection. It is verified exactly as an unlock's quote is (lease.reattest under the policy `manifest` commits to:
    an image the tip no longer lists, and a site it no longer lists, are refused by the PCR that moved), only from the
    system phase instead of the initrd. The record then written is what a boot is: it names the SYSTEM phase. A set
    given per phase names it when its system quote is verified; a set with one value per PCR cannot tell the two
    phases apart by its values, and the owner's tool names the phase the request was made in, so that an unlock (a
    quote in the initrd, a boot that asked for its disk and never came up) is never recorded as a boot. The record
    ("label", "epoch", "phase") is written into the owner's attest state at `state_path`, and returned. That record
    is the retire evidence (rollout's owner witness); the node's own state never is, and an unlock never is.
    `attester` is the owner's verifier under `manifest`/`document` (the same one that issued the evidence's nonce)."""
    node = single_node(manifest, node_id)
    membership.hex_field(session_id, 64, "session_id")
    require(attester is not None, "attest-booted verifies under the owner's verifier: it must be given")
    # The quote's phase: the owner's tool knows which phase the node is in (initrd at the unlock, system after the
    # volume opens), and says so. A quote given in the initrd is an unlock, not a boot: a boot that asked for its
    # disk and never came up is not a boot, and retiring on it would lock the host into the image it never came up on.
    # Checked BEFORE any verification: a refusal must leave the nonce outstanding and the state unwritten.
    phase = evidence.get("phase")
    if phase is not None:
        require(phase == "system", "attest-booted takes the booted system's quote; that quote was given in the %s "
                "(a boot that asked for its disk and never came up is not a boot; retiring on it would lock the host "
                "into the image it never came up on)" % phase)
    try:
        lease.reattest(attester, evidence, node_id, session_id, manifest, node, phase="system")
    except Refused as refusal:
        message = str(refusal)
        if "accepted only from the system phase" in message:
            raise Refused("attest-booted takes the booted system's quote; that quote was given in the initrd (a boot "
                          "that asked for its disk and never came up is not a boot; retiring on it would lock the "
                          "host into the image it never came up on)") from None
        raise
    # The verifier's record names the phase the request came from only when the set is given per phase. Where the
    # set has one value per PCR, the record then names no phase, and the owner's tool -- the judge -- names the
    # phase the request was made in, so that an unlock (initrd) and a boot (system) are two records, not one.
    with attest.locked_state(state_path) as (state, save):
        record = state["nodes"].get(node_id, {})
        measurement = record.get("measurement")
        require(isinstance(measurement, dict), "attest-booted recorded nothing for %s: the verification wrote no "
                "measurement" % node_id)
        if measurement.get("phase") is None:
            measurement["phase"] = "system"
            record["measurement"] = measurement
            save()
    return measurement


class OwnerPeer:
    """The owner's machine answering one single-node host's unlock requests (unlock.serve takes it as a Peer).
    `manifest` is the tip of the owner's verified chain; `attester` the owner's attest.Verifier under the policy that
    manifest commits to; `contribution` (target, path epoch, secret) read_plaintext()'s result; `signer` an owner key
    (public() -> 64 hex, sign(message) -> 64 bytes, Ed25519), one of the manifest's owner_keys; `audit(event)` the sink."""

    def __init__(self, manifest, attester, contribution, signer, audit):
        target, epoch, secret = contribution
        single_node(manifest, target)
        owners = {e["key"] for e in manifest["owner_keys"] if e["alg"] == "ed25519"}
        require(not getattr(signer, "latched", None), "the owner key's token refused its PIN before (latched: %s): it signs nothing until "
                "the latch is cleared (p11sign.WAY_OUT)" % ((getattr(signer, "latched", None) or {}).get("reason"),))
        require(signer.public() in owners, "the token's key %s... is not one of the manifest's ed25519 owner_keys: it would sign "
                "nothing the node accepts" % signer.public()[:16])
        self.manifest, self.attester, self.signer, self.audit = manifest, attester, signer, audit
        self.target, self.path_epoch, self._secret = target, epoch, secret
        self.peer_id = OWNER
        self.halted = None                # why this owner key can sign nothing more (a latched PIN): serving stops
        self.signed = 0                   # responses signed (owner.serve_unlock counts the ones it sent in full)

    def handle(self, raw, caller=None):
        """One request to one reply, as unlock.Peer.handle: a refusal tells the requester nothing but its kind."""
        message = None
        try:
            try:
                message = membership.load(raw, unlock.MAX_BYTES)
                require(isinstance(message, dict) and type(message.get("v")) is int and message["v"] in unlock.EXCHANGE_VERSIONS
                        and isinstance(message.get("op"), str), "not a request of a known version")
                handler = {"hello": self.hello, "unlock": self.unlock}.get(message["op"])
                require(handler is not None, "unknown operation")
            except Refused:
                asked = message.get("v") if isinstance(message, dict) else None
                return {"v": asked if type(asked) is int and asked in unlock.EXCHANGE_VERSIONS else unlock.VERSION, "error": "INVALID_REQUEST"}
            if caller is not None and message.get("node_id") != caller:
                return {"v": message["v"], "error": "DENIED"}
            return handler(message)
        except (Refused, attest.Refused):
            return {"v": message["v"], "error": "DENIED"}

    def hello(self, message):
        membership.exact(message, ("v", "op", "node_id"), "hello")
        requester = unlock.node_id(message["node_id"], "node_id")

        def decide():
            require(requester == self.target, "the contribution this tool holds is for %s, not %s" % (self.target, requester))
            single_node(self.manifest, requester)
            try:
                return self.attester.nonce(requester)
            except attest.Refused as refusal:
                raise Refused("no nonce for %s: %s" % (requester, refusal)) from None
        nonce = convergence.audited(self.audit, "unlock-challenge", self.manifest, requester, OWNER, decide)
        return {"v": message["v"], "peer_id": OWNER, "epoch": self.manifest["epoch"], "nonce": nonce.hex()}

    def unlock(self, message):
        membership.exact(message, ("v", "op", "node_id", "session_id", "path_epoch", "evidence"), "unlock")
        requester, session_id = unlock.node_id(message["node_id"], "node_id"), message["session_id"]
        epoch = unlock.path_epoch(message["path_epoch"])
        membership.hex_field(session_id, 64, "session_id")

        def decide():
            require(requester == self.target, "the contribution this tool holds is for %s, not %s" % (self.target, requester))
            require(epoch == self.path_epoch, "the node asks for path epoch %d; the contribution given is for path epoch %d" % (epoch, self.path_epoch))
            evidence = message["evidence"]
            require(isinstance(evidence, dict) and ("pcr_values" in evidence) == (message["v"] == 2),
                    "a version %d request %s pcr_values" % (message["v"], "without" if message["v"] == 2 else "with"))
            try:
                may_unlock(self.manifest, requester, session_id, evidence, self.attester)
            except attest.Refused as refusal:
                raise Refused(str(refusal)) from None
            ephemeral = bytes.fromhex(evidence["ephemeral_public"])
            return evidence, ephemeral, unlock.recipient_key(ephemeral)
        evidence, ephemeral, recipient = convergence.audited(self.audit, "unlock", self.manifest, requester, OWNER, decide)
        transcript = hashlib.sha256(attest.transcript(requester, self.manifest["epoch"], bytes.fromhex(session_id), ephemeral,
                                                      bytes.fromhex(evidence["nonce"]))).digest()
        response = {"schema": unlock.RESPONSE_SCHEMA, "peer_id": OWNER, "node_id": requester, "epoch": self.manifest["epoch"],
                    "manifest_digest": membership.digest(self.manifest), "session_id": session_id, "transcript_sha256": transcript.hex(),
                    "path_epoch": epoch, "ciphertext": recipient.encrypt(self._secret, unlock._oaep(unlock.CONTRIBUTION_LABEL + transcript)).hex()}
        try:
            sig = self.signer.sign(unlock.owner_signed_message(response))
        except Exception as error:      # noqa: BLE001 - the requester is told only DENIED; the owner is told why
            if getattr(self.signer, "latched", None):
                # a latched PIN never signs again in this process: stop, with the signer's own way out. Set before the
                # audit sink is called, so a sink that fails cannot keep the owner serving with a key that cannot sign
                self.halted = str(error)
            try:
                self.audit({"event": "unlock-sign", "epoch": self.manifest["epoch"], "manifest_digest": membership.digest(self.manifest),
                            "subject": requester, "peer": OWNER, "outcome": "ERROR", "reason": convergence._printable(error, membership.REASON_LIMIT)})
            except Exception:           # noqa: BLE001 - the record failed; the node is still told DENIED, the latch still stands
                pass
            raise Refused("the owner key did not sign") from None
        require(isinstance(sig, bytes) and len(sig) == 64, "the owner key did not give a 64-byte Ed25519 signature")
        self.signed += 1
        return {"response": response, "signature": {"alg": "ed25519", "key": self.signer.public(), "sig": sig.hex()}}


def printed_event(event):
    """An audit event as one line for the owner's console (the reasons, which may name the expected PCR values, go to
    the owner, never to the node)."""
    return json.dumps(event, sort_keys=True)
