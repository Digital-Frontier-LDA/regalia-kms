#!/usr/bin/env python3
"""Peer-assisted disk unlock: a KMS host's root disk opens with its TPM AND one peer, never the TPM alone
(#67, Phase 7 of #59; closes the gap of #135; THREE-SITE-THREAT-MODEL.md S1-S3, THREE-SITE-SECRETS.md).

WHY. A disk that unlocks from the local TPM alone unlocks for every boot image the TPM's policy ever
accepted: a signed PCR policy has no counter, so an old signed kernel on a stolen server opens the disk,
reads the host key and opens the HSM PIN (#135). Retiring an image has to be a decision somebody makes with
current knowledge. Here that somebody is a peer: it gives its half of the disk credential only to a node
its current manifest still lets be unlocked, on a boot image the manifest's measurements still list.

THE CREDENTIAL. One LUKS2 keyslot per peer path. For target T and peer P:

    credential = base64(HKDF-SHA256(local_T || contribution_P->T, info = "regalia/luks/v1/<T>/<P>/<path epoch>"))

local_T is 32 random bytes sealed in T's TPM (a systemd credential, TPM-only: the host key is on the disk
being unlocked). contribution_P->T is 32 random bytes on P's encrypted root disk (Contributions). Neither
alone opens anything; the two paths of a node share local_T and nothing else.

THE EXCHANGE, ported from the lab protocol of PR #91 (lab/bootstrap/PROTOCOL.md) onto the modules on main.
One JSON object each way, exact field sets, duplicate fields refused, bounded input.

    T -> P  {"v": 1, "op": "hello", "node_id": T, "summary": {"epoch": n, "manifest_digest": "..."}}
    P -> T  {"v": 1, "peer_id": P, "epoch": n, "envelopes": [...], "nonce": "<64 hex>" | null}
            or {"v": 1, "behind": {...P's summary...}}: P lacks manifests T holds
    T -> P  {"v": 1, "op": "manifests", "envelopes": [...]}        (only after "behind")
    T -> P  {"v": 1, "op": "unlock", "node_id": T, "session_id": "<64 hex>", "path_epoch": k,
             "evidence": {"ephemeral_public": ..., "nonce": ..., "quote": ..., "signature": ...}}
    P -> T  {"response": {"schema": "regalia.unlock-response/v1", "peer_id": P, "node_id": T, "epoch": n,
                          "manifest_digest": ..., "session_id": ..., "transcript_sha256": ..., "path_epoch": k,
                          "ciphertext": "<hex>"},
             "signature": {"ak_public": ..., "quote": ..., "sig": ...}}
    a refusal is {"v": 1, "error": "DENIED" | "INVALID_REQUEST"}: the reason goes to the peer's audit
    sink, never to the requester.

  * Manifests first. Both sides bring each other to the same root-signed manifest (convergence.py) before
    any quote: T never names an epoch it has not verified against its own TPM anchor.
  * The nonce is the peer's attestation verifier's (attest.Verifier.nonce: good once, two minutes). It is
    issued only to a node the peer may unlock right now.
  * P decides with replacement.may_unlock: the membership matrix, a live heartbeat, and T's fresh quote
    under the EK and AK the manifest names, over (node, epoch, boot session, ephemeral key, nonce) and the
    measurements the peer's attestation policy expects. Nothing of that decision is repeated here.
  * The contribution travels under RSA-OAEP (SHA-256) to T's boot-session RSA-3072 key, with an OAEP label
    that is the digest of the attested transcript: it decrypts in that boot session only.
  * P signs the response with its TPM attestation key, as lease.py signs a lease. T accepts it only from
    the peer it asked, for its own pending transcript, under the AK its own manifest names for a peer that
    may authorize. The FIRST valid response consumes the boot session; an invalid one consumes nothing.

WHERE IT DIFFERS FROM #91, and why: the quote is over attest.transcript, not the lab's JSON request (the
verifier on main, with its one-session-per-boot rule); the challenge is the verifier's nonce, with no
second table of challenges; the peer signs with its TPM AK instead of a software Ed25519 key pinned at
commissioning (no new key, not copyable off the peer's disk, revoked with the peer); freshness is
heartbeat.py's; the measurements come from the peer's attestation policy, not one PCR 7 value in the
manifest; and the HKDF label carries the path epoch, so a rotated path is a different credential.

ON THE DISK. One LUKS2 token per path (cryptsetup token import), naming a keyslot of its own:

    {"type": "regalia-peer-unlock", "keyslots": ["2"], "version": 1, "target": T, "peer": P,
     "path_epoch": k, "local": "<base64 systemd credential holding local_T>"}

The PCR binding of `local` is read from the credential's own header (host_probe.credential_header); the
token does not repeat it. judge_tokens() is what host_probe's root_disk_unlock_revocable asks.

ENROLMENT is an operator step between two running hosts. T makes a one-time RSA key (Enrolment) and shows
its fingerprint; P's operator checks it and runs contribute(), which mints the contribution and wraps it
to that key; T adds the keyslot and the token and proves the keyslot opens. The attested exchange cannot
carry it: T's boot-session key is gone after unlock, and the verifier refuses a second session in a boot.

LIMITS, stated:
  * Root on a running T can read local_T and whatever contribution it received this boot, and so keep a
    whole credential (THREE-SITE-SECRETS.md). After a suspected compromise: rotate both paths, reencrypt.
  * A LUKS header backup restores killed keyslots. None is kept; a host with a damaged header is rebuilt.
  * A peer that has not heard of a revocation helps until its heartbeat expires (24 hours, #69).

THE TARGET'S SIDE HERE IS A REFERENCE (BootSession, ask, unlock). It is what the tests drive and what the
wire format is checked against; it is not what an initramfs ships. The pre-root client is to be a small
native program (Clevis and systemd's token plugins are the mainstream shape; an interpreter is too much
code for the most exposed stage of boot), tested against this peer with shared vectors. The peer's side
runs on a booted, attested host and stays here.

NOT HERE: the transport (WG-BOOT, #66), the pre-root client and its initramfs hook, and the commands an
operator types; this module is the decisions and the formats. Nothing here implements a cryptographic
primitive.
"""
import base64
import contextlib
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from deploy.baremetal import attest, convergence, heartbeat, membership, replacement

Refused, require = membership.Refused, membership.require

VERSION = 1
RESPONSE_SCHEMA = "regalia.unlock-response/v1"
ENROLMENT_SCHEMA = "regalia.unlock-enrolment/v1"
STORE_SCHEMA = "regalia.unlock-contributions/v1"
RESPONSE_DOMAIN = b"regalia-unlock/v1/response\0"
CONTRIBUTION_LABEL = b"regalia-unlock/v1/contribution\0"
ENROLMENT_LABEL = b"regalia-unlock/v1/enrolment\0"
HKDF_INFO = "regalia/luks/v1/%s/%s/%d"
RESPONSE_KEYS = ("schema", "peer_id", "node_id", "epoch", "manifest_digest", "session_id", "transcript_sha256", "path_epoch", "ciphertext")
ENROLMENT_KEYS = ("schema", "target", "peer", "path_epoch", "ciphertext")
TOKEN_TYPE = "regalia-peer-unlock"
TOKEN_KEYS = ("type", "keyslots", "version", "target", "peer", "path_epoch", "local")
LOCAL_NAME = "regalia-unlock-local"
SECRET_BYTES = 32
KEY_BITS = 3072
MAX_BYTES = 4 * 1024 * 1024    # one message: a hello reply may carry manifests
ENVELOPES_PER_MESSAGE = 8      # a node further behind asks again
MAX_EXCHANGES = 16             # messages T sends one peer in one attempt
MAX_PATHS = 4                  # contributions a peer keeps per target (the current one, and one in rotation)
# What systemd-cryptenroll gives a TPM2 or FIDO2 keyslot: the credential is 256 random bits, so a memory-hard
# PBKDF buys nothing and would only slow the boot.
PBKDF = ("--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000")
NODE_ID = r"[a-z0-9][a-z0-9-]{0,31}"
# The key-type id at the head of a systemd encrypted credential (systemd 257; host_probe.py lists all of
# them). The local contribution is one of these two and nothing else: the TPM alone, or the TPM under a
# signed PCR policy as well.
LOCAL_KEY_TYPES = {"0c7cc07b117645919c4b0bea08bc20fe": "tpm2", "faf7eb9341e3412ca1a436f95a29362f": "tpm2-with-public-key"}


def node_id(value, label):
    require(isinstance(value, str) and re.fullmatch(NODE_ID, value) is not None, "%s is not a node ID" % label)
    return value


def path_epoch(value, label="path_epoch"):
    require(isinstance(value, int) and not isinstance(value, bool) and 1 <= value < 2 ** 63, "%s must be an integer >= 1" % label)
    return value


def lower_hex(value, limit, label):
    require(isinstance(value, str) and re.fullmatch(r"([0-9a-f]{2}){1,%d}" % limit, value) is not None,
            "%s must be lowercase hex, at most %d bytes" % (label, limit))
    return bytes.fromhex(value)


def local_key_type(sealed):
    """What a sealed local contribution is sealed with, from its header: "tpm2" or "tpm2-with-public-key".
    Anything else is refused. systemd-creds run without root makes a HOST-KEY credential and says nothing,
    whatever --with-key asked for (measured, systemd 257): such a blob would sit in the token and open
    nowhere before the root disk does."""
    try:
        raw = base64.b64decode("".join(sealed.split()), validate=True) if isinstance(sealed, str) else b""
    except ValueError:
        raw = b""
    kind = LOCAL_KEY_TYPES.get(raw[:16].hex())
    require(kind is not None, "the local contribution is not a systemd credential sealed to the TPM alone")
    return kind


# ---- the credential and the two encryptions (library calls only) ----

def credential(local, contribution, target, peer, epoch):
    """The keyslot passphrase of path `peer` -> `target`: both halves, or nothing."""
    require(isinstance(local, bytes) and len(local) == SECRET_BYTES, "the local contribution must be %d bytes" % SECRET_BYTES)
    require(isinstance(contribution, bytes) and len(contribution) == SECRET_BYTES, "the peer contribution must be %d bytes" % SECRET_BYTES)
    info = HKDF_INFO % (node_id(target, "target"), node_id(peer, "peer"), path_epoch(epoch))
    return base64.b64encode(HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(local + contribution))


def _oaep(label):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def recipient_key(der):
    """An RSA-3072 public key (DER SubjectPublicKeyInfo, exponent 65537), the only kind a contribution is encrypted to."""
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError):
        raise Refused("the recipient key is not a DER public key") from None
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size == KEY_BITS and key.public_numbers().e == 65537,
            "the recipient key must be RSA-%d with exponent 65537" % KEY_BITS)
    return key


def _spki(private):
    return private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _decrypt(private, ciphertext, label):
    try:
        secret = private.decrypt(ciphertext, _oaep(label))
    except ValueError:
        raise Refused("the contribution does not decrypt: it was not encrypted to this key for this exchange") from None
    require(len(secret) == SECRET_BYTES, "the decrypted contribution is not %d bytes" % SECRET_BYTES)
    return secret


def signed_digest(response):
    return hashlib.sha256(RESPONSE_DOMAIN + membership.canonical(response)).digest()


def validate_response(response):
    membership.exact(response, RESPONSE_KEYS, "response")
    require(response["schema"] == RESPONSE_SCHEMA, "schema must be %s" % RESPONSE_SCHEMA)
    for k in ("peer_id", "node_id"):
        node_id(response[k], "response.%s" % k)
    require(isinstance(response["epoch"], int) and not isinstance(response["epoch"], bool) and 1 <= response["epoch"] < 2 ** 63,
            "response.epoch must be an integer >= 1")
    for k in ("manifest_digest", "session_id", "transcript_sha256"):
        membership.hex_field(response[k], 64, "response.%s" % k)
    path_epoch(response["path_epoch"], "response.path_epoch")
    membership.hex_field(response["ciphertext"], KEY_BITS // 4, "response.ciphertext")


def verify_signature(envelope, issuer, run=subprocess.run):
    """The response is signed by the AK the manifest names for `issuer` (its entry), under its EK: a TPM2_Quote
    whose qualifying data is the digest of exactly this response. The check lease.py makes for a lease."""
    sig = envelope["signature"]
    membership.exact(sig, ("ak_public", "quote", "sig"), "signature")
    ak_public, quote, raw = (lower_hex(sig[k], limit, "signature.%s" % k) for k, limit in (("ak_public", 1024), ("quote", 1024), ("sig", 256)))
    try:
        name, spki = attest.ak_identity(ak_public)
        require(name.hex() == issuer["ak_name"], "the response is not signed by the AK the manifest names for %s" % issuer["node_id"])
        attest.verify_signature(spki, quote, raw, run)
        parsed = attest.parse_quote(quote)
    except attest.Refused as refusal:
        raise Refused("the response signature is refused: %s" % refusal)
    require(parsed["qualified_signer"] == attest.qualified_name(bytes.fromhex(issuer["ek_name"]), name),
            "the response is not signed by %s's AK under the EK the manifest names" % issuer["node_id"])
    require(hmac.compare_digest(parsed["extra_data"], signed_digest(envelope["response"])), "the quote is not over this response")


# ---- the peer ----

class Contributions:
    """The peer's half of each path it serves: {target: {path epoch: 32 bytes}}, in one 0600 file on the
    peer's encrypted root disk, changed under a lock and replaced atomically."""

    def __init__(self, path, rand=os.urandom):
        self.path, self.rand = path, rand

    def _read(self):
        try:
            with open(self.path, "rb") as f:
                require(os.fstat(f.fileno()).st_mode & 0o077 == 0, "%s is readable by others than its owner" % self.path)
                state = membership.load(f.read(MAX_BYTES + 1), MAX_BYTES)
        except FileNotFoundError:
            return {"schema": STORE_SCHEMA, "targets": {}}
        membership.exact(state, ("schema", "targets"), "contributions")
        require(state["schema"] == STORE_SCHEMA and isinstance(state["targets"], dict), "contributions: schema must be %s" % STORE_SCHEMA)
        for target, paths in state["targets"].items():
            node_id(target, "contributions: %r" % (target,))
            require(isinstance(paths, dict) and paths, "contributions.%s must hold at least one path" % target)
            for epoch, secret in paths.items():
                require(re.fullmatch(r"[1-9][0-9]{0,18}", epoch) is not None, "contributions.%s: %r is not a path epoch" % (target, epoch))
                membership.hex_field(secret, 2 * SECRET_BYTES, "contributions.%s.%s" % (target, epoch))
        return state

    def _write(self, state):
        directory = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".contributions-")
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
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def get(self, target, epoch):
        paths = self._read()["targets"].get(target, {})
        require(str(epoch) in paths, "this peer holds no contribution for %s at path epoch %d" % (target, epoch))
        return bytes.fromhex(paths[str(epoch)])

    def epochs(self, target):
        return sorted(int(e) for e in self._read()["targets"].get(target, {}))

    def mint(self, target, epoch):
        """A new contribution for `target` at path epoch `epoch`, above every one held for it."""
        node_id(target, "target")
        path_epoch(epoch)
        with membership._exclusive(self.path + ".lock"):
            state = self._read()
            paths = state["targets"].setdefault(target, {})
            require(all(int(e) < epoch for e in paths), "path epoch %d is not above the ones held for %s (%s): a path epoch is never reused"
                    % (epoch, target, ", ".join(sorted(paths, key=int))))
            require(len(paths) < MAX_PATHS, "%d contributions are held for %s already: drop the ones no keyslot uses" % (len(paths), target))
            secret = self.rand(SECRET_BYTES)
            require(isinstance(secret, bytes) and len(secret) == SECRET_BYTES, "the random source did not give %d bytes" % SECRET_BYTES)
            paths[str(epoch)] = secret.hex()
            self._write(state)
        return secret

    def drop(self, target, epoch=None):
        """Forget one path of `target` (after its keyslot was killed), or all of them (a retired node)."""
        with membership._exclusive(self.path + ".lock"):
            state = self._read()
            paths = state["targets"].get(target, {})
            dropped = [e for e in paths if epoch is None or int(e) == epoch]
            for e in dropped:
                del paths[e]
            if target in state["targets"] and not paths:
                del state["targets"][target]
            if dropped:
                self._write(state)
        return sorted(int(e) for e in dropped)

    def drop_retired(self, manifest):
        """A node the manifest has retired for good is never unlocked again: its contributions go."""
        gone = [n for n, node in membership.validate(manifest).items() if node["state"] in replacement.TERMINAL]
        return {n: d for n, d in ((n, self.drop(n)) for n in gone) if d}


class Peer:
    """One peer answering unlock requests. `store` is its membership.Store, `freshness` its
    heartbeat.Freshness, `attester_for(manifest)` its attest.Verifier under the policy that manifest
    commits to, `signer(digest)` its lease.TpmSigner, `audit(event)` the audit sink (S6)."""

    def __init__(self, peer_id, store, freshness, attester_for, contributions, signer, audit, run=subprocess.run):
        self.peer_id, self.store, self.freshness, self.attester_for = node_id(peer_id, "peer_id"), store, freshness, attester_for
        self.contributions, self.signer, self.audit, self.run = contributions, signer, audit, run

    def handle(self, raw):
        """One request (bytes) to one reply (a dict). A refusal tells the requester nothing but its kind."""
        try:
            try:
                message = membership.load(raw, MAX_BYTES)
                require(isinstance(message, dict) and type(message.get("v")) is int and message["v"] == VERSION
                        and isinstance(message.get("op"), str), "not a version 1 request")
                handler = {"hello": self.hello, "manifests": self.manifests, "unlock": self.unlock}.get(message["op"])
                require(handler is not None, "unknown operation")
            except Refused:
                return {"v": VERSION, "error": "INVALID_REQUEST"}
            return handler(message)
        except (Refused, attest.Refused):
            return {"v": VERSION, "error": "DENIED"}

    def _manifest(self):
        manifest = self.store.load()
        require(manifest is not None, "this peer holds no manifest")
        return manifest

    def hello(self, message):
        membership.exact(message, ("v", "op", "node_id", "summary"), "hello")
        requester = node_id(message["node_id"], "node_id")
        standing = convergence.compare(self.store, message["summary"])
        if standing == "behind":
            return {"v": VERSION, "behind": convergence.summary(self.store)}
        envelopes = convergence.missing(self.store, message["summary"], ENVELOPES_PER_MESSAGE) if standing == "ahead" else []
        manifest = self._manifest()
        self.contributions.drop_retired(manifest)
        reply = {"v": VERSION, "peer_id": self.peer_id, "epoch": manifest["epoch"], "envelopes": envelopes, "nonce": None}
        if message["summary"]["epoch"] + len(envelopes) == manifest["epoch"]:
            # A nonce only for a node this peer would unlock now: asking for nonces is not a way to learn
            # anything, and a refusal here is the refusal the requester would get with a quote.
            convergence.audited(self.audit, "unlock-challenge", manifest, requester, self.peer_id,
                                lambda: heartbeat.authorize(manifest, self.peer_id, requester, self.freshness))
            try:
                reply["nonce"] = self.attester_for(manifest).nonce(requester).hex()
            except attest.Refused as refusal:
                raise Refused("no nonce for %s: %s" % (requester, refusal))
        return reply

    def manifests(self, message):
        """Manifests the requester holds and this peer lacks. They are root-signed and chained: the store
        verifies each one, whoever carried it."""
        membership.exact(message, ("v", "op", "envelopes"), "manifests")
        require(isinstance(message["envelopes"], list) and len(message["envelopes"]) <= ENVELOPES_PER_MESSAGE,
                "at most %d envelopes at a time" % ENVELOPES_PER_MESSAGE)
        return {"v": VERSION, "summary": convergence.catch_up(self.store, message["envelopes"])}

    def unlock(self, message):
        membership.exact(message, ("v", "op", "node_id", "session_id", "path_epoch", "evidence"), "unlock")
        requester, session_id, epoch = node_id(message["node_id"], "node_id"), message["session_id"], path_epoch(message["path_epoch"])
        membership.hex_field(session_id, 64, "session_id")
        manifest = self._manifest()

        def decide():
            evidence = message["evidence"]
            replacement.may_unlock(manifest, self.peer_id, requester, session_id, evidence, self.attester_for(manifest), self.freshness)
            # only now is anything in `evidence` to be believed: the quote that was just verified covers it
            ephemeral = bytes.fromhex(evidence["ephemeral_public"])
            return evidence, ephemeral, recipient_key(ephemeral), self.contributions.get(requester, epoch)
        evidence, ephemeral, recipient, contribution = convergence.audited(self.audit, "unlock", manifest, requester, self.peer_id, decide)
        transcript = hashlib.sha256(attest.transcript(requester, manifest["epoch"], bytes.fromhex(session_id), ephemeral,
                                                      bytes.fromhex(evidence["nonce"]))).digest()
        response = {"schema": RESPONSE_SCHEMA, "peer_id": self.peer_id, "node_id": requester, "epoch": manifest["epoch"],
                    "manifest_digest": membership.digest(manifest), "session_id": session_id, "transcript_sha256": transcript.hex(),
                    "path_epoch": epoch, "ciphertext": recipient.encrypt(contribution, _oaep(CONTRIBUTION_LABEL + transcript)).hex()}
        return {"response": response, "signature": self.signer(signed_digest(response))}


# ---- the target ----

class BootSession:
    """What one boot of the target holds in RAM: a session ID and an RSA key, both made here and never
    stored. It opens one response, the first valid one, and is then spent."""

    def __init__(self, target, rand=os.urandom):
        self.node_id = node_id(target, "node_id")
        self.session_id = rand(32)
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
        self.ephemeral_public = _spki(self._private)
        self.pending, self.consumed = {}, False

    def expect(self, peer_id, manifest, nonce):
        """Note the transcript the quote for `peer_id` is over; the response must name exactly it."""
        self.pending[peer_id] = hashlib.sha256(attest.transcript(self.node_id, manifest["epoch"], self.session_id,
                                                                 self.ephemeral_public, nonce)).hexdigest()

    def open(self, peer_id, envelope, manifest, run=subprocess.run):
        """The contribution in `envelope`, the reply of `peer_id`, judged by the target's own `manifest`.
        Raises Refused, and stays usable, for anything but a valid response."""
        require(not self.consumed and self._private is not None, "this boot session has already accepted a response")
        membership.exact(envelope, ("response", "signature"), "unlock reply")
        response = envelope["response"]
        validate_response(response)
        require(response["peer_id"] == peer_id, "the response is from %s, not from %s, the peer that was asked" % (response["peer_id"], peer_id))
        require(response["node_id"] == self.node_id and response["session_id"] == self.session_id.hex(),
                "the response is for another node or another boot session")
        require(peer_id in self.pending and hmac.compare_digest(response["transcript_sha256"], self.pending[peer_id]),
                "the response does not answer the request this boot session sent %s" % peer_id)
        require(response["epoch"] == manifest["epoch"] and response["manifest_digest"] == membership.digest(manifest),
                "the response was decided under another manifest than the one this node holds (epoch %d)" % manifest["epoch"])
        require(membership.may(manifest, peer_id, "authorize"), "%s may not authorize under epoch %d" % (peer_id, manifest["epoch"]))
        verify_signature(envelope, membership.validate(manifest)[peer_id], run)
        secret = _decrypt(self._private, bytes.fromhex(response["ciphertext"]), CONTRIBUTION_LABEL + bytes.fromhex(response["transcript_sha256"]))
        self.consumed = True
        return response["path_epoch"], secret

    def wipe(self):
        """Drop the private key. Python cannot scrub memory: the process holding it must end before the root
        filesystem's init runs."""
        self._private, self.consumed = None, True


def tpm_quote(pcrs, tcti=None, run=subprocess.run):
    """The target's quote function, on its TPM: (node ID, epoch, session_id, ephemeral_public, nonce) ->
    (quote, signature), over `pcrs` of the SHA-256 bank (the ones the peers' attestation policy expects)."""
    def quote(target, epoch, session_id, ephemeral_public, nonce):
        env = dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None
        with tempfile.TemporaryDirectory(prefix="unlock-") as d:
            paths = (os.path.join(d, "quote"), os.path.join(d, "sig"))
            attest.node_quote(target, epoch, session_id, ephemeral_public, nonce, pcrs, *paths,
                              run=lambda argv, **kw: run(argv, env=env, **kw))
            out = []
            for path in paths:
                with open(path, "rb") as f:
                    out.append(f.read())
            return tuple(out)
    return quote


def _reply(transport, message, label):
    raw = transport(membership.canonical(message))
    reply = membership.load(raw, MAX_BYTES) if isinstance(raw, (bytes, str)) else raw
    require(isinstance(reply, dict), "%s: the reply is not an object" % label)
    require("error" not in reply, "%s: the peer refused (%s)" % (label, reply.get("error") if reply.get("error") in ("DENIED", "INVALID_REQUEST") else "?"))
    return reply


def ask(session, store, peer_id, epoch, transport, quote, run=subprocess.run):
    """The target asks `peer_id` for its contribution at path epoch `epoch`. `transport(request bytes)` returns
    the peer's reply (bytes or a dict); `quote` is tpm_quote(). Returns the contribution, or raises Refused:
    the session is spent only by a valid response."""
    node_id(peer_id, "peer_id")
    for _ in range(MAX_EXCHANGES):
        reply = _reply(transport, {"v": VERSION, "op": "hello", "node_id": session.node_id, "summary": convergence.summary(store)}, "hello")
        if "behind" in reply:
            membership.exact(reply, ("v", "behind"), "hello reply")
            _reply(transport, {"v": VERSION, "op": "manifests",
                               "envelopes": convergence.missing(store, convergence.validate_summary(reply["behind"]), ENVELOPES_PER_MESSAGE)}, "manifests")
            continue
        membership.exact(reply, ("v", "peer_id", "epoch", "envelopes", "nonce"), "hello reply")
        require(reply["peer_id"] == peer_id, "the peer that answered is %r, not %s" % (reply["peer_id"], peer_id))
        require(isinstance(reply["envelopes"], list) and len(reply["envelopes"]) <= ENVELOPES_PER_MESSAGE,
                "at most %d envelopes at a time" % ENVELOPES_PER_MESSAGE)
        if reply["envelopes"]:
            convergence.catch_up(store, reply["envelopes"])      # verified from the root, anchored in this node's TPM
        if reply["nonce"] is None:
            require(reply["envelopes"], "the peer gave neither a nonce nor a manifest")
            continue
        membership.hex_field(reply["nonce"], 64, "nonce")
        manifest = store.load()
        require(manifest is not None and reply["epoch"] == manifest["epoch"],
                "the peer is at epoch %r and this node at %d" % (reply["epoch"], manifest["epoch"] if manifest else 0))
        require(membership.may(manifest, peer_id, "authorize"), "%s may not authorize under epoch %d" % (peer_id, manifest["epoch"]))
        nonce = bytes.fromhex(reply["nonce"])
        signed, signature = quote(session.node_id, manifest["epoch"], session.session_id, session.ephemeral_public, nonce)
        session.expect(peer_id, manifest, nonce)
        answer = _reply(transport, {"v": VERSION, "op": "unlock", "node_id": session.node_id, "session_id": session.session_id.hex(),
                                    "path_epoch": epoch, "evidence": {"ephemeral_public": session.ephemeral_public.hex(), "nonce": reply["nonce"],
                                                                      "quote": signed.hex(), "signature": signature.hex()}}, "unlock")
        got, secret = session.open(peer_id, answer, manifest, run)
        require(got == epoch, "the peer answered for path epoch %d, not %d" % (got, epoch))
        return secret
    raise Refused("no contribution from %s after %d messages" % (peer_id, MAX_EXCHANGES))


# ---- the disk: LUKS2 tokens and keyslots ----

def validate_token(token):
    membership.exact(token, TOKEN_KEYS, "token")
    require(token["type"] == TOKEN_TYPE and token["version"] == VERSION and not isinstance(token["version"], bool),
            "a %s token of version %d is expected" % (TOKEN_TYPE, VERSION))
    slots = token["keyslots"]
    require(isinstance(slots, list) and len(slots) == 1 and isinstance(slots[0], str) and re.fullmatch(r"[0-9]{1,2}", slots[0]) is not None,
            "a path token names exactly one keyslot")
    node_id(token["target"], "token.target")
    node_id(token["peer"], "token.peer")
    require(token["target"] != token["peer"], "a node is not its own peer")
    path_epoch(token["path_epoch"], "token.path_epoch")
    require(isinstance(token["local"], str) and 0 < len(token["local"]) <= 16384, "token.local must hold the sealed local contribution")
    local_key_type(token["local"])
    return token


def path_tokens(meta):
    """The path tokens of a LUKS2 header (the JSON of cryptsetup luksDump --dump-json-metadata): [(token ID, token)]."""
    tokens = meta.get("tokens") if isinstance(meta, dict) else None
    return sorted(((i, t) for i, t in (tokens or {}).items() if isinstance(t, dict) and t.get("type") == TOKEN_TYPE),
                  key=lambda item: (len(item[0]), item[0]))


def judge_tokens(meta, node, peers=None):
    """Judge one LUKS2 header for peer-assisted unlock. Pure: metadata holds no key. Returns (ok, why,
    keyslots), `keyslots` being the ones the path tokens account for. True when the volume has at least
    one path token, each well-formed, for this node, from a different peer, naming an existing keyslot no
    other token names, and NO systemd-tpm2 token (a keyslot the local TPM opens by itself is what #135 is
    about). With `peers`, the paths must be exactly those peers'. What `local` is sealed to is read from
    the credential itself by the caller (host_probe.credential_header)."""
    keyslots = set(meta.get("keyslots") or {}) if isinstance(meta, dict) else set()
    tokens = [t for t in ((meta.get("tokens") or {}) if isinstance(meta, dict) else {}).values() if isinstance(t, dict)]
    named = {}
    for token in tokens:
        for slot in token.get("keyslots") or []:
            named.setdefault(str(slot), []).append(token.get("type"))
    paths, accounted = path_tokens(meta), set()
    if not paths:
        return False, "no %s token: the disk has no peer-assisted keyslot (#67)" % TOKEN_TYPE, accounted
    seen = {}
    for token_id, token in paths:
        try:
            validate_token(token)
        except Refused as refusal:
            return False, "token %s: %s" % (token_id, refusal), accounted
        slot = token["keyslots"][0]
        if token["target"] != node:
            return False, "token %s is for node %s, not %s: this header was not enrolled for this host" % (token_id, token["target"], node), accounted
        if slot not in keyslots:
            return False, "token %s names keyslot %s, which does not exist" % (token_id, slot), accounted
        if len(named[slot]) != 1:
            return False, "keyslot %s is named by %s: a peer path must have a keyslot of its own" % (
                slot, " and ".join(sorted(str(t) for t in named[slot]))), accounted
        if token["peer"] in seen:
            return False, "tokens %s and %s are both for peer %s: finish the rotation (kill the old keyslot, remove its token)" % (
                seen[token["peer"]], token_id, token["peer"]), accounted
        seen[token["peer"]] = token_id
        accounted.add(slot)
    tpm_only = sorted(str(s) for t in tokens if t.get("type") == "systemd-tpm2" for s in t.get("keyslots") or [])
    if tpm_only or any(t.get("type") == "systemd-tpm2" for t in tokens):
        return False, "a systemd-tpm2 token is still enrolled (keyslot %s): the local TPM opens the disk by itself, for every image its " \
            "policy ever accepted (#135). Wipe it once a peer path has unlocked the host: systemd-cryptenroll --wipe-slot=tpm2" % (
                ", ".join(tpm_only) or "none"), accounted
    if peers is not None and sorted(seen) != sorted(peers):
        return False, "the disk has paths from %s; the record says %s" % (", ".join(sorted(seen)), ", ".join(sorted(peers)) or "none"), accounted
    return True, "peer-assisted unlock: %s" % ", ".join("%s in keyslot %s (path epoch %d)" % (t["peer"], t["keyslots"][0], t["path_epoch"])
                                                         for _, t in sorted(paths, key=lambda item: item[1]["peer"])), accounted


def luks_meta(device, run=subprocess.run):
    done = run(["cryptsetup", "luksDump", "--dump-json-metadata", device], stdin=subprocess.DEVNULL, capture_output=True)
    require(done.returncode == 0, "cannot read the LUKS2 header of %s" % device)
    try:
        meta = json.loads(done.stdout)
    except ValueError:
        meta = None
    require(isinstance(meta, dict), "the LUKS2 header of %s is not readable JSON" % device)
    return meta


def _cryptsetup(run, args, key, second=None):
    """cryptsetup with a key on stdin and, for luksAddKey, the new key on a pipe: no key touches a file or
    an argument. The output is never passed on."""
    if second is None:
        return run(["cryptsetup", *args], input=key, capture_output=True).returncode
    read_end, write_end = os.pipe()
    try:
        os.write(write_end, second)          # 44 bytes: far below the pipe's buffer
        os.close(write_end)
        write_end = None
        return run(["cryptsetup", *args, "/dev/fd/%d" % read_end], input=key, capture_output=True, pass_fds=(read_end,)).returncode
    finally:
        os.close(read_end)
        if write_end is not None:
            os.close(write_end)


def opens(device, slot, key, run=subprocess.run):
    """Whether `key` opens keyslot `slot`, without mapping the volume. A tool failure is not a 'no'."""
    rc = _cryptsetup(run, ["open", "--test-passphrase", "--key-slot", str(slot), "--key-file", "-", device], key)
    require(rc in (0, 2), "cryptsetup could not test keyslot %s of %s (exit %d)" % (slot, device, rc))   # 2: the key does not open it
    return rc == 0


def enrol_path(device, target, peer, epoch, local, sealed_local, contribution, existing_key, run=subprocess.run):
    """Add the keyslot and the token of path `peer` -> `target`. `existing_key` opens the volume already (the
    recovery key, or another path's credential); `sealed_local` is seal_local()'s text for `local`. The
    keyslot is proven to open with the derived credential before the token is written. Returns the keyslot."""
    token = validate_token({"type": TOKEN_TYPE, "keyslots": ["0"], "version": VERSION, "target": target, "peer": peer,
                            "path_epoch": epoch, "local": sealed_local})
    meta = luks_meta(device, run)
    for _, held in path_tokens(meta):
        require(not (held.get("peer") == peer and held.get("path_epoch") == epoch),
                "the disk already has a path from %s at path epoch %d" % (peer, epoch))
    used = {int(s) for s in meta.get("keyslots") or {}}
    slot = next(s for s in range(32) if s not in used)
    key = credential(local, contribution, target, peer, epoch)
    rc = _cryptsetup(run, ["luksAddKey", "--batch-mode", *PBKDF, "--new-key-slot", str(slot), "--key-file", "-", device], existing_key, key)
    require(rc == 0, "cryptsetup luksAddKey failed (exit %d): the existing key does not open %s, or the header is full" % (rc, device))
    require(opens(device, slot, key, run), "the new keyslot %d does not open with the derived credential" % slot)
    token["keyslots"] = [str(slot)]
    done = run(["cryptsetup", "token", "import", "--json-file", "-", device], input=membership.canonical(token), capture_output=True)
    if done.returncode != 0:
        # no keyslot without its token. In batch mode luksKillSlot asks for no key, but it reads its standard
        # input when that is not a terminal: it gets an empty one, never the caller's.
        run(["cryptsetup", "luksKillSlot", "--batch-mode", device, str(slot)], stdin=subprocess.DEVNULL, capture_output=True)
        raise Refused("cryptsetup token import failed (exit %d); keyslot %d was removed again" % (done.returncode, slot))
    return slot


def remove_path(device, peer, epoch, run=subprocess.run):
    """Kill the keyslot of one path and remove its token: the last step of a rotation, or a peer retired.
    Refused if it would leave the volume without any other keyslot."""
    meta = luks_meta(device, run)
    found = [(i, t) for i, t in path_tokens(meta) if t.get("peer") == peer and t.get("path_epoch") == epoch]
    require(len(found) == 1, "the disk has %d path tokens from %s at path epoch %d" % (len(found), peer, epoch))
    token_id, token = found[0]
    slot = validate_token(token)["keyslots"][0]
    require(set(meta.get("keyslots") or {}) - {slot}, "keyslot %s is the only one: removing it would leave nothing that opens %s" % (slot, device))
    done = run(["cryptsetup", "luksKillSlot", "--batch-mode", device, slot], stdin=subprocess.DEVNULL, capture_output=True)
    require(done.returncode == 0, "cryptsetup luksKillSlot %s failed (exit %d)" % (slot, done.returncode))
    done = run(["cryptsetup", "token", "remove", "--token-id", token_id, device], stdin=subprocess.DEVNULL, capture_output=True)
    require(done.returncode == 0, "keyslot %s is killed but its token %s could not be removed (exit %d)" % (slot, token_id, done.returncode))
    return int(slot)


# ---- the local contribution: a systemd credential sealed to the TPM alone ----

def seal_local(local, pcrs="7", public_key=None, public_key_pcrs="11", tpm2_device=None, run=subprocess.run):
    """`local` as a systemd credential bound to this TPM: to `pcrs` directly and, with `public_key`, to a
    signed policy over `public_key_pcrs` as well (deploy/seal-hsm-pin.sh's binding, without the host key,
    which is on the disk this unlocks). The key type is asked for explicitly: --with-key=tpm2 ignores
    --tpm2-public-key (measured, e2e/pcr-signed-policy-swtpm.sh)."""
    require(isinstance(local, bytes) and len(local) == SECRET_BYTES, "the local contribution must be %d bytes" % SECRET_BYTES)
    args = ["systemd-creds", "encrypt", "--name=" + LOCAL_NAME, "--tpm2-pcrs=" + pcrs]
    if public_key:
        args += ["--with-key=tpm2-with-public-key", "--tpm2-public-key=" + public_key, "--tpm2-public-key-pcrs=" + public_key_pcrs]
    else:
        args += ["--with-key=tpm2"]
    if tpm2_device:
        args.append("--tpm2-device=" + tpm2_device)
    done = run([*args, "-", "-"], input=local, capture_output=True)
    require(done.returncode == 0, "systemd-creds could not seal the local contribution to the TPM (exit %d)" % done.returncode)
    sealed = "".join(done.stdout.decode("ascii", "replace").split())
    wanted = "tpm2-with-public-key" if public_key else "tpm2"
    try:
        made = local_key_type(sealed)
    except Refused:
        raise Refused("systemd-creds did not seal to the TPM (it does that silently when it is not root): nothing was enrolled") from None
    require(made == wanted, "systemd-creds made a %s credential, not %s" % (made, wanted))
    return sealed


def unseal_local(sealed, signature=None, tpm2_device=None, run=subprocess.run):
    """The local contribution, if this TPM releases it on this boot."""
    args = ["systemd-creds", "decrypt", "--newline=no", "--name=" + LOCAL_NAME]
    if signature:
        args.append("--tpm2-signature=" + signature)
    if tpm2_device:
        args.append("--tpm2-device=" + tpm2_device)
    done = run([*args, "-", "-"], input=sealed.encode(), capture_output=True)
    require(done.returncode == 0 and len(done.stdout) == SECRET_BYTES,
            "the TPM does not release the local contribution: another TPM, or a boot its policy does not accept")
    return done.stdout


def unlock(device, session, store, transports, quote, unseal, name=None, run=subprocess.run):
    """Open `device` through the first peer that helps. `transports` maps a peer ID to its transport, in the
    order to try; `unseal(sealed text)` returns the local contribution. With `name` the volume is mapped
    under that dm-crypt name; without it the keyslot is only tested. Returns (peer, keyslot). Every refusal
    is collected: if no path opens the disk, the Refused raised names each peer's reason."""
    reasons = []
    paths = {}
    for token_id, token in path_tokens(luks_meta(device, run)):
        try:
            validate_token(token)
            require(token["target"] == session.node_id, "it is for node %s" % token["target"])
        except Refused as refusal:
            reasons.append("token %s: %s" % (token_id, refusal))
            continue
        paths.setdefault(token["peer"], []).append(token)
    for peer_id, transport in transports.items():
        # the newest path first: during a rotation the old keyslot is still there
        for token in sorted(paths.get(peer_id, []), key=lambda t: -t["path_epoch"]):
            try:
                local = unseal(token["local"])
                contribution = ask(session, store, peer_id, token["path_epoch"], transport, quote, run)
                key = credential(local, contribution, session.node_id, peer_id, token["path_epoch"])
                slot = token["keyslots"][0]
                args = ["open", "--key-slot", slot, "--key-file", "-", device] + ([name] if name else ["--test-passphrase"])
                rc = _cryptsetup(run, args, key)
                require(rc == 0, "the credential derived with %s's contribution does not open keyslot %s (exit %d)" % (peer_id, slot, rc))
                return peer_id, int(slot)
            except (Refused, attest.Refused) as refusal:
                reasons.append("%s (path epoch %d): %s" % (peer_id, token["path_epoch"], refusal))
                if session.consumed:
                    # one boot session opens one response: nothing more can be asked in this boot
                    raise Refused("the disk stays locked: " + "; ".join(reasons))
        if peer_id not in paths:
            reasons.append("%s: the disk has no path from it" % peer_id)
    raise Refused("the disk stays locked: " + ("; ".join(reasons) or "no peer to ask"))


# ---- enrolment: the contribution's one journey outside the attested exchange ----

class Enrolment:
    """The target's side of enrolling one path: a one-time RSA key, held in this object only. The operator
    carries `public` to the peer and checks `fingerprint` there by hand."""

    def __init__(self, target):
        self.target = node_id(target, "target")
        self._private = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
        self.public = _spki(self._private)
        self.fingerprint = hashlib.sha256(self.public).hexdigest()

    def open(self, wrapped, peer):
        """(path epoch, contribution) from what contribute() made on `peer` for this key. Once."""
        require(self._private is not None, "this enrolment key has been used")
        membership.exact(wrapped, ENROLMENT_KEYS, "enrolment")
        require(wrapped["schema"] == ENROLMENT_SCHEMA, "schema must be %s" % ENROLMENT_SCHEMA)
        require(wrapped["target"] == self.target and wrapped["peer"] == node_id(peer, "peer"),
                "the enrolment is from %r for %r, not from %s for %s" % (wrapped["peer"], wrapped["target"], peer, self.target))
        epoch = path_epoch(wrapped["path_epoch"])
        membership.hex_field(wrapped["ciphertext"], KEY_BITS // 4, "enrolment.ciphertext")
        secret = _decrypt(self._private, bytes.fromhex(wrapped["ciphertext"]), _enrolment_label(self.target, peer, epoch))
        self._private = None
        return epoch, secret


def _enrolment_label(target, peer, epoch):
    return ENROLMENT_LABEL + membership.canonical({"target": target, "peer": peer, "path_epoch": epoch})


def contribute(contributions, manifest, peer, target, recipient_der, fingerprint):
    """On the peer: mint a contribution for `target` and wrap it to the target's enrolment key, whose
    SHA-256 `fingerprint` the operator read on the target's console. Only for a node the manifest lets this
    peer unlock. The path epoch is the manifest's epoch, or one above the last path of this pair."""
    require(membership.may(manifest, peer, "authorize"), "%s may not authorize under epoch %d" % (peer, manifest["epoch"]))
    require(membership.may(manifest, target, "request"), "%s may not be unlocked under epoch %d: no contribution for it" % (target, manifest["epoch"]))
    require(peer != target, "a node is not its own peer")
    require(isinstance(fingerprint, str) and hmac.compare_digest(hashlib.sha256(recipient_der).hexdigest(), fingerprint.strip().lower()),
            "the enrolment key is not the one whose fingerprint was given: nothing was created")
    recipient = recipient_key(recipient_der)
    epoch = max([manifest["epoch"]] + [e + 1 for e in contributions.epochs(target)])
    secret = contributions.mint(target, epoch)
    return {"schema": ENROLMENT_SCHEMA, "target": target, "peer": peer, "path_epoch": epoch,
            "ciphertext": recipient.encrypt(secret, _oaep(_enrolment_label(target, peer, epoch))).hex()}
