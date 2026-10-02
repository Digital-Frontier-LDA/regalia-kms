#!/usr/bin/env python3
"""Runtime trust leases: a running node keeps serving only while a peer keeps vouching for it
(#74, Phase 14 of #59; THREE-SITE-THREAT-MODEL.md, attacker case 2 and design question 3).

Membership and heartbeats decide who may be UNLOCKED. Once a node runs, nothing made it stop when it
was revoked. A runtime lease is a short statement by an ACTIVE peer: "under my current manifest, with
fresh membership, this node re-attested a moment ago and may serve until T". The node renews it; when
no peer will renew, it lapses, and the node stops.

A SECOND CONDITION FOR SERVING, NEVER AN ACTIVATION. regalia-fence remains the only authority for which
site signs (FENCING.md). A runtime lease names no site, grants no signing authority and is never
consulted to decide who is active. A node serves only with both; peer health can therefore neither
bypass the fencing authority nor create a second signer.

    envelope = {"lease": {...}, "signature": {"ak_public": "<hex TPM2B_PUBLIC>", "quote": "<hex TPMS_ATTEST>",
                                             "sig": "<hex ECDSA signature>"}}

    lease = {"schema": "regalia.runtime-lease/v1",
             "node_id": <the subject>, "ak_name": <the subject's AK Name>, "issuer": <the peer>,
             "epoch": <the issuer's manifest epoch>, "manifest_digest": "<64 hex>",
             "session_id": "<64 hex: the subject's attested boot session>",
             "nonce": "<64 hex: chosen by the subject for this one request>",
             "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "expires_at": "YYYY-MM-DDTHH:MM:SSZ"}

SIGNED BY THE ISSUER'S TPM. The signature is a TPM2_Quote by the issuer's attestation key whose
qualifying data is SHA-256(b"regalia-runtime-lease/v1\\0" + canonical JSON of the lease). A verifier
computes the AK's Name from the attached public area and requires it to be the issuer's ak_name in the
manifest, and the quote's qualifiedSigner to be that AK under the manifest's ek_name. No new key: the
identities membership.py already pins are the lease signers. (The PCRs in that quote are not judged
here; the issuer's own state is judged when IT asks for a lease.)

A PEER ISSUES (issue) only if, in its current manifest, it is ACTIVE and the subject may serve (ACTIVE
or DRAINING), it is not the subject, it holds a live heartbeat for that manifest (authenticated time, no
rollback: heartbeat.py), and the subject re-attests in that very call as the node the manifest names
(attest.py: the same EK and AK, this epoch, the boot session in the request, a quote over a nonce the
peer issued within its last two minutes and accepts once). The lease lives at most 5 minutes and never
past the issuer's heartbeat's own expiry.

ANYONE VERIFIES (verify: the node itself, a peer, a gateway) against ITS OWN current manifest: the
subject may still serve and has that AK, the issuer may still authorize, the lease's epoch is not newer
than the verifier's (then: fetch the chain, and refuse meanwhile) and at the same epoch the digests
agree, the signature is the issuer's, and the lease is unexpired on the verifier's authenticated clock.
A manifest that revokes the subject or the issuer kills the lease wherever that manifest has arrived.

THE NODE HOLDS (Holder) one lease in a file under /run, gone at reboot. It installs only a lease for
itself, for its current boot session, carrying a nonce it issued for that request (once), and keeps the
later-expiring of two. check() is what a cooperative daemon asks before work: refused means stop serving
and close the HSM sessions. renew at one third of the lifetime used (due()).

LIMITS, stated:
  * PARTITION. A peer that has not received the revoking manifest keeps renewing until its own heartbeat
    expires (24 hours, #69). "Stops within the lease bound" holds from the moment the issuing peers have
    the manifest; before that the bound is the heartbeat's.
  * A lease is a bearer statement. Until it expires it is true for every verifier that sees it; the nonce
    and the boot session stop an old or foreign lease being INSTALLED on the node, not shown to others.
  * Holder.check() is cooperative. A root-compromised node can ignore it. What bounds that case is
    external: peers, gateways and clients stop accepting the node when its lease lapses, the fencing
    lease, and short-lived service certificates. Wiring check() into the Go daemon's admission is a
    separate change.
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import subprocess
import tempfile
import time

from deploy.baremetal import attest, heartbeat, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.runtime-lease/v1"
DOMAIN = b"regalia-runtime-lease/v1\0"
LEASE_KEYS = ("schema", "node_id", "ak_name", "issuer", "epoch", "manifest_digest", "session_id", "nonce", "issued_at", "expires_at")
REQUEST_KEYS = ("node_id", "session_id", "nonce")
MAX_LIFETIME = 300         # the runtime bound: a node no peer will renew stops within this
FUTURE_SKEW = 30
MAX_OUTSTANDING = 4        # renewal requests in flight (one per peer, and a retry each)
MAX_BYTES = 16 * 1024
QUOTE_PCRS = "sha256:7"    # a quote must select something; its PCR values are not judged here


def _stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def _node_id(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", value) is not None, "%s must be a node ID" % label)


def validate_request(request):
    membership.exact(request, REQUEST_KEYS, "lease request")
    _node_id(request["node_id"], "node_id")
    membership.hex_field(request["session_id"], 64, "session_id")
    membership.hex_field(request["nonce"], 64, "nonce")


def validate(lease):
    """Schema only. Returns (issued, expires) in seconds."""
    membership.exact(lease, LEASE_KEYS, "lease")
    require(lease["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    _node_id(lease["node_id"], "node_id")
    _node_id(lease["issuer"], "issuer")
    membership.hex_field(lease["ak_name"], 68, "ak_name")
    require(isinstance(lease["epoch"], int) and not isinstance(lease["epoch"], bool) and 1 <= lease["epoch"] < 2 ** 63,
            "epoch must be an integer >= 1")
    for k in ("manifest_digest", "session_id", "nonce"):
        membership.hex_field(lease[k], 64, k)
    issued, expires = heartbeat.parse_time(lease["issued_at"], "issued_at"), heartbeat.parse_time(lease["expires_at"], "expires_at")
    require(issued < expires, "expires_at must be after issued_at")
    require(expires - issued <= MAX_LIFETIME, "a runtime lease lives at most %d seconds (this one: %d)" % (MAX_LIFETIME, expires - issued))
    return issued, expires


def signed_digest(lease):
    return hashlib.sha256(DOMAIN + membership.canonical(lease)).digest()


def _signature(envelope, issuer, run):
    """The quote is by the AK the manifest names for the issuer, under its EK, over exactly this lease."""
    sig = envelope["signature"]
    membership.exact(sig, ("ak_public", "quote", "sig"), "signature")
    for k, limit in (("ak_public", 1024), ("quote", 1024), ("sig", 256)):
        require(isinstance(sig[k], str) and re.fullmatch(r"([0-9a-f]{2}){1,%d}" % limit, sig[k]) is not None,
                "signature.%s must be lowercase hex, at most %d bytes" % (k, limit))
    try:
        name, spki = attest.ak_identity(bytes.fromhex(sig["ak_public"]))
        require(name.hex() == issuer["ak_name"], "the lease is not signed by the AK the manifest names for %s" % issuer["node_id"])
        quote = bytes.fromhex(sig["quote"])
        attest.verify_signature(spki, quote, bytes.fromhex(sig["sig"]), run)
        parsed = attest.parse_quote(quote)
    except attest.Refused as refusal:
        raise Refused("the lease signature is refused: %s" % refusal)
    require(parsed["qualified_signer"] == attest.qualified_name(bytes.fromhex(issuer["ek_name"]), name),
            "the lease is not signed by %s's AK under the EK the manifest names" % issuer["node_id"])
    require(hmac.compare_digest(parsed["extra_data"], signed_digest(envelope["lease"])), "the quote is not over this lease")


def verify(envelope, manifest, now, run=subprocess.run):
    """Whether `envelope` lets its subject serve at `now` (authenticated seconds: heartbeat.authenticated_now)
    under the verifier's own current `manifest`. Returns the seconds it has left, or raises Refused."""
    membership.exact(envelope, ("lease", "signature"), "envelope")
    lease = envelope["lease"]
    issued, expires = validate(lease)
    nodes = membership.validate(manifest)
    subject, issuer = nodes.get(lease["node_id"]), nodes.get(lease["issuer"])
    require(subject is not None, "%s is not in the manifest" % lease["node_id"])
    require(lease["ak_name"] == subject["ak_name"], "the lease names another AK than the manifest's for %s" % lease["node_id"])
    require(membership.may(manifest, lease["node_id"], "serve"), "%s may not serve under epoch %d (%s)"
            % (lease["node_id"], manifest["epoch"], subject["state"]))
    require(lease["issuer"] != lease["node_id"], "a node does not vouch for itself")
    require(issuer is not None and membership.may(manifest, lease["issuer"], "authorize"),
            "%s may not authorize under epoch %d" % (lease["issuer"], manifest["epoch"]))
    require(lease["epoch"] <= manifest["epoch"], "the lease is from epoch %d, newer than this verifier's %d: fetch the chain"
            % (lease["epoch"], manifest["epoch"]))
    if lease["epoch"] == manifest["epoch"]:
        require(lease["manifest_digest"] == membership.digest(manifest), "the lease is for another manifest at epoch %d (digest mismatch)"
                % manifest["epoch"])
    _signature(envelope, issuer, run)
    require(issued <= now + FUTURE_SKEW, "the lease is issued in the future (%s)" % lease["issued_at"])
    require(now < expires, "EXPIRED: the runtime lease expired at %s" % lease["expires_at"])
    return expires - now


class TpmSigner:
    """The issuer's signature: a TPM2_Quote by its persistent AK (attest.AK_HANDLE) over the lease digest."""

    def __init__(self, tcti=None, run=subprocess.run):
        self.run, self.env = run, (dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None)

    def _tpm(self, *args):
        done = self.run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=self.env)
        require(done.returncode == 0, "tpm2_%s failed: the lease cannot be signed" % args[0])

    def __call__(self, digest):
        with tempfile.TemporaryDirectory(prefix="lease-") as d:
            public, quote, sig = (os.path.join(d, n) for n in ("ak.pub", "quote", "sig"))
            self._tpm("readpublic", "-c", attest.AK_HANDLE, "-o", public)
            self._tpm("quote", "-c", attest.AK_HANDLE, "-g", "sha256", "-l", QUOTE_PCRS, "-q", digest.hex(),
                      "-m", quote, "-s", sig, "-f", "plain")
            out = []
            for path in (public, quote, sig):
                with open(path, "rb") as f:
                    out.append(f.read().hex())
            return dict(zip(("ak_public", "quote", "sig"), out))


EVIDENCE_KEYS = ("ephemeral_public", "nonce", "quote", "signature")


def _reattest(attester, evidence, request, manifest, subject):
    """The subject re-attests NOW, as the node the manifest names. The peer's attestation verifier
    (attest.Verifier) pins the manifest's EK for it and has the manifest's AK enrolled; the quote in
    `evidence` answers a nonce that verifier issued within its last two minutes, good once, and is over
    this node ID, this epoch and the boot session in the request. An earlier verdict cannot be passed
    in: issue() runs the verification itself."""
    require(isinstance(evidence, dict), "the subject has not re-attested: no lease")
    membership.exact(evidence, EVIDENCE_KEYS, "attestation evidence")
    for k, limit in (("ephemeral_public", 512), ("nonce", 32), ("quote", 1024), ("signature", 256)):
        require(isinstance(evidence[k], str) and re.fullmatch(r"([0-9a-f]{2}){1,%d}" % limit, evidence[k]) is not None,
                "evidence.%s must be lowercase hex, at most %d bytes" % (k, limit))
    node_id = request["node_id"]
    policy = attester.nodes.get(node_id)
    require(policy is not None and policy["ek_name"] == subject["ek_name"],
            "the attestation policy does not pin the manifest's EK for %s" % node_id)
    try:
        with attest.locked_state(attester.state_path) as (state, _):
            enrolled = state["nodes"].get(node_id, {}).get("ak_public")
        require(enrolled is not None and attest.ak_identity(bytes.fromhex(enrolled))[0].hex() == subject["ak_name"],
                "the attested AK is not the AK the manifest names for %s" % node_id)
        attester.verify(node_id, manifest["epoch"], bytes.fromhex(request["session_id"]), *(bytes.fromhex(evidence[k]) for k in EVIDENCE_KEYS))
    except attest.Refused as refusal:
        raise Refused("the subject's attestation is refused: %s" % refusal)


def issue(manifest, issuer_id, request, attester, evidence, freshness, signer):
    """A peer's lease for the node in `request`, or Refused. `evidence` is the subject's fresh quote
    ({ephemeral_public, nonce, quote, signature}, hex) answering a nonce from `attester`, the peer's
    attest.Verifier; `freshness` is the peer's heartbeat.Freshness; `signer(digest)` its TpmSigner."""
    validate_request(request)
    nodes = membership.validate(manifest)
    subject_id = request["node_id"]
    require(membership.may(manifest, issuer_id, "authorize"), "%s may not authorize under epoch %d" % (issuer_id, manifest["epoch"]))
    require(issuer_id != subject_id, "a node does not vouch for itself")
    require(membership.may(manifest, subject_id, "serve"), "%s may not serve under epoch %d: no lease" % (subject_id, manifest["epoch"]))
    # One reading of the peer's authenticated clock (with its floor) dates the lease, and the heartbeat's
    # absolute expiry bounds it: however long the attestation below takes, the lease cannot outlive the
    # heartbeat. A lease dated slightly early only ends slightly early.
    now, fresh_until = freshness.live_until(manifest)
    _reattest(attester, evidence, request, manifest, nodes[subject_id])
    lease = {"schema": SCHEMA, "node_id": subject_id, "ak_name": nodes[subject_id]["ak_name"], "issuer": issuer_id,
             "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest), "session_id": request["session_id"],
             "nonce": request["nonce"], "issued_at": _stamp(now), "expires_at": _stamp(min(now + MAX_LIFETIME, fresh_until))}
    return {"lease": lease, "signature": signer(signed_digest(lease))}


class Holder:
    """The running node's side: the lease it holds, the requests it has out, and its time floor, in
    `state_path` (under /run: a reboot starts with nothing). `session_id` is this boot's attested session."""

    def __init__(self, node_id, session_id, clock, tpm_clock, state_path, rand=os.urandom, run=subprocess.run):
        _node_id(node_id, "node_id")
        membership.hex_field(session_id, 64, "session_id")
        self.node_id, self.session_id, self.clock, self.tpm_clock = node_id, session_id, clock, tpm_clock
        self.state_path, self.rand, self.run = state_path, rand, run
        # every method reads, decides and rewrites the state: one at a time, across threads and processes,
        # or a check() racing an install() could drop the new lease or hand a used nonce back
        self.lock_path = state_path + ".lock"

    def _read(self):
        try:
            with open(self.state_path, "rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except FileNotFoundError:
            return {"envelope": None, "floor": None, "nonces": []}
        require(len(raw) <= MAX_BYTES, "the lease state is oversized")
        state = membership.load(raw)
        membership.exact(state, ("envelope", "floor", "nonces"), "lease state")
        heartbeat.validate_floor(state["floor"])
        require(isinstance(state["nonces"], list) and len(state["nonces"]) <= MAX_OUTSTANDING, "nonces must be a short list")
        for nonce in state["nonces"]:
            membership.hex_field(nonce, 64, "a stored nonce")
        return state

    def _write(self, state):
        directory = os.path.dirname(os.path.abspath(self.state_path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".lease-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(state, sort_keys=True).encode())
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.state_path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise

    def _now(self, state):
        seconds, state["floor"] = heartbeat.authenticated_now(self.clock, self.tpm_clock, state["floor"])
        return seconds

    def _mine(self, lease):
        require(lease["node_id"] == self.node_id, "the lease is for %s, not for this node" % lease["node_id"])
        require(lease["session_id"] == self.session_id, "the lease is for another boot session of this node")

    def request(self):
        """What to send a peer to ask for a lease. The nonce is good for one install."""
        nonce = self.rand(32).hex()
        with membership._exclusive(self.lock_path):
            state = self._read()
            state["nonces"] = (state["nonces"] + [nonce])[-MAX_OUTSTANDING:]
            self._write(state)
        return {"node_id": self.node_id, "session_id": self.session_id, "nonce": nonce}

    def install(self, envelope, manifest):
        """Take a lease a peer returned. Returns the seconds the held lease has left."""
        with membership._exclusive(self.lock_path):
            return self._install(envelope, manifest)

    def _install(self, envelope, manifest):
        state = self._read()
        now = self._now(state)
        left = verify(envelope, manifest, now, self.run)
        lease = envelope["lease"]
        self._mine(lease)
        require(lease["nonce"] in state["nonces"], "the lease answers no request this node has outstanding (replayed, or asked for by another)")
        state["nonces"].remove(lease["nonce"])
        held, keep = state["envelope"], False
        if held is not None:
            try:    # the other peer answered first and its lease runs at least as long: keep it
                held_left = verify(held, manifest, now, self.run)
                self._mine(held["lease"])
                keep = held_left >= left
            except Refused:
                pass
        if keep:
            left = held_left
        else:
            state["envelope"] = envelope
        self._write(state)
        return left

    def check(self, manifest):
        """Whether this node may serve right now. Returns the seconds left, or raises Refused: stop serving."""
        with membership._exclusive(self.lock_path):
            return self._check(manifest)[0]

    def _check(self, manifest):
        state = self._read()
        now = self._now(state)
        self._write(state)   # the floor moves whatever follows
        require(state["envelope"] is not None, "no runtime lease is held: no peer vouches for this node")
        left = verify(state["envelope"], manifest, now, self.run)
        self._mine(state["envelope"]["lease"])
        return left, state["envelope"]["lease"]

    def due(self, manifest):
        """Whether to ask for a renewal now: no usable lease, or a third of its lifetime used."""
        try:
            with membership._exclusive(self.lock_path):
                left, held = self._check(manifest)
        except Refused:
            return True
        issued, expires = validate(held)
        return left <= (expires - issued) * 2 / 3
