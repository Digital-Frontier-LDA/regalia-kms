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

    lease = {"schema": "regalia.runtime-lease/v2",
             "node_id": <the subject>, "ak_name": <the subject's AK Name>, "issuer": <the peer>,
             "epoch": <the issuer's manifest epoch>, "manifest_digest": "<64 hex>",
             "session_id": "<64 hex: the subject's attested boot session>",
             "nonce": "<64 hex: chosen by the subject for this one request>",
             "cluster_id": "<16 hex: the etcd cluster>", "state_epoch": <its history: /regalia/v1/state-epoch>,
             "state_revision": <the subject's applied etcd revision>,
             "session_key": "<64 hex: the subject's daemon's Ed25519 session key, this daemon start>",
             "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "expires_at": "YYYY-MM-DDTHH:MM:SSZ"}

v2 (D32, multi-active; #432, regalia-kms-95 with 48): the subject's REQUEST carries {cluster_id,
state_revision, session_key}, and its re-attestation quote binds them (request_binding, attest.transcript's
sixth field), so the three are its TPM's statement, not free fields. The issuer refuses a revision below what
IT had applied one lease ago (RevisionFloor: stale state never serves for more than about two lease lifetimes),
and the lease names all three: the Gate waits for its own watch to reach state_revision, and refuses a lease
whose session_key is not its daemon's; opstate entries are signed by that key. Both read their inputs from
/run (read_applied, read_session_key), each refused when absent, malformed or stale: no input, no lease.

THE STATE EPOCH (#432 item (e), scope full; regalia-kms-95, agreed with 48, d9 and ed): etcd's
--force-new-cluster keeps the cluster ID and the revision (measured on v3.6.15), so a tail the other two
committed without the survivor and the survivor's own later writes carry the same (cluster_id, revision) and
cannot be told apart by them. The survivor's first write after it is /regalia/v1/state-epoch = N (its owner
authorization's epoch, a signed opstate entry that only rises; genesis writes 0, and none reads as 0), the
daemon's watch reports it in applied.json, and revisions are compared only within one epoch:
the request binds `state_epoch`, the floor refuses any other than its own, and when the issuer's own epoch
rises its floor starts again (failing closed for one lease). An epoch never goes back.

SIGNED BY THE ISSUER'S TPM. The signature is a TPM2_Quote by the issuer's attestation key whose
qualifying data is SHA-256(b"regalia-runtime-lease/v2\\0" + canonical JSON of the lease). A verifier
computes the AK's Name from the attached public area and requires it to be the issuer's ak_name in the
manifest, and the quote's qualifiedSigner to be that AK under the manifest's ek_name. No new key: the
identities membership.py already pins are the lease signers. (The PCRs in that quote are not judged
here; the issuer's own state is judged when IT asks for a lease.)

A PEER ISSUES (issue) only if, in its current manifest, it is ACTIVE and the subject may serve (ACTIVE
or DRAINING), it is not the subject, it holds a live heartbeat for that manifest (authenticated time, no
rollback: heartbeat.py), and the subject re-attests in that very call as the node the manifest names
(attest.py: the same EK and AK, this epoch, the boot session in the request, a quote over a nonce the
peer issued within its last two minutes and accepts once). The lease lives at most 30 s and never
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

SCHEMA = "regalia.runtime-lease/v2"
DOMAIN = b"regalia-runtime-lease/v2\0"
# D32 (#432): what the subject's TPM states about its state and its daemon, bound into its re-attestation
STATE_KEYS = ("cluster_id", "state_epoch", "state_revision", "session_key")
LEASE_KEYS = ("schema", "node_id", "ak_name", "issuer", "epoch", "manifest_digest", "session_id", "nonce") + STATE_KEYS + ("issued_at", "expires_at")
REQUEST_KEYS = ("node_id", "session_id", "nonce") + STATE_KEYS
REQUEST_DOMAIN = b"regalia-lease-request/v2\0"
APPLIED_PATH = "/run/regalia-state/applied.json"          # the etcd watcher's last applied revision: its own directory (d9)
SESSION_KEY_PATH = "/run/regalia-kms/session-key.json"    # the daemon's session key's public half, this start (#432)
DAEMON_USER = "regalia-kms"          # the writer of both: the daemon's own etcd watch and session key (regalia-kms-48, ed)
MAX_LIFETIME = 30          # the runtime bound: a node no peer will renew stops within this (ADR-0002 D32: 30 s, renewed every 10 s)
FUTURE_SKEW = 5            # authtime holds the clock within MAX_OFFSET (1 s) of NTS; a lease cannot start later than this
MAX_OUTSTANDING = 4        # renewal requests in flight (one per peer, and a retry each)
MAX_BYTES = 16 * 1024
QUOTE_PCRS = "sha256:7"    # a quote must select something; its PCR values are not judged here


def _stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def _node_id(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", value) is not None, "%s must be a node ID" % label)


def _state(fields, label):
    """cluster_id (16 hex: etcd's uint64), state_epoch and state_revision (integers from 0) and session_key (an
    Ed25519 public key)."""
    membership.hex_field(fields["cluster_id"], 16, "%s.cluster_id" % label)
    for k in ("state_epoch", "state_revision"):
        require(type(fields[k]) is int and 0 <= fields[k] < 2 ** 63, "%s.%s must be an integer from 0" % (label, k))
    membership.hex_field(fields["session_key"], 64, "%s.session_key" % label)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(fields["session_key"]))
    except ValueError:
        raise Refused("%s.session_key is not an Ed25519 public key" % label) from None


def request_binding(request):
    """What the subject's re-attestation quote binds (attest.transcript's sixth field): its state and its session key."""
    return hashlib.sha256(REQUEST_DOMAIN + membership.canonical({k: request[k] for k in STATE_KEYS})).digest()


def validate_request(request):
    membership.exact(request, REQUEST_KEYS, "lease request")
    _node_id(request["node_id"], "node_id")
    membership.hex_field(request["session_id"], 64, "session_id")
    membership.hex_field(request["nonce"], 64, "nonce")
    _state(request, "lease request")


def boottime():
    """CLOCK_BOOTTIME in seconds: monotonic across suspend, unmoved by the wall clock."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _owner_uid(owner):
    """`owner`: a uid, or a user name (DAEMON_USER by default) that must exist."""
    if isinstance(owner, int):
        return owner
    import pwd
    try:
        return pwd.getpwnam(owner).pw_uid
    except KeyError:
        raise Refused("there is no user %s on this host: the file it writes cannot be judged" % owner) from None


def _read_json(path, what, limit=4096, owner=DAEMON_USER):
    """`path`'s JSON, opened without following a link, a regular file of `owner`'s that no one else may write."""
    import stat
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise Refused("%s: %s does not exist, so there is no lease without it" % (what, path)) from None
    except OSError as error:
        raise Refused("%s: %s cannot be opened (%s)" % (what, path, error.strerror)) from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == _owner_uid(owner) and not st.st_mode & 0o022,
                "%s is not a regular file of %s's that only it may write: %s is not trusted" % (path, owner, what))
        raw = f.read(limit + 1)
    require(len(raw) <= limit, "%s is oversized" % path)
    return membership.load(raw)


def this_boot():
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read(64).strip()


def read_applied(path=APPLIED_PATH, max_age=None, now=None, boot_id=None, owner=DAEMON_USER):
    """The etcd watcher's {cluster_id, state_epoch, revision} from `path` = {cluster_id, state_epoch, revision, boot_id,
    boottime_ns}, written (temp
    and rename) each time it applies a revision and on every progress notification. Refused when absent, malformed,
    from another boot, not a regular file of the daemon's user (`owner`) that only it may write, or older than `max_age`
    seconds by CLOCK_BOOTTIME (default one renewal interval, a third of a lease, for both readers; ed): a dead or stalled
    watcher leaves a file that looks current forever, and its frozen revision would
    go into a TPM-bound request or freeze the issuer's floor (regalia-kms-48, d9). Returns (cluster_id, state_epoch,
    revision)."""
    doc = _read_json(path, "the etcd watcher's applied revision", owner=owner)
    membership.exact(doc, ("boot_id", "boottime_ns", "cluster_id", "revision", "state_epoch"), "applied revision")
    membership.hex_field(doc["cluster_id"], 16, "applied.cluster_id")
    for k in ("state_epoch", "revision"):
        require(type(doc[k]) is int and 0 <= doc[k] < 2 ** 63, "applied.%s must be an integer from 0" % k)
    require(type(doc["boottime_ns"]) is int and doc["boottime_ns"] >= 0, "applied.boottime_ns must be an integer")
    require(doc["boot_id"] == (this_boot() if boot_id is None else boot_id), "the etcd watcher's file is from another boot: no lease")
    now, max_age = boottime() if now is None else now, MAX_LIFETIME // 3 if max_age is None else max_age
    age = now - doc["boottime_ns"] / 1e9
    require(age <= max_age, "STALE: the etcd watcher last wrote %s %.0f s ago (more than %d s): no lease" % (path, age, max_age))
    require(age >= -1, "the etcd watcher's file is dated %.0f s ahead of this host's boot clock" % -age)
    return doc["cluster_id"], doc["state_epoch"], doc["revision"]


def read_session_key(path=SESSION_KEY_PATH, boot_id=None, owner=DAEMON_USER):
    """The daemon's session key's public half from `path` ({boot_id, daemon_started, session_key}), refused if from
    another boot (`boot_id`, default this one's). Returns the key, 64 hex."""
    doc = _read_json(path, "the daemon's session key", owner=owner)
    membership.exact(doc, ("boot_id", "daemon_started", "session_key"), "session key file")
    require(doc["boot_id"] == (this_boot() if boot_id is None else boot_id), "the daemon's session key file is from another boot: no lease until the daemon writes it")
    _state({"cluster_id": "00" * 8, "state_epoch": 0, "state_revision": 0, "session_key": doc["session_key"]}, "session key file")
    return doc["session_key"]


class RevisionFloor:
    """The issuer's rule (D32, regalia-kms-48 with 95, 24's decision): it co-signs a subject's lease only for a revision
    at least the one IT had applied one lease (`lifetime`) ago, on CLOCK_BOOTTIME, and only of its own etcd cluster.
    `applied(cluster_id, state_epoch, revision)` is fed from the issuer's own fresh reads (read_applied); the epoch
    and, within it, the revision only rise. It FAILS CLOSED until it has watched for one lease: a restarted issuer
    cannot know what it held a lease ago, so it issues nothing for that long (a short start-up gap). In memory: a
    restart begins again. So does a rise of its own state epoch (an owner-gated force-new-cluster, #432 item (e)):
    revisions of the old history say nothing about the new one, which may lack a tail the old one had."""

    def __init__(self, lifetime=None, clock=boottime):
        import threading
        self.lifetime, self.clock = MAX_LIFETIME if lifetime is None else lifetime, clock
        self.started, self.cluster_id, self.epoch, self.seen = clock(), None, None, []   # seen: [(t, revision)], t rising
        self._lock = threading.Lock()

    def applied(self, cluster_id, state_epoch, revision):
        now = self.clock()
        with self._lock:
            require(self.cluster_id in (None, cluster_id), "the etcd watch names cluster %s, not %s: refused" % (cluster_id, self.cluster_id))
            require(self.epoch is None or state_epoch >= self.epoch, "the applied state epoch went back (%d after %d): refused"
                    % (state_epoch, self.epoch or 0))
            if self.epoch is not None and state_epoch > self.epoch:
                self.started, self.seen = now, []                                # a new history: start again, closed for one lease
            require(not self.seen or revision >= self.seen[-1][1], "the applied etcd revision went back (%d after %d): refused"
                    % (revision, self.seen[-1][1] if self.seen else 0))
            self.cluster_id, self.epoch = cluster_id, state_epoch
            self.seen.append((now, revision))
            cutoff = now - self.lifetime
            older = [i for i, (t, _) in enumerate(self.seen) if t <= cutoff]
            if older:
                self.seen = self.seen[older[-1]:]                                 # the newest at or before the cutoff stays

    def require(self, cluster_id, state_epoch, revision):
        """Refused unless `revision` of `cluster_id` at `state_epoch` is at least what this issuer had applied one lease
        ago, in the same history."""
        now = self.clock()
        with self._lock:
            # EXPECTED AFTER A RESTART, NOT A FAULT (05 on #489): an operator reads this through `update apply`'s WAIT, so it
            # says when to ask again
            require(now - self.started >= self.lifetime, "this issuer has watched etcd for %.0f s, less than one lease (%d s): it issues "
                    "no lease until it knows what it held a lease ago. Expected for a peer that (re)started less than one lease "
                    "ago, not a fault: ask again in %d s" % (now - self.started, self.lifetime,
                                                             max(1, int(self.lifetime - (now - self.started)) + 1)))
            require(cluster_id == self.cluster_id, "the subject is in etcd cluster %s, not this issuer's %s" % (cluster_id, self.cluster_id))
            require(state_epoch == self.epoch, "ANOTHER HISTORY: the subject's etcd state is of state epoch %d, this issuer's of %d: "
                    "revisions of two histories are not compared, no lease" % (state_epoch, self.epoch))
            held = [r for t, r in self.seen if t <= now - self.lifetime]
            require(held, "this issuer applied no etcd revision a lease ago (its watch had not reported): no lease")
            require(revision >= held[-1], "STALE STATE: the subject has applied etcd revision %d, below the %d this issuer had applied one lease "
                    "(%d s) ago: no lease until it catches up" % (revision, held[-1], self.lifetime))


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
    _state(lease, "lease")
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
# Optional beside them (the unlock exchange's version 2): the PCR values the node read beside its quote,
# {"<index>": "<64 hex>"}. Unauthenticated; attest.Verifier uses them only once they hash to the quoted
# digest, and only to name the PCR that differs.
PCR_VALUES = "pcr_values"


def reattest(attester, evidence, node_id, session_id, manifest, subject, phase, binding=None):
    """`node_id` re-attests NOW, in boot session `session_id`, as the node the manifest names (`subject`, its
    entry). Freshness comes only from the nonce inside `evidence`, which the peer's attestation verifier
    issued and accepts once; nothing the requester chose is trusted for it. The peer's attestation verifier
    (attest.Verifier) pins the manifest's EK for it and verified the quote under the manifest's AK; the quote in
    `evidence` answers a nonce that verifier issued within its last two minutes, good once, and is over
    this node ID, this epoch and that boot session. An earlier verdict cannot be passed in: the
    verification runs here. Used for a lease (issue) and for an unlock (replacement.may_unlock).
    `phase` is the boot phase the caller accepts the request from (attest.PHASES): "system" for a lease,
    "initrd" for an unlock. It has no default: where the node's measurements are per phase, the two
    requests are told apart by it and by nothing else. `binding` (bytes): the quote must also bind that value
    (attest.transcript's sixth field, under its own label): a path enrolment key (#190)."""
    require(isinstance(phase, str) and phase in attest.PHASES, "the phase must be one of %s" % ", ".join(attest.PHASES))
    require(isinstance(evidence, dict), "the subject has not re-attested: no lease")
    membership.exact(evidence, EVIDENCE_KEYS + ((PCR_VALUES,) if PCR_VALUES in evidence else ()), "attestation evidence")
    for k, limit in (("ephemeral_public", 512), ("nonce", 32), ("quote", 1024), ("signature", 256)):
        require(isinstance(evidence[k], str) and re.fullmatch(r"([0-9a-f]{2}){1,%d}" % limit, evidence[k]) is not None,
                "evidence.%s must be lowercase hex, at most %d bytes" % (k, limit))
    values = None
    if PCR_VALUES in evidence:                     # present means given: a null is refused, not taken for absent
        values = evidence[PCR_VALUES]
        require(isinstance(values, dict) and 0 < len(values) <= 24 and all(
                    isinstance(k, str) and re.fullmatch(r"0|[1-9]|1[0-9]|2[0-3]", k) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                    for k, v in values.items()),
                "evidence.pcr_values must map PCR indices 0-23 to 64 lowercase hex")
    policy = attester.nodes.get(node_id)
    require(policy is not None and policy["ek_name"] == subject["ek_name"],
            "the attestation policy does not pin the manifest's EK for %s" % node_id)
    try:
        verdict = attester.verify(node_id, manifest["epoch"], bytes.fromhex(session_id),
                                  *(bytes.fromhex(evidence[k]) for k in EVIDENCE_KEYS), phase=phase,
                                  **({"pcr_values": values} if values is not None else {}),   # absent: the call of before
                                  **({"binding": binding} if binding is not None else {}))    # a path enrolment key (#190)
    except attest.Refused as refusal:
        raise Refused("the subject's attestation is refused: %s" % refusal)
    # The AK the quote was actually verified under, reported from inside the verifier's own lock: an AK
    # enrolled over it a moment before or after cannot stand in for the manifest's.
    require(verdict.get("ak_name") == subject["ak_name"], "the attested AK is not the AK the manifest names for %s" % node_id)


def issue(manifest, issuer_id, request, attester, evidence, freshness, signer, floor):
    """A peer's lease for the node in `request`, or Refused. `evidence` is the subject's fresh quote
    ({ephemeral_public, nonce, quote, signature}, hex) answering a nonce from `attester`, the peer's
    attest.Verifier, and binding the request's state and session key (request_binding); `freshness` is the peer's
    heartbeat.Freshness; `signer(digest)` its TpmSigner; `floor` its RevisionFloor (D32)."""
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
    # a lease is for a node that is up and serving: on per-phase measurements, an initrd does not get one
    # D32: the subject's state no older than what this issuer held a lease ago (before the TPM is asked anything)
    floor.require(request["cluster_id"], request["state_epoch"], request["state_revision"])
    reattest(attester, evidence, subject_id, request["session_id"], manifest, nodes[subject_id], phase="system",
             binding=request_binding(request))
    lease = {"schema": SCHEMA, "node_id": subject_id, "ak_name": nodes[subject_id]["ak_name"], "issuer": issuer_id,
             "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest), "session_id": request["session_id"],
             "nonce": request["nonce"], **{k: request[k] for k in STATE_KEYS},
             "issued_at": _stamp(now), "expires_at": _stamp(min(now + MAX_LIFETIME, fresh_until))}
    return {"lease": lease, "signature": signer(signed_digest(lease))}


class Holder:
    """The running node's side: the lease it holds, the requests it has out, and its time floor, in
    `state_path` (under /run: a reboot starts with nothing). `session_id` is this boot's attested session."""

    def __init__(self, node_id, session_id, clock, tpm_clock, state_path, rand=os.urandom, run=subprocess.run, state=None,
                 session_key=None):
        _node_id(node_id, "node_id")
        membership.hex_field(session_id, 64, "session_id")
        self.node_id, self.session_id, self.clock, self.tpm_clock = node_id, session_id, clock, tpm_clock
        self.state_path, self.rand, self.run = state_path, rand, run
        # D32: what the request states, each read when a request is made (read_applied, read_session_key by default)
        self.state = state or read_applied
        self.session_key = session_key or read_session_key
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
        """What to send a peer to ask for a lease. The nonce is good for one install. Its state and session key (D32)
        are read now, and with either missing or stale there is no request: a node that cannot state them asks for nothing."""
        cluster_id, state_epoch, revision = self.state()
        session_key = self.session_key()
        nonce = self.rand(32).hex()
        with membership._exclusive(self.lock_path):
            state = self._read()
            state["nonces"] = (state["nonces"] + [nonce])[-MAX_OUTSTANDING:]
            self._write(state)
        return {"node_id": self.node_id, "session_id": self.session_id, "nonce": nonce, "cluster_id": cluster_id,
                "state_epoch": state_epoch, "state_revision": revision, "session_key": session_key}

    def install(self, envelope, manifest, prefer=False):
        """Take a lease a peer returned. Returns the seconds the held lease has left. Of the lease held and
        the one returned, the longer-lived is kept, and on a tie the one returned. With `prefer`, the one
        returned is held whatever its life: the caller needs a lease asked for NOW (the daemon started
        after the held one was asked for, admission.py), and a shorter one that the daemon serves on is
        worth more than a longer one it refuses."""
        with membership._exclusive(self.lock_path):
            return self._install(envelope, manifest, prefer)

    def _install(self, envelope, manifest, prefer=False):
        state = self._read()
        now = self._now(state)
        left = verify(envelope, manifest, now, self.run)
        lease = envelope["lease"]
        self._mine(lease)
        require(lease["nonce"] in state["nonces"], "the lease answers no request this node has outstanding (replayed, asked for by "
                "another, or older than a request already answered)")
        # REQUESTS ARE ANSWERED IN ORDER, OR NOT AT ALL. The nonces are kept in the order they were asked
        # for; taking this one retires every request made before it. A late answer to an OLDER request
        # would otherwise displace, on a longer life or a tie, the lease asked for after the daemon started
        # (admission.py), and the daemon would stop serving until the next round asked again.
        state["nonces"] = state["nonces"][state["nonces"].index(lease["nonce"]) + 1:]
        held, keep = state["envelope"], False
        if held is not None:
            # The other peer answered first and its lease runs longer: keep it. On a tie the one just
            # asked for is taken: the daemon serves a token only under a lease asked for after its own
            # start (admission.py), and a renewal asked for that reason must not be dropped for an older
            # lease of the same length (the same second, or both cut at the issuer's heartbeat expiry).
            try:
                held_left = verify(held, manifest, now, self.run)
                self._mine(held["lease"])
                keep = held_left > left and not prefer
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

    def held(self):
        """The lease envelope this node holds (a copy), or None. Not a check: use check() to decide."""
        with membership._exclusive(self.lock_path):
            envelope = self._read()["envelope"]
        return json.loads(json.dumps(envelope)) if envelope is not None else None

    def due(self, manifest):
        """Whether to ask for a renewal now: no usable lease, or a third of its lifetime used."""
        try:
            with membership._exclusive(self.lock_path):
                left, held = self._check(manifest)
        except Refused:
            return True
        issued, expires = validate(held)
        return left <= (expires - issued) * 2 / 3
