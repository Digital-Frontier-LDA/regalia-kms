#!/usr/bin/env python3
"""The revocation authority (#199, Phase 13 of #59): it signs the heartbeats that keep the nodes
authorizing, signs the manifests that revoke a node, and publishes both.

    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json serve
    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json revoke --node b --state REVOKED_STOLEN --reason "..."
    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json status
    runuser -u regalia-authority -- python3 -Es -m deploy.baremetal.authority --config ... init|accept --chain chain.json

WHAT IT HOLDS, from the same modules a node uses: the membership chain in a Store under a TPM anchor (a
restored disk cannot roll it back), authtime's verdict on the clock, a TPM NV counter for the heartbeat
sequence, the revocation key behind a Signer, and an audit trail.

ONE WRITER. `serve` is the only process that signs. `revoke` and `status` are its clients, over a Unix
control socket (in its RuntimeDirectory, 0600) that answers root only (SO_PEERCRED); `init` and `accept`
run as the service's own user before or between runs. Inside `serve`, a heartbeat and a revocation each
hold one lock from loading the manifest to publishing.

HEARTBEATS. Every interval_s it publishes a heartbeat {epoch, sequence, issued_at, expires_at,
manifest_digest} for the manifest it holds, and only while authtime says the clock is authenticated.
SIGN ONCE: a number is reserved on its own TPM counter (a crash after that loses it, never reuses it),
signed at most once, and the signed bytes are kept (pending-heartbeat.json) until they are published. A
number is spent the moment it is handed to the signer (a token may sign and still report a failure), so
a failed sign costs that number; a failure after signing republishes the same bytes; signed bytes that
expire unpublished, or that a newer epoch supersedes, are dropped and the number is lost: never two
signatures, and never two heartbeats, under one number. The key is checked against the manifest before a number
is reserved, and a failed beat is retried after 60 s, doubling, at most every interval_s: failures cannot
run the sequence ahead of the nodes' allowance. ONE authority for now: a second could not take over (#231).

THE INTERVAL is bounded at start: at least heartbeat.MIN_INTERVAL_S (a node accepts a sequence jump that
grows by one per MIN_INTERVAL_S of issue time, so an authority that signed faster would look like an
anomaly), and at most a quarter of the heartbeat's lifetime (heartbeat_watch warns at half).

REVOCATION. The next manifest is the current one with one node's state made more restrictive
(QUARANTINED or REVOKED_STOLEN), epoch + 1, signed by the revocation key. membership's rule for a
revocation-signed change is checked by the Store before anything is kept: same nodes, identities, policy
and keys, capabilities only shrink. Anything permissive (reinstating, enrolling) is the root's and is
refused. Under the same lock, a heartbeat for the new manifest is published at once under a fresh number,
and any pending bytes for the old epoch are dropped: no heartbeat for the old epoch is published after
the revocation's. If the process stops between the two, the next start publishes the heartbeat first.

ROOT MANIFESTS (accept) come from the root ceremony and are committed as they are (Store verifies them).

PUBLISHING is sync.Server with no attester and no signer, on the authority's tunnel address: the nodes
pull the chain and the latest heartbeat from it ("a source that issues no leases").

THE OWNER'S DECISIONS ARE SETTINGS (#199): `signer` (key custody: "file" now, "pkcs11" when a token is
chosen; every trail line and `status` name the kind), `interval_s`/`lifetime_s`, `revoke_requesters`
(only "local-root": root on this host, through the control socket; nothing here takes a revocation from
the network), and `sequence_offset`/`sequence_stride`, kept for several authorities but refused above one
until #231.

NOT HERE: where the authority runs, the root key's ceremony, and a networked revocation request.
"""
import argparse
import contextlib
import json
import os
import re
import socket
import stat
import struct
import sys
import tempfile
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import authtime, convergence, heartbeat, membership, node, sitecfg, sync, wgsvc

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.authority/v1"
KEYS = ("schema", "root_key", "tcti", "nv_epoch", "nv_sequence", "state_dir", "run_dir", "signer", "interval_s", "lifetime_s",
        "sequence_offset", "sequence_stride", "revoke_requesters", "wg_service_key", "underlays", "listen_port", "sync_port", "control_socket")
SIGNER_KINDS = ("file", "pkcs11")
REQUESTERS = ("local-root",)
RESTRICTIVE = ("QUARANTINED", "REVOKED_STOLEN")
HEARTBEAT, PENDING = "heartbeat.json", "pending-heartbeat.json"


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def _int(value, low, high, label):
    require(isinstance(value, int) and not isinstance(value, bool) and low <= value <= high, "%s must be an integer from %d to %d" % (label, low, high))
    return value


def validate(doc):
    """The configuration. Refused names the first thing wrong."""
    membership.exact(doc, KEYS, "authority configuration")
    require(doc["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    membership.hex_field(doc["root_key"], 64, "root_key")
    require(doc["tcti"] is None or (isinstance(doc["tcti"], str) and re.fullmatch(r"[a-z]+(:[A-Za-z0-9/_.,=-]{1,200})?", doc["tcti"]) is not None),
            "tcti must be null (the kernel's resource manager) or a TCTI string")
    for k in ("nv_epoch", "nv_sequence"):
        require(isinstance(doc[k], str) and re.fullmatch(r"0x01[0-9a-fA-F]{6}", doc[k]) is not None, "%s must be an NV index 0x01xxxxxx" % k)
    require(abs(int(doc["nv_epoch"], 16) - int(doc["nv_sequence"], 16)) >= 5, "nv_epoch (five indices with its record) and nv_sequence must not overlap")
    for k in ("state_dir", "run_dir", "wg_service_key", "control_socket"):
        require(isinstance(doc[k], str) and doc[k].startswith("/"), "%s must be an absolute path" % k)
    signer = doc["signer"]
    require(isinstance(signer, dict) and signer.get("kind") in SIGNER_KINDS, "signer.kind must be one of %s" % ", ".join(SIGNER_KINDS))
    if signer["kind"] == "file":
        membership.exact(signer, ("kind", "path"), "signer")
        require(isinstance(signer["path"], str) and signer["path"].startswith("/"), "signer.path must be an absolute path")
    _int(doc["interval_s"], heartbeat.MIN_INTERVAL_S, 7 * 86400, "interval_s")
    if doc["lifetime_s"] is not None:
        _int(doc["lifetime_s"], 3600, heartbeat.HARD_MAX_LIFETIME, "lifetime_s")
    stride = _int(doc["sequence_stride"], 1, 16, "sequence_stride")
    _int(doc["sequence_offset"], 0, stride - 1, "sequence_offset")
    require(stride == 1, "sequence_stride must be 1: a second authority cannot take over from the first yet (each counter steps "
            "only when it signs, so the other's heartbeats are replays at the nodes): #231")
    require(doc["interval_s"] >= heartbeat.MIN_INTERVAL_S * stride,
            "interval_s must be at least %d s (MIN_INTERVAL_S x %d authorities): a node accepts a sequence jump of one per %d s"
            % (heartbeat.MIN_INTERVAL_S * stride, stride, heartbeat.MIN_INTERVAL_S))
    requesters = doc["revoke_requesters"]
    require(isinstance(requesters, list) and requesters and all(r in REQUESTERS for r in requesters),
            "revoke_requesters must list only %s" % ", ".join(REQUESTERS))
    underlays = doc["underlays"]
    require(isinstance(underlays, dict) and underlays, "underlays must name the nodes' underlay addresses")
    for nid, where in underlays.items():
        require(isinstance(nid, str) and re.fullmatch(sitecfg.NODE_ID, nid) is not None, "underlays: %r is not a node ID" % (nid,))
        require(isinstance(where, str) and re.fullmatch(r"[0-9a-fA-F:.]{2,45}", where) is not None, "underlays[%s] must be an address" % nid)
    for k in ("listen_port", "sync_port"):
        _int(doc[k], 1, 65535, k)
    return doc


def load(path):
    with open(path, "rb") as f:
        return validate(membership.load(f.read(64 * 1024 + 1), 64 * 1024))


# ---- the revocation key ----

class FileSigner:
    """The revocation key in a file: Ed25519, PEM (PKCS#8), owned by this process's user and readable by no
    one else. A STOPGAP until the owner chooses a token (#199): `kind` is recorded on every signature."""
    kind = "file"

    def __init__(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode), "the revocation key is not a regular file")
            require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0, "the revocation key must be this user's and 0600")
            raw = os.read(fd, 4096)
        finally:
            os.close(fd)
        key = serialization.load_pem_private_key(raw, password=None)
        require(isinstance(key, Ed25519PrivateKey), "the revocation key must be Ed25519")
        self._key = key

    def public(self):
        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, message):
        return self._key.sign(message)


def signer_for(cfg):
    if cfg["signer"]["kind"] == "file":
        return FileSigner(cfg["signer"]["path"])
    raise Refused("signer kind pkcs11 is not built yet: the owner's choice of token comes first (#199)")


# ---- the authority ----

class Authority:
    """The parts, from the configuration. `clock()` returns (unix seconds, authenticated)."""

    def __init__(self, cfg, signer=None, clock=None, run=None, trail=None):
        import subprocess
        self.cfg, self.run = cfg, run or subprocess.run
        self.signer = signer or signer_for(cfg)
        self.clock = clock or authtime.clock(os.path.join(cfg["run_dir"], "authtime.json"))
        self.trail = trail or node.Trail(self.path("audit.jsonl"))
        tcti = cfg["tcti"]
        self.anchor = membership.HighWater(cfg["nv_epoch"], tcti, self.run, lock_path=self.path("highwater.lock"))
        self.counter = heartbeat.Counter(cfg["nv_sequence"], tcti, self.run, lock_path=self.path("sequence.lock"))
        self.store = membership.Store(self.path("membership.json"), cfg["root_key"], self.anchor)
        # One writer: beat and revoke each hold this from loading the manifest to publishing. A revocation
        # arrives through the control socket of the running `serve`, never from a second process.
        self.lock = threading.RLock()
        # A number reserved on the counter that nothing has been signed under yet: retried, never wasted
        self.reserved = None
        self.wake = threading.Event()      # a revocation whose heartbeat failed: run_loop tries again now

    def path(self, name):
        return os.path.join(self.cfg["state_dir"], name)

    # ---- what it publishes ----

    def held(self):
        """The latest heartbeat envelope it published, or None: what sync.Server hands to a puller."""
        return self._read(HEARTBEAT)

    def _read(self, name):
        try:
            with open(self.path(name), "rb") as f:
                return membership.load(f.read(heartbeat.MAX_BYTES + 1), heartbeat.MAX_BYTES)
        except FileNotFoundError:
            return None

    def _write(self, name, raw, mode):
        fd, tmp = tempfile.mkstemp(dir=self.cfg["state_dir"], prefix=".%s-" % name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, self.path(name))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    def _publish(self, raw):
        self._write(HEARTBEAT, raw, 0o644)

    def _unpend(self):
        """Remove the pending file. Returns whether the path is clear. One that cannot be removed is only
        republished (the same bytes), but say so: while it stays, every beat republishes it."""
        try:
            os.unlink(self.path(PENDING))
        except FileNotFoundError:
            pass
        except OSError as failure:
            with contextlib.suppress(Exception):
                self.trail({"event": "authority-heartbeat", "outcome": "STUCK", "reason": "the pending heartbeat cannot be removed: %s" % failure,
                            "signer": self.signer.kind})
            return False
        return True

    # ---- the sequence ----

    def next_sequence(self):
        """The number to sign next: one reserved earlier that nothing was signed under (a failure before
        signing), else the next above the TPM counter, reserved now."""
        held = self.counter.value()
        if self.reserved is not None and self.reserved == held:
            return self.reserved
        self.counter.advance(held + 1)                 # reserved: a crash after this loses the number, never reuses it
        self.reserved = held + 1
        return self.reserved

    def lifetime(self, manifest):
        bound = heartbeat.max_lifetime(manifest)
        lifetime = min(self.cfg["lifetime_s"] or bound, bound)
        require(self.cfg["interval_s"] * 4 <= lifetime, "interval_s %d is more than a quarter of the heartbeat lifetime %d s under epoch %d"
                % (self.cfg["interval_s"], lifetime, manifest["epoch"]))
        return lifetime

    # ---- signing ----

    def beat(self, reason="interval"):
        """Publish a heartbeat for the manifest held now. SIGN ONCE: a heartbeat signed but not yet published
        (PENDING, kept in the state directory) is republished byte for byte until it is out or has expired;
        only then is a new number reserved. A number is signed at most once."""
        with self.lock:
            manifest = self.store.load()
            seconds, authenticated = self.clock()
            require(authenticated, "time is not authenticated: no heartbeat is signed")
            if os.path.exists(self.path(PENDING)):
                try:
                    pending = self._read(PENDING)
                    heartbeat.verify(pending, manifest)                 # for THIS manifest, by a key it names, intact
                    expires = heartbeat.parse_time(pending["heartbeat"]["expires_at"], "expires_at")
                    require(expires > seconds, "expired unpublished")
                    require(heartbeat.MIN_INTERVAL_S <= expires - seconds, "too close to its expiry to be worth publishing")
                except (Refused, ValueError, KeyError, TypeError, OSError) as stale:
                    # unreadable, for another epoch, or out of date: dropped, and its number is lost (never re-signed)
                    cleared = self._unpend()
                    self.trail({"event": "authority-heartbeat", "outcome": "DROPPED", "reason": str(stale)[:240], "signer": self.signer.kind})
                    # a path that cannot be cleared would take every new signature's pending write with it:
                    # refuse before a number is reserved, rather than spend one (and a signature) per beat
                    require(cleared, "the pending heartbeat path cannot be cleared: nothing is signed until it is")
                else:
                    self._publish(json.dumps(pending, sort_keys=True).encode())     # the same bytes, again
                    self._unpend()
                    return pending
            lifetime = self.lifetime(manifest)
            # checked BEFORE a number is reserved: a key the manifest does not name would burn one per retry
            require(self.signer.public() in manifest["revocation_keys"], "the revocation key %s... is not named by the manifest at epoch %d: "
                    "no heartbeat is signed" % (self.signer.public()[:16], manifest["epoch"]))
            sequence = self.next_sequence()
            body = {"schema": heartbeat.SCHEMA, "epoch": manifest["epoch"], "sequence": sequence, "issued_at": stamp(seconds),
                    "expires_at": stamp(seconds + lifetime), "manifest_digest": membership.digest(manifest)}
            # Given to the signer: from here the number is spent, whatever sign() then does (a token may have
            # signed before it failed). One number never carries two signatures; a failure costs one number,
            # at the backoff's rate, which the nodes' allowance absorbs.
            self.reserved = None
            envelope = {"heartbeat": body, "signature": {"key": self.signer.public(),
                                                         "sig": self.signer.sign(heartbeat.DOMAIN + membership.canonical(body)).hex()}}
            heartbeat.verify(envelope, manifest)
            raw = json.dumps(envelope, sort_keys=True).encode()
            self._write(PENDING, raw, 0o600)                            # from here only these bytes go out under it
            self.trail({"event": "authority-heartbeat", "outcome": "SIGNED", "epoch": manifest["epoch"], "sequence": sequence,
                        "digest": body["manifest_digest"], "expires_at": body["expires_at"], "key": self.signer.public(),
                        "signer": self.signer.kind, "reason": reason})
            self._publish(raw)
            self._unpend()
            return envelope

    def catch_up(self):
        """At start: if the store is ahead of the published heartbeat (a revocation whose heartbeat was never
        published: the process stopped between the two), or a signed heartbeat is pending, publish now.
        Returns the envelope, or None."""
        held, manifest = self.held(), self.store.load()
        if os.path.exists(self.path(PENDING)) or held is None or held["heartbeat"]["epoch"] != manifest["epoch"]:
            return self.beat("the store is at epoch %d and no heartbeat for it was published" % manifest["epoch"])
        return None

    def revoke(self, node_id, state, reason, requester):
        """Sign and commit the manifest that makes `node_id` QUARANTINED or REVOKED_STOLEN, then a heartbeat
        for it under a FRESH number, all under the one lock: a heartbeat for the old epoch, pending or in
        flight, can never be published after the revocation's. Returns (manifest envelope, heartbeat envelope)."""
        require(requester in self.cfg["revoke_requesters"], "%s may not request a revocation here" % requester)
        require(state in RESTRICTIVE, "a revocation sets %s: anything else is the root's" % " or ".join(RESTRICTIVE))
        require(isinstance(reason, str) and 3 <= len(reason) <= 240 and reason.isprintable(), "a revocation needs a reason (3 to 240 printable characters)")
        with self.lock:
            current = self.store.load()
            entries = {n["node_id"]: n for n in current["nodes"]}
            require(node_id in entries, "%s is not in the manifest at epoch %d" % (node_id, current["epoch"]))
            require(entries[node_id]["state"] != state and entries[node_id]["state"] not in membership.TERMINAL,
                    "%s is already %s" % (node_id, entries[node_id]["state"]))
            seconds, authenticated = self.clock()
            require(authenticated, "time is not authenticated: no revocation is signed")
            candidate = dict(current, epoch=current["epoch"] + 1, prev_digest=membership.digest(current), issued_at=stamp(seconds),
                             nodes=[dict(n, state=state) if n["node_id"] == node_id else n for n in current["nodes"]])
            envelope = {"manifest": candidate, "signature": {"signer": "revocation", "key": self.signer.public(),
                                                             "sig": self.signer.sign(membership.DOMAIN + membership.canonical(candidate)).hex()}}
            self.store.commit(envelope)                                         # membership's revocation rule, anchored in the TPM
            try:                                                                # from here the revocation is committed, whatever fails
                self.trail({"event": "authority-revoke", "outcome": "SIGNED", "epoch": candidate["epoch"], "node": node_id, "state": state,
                            "digest": membership.digest(candidate), "key": self.signer.public(), "signer": self.signer.kind,
                            "requester": requester, "reason": reason})
                return envelope, self.beat("revocation of %s" % node_id)       # the pending old-epoch bytes are dropped there
            except Exception as failure:      # noqa: BLE001 - committed is committed, whatever the heartbeat did
                self.wake.set()                                         # serve retries at once, not an interval later
                raise Committed(candidate["epoch"], failure) from None

    def init(self, envelopes):
        """First start: define the TPM anchor and the sequence counter, then take the root's chain."""
        self.anchor.define()
        self.counter.define()
        return self.accept(envelopes)

    def accept(self, envelopes):
        """Root-signed manifests from the ceremony, in order. Returns the epoch now held."""
        with self.lock:
            for envelope in envelopes:
                self.store.commit(envelope)
                self.trail({"event": "authority-accept", "outcome": "ALLOW", "epoch": envelope["manifest"]["epoch"],
                            "digest": membership.digest(envelope["manifest"]), "signer": envelope["signature"]["signer"]})
            return self.store.load()["epoch"]

    def status(self):
        manifest, held = self.store.load(), self.held()
        return {"epoch": manifest["epoch"], "digest": membership.digest(manifest), "sequence": self.counter.value(),
                "heartbeat": held["heartbeat"] if held else None, "pending": self._read(PENDING) is not None,
                "signer": self.signer.kind, "key": self.signer.public(), "interval_s": self.cfg["interval_s"], "lifetime_s": self.lifetime(manifest)}

    # ---- the control socket: revoke and status, from root on this host, to the running serve ----

    def control(self, raw, peer_uid, allowed_uid=0):
        """One request on the control socket. Only `allowed_uid` (root) is answered."""
        if peer_uid != allowed_uid:
            self.trail({"event": "authority-control", "outcome": "DENY", "reason": "peer uid %s is not root" % peer_uid})
            return {"ok": False, "refused": "only root on this host may ask"}
        try:
            request = membership.load(raw, 4096)
            require(isinstance(request, dict) and request.get("op") in ("revoke", "status"), "op must be revoke or status")
            if request["op"] == "status":
                return {"ok": True, "status": self.status()}
            membership.exact(request, ("op", "node", "state", "reason"), "revoke request")
            require(all(isinstance(request[k], str) for k in ("node", "state", "reason")), "node, state and reason must be strings")
            envelope, beat = self.revoke(request["node"], request["state"], request["reason"], "local-root")
            return {"ok": True, "epoch": envelope["manifest"]["epoch"], "sequence": beat["heartbeat"]["sequence"], "published": True}
        except Committed as committed:
            return {"ok": True, "epoch": committed.epoch, "published": False, "reason": str(committed)[:240]}
        except (Refused, ValueError, OSError) as failure:
            return {"ok": False, "refused": str(failure)[:240]}
        except Exception as failure:          # noqa: BLE001 - one bad request must not take the socket down
            self.trail({"event": "authority-control", "outcome": "FAILED", "reason": "%s: %s" % (type(failure).__name__, str(failure)[:200])})
            return {"ok": False, "refused": "internal error (%s): recorded" % type(failure).__name__}

    def control_listener(self, stop, allowed_uid=0):
        """The control socket, in its own thread: one JSON request per connection, from root only."""
        path = self.cfg["control_socket"]
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            listener.bind(path)                                # 0600, the service user's: root reaches it, no one else
        finally:
            os.umask(old)
        listener.listen(4)
        listener.settimeout(1)

        def loop():
            try:
                while not stop():
                    try:
                        conn, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with conn:
                        try:                       # whatever one connection does, the listener goes on
                            conn.settimeout(10)
                            uid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
                            raw = conn.recv(4097)
                            conn.sendall(json.dumps(self.control(raw, uid, allowed_uid), sort_keys=True).encode())
                        except Exception:          # noqa: BLE001
                            pass
            finally:
                listener.close()
        thread = threading.Thread(target=loop, daemon=True)
        thread.start()
        return thread

    # ---- serving ----

    def serve(self, stop, sleep=time.sleep, clock=time.monotonic):
        """Publish on the tunnel address, answer the control socket, and publish a heartbeat every interval
        until `stop()`. A failed beat is retried after 60 s, doubling, at most every interval_s: a failure
        reserves at most one number (it is retried, not replaced), and is recorded."""
        own = wgsvc.address(self.signer_tunnel_key())
        listener = node.bind_when_up((own, self.cfg["sync_port"]), stop, family=socket.AF_INET6)
        listener.settimeout(1)
        server = sync.Server(convergence.AUTHORITY, self.store, self, None, None, wgsvc.key_at, self.trail)
        threading.Thread(target=sync.serve, args=(server, listener, stop), daemon=True).start()
        self.control_listener(stop)
        try:
            self.run_loop(stop, sleep, clock)
        finally:
            listener.close()

    def run_loop(self, stop, sleep=time.sleep, clock=time.monotonic):
        due, failures = 0.0, 0
        while not stop():
            if self.wake.is_set():
                self.wake.clear()
                due = 0.0
            if clock() >= due:
                try:
                    self.catch_up() or self.beat()
                    due, failures = clock() + self.cfg["interval_s"], 0
                except Exception as failure:      # noqa: BLE001 - a beat that fails is retried, never the end of serve
                    self.trail({"event": "authority-heartbeat", "outcome": "FAILED", "reason": "%s: %s" % (type(failure).__name__, str(failure)[:220]),
                                "signer": self.signer.kind})
                    due, failures = clock() + retry_delay(failures, self.cfg["interval_s"]), failures + 1
            sleep(1)

    def signer_tunnel_key(self):
        with open(self.cfg["wg_service_key"]) as f:
            private = f.read(200).strip()
        return wgsvc.hex_key(self.run(["wg", "pubkey"], input=(private + "\n").encode(), capture_output=True, timeout=10).stdout.decode().strip())


class Committed(Refused):
    """The revocation is committed (the store is at `epoch`), but its heartbeat is not yet published: the
    next beat publishes it. Asking again would only be told the node is already revoked."""

    def __init__(self, epoch, failure):
        super().__init__("epoch %d is committed; its heartbeat is not yet published (%s): the next beat will" % (epoch, failure))
        self.epoch = epoch


def one_writer(state_dir):
    """The single-writer lock: serve holds it while it runs, init and accept for their write. A second
    writer is refused at once, never queued."""
    import fcntl
    fd = os.open(os.path.join(state_dir, "writer.lock"), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(), "writer.lock is not this user's regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Refused:
        os.close(fd)
        raise
    except BlockingIOError:
        os.close(fd)
        raise Refused("another writer holds %s (is regalia-authority running? stop it first: one writer)" % os.path.join(state_dir, "writer.lock")) from None
    return fd


def retry_delay(failures, interval):
    """60 s after the first failure, doubling, never more than the interval."""
    return min(60 * 2 ** min(failures, 20), interval)


def ask(path, request):
    """The CLI side of the control socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(120)
        conn.connect(path)
        conn.sendall(json.dumps(request).encode())
        conn.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


def wg_apply(authority):
    """The authority's wg-svc, from the manifest it holds: every node a peer, at its underlay."""
    manifest = authority.store.load()
    with open(authority.cfg["wg_service_key"]) as f:
        private = f.read(200).strip()
    return wgsvc.reconcile(manifest, wgsvc.AUTHORITY, authority.cfg["underlays"], private, listen_port=authority.cfg["listen_port"],
                           run=authority.run, own_key=authority.signer_tunnel_key())


# ---- command line ----

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/regalia/authority.json")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("status")
    sub.add_parser("wg-apply")
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--node", required=True)
    revoke.add_argument("--state", required=True, choices=RESTRICTIVE)
    revoke.add_argument("--reason", required=True)
    for name in ("init", "accept"):
        chain = sub.add_parser(name)
        chain.add_argument("--chain", required=True, help="a JSON list of root-signed envelopes, in epoch order")
    args = parser.parse_args(argv)
    try:
        cfg = load(args.config)
        if args.command in ("revoke", "status"):
            # a client of the running serve, which is the one writer: root only (the socket checks it too)
            require(os.geteuid() == 0, "revoke and status are asked of the running authority as root on this host (local-root)")
            request = {"op": "status"} if args.command == "status" else {"op": "revoke", "node": args.node, "state": args.state, "reason": args.reason}
            answer = ask(cfg["control_socket"], request)
            require(answer.get("ok") is True, "the authority refused: %s" % answer.get("refused"))
            print(json.dumps(answer.get("status", answer), indent=1, sort_keys=True))
            return 0
        if args.command in ("init", "accept", "serve"):
            owner = os.stat(cfg["state_dir"]).st_uid
            require(os.geteuid() == owner, "run as the authority's own user (uid %d), e.g. runuser -u regalia-authority -- ...: "
                    "files written as anyone else would lock the service out" % owner)
            _writer = one_writer(cfg["state_dir"])         # after the uid check; held for the life of this process
        authority = Authority(cfg)
        if args.command == "serve":
            authority.serve(lambda: False)
        elif args.command == "wg-apply":
            print("wg-svc applied: %s" % wg_apply(authority))
        else:
            with open(args.chain, "rb") as f:
                envelopes = membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), membership.MAX_CHAIN_BYTES)
            require(isinstance(envelopes, list) and envelopes, "the chain must be a non-empty JSON list of envelopes")
            print("epoch %d held" % (authority.init if args.command == "init" else authority.accept)(envelopes))
    except (OSError, Refused, ValueError) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
