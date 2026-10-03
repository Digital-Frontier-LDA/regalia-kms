#!/usr/bin/env python3
"""The revocation authority (#199, Phase 13 of #59): it signs the heartbeats that keep the nodes
authorizing, signs the manifests that revoke a node, and publishes both.

    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json serve
    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json revoke --node b --state REVOKED_STOLEN --reason "..."
    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json init|accept --chain chain.json
    python3 -Es -m deploy.baremetal.authority --config /etc/regalia/authority.json status

WHAT IT HOLDS, from the same modules a node uses: the membership chain in a Store under a TPM anchor (a
restored disk cannot roll it back), authtime's verdict on the clock, a TPM NV counter for the heartbeat
sequence, the revocation key behind a Signer, and an audit trail.

HEARTBEATS (serve). Every interval_s it signs {epoch, sequence, issued_at, expires_at, manifest_digest}
for the manifest it holds. The sequence comes from its own TPM counter, ADVANCED BEFORE the heartbeat is
signed: a crash between the two loses a number and never reuses one, and a restored disk cannot move the
counter back. It signs only while authtime says the clock is authenticated; otherwise it signs nothing,
the nodes' heartbeats age, and heartbeat_watch warns. Several authorities share the sequence space by
offset and stride (authority k of n signs sequences = k mod n).

THE INTERVAL is bounded at start: at least heartbeat.MIN_INTERVAL_S times the stride (a node accepts a
sequence jump that grows by one per MIN_INTERVAL_S of issue time, so an authority that signed faster
would look like an anomaly), and at most a quarter of the heartbeat's lifetime (heartbeat_watch warns at
half).

REVOCATION (revoke). The next manifest is the current one with one node's state made more restrictive
(QUARANTINED or REVOKED_STOLEN), epoch + 1, signed by the revocation key. membership's rule for a
revocation-signed change is checked by the Store before anything is kept: same nodes, identities, policy
and keys, capabilities only shrink. Anything permissive (reinstating, enrolling) is the root's and is
refused. A heartbeat for the new manifest is signed at once, through the same counter: peers authorize
under the revocation without waiting for the next interval. If the process stops between the two, the
next start finds the store ahead of the heartbeat and signs one first.

ROOT MANIFESTS (accept) come from the root ceremony and are committed as they are (Store verifies them).

PUBLISHING (serve) is sync.Server with no attester and no signer, on the authority's tunnel address: the
nodes pull the chain and the latest heartbeat from it ("a source that issues no leases").

THE OWNER'S DECISIONS ARE SETTINGS (#199): `signer` (key custody: "file" now, "pkcs11" when a token is
chosen; every trail line and `status` name the kind), `sequence_offset`/`sequence_stride` (how many
authorities), `interval_s`/`lifetime_s`, and `revoke_requesters` (only "local-root": the command run as
root on this host; nothing here takes a revocation request from the network).

NOT HERE: where the authority runs, the root key's ceremony, and a networked revocation request.
"""
import argparse
import json
import os
import re
import socket
import stat
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
        "sequence_offset", "sequence_stride", "revoke_requesters", "wg_service_key", "underlays", "listen_port", "sync_port")
SIGNER_KINDS = ("file", "pkcs11")
REQUESTERS = ("local-root",)
RESTRICTIVE = ("QUARANTINED", "REVOKED_STOLEN")
HEARTBEAT = "heartbeat.json"


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
    for k in ("state_dir", "run_dir", "wg_service_key"):
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
        self.lock = threading.Lock()

    def path(self, name):
        return os.path.join(self.cfg["state_dir"], name)

    # ---- what it publishes ----

    def held(self):
        """The latest heartbeat envelope it signed, or None: what sync.Server hands to a puller."""
        try:
            with open(self.path(HEARTBEAT), "rb") as f:
                return membership.load(f.read(heartbeat.MAX_BYTES + 1), heartbeat.MAX_BYTES)
        except FileNotFoundError:
            return None

    def _publish(self, envelope):
        fd, tmp = tempfile.mkstemp(dir=self.cfg["state_dir"], prefix=".heartbeat-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(json.dumps(envelope, sort_keys=True).encode())
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path(HEARTBEAT))
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ---- the sequence ----

    def next_sequence(self):
        """The smallest sequence above the TPM counter that is this authority's (offset mod stride)."""
        now, stride, offset = self.counter.value(), self.cfg["sequence_stride"], self.cfg["sequence_offset"]
        candidate = now + 1
        return candidate + (offset - candidate) % stride

    def lifetime(self, manifest):
        bound = heartbeat.max_lifetime(manifest)
        lifetime = min(self.cfg["lifetime_s"] or bound, bound)
        require(self.cfg["interval_s"] * 4 <= lifetime, "interval_s %d is more than a quarter of the heartbeat lifetime %d s under epoch %d"
                % (self.cfg["interval_s"], lifetime, manifest["epoch"]))
        return lifetime

    # ---- signing ----

    def beat(self, reason="interval"):
        """Sign and publish a heartbeat for the manifest held now. The counter moves FIRST."""
        with self.lock:
            manifest = self.store.load()
            seconds, authenticated = self.clock()
            require(authenticated, "time is not authenticated: no heartbeat is signed")
            lifetime = self.lifetime(manifest)
            sequence = self.next_sequence()
            self.counter.advance(sequence, self.cfg["sequence_stride"])        # a crash after this loses the number, never reuses it
            body = {"schema": heartbeat.SCHEMA, "epoch": manifest["epoch"], "sequence": sequence, "issued_at": stamp(seconds),
                    "expires_at": stamp(seconds + lifetime), "manifest_digest": membership.digest(manifest)}
            envelope = {"heartbeat": body, "signature": {"key": self.signer.public(),
                                                         "sig": self.signer.sign(heartbeat.DOMAIN + membership.canonical(body)).hex()}}
            heartbeat.verify(envelope, manifest)                                 # the key is one the manifest names, and it verifies
            self.trail({"event": "authority-heartbeat", "outcome": "SIGNED", "epoch": manifest["epoch"], "sequence": sequence,
                        "digest": body["manifest_digest"], "expires_at": body["expires_at"], "key": self.signer.public(),
                        "signer": self.signer.kind, "reason": reason})
            self._publish(envelope)
            return envelope

    def catch_up(self):
        """At start: if the store is ahead of the published heartbeat (a revocation whose heartbeat was never
        signed: the process stopped between the two), sign one now. Returns the envelope, or None."""
        held, manifest = self.held(), self.store.load()
        if held is None or held["heartbeat"]["epoch"] != manifest["epoch"]:
            return self.beat("the store is at epoch %d and no heartbeat for it was published" % manifest["epoch"])
        return None

    def revoke(self, node_id, state, reason, requester):
        """Sign and commit the manifest that makes `node_id` QUARANTINED or REVOKED_STOLEN, then sign a
        heartbeat for it at once. Returns (manifest envelope, heartbeat envelope)."""
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
            self.trail({"event": "authority-revoke", "outcome": "SIGNED", "epoch": candidate["epoch"], "node": node_id, "state": state,
                        "digest": membership.digest(candidate), "key": self.signer.public(), "signer": self.signer.kind,
                        "requester": requester, "reason": reason})
        return envelope, self.beat("revocation of %s" % node_id)

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
                "heartbeat": held["heartbeat"] if held else None, "signer": self.signer.kind, "key": self.signer.public(),
                "interval_s": self.cfg["interval_s"], "lifetime_s": self.lifetime(manifest),
                "sequence_offset": self.cfg["sequence_offset"], "sequence_stride": self.cfg["sequence_stride"]}

    # ---- serving ----

    def serve(self, stop, sleep=time.sleep):
        """Publish on the tunnel address and sign every interval until `stop()`. A heartbeat that cannot be
        signed (time not authenticated, a TPM error) is retried after a minute, and recorded."""
        own = wgsvc.address(self.signer_tunnel_key())
        listener = node.bind_when_up((own, self.cfg["sync_port"]), stop, family=socket.AF_INET6)
        listener.settimeout(1)
        server = sync.Server(convergence.AUTHORITY, self.store, self, None, None, wgsvc.key_at, self.trail)
        threading.Thread(target=sync.serve, args=(server, listener, stop), daemon=True).start()
        try:
            due = 0.0
            while not stop():
                if time.monotonic() >= due:
                    try:
                        self.catch_up() or self.beat()
                        due = time.monotonic() + self.cfg["interval_s"]
                    except (Refused, OSError) as failure:
                        self.trail({"event": "authority-heartbeat", "outcome": "FAILED", "reason": str(failure)[:240], "signer": self.signer.kind})
                        due = time.monotonic() + 60
                sleep(1)
        finally:
            listener.close()

    def signer_tunnel_key(self):
        with open(self.cfg["wg_service_key"]) as f:
            private = f.read(200).strip()
        return wgsvc.hex_key(self.run(["wg", "pubkey"], input=(private + "\n").encode(), capture_output=True, timeout=10).stdout.decode().strip())


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
        authority = Authority(load(args.config))
        if args.command == "serve":
            authority.serve(lambda: False)
        elif args.command == "status":
            print(json.dumps(authority.status(), indent=1, sort_keys=True))
        elif args.command == "wg-apply":
            print("wg-svc applied: %s" % wg_apply(authority))
        elif args.command == "revoke":
            require(os.geteuid() == 0, "a revocation is requested as root on this host (local-root)")
            envelope, beat = authority.revoke(args.node, args.state, args.reason, "local-root")
            print("epoch %d: %s is %s; heartbeat %d published" % (envelope["manifest"]["epoch"], args.node, args.state, beat["heartbeat"]["sequence"]))
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
