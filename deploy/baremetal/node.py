#!/usr/bin/env python3
"""A KMS node's running services, assembled from one configuration file (#80, step 3b).

    python3 -Es -m deploy.baremetal.node --config /etc/regalia/node.json authtime | wg-apply | boot-session | admission | sync

Five processes, each the smallest one that can do its part. Only the first three are root, and none of
them parses what a peer sends except `sync` and `admission`, which hold no capability and are not root:

    authtime   root, CAP_DAC_OVERRIDE   asks chrony whether time is authenticated; writes
                                        /run/regalia/authtime.json (authtime.py)
    wg-apply   root, CAP_NET_ADMIN      makes wg-svc and wg-unlock what the CURRENT manifest says, and
                                        reads the result back (wgsvc.py, bootnet.py); a oneshot, run at
                                        boot and again whenever the published chain changes
    boot-session  root, no capability   a oneshot: on a boot where the unlock client presented no
                                        session (the disk opened with the recovery key), makes one and
                                        leaves the pair in /run/regalia, as the client would have
    admission  its own user (regalia-admission, #191), no capability, the TPM through its group
                                        holds this node's runtime lease, asking peers through the
                                        service tunnel; writes /run/regalia/admission/admission.json
                                        for the KMS daemon (admission.py)
    sync       its own user, no capability, the TPM through its group
                                        answers peers on wg-svc (sync.py) and booting nodes on
                                        wg-unlock (unlock.py), pulls manifests and heartbeats from the
                                        peers and the revocation authority, keeps the membership store,
                                        and runs the heartbeat watch (heartbeat_watch.py)

ONE WRITER OF THE MEMBERSHIP CHAIN. `sync` owns the store (membership.Store: its files are its own, 0600).
After every change it PUBLISHES the verified chain, 0644, beside it (publish()). The other services read
that copy and verify it themselves (published()): every signature and transition from the root key, and
the TPM anchor, which only goes up. A `sync` that is compromised can therefore withhold a newer chain or
publish an older one, and either way the other services see a chain below the anchor and refuse it: the
node stops serving, it does not go on under an old manifest.

THE BOOT SESSION. A runtime lease is asked for with a quote over this boot's session, and a peer allows
one session per boot of a node's TPM. If the unlock client presented one in the initrd it left
/run/regalia/boot-session (64 hex) and boot-session.pub (hex of the key's DER); `boot-session` is written
last and is the marker. boot_session() uses that pair. With no `boot-session` at all (the disk opened with
the recovery key before any peer was asked) the root oneshot `boot-session` makes a session and writes the
pair, the same way, before `admission` starts; `admission` only reads it, since it is not root and
/run/regalia is root's, and the KMS daemon accepts the session only from root (#191). A `boot-session`
without its key, or either malformed, is a refusal: the right session cannot be guessed, and a wrong one
would be refused by the peer that holds the right one.

THE TRAIL. Each service appends its audit events to its own file (one JSON object per line, fsynced) in
its own state directory. Shipping them off the host is the audit pipeline's job, not this module's.

NOT HERE: the systemd units, the AppArmor profiles and the probes (#80 step 3b, next); enrolment, which
writes the trust anchors this configuration points at (#190); the revocation authority (#199).
"""
import argparse
import binascii
import contextlib
import errno
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

from deploy.baremetal import (admission, attest, authtime, bootnet, convergence, heartbeat, heartbeat_watch, lease,
                              measurements, membership, sitecfg, sync, unlock, wgsvc)

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.node/v1"
KEYS = ("schema", "node_id", "site", "root_key", "tcti", "nv_epoch", "nv_heartbeat", "state_dir", "admission_dir", "run_dir",
        "wg_service_key", "measurements", "pcrs", "time_servers", "pull_interval")
PUBLISHED = "chain.json"        # in the state directory: the verified chain, for the root services
MAX_BYTES = 64 * 1024


# ---- the configuration ----

def _absolute(value, label):
    require(isinstance(value, str) and value.startswith("/") and "\0" not in value and os.path.normpath(value) == value,
            "%s must be an absolute, normalised path" % label)
    return value


def _index(value, label):
    require(isinstance(value, str) and re.fullmatch(r"0x01[0-9a-f]{6}", value) is not None, "%s must be an NV index, 0x01xxxxxx" % label)
    return value


def validate(doc):
    """The node configuration, checked. Every field is required and nothing else is allowed."""
    membership.exact(doc, KEYS, "node configuration")
    require(doc["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(doc["node_id"], str) and re.fullmatch(sitecfg.NODE_ID, doc["node_id"]) is not None, "node_id is not a node ID")
    membership.hex_field(doc["root_key"], 64, "root_key")
    require(doc["tcti"] is None or (isinstance(doc["tcti"], str) and re.fullmatch(r"[a-z]+(:[A-Za-z0-9/_.,=-]{1,200})?", doc["tcti"]) is not None),
            "tcti must be null (the kernel's resource manager) or a TCTI string")
    epoch, beat = _index(doc["nv_epoch"], "nv_epoch"), _index(doc["nv_heartbeat"], "nv_heartbeat")
    # what each really occupies, from the classes that define them (the anchor: counter, base and two record
    # slots; the heartbeat counter: counter and base), never retyped here
    overlap = membership.HighWater(epoch).indices() & heartbeat.Counter(beat).indices()
    require(not overlap, "nv_epoch and nv_heartbeat must not overlap (both take %s): the anchor takes %s, the heartbeat counter %s" % (
        ", ".join("0x%x" % i for i in sorted(overlap)), ", ".join("0x%x" % i for i in sorted(membership.HighWater(epoch).indices())),
        ", ".join("0x%x" % i for i in sorted(heartbeat.Counter(beat).indices()))))
    for key in ("site", "state_dir", "admission_dir", "run_dir", "wg_service_key", "measurements"):
        _absolute(doc[key], key)
    # each directory has ONE writer: sync's, admission's (regalia-admission, #191), and the run directory (root)
    require(len({doc["state_dir"], doc["admission_dir"], doc["run_dir"]}) == 3, "state_dir, admission_dir and run_dir must be three directories")
    pcrs = doc["pcrs"]
    require(isinstance(pcrs, list) and pcrs and all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i <= 23 for i in pcrs)
            and pcrs == sorted(set(pcrs)), "pcrs must be an ascending list of PCR indices 0-23")
    authtime.servers(doc["time_servers"])
    interval = doc["pull_interval"]
    require(isinstance(interval, int) and not isinstance(interval, bool) and 10 <= interval <= 3600, "pull_interval must be 10 to 3600 seconds")
    return doc


def load(path):
    with open(path, "rb") as f:
        return validate(membership.load(f.read(MAX_BYTES + 1), MAX_BYTES))


# ---- the published chain ----

def publish(store, path):
    """Write the store's verified chain where the root services read it: complete or not at all, 0644."""
    envelopes = store.envelopes(0)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".chain-")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(membership.canonical(envelopes))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return envelopes[-1]["manifest"] if envelopes else None


def published(path, root_key, anchor):
    """The current manifest by the published chain, verified here: every envelope from the root key, and the
    chain the TPM anchors (`anchor`, a membership.HighWater): not below its epoch (ROLLBACK), and at that
    epoch the very manifest its record names, so a fork the TPM never recorded is refused (CONFLICT). The
    read takes no lock (these services cannot write regalia-sync's lock directory); a CONFLICT can be a
    commit racing the read, so it is read once more before it stands."""
    # The file is written by a process that parses what other machines send, and read here by root: no
    # symlink is followed, and nothing but a regular file is read (a FIFO would hang the reader).
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as failure:
        raise Refused("the published membership chain cannot be read (%s)" % type(failure).__name__) from None
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "the published membership chain is not a regular file")
        chunks, size = [], 0
        while size <= membership.MAX_CHAIN_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    envelopes = membership.load(raw, membership.MAX_CHAIN_BYTES)        # refuses a deeply nested document itself
    require(isinstance(envelopes, list) and envelopes, "the published membership chain is empty")
    manifest = membership.accept_chain(None, envelopes, root_key)
    manifests = [e["manifest"] for e in envelopes]                       # verified, epoch 1 first

    def digest_of(epoch):
        require(epoch <= len(manifests), "ROLLBACK: the published chain ends at epoch %d, below the TPM anchor %d" % (len(manifests), epoch))
        return membership.digest(manifests[epoch - 1]) if epoch else membership.HighWater.ZERO
    try:
        anchor.verify(digest_of, lock=False)
    except Refused as refused:
        if str(refused).startswith("ROLLBACK"):
            raise
        anchor.verify(digest_of, lock=False)        # a commit may have been racing the read: it stands only if it stays
    return manifest


# ---- the boot session ----

def boot_session(run_dir, rand=os.urandom, make=False):
    """(session ID, the key's DER) of this boot: the unlock client's, or, with `make` (the root oneshot
    only), one made now. Without `make`, no session is a refusal. See the module."""
    marker, key = os.path.join(run_dir, "boot-session"), os.path.join(run_dir, "boot-session.pub")

    def read(path, label, pattern):
        with open(path, "rb") as f:
            text = f.read(2048).decode("ascii", "replace")
        require(re.fullmatch(pattern, text) is not None, "%s is malformed" % label)
        return text.strip()
    if os.path.exists(marker):
        session = read(marker, "boot-session", r"[0-9a-f]{64}\n")
        require(os.path.exists(key), "boot-session names a session whose key is missing: it cannot be presented again")
        public = bytes.fromhex(read(key, "boot-session.pub", r"([0-9a-f]{2}){1,512}\n"))
        return session, public
    require(make, "this boot has no session in %s: regalia-boot-session.service makes one before the lease service starts" % run_dir)
    session, public = rand(32).hex(), b"regalia-kms runtime session " + rand(32)
    for path, text in ((key, public.hex()), (marker, session)):      # the key first: the marker says both are there
        fd, tmp = tempfile.mkstemp(dir=run_dir, prefix=".boot-session-")
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(text + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
    return session, public


# ---- the trail ----

class Trail:
    """Audit events, one JSON object a line, appended and fsynced. Raises if it cannot write: callers that
    must not act unrecorded (sync.Server) refuse to answer then."""

    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def __call__(self, event):
        line = json.dumps(dict(event, at=int(time.time())), sort_keys=True).encode() + b"\n"
        with self.lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)


# ---- the node ----

class Node:
    """The configured node's parts. `run` is subprocess.run (or a fake): every TPM, chrony, wg and ip call
    goes through it."""

    def __init__(self, cfg, run=subprocess.run):
        self.cfg, self.run, self.node_id = validate(cfg), run, cfg["node_id"]
        self.site = sitecfg.load(cfg["site"])
        require(self.site["boot_mesh"] is not None and self.site["service_mesh"] is not None,
                "the site configuration has no boot_mesh or no service_mesh: this is not a node of a three-site cluster")
        require(self.site["boot_mesh"]["node_id"] == self.node_id, "the site configuration is %s's, not %s's" % (self.site["boot_mesh"]["node_id"], self.node_id))
        self.state, self.runtime, self.tcti = cfg["state_dir"], cfg["run_dir"], cfg["tcti"]

    def path(self, name):
        """A file of `sync`'s state directory (the membership store, the published chain, freshness...)."""
        return os.path.join(self.state, name)

    def held(self, name):
        """A file of the admission service's own directory (its lease and its trail)."""
        return os.path.join(self.cfg["admission_dir"], name)

    # the shared view of time
    def clock(self):
        return authtime.clock(os.path.join(self.runtime, "authtime.json"))

    def tpm_clock(self):
        return heartbeat.TpmClock(self.tcti, self.run)

    def anchor(self):
        """The membership epoch anchor: membership.HighWater on its own index (and the pair and slots after it)."""
        return membership.HighWater(self.cfg["nv_epoch"], self.tcti, self.run, lock_path=self.path("highwater.lock"))

    def manifest(self, patience=2.0, step=0.25):
        """The current manifest, by the published chain, verified (the root services' view).

        `sync` commits a manifest (the TPM anchor moves) and publishes it a moment later. A reader in
        between sees a chain below the anchor. It waits up to `patience` seconds for the publication
        before it refuses: long enough for an honest `sync`, far too short to matter if `sync` withholds."""
        anchor, deadline = self.anchor(), time.monotonic() + patience
        while True:
            try:
                return published(self.path(PUBLISHED), self.cfg["root_key"], anchor)
            except Refused as refused:
                if not str(refused).startswith("ROLLBACK") or time.monotonic() >= deadline:
                    raise
            time.sleep(step)

    # sync's parts
    def store(self):
        return membership.Store(self.path("membership.json"), self.cfg["root_key"], self.anchor())

    def freshness(self):
        counter = heartbeat.Counter(self.cfg["nv_heartbeat"], self.tcti, self.run, lock_path=self.path("heartbeat-counter.lock"))
        return heartbeat.Freshness(counter, self.clock(), self.tpm_clock(), self.path("freshness.json"))

    def attester_for(self, manifest):
        with open(self.cfg["measurements"], "rb") as f:
            document = measurements.load(f.read(measurements.MAX_BYTES + 1))
        policy = measurements.attest_policy(manifest, document, self.node_id)
        return attest.Verifier(policy, self.path("attest.json"), run=self.run)

    def peers(self, manifest):
        """{node ID: its service-tunnel address} for every other node this one may talk to."""
        return {n["node_id"]: wgsvc.address(n["wg_service_pub"]) for n in manifest["nodes"]
                if n["node_id"] != self.node_id and n["state"] not in membership.TERMINAL}

    def sources(self, manifest, timeout=sync.DEADLINE):
        """sync.Client transports: the peers, and the revocation authority if the site names one."""
        mine, port = self.own_address(manifest), self.site["service_mesh"]["sync_port"]
        transports = {node: sync.tcp_transport(where, port, mine, timeout) for node, where in self.peers(manifest).items()}
        authority = self.site["service_mesh"]["authority"]
        if authority is not None:
            transports[convergence.AUTHORITY] = sync.tcp_transport(wgsvc.address(authority["key"]), port, mine, timeout)
        return transports

    def own_address(self, manifest):
        entries = {n["node_id"]: n for n in manifest["nodes"]}
        require(self.node_id in entries, "%s is not in the manifest" % self.node_id)
        return wgsvc.address(entries[self.node_id]["wg_service_pub"])

    def private_key(self):
        with open(self.cfg["wg_service_key"]) as f:
            return f.read(200).strip()

    def quote(self, session_id, ephemeral_public):
        """A `quote(nonce hex, manifest)` for sync.Client.renewer: this node's TPM quote over its boot
        session, the manifest's epoch and the peer's nonce."""
        def evidence(nonce, manifest):
            with tempfile.TemporaryDirectory(prefix="regalia-quote-") as d:
                paths = (os.path.join(d, "quote"), os.path.join(d, "signature"))
                old = os.environ.get("TPM2TOOLS_TCTI")
                if self.tcti:
                    os.environ["TPM2TOOLS_TCTI"] = self.tcti
                try:
                    attest.node_quote(self.node_id, manifest["epoch"], bytes.fromhex(session_id), ephemeral_public, bytes.fromhex(nonce),
                                      self.cfg["pcrs"], *paths, run=self.run)
                finally:
                    if self.tcti:
                        os.environ.pop("TPM2TOOLS_TCTI") if old is None else os.environ.__setitem__("TPM2TOOLS_TCTI", old)
                quote, signature = (open(p, "rb").read().hex() for p in paths)
            return {"ephemeral_public": ephemeral_public.hex(), "nonce": nonce, "quote": quote, "signature": signature}
        return evidence


# ---- the four services ----

def wg_apply(node):
    """Make wg-svc and wg-unlock what the current manifest says, and read both back. ANY refusal, the
    manifest's own included (a chain that does not verify, or is below the TPM anchor), leaves BOTH
    interfaces down: a peer list that is not the current manifest's is not one to answer on. An interrupt
    stays an interrupt, with an interface that could not be taken down noted on it."""
    mesh, svc = node.site["boot_mesh"], node.site["service_mesh"]
    names = (svc["interface"], mesh["interface"])
    try:
        manifest = node.manifest()
        underlays = {p["node_id"]: p["underlay"] for p in mesh["peers"]}
        key = node.private_key()
        wgsvc.reconcile(manifest, node.node_id, underlays, key, svc["authority"], svc["listen_port"], svc["interface"], node.run)
        name, text = mesh["interface"], bootnet.peer_wg_conf(node.site, manifest)
        # as wgsvc.reconcile: nothing is carried until the peers are applied and read back
        present = node.run(["ip", "link", "show", "dev", name], capture_output=True, timeout=10).returncode == 0
        steps = ([] if present else [["ip", "link", "add", "dev", name, "type", "wireguard"]]) + [
            ["ip", "address", "replace", mesh["address"] + "/32", "dev", name]]
        for argv in steps:
            require(node.run(argv, capture_output=True, timeout=10).returncode == 0, "%s failed" % " ".join(argv[:4]))
        done = node.run(["wg", "syncconf", name, "/dev/stdin"], capture_output=True, timeout=10, input=bootnet.with_key(text, key).encode())
        require(done.returncode == 0, "the unlock tunnel's configuration could not be applied")
        wgsvc.verify(text, name, node.run)
        for argv in [["ip", "link", "set", "dev", name, "up"]] + [["ip", "route", "replace", p["address"] + "/32", "dev", name] for p in mesh["peers"]]:
            require(node.run(argv, capture_output=True, timeout=10).returncode == 0, "%s failed" % " ".join(argv[:4]))
    except BaseException as failure:
        stuck = []
        for name in names:
            try:
                wgsvc.down(name, node.run)
            except Refused as refused:
                stuck.append(str(refused))
        if stuck and not isinstance(failure, Exception):
            for note in stuck:
                failure.add_note(note)
            raise failure from None
        if stuck:
            raise Refused("%s; and %s" % (failure, "; ".join(stuck))) from None
        raise
    return manifest["epoch"]


def admission_file(run_dir):
    """Where the lease service writes and the daemon reads: a directory of the lease service's own user
    inside root's run directory (regalia.tmpfiles.conf), so it can replace the file and nothing else there."""
    return os.path.join(run_dir, "admission", "admission.json")


def admission_service(node, daemon_started=None, rand=os.urandom):
    """The lease holder and the admission file, asking peers in turn for a lease over the service tunnel."""
    session, public = boot_session(node.runtime, rand)
    holder = lease.Holder(node.node_id, session, node.clock(), node.tpm_clock(), node.held("lease.json"), run=node.run)
    trail = Trail(node.held("audit.jsonl"))

    class Manifest:
        load = staticmethod(node.manifest)
    order = []

    def renew(request):
        manifest = node.manifest()
        sources = node.sources(manifest)
        peers = [name for name in sorted(sources) if name != convergence.AUTHORITY]
        require(peers, "no peer to ask for a lease")
        order[:] = order[1:] + order[:1] if order and set(order) == set(peers) else peers
        failures = []
        for name in list(order):
            client = sync.Client(node.node_id, Manifest, None, sources, trail)
            try:
                return client.renewer(name, node.quote(session, public))(request)
            except Refused as refused:
                failures.append("%s: %s" % (name, refused))
        raise Refused("no peer gave a lease (%s)" % "; ".join(failures))
    return admission.Service(holder, node.manifest, renew, admission_file(node.runtime),
                             daemon_started=daemon_started or admission.unit_started())


class Sync:
    """The `sync` process: the two listeners, the pull loop and the heartbeat watch, on one store."""

    def __init__(self, node):
        self.node, self.store, self.freshness = node, node.store(), node.freshness()
        self.trail = Trail(node.path("sync-audit.jsonl"))
        self.signer = lease.TpmSigner(node.tcti, node.run)
        self.published = None

    def manifest(self):
        return self.store.load()

    def server(self):
        manifest = self.manifest()
        return sync.Server(self.node.node_id, self.store, self.freshness, self.node.attester_for(manifest), self.signer,
                           wgsvc.key_at, self.trail)

    def unlock_peer(self):
        return unlock.Peer(self.node.node_id, self.store, self.freshness, self.node.attester_for,
                           unlock.Contributions(self.node.path("contributions.json")), self.signer, self.trail, run=self.node.run)

    def caller(self, address):
        """unlock.serve's `caller`: the node a boot-tunnel address belongs to, by the manifest held NOW."""
        try:
            return bootnet.caller_of(self.node.site, self.manifest())(address)
        except Refused:
            return None

    def publish(self):
        """Publish the chain if it changed. Returns whether it did (wg-apply's path unit then runs)."""
        current = convergence.summary(self.store)
        if current == self.published:
            return False
        publish(self.store, self.node.path(PUBLISHED))
        self.published = current
        return True

    def pull_round(self):
        """Ask every source once. A source that refuses or does not answer is recorded and skipped. The
        chain is published after EACH source, not after all of them: a commit moves the TPM anchor, and
        the root services refuse the published chain until it catches up (Node.manifest)."""
        sources = self.node.sources(self.manifest())
        client = sync.Client(self.node.node_id, self.store, self.freshness, sources, self.trail)
        changed = False
        for name in sorted(sources):
            with contextlib.suppress(Refused):
                client.pull(name)
            changed = self.publish() or changed
        return changed

    def watch(self):
        return heartbeat_watch.Watch(self.freshness, self.manifest, self.trail, self.node.path("heartbeat.prom"),
                                     self.node.path("heartbeat-watch.json"))

    def run(self, stop):
        """Until `stop()`: the listeners in threads, then the pull loop and the watch in this one."""
        self.publish()
        mesh, svc = self.node.site["boot_mesh"], self.node.site["service_mesh"]
        listeners = []
        service = bind_when_up((self.node.own_address(self.manifest()), svc["sync_port"]), stop, family=socket.AF_INET6)
        service.settimeout(1)
        listeners.append(service)
        unlocking = bind_when_up((mesh["address"], mesh["unlock_port"]), stop)
        listeners.append(unlocking)
        threads = [threading.Thread(target=sync.serve, args=(self.server(), service, stop), daemon=True),
                   threading.Thread(target=unlock.serve, args=(self.unlock_peer(), unlocking), kwargs={"caller": self.caller}, daemon=True)]
        for thread in threads:
            thread.start()
        watch = self.watch()
        try:
            while not stop():
                self.pull_round()
                with contextlib.suppress(Refused, OSError):
                    watch.step()
                deadline = time.monotonic() + self.node.cfg["pull_interval"]
                while not stop() and time.monotonic() < deadline:
                    time.sleep(1)
        finally:
            for listener in listeners:
                listener.close()


def bind_when_up(where, stop, family=socket.AF_INET, create=socket.create_server, sleep=time.sleep):
    """A listener on a tunnel address, once the tunnel has it. On a host's first start the tunnels do not
    exist yet: regalia-wg-apply makes them from the chain this process has just published. Waiting here,
    rather than exiting, keeps the service from restarting in a loop until they appear."""
    while True:
        try:
            return create(where, family=family)
        except OSError as failure:
            if failure.errno != errno.EADDRNOTAVAIL or stop():
                raise
        sleep(1)


def authtime_service(cfg):
    """Takes the configuration only: it reads nothing else (not the site configuration, not a key), and
    its unit hides the rest of /etc and all of /var from it."""
    return authtime.Service(os.path.join(cfg["run_dir"], "authtime.json"), cfg["time_servers"])


# ---- command line ----

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/regalia/node.json")
    parser.add_argument("service", choices=("authtime", "wg-apply", "boot-session", "admission", "sync", "check"))
    args = parser.parse_args(argv)
    try:
        if args.service == "authtime":
            authtime_service(load(args.config)).run(lambda: False)
            return 0
        if args.service == "boot-session":
            # takes the configuration only, like authtime: it needs the run directory and nothing else
            run_dir = load(args.config)["run_dir"]
            had = os.path.exists(os.path.join(run_dir, "boot-session"))
            session, _ = boot_session(run_dir, make=True)
            print("boot session %s…, %s" % (session[:16], "the unlock client's" if had else "made now: the unlock client presented none"))
            return 0
        node = Node(load(args.config))
        if args.service == "check":
            print(json.dumps({"node_id": node.node_id, "epoch": node.manifest()["epoch"]}))
        elif args.service == "wg-apply":
            print("wg-svc and %s applied under epoch %d" % (node.site["boot_mesh"]["interface"], wg_apply(node)))
        elif args.service == "admission":
            admission_service(node).run(lambda: False)
        else:
            Sync(node).run(lambda: False)
    except (OSError, Refused, sitecfg.InvalidSite, binascii.Error) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
