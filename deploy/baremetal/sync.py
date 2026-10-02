#!/usr/bin/env python3
"""regalia-sync: the transport between running KMS nodes (#80; the design is on that issue).

It carries what the libraries already verify, and decides two things of its own: WHO a message came from,
and HOW MUCH of it is accepted.

    op            request                                  answer                      decided by
    pull          the caller's summary (epoch, digest)     this node's summary, and    convergence.bundle
                  and the sequence of the heartbeat it     a bundle: the envelopes
                  holds (0: none)                          the caller lacks, and the
                                                           heartbeat at the tip if it
                                                           is newer than the caller's
    lease-nonce   the caller's node_id                     a nonce                     attest.Verifier.nonce
    lease         the caller's lease request and its       a lease                     lease.issue
                  fresh quote over that nonce

PULL ONLY. Nobody pushes. A node asks each peer and the authority on a timer (Client.pull) and applies
what it gets through convergence.apply_bundle. A source that lies or withholds can DELAY a node and
nothing more: every envelope and heartbeat is verified against the node's own TPM anchors as if a
stranger had sent it. That holds for the revocation authority's channel too.

WHO. The caller is the node whose WireGuard key the CURRENT manifest pins (peer_of), and nothing the
caller says in-band identifies it. `identify(source)` is injected: it answers which WireGuard public key
owns the source address of a connection (on a host, asked of the kernel: wgsvc, #80 step 2). That key is
looked up in the manifest this node holds NOW, for every request, so a node revoked in the manifest is
refused although its tunnel is still up. A message that names a node (lease-nonce, lease) must name the
node the tunnel identified. A node in a terminal state gets nothing, not even a pull.

HOW MUCH.
  * one request per connection; canonical JSON; a version and an operation; EXACT fields, anything
    unknown refused;
  * a request is at most 64 KiB, an answer at most 1 MiB. A bundle carries at most 64 envelopes and is cut
    further until it fits, so a node far behind catches up over several pulls (a bundle short of the tip
    carries no heartbeat: convergence.bundle);
  * per caller, a token bucket: 20 requests a minute, of which 6 may be lease requests;
  * (the socket layer, serve) 8 connections at once, 2 from one address, 10 seconds each.

EVERY ACCEPT AND EVERY REFUSAL IS ONE AUDIT EVENT (convergence.audited): the operation, the epoch and
digest it was decided under, the caller the tunnel identified (its source address when it could not be
identified), ALLOW or DENY, and the reason. A refusal the caller is told about says the same reason.

NOT A REFUSAL: a caller that is ahead of this node. It is answered with this node's summary and an empty
bundle, and learns from the summary that it is the one with something to offer. Nor is a caller that
already holds this node's heartbeat: it gets none, where the same one again would be refused as a replay.

A SOURCE THAT ISSUES NO LEASES (the revocation authority) runs the same Server with no attester: it
answers pull, and refuses the two lease operations.

NO TLS. WireGuard authenticates both ends by the pinned keys and encrypts; every payload that matters is
signed or attested end to end. See #80.

NOT HERE: the WireGuard interface and the kernel lookup behind `identify` (step 2); units, firewall
rules and probes (step 3); convergence.recover over this transport.
"""
import socket
import threading
import time

from deploy.baremetal import convergence, heartbeat, lease, membership

Refused, require = membership.Refused, membership.require

VERSION = 1
PORT = 7444                      # TCP, on the service tunnel only (7443 is the peer-unlock listener, #66)
MAX_REQUEST = 64 * 1024
MAX_ANSWER = 1024 * 1024
MAX_ENVELOPES = 64               # per bundle; convergence allows 1000, which an answer of 1 MiB does not
REQUEST_FIELDS = {"pull": ("v", "op", "summary", "sequence"),
                  "lease-nonce": ("v", "op", "node_id"),
                  "lease": ("v", "op", "request", "evidence")}
ANSWER_FIELDS = {"pull": ("v", "ok", "summary", "bundle"),
                 "lease-nonce": ("v", "ok", "nonce"),
                 "lease": ("v", "ok", "lease")}
REFUSAL_FIELDS = ("v", "ok", "refused")
EVIDENCE_FIELDS = ("ephemeral_public", "nonce", "quote", "signature")
RATE = {"any": (20, 60), "lease": (6, 60)}      # class -> (requests, per seconds); the bucket holds that many
MAX_CONNECTIONS, MAX_PER_ADDRESS, DEADLINE = 8, 2, 10
MAX_ROUNDS = 64                  # pulls in one catch-up: 64 * 64 epochs, then the next timer tick goes on


def pinned(manifest, key, field="wg_service_pub"):
    """The manifest's entry for the node the WireGuard public key `key` (64 hex) is pinned to. The manifest's
    own validation keeps identities unique, so at most one node matches; a second match is refused rather
    than chosen between."""
    membership.hex_field(key, 64, "the tunnel's key")
    found = [node for node in manifest["nodes"] if node.get(field) == key]
    require(len(found) == 1, "the tunnel's key is not pinned to a node by the current manifest (epoch %d)" % manifest["epoch"])
    return found[0]


def peer_of(manifest, key, field="wg_service_pub"):
    """The ID of the node `key` is pinned to, if it may still be talked to: a node in a terminal state
    (RETIRED, REVOKED_STOLEN) gets nothing."""
    node = pinned(manifest, key, field)
    require(node["state"] not in membership.TERMINAL, "%s is %s under epoch %d" % (node["node_id"], node["state"], manifest["epoch"]))
    return node["node_id"]


class Buckets:
    """Token buckets, one per (caller, class). `clock()` is monotonic seconds."""

    def __init__(self, rates=None, clock=time.monotonic):
        self.rates, self.clock = dict(RATE if rates is None else rates), clock
        self.state, self.lock = {}, threading.Lock()

    def take(self, caller, kind):
        """Spend one request of `kind` for `caller`, or Refused."""
        count, per = self.rates[kind]
        with self.lock:
            now = self.clock()
            tokens, at = self.state.get((caller, kind), (float(count), now))
            tokens = min(float(count), tokens + max(0.0, now - at) * count / per)
            require(tokens >= 1.0, "RATE: more than %d %s requests in %d s from %s" % (count, kind, per, caller))
            self.state[(caller, kind)] = (tokens - 1.0, now)


def _refusal(reason):
    return membership.canonical({"v": VERSION, "ok": False, "refused": convergence._printable(reason)})


class Server:
    """One node's answering side. `store`, `freshness`, `attester` and `signer` are the node's own
    membership.Store, heartbeat.Freshness (anything with held() will do for a source that issues no leases),
    attest.Verifier and lease signer (None for such a source); `identify(source)` returns the
    WireGuard public key (hex) that owns a connection's source address, or raises Refused; `sink(event)`
    takes each audit event."""

    def __init__(self, node_id, store, freshness, attester, signer, identify, sink, buckets=None):
        self.node_id, self.store, self.freshness, self.attester, self.signer = node_id, store, freshness, attester, signer
        self.identify, self.sink, self.buckets = identify, sink, buckets or Buckets()

    def handle(self, raw, source):
        """The answer (bytes) to one request from `source`. A refusal is an answer, and so is a failure
        inside this node. Only a sink that cannot take the event raises: nothing is answered that is not
        recorded."""
        known = {"kind": "sync", "manifest": None, "caller": str(source)}
        answer = refusal = None
        try:
            answer = self._decide(raw, source, known)
        except Refused as refused:
            refusal = refused
        except Exception as failure:       # a bug or a broken disk must not become a stack trace on the wire
            refusal = Refused("this node could not answer (%s)" % type(failure).__name__)

        def decided():
            if refusal is not None:
                raise refusal
            return answer
        # One event, written when the decision is known, under whatever was established on the way: the
        # manifest, the caller the tunnel identified, the operation.
        try:
            return convergence.audited(self.sink, known["kind"], known["manifest"], known["caller"], self.node_id, decided)
        except Refused as refused:
            return _refusal(refused)

    def _decide(self, raw, source, known):
        manifest = known["manifest"] = self.store.load()
        require(manifest is not None, "this node holds no manifest")
        key = self.identify(source)
        caller = known["caller"] = pinned(manifest, key)["node_id"]      # recorded by name even if it is then refused
        peer_of(manifest, key)
        require(caller != self.node_id, "a node does not ask itself")
        self.buckets.take(caller, "any")
        require(isinstance(raw, bytes) and len(raw) <= MAX_REQUEST, "a request is at most %d bytes" % MAX_REQUEST)
        message = membership.load(raw, MAX_REQUEST)
        require(isinstance(message, dict) and message.get("v") == VERSION and not isinstance(message.get("v"), bool),
                "the request's version must be %d" % VERSION)
        op = message.get("op")
        require(isinstance(op, str) and op in REQUEST_FIELDS, "unknown operation")
        known["kind"] = "sync-" + op
        membership.exact(message, REQUEST_FIELDS[op], op)
        answer = getattr(self, "_" + op.replace("-", "_"))(manifest, caller, message)
        encoded = membership.canonical(dict({"v": VERSION, "ok": True}, **answer))
        require(len(encoded) <= MAX_ANSWER, "the answer would exceed %d bytes" % MAX_ANSWER)
        return encoded

    # ---- the operations ----

    def _pull(self, manifest, caller, message):
        theirs, sequence = convergence.validate_summary(message["summary"]), message["sequence"]
        require(isinstance(sequence, int) and not isinstance(sequence, bool) and 0 <= sequence < 2 ** 63, "sequence must be an integer >= 0")
        mine = convergence.summary(self.store)
        if convergence.compare(self.store, theirs) == "behind":          # CONFLICT is raised here, and audited
            return {"summary": mine, "bundle": {"envelopes": [], "heartbeat": None}}
        held = self.freshness.held()
        try:      # worth passing on: for the manifest held here, and newer than the caller's (none held is refused too)
            if heartbeat.verify(held, manifest)["sequence"] <= sequence:
                held = None
        except Refused:
            held = None
        return {"summary": mine, "bundle": self._fitting(theirs, held)}

    def _fitting(self, theirs, held):
        """The largest bundle of at most MAX_ENVELOPES that leaves the answer under MAX_ANSWER."""
        limit = MAX_ENVELOPES
        while True:
            bundle = convergence.bundle(self.store, theirs, held, limit)
            if len(membership.canonical(bundle)) <= MAX_ANSWER - 1024 or limit == 1:
                return bundle
            limit //= 2

    def _lease_nonce(self, manifest, caller, message):
        require(self.attester is not None, "this source issues no leases")
        require(message["node_id"] == caller, "the request names %s; the tunnel is %s's" % (convergence._printable(message["node_id"]), caller))
        self.buckets.take(caller, "lease")
        return {"nonce": self.attester.nonce(caller).hex()}

    def _lease(self, manifest, caller, message):
        require(self.attester is not None, "this source issues no leases")
        request, evidence = message["request"], message["evidence"]
        require(isinstance(request, dict) and isinstance(evidence, dict), "request and evidence are objects")
        lease.validate_request(request)
        require(request["node_id"] == caller, "the request names %s; the tunnel is %s's" % (request["node_id"], caller))
        membership.exact(evidence, EVIDENCE_FIELDS, "evidence")
        self.buckets.take(caller, "lease")
        return {"lease": lease.issue(manifest, self.node_id, request, self.attester, evidence, self.freshness, self.signer)}


# ---- the asking side ----

def _answer(raw, op):
    """A source's answer to `op`, strictly: its payload, or Refused with the source's reason."""
    require(isinstance(raw, bytes) and len(raw) <= MAX_ANSWER, "the answer exceeds %d bytes" % MAX_ANSWER)
    answer = membership.load(raw, MAX_ANSWER)
    require(isinstance(answer, dict) and answer.get("v") == VERSION and not isinstance(answer.get("v"), bool),
            "the answer's version must be %d" % VERSION)
    if answer.get("ok") is False:
        membership.exact(answer, REFUSAL_FIELDS, "refusal")
        raise Refused("the source refused: %s" % convergence._printable(answer["refused"]))
    require(answer.get("ok") is True, "the answer says neither ok nor refused")
    membership.exact(answer, ANSWER_FIELDS[op], op + " answer")
    return answer


class Client:
    """One node's asking side. `transports` maps a source's name (a node ID, or convergence.AUTHORITY) to a
    callable taking the request bytes and returning the answer bytes (tcp_transport over the tunnel)."""

    def __init__(self, node_id, store, freshness, transports, sink):
        self.node_id, self.store, self.freshness, self.transports, self.sink = node_id, store, freshness, transports, sink

    def _ask(self, source, op, **fields):
        require(source in self.transports, "%r is not a configured source" % (source,))
        request = membership.canonical(dict({"v": VERSION, "op": op}, **fields))
        try:
            raw = self.transports[source](request)
        except (OSError, ValueError) as failure:
            raise Refused("%s did not answer (%s)" % (source, type(failure).__name__)) from None
        return _answer(raw, op)

    def pull(self, source):
        """Ask `source` for what this node lacks and apply it, round after round until it has nothing more
        (at most MAX_ROUNDS). Returns (summary, seconds of freshness or None). Each round is one audit event,
        ALLOW or DENY, under the manifest held when it began."""
        left = None
        for _ in range(MAX_ROUNDS):
            before = self._held()

            def one_round():
                held = self.freshness.held()
                sequence = held["heartbeat"]["sequence"] if held is not None else 0
                answer = self._ask(source, "pull", summary=convergence.summary(self.store), sequence=sequence)
                convergence.validate_summary(answer["summary"])
                bundle = answer["bundle"]
                require(isinstance(bundle, dict) and isinstance(bundle.get("envelopes"), list)
                        and len(bundle["envelopes"]) <= MAX_ENVELOPES, "a bundle carries at most %d envelopes" % MAX_ENVELOPES)
                return convergence.apply_bundle(self.store, self.freshness, bundle), len(bundle["envelopes"])
            (now_at, fresh), received = convergence.audited(self.sink, "sync-apply", before, self.node_id, source, one_round)
            left = fresh if fresh is not None else left
            if fresh is not None or received == 0:
                return now_at, left
        return convergence.summary(self.store), left

    def _held(self):
        """The manifest an audit event is filed under; None when there is none or the store refuses (the
        round then refuses too, and says why)."""
        try:
            return self.store.load()
        except Refused:
            return None

    def renewer(self, source, quote):
        """A `renew(request)` for admission.Service: ask `source` for a nonce, answer it with this node's
        fresh quote (`quote(nonce_hex, manifest)` returns the evidence object), and return the lease."""
        def renew(request):
            nonce = self._ask(source, "lease-nonce", node_id=self.node_id)["nonce"]
            membership.hex_field(nonce, 64, "nonce")
            evidence = quote(nonce, self.store.load())
            return self._ask(source, "lease", request=request, evidence=evidence)["lease"]
        return renew


# ---- sockets ----

def _read_all(conn, limit, deadline):
    """Everything the other end sends until it shuts its side, at most `limit` + 1 bytes, by `deadline`."""
    chunks, size = [], 0
    while size <= limit:
        conn.settimeout(max(deadline - time.monotonic(), 0.001))      # past the deadline: the next read times out
        chunk = conn.recv(min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def serve(server, listener, stop, deadline=DEADLINE, connections=MAX_CONNECTIONS, per_address=MAX_PER_ADDRESS):
    """Answer connections on `listener` until `stop()` is true: one request each, read until the caller
    shuts its sending side. Over the limits a connection is closed unanswered; the caller's retry is its
    next timer tick. The listener's own timeout is how often `stop` is looked at."""
    active, lock = [], threading.Lock()      # the address of every connection being answered

    def answer(conn, address):
        try:
            with conn:
                raw = _read_all(conn, MAX_REQUEST, time.monotonic() + deadline)
                conn.settimeout(deadline)
                conn.sendall(server.handle(raw, address))
        except Exception:           # noqa: BLE001 - the caller went away or was too slow (nothing was decided), or
            pass                    # the event could not be recorded (then nothing is answered): close, either way
        finally:
            with lock:
                active.remove(address)

    while not stop():
        try:
            conn, peer = listener.accept()
        except (TimeoutError, socket.timeout):
            continue
        address = peer[0]
        with lock:
            admitted = len(active) < connections and active.count(address) < per_address
            if admitted:
                active.append(address)
        if not admitted:
            conn.close()
            continue
        threading.Thread(target=answer, args=(conn, address), daemon=True).start()


def tcp_transport(host, port=PORT, source=None, timeout=DEADLINE):
    """A Client transport: one connection per request to (host, port), from `source` (this node's tunnel
    address) when given."""
    def send(raw):
        deadline = time.monotonic() + timeout
        with socket.create_connection((host, port), timeout=timeout, source_address=(source, 0) if source else None) as conn:
            conn.sendall(raw)
            conn.shutdown(socket.SHUT_WR)
            return _read_all(conn, MAX_ANSWER, deadline)
    return send
