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
caller says in-band identifies it. `identify(manifest, source)` is injected: it answers which WireGuard
public key the source address of a connection belongs to (on a host: wgsvc, #80 step 2). That key is
looked up in the manifest this node holds NOW, for every request, so a node revoked in the manifest is
refused although its tunnel is still up. A message that names a node (lease-nonce, lease) must name the
node the tunnel identified. A node in a terminal state gets nothing, not even a pull.

HOW MUCH.
  * one request per connection; canonical JSON; a version and an operation; EXACT fields, anything
    unknown refused;
  * a request is at most 64 KiB, an answer at most 1 MiB. A bundle carries at most 64 envelopes and is cut
    further until it fits, so a node far behind catches up over several pulls (a bundle short of the tip
    carries no heartbeat: convergence.bundle);
  * token buckets: 30 requests a minute per SOURCE ADDRESS, spent BEFORE anything else is done (no
    manifest is read and no TPM is touched for a caller over it, whoever it is: a revoked node whose
    tunnel is still up cannot drive this node's disk and TPM); then 20 a minute per NODE, of which 6 may
    be lease requests. The address limit is the looser one on purpose: a node with one address meets
    its own limit first, is refused by name, and is told why;
  * (the socket layer, serve) 8 connections at once, 2 from one address, 10 seconds each. Which addresses
    can connect at all is the tunnel's business: each key is allowed its one address (wgsvc.py).

EVERY DECISION IS ONE AUDIT EVENT (convergence.audited): the operation, the epoch and digest it was
decided under, the caller the tunnel identified (its source address when it could not be identified),
ALLOW or DENY, and the reason. A sink that cannot take the event (whatever it raises) means no answer.
THE ONE EXCEPTION IS A FLOOD: once a caller is over a rate limit, or connections are being dropped, ONE
event is written per minute for it; how many more were refused is written with the next report, or with
the caller's next request that passes (sync-rate). A caller that can make this node refuse cannot
thereby fill its trail. Buckets keyed by a source address are capped (4096); a newcomer is refused while
they are all busy, under one key, so that is one event a minute too. Buckets keyed by a NODE are bounded
by the manifest and kept apart, and a full address table does not turn a node away: an address that the
last manifest read gives to a node goes on to that node's own bucket. (On a host the table cannot fill
at all: the tunnel allows each key one address, wgsvc.py.)

WHAT A CALLER IS TOLD. An identified, admitted node is told the reason it was refused. A caller that was
not identified, or is in a terminal state, is told "refused" and nothing else: the reason (this node's
epoch, the state of its store, the caller's own state) is in the trail, not on the wire.

NOT A REFUSAL: a caller that is ahead of this node. It is answered with this node's summary and an empty
bundle, and learns from the summary that it is the one with something to offer. Nor is a caller that
already holds this node's heartbeat: it gets none, where the same one again would be refused as a replay.
NOR A CALLER WHOSE SUMMARY NAMES ANOTHER MANIFEST AT ITS EPOCH. A summary is unsigned, so it proves
nothing and is no incident here. The caller is sent this node's chain from that epoch on: if it really
holds another SIGNED manifest there, its own catch-up proves the conflict, with the signature, and
records it.

A SOURCE THAT ISSUES NO LEASES (the revocation authority) runs the same Server with no attester: it
answers pull, and refuses the two lease operations.

NO TLS. WireGuard authenticates both ends by the pinned keys and encrypts; every payload that matters is
signed or attested end to end. See #80.

NOT HERE: the WireGuard interface and the kernel lookup behind `identify` (step 2); units, firewall
rules and probes (step 3); convergence.recover over this transport.
"""
import copy
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
RATE = {"address": (30, 60), "any": (20, 60), "lease": (6, 60), "drop": (1, 60)}   # class -> (requests, per seconds); the bucket holds that many
OPEN = ("address", "drop")       # the classes keyed by a source address: anybody who can connect makes a key
MAX_BUCKETS = 4096               # address-keyed buckets remembered at once; idle ones are forgotten first
EVERYBODY = "*"                  # the one key the "too many callers" refusal is counted under
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


class Quiet(Refused):
    """A refusal already reported for this caller in this window: answered, not recorded again."""


class Crowded(Refused):
    """The table of address-keyed buckets is full of busy callers: there is no room to count a new one."""


class QuietlyCrowded(Crowded, Quiet):
    """The same, already reported in this window."""


class SinkFailed(Exception):
    """The audit sink did not take an event. Never a Refused: a refusal is answered, this is not."""


class Buckets:
    """Token buckets, one per (caller, class). `clock()` is monotonic seconds. The first refusal of a
    (caller, class) in a window is a Refused; the rest of that window are Quiet, and the count of those is
    given with the next report, or by the next take() of that key that passes.

    Two tables. The classes keyed by a NODE ("any", "lease") are bounded by the manifest. Those keyed by
    a SOURCE ADDRESS (OPEN) are capped at MAX_BUCKETS, and cannot fill the nodes' table."""

    def __init__(self, rates=None, clock=time.monotonic):
        self.rates, self.clock = dict(RATE if rates is None else rates), clock
        self.nodes, self.open, self.reported, self.lock = {}, {}, {}, threading.Lock()

    def take(self, caller, kind):
        """Spend one request of `kind` for `caller`, or Refused (Quiet when already reported). Returns how
        many of this caller's requests of this kind were refused since the last one that passed: 0, except
        on the first request that passes after it was over its limit. (The first of those was a Refused,
        which its caller may have recorded; the rest were Quiet.)"""
        count, per = self.rates[kind]
        key, table = (caller, kind), (self.open if kind in OPEN else self.nodes)
        with self.lock:
            now = self.clock()
            if table is self.open and key not in table and len(table) >= MAX_BUCKETS:
                self._forget_idle(now)
                if len(table) >= MAX_BUCKETS:
                    self._refuse((EVERYBODY, kind), now, per, "RATE: too many callers at once", Crowded, QuietlyCrowded)
            tokens, at = table.get(key, (float(count), now))
            tokens = min(float(count), tokens + max(0.0, now - at) * count / per)
            if tokens < 1.0:      # nothing is written: the bucket is as it was at its last request that passed
                self._refuse(key, now, per, "RATE: more than %d %s requests in %d s from %s" % (count, kind, per, caller))
            table[key] = (tokens - 1.0, now)
            # What was refused is counted until the reported minute is OVER, and only then handed back. A
            # request that passes in the middle of a flood (one does, every time a token refills) must not
            # restart the minute: the next refusal would be a new event, and a flood would write one event
            # per refill instead of one per minute.
            since, suppressed = self.reported.get(key, (None, 0))
            if since is None or 0 <= now - since < per:
                return 0
            del self.reported[key]
            return suppressed + 1

    def has_room(self, caller, kind):
        """Whether a request of `kind` from `caller` can be counted: it has a bucket already, or there is
        room for one (idle ones are forgotten to find out). Nothing is spent."""
        table = self.open if kind in OPEN else self.nodes
        with self.lock:
            if table is not self.open or (caller, kind) in table or len(table) < MAX_BUCKETS:
                return True
            self._forget_idle(self.clock())
            return len(table) < MAX_BUCKETS

    def _refuse(self, key, now, per, text, loud=Refused, quiet=Quiet):
        since, suppressed = self.reported.get(key, (None, 0))
        if since is not None and 0 <= now - since < per:
            self.reported[key] = (since, suppressed + 1)
            raise quiet(text)
        self.reported[key] = (now, 0)
        raise loud(text + (" (%d more refused since the last report)" % suppressed if suppressed else ""))

    def _forget_idle(self, now):
        """Drop the address-keyed buckets that are full again (nothing of theirs passed for a whole window,
        so forgetting one gives its caller nothing it did not have), and what was being counted for them.
        A key whose refusals are still being counted inside a reported minute is KEPT: for a class whose
        refill time is the whole window ("drop"), a key can be refused all through it and look idle, and
        forgetting it would lose its count and give its place to a newcomer. The count for "everybody"
        stays."""
        def counting(key):
            since = self.reported.get(key, (None, 0))[0]
            return since is not None and 0 <= now - since < self.rates[key[1]][1]
        for key in [k for k, v in self.open.items() if now - v[1] >= self.rates[k[1]][1] and not counting(k)]:
            del self.open[key]                  # in place: take() is holding this very table
        for key in [k for k in self.reported if k[1] in OPEN and k not in self.open and k[0] != EVERYBODY]:
            del self.reported[key]


def _refusal(reason):
    return membership.canonical({"v": VERSION, "ok": False, "refused": convergence._printable(reason)})


class _View:
    """One request's view of the node's store: the chain is read and verified ONCE, and every decision of
    the request is made on that one reading. Without it a pull verified the chain six times over (the
    summary, the comparison, the bundle, each reading the store again), and could have compared against
    one manifest and bundled from the next."""

    def __init__(self, store):
        self._store, self._envelopes = store, None
        self.late = []      # (caller, class, count): refusals of an earlier flood that no report has counted yet

    def envelopes(self, after_epoch=0):
        require(isinstance(after_epoch, int) and not isinstance(after_epoch, bool) and after_epoch >= 0, "after_epoch must be an integer >= 0")
        return copy.deepcopy(self._chain()[after_epoch:])          # epochs run from 1 with no gap: the store's own rule

    def _chain(self):
        if self._envelopes is None:
            self._envelopes = self._store.envelopes(0)
        return self._envelopes

    def load(self):
        """The current manifest, as a copy: whatever a caller of this view does to it stays its own."""
        chain = self._chain()
        return copy.deepcopy(chain[-1]["manifest"]) if chain else None


class Server:
    """One node's answering side. `store`, `freshness`, `attester` and `signer` are the node's own
    membership.Store, heartbeat.Freshness (anything with held() will do for a source that issues no leases),
    attest.Verifier and lease signer (None for such a source); `identify(manifest, source)` returns the
    WireGuard public key (hex) a connection's source address belongs to, or raises Refused; `sink(event)`
    takes each audit event; `clock()` is this node's wall clock, used only to spare a caller a heartbeat
    that has already expired."""

    def __init__(self, node_id, store, freshness, attester, signer, identify, sink, buckets=None, clock=time.time):
        self.node_id, self.store, self.freshness, self.attester, self.signer = node_id, store, freshness, attester, signer
        self.identify, self.sink, self.buckets, self.clock = identify, sink, buckets or Buckets(), clock
        self._seen = None       # the manifest of the last request that read the store: see _is_a_node

    def _record(self, event):
        try:
            self.sink(event)
        except Exception as failure:      # noqa: BLE001 - whatever the sink raises, Refused included, is not a decision
            raise SinkFailed("the audit sink did not take the event (%s)" % type(failure).__name__) from failure

    def handle(self, raw, source):
        """The answer (bytes) to one request from `source`. A refusal is an answer, and so is a failure
        inside this node. Only a sink that cannot take the event raises (SinkFailed): nothing is answered
        that is not recorded."""
        known = {"kind": "sync", "manifest": None, "caller": convergence._printable(source), "identified": False, "late": []}
        answer = refusal = None
        try:
            answer = self._decide(raw, source, known)
        except Refused as refused:
            refusal = refused
        except Exception as failure:       # noqa: BLE001 - a bug or a broken disk must not become a stack trace on the wire
            refusal = Refused("this node could not answer (%s)" % type(failure).__name__)

        def decided():
            if refusal is not None:
                raise refusal
            return answer
        # A flood that ended: what was refused and never counted is written now, with the first request
        # of that caller that got through.
        for who, kind, count in known["late"]:
            self._report(who, kind, count, known["manifest"])
        # One event, written when the decision is known, under whatever was established on the way: the
        # manifest, the caller the tunnel identified, the operation. Not for a refusal already reported
        # in this window (Quiet): the flood is in the count of the next report.
        if not isinstance(refusal, Quiet):
            try:
                return convergence.audited(self._record, known["kind"], known["manifest"], known["caller"], self.node_id, decided)
            except Refused:
                pass
        # the reason goes to a caller this node identified and may talk to; anybody else learns nothing
        return _refusal(refusal if known["identified"] else "refused")

    def _report(self, who, kind, count, manifest):
        def said():
            raise Refused("RATE: %d more %s requests from %s were refused before this one" % (count, kind, who))
        try:
            convergence.audited(self._record, "sync-rate", manifest, who, self.node_id, said)
        except Refused:
            pass

    def _node_at(self, source):
        """The node `source` is the address of, by the manifest this server read LAST (in memory: no disk,
        no TPM), if it may still be talked to; else None. A node in a terminal state there is None.
        Asked only when the address table is full, so that a table full of busy strangers cannot turn a
        node away: the node is then held to its own bucket, BEFORE anything is read, and goes on to the
        real check against the manifest read now."""
        try:
            return peer_of(self._seen, self.identify(self._seen, source)) if self._seen is not None else None
        except Exception:      # noqa: BLE001 - anything that is not "yes, a node" is "no"
            return None

    def _spend(self, late, who, kind):
        """One request of `kind` for `who`, or Refused; a count left over from a flood is put on `late`."""
        refused = self.buckets.take(who, kind)
        if refused > 1:          # the first of them was recorded when it happened
            late.append((who, kind, refused - 1))

    def dropped(self, source, reason):
        """serve() closed a connection from `source` unanswered (over a connection limit, or no complete
        request in time). Recorded, at most once a minute per address."""
        name = convergence._printable(source)
        try:      # the first of a window passes; the others are counted, and none of them is an event of its own
            suppressed = self.buckets.take(name, "drop")
        except Quiet:
            return
        except Crowded as crowded:      # more addresses are being dropped than are remembered: one event a minute says so
            name, reason, suppressed = EVERYBODY, "%s; connections are being dropped: %s" % (crowded, reason), 0
        except Refused:
            return

        def decided():
            raise Refused(reason + (" (%d more dropped since the last report)" % suppressed if suppressed else ""))
        try:
            convergence.audited(self._record, "sync-drop", None, name, self.node_id, decided)
        except Refused:
            pass

    def _decide(self, raw, source, known):
        view = _View(self.store)                                           # nothing is read yet
        view.late = known["late"]
        name = convergence._printable(source)
        # Before the disk and the TPM are touched for anybody. One exception: when the address table is full
        # of busy strangers, an address the last manifest gives to a node is not counted there at all (and
        # so is not refused there): it goes on to that node's own bucket.
        spent = None
        member = None if self.buckets.has_room(name, "address") else self._node_at(source)
        if member is None:
            self._spend(view.late, name, "address")
        else:                     # the node's own bucket stands in front of the store instead
            known["caller"], known["identified"] = member, member != self.node_id     # a node, by the last manifest read: told why
            self._spend(view.late, member, "any")
            spent = member
        manifest = known["manifest"] = self._seen = view.load()
        require(manifest is not None, "this node holds no manifest")
        key = self.identify(manifest, source)
        node = pinned(manifest, key)
        caller = known["caller"] = node["node_id"]                       # recorded by name even if it is then refused
        # From here an admitted node is told why it is refused, its own rate limit included. A node in a
        # terminal state, and this node's own key, stay "refused" and nothing more.
        known["identified"] = node["state"] not in membership.TERMINAL and caller != self.node_id
        if caller != spent:                                                # not spent already, in front of the store
            self._spend(view.late, caller, "any")                        # before the refusals below: they are limited too
        peer_of(manifest, key)
        require(caller != self.node_id, "a node does not ask itself")
        require(isinstance(raw, bytes) and len(raw) <= MAX_REQUEST, "a request is at most %d bytes" % MAX_REQUEST)
        message = membership.load(raw, MAX_REQUEST)
        require(isinstance(message, dict) and message.get("v") == VERSION and not isinstance(message.get("v"), bool),
                "the request's version must be %d" % VERSION)
        op = message.get("op")
        require(isinstance(op, str) and op in REQUEST_FIELDS, "unknown operation")
        known["kind"] = "sync-" + op
        membership.exact(message, REQUEST_FIELDS[op], op)
        answer = getattr(self, "_" + op.replace("-", "_"))(view, manifest, caller, message)
        encoded = membership.canonical(dict({"v": VERSION, "ok": True}, **answer))
        require(len(encoded) <= MAX_ANSWER, "the answer would exceed %d bytes" % MAX_ANSWER)
        return encoded

    # ---- the operations ----

    def _pull(self, view, manifest, caller, message):
        theirs, sequence = convergence.validate_summary(message["summary"]), message["sequence"]
        require(isinstance(sequence, int) and not isinstance(sequence, bool) and 0 <= sequence < 2 ** 63, "sequence must be an integer >= 0")
        mine = convergence.summary(view)
        try:
            standing = convergence.compare(view, theirs)
        except Refused:
            # The caller says it holds ANOTHER manifest at its epoch. A summary is unsigned: this proves
            # nothing, and is no incident here. It gets this node's chain from that epoch on; if it really
            # holds another signed manifest there, its own catch-up proves the conflict and records it.
            return {"summary": mine, "bundle": self._fit(lambda limit: {"envelopes": view.envelopes(theirs["epoch"] - 1)[:limit],
                                                                         "heartbeat": None})}
        if standing == "behind":
            return {"summary": mine, "bundle": {"envelopes": [], "heartbeat": None}}
        held = self._passable(manifest, sequence)
        return {"summary": mine, "bundle": self._fit(lambda limit: convergence.bundle(view, theirs, held, limit))}

    def _passable(self, manifest, sequence):
        """The heartbeat this node holds, if it is worth passing on: for the manifest held here, newer than
        the caller's, and not already expired. None held is None. The caller's authenticated clock decides
        what is live; dropping an expired one here only spares it a refusal."""
        held = self.freshness.held()
        try:
            body = heartbeat.verify(held, manifest)
            if body["sequence"] <= sequence:
                return None
            now = self._now()
            if now is not None and heartbeat.parse_time(body["expires_at"], "expires_at") <= now:
                return None
        except Refused:
            return None
        return held

    def _now(self):
        """This node's time, for that one judgement: its authenticated reading when it has one (the clock
        its own Freshness uses), else its wall clock, else None. A clock that cannot be read withholds
        nothing: the heartbeat is passed on and the caller judges it."""
        for read in (getattr(self.freshness, "clock", None), self.clock):
            try:
                value = read()
                seconds, trusted = value if isinstance(value, tuple) else (value, True)
                if trusted is True and isinstance(seconds, (int, float)) and not isinstance(seconds, bool):
                    return seconds
            except Exception:      # noqa: BLE001 - a clock that fails is a clock that says nothing
                continue
        return None

    @staticmethod
    def _fit(bundle_of):
        """The largest bundle of at most MAX_ENVELOPES (`bundle_of(limit)`) that leaves the answer under MAX_ANSWER."""
        limit = MAX_ENVELOPES
        while True:
            bundle = bundle_of(limit)
            if len(membership.canonical(bundle)) <= MAX_ANSWER - 1024 or limit == 1:
                return bundle
            limit //= 2

    def _lease_nonce(self, view, manifest, caller, message):
        require(self.attester is not None, "this source issues no leases")
        require(message["node_id"] == caller, "the request names %s; the tunnel is %s's" % (convergence._printable(message["node_id"]), caller))
        self._spend(view.late, caller, "lease")
        return {"nonce": self.attester.nonce(caller).hex()}

    def _lease(self, view, manifest, caller, message):
        require(self.attester is not None, "this source issues no leases")
        request, evidence = message["request"], message["evidence"]
        require(isinstance(request, dict) and isinstance(evidence, dict), "request and evidence are objects")
        lease.validate_request(request)
        require(request["node_id"] == caller, "the request names %s; the tunnel is %s's" % (request["node_id"], caller))
        membership.exact(evidence, EVIDENCE_FIELDS, "evidence")
        self._spend(view.late, caller, "lease")
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

    def _record(self, event):
        try:
            self.sink(event)
        except Exception as failure:      # noqa: BLE001 - as on the answering side: never mistaken for a decision
            raise SinkFailed("the audit sink did not take the event (%s)" % type(failure).__name__) from failure

    def _ask(self, source, op, **fields):
        require(source in self.transports, "%r is not a configured source" % (source,))
        request = membership.canonical(dict({"v": VERSION, "op": op}, **fields))
        try:
            raw = self.transports[source](request)
        except (OSError, ValueError) as failure:
            raise Refused("%s did not answer (%s)" % (source, type(failure).__name__)) from None
        return _answer(raw, op)

    @staticmethod
    def _safely(step, what="the round failed"):
        """`step`, with anything it raises that is not a refusal turned into one. A round reads a source's
        answer with code that expects well-formed input in places (a deeply nested answer, a field of the
        wrong type inside an envelope), and it writes to this node's own disk and TPM. Whatever any of
        that raises, the round is refused and recorded, not died of. The words do not say whose fault it
        was: a full disk here and a malformed envelope there both end up in this message."""
        def run():
            try:
                return step()
            except Refused:
                raise
            except Exception as failure:      # noqa: BLE001 - see above
                raise Refused("%s (%s)" % (what, type(failure).__name__)) from None
        return run

    def pull(self, source):
        """Ask `source` for what this node lacks and apply it, round after round until it has nothing more
        (at most MAX_ROUNDS). Returns (summary, seconds of freshness or None). Raises Refused, or SinkFailed
        when the trail cannot be written.

        A round is TWO decisions, each one audit event: the manifests (sync-apply, under the manifest held
        when the round began), then the heartbeat if one came (sync-heartbeat, under the manifest held
        once the manifests were applied). Manifests are durable as each is accepted, so a round can move
        the membership and then be refused; the refusal then says how far it had moved."""
        left = None
        for _ in range(MAX_ROUNDS):
            before = self._held()

            def manifests():
                held = self.freshness.held()
                sequence = held["heartbeat"]["sequence"] if held is not None else 0
                started = convergence.summary(self.store)
                answer = self._ask(source, "pull", summary=started, sequence=sequence)
                convergence.validate_summary(answer["summary"])
                bundle = answer["bundle"]
                require(isinstance(bundle, dict) and isinstance(bundle.get("envelopes"), list)
                        and len(bundle["envelopes"]) <= MAX_ENVELOPES, "a bundle carries at most %d envelopes" % MAX_ENVELOPES)
                membership.exact(bundle, ("envelopes", "heartbeat"), "bundle")
                try:
                    now_at = self._safely(lambda: convergence.catch_up(self.store, bundle["envelopes"]))()
                except Refused as refused:
                    reached = self._held()
                    if reached is not None and reached["epoch"] != started["epoch"]:
                        raise Refused("%s (the membership had moved from epoch %d to %d before this)" % (refused, started["epoch"], reached["epoch"])) from None
                    raise
                return now_at, bundle["heartbeat"], len(bundle["envelopes"])
            now_at, beat, received = convergence.audited(self._record, "sync-apply", before, self.node_id, source, self._safely(manifests))
            fresh = None
            if beat is not None:
                current = self._held()

                def accept():
                    require(now_at["epoch"] >= 1, "a heartbeat cannot be taken before the first manifest")
                    require(current is not None, "this node's manifest cannot be read: the heartbeat is not taken")
                    return self.freshness.accept(beat, current)
                fresh = convergence.audited(self._record, "sync-heartbeat", current, self.node_id, source, self._safely(accept))
            left = fresh if fresh is not None else left
            if fresh is not None or received == 0:
                return now_at, left
        return convergence.summary(self.store), left

    def _held(self):
        """The manifest an audit event is filed under; None when there is none, the store refuses, or it
        cannot be read at all (the round then refuses too, inside its own decision, and says why)."""
        try:
            return self.store.load()
        except Exception:      # noqa: BLE001 - a store that cannot be read is "no manifest" for the event's header
            return None

    def renewer(self, source, quote):
        """A `renew(request)` for admission.Service: ask `source` for a nonce, answer it with this node's
        fresh quote (`quote(nonce_hex, manifest)` returns the evidence object), and return the lease."""
        def renew(request):
            def asked():
                nonce = self._ask(source, "lease-nonce", node_id=self.node_id)["nonce"]
                membership.hex_field(nonce, 64, "nonce")
                evidence = quote(nonce, self.store.load())
                return self._ask(source, "lease", request=request, evidence=evidence)["lease"]
            return self._safely(asked, "the lease could not be asked for")()
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
    shuts its sending side. Over the limits, or with no complete request by the deadline, a connection is
    closed unanswered and server.dropped() records it (at most once a minute per address); the caller's
    retry is its next timer tick. An accept() that fails is recorded the same way and the loop goes on:
    it ends only when `stop()` says so. The listener's own timeout is how often `stop` is looked at."""
    active, lock = [], threading.Lock()      # the address of every connection being answered

    def dropped(address, reason):
        try:
            server.dropped(address, reason)
        except Exception:           # noqa: BLE001 - a trail that cannot be written must not stop the listener
            pass

    def answer(conn, address):
        try:
            with conn:
                try:
                    raw = _read_all(conn, MAX_REQUEST, time.monotonic() + deadline)
                except (TimeoutError, socket.timeout):
                    dropped(address, "no complete request within %d s" % deadline)
                    return
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
        except OSError as failure:      # a connection aborted before it was accepted, no descriptor left: the listener goes on
            dropped("the listener", "a connection could not be accepted (%s)" % type(failure).__name__)
            time.sleep(0.1)
            continue
        address = peer[0]
        with lock:
            admitted = len(active) < connections and active.count(address) < per_address
            if admitted:
                active.append(address)
        if not admitted:
            conn.close()
            dropped(address, "over the connection limit (%d in all, %d from one address)" % (connections, per_address))
            continue
        try:
            threading.Thread(target=answer, args=(conn, address), daemon=True).start()
        except RuntimeError:        # no thread could be started: give the place back, and the caller retries
            conn.close()
            with lock:
                active.remove(address)
            dropped(address, "no thread could be started for the connection")


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
