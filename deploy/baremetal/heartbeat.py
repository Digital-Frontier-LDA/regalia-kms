#!/usr/bin/env python3
"""Freshness heartbeats: a peer authorizes a bootstrap only while it can show its membership is current
(#69, Phase 9 of #59; THREE-SITE-THREAT-MODEL.md design question 1).

A newer manifest proves ordering, not that nothing restrictive happened since. A peer cut off from the
others would go on helping a node that was revoked an hour ago. So the nodes sign, by quorum (beat.py,
#199), a short-lived statement that a manifest is still the current one, and a peer without a live one
refuses. (Before v4 one revocation key signed it, the form below; #199 retired the authority host.)

    envelope  = {"heartbeat": {...}, "signature": {"key": "<hex revocation key, as the manifest names it>", "sig": "<hex signature>"}}

    heartbeat = {"schema": "regalia.heartbeat/v1", "epoch": <the manifest's epoch>, "sequence": <int >= 1>,
                 "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "expires_at": "YYYY-MM-DDTHH:MM:SSZ",
                 "manifest_digest": "<64 hex: membership.digest(manifest)>"}

Signed message: b"regalia-heartbeat/v1\\0" + canonical JSON of the heartbeat (as membership.py: sorted
keys, no spaces, ASCII). The domain differs from a manifest's, so neither signature can stand in for the
other. The key must be a revocation key named by the CURRENT manifest; the root key is offline and signs
no heartbeats.

Under a v4 manifest (#199: no authority host) the envelope is {"heartbeat": {...}, "signatures": [{"party",
"key", "sig"}, ...]} instead, each signature over the same message, and the counting parties must meet the
CURRENT manifest's heartbeat_signers (two of the nodes and the owner; signed_by). One the owner co-signed lives
at most owner_heartbeat_lifetime_s, whoever else signed it.

A heartbeat is accepted (Freshness.accept) and later relied on (Freshness.check) only if:
  * it is for the current manifest: the same epoch AND the same digest;
  * it lives no longer (expires_at - issued_at) than THE CURRENT MANIFEST ALLOWS, whatever the signer
    wrote (max_lifetime). A v2 manifest states the bound itself, heartbeat_max_lifetime_s, from one hour
    to seven days; only the root key can set it, so the revocation key that signs heartbeats cannot
    lengthen its own. A v1 manifest has no such field and keeps the fixed 24 hours. Seven days is also a
    constant here that no manifest raises;
  * TIME IS AUTHENTICATED. The clock is injected and reports (seconds, authenticated). Without
    authenticated time nothing is accepted and nothing is authorized: a peer that cannot tell the time
    cannot tell an expired heartbeat from a live one. Fail closed; a total outage is A3's manual recovery;
  * time has not gone backwards. Each successful reading is recorded with the TPM clock; the next one
    must not be earlier than that reading plus the TPM time elapsed since (the FLOOR). The TPM clock
    stops while the node is off and may lose a few seconds at a power loss, so the floor is a lower
    bound and is never used to show that a heartbeat is still live;
  * it is not expired and not issued in the future (5 minutes of skew);
  * ITS SEQUENCE IS NEW. The highest accepted sequence is a TPM NV counter (Counter, which is
    membership.HighWater on an index pair of its own), outside restorable disk state: a sequence at or
    below it is refused, and the heartbeat on disk must not be below it, so a disk rolled back to an
    older heartbeat is refused however valid that heartbeat still looks.

Order of writes in accept(): the heartbeat reaches the disk first (durably), then the counter advances.
A crash between the two leaves a verified heartbeat above the counter; check() finishes the advance. The
other order would leave the counter above the disk and the peer refusing until the next heartbeat.

authorize(manifest, peer, requester, freshness) is the whole decision: the peer is ACTIVE, the requester
may be unlocked, and the peer's heartbeat is live.

WHAT THE BOUND TRADES. It is how long a peer cut off from the others goes on authorizing a node that was
revoked meanwhile, and equally how long the nodes may fail to co-sign before every peer stops.
Once it has run out, each reboot needs the recovery key until a heartbeat arrives. A longer bound buys
tolerance of a signer outage with a longer window for a stolen node at a partitioned peer.
heartbeat_watch.py says how much is left, and warns while it runs out.

NOT HERE: the authenticated time source itself. NTS-authenticated chrony on the hosts, and how its
"synchronised and authenticated" state is read, belong to the hardware half of #69; this module takes a
clock that answers that question and refuses when the answer is no.
"""
import calendar
import contextlib
import json
import math
import os
import re
import subprocess
import tempfile
import time


from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.heartbeat/v1"
DOMAIN = b"regalia-heartbeat/v1\0"
HEARTBEAT_KEYS = ("schema", "epoch", "sequence", "issued_at", "expires_at", "manifest_digest")
MAX_LIFETIME = 24 * 3600   # the freshness bound under a v1 manifest, which states none of its own
HARD_MAX_LIFETIME = membership.HEARTBEAT_HARD_MAX_S   # seven days: no manifest allows a longer heartbeat
FUTURE_SKEW = 300
STEP_BACK = 5              # an authenticated clock may be corrected backwards by this much, no more
# The TPM clock is allowed to run within 15% of real time (TPM 2.0 Part 1, "Clock"), so only 85% of
# its elapsed time counts toward the floor. To be confirmed on the DL360s' TPMs.
TPM_CLOCK_RATE = 0.85
MAX_BYTES = 16 * 1024
# The shortest interval heartbeats may be signed at (node.json's beat_interval_s is never below it, #199). A node accepts a sequence jump of Counter.MAX_JUMP plus one per
# MIN_INTERVAL_S of issue time since the last heartbeat it accepted: a node back from a month's repair
# catches up (the counter steps what it would have stepped online), while a sequence that runs faster
# than real time is still an anomaly. Decided on #199.
MIN_INTERVAL_S = 600
# The largest allowance ever used, however long a node was away: a year of MIN_INTERVAL_S steps.
MAX_ALLOWANCE = 1000 + math.ceil(366 * 86400 / MIN_INTERVAL_S)


def parse_time(text, label):
    """A UTC timestamp as unix seconds; Refused unless it is exactly YYYY-MM-DDTHH:MM:SSZ and a real date."""
    require(isinstance(text, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", text) is not None,
            "%s must be UTC, YYYY-MM-DDTHH:MM:SSZ" % label)
    try:
        return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        raise Refused("%s is not a real date" % label)


def max_lifetime(manifest):
    """The longest a heartbeat for `manifest` may live, in seconds: a revocation reaches every peer within
    this, or the peer stops. A v2 manifest says (root-signed, validated by membership as 1 hour to 7 days);
    a v1 manifest says nothing and gets 24 hours."""
    if manifest["schema"] == membership.SCHEMA:
        return MAX_LIFETIME
    return min(manifest["heartbeat_max_lifetime_s"], HARD_MAX_LIFETIME)


def allowed_jump(heartbeat, held, base):
    """How far `heartbeat`'s sequence may jump past the counter: `base` (Counter.MAX_JUMP), plus one per
    MIN_INTERVAL_S between the issue time of `held` (the envelope last accepted, from the freshness state)
    and this heartbeat's. Without a readable held envelope, or with an issue time not after it, just `base`:
    the error is toward refusing. The new issue time is bounded by authenticated time (_live).
    The held issue time comes from the freshness state ON DISK, which a restored disk can roll back. An
    older held time only WIDENS the allowance, and the allowance is anomaly detection, not replay
    protection: the TPM counter still requires a sequence above it, and the heartbeat is signed. A
    rollback can loosen the bound; it never lets a replay through."""
    try:
        before = parse_time(held["heartbeat"]["issued_at"], "the held heartbeat's issued_at")
    except (Refused, KeyError, TypeError):
        return base
    issued = parse_time(heartbeat["issued_at"], "issued_at")
    return min(base + math.ceil((issued - before) / MIN_INTERVAL_S), MAX_ALLOWANCE) if issued > before else base


def pending(state, held, base):
    """How far the counter is still owed toward the held heartbeat (0 when it is not above the counter),
    never more than the allowance that heartbeat was accepted under (`base` for a state that has none):
    a planted state widens nothing past what a real acceptance could have."""
    envelope = state.get("envelope")
    try:
        gap = envelope["heartbeat"]["sequence"] - held
    except (KeyError, TypeError):
        return 0
    return max(0, min(gap, state.get("allowance") or base)) if isinstance(gap, int) else 0


def validate(heartbeat):
    """Schema only, with the bound no manifest can raise. Returns (issued, expires) in seconds."""
    membership.exact(heartbeat, HEARTBEAT_KEYS, "heartbeat")
    require(heartbeat["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    for k in ("epoch", "sequence"):
        v = heartbeat[k]
        require(isinstance(v, int) and not isinstance(v, bool) and 1 <= v < 2 ** 63, "%s must be an integer >= 1" % k)
    membership.hex_field(heartbeat["manifest_digest"], 64, "manifest_digest")
    issued, expires = parse_time(heartbeat["issued_at"], "issued_at"), parse_time(heartbeat["expires_at"], "expires_at")
    require(issued < expires, "expires_at must be after issued_at")
    require(expires - issued <= HARD_MAX_LIFETIME, "a heartbeat lives at most %d s under any manifest (this one: %d s)"
            % (HARD_MAX_LIFETIME, expires - issued))
    return issued, expires


def signed(envelope, manifest):
    """The heartbeat inside an envelope, if it is well formed and signed as `manifest` requires (below),
    WHATEVER epoch it is for. Returns (heartbeat, issued, expires). verify() adds the rest."""
    return signed_by(envelope, manifest)[:3]


def signed_by(envelope, manifest):
    """signed(), and who signed: (heartbeat, issued, expires, parties).

    Under a v4 manifest (#199) a heartbeat is signed by a QUORUM: {"heartbeat", "signatures": [{party, key, sig}]},
    each signature over DOMAIN + canonical(heartbeat), counted by membership.counting_parties (a party named twice,
    a key not the party's, a bad signature: refused; a quarantined, retired or stolen node: not counted), and the
    counting parties must meet the manifest's heartbeat_signers (two of the nodes and the owner). `parties` is that
    set, for verify()'s owner rule. Under v1 to v3, one revocation key the manifest names, as before; `parties` is
    empty."""
    if manifest is not None and manifest.get("schema") == membership.SCHEMA_V4:
        membership.exact(envelope, ("heartbeat", "signatures"), "envelope")
        heartbeat = envelope["heartbeat"]
        issued, expires = validate(heartbeat)
        membership.validate(manifest)
        parties = membership.counting_parties(manifest, DOMAIN + membership.canonical(heartbeat), envelope["signatures"], "heartbeat")
        rule = manifest["heartbeat_signers"]
        require(membership.meets(rule, parties), "the heartbeat is signed by %s: %d of %s are needed"
                % (", ".join(sorted(parties)) or "no counting party", rule["threshold"], ", ".join(rule["parties"])))
        return heartbeat, issued, expires, parties
    membership.exact(envelope, ("heartbeat", "signature"), "envelope")
    sig = envelope["signature"]
    membership.exact(sig, ("key", "sig"), "signature")
    require(isinstance(sig["key"], str) and re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{130}", sig["key"]) is not None,
            "signature.key must be 64 or 130 lowercase hex")
    membership.hex_field(sig["sig"], 128, "signature.sig")
    heartbeat = envelope["heartbeat"]
    issued, expires = validate(heartbeat)
    membership.validate(manifest)
    alg = membership.revocation_alg(manifest, sig["key"])      # the manifest's entry says how, never the signature
    require(alg is not None, "the signing key is not a revocation key named by the current manifest")
    try:
        membership.verify_revocation(alg, sig["key"], DOMAIN + membership.canonical(heartbeat), sig["sig"], "heartbeat")
    except Refused:
        raise Refused("the heartbeat signature does not verify") from None
    return heartbeat, issued, expires, set()


def verify(envelope, manifest):
    """The heartbeat inside an envelope, if it is signed as the CURRENT manifest requires (signed_by) and is
    for that manifest. Time and sequence are Freshness's to check."""
    heartbeat, issued, expires, parties = signed_by(envelope, manifest)
    # an owner co-signed heartbeat is an emergency credential (a node opened by hand, the operator present): it
    # lives at most owner_heartbeat_lifetime_s, whoever else signed it (#199)
    if membership.OWNER in parties:
        require(expires - issued <= manifest["owner_heartbeat_lifetime_s"], "a heartbeat the owner signed lives at most %d s "
                "(this one: %d s)" % (manifest["owner_heartbeat_lifetime_s"], expires - issued))
    require(heartbeat["epoch"] == manifest["epoch"], "the heartbeat is for epoch %d, the current manifest is epoch %d"
            % (heartbeat["epoch"], manifest["epoch"]))
    require(heartbeat["manifest_digest"] == membership.digest(manifest), "the heartbeat is for another manifest (digest mismatch)")
    require(expires - issued <= max_lifetime(manifest), "a heartbeat lives at most %d s under the current manifest "
            "(this one: %d s)" % (max_lifetime(manifest), expires - issued))
    return heartbeat


class Counter(membership.HighWater):
    """The highest accepted heartbeat sequence: membership.HighWater (a TPM NV counter and its write-once
    base, outside restorable disk state) under the heartbeat rule, where a sequence AT the counter is a
    replay too. It needs an index pair of its own: membership uses 0x1500016/0x1500017, so this takes
    e.g. 0x1500018 (its base is then 0x1500019). A TPM that cannot be read is a refusal, never zero."""

    RECORD = False     # a sequence has no manifest to record: membership's record index is not defined here

    WRAP = 1 << 64

    def _epoch(self, base):
        # The value is the counter's distance from its base, modulo 2^64: define_at() sets the base so a fresh
        # counter reads a chosen sequence at once, which may put the base above the counter's raw reading.
        # Both only rise and the base is write-once, so the value only rises too. (The membership anchor
        # keeps HighWater's own rule; this is the heartbeat counter's.)
        return (self._read8(self.index) - base) % self.WRAP

    def remains(self):
        """What the old counter still reads, whatever its attributes (for recount's floor), modulo 2^64 as
        _epoch reads it; None when the pair cannot be read."""
        with membership._exclusive(self.lock_path):
            defined = self._defined()
            if int(self.index, 16) not in defined or int(self.base_index, 16) not in defined:
                return None, []
            (a, a_size), (b, b_size) = self._public(self.index), self._public(self.base_index)
            if not (a & self.NT_MASK == self.NT_COUNTER and a & self.WRITTEN and b & self.WRITTEN and (a_size, b_size) == (8, 8)):
                return None, []
            counter = int.from_bytes(self._read_any(self.index, 8, a), "big")
            base = int.from_bytes(self._read_any(self.base_index, 8, b), "big")
            return (counter - base) % self.WRAP, []

    def define_at(self, sequence):
        """Define this counter so it reads `sequence` at once: one increment, then a write-once base of
        (where the counter landed - sequence) mod 2^64. No increment loop (one TPM write per heartbeat ever
        issued would be an hour of calls and real NV wear). For a node replacing another (#190 --replace),
        gated by its caller on a heartbeat that verifies and is live, and for recount.py's floor.

        Refused if the pair is complete (the base written and write-locked): a counter in use is never
        redefined here. An incomplete pair, an earlier define_at cut short (no base, or a base not yet
        locked), is deleted and done again. Returns the value read back."""
        with membership._exclusive(self.lock_path):
            return self._define_at(sequence)

    def _define_at(self, sequence):
        """define_at under the counter's lock, which the caller holds (recount holds it across deleting the
        old pair and defining the new one, so no service advance falls between the two)."""
        require(isinstance(sequence, int) and not isinstance(sequence, bool) and 0 <= sequence < 1 << 63,
                "a sequence must be an integer from 0 to 2^63 - 1")
        defined = self._defined()
        if int(self.base_index, 16) in defined:
            b, _ = self._public(self.base_index)
            require(not (b & self.WRITTEN and b & self.WRITELOCKED),
                    "the counter %s is already defined (its base is written and locked): it is not redefined" % self.index)
        for index in (self.index, self.base_index):
            if int(index, 16) in defined:
                require(self._owner("nvundefine", index).returncode == 0, "cannot delete NV index %s" % index)
        r = self._nvdefine(self.index, 8, "counter")
        require(r.returncode == 0, "cannot define the NV counter %s" % self.index)
        require(self._owner("nvincrement", self.index).returncode == 0, "cannot increment the NV counter")
        base = (self._read8(self.index) - sequence) % self.WRAP
        r = self._nvdefine(self.base_index, 8, "base")
        require(r.returncode == 0, "cannot define the base index %s" % self.base_index)
        r = self._owner("nvwrite", self.base_index, "-i", "-", input=base.to_bytes(8, "big"))
        require(r.returncode == 0, "cannot write the base index")
        require(self._owner("nvwritelock", self.base_index).returncode == 0, "cannot write-lock the base index")
        value = self._epoch(self._base())
        require(value == sequence, "the counter reads %d after define_at(%d)" % (value, sequence))
        return value

    def advance(self, sequence, allowance=None):
        """Move the counter up to `sequence`, at most `allowance` (default MAX_JUMP) above where it is."""
        with membership._exclusive(self.lock_path):
            return self._advance(sequence, allowance)

    def _advance(self, sequence, allowance=None):
        # under HighWater's lock, with the increments: two processes given the same sequence cannot both pass
        now = self.value()
        base = self._base()
        require(sequence > now, "REPLAY: sequence %d is not above the TPM counter %d" % (sequence, now))
        bound = self.MAX_JUMP if allowance is None else allowance
        require(sequence - now <= bound, "sequence jump %d exceeds the bound %d: anomaly" % (sequence - now, bound))
        while now < sequence:
            # by the counter's layout: a policy session for this boot's approved image when it is policy-written (#242)
            require(self._write("nvincrement", self.index).returncode == 0, "cannot increment the NV counter")
            nxt = self._epoch(base)
            require(nxt == now + 1, "the NV counter did not advance by one (%d -> %d)" % (now, nxt))
            now = nxt
        return now


class TpmClock:
    """The TPM's Clock in milliseconds: it only moves forward while the TPM is powered."""

    def __init__(self, tcti=None, run=subprocess.run):
        self.run, self.env = run, (dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None)

    def __call__(self):
        done = self.run(["tpm2_readclock"], capture_output=True, env=self.env)
        found = re.search(r"(?m)^\s+clock: (\d+)$", done.stdout.decode(errors="replace")) if done.returncode == 0 else None
        require(found is not None, "the TPM clock cannot be read")
        return int(found.group(1))


def validate_floor(floor):
    """A stored time floor: None, or the last authenticated reading with the TPM clock at that moment."""
    if floor is not None:
        membership.exact(floor, ("time", "tpm_clock"), "floor")
        require(all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in floor.values()), "floor must be integers")


def authenticated_now(clock, tpm_clock, floor):
    """Authenticated time in seconds, not earlier than `floor`, and the floor to store for the next call.
    `clock()` returns (unix seconds, authenticated); only True authenticates, anything else is a refusal.
    The floor is the last reading plus the TPM time elapsed since (at TPM_CLOCK_RATE): a lower bound, so
    it can refuse a clock that went backwards and can never show that something is still unexpired.
    Used by Freshness here and by the runtime-lease holder (lease.py): one rule for time."""
    seconds, authenticated = clock()
    require(authenticated is True, "time is not authenticated: an expiry cannot be judged (fail closed)")
    require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds >= 0, "the clock returned no time")
    seconds, ticks = int(seconds), tpm_clock()
    if floor is not None:
        elapsed = max(0, ticks - floor["tpm_clock"]) * TPM_CLOCK_RATE / 1000
        lowest = floor["time"] + elapsed
        require(seconds + STEP_BACK >= lowest, "the clock went backwards: it reads %d, and it was at least %d "
                "at an earlier check" % (seconds, lowest))
    # never lower the floor: a small allowed step back must not become the new baseline
    if floor is None or seconds >= floor["time"]:
        floor = {"time": seconds, "tpm_clock": ticks}
    return seconds, floor


class Freshness:
    """One peer's freshness state: the heartbeat it holds and its time floor, in `state_path`; the highest
    accepted sequence in `counter`. `clock()` returns (unix seconds, authenticated); `tpm_clock()` returns
    milliseconds that never run backwards while the TPM is powered."""

    def __init__(self, counter, clock, tpm_clock, state_path):
        self.counter, self.clock, self.tpm_clock, self.state_path = counter, clock, tpm_clock, state_path
        # accept() and check() each read, decide and rewrite the state: one at a time, across processes
        self.lock_path = state_path + ".lock"

    # ---- state on disk ----

    def _read(self):
        try:
            with open(self.state_path, "rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except FileNotFoundError:
            return {"envelope": None, "floor": None, "allowance": None}
        require(len(raw) <= MAX_BYTES, "the freshness state is oversized")
        state = membership.load(raw)
        # "allowance" (the bound the held heartbeat was accepted under) was added for #199; a state written
        # before it has none, and is read as the fixed bound
        require(isinstance(state, dict), "the freshness state must be an object")
        state.setdefault("allowance", None)
        membership.exact(state, ("envelope", "floor", "allowance"), "freshness state")
        validate_floor(state["floor"])
        require(state["allowance"] is None or (isinstance(state["allowance"], int) and not isinstance(state["allowance"], bool)
                                                and 1 <= state["allowance"] <= MAX_ALLOWANCE), "the stored allowance is out of range")
        return state

    def _write(self, state):
        directory = os.path.dirname(os.path.abspath(self.state_path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".freshness-")
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
        entry = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(entry)
        finally:
            os.close(entry)

    # ---- time ----

    def _now(self, state):
        """Authenticated time, not earlier than the floor; the floor is then moved up to it."""
        seconds, state["floor"] = authenticated_now(self.clock, self.tpm_clock, state["floor"])
        return seconds

    @staticmethod
    def _live(heartbeat, now):
        issued, expires = validate(heartbeat)
        require(issued <= now + FUTURE_SKEW, "the heartbeat is issued in the future (%s)" % heartbeat["issued_at"])
        require(now < expires, "EXPIRED: the heartbeat expired at %s" % heartbeat["expires_at"])
        return expires - now

    # ---- the two operations ----

    def accept(self, envelope, manifest):
        """Take a new heartbeat for the current manifest. Returns the seconds it has left."""
        with membership._exclusive(self.lock_path):
            return self._accept(envelope, manifest)

    def _accept(self, envelope, manifest):
        heartbeat = verify(envelope, manifest)
        state = self._read()
        now = self._now(state)
        left = self._live(heartbeat, now)
        held = self.counter.value()
        # An advance a crash interrupted (the held heartbeat is above the counter) is finished FIRST, under
        # the allowance it was accepted under: a node that stopped at ANY increment of a long catch-up is
        # not stranded by the counter it left behind, and the new heartbeat is measured from there. Only
        # for a held heartbeat SIGNED as the current manifest requires (any epoch: the
        # catch-up may span one): a file planted on the disk owes nothing and moves nothing.
        owed = pending(state, held, self.counter.MAX_JUMP)
        widen = 0
        if owed:
            try:
                # signed(), not verify(): no owner lifetime cap here, as this moves only the counter to a number already
                # accepted; every heartbeat relied on goes through verify(), which caps it
                signed(state["envelope"], manifest)
            except Refused:
                # Not finished on the strength of the file (planted, or signed by a key a rotation has since
                # retired). But the gap it records may be real: the bound for THIS heartbeat, which is
                # verified, widens by it (capped), so a node caught mid catch-up by a key rotation is not
                # stranded. The counter still lands only on a genuinely signed sequence.
                owed, widen = 0, owed
        if owed:
            held = self.counter.advance(held + owed, state["allowance"] or self.counter.MAX_JUMP)
        allowance = min(allowed_jump(heartbeat, state["envelope"], self.counter.MAX_JUMP) + widen, MAX_ALLOWANCE)
        require(heartbeat["sequence"] > held, "REPLAY: sequence %d is not above the TPM counter %d" % (heartbeat["sequence"], held))
        require(heartbeat["sequence"] - held <= allowance, "sequence jump %d exceeds the bound %d: anomaly"
                % (heartbeat["sequence"] - held, allowance))
        state["envelope"], state["allowance"] = envelope, allowance
        self._write(state)                                                # disk first, durably
        self.counter.advance(heartbeat["sequence"], state["allowance"])  # then the counter
        return left

    def accept_first(self, envelope, manifest):
        """A replacement node's FIRST heartbeat (#190 --replace, decided by regalia-kms-24): its counter is
        defined AT the heartbeat's sequence (Counter.define_at, no increment loop), and the heartbeat becomes
        the held one, so the time-derived rule applies from its issue time on. Only for a node that holds no
        heartbeat and whose counter's indices do not exist at all (neither the counter nor its base: a damaged
        counter is recount.py's case): the same checks as accept() (signed as the manifest
        requires, for this manifest, live by authenticated time, issued no later than now +
        FUTURE_SKEW). Disk first, then the counter: a cut between leaves a held heartbeat over a counter
        that is missing, which recount.py redefines at that floor. Returns the seconds it has left."""
        with membership._exclusive(self.lock_path):
            heartbeat = verify(envelope, manifest)
            state = self._read()
            require(state["envelope"] is None, "a heartbeat is already held: the first one is taken only by a node that holds none")
            # a genuinely new counter only: a damaged one (a base gone or unlocked) is recount's case, with its
            # floor, its typed phrase, its audit and its proof of the TPM and the chain (a wiped disk also holds
            # no heartbeat, which is exactly what the TPM counter defends against)
            defined = self.counter._defined()
            require(not {int(i, 16) for i in self.counter._indices()} & defined,
                    "the counter %s exists (complete or not): a first heartbeat defines only a new one; use recount" % self.counter.index)
            now = self._now(state)
            left = self._live(heartbeat, now)
            state["envelope"], state["allowance"] = envelope, None
            self._write(state)
            self.counter.define_at(heartbeat["sequence"])
            return left

    def check(self, manifest):
        """Whether this peer may authorize under `manifest` right now. Returns the seconds the heartbeat has
        left, or raises Refused with the reason."""
        now, expires = self.live_until(manifest)
        return expires - now

    def live_until(self, manifest):
        """check(), returning (now, expires): the authenticated reading the decision was made at and the
        heartbeat's absolute expiry. A caller that must not outlive the heartbeat (a runtime lease) bounds
        itself by `expires` and dates itself `now`, without reading the clock a second time."""
        with membership._exclusive(self.lock_path):
            return self._live_until(manifest)

    def held(self):
        """The heartbeat envelope on disk, or None: for passing on to a peer (convergence.bundle), which
        verifies it as if a stranger had sent it. Nothing is checked here and nothing moves."""
        with membership._exclusive(self.lock_path):
            return self._read()["envelope"]

    def window(self, manifest):
        """check(), returning (now, issued, expires, sequence) of the heartbeat relied on: what a monitor
        needs to say how much of its life is left."""
        with membership._exclusive(self.lock_path):
            now, heartbeat = self._checked(manifest)
        issued, expires = validate(heartbeat)
        return now, issued, expires, heartbeat["sequence"]

    def _live_until(self, manifest):
        now, heartbeat = self._checked(manifest)
        return now, validate(heartbeat)[1]

    def _checked(self, manifest):
        state = self._read()
        now = self._now(state)
        self._write(state)   # the floor moves whatever follows
        require(state["envelope"] is not None, "no heartbeat is held: nothing shows the membership is current")
        heartbeat = verify(state["envelope"], manifest)
        held = self.counter.value()
        require(heartbeat["sequence"] >= held, "ROLLBACK: the heartbeat on disk is sequence %d but the TPM counter is %d; "
                "wait for a newer heartbeat" % (heartbeat["sequence"], held))
        self._live(heartbeat, now)
        # accept() was interrupted between the disk and the counter. Only a heartbeat that has just passed
        # every check above (signature, a key of the current manifest, lifetime, expiry) moves the counter:
        # a file planted on the disk cannot push it forward and strand the node.
        if heartbeat["sequence"] > held:
            self.counter.advance(heartbeat["sequence"], state["allowance"] or self.counter.MAX_JUMP)
        return now, heartbeat


def authorize(manifest, peer_id, requester_id, freshness):
    """The peer's decision to give `requester_id` its contribution. Returns the seconds of freshness left."""
    require(membership.may(manifest, peer_id, "authorize"), "%s may not authorize under epoch %d" % (peer_id, manifest["epoch"]))
    require(membership.may(manifest, requester_id, "request"), "%s may not be unlocked under epoch %d" % (requester_id, manifest["epoch"]))
    require(peer_id != requester_id, "a node does not authorize itself")
    return freshness.check(manifest)
