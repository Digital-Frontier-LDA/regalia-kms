#!/usr/bin/env python3
"""Freshness heartbeats: a peer authorizes a bootstrap only while it can show its membership is current
(#69, Phase 9 of #59; THREE-SITE-THREAT-MODEL.md design question 1).

A newer manifest proves ordering, not that nothing restrictive happened since. A peer cut off from the
revocation authority would go on helping a node that was revoked an hour ago. So the authority signs a
short-lived statement that a manifest is still the current one, and a peer without a live one refuses.

    envelope  = {"heartbeat": {...}, "signature": {"key": "<hex Ed25519 public key>", "sig": "<hex signature>"}}

    heartbeat = {"schema": "regalia.heartbeat/v1", "epoch": <the manifest's epoch>, "sequence": <int >= 1>,
                 "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "expires_at": "YYYY-MM-DDTHH:MM:SSZ",
                 "manifest_digest": "<64 hex: membership.digest(manifest)>"}

Signed message: b"regalia-heartbeat/v1\\0" + canonical JSON of the heartbeat (as membership.py: sorted
keys, no spaces, ASCII). The domain differs from a manifest's, so neither signature can stand in for the
other. The key must be a revocation key named by the CURRENT manifest; the root key is offline and signs
no heartbeats.

A heartbeat is accepted (Freshness.accept) and later relied on (Freshness.check) only if:
  * it is for the current manifest: the same epoch AND the same digest;
  * it lives at most 24 hours (expires_at - issued_at), whatever the signer wrote;
  * TIME IS AUTHENTICATED. The clock is injected and reports (seconds, authenticated). Without
    authenticated time nothing is accepted and nothing is authorized: a peer that cannot tell the time
    cannot tell an expired heartbeat from a live one. Fail closed; a total outage is A3's manual recovery;
  * time has not gone backwards. Each successful reading is recorded with the TPM clock; the next one
    must not be earlier than that reading plus the TPM time elapsed since (the FLOOR). The TPM clock
    stops while the node is off and may lose a few seconds at a power loss, so the floor is a lower
    bound and is never used to show that a heartbeat is still live;
  * it is not expired and not issued in the future (5 minutes of skew);
  * ITS SEQUENCE IS NEW. The highest accepted sequence is a TPM NV counter (Counter), outside restorable
    disk state: a sequence at or below it is refused, and the heartbeat on disk must carry exactly the
    counter's value, so a disk rolled back to an older heartbeat is refused however valid that heartbeat
    still looks.

Order of writes in accept(): the heartbeat reaches the disk first (durably), then the counter advances.
A crash between the two leaves a verified heartbeat above the counter; check() finishes the advance. The
other order would leave the counter above the disk and the peer refusing until the next heartbeat.

authorize(manifest, peer, requester, freshness) is the whole decision: the peer is ACTIVE, the requester
may be unlocked, and the peer's heartbeat is live.

NOT HERE: the authenticated time source itself. NTS-authenticated chrony on the hosts, and how its
"synchronised and authenticated" state is read, belong to the hardware half of #69; this module takes a
clock that answers that question and refuses when the answer is no.
"""
import calendar
import json
import os
import re
import subprocess
import tempfile
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.heartbeat/v1"
DOMAIN = b"regalia-heartbeat/v1\0"
HEARTBEAT_KEYS = ("schema", "epoch", "sequence", "issued_at", "expires_at", "manifest_digest")
MAX_LIFETIME = 24 * 3600   # the freshness bound: a revocation reaches every peer within this, or the peer stops
FUTURE_SKEW = 300
STEP_BACK = 5              # an authenticated clock may be corrected backwards by this much, no more
# The TPM clock is allowed to run within 15% of real time (TPM 2.0 Part 1, "Clock"), so only 85% of
# its elapsed time counts toward the floor. To be confirmed on the DL360s' TPMs.
TPM_CLOCK_RATE = 0.85
MAX_BYTES = 16 * 1024


def _time(text, label):
    require(isinstance(text, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text) is not None,
            "%s must be UTC, YYYY-MM-DDTHH:MM:SSZ" % label)
    try:
        return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError:
        raise Refused("%s is not a real date" % label)


def validate(heartbeat):
    """Schema only. Returns (issued, expires) in seconds."""
    membership._exact(heartbeat, HEARTBEAT_KEYS, "heartbeat")
    require(heartbeat["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    for k in ("epoch", "sequence"):
        v = heartbeat[k]
        require(isinstance(v, int) and not isinstance(v, bool) and 1 <= v < 2 ** 63, "%s must be an integer >= 1" % k)
    membership._hex(heartbeat["manifest_digest"], 64, "manifest_digest")
    issued, expires = _time(heartbeat["issued_at"], "issued_at"), _time(heartbeat["expires_at"], "expires_at")
    require(issued < expires, "expires_at must be after issued_at")
    require(expires - issued <= MAX_LIFETIME, "a heartbeat lives at most 24 hours (this one: %d s)" % (expires - issued))
    return issued, expires


def verify(envelope, manifest):
    """The heartbeat inside an envelope, if it is signed by a revocation key the CURRENT manifest names
    and is for that manifest. Time and sequence are Freshness's to check."""
    membership._exact(envelope, ("heartbeat", "signature"), "envelope")
    sig = envelope["signature"]
    membership._exact(sig, ("key", "sig"), "signature")
    membership._hex(sig["key"], 64, "signature.key")
    membership._hex(sig["sig"], 128, "signature.sig")
    heartbeat = envelope["heartbeat"]
    validate(heartbeat)
    membership.validate(manifest)
    require(sig["key"] in manifest["revocation_keys"], "the signing key is not a revocation key named by the current manifest")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["key"])).verify(
            bytes.fromhex(sig["sig"]), DOMAIN + membership.canonical(heartbeat))
    except (InvalidSignature, ValueError):
        raise Refused("the heartbeat signature does not verify")
    require(heartbeat["epoch"] == manifest["epoch"], "the heartbeat is for epoch %d, the current manifest is epoch %d"
            % (heartbeat["epoch"], manifest["epoch"]))
    require(heartbeat["manifest_digest"] == membership.digest(manifest), "the heartbeat is for another manifest (digest mismatch)")
    return heartbeat


class Counter:
    """The highest accepted heartbeat sequence, in a TPM NV counter (TPM_NT_COUNTER) of its own.

    A TPM failure is never read as zero: an index that is missing, is not a counter, or cannot be read is
    a refusal. A counter cannot be rewound by deleting it either: a new counter's first increment lands
    above the highest value any deleted counter on that TPM ever held."""

    MAX_JUMP = 1000

    def __init__(self, index, tcti=None, run=subprocess.run):
        self.index, self.run = index, run
        self.env = dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None

    def _tpm(self, *args):
        return self.run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=self.env)

    def define(self):
        done = self._tpm("nvdefine", self.index, "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite")
        require(done.returncode == 0, "cannot define the NV counter %s" % self.index)

    def value(self):
        """0 for a counter never incremented; otherwise what the TPM holds."""
        public = self._tpm("nvreadpublic", self.index)
        require(public.returncode == 0, "the NV counter %s cannot be read (not defined, or the TPM is unavailable)" % self.index)
        found = re.search(r"attributes:\s*\n\s*friendly: (\S+)", public.stdout.decode(errors="replace"))
        require(found is not None, "unexpected tpm2_nvreadpublic output for %s" % self.index)
        attributes = found.group(1).split("|")
        require("nt=0x1" in attributes, "NV index %s is not a counter" % self.index)
        if "written" not in attributes:
            return 0
        read = self._tpm("nvread", self.index, "-C", "o")
        require(read.returncode == 0 and len(read.stdout) == 8, "the NV counter %s cannot be read" % self.index)
        return int.from_bytes(read.stdout, "big")

    def advance(self, sequence):
        """Raise the counter to `sequence`, which must be above it and within the jump bound."""
        now = self.value()
        require(sequence > now, "REPLAY: sequence %d is not above the TPM counter %d" % (sequence, now))
        require(sequence - now <= self.MAX_JUMP, "sequence jump %d exceeds the bound %d: anomaly" % (sequence - now, self.MAX_JUMP))
        while now < sequence:
            done = self._tpm("nvincrement", self.index, "-C", "o")
            require(done.returncode == 0, "cannot increment the NV counter %s" % self.index)
            after = self.value()
            require(after > now, "the NV counter did not advance (%d -> %d)" % (now, after))
            # A first increment starts above every counter this TPM ever deleted, which may be past the target.
            require(after <= sequence, "the NV counter reads %d, already past sequence %d: this TPM held counters "
                    "before; wait for the authority's sequence to pass it" % (after, sequence))
            now = after
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


class Freshness:
    """One peer's freshness state: the heartbeat it holds and its time floor, in `state_path`; the highest
    accepted sequence in `counter`. `clock()` returns (unix seconds, authenticated); `tpm_clock()` returns
    milliseconds that never run backwards while the TPM is powered."""

    def __init__(self, counter, clock, tpm_clock, state_path):
        self.counter, self.clock, self.tpm_clock, self.state_path = counter, clock, tpm_clock, state_path

    # ---- state on disk ----

    def _read(self):
        try:
            with open(self.state_path, "rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except FileNotFoundError:
            return {"envelope": None, "floor": None}
        require(len(raw) <= MAX_BYTES, "the freshness state is oversized")
        state = membership.load(raw)
        membership._exact(state, ("envelope", "floor"), "freshness state")
        if state["floor"] is not None:
            membership._exact(state["floor"], ("time", "tpm_clock"), "floor")
            require(all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in state["floor"].values()), "floor must be integers")
        return state

    def _write(self, state):
        directory = os.path.dirname(os.path.abspath(self.state_path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".freshness-")
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(state, sort_keys=True).encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)
        entry = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(entry)
        finally:
            os.close(entry)

    # ---- time ----

    def _now(self, state):
        """Authenticated time, not earlier than the floor; the floor is then moved up to it."""
        seconds, authenticated = self.clock()
        require(authenticated is True, "time is not authenticated: a heartbeat's expiry cannot be judged (fail closed)")
        require(isinstance(seconds, (int, float)) and not isinstance(seconds, bool) and seconds >= 0, "the clock returned no time")
        seconds, ticks = int(seconds), self.tpm_clock()
        floor = state["floor"]
        if floor is not None:
            elapsed = max(0, ticks - floor["tpm_clock"]) * TPM_CLOCK_RATE / 1000
            lowest = floor["time"] + elapsed
            require(seconds + STEP_BACK >= lowest, "the clock went backwards: it reads %d, and it was at least %d "
                    "at an earlier check" % (seconds, lowest))
        # never lower the floor: a small allowed step back must not become the new baseline
        if floor is None or seconds >= floor["time"]:
            state["floor"] = {"time": seconds, "tpm_clock": ticks}
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
        heartbeat = verify(envelope, manifest)
        state = self._read()
        now = self._now(state)
        left = self._live(heartbeat, now)
        held = self.counter.value()
        require(heartbeat["sequence"] > held, "REPLAY: sequence %d is not above the TPM counter %d" % (heartbeat["sequence"], held))
        require(heartbeat["sequence"] - held <= Counter.MAX_JUMP, "sequence jump %d exceeds the bound %d: anomaly"
                % (heartbeat["sequence"] - held, Counter.MAX_JUMP))
        state["envelope"] = envelope
        self._write(state)                          # disk first, durably
        self.counter.advance(heartbeat["sequence"])  # then the counter
        return left

    def check(self, manifest):
        """Whether this peer may authorize under `manifest` right now. Returns the seconds the heartbeat has
        left, or raises Refused with the reason."""
        state = self._read()
        now = self._now(state)
        self._write(state)   # the floor moves whatever follows
        require(state["envelope"] is not None, "no heartbeat is held: nothing shows the membership is current")
        heartbeat = verify(state["envelope"], manifest)
        held = self.counter.value()
        require(heartbeat["sequence"] >= held, "ROLLBACK: the heartbeat on disk is sequence %d but the TPM counter is %d; "
                "wait for a newer heartbeat" % (heartbeat["sequence"], held))
        left = self._live(heartbeat, now)
        if heartbeat["sequence"] > held:   # accept() was interrupted between the disk and the counter
            self.counter.advance(heartbeat["sequence"])
        return left


def authorize(manifest, peer_id, requester_id, freshness):
    """The peer's decision to give `requester_id` its contribution. Returns the seconds of freshness left."""
    require(membership.may(manifest, peer_id, "authorize"), "%s may not authorize under epoch %d" % (peer_id, manifest["epoch"]))
    require(membership.may(manifest, requester_id, "request"), "%s may not be unlocked under epoch %d" % (requester_id, manifest["epoch"]))
    require(peer_id != requester_id, "a node does not authorize itself")
    return freshness.check(manifest)
