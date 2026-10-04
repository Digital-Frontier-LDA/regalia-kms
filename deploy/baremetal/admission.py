#!/usr/bin/env python3
"""The admission file: what tells the KMS daemon that this node holds a runtime lease (#74, Phase 14).

The lease rules (lease.py) are Python; the daemon is Go. Writing those rules a second time in Go would
give two copies that drift. So a small service on the host keeps the lease, as a kubelet keeps a
node lease, and writes ONE narrow fact for the daemon to read:

    /run/regalia/admission/admission.json   (0644, replaced atomically)

The service runs as its own user, regalia-admission, not root (#191): it talks to peers and parses their
answers. /run/regalia/admission is that user's (0755, regalia.tmpfiles.conf) inside root's /run/regalia,
so it can replace this file and nothing else there. The daemon accepts the file and its directory only
from that user (runtime_admission_owner) or root, with no group or other write, and nothing above it that
anyone else could swap; and it accepts the boot session beside it only from root.

    {"schema": "regalia.admission/v1",
     "node_id": ..., "session_id": "<64 hex: this boot's attested session>",
     "boot_id": "<the kernel's boot ID>",
     "epoch": <the manifest epoch the check was made under>, "manifest_digest": "<64 hex>",
     "lease_issued_at": "YYYY-MM-DDTHH:MM:SSZ",
     "requested_boottime_ms": <when this node asked for the lease it holds>,
     "serve_until_boottime_ms": <the daemon may serve while its CLOCK_BOOTTIME is below this; 0 = no>,
     "reason": "<why not, when serve_until is 0>"}

THE DAEMON NEEDS NO WALL CLOCK. The service turns the lease's expiry, judged on authenticated time, into
this host's CLOCK_BOOTTIME (which runs through suspend and cannot be set), less a margin. The daemon
compares that with its own CLOCK_BOOTTIME. boot_id ties those numbers to this boot; in another they mean
nothing, and the daemon refuses the file.

REFUSED MEANS ZERO, AT ONCE. Every step() checks the lease under the node's current manifest. When the
check refuses (the node is revoked in a manifest that has arrived, the lease expired, time is not
authenticated or went backwards, the chain was rolled back), serve_until is written as 0 with the
reason, in that same step. When a renewal merely fails (a peer is down), the node keeps what its lease
still gives it, and no more.

IF THIS SERVICE STOPS, the last file stands, and it runs out by itself at the lease's expiry less the
margin: the daemon stops with no one telling it to.

requested_boottime_ms is when the node made the request that the held lease answers. A lease is issued
after it was asked for, so "asked for after the HSM returned" shows a peer vouched after the HSM
returned, with no comparison between two machines' clocks (#72, PoC 12.4).

WHEN THE DAEMON STARTS, THE SERVICE ASKS AT ONCE. The daemon serves a token only under a lease asked for
after the daemon's own process started (#72: a token pulled, the daemon restarted and the token put back
must not resume on the old lease). Left to the schedule, that is a wait of up to a third of a lease. So
each step() compares the held lease's request time with the daemon's start, which the kernel dates in
/proc/<pid>/stat on the boot clock and the daemon reads for itself (internal/admission.ProcessStart): a
lease asked for at or before it is renewed now. `daemon_started` is injected; unit_started() is the one
for a systemd unit. Not knowing the start (the unit is down) changes nothing.

COOPERATIVE, as lease.Holder is: root on the node, and the lease service's own user, can write this
file. What bounds a compromised node is outside it: peers refuse its unlocks, verifiers refuse its
lease, the fencing authority decides who signs.

The call to a peer is injected (`renew`): the transport is #80. Run as a program, this only SHOWS the
admission file the daemon reads.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

from deploy.baremetal import lease, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.admission/v1"
FIELDS = ("schema", "node_id", "session_id", "boot_id", "epoch", "manifest_digest", "lease_issued_at",
          "requested_boottime_ms", "serve_until_boottime_ms", "reason")
MARGIN = 10                # seconds held back from the lease's expiry: the daemon stops before a verifier would refuse
NEVER = "1970-01-01T00:00:00Z"
# The daemon reads this file with a limit of 4096 bytes (internal/admission/admission.go, maxFileBytes) and
# refuses a larger one as "oversized", which would hide the reason. So the reason here is bounded well below
# that. The full text goes to the node's admission trail (admission_dir/audit.jsonl): each renewal attempt and its
# answer (node.admission_service, "admission-renew"), and each change between serving and not serving with its reason
# ("admission-serving", Service below).
ADMISSION_REASON_LIMIT = 1024
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
MAX_REQUESTS = 16


def boottime_ms():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 10 ** 6


def boot_id(path=BOOT_ID_PATH):
    with open(path) as f:
        value = f.read().strip()
    require(re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None, "the kernel boot ID is not a UUID")
    return value


def process_started_ms(pid, proc="/proc"):
    """When process `pid` started, in CLOCK_BOOTTIME milliseconds: field 22 of /proc/<pid>/stat, which the
    kernel counts in clock ticks, rounded down; this returns the tick AFTER, as the daemon does for itself,
    so it is never before the true start. The command name (field 2) is in parentheses and may contain spaces and
    parentheses, so the fields are counted from the LAST ")". Go's reader assumes 100 ticks a second
    (internal/admission.parseProcessStart); another rate here is refused rather than disagreed with."""
    require(os.sysconf("SC_CLK_TCK") == 100, "the kernel clock tick is not 100 Hz: the daemon would read another start time")
    with open(os.path.join(proc, str(int(pid)), "stat")) as f:
        stat = f.read(4096)
    fields = stat[stat.rfind(")") + 1:].split() if ")" in stat else []
    require(len(fields) > 19 and re.fullmatch(r"[1-9][0-9]{0,15}", fields[19]) is not None, "the process start time cannot be read")
    return (int(fields[19]) + 1) * 10


def unit_started(unit="regalia-kms.service", run=subprocess.run, proc="/proc"):
    """A `daemon_started` for Service: when the main process of a systemd unit started, or None when the
    unit has no main process or it cannot be read (then nothing is renewed early)."""
    def started():
        try:
            done = run(["systemctl", "show", "--property=MainPID", "--value", unit], capture_output=True, timeout=10)
            pid = done.stdout.decode(errors="replace").strip() if done.returncode == 0 else ""
            if re.fullmatch(r"[1-9][0-9]{0,9}", pid) is None:
                return None
            return process_started_ms(pid, proc)
        except (OSError, subprocess.SubprocessError, Refused):
            return None
    return started


def _printable(text, limit=membership.NAME_LIMIT):
    return membership.printable(text, limit)


def write(path, document):
    """Replace the admission file: complete or not at all, readable by the daemon, writable by its writer only."""
    require(tuple(document) == FIELDS, "an admission document has exactly its fields, in order")
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".admission-")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(document).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class Service:
    """One node's holder loop. `holder` is its lease.Holder; `manifest()` returns its current manifest (its
    membership.Store.load); `renew(request)` asks a peer and returns the lease envelope, or raises."""

    def __init__(self, holder, manifest, renew, path, boottime=boottime_ms, boot=boot_id, daemon_started=None, metrics=None,
                 record=None, warn=None):
        self.holder, self.manifest, self.renew, self.path, self.boottime = holder, manifest, renew, path, boottime
        self.metrics = metrics                    # #305: metrics(samples) after every round (metrics.publish)
        # #340: record(event) appends to the node's admission trail, raising if it cannot. Each change between serving
        # and not serving is recorded once, with its reason: TO serving only once recorded (else it stays not serving);
        # TO not serving at once, recorded after (a failed record is loud and tried again next round, never a reason
        # to keep serving). recorded is the state the trail last holds (None: nothing yet this run).
        self.record, self.recorded = record, None
        self.warn = warn or (lambda text: print(text, file=sys.stderr, flush=True))
        self.daemon_started = daemon_started      # () -> the daemon's start on the boot clock (ms), or None
        self.boot = boot()
        self.requests_path = path + ".requests"   # nonce -> when it was asked for; survives a restart of this service

    def _requests(self):
        try:
            with open(self.requests_path) as f:
                requests = json.load(f)
        except (OSError, ValueError):
            return {}
        if not isinstance(requests, dict):
            return {}
        return {k: v for k, v in requests.items() if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool)}

    def _remember(self, nonce, asked):
        requests = self._requests()
        requests[nonce] = asked
        kept = dict(sorted(requests.items(), key=lambda item: item[1])[-MAX_REQUESTS:])
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.path)), prefix=".admission-requests-")
        with os.fdopen(fd, "w") as f:
            json.dump(kept, f)
        os.replace(tmp, self.requests_path)

    def _document(self, manifest, envelope, serve_until, reason):
        held = envelope["lease"] if envelope else None
        return {"schema": SCHEMA, "node_id": self.holder.node_id, "session_id": self.holder.session_id, "boot_id": self.boot,
                "epoch": manifest["epoch"] if manifest else 0,
                "manifest_digest": membership.digest(manifest) if manifest else "00" * 32,
                "lease_issued_at": held["issued_at"] if held and serve_until else NEVER,
                "requested_boottime_ms": self._requests().get(held["nonce"], 0) if held and serve_until else 0,
                "serve_until_boottime_ms": serve_until, "reason": _printable(reason, ADMISSION_REASON_LIMIT)}

    def _transition(self, manifest, envelope, serving, reason):
        held = envelope["lease"] if envelope else None
        return {"event": "admission-serving", "epoch": manifest["epoch"] if manifest else 0,
                "manifest_digest": membership.digest(manifest) if manifest else "", "subject": self.holder.node_id,
                "peer": held["issuer"] if held and serving else "", "outcome": "ALLOW" if serving else "DENY",
                "reason": _printable(reason, membership.REASON_LIMIT)}

    def _daemon_waits(self):
        """Whether the daemon started after the held lease was asked for: it will not serve on that lease,
        so a new one is asked for now. False when there is no daemon to wait, or no lease (then due() asks)."""
        started = self.daemon_started() if self.daemon_started is not None else None
        held = self.holder.held()
        if started is None or held is None:
            return False
        return self._requests().get(held["lease"]["nonce"], 0) <= started

    def step(self):
        """One round: renew if due, check, write. Returns the document written."""
        manifest, envelope, serve_until, reason, left = None, None, 0, "", 0
        try:
            manifest = self.manifest()
            require(manifest is not None, "this node holds no manifest")
            waits = self._daemon_waits()
            if waits or self.holder.due(manifest):
                request = self.holder.request()
                self._remember(request["nonce"], self.boottime())
                try:
                    # asked for the daemon's sake: this lease is the one to hold, even if a peer whose clock
                    # runs behind, or whose heartbeat ends sooner, gave it less life than the one held.
                    # If it has no more than MARGIN left (the peer's heartbeat is about to end), this round
                    # writes "not admitted" where the tokens alone were waiting: no key was being served
                    # either way, and the next round's scheduled renewal takes the longer lease.
                    self.holder.install(self.renew(request), manifest, prefer=waits)
                except Exception as failure:      # a peer is down, or refused: what the node still holds decides
                    reason = "renewal failed: %s" % failure
            before = self.boottime()              # read BEFORE the check: the bound can only come out earlier
            left = self.holder.check(manifest)
            envelope = self.holder.held()
            require(left > MARGIN, "the lease has %d s left, inside the %d s margin" % (left, MARGIN))
            serve_until, reason = before + (left - MARGIN) * 1000, ""
        except Refused as refusal:   # serve_until is still 0: it is set only by a check that passed
            reason = (reason + "; " if reason else "") + str(refusal)
        serving = bool(serve_until)
        if serving and self.recorded is not True and self.record is not None:
            try:                                  # TO serving: on the trail first, or not at all
                self.record(self._transition(manifest, envelope, True, ""))
                self.recorded = True
            except Exception as failure:          # noqa: BLE001 - any failure to record keeps the node not serving
                serving, serve_until = False, 0
                reason = "the change to serving could not be recorded on the admission trail: %s" % (str(failure) or type(failure).__name__)
        document = self._document(manifest, envelope, serve_until, reason)
        write(self.path, document)
        if not serving and self.recorded is not False and self.record is not None:
            try:                                  # TO not serving: already done (the file above); recorded after
                self.record(self._transition(manifest, envelope, False, reason))
                self.recorded = False
            except Exception as failure:          # noqa: BLE001 - loud, and tried again next round; the node has stopped
                self.warn("regalia-admission: AUDIT: this node stopped serving (%s) and the admission trail did not take it: %s"
                          % (reason, str(failure) or type(failure).__name__))
        if self.metrics is not None:
            self.metrics([("regalia_admission_serving", {}, 1 if serve_until else 0),
                          ("regalia_admission_lease_seconds_left", {}, max(0, int(left)) if serve_until else 0)])
        return document

    def run(self, stop, interval=5):
        """step() every `interval` seconds until `stop()` is true. An error other than a refusal (the disk,
        the TPM) is not swallowed into a stale file: zero is written, then the error is raised."""
        while not stop():
            try:
                self.step()
            except Exception as failure:
                write(self.path, self._document(None, None, 0, "the lease service failed: %s" % failure))
                raise
            time.sleep(interval)


def read(path):
    """The admission document, as the daemon reads it (for diagnostics; the daemon's own reader is Go)."""
    with open(path, "rb") as f:
        document = membership.load(f.read(4097))
    membership.exact(document, FIELDS, "admission")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description="Show the admission file the KMS daemon reads.")
    parser.add_argument("path", nargs="?", default="/run/regalia/admission/admission.json")
    args = parser.parse_args(argv)
    try:
        document = read(args.path)
    except (OSError, Refused) as failure:
        print("admission: %s" % failure, file=sys.stderr)
        return 1
    left = (document["serve_until_boottime_ms"] - boottime_ms()) / 1000
    print(json.dumps(document, indent=2))
    print("admitted for %.0f more seconds" % left if left > 0 else "NOT ADMITTED: %s" % (document["reason"] or "the lease ran out"))
    return 0 if left > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
