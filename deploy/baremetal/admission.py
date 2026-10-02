#!/usr/bin/env python3
"""The admission file: what tells the KMS daemon that this node holds a runtime lease (#74, Phase 14).

The lease rules (lease.py) are Python; the daemon is Go. Writing those rules a second time in Go would
give two copies that drift. So a small root service on the host keeps the lease, as a kubelet keeps a
node lease, and writes ONE narrow fact for the daemon to read:

    /run/regalia/admission.json   (root, 0644, in a directory only root can write; replaced atomically)

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

COOPERATIVE, as lease.Holder is: root on the node can write this file. What bounds a compromised node is
outside it: peers refuse its unlocks, verifiers refuse its lease, the fencing authority decides who signs.

The call to a peer is injected (`renew`): the transport is #80. The command line takes it as a program.
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
BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
MAX_REQUESTS = 16


def boottime_ms():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 10 ** 6


def boot_id(path=BOOT_ID_PATH):
    with open(path) as f:
        value = f.read().strip()
    require(re.fullmatch(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) is not None, "the kernel boot ID is not a UUID")
    return value


def _printable(text):
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:240]


def write(path, document):
    """Replace the admission file: complete or not at all, readable by the daemon, writable by root only."""
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

    def __init__(self, holder, manifest, renew, path, boottime=boottime_ms, boot=boot_id):
        self.holder, self.manifest, self.renew, self.path, self.boottime = holder, manifest, renew, path, boottime
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
                "serve_until_boottime_ms": serve_until, "reason": _printable(reason)}

    def step(self):
        """One round: renew if due, check, write. Returns the document written."""
        manifest, envelope, serve_until, reason = None, None, 0, ""
        try:
            manifest = self.manifest()
            require(manifest is not None, "this node holds no manifest")
            if self.holder.due(manifest):
                request = self.holder.request()
                self._remember(request["nonce"], self.boottime())
                try:
                    self.holder.install(self.renew(request), manifest)
                except Exception as failure:      # a peer is down, or refused: what the node still holds decides
                    reason = "renewal failed: %s" % failure
            before = self.boottime()              # read BEFORE the check: the bound can only come out earlier
            left = self.holder.check(manifest)
            envelope = self.holder.held()
            require(left > MARGIN, "the lease has %d s left, inside the %d s margin" % (left, MARGIN))
            serve_until, reason = before + (left - MARGIN) * 1000, ""
        except Refused as refusal:   # serve_until is still 0: it is set only by a check that passed
            reason = (reason + "; " if reason else "") + str(refusal)
        document = self._document(manifest, envelope, serve_until, reason)
        write(self.path, document)
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


def command_renewer(argv):
    """`renew` as a program: the request is its stdin (JSON), the lease envelope its stdout. The stand-in for
    the transport (#80)."""
    def renew(request):
        done = subprocess.run(argv, input=json.dumps(request).encode(), capture_output=True, timeout=60)
        require(done.returncode == 0, "the renewal command failed (exit %d)" % done.returncode)
        return membership.load(done.stdout)
    return renew


def read(path):
    """The admission document, as the daemon reads it (for diagnostics; the daemon's own reader is Go)."""
    with open(path, "rb") as f:
        document = membership.load(f.read(4097))
    membership.exact(document, FIELDS, "admission")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description="Show the admission file the KMS daemon reads.")
    parser.add_argument("path", nargs="?", default="/run/regalia/admission.json")
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
