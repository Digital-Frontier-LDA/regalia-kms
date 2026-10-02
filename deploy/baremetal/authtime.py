#!/usr/bin/env python3
"""Authenticated time: whether this host's clock can be trusted to judge an expiry (#69, #80).

A heartbeat's expiry and a lease's are judged against the clock. An attacker who controls the clock makes
an old proof look current, so heartbeat.py and lease.py take a `clock()` that says, with the time,
whether it is AUTHENTICATED, and refuse everything when it is not. This module is that answer on a host:

    the clock is authenticated  <=>  chrony is synchronised, to sources that are ALL authenticated by NTS,
                                     at least two of which agree, recently, with the system clock in step

read from chrony itself (`chronyc -n -c tracking`, `sources`, `authdata`) and judged here (judge()):

  * tracking's leap status is not "Not synchronised";
  * EVERY configured source is in NTS mode. One plain-NTP source is a way in for anyone on the path, so
    its presence is a refusal whether or not chrony is using it. (chrony.conf says `authselectmode
    require`, so chrony would not select it; this does not rely on that);
  * exactly one source is selected ("*"), and it and every source combined with it ("+") holds NTS keys
    and cookies (the key exchange completed) and has been answering (its reach register is not 0);
  * at least TWO such sources agree. The site declares at least two NTS servers from independent
    operators (conf()); with fewer than two in agreement one operator, or whoever holds one server's
    key, could move the clock alone;
  * the last clock update is not older than MAX_AGE (an hour): "synchronised" must not be a memory;
  * the system clock is within MAX_OFFSET (one second) of chrony's estimate: no step is still pending.

UNAUTHENTICATED MEANS NOTHING IS SERVED. With this answer False a peer authorizes no unlock and issues no
lease, and a node's own lease is not renewed: within the lease bound (300 s) the KMS daemon stops serving,
and within the heartbeat bound peers stop authorizing. THAT IS INTENDED: a node that cannot tell the time
cannot tell an expired proof from a live one. So if the NTS servers are unreachable for longer than those
bounds (their outage, or the site's firewall: NTS needs TCP 4460 for the key exchange and UDP 123), the
nodes stop. The TPM clock floor (heartbeat.authenticated_now) stays underneath as the guard against a
clock that goes backwards; it never shows that time is right.

TWO PROCESSES. `chronyc authdata` needs chrony's command socket, which only root (or chrony's own user)
may use. So a small root service (Service.step, every 15 s) asks chrony and writes ONE fact:

    /run/regalia/authtime.json   (root, 0644, replaced atomically)
    {"schema": "regalia.authtime/v1", "boot_id": "<the kernel's boot ID>",
     "checked_boottime_ms": <CLOCK_BOOTTIME when chrony was asked>, "authenticated": true|false,
     "reason": "<why not>"}

and clock(path) is the `clock()` an unprivileged service takes: (time.time(), True) only if that file is
root's, of this boot, says true, and was written within MAX_STALE (60 s) of now on the boot clock. If the
root service stops, the answer turns False by itself a minute later.

COOPERATIVE, as the admission file is: root on the node can write the file. A node whose root is
compromised is bounded elsewhere (peers refuse it, verifiers refuse its lease).

NOT HERE: the unit that runs the service and the site configuration that names the servers (#80 step 3).
"""
import contextlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time

from deploy.baremetal import admission, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.authtime/v1"
FIELDS = ("schema", "boot_id", "checked_boottime_ms", "authenticated", "reason")
MINIMUM = 2            # NTS sources that must agree
MAX_AGE = 3600         # seconds since chrony last updated the clock
MAX_OFFSET = 1.0       # seconds between the system clock and chrony's estimate
MAX_STALE = 60         # seconds a status file is believed, on the boot clock
INTERVAL = 15          # seconds between two checks by the root service
SERVER = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+"


def _printable(text):
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:240]


# ---- what chrony says ----

def _rows(text, columns, what):
    rows = [line.split(",") for line in text.splitlines() if line.strip()]
    require(all(len(row) == columns for row in rows), "chronyc %s is not understood" % what)
    return rows


def _number(text, what):
    try:
        return float(text)
    except ValueError:
        raise Refused("chronyc %s is not understood" % what)


def parse(tracking, sources, authdata):
    """chronyc's three reports (`-n -c`), as one reading. Anything not understood is refused, not guessed."""
    rows = _rows(tracking, 14, "tracking")
    require(len(rows) == 1, "chronyc tracking is not understood")
    row = rows[0]
    reading = {"leap": row[13], "reference_time": _number(row[3], "tracking"), "system_offset": _number(row[4], "tracking"), "sources": []}
    auth = {}
    for name, mode, key_id, _type, key_length, _last, _attempts, nak, cookies, _cookie_length in _rows(authdata, 10, "authdata"):
        require(name not in auth, "chronyc authdata names a source twice")
        auth[name] = {"mode": mode, "keyed": all(re.fullmatch(r"[0-9]+", v) is not None and int(v) > 0 for v in (key_id, key_length, cookies)),
                      "nak": nak}
    for _mode, state, name, _stratum, _poll, reach, *_rest in _rows(sources, 10, "sources"):
        require(name in auth, "chronyc authdata does not cover the source %s" % _printable(name))
        require(re.fullmatch(r"[0-7]{1,3}", reach) is not None, "chronyc sources is not understood")
        reading["sources"].append({"name": name, "state": state, "reaching": int(reach, 8) != 0, **auth[name]})
    require(len(reading["sources"]) == len(auth), "chronyc sources and authdata do not list the same sources")
    return reading


def judge(reading, now, minimum=MINIMUM, max_age=MAX_AGE, max_offset=MAX_OFFSET):
    """Whether the clock is authenticated under `reading`; Refused with the reason when it is not."""
    require(isinstance(minimum, int) and not isinstance(minimum, bool) and minimum >= 2, "at least two NTS sources must agree")
    require(reading["leap"] != "Not synchronised" and reading["leap"] in ("Normal", "Insert second", "Delete second"),
            "the clock is not synchronised (%s)" % _printable(reading["leap"]))
    sources = reading["sources"]
    plain = [s["name"] for s in sources if s["mode"] != "NTS"]
    require(not plain, "a time source without NTS is configured: %s" % _printable(", ".join(plain)))
    selected = [s for s in sources if s["state"] == "*"]
    require(len(selected) == 1, "no time source is selected")
    used = [s for s in sources if s["state"] in ("*", "+")]
    for source in used:
        require(source["keyed"], "the time source %s holds no NTS keys: its key exchange has not completed" % _printable(source["name"]))
        require(source["reaching"], "the time source %s has stopped answering" % _printable(source["name"]))
    require(len(used) >= minimum, "only %d NTS source(s) agree; %d are needed, so that one operator cannot move the clock alone" % (len(used), minimum))
    age = now - reading["reference_time"]
    require(-max_offset <= age <= max_age, "the clock was last updated %.1f s ago (at most %d)" % (age, max_age))
    require(abs(reading["system_offset"]) <= max_offset, "the system clock is %.3f s from chrony's time: a correction is pending" % reading["system_offset"])


def ask(run=subprocess.run, chronyc="chronyc", socket_path=None):
    """One reading from chrony, over its command socket."""
    reports = []
    for report in ("tracking", "sources", "authdata"):
        argv = [chronyc] + (["-h", socket_path] if socket_path else []) + ["-n", "-c", report]
        try:
            done = run(argv, capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as failure:
            raise Refused("chrony could not be asked (%s)" % type(failure).__name__) from None
        require(done.returncode == 0, "chrony could not be asked for %s" % report)
        reports.append(done.stdout.decode(errors="replace"))
    return parse(*reports)


def conf(servers):
    """The time-source part of chrony.conf: each server with NTS, nothing selectable without it, and no
    clock update on fewer than two sources. `servers` are host names: at least two, from independent
    operators (that they are independent is the site's claim; this checks only that they differ)."""
    require(isinstance(servers, (list, tuple)) and len(servers) >= MINIMUM, "at least %d NTS servers are needed" % MINIMUM)
    for name in servers:
        require(isinstance(name, str) and len(name) <= 253 and re.fullmatch(SERVER, name) is not None, "%s is not a host name" % _printable(name))
    require(len(set(servers)) == len(servers), "an NTS server is listed twice")
    return "".join("server %s nts iburst\n" % name for name in servers) + "authselectmode require\nminsources %d\n" % MINIMUM


# ---- the one fact, for the services that are not root ----

def write(path, document):
    require(tuple(document) == FIELDS, "an authtime document has exactly its fields, in order")
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".authtime-")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(document).encode() + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


class Service:
    """The root side: ask chrony, judge, write. `reading()` returns a reading or raises Refused."""

    def __init__(self, path, reading=ask, wall=time.time, boottime=admission.boottime_ms, boot=admission.boot_id, minimum=MINIMUM):
        self.path, self.reading, self.wall, self.boottime, self.boot, self.minimum = path, reading, wall, boottime, boot(), minimum

    def step(self):
        """One check. Returns the document written. The boot clock is read BEFORE chrony is asked: the
        answer can only look older than it is."""
        checked, reason = self.boottime(), ""
        try:
            judge(self.reading(), self.wall(), self.minimum)
        except Refused as refusal:
            reason = _printable(refusal)
        except Exception as failure:      # noqa: BLE001 - whatever went wrong, the clock was not shown to be right
            reason = "the check failed (%s)" % type(failure).__name__
        document = {"schema": SCHEMA, "boot_id": self.boot, "checked_boottime_ms": checked, "authenticated": reason == "", "reason": reason}
        write(self.path, document)
        return document

    def run(self, stop, interval=INTERVAL):
        while not stop():
            self.step()
            time.sleep(interval)


def read(path, owner=0):
    """The status document, if it is a file only `owner` could have written."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as failure:
        raise Refused("the authenticated-time status cannot be read (%s)" % type(failure).__name__) from None
    try:
        info, parent = os.fstat(fd), os.stat(os.path.dirname(os.path.abspath(path)))
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                "the authenticated-time status is not a file only its writer can change")
        require(parent.st_uid == owner and not parent.st_mode & 0o022, "the directory of the authenticated-time status is writable by others")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    document = membership.load(raw, 4096)
    membership.exact(document, FIELDS, "authtime")
    require(document["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(document["authenticated"], bool) and isinstance(document["reason"], str), "authenticated and reason are malformed")
    checked = document["checked_boottime_ms"]
    require(isinstance(checked, int) and not isinstance(checked, bool) and checked >= 0, "checked_boottime_ms is malformed")
    return document


def status(path, boottime=admission.boottime_ms, boot=admission.boot_id, owner=0, max_stale=MAX_STALE):
    """Whether time is authenticated NOW, by the status file; Refused with the reason when it is not."""
    document = read(path, owner)
    require(document["boot_id"] == boot(), "the authenticated-time status is from another boot")
    age = boottime() - document["checked_boottime_ms"]
    require(0 <= age <= max_stale * 1000, "the authenticated-time status is %d ms old (at most %d s): the check has stopped" % (age, max_stale))
    require(document["authenticated"], "time is not authenticated: %s" % _printable(document["reason"]))


def clock(path, wall=time.time, **how):
    """The `clock()` heartbeat.Freshness and lease.Holder take: (unix seconds, authenticated)."""
    def now():
        try:
            status(path, **how)
        except Refused:
            return wall(), False
        return wall(), True
    return now
