#!/usr/bin/env python3
"""Heartbeat watch: how long this peer's freshness has left, as a metric, and warnings while it runs out
(#69).

A peer whose heartbeat expires authorizes no unlock and issues no lease (heartbeat.py), and from then
every reboot at a site needs the recovery key. That must not be the first anyone hears of a revocation
authority that stopped signing. So, at every step():

  * THE METRICS FILE is rewritten (atomically, 0644), in the Prometheus text format, for node_exporter's
    textfile collector or anything that reads it:

        regalia_heartbeat_seconds_left            seconds until the heartbeat expires; 0 with none usable
        regalia_heartbeat_live                    1 while the peer may authorize on it, else 0
        regalia_heartbeat_lifetime_seconds        expires_at - issued_at of the heartbeat held; 0 with none
        regalia_heartbeat_max_lifetime_seconds    what the current manifest allows (heartbeat.max_lifetime)
        regalia_heartbeat_checked_timestamp_seconds   when this file was written: alert if it stops moving

  * A WARNING goes to the sink (the log and the audit trail) when the life left falls to 50 %, to 25 % and
    to 10 % of the heartbeat's own lifetime, once each; from 10 % it is repeated every hour until a newer
    heartbeat arrives. A heartbeat that is expired, missing or unusable (time not authenticated, a
    rollback) is an ERROR, at once and every hour while it lasts. The first step after a warning that
    finds a live heartbeat above every threshold says RENEWED.

THE FRACTION IS OF THE HEARTBEAT'S OWN LIFETIME, not of the manifest's bound: an authority that signs
12-hour heartbeats under a 24-hour bound would otherwise be at "50 % left" the moment each one arrives.
When the authority signs to the bound, the two are the same number.

THE CONDITION THIS PUTS ON THE AUTHORITY: it renews before half of a heartbeat's lifetime is used. One that
renews later has every normal cycle cross the 50 % threshold and warn. (Renewing at a third used, as a
runtime lease is, never warns.) If the authority's schedule cannot change, the thresholds here can.

WHAT HAS BEEN SAID IS ON DISK (`state_path`), not in memory: a watcher that restarts, or runs afresh from
a timer at every step, neither repeats a warning already given nor loses count of the hour.

THE THRESHOLDS AND THE REPEAT ARE A MONITORING SETTING, local to the host, and nothing here decides
anything: the security bound is the manifest's and the refusal at expiry is heartbeat.py's. Losing the
state file costs one repeated warning.

READING IS THE REAL CHECK (Freshness.window): the same authenticated time, floor, counter and signature
a peer's decision uses, so "live" here means what it means there. Like any check it moves the time floor.

The manifest is injected as a callable (the peer's membership.Store.load). Running this from a timer or a
loop on the host belongs with the heartbeat's transport (#80).
"""
import contextlib
import json
import os
import tempfile
import time

from deploy.baremetal import heartbeat, membership

Refused, require = membership.Refused, membership.require

THRESHOLDS = (50, 25, 10)       # percent of the heartbeat's lifetime left
REPEAT = 3600                   # seconds between repeated warnings
MAX_BYTES = 4096
DOWN = "down"


def _printable(text):
    return "".join(c if " " <= c <= "~" else "?" for c in str(text))[:240]


def validate_thresholds(thresholds):
    """Whole percents from 1 to 99, highest first, none twice."""
    require(isinstance(thresholds, (tuple, list)) and len(thresholds) >= 1, "at least one threshold is needed")
    for value in thresholds:
        require(isinstance(value, int) and not isinstance(value, bool) and 0 < value < 100, "a threshold is a whole percent from 1 to 99")
    require(list(thresholds) == sorted(set(thresholds), reverse=True), "thresholds go from the highest down, none twice")
    return tuple(thresholds)


def reading(freshness, manifest):
    """What the peer's freshness is now: {"live", "seconds_left", "lifetime", "max_lifetime", "sequence",
    "epoch", "manifest_digest", "reason"}. Never raises Refused: a refusal IS the reading."""
    result = {"live": False, "seconds_left": 0, "lifetime": 0, "max_lifetime": 0, "sequence": 0, "epoch": 0,
              "manifest_digest": "", "reason": ""}
    try:
        require(manifest is not None, "no manifest is held")
        membership.validate(manifest)
        result.update(epoch=manifest["epoch"], manifest_digest=membership.digest(manifest),
                      max_lifetime=heartbeat.max_lifetime(manifest))
        now, issued, expires, sequence = freshness.window(manifest)
    except Refused as refusal:
        return dict(result, reason=_printable(refusal))
    return dict(result, live=True, seconds_left=expires - now, lifetime=expires - issued, sequence=sequence)


def decide(current, previous, now, thresholds=THRESHOLDS, repeat=REPEAT):
    """The warning due for the reading `current`, if any, and what to remember. `previous` is what the last
    call returned to remember ({} at first): {"key": the heartbeat's sequence or "down", "level": the
    lowest threshold warned about for it (0 for down) or None, "last": when the last warning went}.
    Returns (event or None, remembered). `now` only spaces the repeats: a clock set back repeats at once."""
    key = current["sequence"] if current["live"] else DOWN
    same = previous.get("key") == key
    level, last = (previous.get("level"), previous.get("last")) if same else (None, None)
    waited = last is None or now < last or now - last >= repeat
    remembered = {"key": key, "level": level, "last": last}

    def event(severity, kind, threshold):
        return {"event": "heartbeat-freshness", "severity": severity, "kind": kind, "epoch": current["epoch"],
                "manifest_digest": current["manifest_digest"], "sequence": current["sequence"],
                "seconds_left": current["seconds_left"], "lifetime_s": current["lifetime"],
                "max_lifetime_s": current["max_lifetime"], "threshold_percent": threshold, "reason": current["reason"]}

    if not current["live"]:
        if not waited:
            return None, remembered
        kind = "EXPIRED" if current["reason"].startswith("EXPIRED") else "UNUSABLE"
        return event("ERROR", kind, 0), dict(remembered, level=0, last=int(now))
    crossed = [t for t in thresholds if current["seconds_left"] * 100 <= t * current["lifetime"]]
    if not crossed:
        if previous.get("level") is not None and not same:
            return event("INFO", "RENEWED", 0), remembered
        return None, remembered
    lowest = min(crossed)
    if level is None or lowest < level:
        return event("WARN", "RUNNING_OUT", lowest), dict(remembered, level=lowest, last=int(now))
    if lowest == min(thresholds) and waited:
        return event("WARN", "RUNNING_OUT", lowest), dict(remembered, last=int(now))
    return None, remembered


def metrics(current, now):
    """The metrics file's text."""
    rows = (("regalia_heartbeat_seconds_left", "Seconds until this peer's freshness heartbeat expires; 0 with none usable.",
             current["seconds_left"]),
            ("regalia_heartbeat_live", "1 while this peer may authorize on its heartbeat, else 0.", 1 if current["live"] else 0),
            ("regalia_heartbeat_lifetime_seconds", "Lifetime of the heartbeat held (expiry less issue); 0 with none usable.",
             current["lifetime"]),
            ("regalia_heartbeat_max_lifetime_seconds", "The longest heartbeat the current manifest allows; 0 with no manifest.",
             current["max_lifetime"]),
            ("regalia_heartbeat_checked_timestamp_seconds", "When this file was written.", int(now)))
    return "".join("# HELP %s %s\n# TYPE %s gauge\n%s %d\n" % (name, text, name, name, value) for name, text, value in rows)


def _replace(path, data, mode):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".heartbeat-watch-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


class Watch:
    """One peer's heartbeat monitor. `manifest()` returns the peer's current manifest (or None, or raises
    Refused); `sink(event)` takes each warning; `clock()` is unix seconds, used only to space the repeats
    and to date the metrics file."""

    def __init__(self, freshness, manifest, sink, metrics_path, state_path, thresholds=THRESHOLDS, repeat=REPEAT, clock=time.time):
        require(isinstance(repeat, int) and not isinstance(repeat, bool) and repeat >= 60, "the repeat is at least 60 seconds")
        self.freshness, self.manifest, self.sink, self.clock = freshness, manifest, sink, clock
        self.metrics_path, self.state_path = metrics_path, state_path
        self.thresholds, self.repeat = validate_thresholds(thresholds), repeat

    def _remembered(self):
        """What was warned about last. A missing or damaged file is "nothing": one warning may repeat."""
        try:
            with open(self.state_path, "rb") as f:
                raw = f.read(MAX_BYTES + 1)
            state = membership.load(raw[:MAX_BYTES])
            membership.exact(state, ("key", "level", "last"), "watch state")
            key, level, last = state["key"], state["level"], state["last"]
            require(key == DOWN or (isinstance(key, int) and not isinstance(key, bool)), "key")
            require(level is None or level == 0 or level in self.thresholds, "level")
            require(last is None or (isinstance(last, int) and not isinstance(last, bool)), "last")
            return state
        except (OSError, Refused):
            return {}

    def step(self):
        """Read, write the metrics, warn if a warning is due. Returns the reading."""
        try:
            manifest = self.manifest()
        except Refused:
            manifest = None
        current, now = reading(self.freshness, manifest), self.clock()
        _replace(self.metrics_path, metrics(current, now).encode(), 0o644)
        event, remembered = decide(current, self._remembered(), now, self.thresholds, self.repeat)
        if event is not None:
            self.sink(event)
        # after the sink: a warning that could not be delivered is due again at the next step
        _replace(self.state_path, json.dumps(remembered, sort_keys=True).encode(), 0o600)
        return current
