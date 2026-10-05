"""The pass criteria of the failure drills, as code (#495; ADR-0002 D32): one set of predicates that tier N (the
three-node scenarios, e2e/three-node-wan.py) and the real-hardware runner (deploy/baremetal/drill.py, regalia-kms-3e)
both call, so "passed in CI" and "passed on the DL360s" mean the same thing. Nothing here imports a fixture: every
predicate judges plain evidence.

EVIDENCE
  requests   the load generator's per-request log (regalia-kms-ed): dicts {"start", "end" (unix seconds, floats),
             "op", "key", "node" (the node that answered, or None), "outcome": "ok" | "failed", "stateful": bool}.
  journal    one node's daemon audit journal in its own sequence order: dicts {"seq", "event", ...}. The events
             judged: "gate-serving" {applied_revision, lease_state_revision, state_epoch}, "gate-not-serving"
             {reason} (regalia-kms-ed's gate), and "served" {at} (a served request; the adapter maps the daemon's
             operation lines to it). Ordering inside a node is by sequence, never by clocks.

Every predicate returns (passed, why): `why` names the first thing that failed, or what was checked.
"""

LEASE_S = 30          # lease.MAX_LIFETIME (ADR-0002 D32); tests/test_drill_predicates.py holds the three equal to deploy's
MARGIN_S = 5          # admission.MARGIN
WATCH_S = 0.5         # admission.Service.run's lapse watcher interval (#486)


class Malformed(ValueError):
    """A load-generator line that cannot be judged: refused, never defaulted."""


def from_loadgen(line):
    """One line of the load generator's log, in regalia-kms-ed's format ({start_ms, end_ms (UTC ms), op, key, node,
    outcome: "ok" or the API code, attempt, drill, stateful: bool, declared by the load generator from the canary key's
    profile}), as a request here. One adapter for both tiers (3e on #497). No inference (ed): "stateful" is the line's own,
    and a line without it is refused: a sign with a sequenced Cosmos key must never be read as stateless."""
    for k in ("start_ms", "end_ms", "op", "key", "node", "outcome", "stateful"):
        if k not in line:
            raise Malformed("a load-generator line without %r is refused, never defaulted" % k)
    if not isinstance(line["stateful"], bool):
        raise Malformed("a load-generator line's stateful must be true or false, not %r" % (line["stateful"],))
    return {"start": line["start_ms"] / 1000.0, "end": line["end_ms"] / 1000.0, "op": line["op"], "key": line["key"],
            "node": line["node"], "outcome": "ok" if line["outcome"] == "ok" else "failed", "stateful": line["stateful"]}


def _fail(text):
    return False, text


def load_throughout(requests, t_from, t_to, window=LEASE_S):
    """The load ran the whole run: some request started in every `window` of [t_from, t_to] (3e: a drill whose load
    generator died would otherwise pass every predicate on no evidence). The last window counts only if it is at
    least half a window long."""
    for start, end in _windows(t_from, t_to, window):
        if not any(start <= r["start"] < end for r in requests):
            return _fail("the load sent no request between %.1f and %.1f: there is no evidence to judge" % (start, end))
    return True, "the load ran throughout (%d requests)" % len(requests)


def _windows(t_from, t_to, window):
    t = t_from
    while t < t_to:
        end = min(t + window, t_to)
        if end - t >= window / 2.0:                  # a short tail is not judged alone (3e on #497)
            yield t, end
        t += window


def failures_only_in_flight(requests, t_inject):
    """S1/S3: no request failed except those already in flight at the injection (start <= t_inject <= end). Judged
    together with load_throughout()."""
    if not requests:
        return _fail("no request at all: there is no evidence to judge")
    late = [r for r in requests if r["outcome"] != "ok" and not (r["start"] <= t_inject <= r["end"])]
    if late:
        r = late[0]
        return _fail("%d request(s) failed that were not in flight at the injection; first: %s %s at %.1f on %s"
                     % (len(late), r["op"], r["key"], r["start"], r["node"]))
    return True, "only requests in flight at the injection failed (%d)" % sum(1 for r in requests if r["outcome"] != "ok")


def zero_failures(requests, at_least=1):
    """S2/S5: not one failed request, out of at least `at_least`."""
    if len(requests) < at_least:
        return _fail("%d request(s), fewer than the %d this judgement needs: there is no evidence to judge" % (len(requests), at_least))
    failed = [r for r in requests if r["outcome"] != "ok"]
    return (True, "%d requests, none failed" % len(requests)) if not failed else _fail(
        "%d of %d requests failed; first: %s %s at %.1f" % (len(failed), len(requests), failed[0]["op"], failed[0]["key"], failed[0]["start"]))


def stateful_continues(requests, nodes, t_from, t_to):
    """S1: each of `nodes` committed at least one stateful operation in [t_from, t_to] (a majority of two keeps
    ordering)."""
    for node in nodes:
        if not any(r["stateful"] and r["outcome"] == "ok" and r["node"] == node and t_from <= r["end"] <= t_to for r in requests):
            return _fail("%s committed no stateful operation between %.1f and %.1f" % (node, t_from, t_to))
    return True, "%s each committed stateful operations" % ", ".join(sorted(nodes))


def stateful_in_every_window(requests, t_from, t_to, window=LEASE_S):
    """S5: some stateful operation committed in every `window` seconds of [t_from, t_to]: a rolling restart never
    stops stateful work."""
    for start, end in _windows(t_from, t_to, window):
        if not any(r["stateful"] and r["outcome"] == "ok" and start <= r["end"] < end for r in requests):
            return _fail("no stateful operation committed between %.1f and %.1f" % (start, end))
    return True, "stateful operations committed in every %d s window" % window


def silent_after(requests, node, t_cut, bound=LEASE_S + MARGIN_S + WATCH_S):
    """S1/S3: `node` answered no request that started after t_cut + bound (it stops within one lease)."""
    late = [r for r in requests if r["node"] == node and r["outcome"] == "ok" and r["start"] > t_cut + bound]
    if late:
        return _fail("%s still served %s at %.1f, %.1f s after the cut (bound %.1f s)" % (node, late[0]["op"], late[0]["start"],
                                                                                          late[0]["start"] - t_cut, bound))
    return True, "%s served nothing later than %.1f s after the cut" % (node, bound)


def caught_up_before_serving(journal, at_least_served=1):
    """S2/S3/S4 (D32 item 4, #495 Q1): in this node's journal, every "served" line follows a "gate-serving" line with no
    "gate-not-serving" between them, and every "gate-serving" line has applied_revision >= lease_state_revision. The
    node must be SEEN serving again: at least `at_least_served` served lines (3e: a node that never came back would
    otherwise pass)."""
    serving, seen = False, 0
    for line in sorted(journal, key=lambda e: e["seq"]):
        if line["event"] == "gate-serving":
            if line["applied_revision"] < line["lease_state_revision"]:
                return _fail("seq %d: the gate served at revision %d below the lease's %d" % (line["seq"], line["applied_revision"],
                                                                                            line["lease_state_revision"]))
            serving = True
        elif line["event"] == "gate-not-serving":
            serving = False
        elif line["event"] == "served":
            if not serving:
                return _fail("seq %d: a request was served with the gate not serving (before it caught up)" % line["seq"])
            seen += 1
    if seen < at_least_served:
        return _fail("%d served request(s) in the journal, fewer than %d: the node was not seen serving again" % (seen, at_least_served))
    return True, "%d served request(s), each under a gate caught up to its lease" % seen


def survivor_full_scope(requests, survivor, fenced, t_readback, full_from, profile_of, t_end):
    """S4 (the owner's one-server decision, #432): the survivor serves stateless operations throughout; stateful ones
    only from full_from on, and then only for cosmos-account keys (`profile_of(key)`); nothing from a fenced node after
    its power readback."""
    for r in requests:
        if r["node"] in fenced and r["outcome"] == "ok" and r["start"] > t_readback:
            return _fail("%s, fenced, served %s at %.1f after its power readback" % (r["node"], r["op"], r["start"]))
        if r["node"] != survivor or r["outcome"] != "ok" or not r["stateful"]:
            continue
        if r["start"] < full_from:
            return _fail("the survivor committed %s on %s at %.1f, before full scope (%.1f)" % (r["op"], r["key"], r["start"], full_from))
        if profile_of(r["key"]) != "cosmos-account":
            return _fail("the survivor signed %s with a %s key under full scope" % (r["key"], profile_of(r["key"])))
    for start, end in _windows(t_readback, t_end, LEASE_S):        # 3e: "stateless THROUGHOUT" is checked, not assumed
        if not any(r["node"] == survivor and r["outcome"] == "ok" and not r["stateful"] and start <= r["start"] < end for r in requests):
            return _fail("the survivor answered no stateless request between %.1f and %.1f" % (start, end))
    if not any(r["node"] == survivor and r["outcome"] == "ok" and r["stateful"] and r["start"] >= full_from for r in requests):
        return _fail("the survivor committed no stateful operation after full scope began: everything did not stay active")
    return True, "the survivor kept stateless throughout and stateful from %.1f, cosmos-account keys only" % full_from
