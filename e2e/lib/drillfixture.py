"""The tier-N fixture as a backend for deploy/baremetal/drill.py (#495): the same scenarios (drill.scenarios) as on the
real servers, its faults made by the three-node fixture (threenode.Cluster), and a judge at the LEASE level from the
nodes' own admission trails.

    power_off / power_on   cluster.stop(power="cut") / cluster.start: power lost, then the node booted again
    restart                cluster.stop(power="cycle") then start: an orderly reboot
    partition / heal       cluster.partition (wg-svc's port, in the node's namespace only) / cluster.heal

Every fault is journaled first, as the hardware backend does, so the dry run exercises restore --journal's path too.

WHAT IS JUDGED HERE, AND WHAT IS NOT. The fixture runs sync, admission and wg-apply, not the KMS daemon: there are no
requests and no Gate lines. So the judge holds the lease-level half of each scenario, from the admission trails
("admission-serving" ALLOW and DENY, with their epoch): the others serve throughout; a cut node stops within one lease;
a returning node serves again, under the current epoch. The request-level predicates (e2e/lib/drills.py: zero failed
requests, stateful commits, caught up before a served request) are NOT claimed: they are listed as not judged in the
run's report (its context), never entered as predicates, and they pass nowhere until the daemon runs in tier N
(regalia-kms-24's tracked item on #495)."""
import json
import threading
import time

from threenode import until
from deploy.baremetal import admission, lease

NOT_JUDGED = ("zero_failures", "failures_only_in_flight", "stateful_continues", "caught_up_before_serving")
SLACK_S = 5                       # the admission's round (5 s) and the lapse watcher's 0.5 s, with room


class Fixture:
    def __init__(self, cluster, journal, services):
        self.cluster, self.journal, self.services = cluster, journal, services
        self.samples, self.marks, self._sampling = [], {}, None      # S4's admission.json, every 2 s (48 on #507)

    def _sample(self, node, stop):
        path = self.cluster.nodes[node].run / "admission" / "admission.json"
        while not stop.wait(2):
            try:
                d = json.loads(path.read_text())
            except (OSError, ValueError) as error:
                d = {"unreadable": str(error)[:60]}
            self.samples.append({"t": int(time.time()), "mode": d.get("mode"), "serve_until_boottime_ms": d.get("serve_until_boottime_ms"),
                                 "epoch": d.get("epoch"), "reason": (d.get("reason") or "")[:80], "lease_issued_at": d.get("lease_issued_at"),
                                 **({"unreadable": d["unreadable"]} if "unreadable" in d else {})})

    def _others(self, node):
        return [n for n in self.cluster.nodes if n != node]

    def power_off(self, node):
        self.journal.fault("power-off", node, {"action": "power-on", "node": node})
        self.cluster.stop(node, power="cut")
        return {"node": node, "power": "cut"}

    def power_on(self, node):
        self.cluster.start(node, self.services)
        self.journal.undone_matching({"action": "power-on", "node": node})
        return {"node": node, "power": "on"}

    def restart(self, node):
        self.journal.fault("restart", node, {"action": "power-cycle", "node": node})
        self.cluster.stop(node, power="cycle")
        self.cluster.start(node, self.services)
        return {"node": node, "reboot": "orderly"}

    def restarted(self, node):
        self.journal.undone_matching({"action": "power-cycle", "node": node})

    def power_cycle(self, node):
        self.cluster.stop(node, power="cut")
        self.cluster.start(node, self.services)
        self.journal.undone_matching({"action": "power-cycle", "node": node})
        return {"node": node, "power": "cycled"}

    def partition(self, node):
        self.journal.fault("partition", node, {"action": "unpartition", "node": node})
        self.cluster.partition(node, self._others(node))
        return {"node": node, "cut": "wg-svc"}

    def heal(self, node):
        self.cluster.heal(node)
        self.journal.undone_matching({"action": "unpartition", "node": node})
        return {"node": node, "healed": True}

    def undoers(self):
        return {"power-on": self.power_on, "power-cycle": self.power_cycle, "unpartition": self.heal}

    # S4's owner acts, done for real here: the owner's key on the fixture's SoftHSM token, the shipped survivor command
    def quarantine(self, survivor, others):
        """An owner-signed epoch with `others` QUARANTINED, given to the survivor; alone, it takes the owner's hand
        heartbeat for it (owner_recovery: #199's hand recovery)."""
        stop = threading.Event()
        self._sampling = (threading.Thread(target=self._sample, args=(survivor, stop), daemon=True), stop)
        self._sampling[0].start()
        self.marks["quarantine_begins"] = int(time.time())
        manifest, _ = self.cluster.advance(survivor, signer="owner", owner_recovery=True, **{o: "QUARANTINED" for o in others})
        self.marks["quarantine_done"] = int(time.time())
        return {"epoch": manifest["epoch"]}

    def authorize(self, survivor):
        signed = self.cluster.survivor_authorization(survivor)
        self.marks["install_begins"] = int(time.time())
        done = self.cluster.install_survivor(survivor, signed)
        self.marks["installed"] = int(time.time())
        time.sleep(10)                                  # the sampler sees 10 s past the install, then stops
        if self._sampling:
            self._sampling[1].set()
            self._sampling[0].join(5)
        if done.returncode != 0:
            raise RuntimeError("survivor install on %s failed (%d): %s" % (survivor, done.returncode, (done.stderr or done.stdout).strip()[-600:]))
        return {"expires_at": signed["authorization"]["expires_at"], "scope": signed["authorization"]["scope"],
                "said": (done.stdout or "").strip()[-200:]}

    def lift(self, survivor, others):
        """A root-signed epoch with `others` ACTIVE again, delivered to the survivor (deliver.py): any new epoch ends the
        survivor authorization (survivor.py)."""
        manifest, _ = self.cluster.advance(survivor, signer="root", **{o: "ACTIVE" for o in others})
        return {"epoch": manifest["epoch"]}


class LeaseJudge:
    """judge(name, context) for drill.scenarios, from the admission trails. Every predicate waits (bounded) for the
    line it needs and returns (ok, evidence); none passes on absent evidence."""

    def __init__(self, cluster, backend=None):
        self.cluster, self.backend = cluster, backend

    def serving(self, node, since_ms):
        path = self.cluster._trail_path(node, "admission")
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
        return [e for e in lines if e.get("event") == "admission-serving" and e.get("at", 0) >= since_ms // 1000]

    def _events(self, node, since_ms):
        path = self.cluster._trail_path(node, "admission")
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
        return [{"at": e.get("at"), "event": e.get("event"), "outcome": e.get("outcome"), "epoch": e.get("epoch"),
                 "reason": (e.get("reason") or "")[:100]} for e in lines if e.get("at", 0) >= since_ms // 1000]

    def epoch(self):
        return self.cluster.manifest["epoch"]

    def _others_serve(self, node, since_ms):
        """The other two: no change to not serving since `since_ms`, and serving now."""
        others = [n for n in self.cluster.nodes if n != node]
        denied = {o: [e.get("reason") for e in self.serving(o, since_ms) if e.get("outcome") == "DENY"] for o in others}
        serving = {o: bool(self.cluster.lease(o)) for o in others}
        return (not any(denied.values()) and all(serving.values()),
                {"stopped serving": {o: r for o, r in denied.items() if r}, "serving now": serving})

    def _serves_again(self, node, since_ms, bound_s=240):
        """The node's first change to serving since `since_ms`, under the current epoch."""
        got = until(lambda: [e for e in self.serving(node, since_ms) if e.get("outcome") == "ALLOW"], bound_s, 2)
        allowed = got if isinstance(got, list) else []
        epoch = self.epoch()
        good = bool(allowed) and allowed[0].get("epoch") == epoch
        return good, {"first serving line": allowed[0] if allowed else None, "epoch now": epoch,
                      "waited (s)": round(time.time() - since_ms / 1000)}

    def _stops_within_a_lease(self, node, since_ms):
        bound = lease.MAX_LIFETIME + admission.MARGIN + SLACK_S
        got = until(lambda: [e for e in self.serving(node, since_ms) if e.get("outcome") == "DENY"], bound + 30, 1)
        denied = got if isinstance(got, list) else []
        # integer ms in the evidence: the report's canonical bytes refuse a float (drill.report)
        took_ms = (denied[0]["at"] * 1000 - since_ms) if denied else None
        return (took_ms is not None and took_ms <= bound * 1000), {"stopped after (ms)": took_ms, "bound (s)": bound,
                                                                   "line": denied[0] if denied else None}

    RECOVERY = "RECOVERY: serving alone under the owner's survivor authorization"

    def _s4(self, ctx):
        node, t_off, t_auth = ctx["node"], ctx["t_inject_ms"], ctx["t_auth_ms"]
        got = until(lambda: [e for e in self.serving(node, t_auth) if e.get("outcome") == "ALLOW"
                             and (e.get("reason") or "").startswith(self.RECOVERY)], 120, 2)
        recovered = got if isinstance(got, list) else []
        document = self.cluster.lease(node) or {}
        # every serving-state line since the others went off, as evidence either way (48 on #507: the intended order is a
        # DENY round, its held lease refused under the quarantine epoch, then the RECOVERY ALLOW)
        lines = [{"at": e.get("at"), "outcome": e.get("outcome"), "epoch": e.get("epoch"), "reason": (e.get("reason") or "")[:80]}
                 for e in self.serving(node, t_off)]
        first_recovery = recovered[0]["at"] if recovered else None
        # THE INVARIANT (48 on #507): at the RECOVERY line no VALID normal lease exists. Its order on the trail decides: the
        # serving-state line just before it is either a not-serving one, or a lease-mode ALLOW under an EARLIER epoch (its
        # issuer quarantined in the recovery's epoch, so that lease is refused there). Not "a DENY first": with the
        # authorization already installed when a restarted admission first publishes, there is no not-serving round.
        whole = [e for e in self._events(node, 0) if e["event"] == "admission-serving"]
        at_switch = next((i for i, e in enumerate(whole) if e["outcome"] == "ALLOW" and (e["reason"] or "").startswith(self.RECOVERY)), None)
        before = whole[at_switch - 1] if at_switch else None
        recovery_epoch = whole[at_switch]["epoch"] if at_switch is not None else None
        no_valid_lease = at_switch is not None and (before is None or before["outcome"] == "DENY"
                                                    or (before["epoch"] is not None and before["epoch"] < recovery_epoch))
        # it switched to recovery as soon as it could: by the later of its lease's end (one lease after the others went off)
        # and the authorization's install, plus a round. Serving on under its old lease would make the switch late
        bound_s = max(t_off // 1000 + lease.MAX_LIFETIME + admission.MARGIN, t_auth // 1000) + SLACK_S
        evidence = {"serving lines since the others went off": lines, "admission.json": {"mode": document.get("mode"),
                    "serve_until_boottime_ms": document.get("serve_until_boottime_ms")}, "switch bound": bound_s,
                    # and its journal: a round that raised before recording (48 on #507) would show there
                    "admission journal": self.cluster.journal(node, "admission", lines=60)[-2500:],
                    # and its WHOLE admission trail, unfiltered (48 on #507), the times to place it, admission.json sampled
                    "whole admission trail (last 40)": self._events(node, 0)[-40:],
                    "times": dict({"t_off": t_off // 1000, "t_auth": t_auth // 1000}, **(self.backend.marks if self.backend else {})),
                    "admission.json every 2 s": (self.backend.samples if self.backend else [])}
        evidence["the serving line just before the RECOVERY line"] = before
        return {"no valid normal lease at the switch to recovery (the line before it: not serving, or a lease under an earlier epoch)":
                    (no_valid_lease, evidence),
                "it switched to recovery no later than its lease's end or the install, whichever was later":
                    (first_recovery is not None and first_recovery <= bound_s, {"switched at": first_recovery, "bound": bound_s}),
                "it serves in RECOVERY under the owner's authorization, its admission file in mode recovery":
                    (bool(recovered) and document.get("mode") == "recovery",
                     {"recovery line": recovered[0] if recovered else None, "mode": document.get("mode")})}

    def _s4_back(self, ctx):
        node, t_off, t_lift = ctx["node"], ctx["t_inject_ms"], ctx["t_lift_ms"]
        # never served under a lease while the others were down (from one lease after they went off, to the lift)
        lease_mode = [e for e in self.serving(node, t_off + (lease.MAX_LIFETIME + admission.MARGIN + SLACK_S) * 1000)
                      if e.get("outcome") == "ALLOW" and not (e.get("reason") or "").startswith(self.RECOVERY)
                      and e.get("at", 0) < t_lift // 1000]
        got = until(lambda: [e for e in self.serving(node, t_lift) if e.get("outcome") == "ALLOW"
                             and not (e.get("reason") or "").startswith(self.RECOVERY)], 300, 3)
        normal = got if isinstance(got, list) else []
        document = self.cluster.lease(node) or {}
        return {"never served under a lease from one lease after the others went off until the lift":
                    (not lease_mode, {"lease-mode lines": lease_mode}),
                "the others back, it leaves recovery at its first normal lease":
                    (bool(normal) and document.get("mode") == "lease" and normal[0].get("epoch") == self.epoch(),
                     {"first normal line": normal[0] if normal else None, "mode": document.get("mode"), "epoch now": self.epoch()})}

    def __call__(self, name, ctx):
        node, t = ctx.get("node"), ctx.get("t_inject_ms")
        lease_window = lease.MAX_LIFETIME + admission.MARGIN + SLACK_S
        if name == "S1":
            time.sleep(lease_window)                  # one whole lease with the node off: the others must renew without it
            judged = {"the other two serve throughout": self._others_serve(node, t)}
        elif name == "S1-back":
            judged = {"it serves again, under the current epoch": self._serves_again(node, ctx["t_on_ms"])}
        elif name == "S2":
            judged = {"it serves again, under the current epoch": self._serves_again(node, t),
                      "the other two serve throughout": self._others_serve(node, t)}
        elif name == "S3":
            judged = {"the cut node stops serving within one lease": self._stops_within_a_lease(node, t),
                      "the other two serve throughout": self._others_serve(node, t)}
        elif name == "S3-healed":
            judged = {"healed, it serves again, under the current epoch": self._serves_again(node, ctx["t_heal_ms"])}
        elif name == "S4":
            return self._s4(ctx)
        elif name == "S4-back":
            return self._s4_back(ctx)
        elif name == "S5-wait":                      # drill.scenarios stops the roll unless this holds
            return {"it serves again, under the current epoch": self._serves_again(node, ctx["restarts"][-1]["t_inject_ms"])}
        elif name == "S5":
            restarts = ctx["restarts"]
            ends = [r["t_inject_ms"] for r in restarts[1:]] + [int(time.time() * 1000)]
            gaps = {}
            for r, end in zip(restarts, ends):       # while each restarts, the other two keep serving
                for other in (n for n in self.cluster.nodes if n != r["node"]):
                    stopped = [e for e in self.serving(other, r["t_inject_ms"]) if e.get("outcome") == "DENY" and e["at"] <= end // 1000]
                    if stopped:
                        gaps["%s while %s restarted" % (other, r["node"])] = stopped
            judged = {"no outage across the roll": (not gaps and len(restarts) == len(set(r["node"] for r in restarts)) >= 2,
                                                    {"stopped serving": gaps, "rolled": [r["node"] for r in restarts]})}
        else:
            raise ValueError("no judge for %s" % name)
        # the request-level half (NOT_JUDGED) is not a predicate here at all: listed in the run's report as not judged,
        # never entered as a pass (the KMS daemon is not in tier N)
        return judged
