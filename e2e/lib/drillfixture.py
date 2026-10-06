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
import time

from threenode import until
from deploy.baremetal import admission, lease

NOT_JUDGED = ("zero_failures", "failures_only_in_flight", "stateful_continues", "caught_up_before_serving")
SLACK_S = 5                       # the admission's round (5 s) and the lapse watcher's 0.5 s, with room


class Fixture:
    def __init__(self, cluster, journal, services):
        self.cluster, self.journal, self.services = cluster, journal, services

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
        self.journal.fault("restart", node, {"action": "power-on", "node": node})
        self.cluster.stop(node, power="cycle")
        self.cluster.start(node, self.services)
        return {"node": node, "reboot": "orderly"}

    def restarted(self, node):
        self.journal.undone_matching({"action": "power-on", "node": node})

    def partition(self, node):
        self.journal.fault("partition", node, {"action": "unpartition", "node": node})
        self.cluster.partition(node, self._others(node))
        return {"node": node, "cut": "wg-svc"}

    def heal(self, node):
        self.cluster.heal(node)
        self.journal.undone_matching({"action": "unpartition", "node": node})
        return {"node": node, "healed": True}

    def undoers(self):
        return {"power-on": self.power_on, "unpartition": self.heal}


class LeaseJudge:
    """judge(name, context) for drill.scenarios, from the admission trails. Every predicate waits (bounded) for the
    line it needs and returns (ok, evidence); none passes on absent evidence."""

    def __init__(self, cluster):
        self.cluster = cluster

    def serving(self, node, since_ms):
        path = self.cluster._trail_path(node, "admission")
        lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
        return [e for e in lines if e.get("event") == "admission-serving" and e.get("at", 0) >= since_ms // 1000]

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
        took = (denied[0]["at"] - since_ms / 1000) if denied else None
        return (took is not None and took <= bound), {"stopped after (s)": took, "bound (s)": bound,
                                                      "line": denied[0] if denied else None}

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
        elif name == "S5-wait":
            good, evidence = self._serves_again(node, ctx["restarts"][-1]["t_inject_ms"])
            if not good:
                raise RuntimeError("S5: %s did not serve again after its restart: %s" % (node, evidence))
            return {}
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
