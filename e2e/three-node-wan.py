#!/usr/bin/env python3
"""#432 (owner requirement 2026-10-05: the servers may be about 500 km apart), tier N: today's three-node services
across a WAN (e2e/lib/threenode.py), every link given about 100 ms round trip with jitter and a little loss (netem on
each node's underlay; 50 ms +- 15 ms each way). It measures what the multi-active design (#432) must keep or beat.

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-wan.py

IT CHANGES THE MACHINE (namespaces, interfaces, queueing disciplines inside the nodes' namespaces, loop devices,
dm-crypt mappings, transient units), so it runs only on a GitHub-hosted runner, or on a throwaway host whose
/etc/machine-id is in REGALIA_THREE_NODE_HOST_OK. It needs the kernel's netem module (linux-modules-extra on the runner).

  1  three nodes, then the WAN: every pair's round trip measured on the underlay, at least 80 ms (netem is on)
  2  every node leased across the WAN, and every node's sync pulls from both others
  3  a's lease renewed across the WAN
  4  failover: a's issuer cut off entirely (netem loss 100%); a renewed by the other peer with no gap in serving;
     the cut-off node stops serving by itself at its lease's end
  5  heal: the cut-off node rejoins and is leased again
  6  a new epoch across the WAN: every node takes it and the nodes sign its heartbeat (the stateful path today)

Each step prints a MEASURED line. Today's runtime lease is lease.MAX_LIFETIME (300 s), renewed at a third of its life;
the multi-active design's short leases and majority commits (#432) are measured here once they exist. The
namespaces share one kernel clock, so clock skew is not here (authtime's and the Gate's unit tests hold it).
"""
import os
import pathlib
import re
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402
from deploy.baremetal import admission, authtime, lease   # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")
WAN = ("delay", "50ms", "15ms", "distribution", "normal", "loss", "0.5%")   # each way: ~100 ms round trip per pair
CUT = ("loss", "100%")


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": %s" % (detail,)) if detail != "" else ""))
    sys.stdout.flush()


def header(text):
    print("\n\033[1m### %s\033[0m" % text)
    sys.stdout.flush()


def netem(cluster, name, spec):
    """The node's underlay (eth0 in its namespace) through netem `spec`: its egress only, so a pair's round trip is
    the sum of both nodes' delays. Inside the node's namespace, never the host's."""
    cluster.member(name).in_ns("tc", "qdisc", "replace", "dev", "eth0", "root", "netem", *spec)


def rtt(cluster, name, other):
    """(min, avg, max) round trip in ms from `name` to `other` on the underlay, from ping's summary; None if none."""
    out = cluster.member(name).in_ns("ping", "-c", "10", "-i", "0.2", "-W", "2", "-q", cluster.member(other).underlay, check=False).stdout
    found = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/", out)
    return tuple(float(v) for v in found.groups()) if found else None


def held(cluster, name):
    """(lease_issued_at, issuer) of the lease the node's admission holds now, or (None, None) when it serves none."""
    document = cluster.lease(name)
    return (document.get("lease_issued_at"), cluster.lease_issuer(name)) if document else (None, None)


def renewed(cluster, name, after, by=None):
    """A lease issued after `after` (its issued_at string), by `by` if given, and serving."""
    issued, issuer = held(cluster, name)
    return issued and issued > (after or "") and (by is None or issuer == by) and (issued, issuer)


def answered(cluster, server, caller, since=0.0):
    """Whether `server`'s sync answered a pull from `caller` (ALLOW) at or after `since` (unix seconds)."""
    return any(e.get("event") == "sync-pull" and e.get("subject") == caller and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
               for e in cluster.trail(server))


def scenario(cluster):
    names = ["a", "b", "c"]
    renewal = lease.MAX_LIFETIME / 3 + 30            # one renewal within a third of the lease's life, and slack

    header("1  three nodes, then the WAN on every underlay")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        netem(cluster, name, WAN)
    for name, other in (("a", "b"), ("b", "c"), ("c", "a")):
        measured = rtt(cluster, name, other)
        ok(measured is not None and measured[1] >= 80, "%s -> %s round trip on the underlay: %s ms (min/avg/max), netem on" % (name, other, measured), measured)
        print("  MEASURED: %s <-> %s underlay round trip min/avg/max %s ms" % (name, other, measured))

    header("2  every node leased across the WAN; every node pulls from both others")
    started = time.time()
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 240, 3)), "%s holds a lease across the WAN" % name, cluster.journal(name, "admission")[-400:])
    print("  MEASURED: services started -> every node leased: %.0f s" % (time.time() - started))
    for server in names:
        for caller in names:
            if caller != server:
                ok(until(lambda: answered(cluster, server, caller), 120, 2) is True,
                   "%s answered %s's pull across the WAN" % (server, caller), cluster.journal(caller, "sync")[-400:])

    header("3  a's lease renewed across the WAN")
    first, _ = held(cluster, "a")
    asked = time.time()
    got = until(lambda: renewed(cluster, "a", first), renewal + 60, 3)
    ok(bool(got), "a's lease renewed (issued %s, then %s, by %s)" % (first, got and got[0], got and got[1]), held(cluster, "a"))
    print("  MEASURED: a's renewal seen %.0f s after the wait began (due at a third of %d s)" % (time.time() - asked, lease.MAX_LIFETIME))

    header("4  failover: a's issuer cut off entirely; the other peer renews a, and the cut-off node stops by itself")
    current, issuer = held(cluster, "a")
    other = next(n for n in ("b", "c") if n != issuer)
    netem(cluster, issuer, CUT)
    cut = time.time()
    gaps, got, end = [], None, time.time() + renewal + 120
    while time.time() < end and not got:
        if not cluster.lease("a"):
            gaps.append(round(time.time() - cut))
        got = renewed(cluster, "a", current, by=other)
        time.sleep(2)
    ok(bool(got), "with %s cut off, a's next lease is %s's (%s)" % (issuer, other, got and got[0]), held(cluster, "a"))
    ok(not gaps, "and a served at every sample from the cut until %s's lease came" % other, gaps)
    print("  MEASURED: %s cut off -> a renewed by %s: %.0f s" % (issuer, other, time.time() - cut))
    stopped = until(lambda: not cluster.lease(issuer), lease.MAX_LIFETIME + admission.MARGIN + 60, 2)
    took = time.time() - cut
    ok(stopped is True and took <= lease.MAX_LIFETIME + 15,
       "%s, cut off from both peers, stopped serving by itself %.0f s after the cut (its lease had at most %d s)" % (issuer, took, lease.MAX_LIFETIME),
       cluster.journal(issuer, "admission")[-400:])
    print("  MEASURED: %s cut off -> it stops serving: %.0f s (bound: MAX_LIFETIME %d s)" % (issuer, took, lease.MAX_LIFETIME))
    ok(until(lambda: all(cluster.lease(n) for n in names if n != issuer), 30, 2) is True,
       "the two connected nodes serve throughout", {n: held(cluster, n) for n in names})

    header("5  heal: the cut-off node rejoins")
    netem(cluster, issuer, WAN)
    back = time.time()
    ok(bool(until(lambda: cluster.lease(issuer), renewal + 120, 3)), "%s, back on the WAN, is leased again" % issuer,
       cluster.journal(issuer, "admission")[-400:])
    print("  MEASURED: %s healed -> leased again: %.0f s" % (issuer, time.time() - back))

    header("6  a new epoch across the WAN")
    began = time.time()
    manifest, _ = cluster.advance(other)             # raises unless every running node takes it
    for name in names:
        ok(cluster.node(name).store().load()["epoch"] == manifest["epoch"], "%s holds epoch %d" % (name, manifest["epoch"]))
    fresh = cluster.fresh(names, epoch=manifest["epoch"], timeout=300)
    ok(all(fresh.values()), "every node holds epoch %d's heartbeat, signed by the nodes, across the WAN" % manifest["epoch"], fresh)
    print("  MEASURED: epoch %d delivered on %s -> every node holds it and its heartbeat: %.0f s" % (manifest["epoch"], other, time.time() - began))


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-wan: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    present += [p for p in (os.path.join(authtime.RUN_DIR, "authtime.json"),) if os.path.lexists(p)]
    present += [authtime.RUN_DIR + " (not empty)"] if os.path.isdir(authtime.RUN_DIR) and os.listdir(authtime.RUN_DIR) else []
    if present:
        print("three-node-wan: refused: %s exists: another run's leftovers, or this host's own, are here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-wan: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work)
    try:
        scenario(cluster)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in list(cluster.nodes):
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
        print("----- heartbeat events\n%s" % cluster.beat_events(list(cluster.nodes), last=8))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-wan: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
