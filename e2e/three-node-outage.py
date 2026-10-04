#!/usr/bin/env python3
"""#71 (Phase 11): a total outage, restored by one manual recovery, on three nodes and the revocation authority
(e2e/lib/threenode.py with authority=True: each node its real services in its own namespace against its own
TPM; the authority its real `serve`, on its own namespace and TPM, signing the heartbeats).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-outage.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

The recovery runbook it holds to (threat model A3; no key ceremony for a routine outage): the authority's host
first (it recovers by itself: its own anchored store, its TPM's heartbeat counter, its key), then one node by
hand with its recovery key, then the other two by themselves, through that node.

  1  three nodes and the authority: every node takes the authority's heartbeat (its trail names it) and is leased
  2  PoC 11.1, the total outage: the three nodes and the authority powered off; no node gets a key from anyone.
     The authority back first: still none (without an ACTIVE peer, the cluster stays encrypted)
  3  PoC 11.2-11.4: for each first node X: X's volume opened by hand with its recovery key (keyslot of no peer);
     X up, it takes a fresh heartbeat from the authority (a new boot of the authority's: its sequence goes on from
     its TPM counter); the other two open their volumes through X's keyslot, unattended; all three leased. Then
     the total outage again, the authority first.
"""
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import AUTH, sh, until                # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")


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


def took_heartbeat(cluster, name, since):
    """Whether the node's sync accepted a heartbeat from the authority at or after `since` (its trail)."""
    return any(e.get("event") == "sync-heartbeat" and e.get("peer") == "@authority" and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
               for e in cluster.trail(name))


def outage(cluster, names):
    """Everything powered off, the authority too; then the authority's host first, as the runbook says."""
    for name in names + [AUTH]:
        cluster.stop(name)


def scenario(cluster):
    names = list(cluster.nodes)

    header("1  three nodes and the authority: the authority's heartbeats, and leases")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    cluster.start(AUTH)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(until(lambda: took_heartbeat(cluster, name, 0), 120, 2) is True, "%s took a heartbeat from the authority" % name,
           cluster.journal(name, "sync")[-600:] + cluster.journal(AUTH, "serve")[-600:])
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 120, 2)), "%s holds a lease" % name, cluster.journal(name, "admission")[-600:])

    header("2  PoC 11.1: the total outage: nobody gives a key")
    outage(cluster, names)
    for name in names:
        got = cluster.unlock(name, timeout=120, rounds=2)
        ok(got["rc"] != 0 and got["peer"] is None, "N: %s, everything down, gets no key" % name, got)
    cluster.start(AUTH)
    got = cluster.unlock(names[0], timeout=120, rounds=2)
    ok(got["rc"] != 0 and got["peer"] is None, "N: the authority back, still no node up: %s gets no key (stays encrypted)" % names[0], got)

    header("3  PoC 11.2-11.4: one node by hand, the other two through it")
    for first in names:
        others = [n for n in names if n != first]
        got = cluster.recover(first)
        ok(got["rc"] == 0 and got["peer"] is None and got["marker"],
           "manual: %s's volume opened by hand with its recovery key (keyslot %s, no peer's) and read back" % (first, got["slot"]), got)
        since = time.time()
        cluster.start(first, SERVICES)
        ok(until(lambda: took_heartbeat(cluster, first, since), 120, 2) is True,
           "%s took a fresh heartbeat from the authority, back after its own outage" % first, cluster.journal(first, "sync")[-600:])
        for name in others:
            got = cluster.unlock(name)
            ok(got["rc"] == 0 and got["peer"] == first and got["marker"],
               "U: %s, unattended, opened its volume through %s's keyslot" % (name, first), got)
        for name in others:
            cluster.start(name, SERVICES)
        for name in [first] + others:
            ok(bool(until(lambda: cluster.lease(name), 150, 3)), "L: %s holds a lease (from %s)" % (name, cluster.lease_issuer(name)),
               cluster.journal(name, "admission")[-600:])
        outage(cluster, names)
        cluster.start(AUTH)


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-outage: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES + (AUTH,)) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("three-node-outage: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-outage: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work, authority=True)
    try:
        scenario(cluster)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in list(cluster.nodes):
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
        print("----- authority serve\n%s" % cluster.journal(AUTH, "serve"))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-outage: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
