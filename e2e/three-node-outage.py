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
  4  the authority revokes c (REVOKED_STOLEN): its published chain changes, and its own wg-apply (the path unit's
     trigger) drops c from its tunnel, as the nodes' do
  5  its time no longer authenticated: the authority signs no heartbeat, and its trail says why (fail closed)
"""
import json
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


def recent(cluster, name, kinds=("sync-heartbeat", "sync-pull", "sync-apply", "authority-heartbeat", "authority-publish"), n=6):
    """The member's last trail events of these kinds: why a heartbeat did not come."""
    return [{k: e.get(k) for k in ("event", "peer", "subject", "outcome", "reason", "epoch", "sequence") if e.get(k) not in (None, "")}
            for e in cluster.trail(name) if e.get("event") in kinds][-n:]


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
           {"node": recent(cluster, name), "authority": recent(cluster, AUTH), "authority peers": sorted(cluster.wg_peers(AUTH, "wg-svc")),
            "node peers": sorted(cluster.wg_peers(name, "wg-svc"))})
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
           "%s took a fresh heartbeat from the authority, back after its own outage" % first,
           {"node": recent(cluster, first), "authority": recent(cluster, AUTH)})
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

    header("4  a revocation leaves the authority's own tunnel too")
    before = cluster.wg_peers(AUTH, "wg-svc")
    keys = {name: cluster.keys[name]["service"][1] for name in names}
    said = cluster.revoke("c", "REVOKED_STOLEN", "e2e: the authority's tunnel follows the chain").stdout
    ok(until(lambda: cluster.wg_peers(AUTH, "wg-svc") == {keys["a"], keys["b"]}, 60, 2) is True and keys["c"] in before,
       "after `authority revoke` (epoch 2 published), its wg-apply path dropped c from wg-svc; a and b remain",
       {"before": sorted(before), "after": sorted(cluster.wg_peers(AUTH, "wg-svc")), "said": said[-300:]})

    header("5  without authenticated time the authority signs nothing")
    cluster.time[AUTH] = False                       # chrony stops vouching (the stand-in's switch)
    until(lambda: not json.loads((cluster.auth.run / "authtime.json").read_text())["authenticated"], 30, 1)
    since = time.time()
    # serve tries a beat at its start and then every interval_s (600 s): restarted, it tries now, as after a reboot
    sh("systemctl", "restart", cluster.unit(AUTH, "serve"))
    refused = until(lambda: any(e.get("event") == "authority-heartbeat" and e.get("outcome") == "FAILED" and "time is not authenticated" in e.get("reason", "")
                                and e.get("at", 0) >= since for e in cluster.trail(AUTH)), 180, 3)
    signed = [e for e in cluster.trail(AUTH) if e.get("event") == "authority-heartbeat" and e.get("outcome") not in ("FAILED", None) and e.get("at", 0) >= since]
    ok(refused is True and not signed, "time no longer authenticated: the authority signs no heartbeat, and records why (fail closed)",
       recent(cluster, AUTH))


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
        print("----- authority serve\n%s\n----- authority trail\n%s" % (cluster.journal(AUTH, "serve"), recent(cluster, AUTH, n=15)))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-outage: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
