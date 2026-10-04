#!/usr/bin/env python3
"""#70 (Phase 10), PR 2: every directed peer recovery path, and the nodes that must NOT be restored, on three
nodes (e2e/lib/threenode.py: each its real services in its own namespace, against its own TPM).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-recovery.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

The observables (#70's design): U, the node's volume opened with key material from a named peer's
contribution (that peer's keyslot), its filesystem read back, no key typed; L, a runtime lease issued by
that peer, held by the node's own regalia-admission; N, for a node that must not be restored: no key, no lease.

  1  three disks, LUKS2 on loop devices, each with one path from each other node (the contributions minted
     by the peers' real stores, the local half sealed to the node's TPM); every node starts and is leased
  2  PoC 10.1, all six directed relationships: X and the third node power-cycled, X restored by P alone
     (U through P's keyslot; L from P); the third node back
  3  PoC 10.2-10.4: for each survivor, the two others power-cycled and both unlocked through the survivor
     before either starts (the survivor the only source); both then hold leases the survivor issued
  4  PoC 10.5: two returners ask one survivor at the same time: both get their key from it
  5  N: a QUARANTINED (by the revocation key), then RETIRED (by the root), then b REVOKED_STOLEN: each,
     power-cycled, gets no key from any peer and no lease
"""
import itertools
import os
import pathlib
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402

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


def leased_by(cluster, peer, subject, since):
    """Whether `peer`'s sync issued `subject` a lease (its trail) at or after `since`."""
    return any(e.get("event") == "sync-lease" and e.get("subject") == subject and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
               for e in cluster.trail(peer))


def scenario(cluster):
    names = list(cluster.nodes)

    header("1  three enrolled disks; every node starts and is leased")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        held = until(lambda: cluster.lease(name), 120, 2)
        ok(bool(held), "%s holds a runtime lease (epoch %s)" % (name, (held or {}).get("epoch")), cluster.journal(name, "admission")[-600:])

    header("2  PoC 10.1: every directed relationship, X restored by P alone")
    for target, peer in itertools.permutations(names, 2):
        third = next(n for n in names if n not in (target, peer))
        cluster.stop(target)
        cluster.stop(third)
        since = time.time()
        got = cluster.unlock(target)
        ok(got["rc"] == 0 and got["peer"] == peer and got["marker"],
           "U: %s, with only %s up, opened its volume through %s's keyslot and read it back" % (target, peer, peer), got)
        cluster.start(target, SERVICES)
        leased = until(lambda: cluster.lease(target) and leased_by(cluster, peer, target, since), 120, 2)
        ok(bool(leased), "L: %s holds a lease %s issued" % (target, peer), cluster.journal(target, "admission")[-600:])
        cluster.start(third, SERVICES)
        until(lambda: cluster.lease(third), 120, 2)

    header("3  PoC 10.2-10.4: two nodes down, the survivor restores both")
    for survivor in names:
        down = [n for n in names if n != survivor]
        for name in down:
            cluster.stop(name)
        since = time.time()
        for name in down:                              # both unlocked before either starts: the survivor is the only source
            got = cluster.unlock(name)
            ok(got["rc"] == 0 and got["peer"] == survivor and got["marker"],
               "U: %s, with only %s up, opened its volume through %s's keyslot" % (name, survivor, survivor), got)
        for name in down:
            cluster.start(name, SERVICES)
        for name in down:
            leased = until(lambda: cluster.lease(name) and leased_by(cluster, survivor, name, since), 120, 2)
            ok(bool(leased), "L: %s holds a lease %s issued" % (name, survivor), cluster.journal(name, "admission")[-600:])

    header("4  PoC 10.5: two recovery requests to one survivor at once")
    survivor, down = names[0], names[1:]
    for name in down:
        cluster.stop(name)
    results = {}
    workers = [threading.Thread(target=lambda name=name: results.__setitem__(name, cluster.unlock(name))) for name in down]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    for name in down:
        got = results.get(name, {"rc": None, "peer": None, "marker": False})
        ok(got["rc"] == 0 and got["peer"] == survivor and got["marker"],
           "U: %s, asking %s at the same time as %s, opened its volume through %s's keyslot"
           % (name, survivor, next(o for o in down if o != name), survivor), got)
    for name in down:
        cluster.start(name, SERVICES)
    for name in down:
        until(lambda: cluster.lease(name), 120, 2)

    header("5  N: a quarantined, then retired; b reported stolen: no key, no lease")
    for victim, signer, state in (("a", "revocation", "QUARANTINED"), ("a", "root", "RETIRED"), ("b", "revocation", "REVOKED_STOLEN")):
        manifest = cluster.advance(signer=signer, **{victim: state})
        survivors = [n for n in names if n != victim and next(m for m in manifest["nodes"] if m["node_id"] == n)["state"] == "ACTIVE"]
        for name in survivors:                                   # the survivors run under the new epoch
            until(lambda: cluster.node(name).manifest()["epoch"] == manifest["epoch"], 60, 2)
        cluster.stop(victim)
        got = cluster.unlock(victim, timeout=120, rounds=2)
        ok(got["rc"] != 0 and got["peer"] is None, "N: %s, %s at epoch %d, gets no key from %s"
           % (victim, state, manifest["epoch"], ", ".join(survivors)), got)
        since = time.time()
        cluster.start(victim, ("sync", "wg-apply", "admission"))
        time.sleep(30)
        ok(not cluster.lease(victim) and not any(leased_by(cluster, s, victim, since) for s in survivors),
           "N: and no lease (none issued to it by %s)" % ", ".join(survivors), cluster.journal(victim, "admission")[-400:])


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-recovery: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("three-node-recovery: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-recovery: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work)
    try:
        scenario(cluster)
    except Exception as failure:          # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in cluster.nodes:
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-recovery: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
