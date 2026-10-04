#!/usr/bin/env python3
"""Three KMS nodes on one machine, each its real services in its own namespace, against its own TPM (#70,
PR 1: the fixture's smoke test; e2e/lib/threenode.py is the fixture).

    sudo --preserve-env=RUNNER_ENVIRONMENT python3 -Es e2e/three-node-netns.py

IT CHANGES THE MACHINE (namespaces, interfaces, transient units), so it runs only on a GitHub-hosted runner
(RUNNER_ENVIRONMENT=github-hosted), or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

  1  three nodes built: a software TPM each, an EK and AK each, one chain naming all three, committed under
     each node's own TPM anchor
  2  each node's regalia-sync and regalia-wg-apply, as transient units in its namespace: the chain published,
     wg-svc and wg-unlock up with the two other nodes as peers
  3  the service mesh: every node reaches both others' service addresses (WireGuard on the underlay)
  4  every node pulls from both others: each node's trail names both as callers it answered
  5  a power cut on a: b and c go on pulling from each other; a started again rejoins: both answer it again
"""
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402

passed, failed = 0, 0


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


def answered(cluster, server, caller, since=0.0):
    """Whether `server`'s sync answered a pull from `caller` (ALLOW) at or after `since` (unix seconds)."""
    return any(e.get("event") == "sync-pull" and e.get("subject") == caller and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
               for e in cluster.trail(server))


def scenario(cluster):
    from deploy.baremetal import node, wgsvc
    names = list(cluster.nodes)

    header("1  three nodes: a TPM, an EK and AK each, one chain naming all three under each node's own anchor")
    cluster.build()
    for name in names:
        held = cluster.node(name).store().load()
        ok(held["epoch"] == 1 and sorted(m["node_id"] for m in held["nodes"]) == names,
           "%s's store holds epoch 1 naming %s, under its own TPM's anchor" % (name, ", ".join(names)))

    header("2  each node's sync and wg-apply, transient units in its namespace")
    for name in names:
        cluster.start(name)
    for name in names:
        n = cluster.nodes[name]
        published = until(lambda: (n.state / node.PUBLISHED).exists() and cluster.node(name).manifest()["epoch"] == 1, 30, 1)
        ok(published is True, "%s's sync published epoch 1, verified against its anchor" % name, cluster.journal(name, "sync")[-600:])
        peers = n.in_ns("wg", "show", "wg-svc", "peers", check=False).stdout.split()
        ok(len(peers) == 2 and n.in_ns("ip", "link", "show", "wg-unlock", check=False).returncode == 0,
           "%s's wg-apply: wg-svc with the two others as peers, and wg-unlock up" % name, cluster.journal(name, "wg-apply")[-600:])

    header("3  the service mesh: every node reaches both others")
    address = {name: wgsvc.address(cluster.keys[name]["service"][1]) for name in names}
    for name in names:
        for other in names:
            if other == name:
                continue
            reached = until(lambda: cluster.nodes[name].in_ns("ping", "-6", "-c", "1", "-W", "2", address[other], check=False).returncode == 0, 30, 1)
            ok(reached is True, "%s reaches %s's service address over wg-svc" % (name, other))

    header("4  every node pulls from both others")
    for server in names:
        for caller in names:
            if caller != server:
                pulled = until(lambda: answered(cluster, server, caller), 60, 2)
                ok(pulled is True, "%s answered %s's pull (its trail names %s as the caller)" % (server, caller, caller),
                   cluster.journal(caller, "sync")[-500:])

    header("5  a power cut on a: b and c go on; a started again rejoins")
    cluster.stop("a")
    cut = time.time()
    ok(until(lambda: answered(cluster, "b", "c", cut) and answered(cluster, "c", "b", cut), 60, 2) is True,
       "with a down, b and c still pull from each other")
    ok(not answered(cluster, "b", "a", cut + 1) and not answered(cluster, "c", "a", cut + 1), "and nobody answered a while it was down")
    back = time.time()
    cluster.start("a")
    ok(until(lambda: answered(cluster, "b", "a", back) and answered(cluster, "c", "a", back), 90, 2) is True,
       "a started again: b and c answer its pulls", cluster.journal("a", "sync")[-600:])


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-netns: refused: this changes the machine (namespaces, interfaces, transient units). It runs on a "
              "GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    if present:
        print("three-node-netns: refused: %s exists: another run's namespaces are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0:
        print("three-node-netns: run as root")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work)
    try:
        scenario(cluster)
    except Exception as failure:          # noqa: BLE001 - a fixture that failed to build is a failure, said once
        ok(False, "the scenario ran to its end", repr(failure))
        for name in cluster.nodes:
            print("----- %s sync\n%s" % (name, cluster.journal(name, "sync")))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-netns: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
