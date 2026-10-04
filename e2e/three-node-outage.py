#!/usr/bin/env python3
"""#71 (Phase 11): a total outage, restored by one manual recovery, on three nodes (e2e/lib/threenode.py, v4 since #199:
each node its real services in its own namespace against its own TPM, the nodes signing their own heartbeats; no
authority host; the owner's keys on a SoftHSM token, signed through the real owner.py halves).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-outage.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

The recovery runbook it holds to (threat model A3; no key ceremony for a routine outage): one node by hand with its
recovery key; at its console the operator co-signs its heartbeat with an owner key (owner.py beat, at most 1 h);
then the other two by themselves, through that node; then the nodes sign their own heartbeats again.

  1  three nodes: every node holds a heartbeat the nodes signed (from bootstrap) and is leased
  2  PoC 11.1, the total outage: the three nodes powered off; no node gets a key from anyone
  3  PoC 11.2-11.4: for each first node X: X's volume opened by hand with its recovery key (keyslot of no peer);
     X up, the hand recovery: X and an owner key (either of the two) sign X's heartbeat, living at most 1 h; the other
     two open their volumes through X's keyslot, unattended; all three leased; (once) the nodes then sign their own
     heartbeats again, with no owner. Then the total outage again.
  4  a and b revoke c (REVOKED_STOLEN), each at its own console (revoke.py): their wg-apply drops c from wg-svc
  5  a's time no longer authenticated (its authtime.json says so): a signs no heartbeat, and its trail says why
     (fail closed)
"""
import base64
import json
import os
import pathlib
import sys
import tempfile
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


def recent(cluster, name, n=8):
    """The node's last heartbeat events (beat-propose, the beat-sign answers it gave, owner-beat): why it holds none."""
    return cluster.beat_events([name], last=n)[name]


def outage(cluster, names):
    """Everything powered off."""
    for name in names:
        cluster.stop(name)


def scenario(cluster):
    names = list(cluster.nodes)

    header("1  three nodes: the heartbeats the nodes sign themselves, and leases")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    fresh = cluster.fresh(names, timeout=240)
    for name in names:
        ok(fresh[name], "%s holds a heartbeat the nodes signed (from bootstrap, no authority)" % name, recent(cluster, name))
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 120, 2)), "%s holds a lease" % name, cluster.journal(name, "admission")[-600:])

    header("2  PoC 11.1: the total outage: nobody gives a key")
    outage(cluster, names)
    for name in names:
        got = cluster.unlock(name, timeout=120, rounds=2)
        ok(got["rc"] != 0 and got["peer"] is None, "N: %s, everything down, gets no key" % name, got)

    header("3  PoC 11.2-11.4: one node by hand, the owner's hand recovery, the other two through it")
    for first in names:
        others = [n for n in names if n != first]
        got = cluster.recover(first)
        ok(got["rc"] == 0 and got["peer"] is None and got["marker"],
           "manual: %s's volume opened by hand with its recovery key (keyslot %s, no peer's) and read back" % (first, got["slot"]), got)
        cluster.start(first, SERVICES)
        # #199's hand recovery (owner.py beat): alone, the node can sign no heartbeat with a peer, so the operator at its
        # console co-signs one with an owner key. It lives at most owner_heartbeat_lifetime_s (1 h)
        envelope = cluster.owner_beat(first, which=names.index(first) % 2)      # either owner key will do (ADR-0002 D30)
        body = envelope["heartbeat"]
        lives = threenode.heartbeat.parse_time(body["expires_at"], "e") - threenode.heartbeat.parse_time(body["issued_at"], "i")
        ok(cluster.heartbeat_signers(first) == [first, "owner"] and lives <= 3600,
           "hand recovery: %s holds a heartbeat it and an owner key signed (sequence %d, living %d s, at most 1 h)" % (first, body["sequence"], lives),
           recent(cluster, first))
        for name in others:
            got = cluster.unlock(name)
            ok(got["rc"] == 0 and got["peer"] == first and got["marker"],
               "U: %s, unattended, opened its volume through %s's keyslot" % (name, first), got)
        for name in others:
            cluster.start(name, SERVICES)
        for name in [first] + others:
            ok(bool(until(lambda: cluster.lease(name), 150, 3)), "L: %s holds a lease (from %s)" % (name, cluster.lease_issuer(name)),
               cluster.journal(name, "admission")[-600:])
        if first == names[-1]:
            # the next beat is the nodes' own again (6 h), with no owner, once the owner's is due for renewal (its issue
            # plus beat_interval_s): the emergency credential is not needed any more. Once, not for every first node
            back = cluster.fresh(names, timeout=900)
            ok(all(back.values()), "the nodes sign their own heartbeats again, with no owner (%s)" % back, {n: recent(cluster, n) for n in names})
        outage(cluster, names)

    header("4  two nodes revoke the third; their service tunnels drop it")
    for name in names:
        cluster.start(name, SERVICES)
    cluster.fresh(names, timeout=300)
    keys = {name: base64.b64encode(bytes.fromhex(cluster.keys[name]["service"][1])).decode() for name in names}
    before = {n: cluster.wg_peers(n, "wg-svc") for n in ("a", "b")}
    cluster.revoke_by_nodes("a", "b", "c", "REVOKED_STOLEN", "e2e: two nodes revoke the third")
    ok(until(lambda: all(keys["c"] not in cluster.wg_peers(n, "wg-svc") for n in ("a", "b")), 60, 2) is True
       and all(keys["c"] in before[n] for n in ("a", "b")),
       "after a and b signed epoch 2 (c REVOKED_STOLEN, revoke.py at each console), their wg-apply dropped c from wg-svc",
       {n: sorted(cluster.wg_peers(n, "wg-svc")) for n in ("a", "b")})

    header("5  without authenticated time a node signs nothing")
    cluster.time["a"] = False                        # chrony stops vouching (the stand-in's switch)
    ok(until(lambda: not json.loads((cluster.nodes["a"].run / "authtime.json").read_text())["authenticated"], 30, 1) is True,
       "a's authtime.json says not authenticated")
    since = time.time()
    refused = until(lambda: any(e.get("event") == "beat-propose" and e.get("outcome") == "DENY" and "time is not authenticated" in e.get("reason", "")
                                and e.get("at", 0) >= since for e in cluster.trail("a")), 180, 3)
    signed = [e for e in cluster.trail("a") if e.get("event") == "beat-propose" and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since]
    ok(refused is True and not signed, "time no longer authenticated: a signs no heartbeat, and records why (fail closed)", recent(cluster, "a"))


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-outage: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("three-node-outage: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-outage: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
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
        print("\nthree-node-outage: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
