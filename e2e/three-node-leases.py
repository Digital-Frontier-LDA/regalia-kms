#!/usr/bin/env python3
"""#74 (Phase 14), tier N: runtime leases on three nodes (e2e/lib/threenode.py, v4 since #199: the nodes sign their own
heartbeats; no authority host): the real regalia-admission asking the real peers' sync, leases of at most 300 s
(lease.MAX_LIFETIME) renewed at a third of their life, and a running node revoked by two nodes (revoke.py).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-leases.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units; an nftables table
inside one node's namespace, never the host's), so it runs only on a GitHub-hosted runner, or on a throwaway host
whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

  1  three nodes, every node leased
  2  14.1: a's lease is renewed: a newer lease in its admission state, its issuer's sync-lease ALLOW in its trail
  3  14.2: a's issuer crashes; a's next renewal comes from the other peer, and a never stops serving meanwhile
  4  renewals go on, on the heartbeats the nodes sign themselves
  5  a cut off from one peer (its service mesh): it renews through the other
  6  14.3: running a revoked by b and c, each at its own console (revoke.py); both peers refuse its renewals (it is off their service tunnels; by name through a
     tunnel forced open), and a's admission stops serving by itself when its lease ends (measured against 300 s)

The KMS daemon's own refusal at the lease's end and on revocation is e2e/runtime-admission.py's (two nodes, the
real daemon: steps 1, 3 and 6); the three-node daemon waits with 14.4. Clock skew is not here: the namespaces share
one kernel clock (authtime's and freshness's unit tests hold the skew and rollback refusals).
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
from threenode import AUTH, sh, until                # noqa: E402
from deploy.baremetal import admission, authtime, lease   # noqa: E402

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


def held(cluster, name):
    """(lease_issued_at, issuer, serving) of the node's admission now."""
    path = cluster.nodes[name].run / "admission" / "admission.json"
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return None, None, False
    return doc.get("lease_issued_at"), cluster.lease_issuer(name), bool(cluster.lease(name))


def renewed(cluster, name, after, by=None):
    """A lease issued after `after` (its issued_at string), by `by` if given, and serving."""
    issued, issuer, serving = held(cluster, name)
    return serving and issued and issued != after and issued > after and (by is None or issuer == by) and (issued, issuer)


def lease_expiry(cluster, name):
    """The expiry (unix seconds) of the lease the node's admission holds now, from its lease state, or None."""
    import calendar
    try:
        state = json.loads((cluster.nodes[name].admission / "lease.json").read_text())
        return calendar.timegm(time.strptime(state["envelope"]["lease"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ"))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def scenario(cluster):
    names = ["a", "b", "c"]
    # the holder asks again once a third of its lease's life is used (lease.Holder.due), so one renewal comes within a
    # third of MAX_LIFETIME; the slack covers a round that has to go to its second peer
    renewal = lease.MAX_LIFETIME / 3 + 30

    header("1  three nodes, every node leased")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 150, 3)), "%s holds a lease" % name, cluster.journal(name, "admission")[-400:])

    header("2  14.1: a's lease is renewed")
    first, issuer, _ = held(cluster, "a")
    since = time.time()
    got = until(lambda: renewed(cluster, "a", first), renewal + 60, 3)
    ok(bool(got) and any(e.get("event") == "sync-lease" and e.get("subject") == "a" and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
                         for e in cluster.trail(got[1] if got else issuer)),
       "a's lease is renewed (issued %s, then %s, by %s), and its issuer's trail holds the ALLOW" % (first, got and got[0], got and got[1]), got)

    header("3  14.2: a's issuer crashes; the other peer renews, and a never stops serving")
    current, issuer, _ = held(cluster, "a")
    other = next(n for n in ("b", "c") if n != issuer)
    cluster.stop(issuer, power=None)
    # one loop, the whole window that matters: from the issuer's crash until the other peer's lease is in, a sampled
    # every 2 s (regalia-kms-3e)
    gaps, got, end = [], None, time.time() + renewal + 90
    while time.time() < end and not got:
        if not cluster.lease("a"):
            gaps.append(round(time.time()))
        got = renewed(cluster, "a", current, by=other)
        time.sleep(2)
    ok(bool(got), "with %s down, a's next lease is %s's (%s)" % (issuer, other, got and got[0]), held(cluster, "a"))
    ok(not gaps, "and a served at every sample from %s's crash until %s's lease came" % (issuer, other), gaps)
    cluster.start(issuer, SERVICES)
    until(lambda: cluster.lease(issuer), 150, 3)

    header("4  #199, no authority: renewals go on on the heartbeats the nodes sign themselves")
    current, _, _ = held(cluster, "a")
    got = until(lambda: renewed(cluster, "a", current), renewal + 60, 3)
    fresh = cluster.fresh(names, timeout=60)
    ok(bool(got) and all(cluster.lease(n) for n in names) and all(fresh.values()),
       "a is renewed (%s) and every node serves, each holding a heartbeat the nodes signed (%s)" % (got and got[0], fresh),
       {n: held(cluster, n) for n in names})

    header("5  a cut off from b: it renews through c")
    cluster.partition("a", ["b"])
    # the holder starts each round at the next peer in turn (node.admission_service), so over two rounds a asks b
    # first at least once; both leases coming from c shows that ask failed and c answered (regalia-kms-3e)
    current, _, _ = held(cluster, "a")
    first = until(lambda: renewed(cluster, "a", current, by="c"), renewal + 90, 3)
    second = first and until(lambda: renewed(cluster, "a", first[0], by="c"), renewal + 90, 3)
    ok(bool(first) and bool(second), "a, cut off from b, renewed twice, both times by c (%s, %s): the round that began at b fell to c"
       % (first and first[0], second and second[0]), held(cluster, "a"))
    cluster.heal("a")

    header("6  14.3: running a revoked; nobody renews it, and it stops serving by itself")
    service_a = base64.b64encode(bytes.fromhex(cluster.keys["a"]["service"][1])).decode()
    revoked_at = time.time()
    # #199: by two nodes, each at its own console (revoke.py propose on b, cosign on c, which commits it)
    cluster.revoke_by_nodes("b", "c", "a", "REVOKED_STOLEN", "e2e: revoked while running")
    off = until(lambda: all(service_a not in cluster.wg_peers(p, "wg-svc") for p in ("b", "c")), 90, 2)
    ok(off is True, "b's and c's service tunnels drop a: its renewals cannot reach them")
    a_address = threenode.wgsvc.address(cluster.keys["a"]["service"][1])
    cluster.nodes["b"].in_ns("wg", "set", "wg-svc", "peer", service_a, "allowed-ips", a_address + "/128",
                             "endpoint", "%s:51821" % cluster.nodes["a"].underlay)
    named = until(lambda: [e.get("reason") for e in cluster.trail("b") if e.get("event", "").startswith("sync") and e.get("outcome") == "DENY"
                           and "a is REVOKED_STOLEN under epoch 2" in e.get("reason", "") and e.get("at", 0) >= revoked_at], 150, 3)
    ok(bool(named), "through a tunnel forced open on b, b's sync refuses a's requests by name", named)
    expiry = [lease_expiry(cluster, "a")]

    def stopped():                                    # the expiry of the last lease a held, read while it still served
        if cluster.lease("a"):
            expiry[0] = lease_expiry(cluster, "a") or expiry[0]
            return False
        return True
    done = until(stopped, lease.MAX_LIFETIME + admission.MARGIN + 60, 2)
    stop_at = time.time()
    took = stop_at - revoked_at
    due = (expiry[0] - admission.MARGIN) if expiry[0] else None
    ok(done is True and due is not None and expiry[0] - revoked_at <= lease.MAX_LIFETIME and abs(stop_at - due) <= 10,
       "a's admission stopped serving by itself %.0f s after the revocation: at its last lease's end less the %d s margin "
       "(expected %.0f s; that lease had at most %d s left)" % (took, admission.MARGIN, (due or 0) - revoked_at, lease.MAX_LIFETIME),
       {"stop_minus_due": round(stop_at - due, 1) if due else None, "held": held(cluster, "a")})
    print("  MEASURED: running a revoked -> it stops serving: %.0f s (its last lease's end less the margin; MAX_LIFETIME %d s)"
          % (took, lease.MAX_LIFETIME))
    ok(not any(e.get("event") == "sync-lease" and e.get("subject") == "a" and e.get("outcome") == "ALLOW" and e.get("at", 0) >= revoked_at
               for p in ("b", "c") for e in cluster.trail(p)), "and nobody issued a a lease after the revocation")


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-leases: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES + (AUTH,)) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    present += [p for p in (os.path.join(authtime.RUN_DIR, "authtime.json"),) if os.path.lexists(p)]
    present += [authtime.RUN_DIR + " (not empty)"] if os.path.isdir(authtime.RUN_DIR) and os.listdir(authtime.RUN_DIR) else []
    if present:
        print("three-node-leases: refused: %s exists: another run's leftovers, or this host's own, are here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-leases: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
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
        print("\nthree-node-leases: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
