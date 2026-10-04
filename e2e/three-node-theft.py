#!/usr/bin/env python3
"""#69 (Phase 9): a stolen node revoked, the revocation spreading, and the window a partition leaves, on three nodes
and the revocation authority (e2e/lib/threenode.py with authority=True: each node its real services in its own
namespace against its own TPM, the authority its real `serve`; revocations by `authority revoke`, epochs reaching
the nodes only by sync).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-theft.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units; an nftables table
inside one node's namespace, never the host's), so it runs only on a GitHub-hosted runner, or on a throwaway host
whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

  1  three nodes and the authority, every node leased
  2  c partitioned from b and the authority (its service mesh only; the boot mesh stays up); the window it is left
     with measured: the remaining life of the heartbeat it holds, beside that heartbeat's lifetime
  3  a powered off (stolen); `authority revoke a REVOKED_STOLEN`; b takes the new epoch by sync (timed from the
     revoke command); c, cut off, tries (its pulls do not answer) and does not
  4  9.4, THE WINDOW, shown and not hidden: the stolen a boots with its genuine TPM, keys and paths; b refuses it
     (b's unlock tunnel no longer admits it), and the stale c gives it its key: a partitioned node trusts a stolen
     one until its heartbeat expires or the new epoch reaches it (the bound is heartbeat_max_lifetime_s: 6 h in
     production, decided on #69)
  5  the partition healed: c takes the epoch (timed) and drops a from its unlock tunnel; a, power-cycled, gets no key
     from anyone (9.1), and no lease (off every service tunnel)
  6  9.2: a, whose own chain is still the old ACTIVE one, through a service tunnel forced open by hand on b: b's sync
     refuses it by name, and b's store stays at the current epoch
  7  9.3: b power-cycled with only a (revoked) and nobody else up: b's chain is current, its boot configuration does
     not list a, and it gets no key (it never asks a); with c back, b opens through c
  8  #340, audit completeness: the real trail shippers and collector ran throughout (Cluster(audit=True)); every node's
     sync and admission trail is in the collector line for line, chained, each DENY a deny, and the scenario's own
     security events are there by name, for the node that recorded them

Not here: the expiry itself (a heartbeat lifetime is at least 40 minutes: freshness's unit tests show the refusal at
expiry, and step 2 measures the window); a stale b asking a (the same window as 4, stated on #69); the physical
rehearsal.
"""
import base64
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import AUTH, sh, until                # noqa: E402
from deploy.baremetal import authtime                # noqa: E402

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


def as_wg(key):
    return base64.b64encode(bytes.fromhex(key)).decode()          # wg prints base64; the manifest holds hex


def took_epoch(cluster, name, epoch):
    return cluster.node(name).store().load()["epoch"] == epoch


def scenario(cluster):
    names = ["a", "b", "c"]

    header("1  three nodes and the authority, every node leased")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    cluster.start(AUTH)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 150, 3)), "%s holds a lease" % name, cluster.journal(name, "admission")[-400:])

    header("2  c partitioned from b and the authority; the window it is left with")
    cluster.partition("c", ["b", AUTH])
    cut_at = time.time()
    left = cluster.heartbeat_left("c")
    held = cluster.node("c").freshness().held()
    import calendar
    stamp = lambda text: calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ"))         # noqa: E731
    life = stamp(held["heartbeat"]["expires_at"]) - stamp(held["heartbeat"]["issued_at"]) if held else None
    ok(left is not None and life is not None and 0 < left <= life,
       "c holds a heartbeat with %.0f s left of its %.0f s at the cut: the longest a stale c can trust a stolen node" % (left or 0, life or 0), held)
    print("  MEASURED: c's heartbeat window at the cut: %.0f s (%.1f h), of a heartbeat lifetime of %.0f s. FIXTURE manifest: schema v1, "
          "which has no heartbeat_max_lifetime_s (its bound is 24 h); PRODUCTION: v2/v3 with 21600 s, so at most 6 h (#69)"
          % (left or 0, (left or 0) / 3600, life or 0))

    header("3  a stolen: powered off and revoked; b takes the epoch, c does not")
    cluster.stop("a")
    revoked_at = time.time()
    cluster.revoke("a", "REVOKED_STOLEN", "e2e: a stolen node")
    took = until(lambda: took_epoch(cluster, "b", 2), 120, 1)
    b_after = time.time() - revoked_at
    ok(took is True, "b took epoch 2 (a REVOKED_STOLEN) from the authority by sync, %.0f s after the revocation" % b_after)
    print("  MEASURED: dissemination to b: %.0f s" % b_after)
    tried = until(lambda: [e.get("reason") for e in cluster.trail("c") if e.get("event") == "sync-apply" and e.get("outcome") == "DENY"
                           and e.get("peer") in ("b", "@authority") and "did not answer" in e.get("reason", "") and e.get("at", 0) >= cut_at], 90, 3)
    ok(bool(tried) and took_epoch(cluster, "c", 1),
       "c, cut off, tried (its pulls from b and the authority did not answer) and still holds epoch 1", tried)

    header("4  9.4, the window: the stolen a boots; b refuses it, the stale c gives it its key")
    boot_a = as_wg(cluster.keys["a"]["boot"][1])
    ok(until(lambda: boot_a not in cluster.wg_peers("b", "wg-unlock"), 60, 2) is True and boot_a in cluster.wg_peers("c", "wg-unlock"),
       "b's unlock tunnel has dropped a; c's, on the old epoch, still admits it",
       {"b": sorted(cluster.wg_peers("b", "wg-unlock")), "c": sorted(cluster.wg_peers("c", "wg-unlock"))})
    got = cluster.unlock("a", timeout=150, rounds=3)
    ok(got["rc"] == 0 and got["peer"] == "c", "WINDOW: within c's heartbeat, the stale c unlocked the stolen a (the exposure #69 bounds)", got)
    print("  OBSERVED: a partitioned node trusts a stolen one until its heartbeat expires or the epoch reaches it")

    header("5  the partition healed: c converges; a gets nothing from anyone (9.1)")
    cluster.stop("a")
    healed_at = time.time()
    cluster.heal("c")
    took = until(lambda: took_epoch(cluster, "c", 2), 180, 1)
    c_after = time.time() - healed_at
    ok(took is True, "c took epoch 2 %.0f s after the partition healed" % c_after)
    print("  MEASURED: convergence of c after the heal: %.0f s" % c_after)
    ok(until(lambda: all(boot_a not in cluster.wg_peers(p, "wg-unlock") for p in ("b", "c")), 60, 2) is True,
       "no peer's unlock tunnel admits a any more", {p: sorted(cluster.wg_peers(p, "wg-unlock")) for p in ("b", "c")})
    got = cluster.unlock("a", timeout=150, rounds=2)
    ok(got["rc"] != 0 and got["peer"] is None, "N: a, with its genuine TPM, keys and paths, gets no key from anyone (9.1)", got)
    service_a = as_wg(cluster.keys["a"]["service"][1])
    since = time.time()
    cluster.start("a", SERVICES)
    off = until(lambda: all(service_a not in cluster.wg_peers(p, "wg-svc") for p in ("b", "c")), 60, 2)
    admission = cluster.nodes["a"].run / "admission" / "admission.json"
    import json

    def asked_and_refused():                         # a's own admission tried, and holds no lease (its reason says why)
        try:
            doc = json.loads(admission.read_text())
        except (OSError, ValueError):
            return None
        return doc if doc.get("reason") and not doc.get("serve_until_boottime_ms") else None
    tried = until(asked_and_refused, 120, 3)
    ok(off is True and bool(tried) and not any(e.get("event") == "sync-lease" and e.get("subject") == "a" and e.get("outcome") == "ALLOW"
                                               and e.get("at", 0) >= since for p in ("b", "c") for e in cluster.trail(p)),
       "N: and no lease: a's admission asked and was refused (%s); a is off every service tunnel, and nobody issued it one"
       % ((tried or {}).get("reason", "")[:80]), tried)

    header("6  9.2: a's old ACTIVE chain, through a tunnel forced open on b, moves nothing")
    since = time.time()
    a_address = threenode.wgsvc.address(cluster.keys["a"]["service"][1])
    cluster.nodes["b"].in_ns("wg", "set", "wg-svc", "peer", service_a, "allowed-ips", a_address + "/128",
                             "endpoint", "%s:51821" % cluster.nodes["a"].underlay)
    named = until(lambda: [e.get("reason") for e in cluster.trail("b") if e.get("event", "").startswith("sync") and e.get("outcome") == "DENY"
                           and "a is REVOKED_STOLEN under epoch 2" in e.get("reason", "") and e.get("at", 0) >= since], 120, 3)
    ok(bool(named), "b's sync refuses a's requests by name: a is REVOKED_STOLEN under epoch 2", named)
    ok(took_epoch(cluster, "b", 2) and took_epoch(cluster, "a", 1), "b's store stays at epoch 2; a's own stays at the old epoch 1")

    header("7  9.3: b's chain is current: it never asks the revoked a")
    cluster.stop("c")
    cluster.stop("b")
    got = cluster.unlock("b", timeout=150, rounds=2)
    asked_a = "a (path" in got.get("stderr", "")
    import json
    peers = [p.get("node_id") for p in json.loads((cluster.nodes["b"].dir / "unlock.json").read_text()).get("peers", [])]
    ok(got["rc"] != 0 and got["peer"] is None and not asked_a and "a" not in peers and peers,
       "N: b, with only the revoked a up, gets no key; its boot configuration names %s, not a, and its client never asked a" % peers, got)
    cluster.start("c", SERVICES)
    got = cluster.unlock("b")
    ok(got["rc"] == 0 and got["peer"] == "c" and got["marker"], "control: with c back, b opens its volume through c's keyslot", got)

    header("8  #340: every event the scenario caused is in the audit collector's chained stream, for the node that recorded it")
    wrong = cluster.audit_complete()
    ok(wrong == {}, "every node trail (sync, admission) is in the collector line for line, in order, its chain unbroken, each DENY a deny",
       {"%s.%s" % k: v for k, v in wrong.items()})
    named = cluster.audit_has("b", "sync", outcome="DENY", reason=lambda r: bool(r) and "a is REVOKED_STOLEN under epoch 2" in r)
    ok(bool(named), "b's refusal of the stolen a by name (9.2) is in b's stream", len(named))
    cut = cluster.audit_has("c", "sync", event="sync-apply", outcome="DENY", reason=lambda r: bool(r) and "did not answer" in r)
    ok(bool(cut), "c's pulls that did not answer while it was cut off are in c's stream (%d)" % len(cut))
    for name in ("b", "c"):
        took = cluster.audit_has(name, "sync", event="sync-apply", outcome="ALLOW", epoch=lambda e: e == 2)
        ok(bool(took), "%s taking the revocation (epoch 2) is in %s's stream" % (name, name))
    # the admission trail (#347): every node's own record of serving, and the stolen a's of not serving
    serving = {name: bool(cluster.audit_has(name, "admission", event="admission-serving", outcome="ALLOW")) for name in names}
    ok(all(serving.values()), "each node's change to serving is in its own admission stream", serving)
    refused = cluster.audit_has("a", "admission", event="admission-serving", outcome="DENY")
    ok(bool(refused), "the stolen a's own trail says it is not serving, and why (%s)" % ((refused or [{}])[-1].get("reason", "")[:80]),
       cluster.audit_stream("a", "admission")[-3:])


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-theft: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES + (AUTH,)) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    present += [p for p in (os.path.join(authtime.RUN_DIR, "authtime.json"),) if os.path.lexists(p)]
    present += [authtime.RUN_DIR + " (not empty)"] if os.path.isdir(authtime.RUN_DIR) and os.listdir(authtime.RUN_DIR) else []
    if present:
        print("three-node-theft: refused: %s exists: another run's leftovers, or this host's own, are here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK) or not all(
            os.access(os.path.join(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"), b), os.X_OK) for b in ("regalia-audit-ship", "regalia-audit-collector")):
        print("three-node-theft: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock and REGALIA_AUDIT_BIN a directory "
              "with the built regalia-audit-ship and regalia-audit-collector (#340)")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work, authority=True, audit=True)
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
        print("\nthree-node-theft: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
