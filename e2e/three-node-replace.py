#!/usr/bin/env python3
"""#76 (Phase 16): a node that failed for good is replaced, and its retired hardware is refused, on three nodes
(e2e/lib/threenode.py, v4 since #199: each node its real services in its own namespace against its own TPM, the nodes
signing their own heartbeats; no authority host).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/three-node-replace.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

What main models (deploy/baremetal/replacement.py), end to end: ONE root-signed manifest enrolls the new node c2
with new identities and keeps c as RETIRED, a tombstone whose identities are never enrolled again.

  1  three nodes, every node leased
  2  PoC 16.1-16.4: c fails for good; c2 (a new TPM, new WireGuard keys and signing key, a new HSM serial) replaces
     it in one root-signed manifest (measurements.check_replacement), given to a; b takes it from a by sync, and a
     and b sign its heartbeat. The same replacement signed by the owner (a revocation quorum), or reusing c's EK,
     is refused
  3  c2 enrolled through a and b (their real contribution stores and verifiers): with only a up it opens its
     volume through a's keyslot, then with only b up through b's; it holds a lease
  4  c2 provides bootstrap: b, with only c2 up, opens its volume through c2's keyslot
  5  PoC 16.5: old c powered back, with every credential it ever held (its disk, its sealed local half, its
     paths, its WireGuard keys): no peer's unlock tunnel admits it, it gets no key; off every service tunnel, no
     lease; and through a service tunnel forced open by hand, a's sync refuses it by name (RETIRED). Its TPM posing
     as c2 (refused on the EK and AK the manifest pins for c2) is NOT covered here: replacement.py's unit tests
     cover it (test_poc_16_5_the_old_hardware_is_refused_by_every_decision).

Not here: restoring the service keys onto c2's HSM (the DKEK domain, #64); `enrol --replace` as the operator's
command (#279, merged: the fixture enrolls c2 as it enrolls every node, and starts its heartbeat counter at 0, so it
takes the nodes' current heartbeat by sync, not at a heartbeat c2 verified as #279 does); the physical rehearsal.
"""
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import AUTH, sh, until                # noqa: E402
from deploy.baremetal import authtime, membership   # noqa: E402

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


def refused(fn, *args):
    """The refusal's text, or None if `fn(*args)` was not refused."""
    try:
        fn(*args)
    except membership.Refused as refusal:
        return str(refusal)
    return None


def scenario(cluster):
    names = ["a", "b", "c"]

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

    header("2  PoC 16.1-16.4: c fails for good; c2 replaces it in one root-signed manifest")
    cluster.stop("c")                                 # gone: it stays off
    cluster.add_node("c2")
    current, current_document = cluster.manifest, cluster.document
    root = cluster.signed(current)["signature"]["key"]
    # through the gate that decides (membership.accept_chain, as every Store runs it)
    by_quorum, _ = cluster.replacement("c", "c2", same_policy=True)           # all a quorum may not change, but the nodes
    said = refused(membership.accept_chain, None, cluster.chain + [{"manifest": by_quorum, "signatures": [cluster.owner_signature(by_quorum)]}], root)
    ok(said is not None and "cannot add or remove nodes" in said,
       "the same replacement signed by the owner (a revocation quorum, #199) is refused: only the root enrolls (%s)" % (said or "accepted")[:90])
    # (the same refusal for a two-node quorum, a's and b's signing keys: membership's own unit test,
    # tests/test_baremetal_membership_v4.py, test_a_quorum_only_restricts_and_never_touches_the_signers, its "a node added" case, signed by b and c)
    reusing, _ = cluster.replacement("c", "c2", reuse=("c", ("ek_name",)))
    said = refused(membership.accept_chain, None, cluster.chain + [cluster.signed(reusing)], root)
    ok(said is not None and "ek_name of c2 is already used (ek_name of c)" in said,
       "root-signed, one giving c2 the retired c's EK is refused: the tombstone keeps it (%s)" % (said or "accepted")[:90])
    since = time.time()
    cluster.replace("c", "c2")                       # #199: the root's envelope given to a, as advance() gives an epoch
    took = until(lambda: all(cluster.node(name).store().load()["epoch"] == 2 for name in ("a", "b"))
                 and any(e.get("event") == "sync-apply" and e.get("peer") == "a" and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
                         for e in cluster.trail("b")), 120, 3)
    ok(took is True, "the root's replacement given to a, b took epoch 2 from a by sync: c RETIRED, c2 ACTIVE")
    fresh = cluster.fresh(["a", "b"], 2, timeout=300)
    ok(all(fresh.values()), "a and b sign epoch 2's heartbeat themselves (c2, not yet running, joins later) (%s)" % fresh,
       cluster.beat_events(["a", "b"]))

    header("3  c2 enrolled through a and b, opens its volume through each, and is leased")
    for name in ("a", "b"):                           # the fixture writes their stores: their services stop meanwhile
        cluster.stop(name, power=None)
    cluster.disk("c2")
    cluster.enrol("c2", peers=["a", "b"])
    for name in ("a", "b"):
        cluster.start(name, SERVICES)
    for alone, other in (("a", "b"), ("b", "a")):
        cluster.stop(other)
        got = cluster.unlock("c2")
        ok(got["rc"] == 0 and got["peer"] == alone and got["marker"],
           "U: c2, with only %s up, opened its volume through %s's keyslot" % (alone, alone), got)
        cluster.start("c2", SERVICES)
        ok(bool(until(lambda: cluster.lease("c2") and cluster.lease_issuer("c2") == alone, 150, 3)),
           "L: c2 holds a lease %s issued" % alone, cluster.journal("c2", "admission")[-400:])
        cluster.stop("c2")
        cluster.start(other, SERVICES)

    header("4  c2 provides bootstrap: b, with only c2 up, opens through c2's keyslot")
    cluster.stop("b", power=None)                     # c2 is down (it was stopped above)
    cluster.enrol("b", peers=["c2"])
    cluster.stop("a")
    cluster.stop("b")
    cluster.start("c2", SERVICES)
    got = cluster.unlock("b")
    ok(got["rc"] == 0 and got["peer"] == "c2" and got["marker"], "U: b, with only c2 up, opened its volume through c2's keyslot",
       {"client": got, "c2 decided": [{k: e.get(k) for k in ("event", "subject", "outcome", "reason")} for e in cluster.trail("c2")
                                      if e.get("event", "").startswith(("unlock", "sync-heartbeat"))][-6:]})
    for name in ("a", "b"):
        cluster.start(name, SERVICES)

    header("5  PoC 16.5: old c, powered back with every credential it held, is refused")
    boot_key, service_key = cluster.keys["c"]["boot"][1], cluster.keys["c"]["service"][1]
    import base64
    as_wg = lambda key: base64.b64encode(bytes.fromhex(key)).decode()          # noqa: E731 - wg prints base64
    peers = ("a", "b", "c2")
    cut = until(lambda: all(as_wg(boot_key) not in cluster.wg_peers(p, "wg-unlock") for p in peers), 60, 2)
    ok(cut is True, "no peer's unlock tunnel admits c's WG-BOOT key", {p: sorted(cluster.wg_peers(p, "wg-unlock")) for p in peers})
    got = cluster.unlock("c", timeout=120, rounds=2)
    ok(got["rc"] != 0 and got["peer"] is None, "N: c, from its own chain (epoch 1) and its paths, gets no key", got)
    since = time.time()
    cluster.start("c", SERVICES)
    off = until(lambda: all(as_wg(service_key) not in cluster.wg_peers(p, "wg-svc") for p in peers), 60, 2)
    time.sleep(30)
    ok(off is True and not cluster.lease("c") and not any(e.get("event") == "sync-lease" and e.get("subject") == "c" and e.get("outcome") == "ALLOW"
                                                         and e.get("at", 0) >= since for p in peers for e in cluster.trail(p)),
       "N: and no lease: c is off every peer's service tunnel, and nobody issued it one", cluster.journal("c", "admission")[-400:])
    # Beneath the tunnels, membership itself: c's service key put back into a's wg-svc by hand (as if a's tunnel had not
    # followed the chain); whatever c then asks of a (its sync's pulls, its admission's lease) a's sync refuses by name,
    # before any operation (sync.peer_of). (On the unlock side a's
    # listener answers no address of a node that may not request: closed unanswered, by design, with nothing to record.)
    since = time.time()
    c_address = threenode.wgsvc.address(service_key)
    cluster.nodes["a"].in_ns("wg", "set", "wg-svc", "peer", as_wg(service_key), "allowed-ips", c_address + "/128",
                             "endpoint", "%s:51821" % cluster.nodes["c"].underlay)
    named = until(lambda: [e.get("reason") for e in cluster.trail("a") if e.get("event", "").startswith("sync") and e.get("outcome") == "DENY"
                           and "c is RETIRED under epoch 2" in e.get("reason", "") and e.get("at", 0) >= since], 120, 3)
    ok(bool(named) and not cluster.lease("c"), "and through a tunnel forced open by hand, a's sync refuses c's requests by name: c is RETIRED under epoch 2",
       {"a denied": named, "c": cluster.journal("c", "admission")[-300:]})


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-replace: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES + (AUTH, "c2")) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    present += [p for p in (os.path.join(authtime.RUN_DIR, "authtime.json"),) if os.path.lexists(p)]
    present += [authtime.RUN_DIR + " (not empty)"] if os.path.isdir(authtime.RUN_DIR) and os.listdir(authtime.RUN_DIR) else []
    if present:
        print("three-node-replace: refused: %s exists: another run's leftovers, or this host's own, are here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("three-node-replace: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
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
        print("\nthree-node-replace: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
