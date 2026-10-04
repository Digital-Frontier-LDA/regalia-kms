#!/usr/bin/env python3
"""#75 (Phase 15), tier N: a new image rolled through three nodes while CURRENT and NEXT are both accepted, on
three nodes (e2e/lib/threenode.py: each its real services in its own namespace, against its own TPM).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/rolling-threenode.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

An image is what a UKI changes, PCR 11 (the fixture's boot(name, image): extended after the power cycle, before
the node asks for its disk). The unlock and the leases are the real ones: the pre-root client against the peers'
unlock listeners, the admission service against their sync. may_reboot is asked as `update apply` asks it: as
root in the node's namespace, on leases the node asks its peers for at that moment (update.fresh_leases), the
set it runs read from its TPM (update.running_set). The retire is judged as `rollout propose` judges it
(rollout.check_lockout), from the peers' real attestation state files.

  1  CURRENT: three enrolled disks; every node starts and is leased
  2  NEXT before the root approved it: a boots it and gets no key from either peer; b and c keep their leases;
     a, power-cycled onto CURRENT, is unlocked and leased again
  3  the root approves CURRENT and NEXT in one epoch: every node holds it, committed to the new document
  4  one at a time: asked at the same moment, may_reboot says yes to a and WAIT to b and c
  5  a reboots onto NEXT: unlocked by a peer, leased, seen on NEXT by its peers; and it vouches for b and c (leases)
     while they are still on CURRENT
  6  a rolls back to CURRENT under the same epoch: still unlocked (both are approved), and the retire is refused
     naming a; then a is back on NEXT
  7  b's turn once b itself has seen a on NEXT: b onto NEXT; the retire still refused, naming c; then c onto NEXT
  8  the retire, once every node is seen on NEXT by every peer: accepted; the root signs NEXT alone; c, booted onto
     CURRENT again, gets no key from either peer; onto NEXT, it is unlocked and leased
"""
import json
import os
import pathlib
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402
from deploy.baremetal import measurements, membership, rollout  # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")
NEXT_IMAGE = "image-2"


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
    return any(e.get("event") == "sync-lease" and e.get("subject") == subject and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
               for e in cluster.trail(peer))


def refused_for_pcr11(cluster, peer, subject, since, value):
    """Whether `peer` refused `subject` an unlock since `since` BECAUSE of its PCR 11 (attest's reason names the PCR
    and the value the node quoted), not for any other cause a broken setup would give."""
    return any(e.get("event") == "unlock" and e.get("subject") == subject and e.get("outcome") == "DENY" and e.get("at", 0) >= since
               and ("PCR 11 is %s" % value) in e.get("reason", "") for e in cluster.trail(peer))


def opened(got):
    return got.get("rc") == 0 and bool(got.get("marker"))


# may_reboot as `update apply` asks it: as root in the node's namespace, on fresh leases, the running set from the TPM
DECIDE = (
    "import json, sys\n"
    "from deploy.baremetal import measurements, membership, node, rollout, update\n"
    "d = json.load(sys.stdin)\n"
    "h = update.Host(node.load(d['cfg']))\n"
    "m, doc = h.manifest(), h.document()\n"
    "measurements.bind(m, doc)\n"
    "running = update.running_set(doc, h.node_id, h.pcrs)['label']\n"
    "s = h.session()\n"
    "got, refused = update.fresh_leases(h, m, update.authorizers(m, h.node_id), s)\n"
    "try:\n"
    "    out = dict(rollout.may_reboot(m, doc, h.node_id, running, s, h.own_state(), list(got.values()), h.now(), run=h.run), ok=True)\n"
    "except membership.Refused as r:\n"
    "    out = {'ok': False, 'reason': str(r)}\n"
    "print(json.dumps(dict(out, running=running, epoch=m['epoch'], refused=refused)))\n")


def decide(cluster, name):
    n = cluster.nodes[name]
    return json.loads(n.in_ns("env", "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-Es", "-c", DECIDE,
                              input=json.dumps({"cfg": str(n.cfg_path)}), cwd=str(cluster.code)).stdout)


def states(cluster):
    """Every node's attestation verifier state, as an operator collects them for retire-ready."""
    return {name: json.loads(pathlib.Path(cluster.node(name).path("attest.json")).read_text()) for name in cluster.nodes}


def seen(cluster, peer, subject):
    """(label, epoch) of `peer`'s last accepted quote of `subject`, or None."""
    last = states(cluster)[peer].get("nodes", {}).get(subject, {}).get("measurement")
    return (last["label"], last["epoch"]) if isinstance(last, dict) else None


def everyone_saw(cluster, subject, label, epoch):
    return all(seen(cluster, p, subject) == (label, epoch) for p in cluster.nodes if p != subject)


def reboot(cluster, name, image):
    """`name` power-cycled onto `image` (None: CURRENT), asks for its disk, and if it gets it, starts and is leased.
    Returns (the unlock's result, whether it is leased)."""
    cluster.stop(name)
    cluster.boot(name, image)
    got = cluster.unlock(name, timeout=120, rounds=3)
    if not opened(got):
        return got, False
    cluster.start(name, SERVICES)
    return got, bool(until(lambda: cluster.lease(name), 120, 2))


def retire_check(cluster, manifest, both, nxt):
    try:
        return rollout.check_lockout(manifest, both, nxt, measurements.transition(both, nxt), states(cluster), False, [])
    except membership.Refused as refused:
        return str(refused)


def scenario(cluster):
    names = list(cluster.nodes)
    a, b, c = names

    header("1  CURRENT: three enrolled disks; every node starts and is leased")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 120, 2)), "%s holds a runtime lease on CURRENT" % name, cluster.journal(name, "admission")[-600:])

    header("2  NEXT before the root approved it: no key for a; b and c serve on")
    since = time.time()
    got, leased = reboot(cluster, a, NEXT_IMAGE)
    quoted = cluster.image_set(a, NEXT_IMAGE)["pcrs"]["11"]
    ok(not opened(got) and all(refused_for_pcr11(cluster, p, a, since, quoted) for p in (b, c)),
       "a, booted onto %s under epoch 1, gets no key: both peers refuse it for its PCR 11 (their trails)" % NEXT_IMAGE,
       {"unlock": got, "denials": [e for p in (b, c) for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("at", 0) >= since]})
    ok(bool(cluster.lease(b)) and bool(cluster.lease(c)), "b and c still hold leases (the cluster serves on two)")
    got, leased = reboot(cluster, a, None)
    ok(opened(got) and leased, "a, power-cycled onto CURRENT, is unlocked through %s and leased again" % got.get("peer"), got)

    header("3  the root approves CURRENT and NEXT in one epoch")
    both = {n: [None, NEXT_IMAGE] for n in names}
    manifest, _ = cluster.accept(c, both, "v2")
    doc_both = cluster.document
    for name in names:
        held = cluster.node(name).store().load()
        ok(held["epoch"] == 2 and held["policy_version"] == measurements.version(doc_both),
           "%s holds epoch 2, committed to the document that accepts both (from its TPM-anchored store)" % name, held.get("epoch"))

    header("4  one at a time: may_reboot asked on each node at once")
    verdicts = {name: decide(cluster, name) for name in names}
    ok(verdicts[a]["ok"] and verdicts[a]["target"] == NEXT_IMAGE and verdicts[a]["running"] == cluster.image_set(a)["label"],
       "a may reboot into %s (vouched for by %s, on leases it asked for now)" % (NEXT_IMAGE, verdicts[a].get("authorizers")), verdicts[a])
    for name in (b, c):
        ok(not verdicts[name]["ok"] and "a updates first" in verdicts[name].get("reason", ""), "%s is told to wait: a goes first" % name, verdicts[name])

    header("5  a onto NEXT: unlocked, leased, seen on NEXT, and vouching for b and c")
    since = time.time()
    got, leased = reboot(cluster, a, NEXT_IMAGE)
    ok(opened(got) and leased, "a, on %s under epoch 2, is unlocked through %s and leased" % (NEXT_IMAGE, got.get("peer")), got)
    ok(bool(until(lambda: everyone_saw(cluster, a, NEXT_IMAGE, 2), 300, 5)), "both peers have verified a on %s under epoch 2" % NEXT_IMAGE,
       {p: seen(cluster, p, a) for p in (b, c)})
    ok(bool(until(lambda: leased_by(cluster, a, b, since) and leased_by(cluster, a, c, since), 420, 5)),
       "a, on NEXT, issues leases to b and c, still on CURRENT")

    header("6  a rolls back to CURRENT under epoch 2, and the retire waits for it")
    got, leased = reboot(cluster, a, None)
    ok(opened(got) and leased, "a, back on CURRENT, is still unlocked (through %s) and leased: both are approved" % got.get("peer"), got)
    until(lambda: everyone_saw(cluster, a, cluster.image_set(a)["label"], 2), 300, 5)
    nxt = {n: [NEXT_IMAGE] for n in names}
    doc_next = {"schema": measurements.SCHEMA, "name": "v3", "nodes": {n: {"accepted": [cluster.image_set(n, NEXT_IMAGE)]} for n in names}}
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(isinstance(verdict, str) and "NOT YET" in verdict and "lock out a" in verdict, "the retire is refused, naming a", verdict)
    got, leased = reboot(cluster, a, NEXT_IMAGE)
    ok(opened(got) and leased, "a is on %s again" % NEXT_IMAGE, got)

    header("7  b once it has seen a on NEXT itself, then c")
    ok(bool(until(lambda: seen(cluster, b, a) == (NEXT_IMAGE, 2), 300, 5)), "b's own verifier has seen a on %s" % NEXT_IMAGE, seen(cluster, b, a))
    verdict = decide(cluster, b)
    ok(verdict["ok"], "b may reboot now", verdict)
    got, leased = reboot(cluster, b, NEXT_IMAGE)
    ok(opened(got) and leased, "b, on %s, is unlocked through %s and leased" % (NEXT_IMAGE, got.get("peer")), got)
    until(lambda: everyone_saw(cluster, b, NEXT_IMAGE, 2), 300, 5)
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(isinstance(verdict, str) and "lock out c" in verdict and "lock out a" not in verdict, "the retire is refused while c is on CURRENT, naming c", verdict)
    ok(bool(until(lambda: seen(cluster, c, a) == (NEXT_IMAGE, 2) and seen(cluster, c, b) == (NEXT_IMAGE, 2), 300, 5)),
       "c's own verifier has seen a and b on %s" % NEXT_IMAGE, {s: seen(cluster, c, s) for s in (a, b)})
    verdict = decide(cluster, c)
    ok(verdict["ok"], "c may reboot now", verdict)
    got, leased = reboot(cluster, c, NEXT_IMAGE)
    ok(opened(got) and leased, "c, on %s, is unlocked through %s and leased" % (NEXT_IMAGE, got.get("peer")), got)

    header("8  the retire: accepted once every node is seen on NEXT; CURRENT then gets nothing")
    ok(bool(until(lambda: all(everyone_saw(cluster, n, NEXT_IMAGE, 2) for n in names), 300, 5)), "every node is seen on %s by both peers" % NEXT_IMAGE,
       {n: {p: seen(cluster, p, n) for p in names if p != n} for n in names})
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(verdict == [], "the retire locks out nobody (rollout.check_lockout, the peers' real state files)", verdict)
    manifest, _ = cluster.accept(a, nxt, "v3")
    ok(all(cluster.node(n).store().load()["epoch"] == 3 for n in names), "every node holds epoch 3, NEXT alone")
    since = time.time()
    got, leased = reboot(cluster, c, None)
    quoted = cluster.image_set(c)["pcrs"]["11"]
    ok(not opened(got) and all(refused_for_pcr11(cluster, p, c, since, quoted) for p in (a, b)),
       "c, booted onto the retired CURRENT, gets no key: both peers refuse it for its PCR 11 (their trails)",
       {"unlock": got, "denials": [e for p in (a, b) for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("at", 0) >= since]})
    got, leased = reboot(cluster, c, NEXT_IMAGE)
    ok(opened(got) and leased, "c, onto %s, is unlocked through %s and leased" % (NEXT_IMAGE, got.get("peer")), got)


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("rolling-threenode: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("rolling-threenode: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("rolling-threenode: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
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
        print("\nrolling-threenode: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
