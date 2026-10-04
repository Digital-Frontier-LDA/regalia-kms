#!/usr/bin/env python3
"""#75 (Phase 15), tier N: a new image rolled through three nodes while CURRENT and NEXT are both accepted, on
three nodes (e2e/lib/threenode.py: each its real services in its own namespace, against its own TPM).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> REGALIA_AUDIT_BIN=<dir with built regalia-audit-ship, regalia-audit-collector> \
        sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN,REGALIA_AUDIT_BIN python3 -Es e2e/rolling-threenode.py

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
  9  #340: every line of every node's sync and admission trail is in the audit collector (a real collector and
     each node's real shipper: Cluster(audit=True)), and the events the rollout turns on are in it by name: the
     PCR 11 refusals, the leases a issued on NEXT, the epoch that retired CURRENT, each node's return to serving
Every move to NEXT is an update: may_reboot first. A boot onto an image that is not approved (step 2), back onto
CURRENT (step 6) or onto the retired image (step 8) is a power cycle, not an update. During every reboot the two
other nodes must be given FRESH leases (their peers' trails), not merely hold old ones.

LIMITS (tier N; tier Q is #75's PR 4):
  * PCR 11 is the fixture's one tpm2_pcrextend of SHA-256(image) after the power cycle, not systemd-stub's
    measurement of a real UKI's sections and systemd-pcrphase's phases (unlock-boot-qemu does that).
  * `update apply` itself (BootNext, the trial boot, the reset fallback; #325, #326) is not run: only the may_reboot
    question it asks, as it asks it.
  * The epochs come from the fixture (advance), signed by the root; their heartbeats from the nodes themselves (#199).
  * The local half is sealed to PCR 7, so no image touches it (as on a host, PIN-CUSTODY.md).
  * The document and its epoch are taken together because the fixture stops every node's services across the
    change (Cluster.accept). A host has no such step yet: delivering the document with the epoch that names it is
    regalia-kms-24's decision on #75 (d9), and until it lands a host refuses attestations in between (KERNEL-UPDATE 2.7).
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
    "m = h.manifest()\n"
    "doc = h.document(m)\n"
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


def served_while_down(cluster, name, since):
    """Asked WHILE `name` is down (after its stop, before it asks for its disk): whether each of the two other nodes
    has been given a FRESH lease since `since` by the third (their sync trails), never by `name`, and not one held
    from before that has not run out yet. The cluster serves on two (regalia-kms-51)."""
    others = [o for o in cluster.nodes if o != name]
    return bool(until(lambda: all(any(leased_by(cluster, p, o, since) for p in cluster.nodes if p not in (o, name)) for o in others), 240, 5))


def reboot(cluster, name, image):
    """`name` power-cycled onto `image` (None: CURRENT): asks for its disk, and if it gets it, starts and is leased.
    Returns {"got": the unlock's result, "leased": whether it is, "served": whether the two others were freshly
    leased while it was down}."""
    since = time.time()
    cluster.stop(name)
    cluster.boot(name, image)
    served = served_while_down(cluster, name, since)          # while it is down: it can have issued nothing since
    got = cluster.unlock(name, timeout=120, rounds=3)
    leased = False
    if opened(got):
        cluster.start(name, SERVICES)
        leased = bool(until(lambda: cluster.lease(name), 120, 2))
    return {"got": got, "leased": leased, "served": served, "since": since}


def moved(cluster, name, image, what):
    """An update step: may_reboot first (as `update apply` asks it), then the reboot. Three checks."""
    verdict = decide(cluster, name)
    ok(verdict["ok"], "%s: may_reboot says %s may reboot now" % (what, name), verdict)
    r = reboot(cluster, name, image)
    ok(opened(r["got"]) and r["leased"], "%s: %s on %s is unlocked through %s and leased" % (what, name, image or "CURRENT", r["got"].get("peer")), r["got"])
    ok(r["served"], "%s: the two others were freshly leased while %s was down" % (what, name))
    return r


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

    header("2  NEXT before the root approved it (a power cycle onto it, not an update): no key for a; b and c serve on")
    r = refused_next = reboot(cluster, a, NEXT_IMAGE)
    quoted = threenode.unlock_pcr11(cluster.image_set(a, NEXT_IMAGE))
    ok(not opened(r["got"]) and all(refused_for_pcr11(cluster, p, a, r["since"], quoted) for p in (b, c)),
       "a, booted onto %s under epoch 1, gets no key: both peers refuse it for its PCR 11 (their trails)" % NEXT_IMAGE,
       {"unlock": r["got"], "denials": [e for p in (b, c) for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("at", 0) >= r["since"]]})
    ok(r["served"], "b and c were freshly leased while a was refused")
    r = reboot(cluster, a, None)
    ok(opened(r["got"]) and r["leased"], "a, power-cycled onto CURRENT, is unlocked through %s and leased again" % r["got"].get("peer"), r["got"])

    header("3  the root approves CURRENT and NEXT in one epoch (the document and the epoch taken together: Cluster.accept)")
    both = {n: [None, NEXT_IMAGE] for n in names}
    manifest, _ = cluster.accept(c, both, "v2")
    doc_both = cluster.document
    for name in names:
        held = cluster.node(name).store().load()
        ok(held["epoch"] == 2 and held["policy_version"] == measurements.version(doc_both),
           "%s holds epoch 2, committed to the document that accepts both (from its TPM-anchored store)" % name, held.get("epoch"))
    ok(all(until(lambda: cluster.lease(name), 120, 2) for name in names), "every node holds a lease again after the epoch",
       {name: bool(cluster.lease(name)) for name in names})

    header("4  one at a time: may_reboot asked on each node at once")
    verdicts = {name: decide(cluster, name) for name in names}
    ok(verdicts[a]["ok"] and verdicts[a]["target"] == NEXT_IMAGE and verdicts[a]["running"] == cluster.image_set(a)["label"],
       "a may reboot into %s (vouched for by %s, on leases it asked for now)" % (NEXT_IMAGE, verdicts[a].get("authorizers")), verdicts[a])
    for name in (b, c):
        ok(not verdicts[name]["ok"] and "a updates first" in verdicts[name].get("reason", ""), "%s is told to wait: a goes first" % name, verdicts[name])

    header("5  a onto NEXT: unlocked, leased, seen on NEXT, and vouching for b and c")
    r = on_next = moved(cluster, a, NEXT_IMAGE, "5")
    ok(bool(until(lambda: everyone_saw(cluster, a, NEXT_IMAGE, 2), 300, 5)), "both peers have verified a on %s under epoch 2" % NEXT_IMAGE,
       {p: seen(cluster, p, a) for p in (b, c)})
    ok(bool(until(lambda: leased_by(cluster, a, b, r["since"]) and leased_by(cluster, a, c, r["since"]), 420, 5)),
       "a, on NEXT, issues leases to b and c, still on CURRENT")

    header("6  a rolls back to CURRENT under epoch 2 (a power cycle onto it), and the retire waits for it")
    r = reboot(cluster, a, None)
    ok(opened(r["got"]) and r["leased"], "a, back on CURRENT, is still unlocked (through %s) and leased: both are approved" % r["got"].get("peer"), r["got"])
    ok(r["served"], "b and c were freshly leased while a was down")
    current = cluster.image_set(a)["label"]
    ok(bool(until(lambda: everyone_saw(cluster, a, current, 2), 300, 5)), "both peers have verified a on CURRENT again under epoch 2",
       {p: seen(cluster, p, a) for p in (b, c)})
    doc_next = {"schema": measurements.SCHEMA, "name": "v3", "nodes": {n: {"accepted": [cluster.image_set(n, NEXT_IMAGE)]} for n in names}}
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(isinstance(verdict, str) and "NOT YET" in verdict and "lock out a" in verdict, "the retire is refused, naming a", verdict)
    a_last = moved(cluster, a, NEXT_IMAGE, "6, a again")

    header("7  b once it has seen a on NEXT itself, then c")
    ok(bool(until(lambda: seen(cluster, b, a) == (NEXT_IMAGE, 2), 300, 5)), "b's own verifier has seen a on %s" % NEXT_IMAGE, seen(cluster, b, a))
    moved(cluster, b, NEXT_IMAGE, "7, b")
    ok(bool(until(lambda: everyone_saw(cluster, b, NEXT_IMAGE, 2), 300, 5)), "both peers have verified b on %s under epoch 2" % NEXT_IMAGE,
       {p: seen(cluster, p, b) for p in (a, c)})
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(isinstance(verdict, str) and "lock out c" in verdict and "lock out a" not in verdict and "lock out b" not in verdict,
       "the retire is refused while c is on CURRENT, naming c alone", verdict)
    ok(bool(until(lambda: seen(cluster, c, a) == (NEXT_IMAGE, 2) and seen(cluster, c, b) == (NEXT_IMAGE, 2), 300, 5)),
       "c's own verifier has seen a and b on %s" % NEXT_IMAGE, {s: seen(cluster, c, s) for s in (a, b)})
    moved(cluster, c, NEXT_IMAGE, "7, c")

    header("8  the retire: accepted once every node is seen on NEXT; CURRENT then gets nothing")
    ok(bool(until(lambda: all(everyone_saw(cluster, n, NEXT_IMAGE, 2) for n in names), 300, 5)), "every node is seen on %s by both peers" % NEXT_IMAGE,
       {n: {p: seen(cluster, p, n) for p in names if p != n} for n in names})
    verdict = retire_check(cluster, manifest, doc_both, doc_next)
    ok(verdict == [], "the retire locks out nobody (rollout.check_lockout, the peers' real state files)", verdict)
    manifest, retired = cluster.accept(a, {n: [NEXT_IMAGE] for n in names}, "v3")
    ok(all(cluster.node(n).store().load()["epoch"] == 3 for n in names), "every node holds epoch 3, NEXT alone")
    ok(all(until(lambda: cluster.lease(name), 120, 2) for name in names), "every node holds a lease again after the epoch",
       {name: bool(cluster.lease(name)) for name in names})
    # not updates: a power cycle onto the retired image (a stale BootOrder, KERNEL-UPDATE 3.8), then onto NEXT again
    r = refused_retired = reboot(cluster, c, None)
    quoted = threenode.unlock_pcr11(cluster.image_set(c))
    ok(not opened(r["got"]) and all(refused_for_pcr11(cluster, p, c, r["since"], quoted) for p in (a, b)),
       "c, booted onto the retired CURRENT, gets no key: both peers refuse it for its PCR 11 (their trails)",
       {"unlock": r["got"], "denials": [e for p in (a, b) for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("at", 0) >= r["since"]]})
    ok(r["served"], "a and b were freshly leased while c was refused")
    r = reboot(cluster, c, NEXT_IMAGE)
    ok(opened(r["got"]) and r["leased"], "c, onto %s, is unlocked through %s and leased" % (NEXT_IMAGE, r["got"].get("peer")), r["got"])
    ok(r["served"], "a and b were freshly leased while c was down")

    header("9  #340: every line of every node's sync and admission trail is in the audit collector, for the node that recorded it")
    wrong = cluster.audit_complete()
    counts = {"%s.%s" % (n, t): len(cluster.audit_stream(n, t)) for n in names for t in ("sync", "admission")}
    ok(wrong == {}, "every node's sync and admission trail is written and in the collector line for line: sequence from 1, chained from "
       "genesis, each DENY a deny, and its head as the collector's signed receipt and the shipper's head file state it %s" % counts,
       {"%s.%s" % k: v for k, v in wrong.items()})

    def pcr11(value):
        return lambda r: bool(r) and ("PCR 11 is %s" % value) in r
    ok(all(cluster.audit_has(p, "sync", since=refused_next["since"], event="unlock", subject=a, outcome="DENY",
                             reason=pcr11(threenode.unlock_pcr11(cluster.image_set(a, NEXT_IMAGE)))) for p in (b, c)),
       "b's and c's refusals of a on the unapproved %s, for its PCR 11 (step 2), are in their streams" % NEXT_IMAGE)
    ok(all(cluster.audit_has(p, "sync", since=refused_retired["since"], event="unlock", subject=c, outcome="DENY",
                             reason=pcr11(threenode.unlock_pcr11(cluster.image_set(c)))) for p in (a, b)),
       "a's and b's refusals of c on the retired CURRENT, for its PCR 11 (step 8), are in their streams")
    ok(all(cluster.audit_has(a, "sync", since=on_next["since"], event="sync-lease", subject=s, outcome="ALLOW") for s in (b, c)),
       "the leases a issued to b and c from %s (step 5) are in a's stream" % NEXT_IMAGE)
    took = {n: cluster.moved_by_sync(n, retired, 3) for n in (b, c)}
    ok(all(took.values()), "the sync round that moved b and c to epoch 3, the retire, is in each one's stream (from %s)" % took, took)
    serving = {n: bool(cluster.audit_has(n, "admission", event="admission-serving", outcome="ALLOW")) for n in names}
    ok(all(serving.values()), "each node's change to serving is in its own admission stream", serving)
    back = cluster.audit_has(a, "admission", since=a_last["since"], event="admission-serving", outcome="ALLOW")
    ok(bool(back), "a's return to serving after its last reboot (onto %s, step 6) is in a's admission stream" % NEXT_IMAGE,
       cluster.audit_stream(a, "admission")[-3:])


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
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK) or not all(
            os.access(os.path.join(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"), b), os.X_OK) for b in ("regalia-audit-ship", "regalia-audit-collector")):
        print("rolling-threenode: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock and REGALIA_AUDIT_BIN a directory "
              "with the built regalia-audit-ship and regalia-audit-collector (#340)")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work, audit=True)
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
