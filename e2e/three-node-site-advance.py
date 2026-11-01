#!/usr/bin/env python3
"""#615, tier N: a site change through three nodes without re-enrolment, on three nodes (e2e/lib/threenode.py with
site_pcr: each node's ESP holds its measured site document, and the nodes attest and unlock on PCR 7, 11 and 12, as a
host does, bootcreds.UNLOCK_PCRS).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> REGALIA_AUDIT_BIN=<dir with built regalia-audit-ship, regalia-audit-collector> \
        sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN,REGALIA_AUDIT_BIN python3 -Es e2e/three-node-site-advance.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs
only on a GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

The move is #615's: the root approves, in one epoch, each node's current set and the same set with only PCR 12 replaced
by what its ESP will measure; each node's site-advance (the real `regalia-node site-advance`, as root under
regalia-esp-advance's identity) writes its new document only because that set is approved; each node reboots onto it in
turn and its peers unlock and lease it; the next epoch retires the old sets, and the old document is then refused.

  1  three enrolled disks, PCR 12 measured from each node's site document; every node starts and is leased
  2  before the root approves the move: site-advance on a refuses, and a's site document is unchanged
  3  the root approves epoch 2: each node's current set and the same set with only PCR 12 replaced
  4  site-advance on all three: each writes its new document and names the moved set; nothing else on its ESP changes;
     each ALLOW is in its esp-advances trail; regalia-site-check refuses until the rootfs site configuration is replaced
     with the moved one, then agrees
  5  one at a time, each node rebooted onto its new document: unlocked by a peer and leased, the two others freshly
     leased while it was down, and seen on the moved set by both peers
  6  epoch 3 retires the old sets
  7  a's old document written back by hand (as anyone with root or the ESP in hand could): a gets no key, both peers
     refuse it for its PCR 12 (their trails); with its new document back, a is unlocked and leased
  8  #340: every line of every node's sync, admission and ESP-advance trail is in the audit collector, with each
     site-advance's ALLOW and the PCR 12 refusals of step 7 by name

LIMITS (tier N):
  * The move changes each node's boot_mesh.nic_mac: a field the site document holds and PCR 12 measures, which the
    fixture's network does not read, so the namespaces stay wired at their addresses. A real move also changes host_ipv4
    and the peers' underlay; that is the same measurement over another document. The fixture's initrd network is set up
    from the rootfs site.json, not from the ESP's document (Cluster.unlock), so the addresses changing is tier Q's.
  * PCR 12 is the fixture's one tpm2_pcrextend of the stub's archive digest at each TPM start (Cluster._measure_site),
    read back and held to espcreds.pcr12; not systemd-stub itself (unlock-boot-qemu measures a real UKI's).
  * That every peer has anchored the approving epoch before a site-advance is checked here by the scenario (step 3: every
    node holds epoch 2), not by site-advance itself (#615's open question).
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
from deploy.baremetal import bootcreds, espcreds, measurements, node  # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")
MOVED = "e2e-moved"


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


def refused_for_pcr12(cluster, peer, subject, since, value):
    """Whether `peer` refused `subject` an unlock since `since` BECAUSE of its PCR 12 (attest's reason names the PCR and the
    value the node quoted), not for any other cause a broken setup would give."""
    return any(e.get("event") == "unlock" and e.get("subject") == subject and e.get("outcome") == "DENY" and e.get("at", 0) >= since
               and ("PCR 12 is %s" % value) in e.get("reason", "") for e in cluster.trail(peer))


def opened(got):
    return got.get("rc") == 0 and bool(got.get("marker"))


def states(cluster):
    return {name: json.loads(pathlib.Path(cluster.node(name).path("attest.json")).read_text()) for name in cluster.nodes}


def seen(cluster, peer, subject):
    """(label, epoch) of `peer`'s last accepted quote of `subject`, or None."""
    last = states(cluster)[peer].get("nodes", {}).get(subject, {}).get("measurement")
    return (last["label"], last["epoch"]) if isinstance(last, dict) else None


def everyone_saw(cluster, subject, label, epoch):
    return all(seen(cluster, p, subject) == (label, epoch) for p in cluster.nodes if p != subject)


def served_while_down(cluster, name, since):
    """Whether each of the two other nodes has been given a FRESH lease since `since` by the third, never by `name`."""
    others = [o for o in cluster.nodes if o != name]
    return bool(until(lambda: all(any(leased_by(cluster, p, o, since) for p in cluster.nodes if p not in (o, name)) for o in others), 240, 5))


def reboot(cluster, name):
    """`name` power-cycled (its TPM start measures its ESP's site document as it is now): asks for its disk, and if it gets
    it, starts and is leased."""
    since = time.time()
    cluster.stop(name)
    cluster.boot(name, None)
    served = served_while_down(cluster, name, since)
    got = cluster.unlock(name, timeout=120, rounds=3)
    leased = False
    if opened(got):
        cluster.start(name, SERVICES)
        leased = bool(until(lambda: cluster.lease(name), 120, 2))
    return {"got": got, "leased": leased, "served": served, "since": since}


def moved_site(cluster, name):
    """The node's site configuration at its new site (the move sheet's): another network card, the same addresses."""
    n = cluster.nodes[name]
    site = cluster.site_config(n)
    return dict(site, boot_mesh=dict(site["boot_mesh"], nic_mac="52:54:00:12:35:%02x" % (0x50 + n.index)))


def esp_files(cluster, name):
    """{relative path: bytes} of every file on the node's ESP but its site document."""
    esp, out = cluster.esp(name), {}
    for top, _dirs, files in os.walk(esp):
        for f in files:
            rel = os.path.relpath(os.path.join(top, f), esp)
            if rel != node.SITE_ON_ESP:
                out[rel] = pathlib.Path(top, f).read_bytes()
    return out


def esp_trail(cluster, name):
    path = cluster.nodes[name].log / "esp-advances.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def scenario(cluster):
    names = list(cluster.nodes)
    a, b, c = names

    header("1  three enrolled disks, PCR 12 measured from each node's site document; every node starts and is leased")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        ok(bool(until(lambda: cluster.lease(name), 120, 2)), "%s holds a runtime lease, unlocked and attested on PCR 7, 11 and 12" % name,
           cluster.journal(name, "admission")[-600:])
    for name in names:
        built = cluster.reference[name]["pcrs"].get("12")
        ok(built == cluster.site_pcr12(name) and built != espcreds.ZERO,
           "%s's accepted set attests PCR 12, the stub's value for the site document on its ESP" % name, {"set": built, "esp": cluster.site_pcr12(name)})
    old = {name: cluster.site_document_path(name).read_bytes() for name in names}
    new = {name: bootcreds.site_document(moved_site(cluster, name), node.ESP_RENDER_DEVICE) for name in names}

    header("2  before the root approves the move: site-advance on a refuses, and a's site document is unchanged")
    done = cluster.site_advance(a, moved_site(cluster, a))
    ok(done.returncode == 2 and "the root has not approved this site document" in done.stderr,
       "a's site-advance refuses: no accepted set is its booted set with the new PCR 12", {"rc": done.returncode, "stderr": done.stderr[-600:]})
    ok(cluster.site_document_path(a).read_bytes() == old[a], "a's ESP still holds its old site document")

    header("3  the root approves epoch 2: each node's current set and the same set with only PCR 12 replaced")
    approving = {"schema": measurements.SCHEMA, "name": "move",
                 "nodes": {name: {"accepted": [cluster.image_set(name), cluster.site_set(name, new[name], MOVED)]} for name in names}}
    cluster.advance(c, document=approving)
    for name in names:
        held = cluster.node(name).store().load()
        ok(held["epoch"] == 2 and held["policy_version"] == measurements.version(approving),
           "%s holds epoch 2, committed to the document that approves its moved set (from its TPM-anchored store)" % name, held.get("epoch"))
    ok(all(until(lambda: cluster.lease(name), 120, 2) for name in names), "every node holds a lease again after the epoch",
       {name: bool(cluster.lease(name)) for name in names})

    header("4  site-advance on all three; site-check refuses until the rootfs site configuration is replaced")
    since = time.time()
    others = {name: esp_files(cluster, name) for name in names}
    for name in names:
        done = cluster.site_advance(name, moved_site(cluster, name))
        ok(done.returncode == 0 and cluster.site_document_path(name).read_bytes() == new[name] and repr(MOVED) in done.stdout,
           "%s's site-advance writes its new site document and names the moved set" % name,
           {"rc": done.returncode, "stdout": done.stdout[-400:], "stderr": done.stderr[-600:]})
    ok(all(esp_files(cluster, name) == others[name] for name in names), "nothing else on any node's ESP changed")
    allowed = {name: [e for e in esp_trail(cluster, name) if e.get("event") == "site-advance" and e.get("outcome") == "ALLOW"
                      and e.get("next_set") == MOVED and e.get("epoch") == 2] for name in names}
    ok(all(len(v) == 1 for v in allowed.values()), "each node's esp-advances trail holds one site-advance ALLOW for the moved set at epoch 2",
       {name: len(v) for name, v in allowed.items()})
    for name in names:
        done = cluster.site_check(name)
        ok(done.returncode == 2 and "differ in" in done.stderr, "%s's site-check refuses: its rootfs site configuration is the old site's" % name,
           {"rc": done.returncode, "stderr": done.stderr[-400:]})
    for name in names:
        threenode._replace(cluster.nodes[name].dir / "etc" / "site.json", json.dumps(moved_site(cluster, name)))   # the operator, at the move
    for name in names:
        done = cluster.site_check(name)
        ok(done.returncode == 0, "%s's site-check agrees once its rootfs site configuration is the moved one" % name,
           {"rc": done.returncode, "stderr": done.stderr[-400:]})

    header("5  one at a time, each node rebooted onto its new site document")
    for name in names:
        r = reboot(cluster, name)
        ok(opened(r["got"]) and r["leased"], "%s, on its new site document, is unlocked through %s and leased" % (name, r["got"].get("peer")), r["got"])
        ok(r["served"], "the two others were freshly leased while %s was down" % name)
        ok(bool(until(lambda: everyone_saw(cluster, name, MOVED, 2), 240, 5)), "both peers see %s on the moved set at epoch 2" % name,
           {p: seen(cluster, p, name) for p in names if p != name})

    header("6  epoch 3 retires the old sets")
    retiring = {"schema": measurements.SCHEMA, "name": "moved",
                "nodes": {name: {"accepted": [cluster.site_set(name, new[name], MOVED)]} for name in names}}
    cluster.advance(c, document=retiring)
    held = {name: cluster.node(name).store().load() for name in names}
    ok(all(h["epoch"] == 3 and h["policy_version"] == measurements.version(retiring) for h in held.values()),
       "every node holds epoch 3, committed to the document that lists the moved sets alone", {n: h.get("epoch") for n, h in held.items()})
    ok(all(until(lambda: cluster.lease(name), 120, 2) for name in names), "every node holds a lease again after the retire",
       {name: bool(cluster.lease(name)) for name in names})

    header("7  a's old site document written back by hand: refused for its PCR 12; the new one back, unlocked")
    cluster.write_site_document(a, cluster.site_config(cluster.nodes[a]))
    quoted = cluster.reference[a]["pcrs"]["12"]
    r = refused_old = reboot(cluster, a)
    ok(not opened(r["got"]) and all(refused_for_pcr12(cluster, p, a, r["since"], quoted) for p in (b, c)),
       "a, booted with its old site document after the retire, gets no key: both peers refuse it for its PCR 12 (their trails)",
       {"unlock": r["got"], "denials": [e for p in (b, c) for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("at", 0) >= r["since"]]})
    ok(r["served"], "b and c were freshly leased while a was refused")
    cluster.write_site_document(a, moved_site(cluster, a))
    r = reboot(cluster, a)
    ok(opened(r["got"]) and r["leased"], "a, with its new site document back, is unlocked through %s and leased" % r["got"].get("peer"), r["got"])

    header("8  #340: every line of every node's sync, admission and ESP-advance trail is in the audit collector")
    wrong = cluster.audit_complete()
    ok(wrong == {}, "every node's sync, admission and ESP-advance trail is in the collector line for line",
       {"%s.%s" % k: v for k, v in wrong.items()})
    ok(all(cluster.audit_has(name, "esp-advances", since=since, event="site-advance", outcome="ALLOW", next_set=MOVED) for name in names),
       "each node's site-advance ALLOW for the moved set is in its esp-advances stream")
    ok(all(cluster.audit_has(p, "sync", since=refused_old["since"], event="unlock", subject=a, outcome="DENY",
                             reason=lambda reason: bool(reason) and ("PCR 12 is %s" % quoted) in reason) for p in (b, c)),
       "b's and c's refusals of a on its old site document, for its PCR 12 (step 7), are in their streams")


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("three-node-site-advance: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    if present:
        print("three-node-site-advance: refused: %s exists: another run's leftovers are still here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK) or not all(
            os.access(os.path.join(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"), b), os.X_OK) for b in ("regalia-audit-ship", "regalia-audit-collector")):
        print("three-node-site-advance: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock and REGALIA_AUDIT_BIN a directory "
              "with the built regalia-audit-ship and regalia-audit-collector (#340)")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work, audit=True, site_pcr=True)
    try:
        scenario(cluster)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in cluster.nodes:
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\nthree-node-site-advance: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
