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
  5  PoC 10.5, the session binding: b crashed (the same TPM boot) presents a second session and a gives it
     nothing, while c, in a new boot, unlocks through a at the same time; b power-cycled then unlocks through a
  6  PoC 10.5, the rate limits: b's lease requests to a, its admission stopped and its bucket full: the
     first 6 in a minute answered, the 7th refused and recorded; c, beside it, answered
  7  N: a QUARANTINED (by the owner's key, #199), then RETIRED (by the root), then b REVOKED_STOLEN (c is then the only
     node that counts: it holds no heartbeat for the epoch until the owner's hand recovery, owner.py beat). In each, a
     control first (a node that may still ask opens its volume: the setup works), then the epoch given to one
     survivor and taken by the others with their sync; the survivors' wg-unlock drops the node; it gets no key,
     and no lease, with the reason (a survivor's DENY naming its state, or it is off wg-svc)

L always: a live lease in the node's admission, whose holder names the peer as issuer, and that peer's trail
saying it issued one.
"""
import itertools
import json
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


def leased(cluster, name, peer, since):
    """L: the node's admission holds a live lease, the one it holds names `peer` as its issuer, and `peer`'s trail
    says it issued it one since `since`."""
    return bool(cluster.lease(name)) and cluster.lease_issuer(name) == peer and leased_by(cluster, peer, name, since)


def unlocked(got, peer):
    """U: the client gave a key, it opened the keyslot of `peer`'s path, and the filesystem reads back."""
    return got.get("rc") == 0 and got.get("peer") == peer and bool(got.get("marker"))


def may(manifest, name, action):
    return action in {"ACTIVE": ("serve", "request", "authorize"), "MAINTENANCE": ("request",), "DRAINING": ("serve",)}.get(
        next(m for m in manifest["nodes"] if m["node_id"] == name)["state"], ())


def attempt(cluster, results, name, **kw):
    """cluster.unlock in a thread: its result, or what stopped it, into `results`."""
    try:
        results[name] = cluster.unlock(name, **kw)
    except Exception as failure:                     # noqa: BLE001 - reported by the check that reads it
        results[name] = {"error": repr(failure)}


# update.py's own collection (#75): Host.lease_from (sync.Client.renewer, node.quote, lease.Holder.install) and
# fresh_leases' private directory, as `update apply` runs them, as root, in the node's namespace
LIVE_LEASES = (
    "import json, os, sys, tempfile\n"
    "from deploy.baremetal import lease, node, update\n"
    "d = json.load(sys.stdin)\n"
    "h = update.Host(node.load(d['cfg']))\n"
    "h.private_root = tempfile.mkdtemp(dir='/run', prefix='regalia-e2e-update-')\n"
    "m = h.manifest()\n"
    "s = h.session()\n"
    "got, refused = update.fresh_leases(h, m, update.authorizers(m, h.node_id), s)\n"
    "now = h.now()\n"
    "out = {p: {'node_id': e['lease']['node_id'], 'issuer': e['lease']['issuer'], 'this_session': e['lease']['session_id'] == s,\n"
    "           'left': lease.verify(e, m, now)} for p, e in got.items()}\n"
    "left = os.listdir(h.private_root)\n"
    "os.rmdir(h.private_root)\n"
    "print(json.dumps({'leases': out, 'refused': refused, 'private_left': left}))\n")


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

    header("1b  #75: update.py's live leases, the real call: a asks b and c for a lease for its boot, as root in its namespace")
    got = json.loads(cluster.nodes["a"].in_ns("env", "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-Es", "-c", LIVE_LEASES,
                                               input=json.dumps({"cfg": str(cluster.nodes["a"].cfg_path)}), cwd=str(cluster.code)).stdout)
    ok(sorted(got["leases"]) == ["b", "c"] and not got["refused"], "a got a lease from b and from c, each asked once (%s)" % got.get("refused"), got)
    ok(all(v["node_id"] == "a" and v["issuer"] == p and v["this_session"] and v["left"] > 0 for p, v in got["leases"].items()),
       "each names a as subject, its peer as issuer, a's boot session, and verifies under a's manifest now", got)
    ok(got["private_left"] == [], "the leases' private directory under /run is gone when the collection returns", got)

    header("2  PoC 10.1: every directed relationship, X restored by P alone")
    for target, peer in itertools.permutations(names, 2):
        third = next(n for n in names if n not in (target, peer))
        cluster.stop(target)
        cluster.stop(third)
        since = time.time()
        got = cluster.unlock(target)
        ok(unlocked(got, peer), "U: %s, with only %s up, opened its volume through %s's keyslot and read it back" % (target, peer, peer), got)
        cluster.start(target, SERVICES)
        ok(until(lambda: leased(cluster, target, peer, since), 120, 2) is True, "L: %s holds a lease %s issued" % (target, peer),
           cluster.journal(target, "admission")[-600:])
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
            ok(unlocked(got, survivor), "U: %s, with only %s up, opened its volume through %s's keyslot" % (name, survivor, survivor), got)
        for name in down:
            cluster.start(name, SERVICES)
        for name in down:
            ok(until(lambda: leased(cluster, name, survivor, since), 120, 2) is True, "L: %s holds a lease %s issued" % (name, survivor),
               cluster.journal(name, "admission")[-600:])

    header("4  PoC 10.5: two recovery requests to one survivor at once")
    survivor, down = names[0], names[1:]
    for name in down:
        cluster.stop(name)
    results = {}
    workers = [threading.Thread(target=attempt, args=(cluster, results, name)) for name in down]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    for name in down:
        ok(unlocked(results.get(name, {}), survivor), "U: %s, asking %s at the same time as %s, opened its volume through %s's keyslot"
           % (name, survivor, next(o for o in down if o != name), survivor), results.get(name))
    for name in down:
        cluster.start(name, SERVICES)
    for name in down:
        until(lambda: cluster.lease(name), 120, 2)

    header("5  PoC 10.5: one boot, one session: a second session in the same boot is refused, and only it")
    # b crashes (its services stop, its TPM does not: the same boot) and a new client of b's presents a new session;
    # c, power-cycled (a new boot), asks the same survivor at the same time
    survivor, crashed, rebooted = "a", "b", "c"
    cluster.stop(rebooted)
    cluster.stop(crashed, power=None)
    for interface in ("wg-unlock", "wg-svc"):                 # its running system's tunnels down (wg-boot takes wg-unlock's port);
        cluster.nodes[crashed].in_ns("ip", "link", "del", interface, check=False)   # the TPM untouched: the same boot
    before = cluster.reset_count(crashed)
    (cluster.nodes[crashed].run / "boot-session").unlink()   # what the client before it left: gone, so it asks again
    asked = time.time()
    results = {}
    workers = [threading.Thread(target=attempt, args=(cluster, results, name), kwargs={"timeout": 150, "rounds": rounds})
               for name, rounds in ((rebooted, 5), (crashed, 2))]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    ok(unlocked(results.get(rebooted, {}), survivor),
       "U: %s, in a new boot, opened its volume through %s's keyslot while %s asked too" % (rebooted, survivor, crashed), results.get(rebooted))
    got = results.get(crashed, {})
    second = "a second boot session in the same boot"           # attest.Verifier's refusal, in the survivor's unlock trail
    denied = [e.get("reason") for e in cluster.trail(survivor) if e.get("event") == "unlock" and e.get("subject") == crashed
              and e.get("outcome") == "DENY" and e.get("at", 0) >= asked - 1]
    ok("error" not in got and got.get("rc") != 0 and got.get("peer") is None and cluster.reset_count(crashed) == before
       and any(second in r for r in denied),
       "N: %s, in the same TPM boot (resetCount %d) with a second session, gets no key from %s, which says why: %s"
       % (crashed, before, survivor, second), {"client": got, "denied": denied})
    cluster.stop(crashed)                                       # the power cycle: a new boot
    ok(cluster.reset_count(crashed) == before + 1, "%s power-cycled: resetCount %d -> %d" % (crashed, before, cluster.reset_count(crashed)))
    since = time.time()
    got = cluster.unlock(crashed)
    ok(unlocked(got, survivor), "U: %s, in its new boot, opened its volume through %s's keyslot" % (crashed, survivor), got)
    for name in (crashed, rebooted):
        cluster.start(name, SERVICES)
    ok(until(lambda: leased(cluster, crashed, survivor, since), 120, 2) is True, "L: %s holds a lease %s issued" % (crashed, survivor),
       cluster.journal(crashed, "admission")[-600:])
    until(lambda: cluster.lease(rebooted), 120, 2)

    header("6  PoC 10.5, the rate limits: sync's leases per node, and one node does not use up another's")
    # b's own admission stopped (its asks would spend the same bucket), and a minute for the bucket to fill
    sh("systemctl", "stop", cluster.unit("b", "admission"), check=False)
    time.sleep(61)
    count, per = 6, 60                                   # deploy/baremetal/sync.py RATE["lease"]
    since = time.time()
    answers = cluster.ask("b", "a", "lease-nonce", times=count + 1, node_id="b")
    ok([a.get("ok") for a in answers] == [True] * count + [False]
       and "RATE: more than %d lease requests in %d s from b" % (count, per) in answers[-1].get("refused", ""),
       "a answered b's first %d lease requests in a minute and refused the next: %s" % (count, answers[-1].get("refused")), answers[-2:])
    ok(any(e.get("event") == "sync-lease-nonce" and e.get("subject") == "b" and e.get("outcome") == "DENY" and "RATE" in e.get("reason", "")
           and e.get("at", 0) >= since - 1 for e in cluster.trail("a")), "a's trail records the refusal")
    answers = cluster.ask("c", "a", "lease-nonce", node_id="c")
    ok(answers[0].get("ok") is True, "c, beside it, is answered: a lease nonce", answers)
    cluster.start("b", ("admission",))
    until(lambda: cluster.lease("b"), 150, 3)

    header("7  N: a quarantined, then retired; b reported stolen: no key, no lease, and why")
    for victim, signer, state in (("a", "owner", "QUARANTINED"), ("a", "root", "RETIRED"), ("b", "owner", "REVOKED_STOLEN")):
        before = cluster.manifest
        survivors = [n for n in names if n != victim and may(before, n, "authorize")]
        # the control: the setup works at this moment (tunnels, endpoints, the survivors' services); only the epoch changes
        subject = victim if may(before, victim, "request") else survivors[-1]
        cluster.stop(subject)
        got = cluster.unlock(subject)
        ok(got.get("rc") == 0 and got.get("peer") in survivors and got.get("marker"),
           "control: %s, at epoch %d, still opens its volume through %s's keyslot" % (subject, before["epoch"], got.get("peer")), got)
        cluster.start(subject, SERVICES)
        until(lambda: cluster.lease(subject), 120, 2)

        cluster.stop(victim)                            # down when it is revoked: it takes the epoch as a stopped node
        seed = survivors[0]
        manifest, since = cluster.advance(seed, signer=signer, **{victim: state})
        counting = [s for s in survivors if s in cluster.manifest["heartbeat_signers"]["parties"] and cluster.running(s)
                    and may(manifest, s, "authorize")]
        if len(counting) == 1:
            # #199: one node left that counts. Nobody can co-sign its heartbeat for the new epoch: it stays without one
            # (fail closed) until the operator's hand recovery, owner.py beat, which the scenario now plays explicitly
            alone = counting[0]
            ok(not cluster.holds_heartbeat(alone, manifest["epoch"]),
               "%s, the only node left that counts, holds no heartbeat for epoch %d: alone it signs nothing" % (alone, manifest["epoch"]))
            envelope = cluster.owner_beat(alone)
            lives = threenode.heartbeat.parse_time(envelope["heartbeat"]["expires_at"], "e") - threenode.heartbeat.parse_time(envelope["heartbeat"]["issued_at"], "i")
            ok(cluster.holds_heartbeat(alone, manifest["epoch"]) and cluster.heartbeat_signers(alone) == [alone, "owner"] and lives <= 3600,
               "the hand recovery (owner.py beat): %s and the owner's key sign a heartbeat for epoch %d that lives %d s (at most 1 h)"
               % (alone, manifest["epoch"], lives), envelope["heartbeat"])
        pulled = [s for s in survivors if s != seed]
        ok(all(cluster.node(s).store().load()["epoch"] == manifest["epoch"] for s in survivors)
           and all(any(e.get("event") == "sync-apply" and e.get("peer") == seed and e.get("outcome") == "ALLOW" and e.get("at", 0) >= since
                       for e in cluster.trail(s)) for s in pulled),
           "epoch %d (%s %s, by the %s key) given to %s; %s took it from %s by sync"
           % (manifest["epoch"], victim, state, signer, seed, ", ".join(pulled) or "nobody else", seed))
        boot_key, svc_key = cluster.keys[victim]["boot"][1], cluster.keys[victim]["service"][1]
        cut = until(lambda: all(boot_key not in cluster.wg_peers(s, "wg-unlock") for s in survivors), 60, 2)
        ok(cut is True, "why no key: %s's wg-apply (run again by the new chain) dropped %s from wg-unlock" % (", ".join(survivors), victim),
           {s: sorted(cluster.wg_peers(s, "wg-unlock")) for s in survivors})
        got = cluster.unlock(victim, timeout=120, rounds=2)
        ok(got["rc"] != 0 and got["peer"] is None, "N: %s, %s at epoch %d, gets no key from %s"
           % (victim, state, manifest["epoch"], ", ".join(survivors)), got)
        since = time.time()
        cluster.start(victim, SERVICES)
        refused = "may not serve under epoch %d" % manifest["epoch"]

        def why():
            # refused at the nonce (#332: the verifier is the current manifest's, and a node that may not serve gets no
            # nonce) or at the lease itself: the same reason either way
            denied = [s for s in survivors if any(e.get("event") in ("sync-lease-nonce", "sync-lease") and e.get("subject") == victim
                                                  and e.get("outcome") == "DENY"
                                                  and refused in e.get("reason", "") and e.get("at", 0) >= since for e in cluster.trail(s))]
            if denied:
                return "%s refused its lease request: %s" % (", ".join(denied), refused)
            if state in ("RETIRED", "REVOKED_STOLEN") and all(svc_key not in cluster.wg_peers(s, "wg-svc") for s in survivors):
                return "%s dropped it from wg-svc: it cannot ask" % ", ".join(survivors)
            return None
        reason = until(why, 90, 3)
        ok(bool(reason) and not cluster.lease(victim) and not any(leased_by(cluster, s, victim, since) for s in survivors),
           "N: and no lease, because %s" % reason, cluster.journal(victim, "admission")[-400:])
        cluster.stop(victim)


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
