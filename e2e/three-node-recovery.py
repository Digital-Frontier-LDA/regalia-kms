#!/usr/bin/env python3
"""#70 (Phase 10), PR 2: every directed peer recovery path, and the nodes that must NOT be restored, on three
nodes (e2e/lib/threenode.py: each its real services in its own namespace, against its own TPM).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> REGALIA_AUDIT_BIN=<dir with built regalia-audit-ship, regalia-audit-collector> \
        sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN,REGALIA_AUDIT_BIN python3 -Es e2e/three-node-recovery.py

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
  5  PoC 10.5: b crashed in its running system (the same boot) asks and is refused for its phase (#397); then the
     session binding: b's initrd, unlocked once, runs its client again in the same TPM boot with
     a second session and a gives it nothing, while c, in a new boot, unlocks through a at the same time; b
     power-cycled then unlocks through a
  6  PoC 10.5, the rate limits: b's lease requests to a, its admission stopped and its bucket full: the
     first 6 in a minute answered, the 7th refused and recorded; c, beside it, answered
  7  N: a QUARANTINED (by the owner's key, #199), then RETIRED (by the root), then b REVOKED_STOLEN (c is then the only
     node that counts: it holds no heartbeat for the epoch until the owner's hand recovery, owner.py beat). In each, a
     control first (a node that may still ask opens its volume: the setup works), then the epoch given to one
     survivor and taken by the others with their sync; the survivors' wg-unlock drops the node; it gets no key,
     and no lease, with the reason (a survivor's DENY naming its state, or it is off wg-svc)
  8  #340: every line of every node's sync and admission trail is in the audit collector (a real collector and each
     node's real shipper: Cluster(audit=True)), and the decisions this scenario turns on are there by name, in the
     stream of the node that made them: every directed unlock of step 2, a's refusal of b's second session (5), a's
     refusal of b's seventh lease request (6), the lone node's refused proposal and its hand recovery (7), and each
     node's change to serving. Not here: the time trail (the fixture's time stand-in writes none) and the update
     trail (1b's call writes none)

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
    # #199: nobody writes a heartbeat here: the nodes sign the first one themselves (beat.Proposer, from bootstrap)
    fresh = cluster.fresh(names, timeout=240)
    ok(all(fresh.values()), "every node holds a heartbeat the nodes signed themselves, from bootstrap (%s)" % fresh, cluster.beat_events(names))
    for name in names:
        held = until(lambda: cluster.lease(name), 120, 2)
        ok(bool(held), "%s holds a runtime lease (epoch %s)" % (name, (held or {}).get("epoch")), cluster.journal(name, "admission")[-600:])

    header("1b  #75: update.py's live leases, the real call: a asks b and c for a lease for its boot, as root in its namespace")
    def live_leases():
        # as root in a's namespace with a's /run/systemd, as update.py runs on its host (#242 B3: its read of a's anchor,
        # written by policy, needs the system-phase key)
        done = cluster.as_root("a", "live-leases-%d" % time.monotonic_ns(), ["/usr/bin/python3", "-Es", "-c", LIVE_LEASES],
                               input=json.dumps({"cfg": str(cluster.nodes["a"].cfg_path)}), in_ns=True)
        if done.returncode != 0:
            raise RuntimeError("update.py's live leases on a failed (%d): %s" % (done.returncode, (done.stderr or done.stdout).strip()[-600:]))
        return json.loads(done.stdout)
    got = live_leases()
    if got["refused"] and all("RATE:" in r for r in got["refused"].values()):
        # a's own admission may have spent its lease requests at b during the bootstrap (6 a minute, sync.RATE): the
        # limit doing its job, not this call's. Once the window has passed, the call is made again, once
        time.sleep(61)
        got = live_leases()
    ok(sorted(got["leases"]) == ["b", "c"] and not got["refused"], "a got a lease from b and from c, each asked once (%s)" % got.get("refused"), got)
    ok(all(v["node_id"] == "a" and v["issuer"] == p and v["this_session"] and v["left"] > 0 for p, v in got["leases"].items()),
       "each names a as subject, its peer as issuer, a's boot session, and verifies under a's manifest now", got)
    ok(got["private_left"] == [], "the leases' private directory under /run is gone when the collection returns", got)

    header("2  PoC 10.1: every directed relationship, X restored by P alone")
    step2 = time.time()
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

    step2_end = time.time()
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
    # b's initrd, having unlocked once in this boot, runs its client again (the TPM untouched: the same boot) and presents
    # a new session; c, power-cycled (a new boot), asks the same survivor at the same time. In its initrd: an unlock is
    # judged in the initrd phase (#396), so a booted system that crashed is refused for its phase before its session
    survivor, crashed, rebooted = "a", "b", "c"
    # #397, first: b crashes in its RUNNING system (its services stop, its TPM does not: PCR 11 in the system phase) and
    # a client asks for its disk with a new session. Refused for its PHASE, before any session is judged: a booted
    # system that crashed never gets its disk key back without a reboot
    cluster.stop(crashed, power=None)
    for interface in ("wg-unlock", "wg-svc"):                 # its running system's tunnels down (wg-boot takes wg-unlock's port)
        cluster.nodes[crashed].in_ns("ip", "link", "del", interface, check=False)
    (cluster.nodes[crashed].run / "boot-session").unlink(missing_ok=True)   # so the client asks rather than standing down
    since = time.time()
    # two rounds to each peer: with the session-binding check's own rounds below, b's unlock requests to a in this minute
    # stay well under the listener's per-subject rate limit (a later added round could otherwise read as a refusal of
    # the session binding when it is the rate's: regalia-kms-48)
    got = cluster.unlock(crashed, timeout=90, rounds=2)
    phase = "the node is in the system phase"                   # each peer's attestation refusal, in its unlock trail
    denied = {p: [e.get("reason") for e in cluster.trail(p) if e.get("event") == "unlock" and e.get("subject") == crashed
                  and e.get("outcome") == "DENY" and e.get("at", 0) >= since - 1] for p in (survivor, rebooted)}
    ok("error" not in got and got.get("rc") != 0 and got.get("peer") is None
       and all(any(phase in (r or "") for r in denied[p]) for p in (survivor, rebooted)),
       "N: %s, crashed in its running system (the same boot, PCR 11 in the system phase), gets no key from %s or %s, both "
       "saying why: %s" % (crashed, survivor, rebooted, phase), {"client": got, "denied": denied})
    survivor_5, crashed_5 = survivor, crashed           # for step 8
    cluster.stop(rebooted)
    cluster.stop(crashed)                                       # a new boot, never started: PCR 11 in the initrd phase
    first = cluster.unlock(crashed)
    if not unlocked(first, survivor):
        raise RuntimeError("%s's first session of the boot was not unlocked through %s: %s" % (crashed, survivor, first))
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
    since = rated = time.time()
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
    alone_at = []                                       # (node, epoch, since) of each hand recovery, for step 8
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
        # who counts is the manifest's (a party that may authorize), never whether its sync is up at this instant: an
        # owner-signed epoch restarts the seed's services, and a check of `running` here once found none, skipped the
        # lone-node branch silently and left step 8 nothing to see (regalia-kms-48 on #440). A survivor that counts must
        # be running; one that is not fails here, by name
        counting = [s for s in survivors if s in cluster.manifest["heartbeat_signers"]["parties"] and may(manifest, s, "authorize")]
        down = [s for s in counting if not until(lambda: cluster.running(s), 60, 1)]
        ok(not down, "every survivor that counts at epoch %d (%s) is running" % (manifest["epoch"], ", ".join(counting)),
           {s: cluster.journal(s, "sync")[-800:] for s in down})
        if len(counting) == 1:
            # #199: one node left that counts. Nobody can co-sign its heartbeat for the new epoch: it stays without one
            # (fail closed) until the operator's hand recovery, owner.py beat, which the scenario now plays explicitly
            alone = counting[0]
            # not vacuous (regalia-kms-3e): wait for its own try at the epoch, refused for want of a co-signer, then look
            tried = until(lambda: [e for e in cluster.trail(alone) if e.get("event") == "beat-propose" and e.get("epoch") == manifest["epoch"]
                                   and e.get("outcome") == "DENY" and "no other node counts" in e.get("reason", "") and e.get("at", 0) >= since],
                          240, 3)
            ok(bool(tried) and not cluster.holds_heartbeat(alone, manifest["epoch"]),
               "%s, the only node left that counts, tried to sign epoch %d's heartbeat, found no co-signer, and holds none: alone it "
               "signs nothing" % (alone, manifest["epoch"]), cluster.beat_events([alone]))
            alone_at.append((alone, manifest["epoch"], since))
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
    # the last epoch (b REVOKED_STOLEN) leaves one node that counts: its hand recovery ran, or this step proved nothing of it
    ok(len(alone_at) == 1, "one node was left alone in step 7 and recovered by hand: %s" % [(n, e) for n, e, _ in alone_at])

    header("8  #340: every line of every node's sync and admission trail is in the audit collector, for the node that recorded it")
    wrong = cluster.audit_complete()
    counts = {"%s.%s" % (n, t): len(cluster.audit_stream(n, t)) for n in names for t in ("sync", "admission")}
    ok(wrong == {}, "every node's sync and admission trail is written and in the collector line for line: sequence from 1, chained from "
       "genesis, each DENY a deny, and its head as the collector's signed receipt and the shipper's head file state it %s" % counts,
       {"%s.%s" % k: v for k, v in wrong.items()})
    # within step 2's own time (later steps unlock too): strictly before the second step 3 began
    gave = {(target, peer): bool([e for e in cluster.audit_has(peer, "sync", since=step2, event="unlock", subject=target, outcome="ALLOW")
                                  if e.get("at", 0) < int(step2_end)])
            for target, peer in itertools.permutations(names, 2)}
    ok(all(gave.values()), "every directed unlock of step 2 is in the stream of the peer that gave it",
       {"%s<-%s" % k: v for k, v in gave.items() if not v})
    second = cluster.audit_has(survivor_5, "sync", since=asked - 1, event="unlock", subject=crashed_5, outcome="DENY",
                               reason=lambda r: bool(r) and "a second boot session in the same boot" in r)
    ok(bool(second), "%s's refusal of %s's second session in one boot (step 5) is in %s's stream" % (survivor_5, crashed_5, survivor_5))
    limited = cluster.audit_has("a", "sync", since=rated - 1, event="sync-lease-nonce", subject="b", outcome="DENY",
                                reason=lambda r: bool(r) and "RATE: more than 6 lease requests in 60 s from b" in r)
    ok(bool(limited), "a's refusal of b's seventh lease request in a minute (step 6) is in a's stream")
    hand = {"%s@%d" % (n, e): (bool(cluster.audit_has(n, "sync", since=t, event="beat-propose", epoch=e, outcome="DENY",
                                                      reason=lambda r: bool(r) and "no other node counts" in r)),
                               bool(cluster.audit_has(n, "sync", since=t, event="owner-beat", epoch=e, outcome="ALLOW")))
            for n, e, t in alone_at}
    ok(bool(hand) and all(all(v) for v in hand.values()),
       "the lone node's refused proposal and its hand recovery (owner-beat) in step 7 are in its own stream %s" % hand, cluster.beat_events(names))
    serving = {n: bool(cluster.audit_has(n, "admission", event="admission-serving", outcome="ALLOW")) for n in names}
    ok(all(serving.values()), "each node's change to serving is in its own admission stream", serving)


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
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK) or not all(
            os.access(os.path.join(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"), b), os.X_OK) for b in ("regalia-audit-ship", "regalia-audit-collector")):
        print("three-node-recovery: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock and REGALIA_AUDIT_BIN a directory "
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
        print("\nthree-node-recovery: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
