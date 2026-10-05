#!/usr/bin/env python3
"""#71 (Phase 11): a total outage, restored by one manual recovery, on three nodes (e2e/lib/threenode.py, v4 since #199:
each node its real services in its own namespace against its own TPM, the nodes signing their own heartbeats; no
authority host; the owner's keys on a SoftHSM token, signed through the real owner.py halves).

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> REGALIA_AUDIT_BIN=<dir with built regalia-audit-ship, regalia-audit-collector> \
        sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN,REGALIA_AUDIT_BIN python3 -Es e2e/three-node-outage.py

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
     (fail closed). Judged by position in a's trail, not by time: after a's first refusal for want of time, no
     signature as proposer or co-signer. One signature already in flight across the switch is allowed (the Proposer
     reads authenticated time once per step): a stated limitation, not a failure
  6  #340: every line of every node's sync, admission and time trail is in the audit collector (a real collector and each
     node's real shipper: Cluster(audit=True)), and the decisions this scenario turns on are there by name, in the
     stream of the node that made them: c's revocation committed (step 4), and a's time no longer authenticated on its
     time trail with its refusals for want of it, as proposer and as co-signer (step 5)
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
    step5 = time.time()                               # for step 6: a's refusals are this step's (regalia-kms-1e on #473)
    # BY POSITION IN a's TRAIL, NOT BY TIME (regalia-kms-48 and 3e): a trail's "at" is whole seconds, and a signature
    # a's Proposer began before its clock read saw the switch is legitimate. So: the trail's last sequence before the
    # switch; then a's first refusal for want of time after it, which must exist; then nothing signed after THAT
    # refusal. Positions are each line's own hash-chained `seq` (trails.py), never a list index, so a rotation or a
    # prune of the file cannot move them. Between the switch and the refusal, one signature in flight is allowed (the
    # Proposer reads the time once per step): the stated limitation (LIMITATIONS.md, Tests)
    switched_at = max([e.get("seq", 0) for e in cluster.trail("a")] or [0])
    cluster.time["a"] = False                        # chrony stops vouching (the stand-in's switch)
    ok(until(lambda: not json.loads((cluster.nodes["a"].run / "authtime.json").read_text())["authenticated"], 30, 1) is True,
       "a's authtime.json says not authenticated")

    def first_refusal():
        # as a proposer: Proposer.step reads authenticated time before it asks whether it is due, and the sync loop
        # records the refusal at once (one line per cause), so a's first loop after the switch says it. Returns
        # ("found", its seq) or None: a value `until` cannot take for false (a seq is never 0, but nothing relies on it)
        seq = next((e.get("seq") for e in cluster.trail("a") if e.get("seq", 0) > switched_at and e.get("event") == "beat-propose"
                    and e.get("outcome") == "DENY" and "time is not authenticated" in (e.get("reason") or "")), None)
        return ("found", seq) if isinstance(seq, int) and not isinstance(seq, bool) else None
    found = until(first_refusal, 180, 3)
    # anything else (None, or an exception `until` gave back at its deadline) is not found
    refused = isinstance(found, tuple) and found[0] == "found"
    refused_at = found[1] if refused else None
    # and as a co-signer (regalia-kms-3e): b's tunnel asks a to co-sign a well-formed body; beat.cosign reads the time
    # before it judges the proposer's signature, so a refuses for want of time, whatever b would have signed
    current = cluster.manifest
    body = {"schema": threenode.heartbeat.SCHEMA, "epoch": current["epoch"], "sequence": 10 ** 6, "issued_at": threenode.beat_stamp(time.time()),
            "expires_at": threenode.beat_stamp(time.time() + 3600), "manifest_digest": threenode.membership.digest(current)}
    answer = cluster.ask("b", "a", "beat-sign", heartbeat=body, signature={"party": "b", "key": "00" * 65, "sig": "00" * 64})[0]
    trail = cluster.trail("a")
    signed = [e for e in trail if refused and e.get("seq", 0) > refused_at and e.get("event") in ("beat-propose", "sync-beat-sign")
              and e.get("outcome") == "ALLOW"]
    in_flight = [e for e in trail if refused and switched_at < e.get("seq", 0) < refused_at and e.get("event") == "beat-propose"
                 and e.get("outcome") == "ALLOW"]
    ok(refused and answer.get("ok") is False and "time is not authenticated" in answer.get("refused", "") and not signed and len(in_flight) <= 1,
       "time no longer authenticated: after its first refusal for want of time, a signs no heartbeat, as proposer or as "
       "co-signer, and says why (fail closed)%s" % (" (one signature in flight across the switch, allowed)" if in_flight else ""),
       {"co-sign answer": answer, "refused at": refused_at, "signed after": signed, "in flight": in_flight, "events": recent(cluster, "a")})

    header("6  #340: every line of every node's sync, admission and time trail is in the audit collector, for the node that recorded it")
    wrong = cluster.audit_complete()
    counts = {"%s.%s" % (n, t): len(cluster.audit_stream(n, t)) for n in names for t, _, _ in threenode.AUDIT_TRAILS}
    ok(wrong == {}, "every node's trails are written and in the collector line for line: sequence from 1, chained from genesis, "
       "each DENY a deny, and its head as the collector's signed receipt and the shipper's head file state it %s" % counts,
       {"%s.%s" % k: v for k, v in wrong.items()})
    revoked = {n: bool(cluster.audit_has(n, "sync", event="revoke-commit", outcome="ALLOW", epoch=2)) for n in ("a", "b")}
    ok(any(revoked.values()), "c's revocation (epoch 2, step 4) committed in the stream of the node that committed it %s" % revoked)
    untimed = lambda r: bool(r) and "time is not authenticated" in r
    # since step 5 began: a node's first rounds after any start may refuse for want of time too, before chrony answers
    as_proposer = cluster.audit_has("a", "sync", since=step5, event="beat-propose", outcome="DENY", reason=untimed)
    as_cosigner = cluster.audit_has("a", "sync", since=step5, event="sync-beat-sign", outcome="DENY", reason=untimed)
    # and the switch itself, on a's TIME trail (#303: authtime records each change between authenticated and not)
    switched = cluster.audit_has("a", "time", since=step5, event="time-unauthenticated")
    ok(bool(as_proposer) and bool(as_cosigner) and bool(switched),
       "a's time no longer authenticated (step 5) is in a's time stream (%d), and its refusals for want of it, as proposer (%d) "
       "and as co-signer (%d), in its sync stream" % (len(switched), len(as_proposer), len(as_cosigner)))


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
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK) or not all(
            os.access(os.path.join(os.environ.get("REGALIA_AUDIT_BIN", "/nonexistent"), b), os.X_OK) for b in ("regalia-audit-ship", "regalia-audit-collector")):
        print("three-node-outage: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock and REGALIA_AUDIT_BIN a directory "
              "with the built regalia-audit-ship and regalia-audit-collector (#340)")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work, audit=True)                    # the nodes' trails shipped to a real collector (#340)
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
