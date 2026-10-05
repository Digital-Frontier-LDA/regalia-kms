#!/usr/bin/env python3
"""The production burn-in and recurring failure drills on the real three servers (#495; the procedure is the private
RUNBOOK-KMS-FAULT-DRILLS.md, "Production burn-in and recurring drills").

    python3 -Es -m deploy.baremetal.drill partition --node b --ttl 600        # S3's cut, with its dead-man timer
    python3 -Es -m deploy.baremetal.drill unpartition --node b
    (preflight, run S1..S5, restore and the report come with their pieces: below)

It runs on an operator workstation on the management network, never on the offline signing laptop or a server. It
INJECTS faults and records evidence; the pass criteria are the predicates shared with tier N (e2e/lib/drills.py,
regalia-kms-48), so "passed in CI" and "passed on the servers" mean the same thing.

THIS SLICE (3e): the runner's frame, every seam a callable:
  * Partition: S3's cut. A drill-only nftables table on the server dropping UDP 51821 (wg-svc: sync, leases,
    heartbeats, etcd's peers) in and out; UDP 51820, SSH and the collector's path stay up. In this order, each step
    checked: the dead-man timer ARMED FIRST (a transient systemd timer that deletes the table, so a workstation that
    dies mid-drill cannot leave a server cut off), `nft -c` on the ruleset, then `nft -f`; then both the table and the
    timer are read back before anything else is injected. Never persisted: a reboot clears it. Removal deletes the
    table, stops the timer, and reads back that the table is gone.
  * Journal: the WORKSTATION's fault journal (d9 and 24 on #498). A powered-off server has no dead-man of its own (iLO 4
    has no timed power-on), so every fault is written with its undo and fsynced BEFORE it is injected, and marked undone
    after; `restore --journal FILE` replays every undo still pending, newest first, a failed one left pending and said.
    The witness has iLO access for the power scenarios. Until d9's Redfish client lands, the power undo says to power
    the server on by hand.
  * preflight(checks): every check run, the drill refused if any fails, each named with what it saw. canary_only()
    is one of them: every key the load uses is canary-* in the KMS's KEY-STATE STORE, not by its name.
  * run(scenarios, abort): each scenario's inject, then its judge, with `abort()` asked between every step; restore
    ALWAYS runs (finally), also on SIGTERM or SIGHUP (they stop the run as an abort), and an abort ends the run as
    failed with its reason. Run it under systemd-run or tmux, so a closed terminal is not a SIGKILL.
  * The report (regalia.drill-report/v1): its canonical bytes and SHA-256, every time integer ms, a float or NaN
    refused. It is SIGNED BY THE KMS ITSELF with the
    drill-report key, a canary key and approval-free (regalia-kms-24 on #495), so the signature is the run's last
    end-to-end check, and the collector's receipt is its timestamp. Neither the developer card (D30.7: no KMS keys) nor
    the owner's card (kept for owner acts; it signs only S4's recovery authorization). Signing and shipping come with
    ed's mTLS client.

NOT IN THIS SLICE (each its own PR, by its owner): the Redfish client (d9, redfish.py, shared with D32's G1 fence),
the load generator (ed, e2e/lib/loadgen.py), the predicates (48, e2e/lib/drills.py), the Gate's gate-serving line
(ed), signing (the KMS's drill-report key) and shipping the report. Until they land, `run` has nothing to inject or judge with.
"""
import argparse
import contextlib
import hashlib
import json
import math
import os
import re
import shlex
import signal
import subprocess
import sys
import time

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

TABLE = "regalia_drill"                    # inet family: drill-only, never another tool's
WG_SVC_PORT = 51821                        # wg-svc: every runtime inter-node path (48 on #495)
TIMER_UNIT = "regalia-drill-unpartition"
TTL_MIN, TTL_MAX = 60, 3600                # a cut longer than an hour is not a drill
REPORT_SCHEMA = "regalia.drill-report/v1"
NODE = re.compile(r"[a-z][a-z0-9-]{0,31}")


def ruleset():
    """The partition's nftables ruleset: its own table, two chains, UDP 51821 dropped in and out. Nothing else."""
    return ("table inet %s {\n"
            "  chain input { type filter hook input priority -10; policy accept; udp dport %d drop; udp sport %d drop; }\n"
            "  chain output { type filter hook output priority -10; policy accept; udp dport %d drop; udp sport %d drop; }\n"
            "}\n" % (TABLE, WG_SVC_PORT, WG_SVC_PORT, WG_SVC_PORT, WG_SVC_PORT))


class Partition:
    """S3's cut on one server, through `ssh(node, argv, input=None)` -> CompletedProcess (as root there)."""

    def __init__(self, ssh):
        self.ssh = ssh

    def _run(self, node, argv, input=None, what=""):
        done = self.ssh(node, argv, input=input)
        require(done.returncode == 0, "%s on %s failed (exit %s): %s" % (what or argv[0], node, done.returncode,
                                                                         (done.stderr or done.stdout or "").strip()[:300]))
        return done

    def present(self, node):
        """(the table is loaded, the dead-man timer is active) on `node`."""
        table = self.ssh(node, ["nft", "list", "table", "inet", TABLE]).returncode == 0
        timer = self.ssh(node, ["systemctl", "is-active", "--quiet", TIMER_UNIT + ".timer"]).returncode == 0
        return table, timer

    def install(self, node, ttl):
        require(NODE.fullmatch(node or "") is not None, "the node %r is not a node name" % (node,))
        require(isinstance(ttl, int) and not isinstance(ttl, bool) and TTL_MIN <= ttl <= TTL_MAX,
                "the dead-man timer is %d to %d s, not %r" % (TTL_MIN, TTL_MAX, ttl))
        table, timer = self.present(node)
        require(not table and not timer, "%s already holds a drill partition or its timer: remove it first (unpartition)" % node)
        # 1. the way back FIRST: whatever happens to the workstation from here, the table goes when the timer fires
        self._run(node, ["systemd-run", "--unit", TIMER_UNIT, "--on-active=%ds" % ttl, "--timer-property=AccuracySec=1s",
                         "/usr/sbin/nft", "delete", "table", "inet", TABLE], what="arming the dead-man timer")
        try:
            # 2. the ruleset checked, then loaded; never persisted (no file under /etc/nftables*)
            self._run(node, ["nft", "-c", "-f", "-"], input=ruleset(), what="nft -c")
            self._run(node, ["nft", "-f", "-"], input=ruleset(), what="loading the partition")
            # 3. both read back before anything else is injected
            table, timer = self.present(node)
            require(table and timer, "after the partition, %s reads table=%s timer=%s: refused to go on" % (node, table, timer))
        except BaseException:
            # nothing half-done is left behind: the table (if it loaded) and the timer go (24 on #498)
            with contextlib.suppress(Exception):
                self.remove(node)
            raise
        return {"node": node, "ttl": ttl, "installed_at_ms": int(time.time() * 1000)}

    def remove(self, node):
        if self.present(node)[0]:
            self._run(node, ["nft", "delete", "table", "inet", TABLE], what="removing the partition")
        self.ssh(node, ["systemctl", "stop", TIMER_UNIT + ".timer"])        # gone already if it fired
        table, _ = self.present(node)
        require(not table, "%s still holds the drill table after its removal" % node)
        return {"node": node, "removed_at_ms": int(time.time() * 1000)}


class Journal:
    """The workstation's fault journal (d9 and 24 on #498): every fault is written, with how to undo it, and fsynced
    BEFORE it is injected; marked undone after its undo. A powered-off server has no dead-man of its own (iLO 4 has no
    timed power-on), so if the workstation or this process dies, `drill.py restore --journal FILE` replays the undo of
    every fault not marked undone, newest first. Append-only JSON lines; the file is never rewritten."""

    def __init__(self, path):
        self.path = path

    def _append(self, entry):
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, membership.canonical(entry) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    def entries(self):
        try:
            with open(self.path, "rb") as f:
                return [json.loads(line) for line in f.read().splitlines() if line.strip()]
        except FileNotFoundError:
            return []

    def fault(self, action, node, undo):
        """Record a fault BEFORE it is injected. `undo` is {"action", "node"}, what restore does. Returns its id."""
        fault_id = len([e for e in self.entries() if e.get("kind") == "fault"]) + 1
        self._append({"kind": "fault", "id": fault_id, "action": action, "node": node, "undo": undo,
                      "at_ms": int(time.time() * 1000)})
        return fault_id

    def undone(self, fault_id):
        self._append({"kind": "undone", "id": fault_id, "at_ms": int(time.time() * 1000)})

    def pending(self):
        """The faults not undone, newest first."""
        done = {e["id"] for e in self.entries() if e.get("kind") == "undone"}
        return [e for e in reversed(self.entries()) if e.get("kind") == "fault" and e["id"] not in done]

    def restore(self, undoers):
        """Each pending fault's undo, newest first, through undoers[undo["action"]](node); each marked undone once it
        succeeds. Returns (done, failed): a failed undo stays pending, said, and is tried again next time."""
        done, failed = [], []
        for entry in self.pending():
            undo = entry["undo"]
            try:
                undoers[undo["action"]](undo["node"])
            except Exception as failure:              # noqa: BLE001 - each fault's undo tried; the rest go on
                failed.append({"id": entry["id"], "undo": undo, "error": "%s: %s" % (type(failure).__name__, failure)})
                continue
            self.undone(entry["id"])
            done.append({"id": entry["id"], "undo": undo})
        return done, failed


def canary_only(keys, purpose_of):
    """A preflight check (24 on #498): every key the load uses is a canary key IN THE KMS's KEY-STATE STORE
    (`purpose_of(key)` reads it), not only by its name. Returns (ok, what it saw)."""
    if not keys:
        return False, "the load names no key"
    wrong = {key: purpose_of(key) for key in keys}
    wrong = {key: purpose for key, purpose in wrong.items() if not (isinstance(purpose, str) and purpose.startswith("canary-"))}
    return (not wrong), ("every key's purpose is canary-*" if not wrong else "not canary in the key-state store: %s" % wrong)


def preflight(checks):
    """Each (name, check) run; check() -> (ok, what it saw). Returns the results; refuses if any failed."""
    results = []
    for name, check in checks:
        try:
            good, saw = check()
        except Exception as failure:                  # noqa: BLE001 - a check that cannot run has not passed
            good, saw = False, "the check failed: %s: %s" % (type(failure).__name__, failure)
        results.append({"check": name, "ok": bool(good), "saw": saw})
    failed = [r for r in results if not r["ok"]]
    require(not failed, "preflight refused: %s" % "; ".join("%s (%s)" % (r["check"], r["saw"]) for r in failed))
    return results


class Aborted(Refused):
    pass


class Stopped(BaseException):
    """SIGTERM or SIGHUP: the run stops, and restore still runs (24 on #498: a signal must not skip `finally`)."""


@contextlib.contextmanager
def signals_stop_the_run():
    def stop(number, _frame):
        raise Stopped("signal %d" % number)
    previous = {n: signal.signal(n, stop) for n in (signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _ms(clock):
    return int(clock() * 1000)


def run(scenarios, abort, restore, clock=time.time):
    """Each scenario: {"name", "inject": callable, "judge": callable -> {predicate: (ok, evidence)}}. `abort()` returns
    a reason to stop, or None; it is asked before each inject, after it and after the judge. `restore()` ALWAYS runs at
    the end, also on SIGTERM or SIGHUP. Returns the per-scenario results; an abort, a signal or an exception ends the
    run, recorded as failed. Times are integer milliseconds."""
    results, stopped = [], None

    def check(when):
        reason = abort()
        if reason:
            raise Aborted("%s: %s" % (when, reason))

    def scenarios_in_turn():
        for scenario in scenarios:
            entry = {"scenario": scenario["name"], "started_ms": _ms(clock)}
            results.append(entry)
            check("before %s" % scenario["name"])
            entry["injected_ms"] = _ms(clock)
            entry["injection"] = scenario["inject"]()
            check("after injecting %s" % scenario["name"])
            entry["predicates"] = {name: {"ok": bool(good), "evidence": evidence}
                                   for name, (good, evidence) in scenario["judge"]().items()}
            entry["passed"] = bool(entry["predicates"]) and all(p["ok"] for p in entry["predicates"].values())
            entry["ended_ms"] = _ms(clock)
            check("after judging %s" % scenario["name"])
    try:
        with signals_stop_the_run():
            scenarios_in_turn()
    except (Exception, Stopped) as failure:           # noqa: BLE001 - recorded, then restore, then the run is failed
        stopped = "%s: %s" % ("ABORTED" if isinstance(failure, (Aborted, Stopped)) else type(failure).__name__, failure)
    finally:
        try:
            restored = restore()
        except Exception as failure:                  # noqa: BLE001 - a restore that fails is an incident, said
            restored = {"failed": "%s: %s" % (type(failure).__name__, failure)}
    return {"scenarios": results, "stopped": stopped, "restored": restored,
            "passed": stopped is None and bool(results) and all(r.get("passed") for r in results)}


def _no_floats(value, where):
    """The report's canonical bytes hold no float (24 on #498: times are integer ms; a float's text and NaN are not
    canonical across languages). Refused, naming where."""
    if isinstance(value, float):
        raise Refused("%s holds a float (%r): times are integer milliseconds" % (where, value) if not math.isnan(value)
                      else "%s holds NaN" % where)
    if isinstance(value, dict):
        for key, item in value.items():
            _no_floats(item, "%s.%s" % (where, key))
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _no_floats(item, "%s[%d]" % (where, i))


def report(run_id, operator, witness, outcome, context):
    """The report's canonical bytes and their SHA-256. The operator and the witness are two people (the runbook)."""
    require(operator and witness and operator != witness, "a drill names an operator and a different witness")
    require(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", run_id or "") is not None, "the run id %r is not plain" % (run_id,))
    document = {"schema": REPORT_SCHEMA, "run_id": run_id, "operator": operator, "witness": witness,
                "passed": bool(outcome.get("passed")), "outcome": outcome, "context": context}
    _no_floats(document, "the report")
    data = membership.canonical(document)
    return data, hashlib.sha256(data).hexdigest()


def ssh_runner(host_of, user="root"):
    """ssh(node, argv, input) over OpenSSH, as `user` on host_of(node), the command quoted, batch mode (no prompt)."""
    def ssh(node, argv, input=None):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "%s@%s" % (user, host_of(node)),
                               " ".join(shlex.quote(a) for a in argv)], input=input, capture_output=True, text=True, timeout=60)
    return ssh


def power_on_by_hand(node):
    """The power undo until the Redfish client lands (d9, redfish.py): said, never pretended."""
    raise Refused("the Redfish client is not built yet: power %s on through its iLO by hand, then run restore again" % node)


def main(argv=None, ssh=None):
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.drill", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="op", required=True)
    for name in ("partition", "unpartition"):
        p = sub.add_parser(name)
        p.add_argument("--node", required=True)
        p.add_argument("--host", help="the node's SSH address (default: the node name)")
        p.add_argument("--journal", required=True, help="the workstation's fault journal (restore --journal replays it)")
        if name == "partition":
            p.add_argument("--ttl", type=int, default=600, help="the dead-man timer, seconds (%d to %d)" % (TTL_MIN, TTL_MAX))
    p = sub.add_parser("restore", help="undo every fault the journal holds that is not marked undone, newest first")
    p.add_argument("--journal", required=True)
    p.add_argument("--host", action="append", default=[], metavar="NODE=ADDRESS", help="a node's SSH address")
    args = ap.parse_args(argv)
    if args.op == "restore":
        hosts = dict(h.split("=", 1) for h in args.host)
        address = lambda node: hosts.get(node, node)                                  # noqa: E731
    else:
        address = lambda node: args.host or node                                       # noqa: E731
    cut = Partition(ssh or ssh_runner(address))
    journal = Journal(args.journal)
    try:
        if args.op == "partition":
            journal.fault("partition", args.node, {"action": "unpartition", "node": args.node})   # fsynced BEFORE the cut
            done = cut.install(args.node, args.ttl)
        elif args.op == "unpartition":
            done = cut.remove(args.node)
            for entry in journal.pending():
                if entry["undo"] == {"action": "unpartition", "node": args.node}:
                    journal.undone(entry["id"])
        else:
            restored, failed = journal.restore({"unpartition": cut.remove, "power-on": power_on_by_hand})
            done = {"restored": restored, "still_pending": failed}
            print(json.dumps(done, sort_keys=True))
            return 0 if not failed else 3
    except Refused as refusal:
        print("drill: %s refused: %s" % (args.op, refusal), file=sys.stderr)
        return 1
    print(json.dumps(done, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
