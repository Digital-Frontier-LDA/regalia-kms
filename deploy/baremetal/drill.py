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
    ALWAYS runs (finally), also on SIGTERM, SIGHUP or SIGINT (they stop the run as an abort), and an abort ends the run as
    failed with its reason. Run it under systemd-run or tmux, so a closed terminal is not a SIGKILL.
  * The report (regalia.drill-report/v1): its canonical bytes and SHA-256, every time integer ms, a float or NaN
    refused. It is SIGNED BY THE KMS ITSELF with the
    drill-report key, a canary key and approval-free (regalia-kms-24 on #495), so the signature is the run's last
    end-to-end check, and the collector's receipt is its timestamp. Neither the developer card (D30.7: no KMS keys) nor
    the owner's card (kept for owner acts; it signs only S4's recovery authorization). Signing and shipping come with
    ed's mTLS client.

  * Hardware: the real servers' faults over a backend interface (power_off/power_on through d9's redfish.Client, restart
    in-band over SSH, partition/heal), every fault journaled before it is injected and its undo marked after; and
    scenarios(backend, plan, judge): S1, S2, S3 and S5 as run() takes them, each with its own node and a recover step,
    judged by the caller's predicates. The tier-N fixture's backend (e2e/lib/drillfixture.py) runs the same scenarios.

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

from deploy.baremetal import lease, membership

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
        fd = os.open(self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b"\n":
                # a torn last write (power lost mid-append): ended, and marked, so the next line is not glued onto it
                os.write(fd, b"\n" + membership.canonical({"kind": "torn-line"}) + b"\n")
            os.write(fd, membership.canonical(entry) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    TORN = {"kind": "fault", "id": 0, "action": "unknown", "node": "?", "undo": {"action": "torn", "node": "?"}}

    def entries(self):
        """The journal's entries. A line that does not parse is a write torn by a power loss (d9 on #498) only if it is the
        LAST line, or the next is the "torn-line" marker _append writes after one: it stands for a fault whose undo is
        unknown (restore refuses it: every server to be checked by hand, then `restore --torn-checked`). A bad line
        anywhere else is not a torn write: refused."""
        try:
            with open(self.path, "rb") as f:
                lines = [line for line in f.read().splitlines() if line.strip()]
        except FileNotFoundError:
            return []
        def marker(i):
            try:
                return i < len(lines) and json.loads(lines[i]) == {"kind": "torn-line"}
            except ValueError:
                return False
        out = []
        for i, line in enumerate(lines):
            try:
                out.append(json.loads(line))
            except ValueError:
                require(i == len(lines) - 1 or marker(i + 1), "the fault journal %s has an unreadable line %d that is neither "
                        "its last nor marked torn: refused" % (self.path, i + 1))
                out.append(dict(self.TORN))
        return [e for e in out if e != {"kind": "torn-line"}]

    def fault(self, action, node, undo):
        """Record a fault BEFORE it is injected. `undo` is {"action", "node"}, what restore does. Returns its id."""
        fault_id = len([e for e in self.entries() if e.get("kind") == "fault" and e.get("id")]) + 1
        self._append({"kind": "fault", "id": fault_id, "action": action, "node": node, "undo": undo,
                      "at_ms": int(time.time() * 1000)})
        return fault_id

    def undone(self, fault_id):
        self._append({"kind": "undone", "id": fault_id, "at_ms": int(time.time() * 1000)})

    def pending(self):
        """The faults not undone, newest first."""
        done = {e["id"] for e in self.entries() if e.get("kind") == "undone"}
        return [e for e in reversed(self.entries()) if e.get("kind") == "fault" and e["id"] not in done]

    def undone_matching(self, undo):
        """Every pending fault whose undo is `undo`, marked undone (a power-on or a heal done by the run itself)."""
        for entry in self.pending():
            if entry["undo"] == undo:
                self.undone(entry["id"])

    def restore(self, undoers, torn_checked=False):
        """Each pending fault's undo, newest first, through undoers[undo["action"]](node); each marked undone once it
        succeeds. Returns (done, failed): a failed undo stays pending, said, and is tried again next time. `torn_checked`:
        the operator has checked every server by hand after a torn write, which clears it."""
        if torn_checked and any(e["undo"]["action"] == "torn" for e in self.pending()):
            self.undone(0)
        done, failed = [], []
        for entry in self.pending():
            undo = entry["undo"]
            if undo["action"] == "torn":
                failed.append({"id": 0, "undo": undo, "error": "the journal's last line is torn (power lost mid-write): the fault it "
                               "recorded is unknown. Check every server by hand: its power (iLO) and `nft list table inet %s`" % TABLE})
                continue
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


# #495 section 2: what preflight must have checked, by name, before a drill may start (d9 on #498: a caller cannot drop
# one, the canary check above all)
REQUIRED_CHECKS = ("three-serving", "etcd-healthy", "collector-current", "monitoring-reachable", "ilo-reachable",
                   "canary-only", "baseline-on-file", "pin-retries-recorded", "operator-and-witness")


def preflight(checks, required=REQUIRED_CHECKS):
    """Each (name, check) run; check() -> (ok, what it saw). Returns the results; refuses if any failed, or if any
    `required` check is missing from the list."""
    missing = [name for name in required if name not in {name for name, _ in checks}]
    require(not missing, "preflight refused: the required check(s) %s are not in the list" % ", ".join(missing))
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
    """SIGTERM, SIGHUP or SIGINT (Ctrl-C at the console): the run stops, and restore still runs (24 on #498: a signal must not skip `finally`)."""


STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)    # SIGINT too (cc on #498): Ctrl-C during restore


@contextlib.contextmanager
def signals_stop_the_run(state=None):
    """Installed for the whole run, restore included (CodeRabbit on #498: a SIGTERM during restore must not kill it).
    The first signal while `state["raise"]` raises Stopped, once; any later one, or one after the scenarios ended, is
    only recorded in `state["late"]`."""
    state = {} if state is None else state
    state.update({"raise": True, "late": []})

    def stop(number, _frame):
        if not state["raise"]:
            state["late"].append(number)
            return
        state["raise"] = False
        raise Stopped("signal %d" % number)
    previous = {n: signal.signal(n, stop) for n in STOP_SIGNALS}
    try:
        yield state
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _ms(clock):
    return int(clock() * 1000)


def run(scenarios, abort, restore, clock=time.time):
    """Each scenario: {"name", "inject": callable, "judge": callable -> {predicate: (ok, evidence)}}. `abort()` returns
    a reason to stop, or None; it is asked before each inject, after it and after the judge. `restore()` ALWAYS runs at
    the end, also on SIGTERM, SIGHUP or SIGINT. Returns the per-scenario results; an abort, a signal or an exception ends the
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
            check("after judging %s" % scenario["name"])
            if scenario.get("recover"):                # the fault undone (a server powered back on, a cut healed)
                recovered = scenario["recover"]()
                # what the recovery itself must show (a returning server catching up before it serves) counts too
                after = recovered.pop("predicates", {}) if isinstance(recovered, dict) else {}
                entry["recovered"] = recovered
                for name, (good, evidence) in after.items():
                    entry["predicates"]["after recovery: " + name] = {"ok": bool(good), "evidence": evidence}
                entry["passed"] = bool(entry["predicates"]) and all(p["ok"] for p in entry["predicates"].values())
                check("after recovering %s" % scenario["name"])
            entry["ended_ms"] = _ms(clock)

    def said(failure):
        return "%s: %s" % ("ABORTED" if isinstance(failure, (Aborted, Stopped)) else type(failure).__name__, failure)
    with signals_stop_the_run() as signals:
        try:
            try:
                scenarios_in_turn()
                signals["raise"] = False              # from here a signal is recorded, never raised: restore runs whole
            except (Exception, Stopped) as failure:   # noqa: BLE001 - recorded, then restore, then the run is failed
                signals["raise"] = False
                stopped = said(failure)
        except Stopped as late:                       # a signal while an earlier failure was handled (cc on #498): both said
            first = late.__context__
            stopped = "%s; then %s" % (said(first), said(late)) if first is not None else said(late)
        finally:
            try:
                restored = restore()
            except Exception as failure:              # noqa: BLE001 - a restore that fails is an incident, said
                restored = {"failed": "%s: %s" % (type(failure).__name__, failure)}
    out = {"scenarios": results, "stopped": stopped, "restored": restored}
    if signals["late"]:
        out["late_signals"] = signals["late"]
        out["stopped"] = stopped or "ABORTED: signal %d after the scenarios" % signals["late"][0]
    out["passed"] = out["stopped"] is None and bool(results) and all(r.get("passed") for r in results)
    return out


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


# rollout.may_reboot as `update apply` asks it, read-only: as root on the node, on fresh leases from its peers, its running
# set from its TPM (the same check as e2e/rolling-threenode.py's DECIDE). Prints {"ok": true, ...} or {"ok": false,
# "reason": ...}. S5 asks it before each restart (#504's red under lease v2, #489: a peer restarted less than one lease ago
# issues no lease yet, so restarting the next node then leaves the third with no issuer).
MAY_REBOOT = (
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
HOST_CONFIG = "/etc/regalia/node.json"
HOST_CODE = "/usr/lib/regalia-kms"          # the units' WorkingDirectory: where `deploy` is imported from on a host
MAY_RESTART_PATIENCE_S = 3 * lease.MAX_LIFETIME    # as rolling-threenode's moved(): a WAIT is asked again until then


def ask_again_after(reason):
    """Seconds before may_reboot is asked again after a WAIT: the most "ask again in N s" among its refusals (an issuer's
    warm-up, lease.py), else one lease; at least 1 s. Each ask takes a real lease from every peer, from the same rate
    bucket as the node's own admission renewals (sync.RATE), so asking every few seconds could cost the node its lease
    (62 on #504)."""
    found = [int(n) for n in re.findall(r"ask again in (\d+) s", reason)]
    return max(1, max(found) if found else lease.MAX_LIFETIME)


def verdict_of(done, node):
    """may_reboot's printed verdict from a finished process; a failure to ask is a refusal, never a yes."""
    if done.returncode != 0:
        return {"ok": False, "reason": "may_reboot could not be asked on %s (exit %s): %s"
                % (node, done.returncode, ((done.stderr or "") + (done.stdout or "")).strip()[-300:])}
    try:
        verdict = json.loads((done.stdout or "").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "reason": "may_reboot on %s printed no verdict: %r" % (node, (done.stdout or "")[-200:])}
    if not isinstance(verdict, dict) or verdict.get("ok") is not True:
        return dict(verdict if isinstance(verdict, dict) else {}, ok=False,
                    reason=str((verdict.get("reason") if isinstance(verdict, dict) else None) or "no yes from may_reboot"))
    return verdict


def ssh_runner(host_of, user="root"):
    """ssh(node, argv, input) over OpenSSH, as `user` on host_of(node), the command quoted, batch mode (no prompt)."""
    def ssh(node, argv, input=None):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "%s@%s" % (user, host_of(node)),
                               " ".join(shlex.quote(a) for a in argv)], input=input, capture_output=True, text=True, timeout=60)
    return ssh


class Hardware:
    """The real servers' faults, each JOURNALED before it is injected (Journal.fault, fsynced), its undo marked when the
    run itself undoes it:
      power_off / power_on   redfish.Client (d9, #501): ForceOff or On, PowerState read back; the record returned
      restart                in-band `systemctl reboot` over SSH (iLO 4 has no GracefulRestart); its undo, should the
                             server not come back, is a power-on
      partition / heal       S3's Partition (the dead-man timer first)
      may_restart            rollout.may_reboot on the node over SSH (MAY_REBOOT), read-only: S5 asks it before each restart
    `redfish_for(node)` -> a redfish.Client for that server; `ssh(node, argv, input=None)`."""

    def __init__(self, journal, ssh, redfish_for, ttl=600):
        self.journal, self.ssh, self.redfish_for, self.ttl = journal, ssh, redfish_for, ttl
        self.cut = Partition(ssh)

    def power_off(self, node):
        self.journal.fault("power-off", node, {"action": "power-on", "node": node})
        return self.redfish_for(node).force_off()

    def power_on(self, node):
        record = self.redfish_for(node).power_on()
        # undone only on the final readback of On (d9 on #504): anything else leaves the fault pending for restore
        readbacks = record.get("readbacks") or []
        require(readbacks and readbacks[-1].get("power") == "On", "%s did not read back On after power-on: %s" % (node, record))
        self.journal.undone_matching({"action": "power-on", "node": node})
        return record

    def restart(self, node):
        # its undo is a power CYCLE, not a power-on: a server hung while still powered reads "already On" (d9 on #504)
        self.journal.fault("restart", node, {"action": "power-cycle", "node": node})
        done = self.ssh(node, ["systemctl", "reboot"])
        # the connection drops as the server goes down (OpenSSH exits 255): that is the reboot taking, not a failure
        require(done.returncode in (0, 255), "systemctl reboot on %s failed (exit %s): %s" % (node, done.returncode, (done.stderr or "").strip()[:200]))
        return {"node": node, "reboot_asked_ms": int(time.time() * 1000)}

    def restarted(self, node):
        """The restart's server is back (its scenario's predicates held): its fault is undone."""
        self.journal.undone_matching({"action": "power-cycle", "node": node})

    def may_restart(self, node):
        return verdict_of(self.ssh(node, ["env", "-C", HOST_CODE, "python3", "-Es", "-c", MAY_REBOOT],
                                   input=json.dumps({"cfg": HOST_CONFIG})), node)

    def partition(self, node):
        self.journal.fault("partition", node, {"action": "unpartition", "node": node})
        return self.cut.install(node, self.ttl)

    def heal(self, node):
        record = self.cut.remove(node)
        self.journal.undone_matching({"action": "unpartition", "node": node})
        return record

    def power_cycle(self, node):
        """restore's undo of a restart (or a hung server): ForceRestart, power read back On. Marked undone on that
        readback, because otherwise every later restore would power-cycle the server again. Whether it SERVES is the
        next run's mandatory preflight ("three-serving" refuses until it does). Inside a run, S2 and S5 mark a restart
        undone only after their serving predicates hold."""
        client = self.redfish_for(node)
        require(hasattr(client, "force_restart"), "the Redfish client has no force_restart yet (d9, #501): power-cycle %s through "
                "its iLO by hand, then run restore again" % node)
        record = client.force_restart()
        readbacks = record.get("readbacks") or []
        require(readbacks and readbacks[-1].get("power") == "On", "%s did not read back On after its power cycle: %s" % (node, record))
        self.journal.undone_matching({"action": "power-cycle", "node": node})
        return record

    def undoers(self):
        return {"power-on": self.power_on, "power-cycle": self.power_cycle, "unpartition": self.heal}


def _all_ok(predicates):
    return bool(predicates) and all(bool(good) for good, _ in predicates.values())


def scenarios(backend, plan, judge, patience=MAY_RESTART_PATIENCE_S, sleep=time.sleep, monotonic=time.monotonic):
    """S1, S2, S3 and S5 as run() takes them, over any backend with power_off/power_on/restart/restarted/partition/heal
    and may_restart (Hardware here; the tier-N fixture's in e2e/lib/drillfixture.py). `plan`: {"S1": node, "S2": node, "S3": node,
    "S5": [nodes in order]}; only the scenarios it names. `judge(name, context)` -> {predicate: (ok, evidence)}, where
    context holds the injection's times (ms) and records; the predicates are the shared ones (e2e/lib/drills.py). S4
    needs the owner's recovery authorization: not here yet."""
    def now():
        return int(time.time() * 1000)

    # each scenario in its own scope: its node is bound when it is built, never read later from a shared name
    def s1(node):
        ctx = {"node": node}
        def back():                         # S1, then the server powered on: S2's predicates on its return
            ctx.update(on=backend.power_on(node), t_on_ms=now())
            return {"record": ctx["on"], "predicates": judge("S1-back", ctx)}
        return {"name": "S1", "inject": lambda: ctx.update(t_inject_ms=now(), off=backend.power_off(node)) or ctx,
                "judge": lambda: judge("S1", ctx), "recover": back}

    def s2(node):
        ctx = {"node": node}

        def judged():
            ctx["judged"] = judge("S2", ctx)
            return ctx["judged"]

        def back():                         # undone only if it came back as its predicates say (d9 on #504)
            if not _all_ok(ctx.get("judged", {})):
                return {"left pending": "%s's restart: its predicates did not hold; restore power-cycles it" % node}
            backend.restarted(node)
            return {"restarted": node}
        return {"name": "S2", "inject": lambda: ctx.update(t_inject_ms=now(), restart=backend.restart(node)) or ctx,
                "judge": judged, "recover": back}

    def s3(node):
        ctx = {"node": node}
        def healed():                       # on heal it catches up before it serves
            ctx.update(healed=backend.heal(node), t_heal_ms=now())
            return {"record": ctx["healed"], "predicates": judge("S3-healed", ctx)}
        return {"name": "S3", "inject": lambda: ctx.update(t_inject_ms=now(), cut=backend.partition(node)) or ctx,
                "judge": lambda: judge("S3", ctx), "recover": healed}

    def s5(order):
        ctx = {"restarts": []}

        def asked(node):
            """may_reboot, as `update apply` asks it, until a yes; a WAIT (a peer back less than one lease ago issues no
            lease yet, #489) is asked again after the seconds it gives (ask_again_after) until MAY_RESTART_PATIENCE_S; any
            other no, or a WAIT past it, stops the roll and the run (restore then runs), nothing injected on the node."""
            deadline, asks = monotonic() + patience, 0
            while True:
                verdict, asks = backend.may_restart(node), asks + 1
                if verdict.get("ok") is True:
                    return {"ok": True, "asks": asks, "authorizers": verdict.get("authorizers")}
                reason = str(verdict.get("reason", ""))
                left = deadline - monotonic()
                if not reason.startswith("WAIT") or left <= 0:
                    raise Aborted("S5: may_reboot does not let %s restart (%s, after %d asks): the roll stops before it"
                                  % (node, reason, asks))
                # the issuer's hint is in `refused` (fresh_leases), not in may_reboot's reason (62 on #504)
                hints = " ".join([reason] + [str(v) for v in (verdict.get("refused") or {}).values()])
                sleep(max(1, min(ask_again_after(hints), math.ceil(left))))

        def roll():
            for node in order:              # one at a time; each must be BACK, by its predicates, before the next goes down
                may = asked(node)           # and the cluster must let it go: may_reboot says yes first (#504's red, #489)
                ctx["restarts"].append({"node": node, "may_reboot": may, "t_inject_ms": now(), "restart": backend.restart(node)})
                back = judge("S5-wait", dict(ctx, node=node))
                ctx["restarts"][-1]["back"] = {name: {"ok": bool(good), "evidence": evidence} for name, (good, evidence) in back.items()}
                if not _all_ok(back):       # two of three down otherwise (d9 on #504): stop, the fault left pending
                    raise Aborted("S5: %s did not come back (%s): the roll stops, its restart left pending for restore"
                                  % (node, {n: e for n, (g, e) in back.items() if not g}))
                backend.restarted(node)
            return ctx
        return {"name": "S5", "inject": roll, "judge": lambda: judge("S5", ctx)}

    built = [make(plan[name]) for name, make in (("S1", s1), ("S2", s2), ("S3", s3), ("S5", lambda order: s5(list(order))))
             if name in plan]
    require(built, "the plan names no scenario")
    return built


def restore_summary(restored, failed):
    """What restore says to the operator, who is often about to leave (d9 on #504): every server it powered on or
    power-cycled is ON BY READBACK ONLY, its serving not confirmed; every undo that failed is still pending."""
    lines = []
    for entry in restored:
        undo = entry["undo"]
        if undo["action"] in ("power-on", "power-cycle"):
            lines.append("%s: powered On by readback; SERVING NOT CONFIRMED. Check that %s serves (or that RegaliaNodeDown has "
                         "cleared) before you leave" % (undo["node"], undo["node"]))
        else:
            lines.append("%s: %s done" % (undo["node"], undo["action"]))
    for entry in failed:
        lines.append("STILL PENDING: %s" % entry["error"])
    return lines


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
    p.add_argument("--torn-checked", action="store_true", help="after a torn journal write: every server was checked by hand")
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
            restored, failed = journal.restore({"unpartition": cut.remove, "power-on": power_on_by_hand}, torn_checked=args.torn_checked)
            done = {"restored": restored, "still_pending": failed, "summary": restore_summary(restored, failed)}
            for line in done["summary"]:
                print("drill: restore: " + line, file=sys.stderr)
            print(json.dumps(done, sort_keys=True))
            return 0 if not failed else 3
    except Refused as refusal:
        print("drill: %s refused: %s" % (args.op, refusal), file=sys.stderr)
        return 1
    print(json.dumps(done, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
