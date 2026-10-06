"""deploy/baremetal/drill.py (#495): the partition's order and its read-backs, preflight, the runner's abort and
restore, and the report."""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import unittest

from deploy.baremetal import drill, membership as m


class FakeServer:
    """One server's nftables table and systemd timer, as `ssh(node, argv, input)` sees them."""

    def __init__(self, fail=None):
        self.table = self.timer = False
        self.calls, self.fail = [], fail or (lambda argv: False)

    def __call__(self, node, argv, input=None):
        self.calls.append((node, list(argv), input))
        rc = 0
        if self.fail(argv):
            rc = 1
        elif argv[:2] == ["systemd-run", "--unit"]:
            self.timer = True
        elif argv[:3] == ["nft", "-f", "-"]:
            self.table = True
        elif argv[:3] == ["nft", "delete", "table"]:
            rc = 0 if self.table else 1
            self.table = False
        elif argv[:3] == ["nft", "list", "table"]:
            rc = 0 if self.table else 1
        elif argv[:3] == ["systemctl", "is-active", "--quiet"]:
            rc = 0 if self.timer else 3
        elif argv[:2] == ["systemctl", "stop"]:
            self.timer = False
        return subprocess.CompletedProcess(argv, rc, "", "refused" if rc else "")

    def verbs(self):
        return [" ".join(argv[:3]) for _, argv, _ in self.calls]


class Partition(unittest.TestCase):
    def test_the_way_back_is_armed_before_the_table_and_both_are_read_back(self):
        server = FakeServer()
        done = drill.Partition(server).install("b", 600)
        verbs = server.verbs()
        armed, checked, loaded = verbs.index("systemd-run --unit regalia-drill-unpartition"), verbs.index("nft -c -f"), verbs.index("nft -f -")
        self.assertLess(armed, checked)                   # the dead-man timer FIRST
        self.assertLess(checked, loaded)                  # nft -c before nft -f
        self.assertEqual(verbs[loaded + 1:], ["nft list table", "systemctl is-active --quiet"])   # read back after
        self.assertEqual((server.table, server.timer, done["node"], done["ttl"]), (True, True, "b", 600))
        timer = next(argv for _, argv, _ in server.calls if argv[0] == "systemd-run")
        self.assertIn("--on-active=600s", timer)
        self.assertEqual(timer[-5:], ["/usr/sbin/nft", "delete", "table", "inet", drill.TABLE])

    def test_the_ruleset_drops_wg_svc_both_ways_and_nothing_else(self):
        rules = drill.ruleset()
        self.assertEqual(rules.count("drop"), 4)
        self.assertEqual(rules.count("udp dport 51821 drop") + rules.count("udp sport 51821 drop"), 4)
        self.assertNotIn("51820", rules)                  # the boot mesh, SSH and the collector stay up
        self.assertNotIn("policy drop", rules)
        self.assertIn("table inet %s" % drill.TABLE, rules)

    @unittest.skipUnless(shutil.which("nft") and os.geteuid() == 0, "nft -c needs nft and root (CI's runners)")
    def test_nft_accepts_the_ruleset_without_loading_it(self):
        subprocess.run(["nft", "-c", "-f", "-"], input=drill.ruleset(), text=True, check=True)

    def test_no_table_is_loaded_when_the_timer_cannot_be_armed_or_the_check_fails(self):
        for failing in (lambda argv: argv[0] == "systemd-run", lambda argv: argv[:2] == ["nft", "-c"]):
            server = FakeServer(fail=failing)
            with self.assertRaises(m.Refused):
                drill.Partition(server).install("b", 600)
            self.assertFalse(server.table, "a table was loaded although an earlier step failed")
            self.assertNotIn("nft -f -", server.verbs())

    def test_a_table_that_does_not_read_back_refuses_the_drill(self):
        server = FakeServer()
        real = server.__call__
        server_calls = []

        def lying(node, argv, input=None):
            if argv[:3] == ["nft", "list", "table"] and server.table:   # loaded, but it does not read back
                server_calls.append(argv)
                return subprocess.CompletedProcess(argv, 1, "", "")
            return real(node, argv, input)
        with self.assertRaisesRegex(m.Refused, "refused to go on"):
            drill.Partition(lying).install("b", 600)
        self.assertTrue(server_calls)

    def test_an_existing_partition_or_timer_is_not_stacked(self):
        server = FakeServer()
        server.timer = True
        with self.assertRaisesRegex(m.Refused, "already holds"):
            drill.Partition(server).install("b", 600)
        self.assertEqual([v for v in server.verbs() if v.startswith(("systemd-run", "nft -f"))], [])

    def test_bounds_on_the_node_and_the_timer(self):
        server = FakeServer()
        for node, ttl in (("b; rm -rf /", 600), ("b", 30), ("b", 7200), ("b", True), ("B", 600)):
            with self.assertRaises(m.Refused):
                drill.Partition(server).install(node, ttl)
        self.assertEqual(server.calls, [])

    def test_removal_deletes_the_table_stops_the_timer_and_reads_back(self):
        server = FakeServer()
        cut = drill.Partition(server)
        cut.install("b", 600)
        cut.remove("b")
        self.assertEqual((server.table, server.timer), (False, False))
        cut.remove("b")                                   # again, with nothing there: still fine
        server.fail = lambda argv: argv[:3] == ["nft", "delete", "table"]
        cut.install("b", 600)
        with self.assertRaises(m.Refused):
            cut.remove("b")


class Preflight(unittest.TestCase):
    def test_every_check_runs_and_any_failure_refuses_naming_it(self):
        ran = []

        def check(name, good):
            def run():
                ran.append(name)
                if good is None:
                    raise OSError("no route to the iLO")
                return good, "%s saw this" % name
            return name, run
        with self.assertRaises(m.Refused) as caught:
            drill.preflight([check("three serving", True), check("ilo b", None), check("canary only", False)], required=())
        self.assertEqual(ran, ["three serving", "ilo b", "canary only"])
        self.assertIn("ilo b (the check failed: OSError: no route to the iLO)", str(caught.exception))
        self.assertIn("canary only (canary only saw this)", str(caught.exception))
        self.assertNotIn("three serving", str(caught.exception))
        self.assertEqual([r["ok"] for r in drill.preflight([check("x", True)], required=())], [True])

    def test_a_required_check_cannot_be_dropped(self):
        # d9 on #498: the canary check (and #495's other required checks) must be in the list, whoever builds it
        every = [(name, lambda: (True, "fine")) for name in drill.REQUIRED_CHECKS]
        self.assertEqual(len(drill.preflight(every)), len(drill.REQUIRED_CHECKS))
        without = [(name, check) for name, check in every if name != "canary-only"]
        with self.assertRaisesRegex(m.Refused, "the required check\\(s\\) canary-only are not in the list"):
            drill.preflight(without)


class Run(unittest.TestCase):
    def scenario(self, name, log, passed=True, raises=None):
        def inject():
            log.append("inject " + name)
            if raises:
                raise raises
            return {"node": "b"}

        def judge():
            log.append("judge " + name)
            return {"zero_failures": (passed, "0 failed of 120")}
        return {"name": name, "inject": inject, "judge": judge}

    def test_all_pass_and_restore_runs_once_at_the_end(self):
        log = []
        out = drill.run([self.scenario("S1", log), self.scenario("S2", log)], abort=lambda: None,
                        restore=lambda: log.append("restore") or {"ok": True})
        self.assertTrue(out["passed"])
        self.assertEqual(log, ["inject S1", "judge S1", "inject S2", "judge S2", "restore"])

    def test_an_abort_stops_injecting_restores_and_fails_the_run(self):
        log, asks = [], []

        def abort():
            asks.append(1)
            return "PIN retries dropped on b (3 -> 2)" if len(asks) == 2 else None
        out = drill.run([self.scenario("S1", log), self.scenario("S2", log)], abort=abort, restore=lambda: log.append("restore"))
        self.assertEqual(log, ["inject S1", "restore"])  # aborted right after the first injection: nothing judged, nothing more injected
        self.assertFalse(out["passed"])
        self.assertIn("ABORTED: after injecting S1: PIN retries dropped", out["stopped"])

    def test_a_failing_injection_or_predicate_fails_the_run_and_still_restores(self):
        log = []
        out = drill.run([self.scenario("S1", log, raises=OSError("iLO timed out"))], abort=lambda: None, restore=lambda: log.append("restore"))
        self.assertEqual((out["passed"], log[-1]), (False, "restore"))
        self.assertIn("OSError: iLO timed out", out["stopped"])
        log = []
        out = drill.run([self.scenario("S1", log, passed=False)], abort=lambda: None, restore=lambda: None)
        self.assertFalse(out["passed"])
        self.assertIsNone(out["stopped"])
        self.assertFalse(out["scenarios"][0]["passed"])

    def test_a_restore_that_fails_is_recorded_not_hidden(self):
        def broken():
            raise RuntimeError("b did not power on")
        out = drill.run([self.scenario("S1", [])], abort=lambda: None, restore=broken)
        self.assertEqual(out["restored"], {"failed": "RuntimeError: b did not power on"})

    def test_no_scenario_is_not_a_pass(self):
        self.assertFalse(drill.run([], abort=lambda: None, restore=lambda: None)["passed"])


class Report(unittest.TestCase):
    def test_canonical_bytes_and_their_digest(self):
        data, digest = drill.report("2026-10-06-q4", "operator-a", "witness-b", {"passed": True}, {"epoch": 3})
        document = json.loads(data)
        self.assertEqual((document["schema"], document["passed"], document["run_id"]), (drill.REPORT_SCHEMA, True, "2026-10-06-q4"))
        self.assertEqual(data, m.canonical(document))
        import hashlib
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_two_people_and_a_plain_run_id(self):
        for operator, witness, run_id in (("a", "a", "r1"), ("a", "", "r1"), ("a", "b", "r 1"), ("a", "b", "../x")):
            with self.assertRaises(m.Refused):
                drill.report(run_id, operator, witness, {}, {})


class FailedInstall(unittest.TestCase):
    def test_a_failed_install_leaves_no_timer_and_no_table(self):
        # 24 on #498: after the timer is armed, any later failure takes it (and a loaded table) back
        for failing in (lambda argv: argv[:2] == ["nft", "-c"], lambda argv: argv[:3] == ["nft", "-f", "-"]):
            server = FakeServer(fail=failing)
            with self.assertRaises(m.Refused):
                drill.Partition(server).install("b", 600)
            self.assertEqual((server.table, server.timer), (False, False))


class Journal(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.path = os.path.join(self.d, "faults.jsonl")

    def test_restore_replays_every_pending_undo_newest_first_and_marks_it(self):
        journal = drill.Journal(self.path)
        first = journal.fault("power-off", "c", {"action": "power-on", "node": "c"})
        second = journal.fault("partition", "b", {"action": "unpartition", "node": "b"})
        done = []
        restored, failed = journal.restore({"power-on": lambda n: done.append(("on", n)), "unpartition": lambda n: done.append(("cut", n))})
        self.assertEqual(done, [("cut", "b"), ("on", "c")])                  # newest first
        self.assertEqual(([r["id"] for r in restored], failed, journal.pending()), ([second, first], [], []))
        self.assertEqual(journal.restore({}), ([], []))                     # nothing left to do

    def test_a_failed_undo_stays_pending_and_is_said(self):
        journal = drill.Journal(self.path)
        journal.fault("power-off", "c", {"action": "power-on", "node": "c"})
        restored, failed = journal.restore({"power-on": drill.power_on_by_hand})
        self.assertEqual(restored, [])
        self.assertIn("power c on through its iLO by hand", failed[0]["error"])
        self.assertEqual(len(journal.pending()), 1)

    def test_a_torn_last_line_is_a_fault_to_check_by_hand_and_a_bad_middle_line_refuses(self):
        journal = drill.Journal(self.path)
        journal.fault("partition", "b", {"action": "unpartition", "node": "b"})
        with open(self.path, "ab") as f:
            f.write(b'{"kind": "fault", "id": 2, "act')                  # power lost mid-append
        undone = []
        restored, failed = journal.restore({"unpartition": undone.append})
        self.assertEqual(undone, ["b"])                                    # the readable fault is still undone
        self.assertEqual([f["id"] for f in failed], [0])
        self.assertIn("the journal's last line is torn", failed[0]["error"])
        # the undone line was NOT glued onto the torn one: the journal still reads, the torn fault still pending
        self.assertEqual([e["undo"]["action"] for e in journal.pending()], ["torn"])
        journal.fault("power-off", "c", {"action": "power-on", "node": "c"})   # and later faults are fine too
        self.assertEqual(len(journal.pending()), 2)
        restored, failed = journal.restore({"power-on": undone.append}, torn_checked=True)
        self.assertEqual((undone[-1], failed, journal.pending()), ("c", [], []))
        bad = os.path.join(self.d, "bad.jsonl")                          # an unreadable line that is not a torn write
        with open(bad, "wb") as f:
            f.write(m.canonical({"kind": "fault", "id": 1, "action": "x", "node": "b", "undo": {"action": "unpartition", "node": "b"}})
                    + b"\nnot json\n" + m.canonical({"kind": "undone", "id": 1}) + b"\n")
        with self.assertRaisesRegex(m.Refused, "unreadable line 2 that is neither its last nor marked torn"):
            drill.Journal(bad).entries()

    def test_the_fault_is_on_disk_before_the_cut_and_restore_undoes_it(self):
        # the journal line exists before the server is touched at all
        seen = []
        server = FakeServer()

        def ssh(node, argv, input=None):
            if not seen:
                seen.append([e["kind"] for e in drill.Journal(self.path).entries()])
            return server(node, argv, input)
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drill.main(["partition", "--node", "b", "--journal", self.path], ssh=ssh), 0)
        self.assertEqual(seen, [["fault"]])
        self.assertTrue(server.table)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drill.main(["restore", "--journal", self.path], ssh=server), 0)
        self.assertEqual((server.table, server.timer, drill.Journal(self.path).pending()), (False, False, []))


class Canary(unittest.TestCase):
    def test_every_key_must_be_canary_in_the_key_state_store(self):
        store = {"canary-sign-1": "canary-sign", "prod-validator": "cosmos-validator", "named-canary-but-not": "sign",
                 "canary-validator": "cosmos-validator"}                    # NAMED canary-*, a production key in the store
        self.assertEqual(drill.canary_only(["canary-sign-1"], store.get)[0], True)
        good, saw = drill.canary_only(["canary-sign-1", "prod-validator", "named-canary-but-not"], store.get)
        self.assertFalse(good)
        self.assertIn("prod-validator", saw)
        self.assertIn("named-canary-but-not", saw)                        # the name does not count, the store does
        good, saw = drill.canary_only(["canary-sign-1", "canary-validator"], store.get)
        self.assertFalse(good, "a key NAMED canary-* whose purpose in the store is production passed")
        self.assertIn("canary-validator", saw)
        self.assertEqual(drill.canary_only([], store.get)[0], False)        # no key named: not a canary run


class Signals(unittest.TestCase):
    def test_sigterm_mid_run_still_restores_and_fails_the_run(self):
        log = []

        def inject():
            os.kill(os.getpid(), signal.SIGTERM)
            log.append("after the signal")                               # never reached
        before = signal.getsignal(signal.SIGTERM)
        out = drill.run([{"name": "S1", "inject": inject, "judge": lambda: {}}], abort=lambda: None,
                        restore=lambda: log.append("restore"))
        self.assertEqual(log, ["restore"])
        self.assertIn("ABORTED: signal %d" % signal.SIGTERM, out["stopped"])
        self.assertIs(signal.getsignal(signal.SIGTERM), before)              # the handler put back


class Integers(unittest.TestCase):
    def test_times_are_integer_ms_and_a_float_or_nan_is_refused(self):
        out = drill.run([{"name": "S1", "inject": lambda: {}, "judge": lambda: {"x": (True, "y")}}], abort=lambda: None,
                        restore=lambda: None, clock=lambda: 1791228593.25)
        self.assertEqual(out["scenarios"][0]["started_ms"], 1791228593250)
        drill.report("r1", "a", "b", out, {})
        for bad in (0.5, float("nan")):
            with self.assertRaisesRegex(m.Refused, "float|NaN"):
                drill.report("r1", "a", "b", {"passed": True, "rtt": [1, {"x": bad}]}, {})


class FakeIlo:
    def __init__(self, node, log):
        self.node, self.log = node, log

    def force_off(self):
        self.log.append(("off", self.node))
        return {"outcome": "Off", "node": self.node}

    def power_on(self):
        self.log.append(("on", self.node))
        return {"outcome": "On", "node": self.node, "readbacks": [{"power": "Off"}, {"power": "PoweringOn"}, {"power": "On"}]}


class HardwareBackend(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.journal = drill.Journal(os.path.join(self.d, "faults.jsonl"))
        self.log, self.server = [], FakeServer()

        def ssh(node, argv, input=None):
            self.log.append(("ssh", node, argv[0], [e["action"] for e in self.journal.pending()]))
            if argv == ["systemctl", "reboot"]:
                return subprocess.CompletedProcess(argv, 255, "", "Connection closed by remote host")
            return self.server(node, argv, input)

        def ilo(node):
            pending = [e["action"] for e in self.journal.pending()]
            self.log.append(("journal at iLO call", node, pending))
            return FakeIlo(node, self.log)
        self.hw = drill.Hardware(self.journal, ssh, ilo)

    def test_every_fault_is_journaled_before_it_is_injected_and_undone_after(self):
        self.hw.power_off("c")
        self.assertEqual(self.log[:2], [("journal at iLO call", "c", ["power-off"]), ("off", "c")])
        self.hw.power_on("c")
        self.assertEqual(self.journal.pending(), [])
        self.hw.restart("b")                                             # 255: the connection dropping with the reboot
        self.assertEqual(self.log[-1], ("ssh", "b", "systemctl", ["restart"]))
        self.assertEqual(self.journal.pending()[0]["undo"], {"action": "power-cycle", "node": "b"})
        self.hw.restarted("b")
        self.hw.partition("a")
        self.assertEqual([e["action"] for e in self.journal.pending()], ["partition"])
        self.hw.heal("a")
        self.assertEqual((self.journal.pending(), self.server.table), ([], False))

    def test_restore_powers_on_through_the_ilo_and_heals(self):
        self.hw.power_off("c")
        self.hw.partition("a")
        restored, failed = self.journal.restore(self.hw.undoers())
        self.assertEqual(failed, [])
        self.assertIn(("on", "c"), self.log)
        self.assertFalse(self.server.table)

    def test_scenarios_bind_each_their_own_node(self):
        # a regression: lambdas read a shared name, and every scenario hit the last planned node
        judged = []
        built = drill.scenarios(self.hw, {"S1": "c", "S2": "b", "S3": "a", "S5": ["a", "b"]},
                                lambda name, ctx: judged.append((name, ctx.get("node"))) or {"seen": (True, name)})
        out = drill.run(built, abort=lambda: None, restore=lambda: None)
        self.assertTrue(out["passed"], out)
        self.assertIn(("off", "c"), self.log)
        self.assertIn(("on", "c"), self.log)
        self.assertEqual([n for name, n in judged if name in ("S1", "S2", "S3")], ["c", "b", "a"])
        self.assertEqual([n for name, n in judged if name == "S5-wait"], ["a", "b"])
        self.assertEqual(self.journal.pending(), [])                     # every fault the run made, undone by it
        self.assertEqual([s["scenario"] for s in out["scenarios"]], ["S1", "S2", "S3", "S5"])
        self.assertIn("recovered", out["scenarios"][0])

    def test_what_the_recovery_must_show_counts_and_can_fail_the_scenario(self):
        def judge(name, ctx):
            if name == "S1-back":
                return {"caught up before serving": (False, "served at revision 7 below the lease's 9")}
            return {"seen": (True, name)}
        out = drill.run(drill.scenarios(self.hw, {"S1": "c", "S3": "a"}, judge), abort=lambda: None, restore=lambda: None)
        s1, s3 = out["scenarios"]
        self.assertFalse(s1["passed"])
        self.assertFalse(s1["predicates"]["after recovery: caught up before serving"]["ok"])
        self.assertTrue(s3["passed"])
        self.assertIn("after recovery: seen", s3["predicates"])            # S3-healed judged too
        self.assertFalse(out["passed"])

    def test_s5_stops_when_a_server_does_not_come_back_and_leaves_its_restart_pending(self):
        # d9 on #504: rolling on would have two of three down
        def judge(name, ctx):
            if name == "S5-wait" and ctx["node"] == "b":
                return {"it serves again": (False, "no serving line in 240 s")}
            return {"seen": (True, name)}
        restarted = []
        out = drill.run(drill.scenarios(self.hw, {"S5": ["a", "b", "c"]}, judge), abort=lambda: None, restore=lambda: None)
        self.assertIn("ABORTED: S5: b did not come back", out["stopped"])
        self.assertFalse(out["passed"])
        self.assertNotIn(("ssh", "c", "systemctl", ["restart"]), [x for x in self.log if x[0] == "ssh"])   # c never restarted
        self.assertEqual([(e["node"], e["undo"]["action"]) for e in self.journal.pending()], [("b", "power-cycle")])

    def test_s2_leaves_its_restart_pending_when_its_predicates_fail(self):
        out = drill.run(drill.scenarios(self.hw, {"S2": "b"}, lambda name, ctx: {"back": (False, "not serving")}),
                        abort=lambda: None, restore=lambda: None)
        self.assertFalse(out["passed"])
        self.assertIn("left pending", out["scenarios"][0]["recovered"])
        self.assertEqual([e["undo"] for e in self.journal.pending()], [{"action": "power-cycle", "node": "b"}])

    def test_a_power_cycle_undo_is_by_hand_until_the_client_can(self):
        self.hw.restart("b")
        restored, failed = self.journal.restore(self.hw.undoers())
        self.assertIn("power-cycle b through its iLO by hand", failed[0]["error"])

    def test_a_power_on_without_a_final_on_readback_leaves_the_fault_pending(self):
        class Stuck(FakeIlo):
            def power_on(self):
                return {"outcome": "timeout", "readbacks": [{"power": "Off"}, {"power": "Off"}]}
        hw = drill.Hardware(self.journal, lambda *a, **k: None, lambda node: Stuck(node, []))
        hw.power_off("c")
        with self.assertRaisesRegex(m.Refused, "did not read back On"):
            hw.power_on("c")
        self.assertEqual(len(self.journal.pending()), 1)

    def test_restore_says_serving_is_not_confirmed_for_every_power_undo(self):
        self.hw.power_off("c")
        self.hw.partition("a")
        restored, failed = self.journal.restore(self.hw.undoers())
        lines = drill.restore_summary(restored, failed + [{"error": "b: power-cycle by hand"}])
        self.assertIn("c: powered On by readback; SERVING NOT CONFIRMED. Check that c serves (or that RegaliaNodeDown has "
                      "cleared) before you leave", lines)
        self.assertIn("a: unpartition done", lines)
        self.assertIn("STILL PENDING: b: power-cycle by hand", lines)

    def test_a_plan_with_no_scenario_is_refused(self):
        with self.assertRaises(m.Refused):
            drill.scenarios(self.hw, {}, lambda name, ctx: {})


if __name__ == "__main__":
    unittest.main()
