"""deploy/baremetal/drill.py (#495): the partition's order and its read-backs, preflight, the runner's abort and
restore, and the report."""
import json
import os
import shutil
import subprocess
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
            drill.preflight([check("three serving", True), check("ilo b", None), check("canary only", False)])
        self.assertEqual(ran, ["three serving", "ilo b", "canary only"])
        self.assertIn("ilo b (the check failed: OSError: no route to the iLO)", str(caught.exception))
        self.assertIn("canary only (canary only saw this)", str(caught.exception))
        self.assertNotIn("three serving", str(caught.exception))
        self.assertEqual([r["ok"] for r in drill.preflight([check("x", True)])], [True])


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


if __name__ == "__main__":
    unittest.main()
