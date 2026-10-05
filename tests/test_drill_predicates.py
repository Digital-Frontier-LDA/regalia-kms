"""e2e/lib/drills.py (#495): the drills' pass criteria, shared by tier N and the real-hardware runner. Each predicate is
shown passing on healthy evidence and failing, with its own reason, on the fault it exists to catch."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "e2e" / "lib"))
import drills  # noqa: E402


def req(start, node, outcome="ok", stateful=False, op="sign", key="canary-sign", end=None):
    return {"start": start, "end": start + 0.05 if end is None else end, "op": op, "key": key, "node": node, "outcome": outcome, "stateful": stateful}


class Predicates(unittest.TestCase):
    def failed(self, result, reason):
        ok, why = result
        self.assertFalse(ok)
        self.assertIn(reason, why)

    def test_failures_only_in_flight(self):
        good = [req(9.9, "a", "failed", end=10.4), req(11, "b")]
        self.assertTrue(drills.failures_only_in_flight(good, 10)[0])
        self.failed(drills.failures_only_in_flight(good + [req(12, "b", "failed")], 10), "not in flight at the injection")
        self.failed(drills.failures_only_in_flight([], 10), "no request at all")

    def test_the_load_ran_throughout(self):
        log = [req(t, "a") for t in (1, 31, 61)]
        self.assertTrue(drills.load_throughout(log, 0, 90)[0])
        self.failed(drills.load_throughout(log[:2], 0, 90), "no request between 60.0 and 90.0")
        self.assertTrue(drills.load_throughout(log, 0, 95)[0])           # a 5 s tail is not judged alone

    def test_zero_failures(self):
        self.assertTrue(drills.zero_failures([req(1, "a"), req(2, "b")])[0])
        self.failed(drills.zero_failures([req(1, "a"), req(2, "b", "failed")]), "1 of 2 requests failed")
        self.failed(drills.zero_failures([]), "no evidence to judge")
        self.failed(drills.zero_failures([req(1, "a")], at_least=10), "fewer than the 10")

    def test_stateful_continues_on_each_up_node(self):
        log = [req(11, "a", stateful=True), req(12, "b", stateful=True)]
        self.assertTrue(drills.stateful_continues(log, {"a", "b"}, 10, 20)[0])
        self.failed(drills.stateful_continues(log[:1], {"a", "b"}, 10, 20), "b committed no stateful operation")

    def test_stateful_in_every_window(self):
        log = [req(t, "a", stateful=True) for t in (1, 31, 61)]
        self.assertTrue(drills.stateful_in_every_window(log, 0, 90)[0])
        self.failed(drills.stateful_in_every_window([log[0], log[2]], 0, 90), "between 30.0 and 60.0")
        self.assertTrue(drills.stateful_in_every_window(log, 0, 93)[0])  # the 3 s tail is not a false fail

    def test_silent_after_the_lease_bound(self):
        bound = drills.LEASE_S + drills.MARGIN_S + drills.WATCH_S
        self.assertTrue(drills.silent_after([req(100 + bound - 1, "c")], "c", 100)[0])
        self.failed(drills.silent_after([req(100 + bound + 1, "c")], "c", 100), "c still served")

    def test_caught_up_before_serving(self):
        good = [{"seq": 1, "event": "gate-not-serving", "reason": "revision-behind"},
                {"seq": 2, "event": "gate-serving", "applied_revision": 40, "lease_state_revision": 40, "state_epoch": 0},
                {"seq": 3, "event": "served"}]
        self.assertTrue(drills.caught_up_before_serving(good)[0])
        early = [{"seq": 1, "event": "served"}] + good[1:]
        self.failed(drills.caught_up_before_serving(early), "with the gate not serving")
        behind = [dict(good[1], applied_revision=39), good[2]]
        self.failed(drills.caught_up_before_serving(behind), "below the lease's 40")
        self.failed(drills.caught_up_before_serving(good[:2]), "not seen serving again")
        stopped = good + [{"seq": 4, "event": "gate-not-serving", "reason": "watch-stalled"}, {"seq": 5, "event": "served"}]
        self.failed(drills.caught_up_before_serving(stopped), "seq 5")

    def test_survivor_full_scope(self):
        profile = {"acct": "cosmos-account", "val": "cosmos-validator"}.get
        stateless = [req(t, "a") for t in range(5, 1030, 20)]
        log = stateless + [req(1000, "a", stateful=True, key="acct")]
        run = lambda extra, rows=None: drills.survivor_full_scope((rows if rows is not None else log) + extra, "a", {"b", "c"}, 1, 960, profile, 1030)  # noqa: E731
        self.assertTrue(run([])[0])
        self.failed(run([req(900, "a", stateful=True, key="acct")]), "before full scope")
        self.failed(run([req(1001, "a", stateful=True, key="val")]), "cosmos-validator key")
        self.failed(run([req(2, "b")]), "after its power readback")
        self.failed(run([], stateless), "everything did not stay active")
        gap = [r for r in log if not (300 <= r["start"] < 400)]
        self.failed(run([], gap), "answered no stateless request")

    def test_the_load_generator_s_line_becomes_a_request(self):
        line = {"start_ms": 1700000000123, "end_ms": 1700000000373, "op": "sign", "key": "canary-cosmos", "node": "b",
                "outcome": "ABORTED", "attempt": 1, "drill": "r1", "stateful": True}
        r = drills.from_loadgen(line)
        self.assertEqual((r["start"], r["end"], r["outcome"], r["stateful"], r["node"]), (1700000000.123, 1700000000.373, "failed", True, "b"))
        self.assertEqual(drills.from_loadgen(dict(line, outcome="ok", stateful=False))["outcome"], "ok")

    def test_a_line_without_stateful_is_refused_never_defaulted(self):
        """ed: no inference; a sign with a sequenced Cosmos key is stateful, which only the load generator knows."""
        line = {"start_ms": 1, "end_ms": 2, "op": "sign", "key": "k", "node": "a", "outcome": "ok", "attempt": 1, "drill": "r1"}
        with self.assertRaises(drills.Malformed) as caught:
            drills.from_loadgen(line)
        self.assertIn("without 'stateful' is refused", str(caught.exception))
        with self.assertRaises(drills.Malformed):
            drills.from_loadgen(dict(line, stateful="yes"))

    def test_the_bounds_are_deploy_s(self):
        """3e on #497: drills.py may not import deploy; these hold its copies equal to the source."""
        import inspect
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        from deploy.baremetal import admission, lease
        self.assertEqual((drills.LEASE_S, drills.MARGIN_S), (lease.MAX_LIFETIME, admission.MARGIN))
        self.assertEqual(drills.WATCH_S, inspect.signature(admission.Service.run).parameters["watch"].default)


if __name__ == "__main__":
    unittest.main()
