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

    def test_zero_failures(self):
        self.assertTrue(drills.zero_failures([req(1, "a"), req(2, "b")])[0])
        self.failed(drills.zero_failures([req(1, "a"), req(2, "b", "failed")]), "1 of 2 requests failed")

    def test_stateful_continues_on_each_up_node(self):
        log = [req(11, "a", stateful=True), req(12, "b", stateful=True)]
        self.assertTrue(drills.stateful_continues(log, {"a", "b"}, 10, 20)[0])
        self.failed(drills.stateful_continues(log[:1], {"a", "b"}, 10, 20), "b committed no stateful operation")

    def test_stateful_in_every_window(self):
        log = [req(t, "a", stateful=True) for t in (1, 31, 61)]
        self.assertTrue(drills.stateful_in_every_window(log, 0, 90)[0])
        self.failed(drills.stateful_in_every_window([log[0], log[2]], 0, 90), "between 30.0 and 60.0")

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
        stopped = good + [{"seq": 4, "event": "gate-not-serving", "reason": "watch-stalled"}, {"seq": 5, "event": "served"}]
        self.failed(drills.caught_up_before_serving(stopped), "seq 5")

    def test_survivor_full_scope(self):
        profile = {"acct": "cosmos-account", "val": "cosmos-validator"}.get
        log = [req(5, "a"), req(1000, "a", stateful=True, key="acct")]
        self.assertTrue(drills.survivor_full_scope(log, "a", {"b", "c"}, 1, 960, profile)[0])
        self.failed(drills.survivor_full_scope(log + [req(900, "a", stateful=True, key="acct")], "a", {"b", "c"}, 1, 960, profile),
                    "before full scope")
        self.failed(drills.survivor_full_scope(log + [req(1001, "a", stateful=True, key="val")], "a", {"b", "c"}, 1, 960, profile),
                    "cosmos-validator key")
        self.failed(drills.survivor_full_scope(log + [req(2, "b")], "a", {"b", "c"}, 1, 960, profile), "after its power readback")
        self.failed(drills.survivor_full_scope([req(5, "a")], "a", {"b", "c"}, 1, 960, profile), "everything did not stay active")


if __name__ == "__main__":
    unittest.main()
