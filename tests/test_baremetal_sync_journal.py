"""#470: regalia-sync says in the journal what each pull round did, one line per source, rate-bounded; the trail stays
the record (the DENY line carries the reason the trail recorded, word for word)."""
import unittest
from unittest import mock

from deploy.baremetal import node as nodemod
from deploy.baremetal.membership import Refused


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class RoundLogLines(unittest.TestCase):
    def setUp(self):
        self.clock, self.lines = Clock(), []
        self.log = nodemod.RoundLog(clock=self.clock, out=self.lines.append)

    def test_each_outcome_has_its_line(self):
        self.log.pulled("b", 3, 4)
        self.log.pulled("c", 4, 4)
        self.log.pulled("d", None, 1)
        self.log.refused("b", Refused("b did not answer (ConnectionRefusedError)"), {"event": "sync-apply", "reason": "b did not answer (ConnectionRefusedError)"})
        self.log.refused("c", Refused("ROLLBACK: epoch 2"), {"event": "sync-apply", "reason": "ROLLBACK: epoch 2"})
        self.log.refused("d", Refused("'x' is not a configured source"), None)
        self.assertEqual(self.lines, [
            "applied epoch 4 from b (held 3 before)",
            "nothing newer from c: epoch 4 held",
            "applied epoch 1 from d (held none before)",
            "peer b did not answer (ConnectionRefusedError)",
            "DENY sync-apply from c: ROLLBACK: epoch 2",
            "DENY pull from d: 'x' is not a configured source",
        ])

    def test_the_same_outcome_is_said_once_per_repeat_window_per_source(self):
        for _ in range(5):
            self.log.pulled("b", 4, 4)
            self.log.pulled("c", 4, 4)                       # another source has its own window
            self.clock.now += 60
        self.assertEqual(self.lines, ["nothing newer from b: epoch 4 held", "nothing newer from c: epoch 4 held"])
        self.clock.now += nodemod.RoundLog.REPEAT_S
        self.log.pulled("b", 4, 4)
        self.assertEqual(self.lines[-1], "nothing newer from b: epoch 4 held")
        self.assertEqual(len(self.lines), 3)

    def test_a_changed_outcome_is_said_at_once(self):
        self.log.pulled("b", 4, 4)
        self.log.refused("b", Refused("b did not answer (TimeoutError)"), None)
        self.log.refused("b", Refused("b did not answer (ConnectionRefusedError)"), None)   # another error class
        self.log.refused("b", Refused("b did not answer (ConnectionRefusedError)"), None)
        self.log.pulled("b", 4, 4)
        self.assertEqual(self.lines, ["nothing newer from b: epoch 4 held", "peer b did not answer (TimeoutError)",
                                      "peer b did not answer (ConnectionRefusedError)", "nothing newer from b: epoch 4 held"])

    def test_a_varying_number_in_a_deny_does_not_defeat_the_bound(self):
        for seconds in range(5):
            reason = "the heartbeat expires in %d s" % (100 - seconds)
            self.log.refused("b", Refused(reason), {"event": "sync-heartbeat", "reason": reason})
        self.assertEqual(self.lines, ["DENY sync-heartbeat from b: the heartbeat expires in 100 s"])

    def test_a_reason_cannot_forge_a_second_line(self):
        reason = "bad\napplied epoch 99 from b (held 1 before)"
        self.log.refused("b", Refused(reason), {"event": "sync-apply\nx", "reason": reason})
        self.assertEqual(len(self.lines), 1)
        self.assertNotIn("\n", self.lines[0])
        self.assertTrue(self.lines[0].startswith("DENY sync-apply"))

    def test_a_deny_says_which_decision_and_why(self):
        event = {"event": "sync-heartbeat", "reason": "the heartbeat is older than the one held"}
        self.log.refused("b", Refused(event["reason"]), event)
        self.log.refused("b", Refused("another"), {"event": "sync-heartbeat", "reason": "another"})
        self.assertEqual(self.lines, ["DENY sync-heartbeat from b: the heartbeat is older than the one held",
                                      "DENY sync-heartbeat from b: another"])


class FakeClient:
    """sync.Client's pull, scripted per source: an epoch reached, or a refusal with the events it records."""
    script = {}

    def __init__(self, node_id, store, freshness, transports, sink, documents=None):
        self.sink, self.store = sink, store

    def pull(self, source):
        outcome = self.script[source]
        if isinstance(outcome, int):
            self.sink({"event": "sync-apply", "epoch": self.store.epoch, "outcome": "ALLOW", "reason": ""})
            self.store.epoch = outcome
            return {"epoch": outcome}, None
        for event in outcome[1]:
            self.sink(event)
        raise Refused(outcome[0])


class Store:
    epoch = 5
    loads = 0

    def load(self):
        Store.loads += 1
        return {"epoch": self.epoch}


class PullRound(unittest.TestCase):
    """node.Sync.pull_round: each source's outcome reaches the journal, and every event still reaches the trail first."""

    def setUp(self):
        self.trail, self.lines = [], []
        s = nodemod.Sync.__new__(nodemod.Sync)
        s.node = mock.Mock(node_id="a", sources=lambda man: {"b": None, "c": None, "d": None}, documents=lambda: None)
        s.store, s.freshness, s.trail = Store(), None, self.trail.append
        s.manifest = s.store.load
        s.publish = lambda: False
        s.rounds = nodemod.RoundLog(clock=Clock(), out=self.lines.append)
        self.sync = s

    def test_one_line_per_source(self):
        deny = {"event": "sync-apply", "outcome": "DENY", "reason": "CONFLICT: epoch 6"}
        FakeClient.script = {"b": 6, "c": ("CONFLICT: epoch 6", [deny]),
                             "d": ("d did not answer (TimeoutError)", [dict(deny, reason="d did not answer (TimeoutError)")])}
        with mock.patch.object(nodemod.sync, "Client", FakeClient):
            self.sync.pull_round()
        self.assertEqual(self.lines, ["applied epoch 6 from b (held 5 before)", "DENY sync-apply from c: CONFLICT: epoch 6",
                                      "peer d did not answer (TimeoutError)"])
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW", "DENY", "DENY"])

    def test_the_round_loads_the_store_no_more_than_before(self):
        """The held epoch comes from the sync-apply event, not a store load per source (3e's read: a load is a
        chain verification and a TPM read)."""
        FakeClient.script = {"b": 6, "c": 6, "d": 6}
        Store.loads = 0
        with mock.patch.object(nodemod.sync, "Client", FakeClient):
            self.sync.pull_round()
        self.assertEqual(Store.loads, 1)                    # the round's manifest(), once, as before #470
        self.assertEqual(self.lines, ["applied epoch 6 from b (held 5 before)", "nothing newer from c: epoch 6 held",
                                      "nothing newer from d: epoch 6 held"])

    def test_a_deny_line_names_this_sources_event_not_an_earlier_ones(self):
        FakeClient.script = {"b": ("first", [{"event": "sync-heartbeat", "outcome": "DENY", "reason": "first"}]),
                             "c": ("'c' is not a configured source", []), "d": 5}
        with mock.patch.object(nodemod.sync, "Client", FakeClient):
            self.sync.pull_round()
        self.assertEqual(self.lines, ["DENY sync-heartbeat from b: first", "DENY pull from c: 'c' is not a configured source",
                                      "nothing newer from d: epoch 5 held"])

    def test_a_journal_that_cannot_be_written_never_stops_the_round(self):
        published = []

        def broken(line):
            raise BrokenPipeError("stderr is closed")
        self.sync.rounds = nodemod.RoundLog(clock=Clock(), out=broken)
        self.sync.publish = lambda: published.append(True) or False
        FakeClient.script = {"b": 6, "c": 6, "d": 6}
        with mock.patch.object(nodemod.sync, "Client", FakeClient):
            self.sync.pull_round()
        self.assertEqual(len(published), 3)                 # every source's round went on to publish
        self.assertEqual(self.sync.rounds.last, {})         # nothing counted as said: the next round tries again

    def test_a_trail_that_fails_stops_the_round_as_before(self):
        def broken(event):
            raise nodemod.sync.SinkFailed("the audit sink did not take the event (OSError)")
        self.sync.trail = broken
        FakeClient.script = {"b": 6, "c": 6, "d": 6}
        with mock.patch.object(nodemod.sync, "Client", FakeClient), self.assertRaises(nodemod.sync.SinkFailed):
            self.sync.pull_round()
        self.assertEqual(self.lines, [])


if __name__ == "__main__":
    unittest.main()
