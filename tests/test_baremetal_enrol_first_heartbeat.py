"""regalia-node enrol, a node joining a running network (#190 --replace, decided on #190 as (B) at define time): its
heartbeat counter starts AT the network's current sequence, from the highest heartbeat a peer or the authority holds,
verified under its manifest and live by authenticated time (heartbeat.Freshness.accept_first). The sync tests'
fixtures: b and c hold the chain and heartbeats; node a's own counter is not defined yet."""
import json
import os

from deploy.baremetal import enrol, heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_sync as st


class FirstHeartbeat(st.Case):
    def setUp(self):
        super().setUp()
        self.counter = hb.Counter("0x1500018", lock_path=os.path.join(self.d, "late.lock"), run=hbt.FakeTpm())
        self.late = hb.Freshness(self.counter, self.clock, lambda: self.ticks, os.path.join(self.d, "late-freshness.json"))
        self.trail = []

    def take(self, sources=("b", "c", "authority"), bootstrap=False, manifest=None):
        transports = {s if s != "authority" else "authority": self.wire(s, "a") for s in sources}
        return enrol.take_first_heartbeat("a", manifest or self.m1, self.stores["b"], self.late, transports, self.trail.append, bootstrap)

    def test_the_highest_heartbeat_starts_the_counter_with_no_increment_loop(self):
        self.beat(self.m1)
        self.beat(self.m1, peers=("c",))                 # c holds a newer one than b
        held_by_c = self.peers["c"]["freshness"].held()
        sequence, left = self.take()
        self.assertEqual(sequence, held_by_c["heartbeat"]["sequence"])
        self.assertGreater(left, 0)
        self.assertEqual(self.counter.value(), sequence, "the counter reads the sequence at once")
        self.assertEqual(self.late.held(), held_by_c)
        self.assertEqual([(e["event"], e["outcome"], e["sequence"], e["source"]) for e in self.trail],
                         [("heartbeat-first", "INCOMPLETE", sequence, "c"), ("heartbeat-first", "ALLOW", sequence, "c")])
        self.assertEqual(self.take(), (None, None), "a second run takes nothing: a heartbeat is held")

    def test_nobody_answering_is_a_refusal_that_writes_nothing(self):
        with self.assertRaisesRegex((enrol.Refused, m.Refused), "no peer and no authority gave a heartbeat"):
            self.take(sources=())
        self.assertIsNone(self.late.held())
        self.assertEqual(self.trail, [])

    def test_bootstrap_starts_at_zero_only_when_nobody_holds_a_heartbeat_and_only_at_epoch_1(self):
        """#190 (24): at 0 only by --bootstrap, the first bring-up of a cluster: and even then a heartbeat any reachable
        source holds is taken instead."""
        self.assertEqual(self.take(sources=(), bootstrap=True), (0, None))
        self.assertEqual(self.counter.value(), 0)
        self.assertEqual([(e["outcome"], e["sequence"]) for e in self.trail], [("INCOMPLETE", 0), ("ALLOW", 0)])
        self.assertIn("bootstrap", self.trail[-1]["reason"])
        self.assertEqual(self.take(sources=(), bootstrap=True), (None, None), "defined: nothing more to do")

    def test_bootstrap_takes_a_heartbeat_when_there_is_one(self):
        self.beat(self.m1)
        sequence, left = self.take(bootstrap=True)
        self.assertGreater(sequence, 0)
        self.assertIsNotNone(left)

    def test_bootstrap_is_refused_above_epoch_1(self):
        later = dict(self.m1, epoch=2)
        with self.assertRaisesRegex((enrol.Refused, m.Refused), "--bootstrap is the first bring-up of a cluster, under epoch 1"):
            self.take(sources=(), bootstrap=True, manifest=later)

    def test_a_refused_first_heartbeat_closes_the_trail_with_deny(self):
        """d9's LOW on #279: the trail never ends open."""
        self.beat(self.m1)
        import unittest.mock
        with unittest.mock.patch.object(self.late, "accept_first", side_effect=m.Refused("the heartbeat has expired")):
            with self.assertRaisesRegex((enrol.Refused, m.Refused), "the heartbeat has expired. Run commit again"):
                self.take()
        self.assertEqual([e["outcome"] for e in self.trail], ["INCOMPLETE", "DENY"])

    def test_a_half_defined_counter_is_recounts_case(self):
        self.counter._tpm("nvdefine", self.counter.index, "-C", "o", "-a", "nt=counter|ownerwrite|ownerread", "-s", "8")
        with self.assertRaisesRegex((enrol.Refused, m.Refused), "half defined"):
            self.take()

    def test_a_heartbeat_for_another_manifest_is_not_taken(self):
        self.beat(self.m1)
        other = self.advance(1)                           # the authority moves on; a's manifest stays epoch 1
        with self.assertRaises((enrol.Refused, m.Refused)):
            enrol.take_first_heartbeat("a", other, self.stores["b"], self.late, {"b": self.wire("b", "a")}, self.trail.append)
        self.assertIsNone(self.late.held())


if __name__ == "__main__":
    import unittest
    unittest.main()
