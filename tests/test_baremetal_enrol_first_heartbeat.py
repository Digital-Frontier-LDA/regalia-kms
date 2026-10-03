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

    def take(self, sources=("b", "c", "authority")):
        transports = {s if s != "authority" else "authority": self.wire(s, "a") for s in sources}
        return enrol.take_first_heartbeat("a", self.m1, self.stores["b"], self.late, transports, self.trail.append)

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

    def test_a_heartbeat_for_another_manifest_is_not_taken(self):
        self.beat(self.m1)
        other = self.advance(1)                           # the authority moves on; a's manifest stays epoch 1
        with self.assertRaises((enrol.Refused, m.Refused)):
            enrol.take_first_heartbeat("a", other, self.stores["b"], self.late, {"b": self.wire("b", "a")}, self.trail.append)
        self.assertIsNone(self.late.held())


if __name__ == "__main__":
    import unittest
    unittest.main()
