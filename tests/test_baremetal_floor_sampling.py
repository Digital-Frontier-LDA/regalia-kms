"""node.Sync.between_rounds (#432, D32): a restarted issuer's RevisionFloor is fed every few seconds between pull rounds,
not once a round, so its one-lease warm-up ends within FLOOR_SAMPLE_S of a lease after its etcd watch's first fresh
applied.json. KERNEL-UPDATE step 3.5's "serving, then one lease more" and the drills rely on it (62's read of #504)."""
import unittest

from deploy.baremetal import lease, node
from deploy.baremetal import membership as m

CLUSTER, EPOCH, REVISION = "c1" * 8, 0, 7


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class Stub:
    """What between_rounds needs of a Sync: observe_state, and the class's FLOOR_SAMPLE_S."""
    FLOOR_SAMPLE_S = node.Sync.FLOOR_SAMPLE_S
    between_rounds = node.Sync.between_rounds

    def __init__(self, clock, fresh_from):
        self.clock, self.fresh_from, self.samples = clock, fresh_from, []
        self.floor = lease.RevisionFloor(clock=clock)

    def observe_state(self):
        self.samples.append(self.clock.t)
        if self.clock.t >= self.fresh_from:                  # the daemon's applied.json, fresh from then on
            self.floor.applied(CLUSTER, EPOCH, REVISION)


class BetweenRounds(unittest.TestCase):
    def test_the_floor_is_sampled_every_few_seconds_through_a_pull_interval(self):
        clock = Clock()
        sync = Stub(clock, fresh_from=0)
        start = clock.t
        sync.between_rounds(lambda: False, 60, clock=clock, sleep=clock.sleep)
        gaps = [b - a for a, b in zip([start] + sync.samples, sync.samples)]
        self.assertGreaterEqual(len(sync.samples), 60 // node.Sync.FLOOR_SAMPLE_S - 1)
        self.assertLessEqual(max(gaps), node.Sync.FLOOR_SAMPLE_S + 1)
        self.assertGreaterEqual(clock.t - start, 60)

    def test_it_stops_when_asked(self):
        clock = Clock()
        sync = Stub(clock, fresh_from=0)
        start = clock.t
        sync.between_rounds(lambda: clock.t - start >= 12, 60, clock=clock, sleep=clock.sleep)
        self.assertLess(clock.t - start, 14)

    def test_a_restarted_issuer_issues_within_a_lease_and_a_sample_of_its_first_fresh_state(self):
        """The watch's file is fresh 7 s after sync started (the daemon came up later, as on a host): the floor issues by
        7 + one lease + FLOOR_SAMPLE_S, inside one pull round. Sampled once a round, it would still be closed then."""
        clock = Clock()
        sync = Stub(clock, fresh_from=clock.t + 7)
        sync.observe_state()                                     # the round's own sample, at sync start: not fresh yet
        bound = sync.fresh_from + lease.MAX_LIFETIME + node.Sync.FLOOR_SAMPLE_S + 1
        sync.between_rounds(lambda: clock.t >= bound, 60, clock=clock, sleep=clock.sleep)
        sync.floor.require(CLUSTER, EPOCH, REVISION)             # issues: a sample a lease old, watched for a lease
        once_a_round = lease.RevisionFloor(clock=clock)          # the old cadence: one sample at the start, none since
        once_a_round.started = sync.floor.started
        with self.assertRaises(m.Refused):
            once_a_round.require(CLUSTER, EPOCH, REVISION)


class ObserveState(unittest.TestCase):
    def test_an_unreadable_watch_file_is_a_missed_sample_never_the_end_of_the_loop(self):
        """c4's read of #525: an I/O error reading applied.json (EIO, /proc) is caught like a refusal, so a sample every
        5 s cannot end Sync.run; the floor records nothing for it."""
        from unittest import mock
        stub = type("S", (), {"observe_state": node.Sync.observe_state})()
        stub.floor = lease.RevisionFloor(clock=Clock())
        for failure in (OSError(5, "Input/output error"), m.Refused("stale")):
            with self.subTest(type(failure).__name__), mock.patch.object(lease, "read_applied", side_effect=failure):
                stub.observe_state()
        self.assertEqual(stub.floor.seen, [])


if __name__ == "__main__":
    unittest.main()
