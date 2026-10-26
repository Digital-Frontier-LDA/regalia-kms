"""e2e/lib/threenode.py moving_line (#340, b9 on #577): the sync-apply whose round moved a node to an epoch, which the
three-node scenarios' audit steps take as the exact point from which the node held it. A unit test on trail lines, so
the rule is held here and not only by a scenario that needs a runner.

The rule: a sync-apply is filed under the epoch its round BEGAN from, so the move is the LAST sync-apply before the first
pull line under the new epoch, filed under the epoch before, from the same peer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode  # noqa: E402


def line(seq, event, epoch, peer="c", outcome="ALLOW", **kw):
    return dict({"seq": seq, "event": event, "epoch": epoch, "peer": peer, "outcome": outcome}, **kw)


class MovingLine(unittest.TestCase):
    def stream(self):
        return [line(10, "sync-apply", 1),                              # an empty round under epoch 1
                line(11, "sync-apply", 1),                              # THE move: filed under 1, it brought 2
                line(12, "sync-lease", 1, subject="a"),                 # a lease issued between the move and the next round
                line(13, "sync-heartbeat", 2),                          # the first line under epoch 2
                line(14, "sync-apply", 2)]

    def test_the_move_is_the_last_sync_apply_before_the_first_line_under_the_new_epoch(self):
        self.assertEqual(threenode.moving_line(self.stream(), 2)["seq"], 11)

    def test_a_lease_between_the_move_and_the_first_epoch_line_is_after_the_bound(self):
        """The case the bound exists for: bounded by the first epoch-2 line (13) it would be missed; by the move (11) it is
        caught. This is the converse three-node-leases asserts for the node that only proposed the revocation."""
        stream = self.stream()
        bound = threenode.moving_line(stream, 2)["seq"]
        late = [e for e in stream if e["event"] == "sync-lease" and e.get("subject") == "a" and e["seq"] > bound]
        self.assertEqual([e["seq"] for e in late], [12])
        first_epoch_line = next(e["seq"] for e in stream if e["epoch"] == 2)
        self.assertEqual([e for e in late if e["seq"] > first_epoch_line], [])    # the old, late bound would miss it

    def test_no_move_without_a_line_under_the_epoch_or_from_another_peer(self):
        self.assertIsNone(threenode.moving_line([line(1, "sync-apply", 1)], 2))
        self.assertIsNone(threenode.moving_line([line(1, "sync-apply", 1, peer="b"), line(2, "sync-heartbeat", 2, peer="c")], 2))
        self.assertIsNone(threenode.moving_line([line(1, "sync-apply", 0), line(2, "sync-heartbeat", 2)], 2))

    def test_a_refused_round_counts_only_when_it_says_it_moved_first(self):
        moved = [line(1, "sync-apply", 1, outcome="DENY", reason="refused: the round had moved from epoch 1 to 2, then ..."),
                 line(2, "sync-heartbeat", 2)]
        self.assertEqual(threenode.moving_line(moved, 2)["seq"], 1)
        not_moved = [line(1, "sync-apply", 1, outcome="DENY", reason="refused: no answer"), line(2, "sync-heartbeat", 2)]
        self.assertIsNone(threenode.moving_line(not_moved, 2))


if __name__ == "__main__":
    unittest.main()
