"""e2e/lib/threenode.py renewals_beyond (regalia-rlj, three-node-leases' step 7): of an issuer's lease ALLOWs in a window
opened at a cut, the lease the node already held at the cut is left out, exactly that one line and only when that
issuer issued it, while every renewal made after the cut is counted, an extra one a second after it included
(TEAMLEAD-grafana on #606). A unit test, so the rule is held here and not only by a scenario that needs a runner."""
import calendar
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode  # noqa: E402

CUT = calendar.timegm(time.strptime("2026-10-27T05:06:25Z", "%Y-%m-%dT%H:%M:%SZ"))     # #605's run: the cut's second


def allow(at):
    return {"event": "sync-lease", "subject": "a", "outcome": "ALLOW", "at": at}


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


class RenewalsBeyond(unittest.TestCase):
    def test_the_failing_run_the_held_lease_in_the_cuts_second_is_left_out(self):
        """#605 run 40453195050: a held c's lease of 05:06:25 at a cut in that second; two renewals came after it."""
        lines = [allow(CUT), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines), [allow(CUT + 11), allow(CUT + 25)])

    def test_an_extra_renewal_a_second_after_the_cut_is_counted(self):
        """The power a padded window would have taken away: three renewals after the cut are three."""
        lines = [allow(CUT), allow(CUT + 1), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(len(threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines)), 3)

    def test_an_extra_renewal_right_after_a_lease_held_from_before_the_cut_is_counted(self):
        """The held lease's ALLOW is outside the window (issued seconds before the cut): nothing in the window is it."""
        lines = [allow(CUT + 1), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(len(threenode.renewals_beyond(lines, stamp(CUT - 7), "c", by="c", stream=lines)), 3)

    def test_a_renewal_two_seconds_after_the_held_lease_is_never_taken_for_it(self):
        """Held from the second before the cut, its ALLOW outside the window; a renewal at the cut's next second counts."""
        lines = [allow(CUT + 1), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(len(threenode.renewals_beyond(lines, stamp(CUT - 1), "c", by="c", stream=lines)), 3)

    def test_a_double_issue_a_second_after_a_held_lease_from_before_the_cut_counts(self):
        """b9 on 2837eac2: held issued CUT-1, its ALLOW at CUT-1 (before the window), an extra lease at CUT: the fallback to
        the next second would drop that extra one and read 2 where 3 were issued."""
        window = [allow(CUT), allow(CUT + 11), allow(CUT + 25)]
        stream = [allow(CUT - 1)] + window
        self.assertEqual(threenode.renewals_beyond(window, stamp(CUT - 1), "c", by="c", stream=stream), window)

    def test_the_next_second_is_taken_only_when_the_issue_second_is_nowhere(self):
        window = [allow(CUT), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(threenode.renewals_beyond(window, stamp(CUT - 1), "c", by="c", stream=window), window[1:])

    def test_the_stream_is_required(self):
        with self.assertRaises(TypeError):
            threenode.renewals_beyond([], stamp(CUT), "c", by="c")      # noqa: the fallback is never taken blind

    def test_a_held_lease_written_as_the_second_turned_is_left_out(self):
        lines = [allow(CUT + 1), allow(CUT + 11), allow(CUT + 25)]
        self.assertEqual(threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines), [allow(CUT + 11), allow(CUT + 25)])

    def test_its_own_second_is_preferred_to_the_next(self):
        lines = [allow(CUT), allow(CUT + 1), allow(CUT + 11)]
        self.assertEqual(threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines), [allow(CUT + 1), allow(CUT + 11)])

    def test_only_one_line_is_ever_left_out(self):
        lines = [allow(CUT), allow(CUT), allow(CUT + 11)]
        self.assertEqual(len(threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines)), 2)

    def test_a_lease_another_issuer_held_leaves_this_issuers_lines_whole(self):
        lines = [allow(CUT), allow(CUT + 11)]
        self.assertEqual(threenode.renewals_beyond(lines, stamp(CUT), "b", by="c", stream=lines), lines)

    def test_no_held_lease_leaves_them_whole(self):
        lines = [allow(CUT), allow(CUT + 11)]
        self.assertEqual(threenode.renewals_beyond(lines, None, None, by="c", stream=lines), lines)

    def test_its_input_is_not_changed(self):
        lines = [allow(CUT), allow(CUT + 11)]
        threenode.renewals_beyond(lines, stamp(CUT), "c", by="c", stream=lines)
        self.assertEqual(lines, [allow(CUT), allow(CUT + 11)])


if __name__ == "__main__":
    unittest.main()
