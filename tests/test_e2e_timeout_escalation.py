"""#682: every bounded token call in pkcs11-removal.sh and lib/bench_cards.sh escalates to SIGKILL.

`timeout N` alone only sends SIGTERM. A PKCS#11 module or reader stuck in a driver call can ignore it, and the call
then hangs despite its bound. #679 fixed pkcs11-contract.sh (tests/test_p11_extract_probe.py); these are the other two
token-facing scripts. Also here: the hang cleanup the behavioural tests rely on (tests/hang_guard.py), with its own
red control, since a cleanup that misses timeout's process group leaves the stuck tool running after the suite.
"""
import os
import re
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import hang_guard
from tests.hang_guard import DEAF_TO_TERM, run_bounded

ROOT = Path(__file__).resolve().parents[1]
REMOVAL = ROOT / "e2e" / "pkcs11-removal.sh"
BENCH = ROOT / "e2e" / "lib" / "bench_cards.sh"
# (script, how its grace is written, how many bounded calls it has at least)
SCRIPTS = ((REMOVAL, r'"\$KILL_GRACE"', 6), (BENCH, r"(\d+)", 3))
ESCALATES = r'\btimeout -k {grace} (?:\d+|"\$\w+") '
BOUND = 2


def bounded_calls(text):
    """(line number, code) for every executable line of TEXT that runs timeout(1); comment lines are skipped."""
    return [(n, line) for n, line in enumerate(text.splitlines(), 1)
            if not line.lstrip().startswith("#") and re.search(r"\btimeout\s", line.split(" #", 1)[0])]


def shorten(code, bound_from, expect):
    """CODE with each timeout's duration BOUND_FROM cut to BOUND, whatever options precede it: the behaviour under
    test is the script's own -k, so only the duration is touched. Exactly EXPECT durations must be found."""
    out, n = re.subn(r"(\btimeout(?:\s+-k\s+\S+)?\s+)%d\b" % bound_from, r"\g<1>%d" % BOUND, code)
    assert n == expect, f"expected {expect} timeout {bound_from} calls to shorten, found {n}"
    return out


def definition(text, name):
    """The shell function NAME's source, from `NAME(){` to the first line after it that ends in `; }`."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(name + "(){")), None)
    assert start is not None, f"no {name}(){{ in the script"
    for end in range(start, len(lines)):
        if lines[end].rstrip().endswith("; }") and (end > start or lines[start].count("{") == lines[start].count("}")):
            return "\n".join(lines[start:end + 1])
    raise AssertionError(f"{name}(){{ never closes")


def grace_of_removal():
    m = re.search(r"^KILL_GRACE=(\d+)$", REMOVAL.read_text(), re.M)
    assert m, "pkcs11-removal.sh sets no KILL_GRACE"
    return int(m.group(1))


def deaf_tools(d, *names):
    """PATH dir holding NAMES as SIGTERM-ignoring stand-ins."""
    for name in names:
        tool = Path(d, name)
        tool.write_text("#!/usr/bin/env python3\n" + DEAF_TO_TERM)
        tool.chmod(0o755)
    return d


class EveryBoundEscalatesToKill(unittest.TestCase):

    def test_the_grace_is_set_and_short(self):
        self.assertLessEqual(grace_of_removal(), 10, "pkcs11-removal.sh: a grace this long makes the bound a suggestion")
        self.assertGreater(grace_of_removal(), 0, "pkcs11-removal.sh: -k 0 never sends SIGKILL")
        for number, line in bounded_calls(BENCH.read_text()):
            m = re.search(ESCALATES.format(grace=r"(\d+)"), line)
            if m:
                with self.subTest(script="bench_cards.sh", line=number):
                    self.assertTrue(0 < int(m.group(1)) <= 10, f"bench_cards.sh:{number}: grace {m.group(1)} s is not in 1..10")

    def test_every_timeout_call_escalates(self):
        for script, grace, at_least in SCRIPTS:
            calls = bounded_calls(script.read_text())
            # Positive control: fewer calls than the script has means the scan went blind.
            self.assertGreaterEqual(len(calls), at_least, f"{script.name}: found only {len(calls)} timeout calls")
            for number, line in calls:
                with self.subTest(script=script.name, line=number):
                    self.assertRegex(line, ESCALATES.format(grace=grace),
                                     f"{script.name}:{number} has a timeout with no SIGKILL escalation: {line.strip()}")

    def test_the_scan_sees_a_call_without_escalation(self):
        calls = bounded_calls('# timeout 9 in a comment\nx(){ timeout 30 pkcs11-tool -L; }\ny(){ timeout -k "$KILL_GRACE" 30 z; }\n')
        self.assertEqual([n for n, _ in calls], [2, 3])
        self.assertNotRegex(calls[0][1], ESCALATES.format(grace=r'"\$KILL_GRACE"'))
        self.assertNotRegex('timeout 60 -k 5 pkcs11-tool', ESCALATES.format(grace=r"(\d+)"), "-k after the duration is no option")

    def assert_killed_in_time(self, result, grace, what):
        self.assertFalse(result.hung, f"{what} did not return within 30 s against a tool that ignores SIGTERM: no SIGKILL")
        self.assertLess(result.seconds, BOUND + grace + 5, f"{what} took {result.seconds:.1f} s (bound {BOUND} s, grace {grace} s)")
        self.assertEqual(result.leftovers, [], f"{what} left processes running")

    def test_removal_p11_deaf_to_term_is_killed_within_bound_and_grace(self):
        grace = grace_of_removal()
        p11 = shorten(definition(REMOVAL.read_text(), "p11"), 60, 1)
        with tempfile.TemporaryDirectory() as d:
            script = "\n".join(["set -u", 'PATH="$1:$PATH" SLOT=0 MODULE=m', f"KILL_GRACE={grace}", p11,
                                'p11 -L; printf "rc=%s\\n" "$?"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool"))
        self.assert_killed_in_time(result, grace, "pkcs11-removal.sh p11")
        self.assertIn("rc=137", result.stdout, result.stdout)

    def test_removal_slot_of_deaf_to_term_is_killed_within_bound_and_grace(self):
        grace = grace_of_removal()
        slot_of = shorten(definition(REMOVAL.read_text(), "slot_of"), 30, 1)
        with tempfile.TemporaryDirectory() as d:
            script = "\n".join(["set -u", 'PATH="$1:$PATH" MODULE=m SERIAL=s', f"KILL_GRACE={grace}", slot_of,
                                's="$(slot_of)"; printf "slot=[%s]\\n" "$s"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool"))
        self.assert_killed_in_time(result, grace, "pkcs11-removal.sh slot_of")
        self.assertIn("slot=[]", result.stdout, "a killed listing must name no slot: " + result.stdout)

    def test_bench_slot_deaf_to_term_is_killed_within_bound_and_grace(self):
        text = BENCH.read_text()
        graces = {int(g) for g in re.findall(r"\btimeout -k (\d+) ", text)} or {0}
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d, "bench_cards.sh"); lib.write_text(shorten(text, 30, 3))
            script = "\n".join(["set -u", 'PATH="$1:$PATH"', f'. "{lib}"', "BENCH_MODULE=m",
                                's="$(bench_slot s)"; printf "slot=[%s]\\n" "$s"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool", "opensc-tool"))
        self.assert_killed_in_time(result, max(graces), "bench_cards.sh bench_slot")
        self.assertIn("slot=[]", result.stdout, result.stdout)


@unittest.skipUnless(hang_guard.HAVE_PROC, "needs /proc")
class TheHangCleanupLeavesNothing(unittest.TestCase):
    """f9 on #681: a cleanup that kills only the session's own group misses timeout(1)'s group, and the stuck tool
    (and its fork) keeps running after the suite."""

    def test_a_hang_is_cleaned_up_with_no_orphans(self):
        with tempfile.TemporaryDirectory() as d:
            # Unescalated on purpose, so the command really hangs and only the cleanup can end it.
            result = run_bounded('timeout 600 "$1/pkcs11-tool"; echo done', deaf_tools(d, "pkcs11-tool"), limit=3)
        self.assertTrue(result.hung, "the stand-in was meant to hang: " + result.stdout)
        self.assertEqual(result.leftovers, [], "the hang cleanup left processes running")

    def test_a_sweep_spares_the_runner_and_its_session(self):
        # The sweep kills whole process groups, so it must never reach the runner's. A sibling in the RUNNER's own
        # session (as the harness and CI's step shell are) must survive a hang's cleanup, and sweeping the
        # caller's own session is refused.
        sibling = subprocess.Popen(["python3", "-c", "import time; time.sleep(600)"])
        try:
            with tempfile.TemporaryDirectory() as d:
                result = run_bounded('timeout 600 "$1/pkcs11-tool"', deaf_tools(d, "pkcs11-tool"), limit=2)
            self.assertTrue(result.hung)
            self.assertEqual(result.leftovers, [])
            self.assertIsNone(sibling.poll(), "the sweep killed a process in the runner's own session")
            self.assertEqual(os.getsid(sibling.pid), os.getsid(0))
            os.kill(os.getppid(), 0)                      # the runner's parent is still there
            # killpg stubbed out, so a sweep that is NOT refused shows as a failure here instead of killing the runner.
            with mock.patch.object(hang_guard.os, "killpg") as killpg, self.assertRaises(ValueError):
                hang_guard.kill_session(os.getsid(0))
            killpg.assert_not_called()
            self.assertIsNone(sibling.poll())
        finally:
            sibling.kill()
            sibling.wait()

    def test_the_orphan_scan_sees_a_leftover(self):
        # Red control for the scan: a planted leftover in a session of its own must be counted, then killed.
        planted = subprocess.Popen(["python3", "-c", "import time; time.sleep(600)"], start_new_session=True)
        try:
            time.sleep(0.2)
            self.assertEqual(len(hang_guard.session_members(planted.pid)), 1)
            hang_guard.kill_session(planted.pid)
            planted.wait(timeout=5)
            self.assertEqual(hang_guard.session_members(planted.pid), [])
        finally:
            if planted.poll() is None:
                os.kill(planted.pid, 9)
                planted.wait()


if __name__ == "__main__":
    unittest.main()
