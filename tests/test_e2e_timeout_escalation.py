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
from tests.hang_guard import DEAF_TO_TERM, LEADER_EXITS_CHILD_DEAF, run_bounded

ROOT = Path(__file__).resolve().parents[1]
REMOVAL = ROOT / "e2e" / "pkcs11-removal.sh"
BENCH = ROOT / "e2e" / "lib" / "bench_cards.sh"
HELPER = ROOT / "e2e" / "lib" / "bounded.py"
# (script, its bounding function, how many bounded token calls it has at least)
SCRIPTS = ((REMOVAL, "bounded", 6), (BENCH, "bench_bounded", 3))
BOUND = 2


def code(text):
    """TEXT's lines with comment lines blanked (line numbers kept)."""
    return ["" if line.lstrip().startswith("#") else line for line in text.splitlines()]


def bounded_calls(text, fn):
    """(line number, code) for every line of TEXT that calls the bounding function FN with a duration."""
    return [(n, line) for n, line in enumerate(code(text), 1) if re.search(r"\b%s \d+ " % fn, line)]


def timeout_calls(text):
    """(line number, code) for every line of TEXT that still runs timeout(1)."""
    return [(n, line) for n, line in enumerate(code(text), 1) if re.search(r"(?<![\w-])timeout\s", line)]


def shorten(code_, fn, bound_from, expect):
    """CODE_ with each `FN BOUND_FROM` cut to BOUND. Exactly EXPECT calls must be found."""
    out, n = re.subn(r"(\b%s\s+)%d\b" % (fn, bound_from), r"\g<1>%d" % BOUND, code_)
    assert n == expect, f"expected {expect} {fn} {bound_from} calls to shorten, found {n}"
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


def assignment(text, name):
    m = re.search(r"^%s=(.*)$" % name, text, re.M)
    assert m, f"pkcs11-removal.sh sets no {name}"
    return m.group(0)


def grace_of_removal():
    return int(assignment(REMOVAL.read_text(), "KILL_GRACE").split("=", 1)[1])


def tools(d, body, *names):
    """PATH dir holding NAMES as Python stand-ins running BODY."""
    for name in names:
        tool = Path(d, name)
        tool.write_text("#!/usr/bin/env python3\n" + body)
        tool.chmod(0o755)
    return d


def deaf_tools(d, *names):
    return tools(d, DEAF_TO_TERM, *names)


def removal_prelude(*names, bound_from=30, expect=1):
    """The definitions pkcs11-removal.sh's checks rely on, with bounds cut to BOUND, run against stand-ins on $1."""
    text = REMOVAL.read_text()
    defs = [definition(text, n) for n in ("P", "F", "H", "log", "hung", "listed")]
    # under bash -c, $0 is "bash": the helper's path is put where the script finds it from its own
    own = '"$(dirname "$0")/lib/bounded.py"'
    assert definition(text, "bounded").count(own) == 1, "bounded() does not run lib/bounded.py next to the script"
    defs.append(definition(text, "bounded").replace(own, '"%s"' % HELPER))
    parts = ["set -u", 'PATH="$1:$PATH" SLOT=0 MODULE=m SERIAL=s STALE=0 ID_EC=01 W="$2" pass=0 fail=0 hungs=0 Q_PIN= EVID=/dev/null',
             assignment(text, "KILL_GRACE"), assignment(text, "HUNG")] + defs
    for n in names:
        parts.append(shorten(definition(text, n), "bounded", bound_from if n != "p11" else 60, expect))
    return parts


# The one way a script may run the helper: python3 -I on its path, found from the script's own location (a refuse
# path: any other spelling fails, rather than a list of bad ones).
ISOLATED_RUN = re.compile(r'python3 -I "(?:\$\(dirname "\$0"\)/lib|\$HERE/lib|\$\{BASH_SOURCE\[0\]%/\*\})/bounded\.py" ')


class EveryTokenCallIsBoundedByTheHelper(unittest.TestCase):

    def test_the_grace_is_set_and_short(self):
        self.assertLessEqual(grace_of_removal(), 10, "pkcs11-removal.sh: a grace this long makes the bound a suggestion")
        self.assertGreater(grace_of_removal(), 0, "pkcs11-removal.sh: a zero grace never sends SIGKILL")
        m = re.search(r'bench_bounded\(\)\{ python3 -I "\$\{BASH_SOURCE\[0\]%/\*\}/bounded\.py" "\$1" (\d+) ', BENCH.read_text())
        self.assertTrue(m and 0 < int(m.group(1)) <= 10, "bench_cards.sh: bench_bounded's grace is not in 1..10 s")

    def test_no_script_runs_timeout_and_every_call_is_bounded(self):
        for script, fn, at_least in SCRIPTS:
            text = script.read_text()
            with self.subTest(script=script.name):
                self.assertEqual(timeout_calls(text), [], f"{script.name} still runs timeout(1), whose -k is not portable")
                # Positive control: fewer calls than the script has means the scan went blind.
                self.assertGreaterEqual(len(bounded_calls(text, fn)), at_least, bounded_calls(text, fn))

    def test_the_helper_is_only_run_as_python3_isolated(self):
        # bounded.py is 100644 with no shebang: it runs only as `python3 -I <path>`, where -I keeps lib/ off sys.path.
        # A bare call would not run, and one without -I would import from lib/ first.
        self.assertFalse(HELPER.read_text().startswith("#!"), "bounded.py gained a shebang: is it meant to run directly?")
        uses = []
        for path in sorted((ROOT / "e2e").rglob("*.sh")):
            for n, line in enumerate(code(path.read_text()), 1):
                if "bounded.py" in line:
                    uses.append((path.name, n, line))
        self.assertGreaterEqual(len(uses), 2, uses)          # pkcs11-removal.sh's and bench_cards.sh's
        for name, n, line in uses:
            with self.subTest(script=name, line=n):
                self.assertEqual(len(re.findall(r"bounded\.py", line)), len(ISOLATED_RUN.findall(line)),
                                 f"{name}:{n} runs bounded.py another way: {line.strip()}")

    def test_each_drill_bound_takes_one_word_before_the_command(self):
        # The card-isolation scan reads "bounded WORD COMMAND" / "bench_bounded WORD COMMAND" (#684): exactly one word
        # before the command. Every run of the helper is one of these definitions, passing "$1" then "${@:2}"; a second
        # grace word, or a caller of the helper outside them, would put a word the scan takes for the command first.
        shape = re.compile(r'^(bounded|bench_bounded)\(\)\{ ' + ISOLATED_RUN.pattern + r'"\$1" (?:"\$KILL_GRACE"|\d+) '
                           r'"\$\{@:2\}"; \}$')
        names = []
        for path in sorted((ROOT / "e2e").rglob("*.sh")):
            for n, line in enumerate(code(path.read_text()), 1):
                if "bounded.py" in line:
                    with self.subTest(script=path.name, line=n):
                        m = shape.match(line.strip())
                        self.assertIsNotNone(m, f"{path.name}:{n} runs bounded.py, not as a one-word bound: {line.strip()}")
                        names.append(m and m.group(1))
        self.assertEqual(sorted(set(names)), ["bench_bounded", "bounded"], names)

    def test_a_second_number_or_an_option_runs_nothing(self):
        # what the scan does not model runs nothing: "bounded 60 5 touch F" runs a command named 5 (127), and a bound
        # that starts with "-" is refused before anything runs (125)
        with tempfile.TemporaryDirectory() as d:
            ran = Path(d, "ran")
            for call, rc in (('bounded 1 5 touch "%s"' % ran, 127), ('bounded -k 5 touch "%s"' % ran, 125),
                             ('bounded -1 touch "%s"' % ran, 125), ('bounded --signal=KILL touch "%s"' % ran, 125)):
                with self.subTest(call=call):
                    script = "\n".join(removal_prelude() + [call + ' 2>/dev/null; printf "rc=%s\\n" "$?"'])
                    out = subprocess.run(["bash", "-c", script, "bash", d, d], capture_output=True, text=True, timeout=30)
                    self.assertIn("rc=%d" % rc, out.stdout, out.stdout + out.stderr)
                    self.assertFalse(ran.exists(), f"{call} ran its command")

    def test_the_isolated_run_check_refuses_other_spellings(self):
        for fine in ('python3 -I "$(dirname "$0")/lib/bounded.py" 30 x', 'python3 -I "$HERE/lib/bounded.py" 1 x',
                     'python3 -I "${BASH_SOURCE[0]%/*}/bounded.py" 3 x'):
            with self.subTest(fine=fine):
                self.assertEqual(len(ISOLATED_RUN.findall(fine)), 1)
        for bad in ('python3 "$HERE/lib/bounded.py" 1 x', 'python3 -Es "$HERE/lib/bounded.py" 1 x', '"$HERE/lib/bounded.py" 1 x',
                    'python3 -I "$X/bounded.py" 1 x', 'python3 -I bounded.py 1 x'):
            with self.subTest(bad=bad):
                self.assertEqual(ISOLATED_RUN.findall(bad), [])

    def test_the_scans_see_what_they_look_for(self):
        planted = '# timeout 9 in a comment\nx(){ timeout -k 5 30 pkcs11-tool -L; }\ny(){ bounded 30 z; }\n'
        self.assertEqual([n for n, _ in timeout_calls(planted)], [2])
        self.assertEqual([n for n, _ in bounded_calls(planted, "bounded")], [3])
        self.assertEqual(timeout_calls("KILL_GRACE=5\nbench_bounded 30 x\n"), [])

    def assert_ended_in_time(self, result, grace, what):
        self.assertFalse(result.hung, f"{what} did not return within 30 s against a tool that ignores SIGTERM")
        self.assertLess(result.seconds, BOUND + grace + 5, f"{what} took {result.seconds:.1f} s (bound {BOUND} s, grace {grace} s)")
        self.assertEqual(result.leftovers, [], f"{what} left processes running")

    def test_removal_p11_deaf_to_term_is_killed_within_bound_and_grace(self):
        with tempfile.TemporaryDirectory() as d:
            script = "\n".join(removal_prelude("p11") + ['p11 -L; printf "rc=%s\\n" "$?"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool"), d)
        self.assert_ended_in_time(result, grace_of_removal(), "pkcs11-removal.sh p11")
        self.assertIn("rc=137", result.stdout, result.stdout)

    def test_removal_slot_of_deaf_to_term_is_killed_and_says_it_hung(self):
        with tempfile.TemporaryDirectory() as d:
            script = "\n".join(removal_prelude("slot_of") + ['s="$(slot_of)"; printf "slot=[%s] rc=%s\\n" "$s" "$?"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool"), d)
        self.assert_ended_in_time(result, grace_of_removal(), "pkcs11-removal.sh slot_of")
        self.assertIn("slot=[] rc=3", result.stdout, "a killed listing names no slot and returns HUNG: " + result.stdout)

    def test_bench_slot_deaf_to_term_is_killed_within_bound_and_grace(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d, "bench_cards.sh"); lib.write_text(shorten(BENCH.read_text(), "bench_bounded", 30, 3))
            Path(d, "bounded.py").write_text(HELPER.read_text())
            script = "\n".join(["set -u", 'PATH="$1:$PATH"', f'. "{lib}"', "BENCH_MODULE=m",
                                's="$(bench_slot s)"; printf "slot=[%s]\\n" "$s"'])
            result = run_bounded(script, deaf_tools(d, "pkcs11-tool", "opensc-tool"))
        self.assert_ended_in_time(result, 5, "bench_cards.sh bench_slot")
        self.assertIn("slot=[]", result.stdout, result.stdout)


@unittest.skipUnless(hang_guard.HAVE_PROC, "needs /proc")
class ANegativeCheckFailsOnAHang(unittest.TestCase):
    """67 on #684 (5): a call its bound ended must never pass a NEGATIVE check. "No slot listed" from a hung listing
    is not "the token is gone"."""

    def check(self, name, body, *extra, raw=()):
        with tempfile.TemporaryDirectory() as d:
            text = REMOVAL.read_text()
            script = "\n".join(removal_prelude(*extra) + [definition(text, n) for n in raw]
                               + [definition(text, name), name, 'echo "counts $pass $fail $hungs"'])
            result = run_bounded(script, tools(d, body, "pkcs11-tool"), d)
        self.assertFalse(result.hung, result.stdout)
        self.assertEqual(result.leftovers, [], result.stdout)
        return result.stdout

    def assert_hung_error(self, out):
        # a third outcome: HUNG/ERROR, counted as hung, neither a PASS nor a FAIL
        self.assertIn("HUNG/ERROR", out, out)
        self.assertIn("not measured", out, out)
        self.assertNotIn("PASS", out, out)
        self.assertNotIn("FAIL", out, out)
        self.assertIn("counts 0 0 1", out, out)

    def test_a_hung_listing_fails_gone_while_removed(self):
        self.assert_hung_error(self.check("gone_while_removed", DEAF_TO_TERM, "slot_of"))

    def test_every_hung_path_is_hung_error(self):
        # every check #684 bounds, against a tool deaf to SIGTERM: the read and sign through their real p11 / p11l
        # (p11l's slot gate hangs first, so its 124 is what the sign check sees)
        text = REMOVAL.read_text()
        for name, extra, raw in (("gone_while_removed", ("slot_of",), ()), ("absent_read_fails", ("p11",), ()),
                                 ("absent_sign_fails", ("target_ok", "p11"), ("p11l",))):
            with self.subTest(check=name):
                self.assert_hung_error(self.check(name, DEAF_TO_TERM, *extra, raw=raw))

    def test_no_verdict_on_a_hang_is_a_fail_or_a_pass(self):
        # structural: every verdict that names a hang is H, in the functions and in section 4's inline gate
        lines = code(REMOVAL.read_text())
        named = [(n, line.strip()) for n, line in enumerate(lines, 1) if re.search(r'\b[PF] "[^"]*\bhung\b', line)]
        self.assertEqual(named, [], "a hang reported as a pass or a failure")
        self.assertGreaterEqual(sum(bool(re.search(r'(?:^|[;&|(]|then|else|\))\s*H "', line)) for line in lines), 5,
                                "fewer H verdicts than hung paths: the scan went blind")

    def test_an_empty_listing_passes_gone_while_removed(self):
        # control: the same check passes on a listing the tool really gave, with no slot in it
        out = self.check("gone_while_removed", "import sys; sys.exit(0)\n", "slot_of")
        self.assertIn("PASS the token is gone while removed", out.replace("\x1b[32m", "").replace("\x1b[0m", ""), out)

    def test_a_hung_read_fails_absent_read_fails(self):
        out = self.check("absent_read_fails", DEAF_TO_TERM, "p11")
        self.assert_hung_error(out)
        self.assertIn("rc=137", out, out)

    def test_a_refused_read_passes_absent_read_fails(self):
        out = self.check("absent_read_fails", "import sys; sys.exit(1)\n", "p11")
        self.assertIn("PASS", out, out)
        self.assertNotIn("FAIL", out, out)

    def test_a_sign_its_bound_ended_is_hung_error_in_absent_sign_fails(self):
        # de/a0f4 on #684 (R2): the sign ITSELF hangs, past a slot gate that answered (the gate's own hang, rc 124, is
        # test_every_hung_path_is_hung_error): the real p11l and p11 against a tool deaf to SIGTERM, ended by its bound
        with tempfile.TemporaryDirectory() as d:
            text = REMOVAL.read_text()
            script = "\n".join(removal_prelude("p11") + [definition(text, "p11l"), "target_ok(){ return 0; }",
                                                       definition(text, "absent_sign_fails"), "absent_sign_fails",
                                                       'echo "counts $pass $fail $hungs"'])
            result = run_bounded(script, tools(d, DEAF_TO_TERM, "pkcs11-tool"), d)
        self.assertFalse(result.hung, result.stdout)
        self.assertEqual(result.leftovers, [], result.stdout)
        self.assert_hung_error(result.stdout)
        self.assertIn("rc=137", result.stdout, result.stdout)

    def test_a_hung_slot_check_reads_as_hung_not_as_empty(self):
        # de on #684 (R3, CodeRabbit :209): the check that the removed token's slot holds nothing, against a tool deaf
        # to SIGTERM, is HUNG: "nothing answered" is never "nothing there"
        with tempfile.TemporaryDirectory() as d:
            text = REMOVAL.read_text()
            script = "\n".join(removal_prelude("slot_has_token") + ['slot_has_token 0; echo "held=$?"'])
            result = run_bounded(script, tools(d, DEAF_TO_TERM, "pkcs11-tool"), d)
        self.assertFalse(result.hung, result.stdout)
        self.assertEqual(result.leftovers, [], result.stdout)
        self.assertIn("held=%s" % assignment(text, "HUNG").split("=", 1)[1], result.stdout, result.stdout)

    def test_startup_without_the_token_is_tried_only_on_a_slot_both_listings_answered_for(self):
        # section 4 makes no attempt on the removed token's slot unless the token is not listed AND the slot is seen to
        # hold nothing: a hung listing gates it off like a token found there (2026-10-02: another card got the PIN)
        text = REMOVAL.read_text()
        hung = assignment(text, "HUNG").split("=", 1)[1]
        cases = (("hung slot check", ":", hung, "HUNG/ERROR", "counts 0 0 1"),
                 ("hung token listing", "return %s" % hung, "1", "HUNG/ERROR", "counts 0 0 1"),
                 ("another token in the slot", ":", "0", "FAIL", "counts 0 1 0"),
                 ("the token still listed", "echo 3", "1", "FAIL", "counts 0 1 0"))
        for label, listing, held, verdict, counts in cases + (("control: an empty slot", ":", "1", None, "counts 0 0 0"),):
            with self.subTest(case=label):
                script = "\n".join(removal_prelude() + [definition(text, "startup_without_token"),
                                    "slot_of(){ %s; }" % listing, "slot_has_token(){ return %s; }" % held,
                                    'absent_read_fails(){ echo "ATTEMPTED read"; }', 'absent_sign_fails(){ echo "ATTEMPTED sign"; }',
                                    "startup_without_token", 'echo "counts $pass $fail $hungs"'])
                out = subprocess.run(["bash", "-c", script, "bash", "/nonexistent", "/nonexistent"],
                                     capture_output=True, text=True, timeout=30).stdout
                self.assertIn(counts, out, out)
                if verdict is None:
                    self.assertIn("ATTEMPTED read\nATTEMPTED sign", out, out)
                else:
                    self.assertIn(verdict, out, out)
                    self.assertNotIn("ATTEMPTED", out, out)
        self.assertEqual(sum(line.strip() == "startup_without_token" for line in code(text)), 1,
                         "section 4 does not run its gate exactly once")


class AStreamVerdictIgnoresAHang(unittest.TestCase):
    """de on #684: sections 2 and 3 counted a call their bound ended as "failed in flight", which fed the PASS
    "the removal interrupted the stream". A hung call feeds no verdict, positive or negative: it fails the section."""

    def run_removal(self, *lines, body=None):
        with tempfile.TemporaryDirectory() as d:
            text = REMOVAL.read_text()
            script = "\n".join(removal_prelude() + [definition(text, "stream_line"), definition(text, "stream_verdict")]
                               + [line.replace("@D", d) for line in lines])
            if body is None:
                return subprocess.run(["bash", "-c", script, "bash", d, d], capture_output=True, text=True, timeout=30).stdout
            result = run_bounded(script, tools(d, body, "pkcs11-tool"), d)
        self.assertFalse(result.hung, result.stdout)
        self.assertEqual(result.leftovers, [], result.stdout)
        return result.stdout

    def test_a_call_its_bound_ended_is_a_hung_line(self):
        # the real bound against a stand-in deaf to SIGTERM: 137, read as hung, not as failed in flight
        out = self.run_removal('bounded 1 pkcs11-tool --sign; stream_line "$?" 7', body=DEAF_TO_TERM)
        self.assertIn("hung 7", out, out)
        self.assertNotIn("err 7", out, out)

    def test_each_status_maps_to_its_outcome(self):
        out = self.run_removal(*['stream_line %s %s' % (rc, rc) for rc in (0, 97, 124, 137, 1, 125)])
        self.assertEqual(out.split("\n")[:6], ["ok 0", "skip 97", "hung 124", "hung 137", "err 1", "err 125"], out)

    def test_a_hung_call_fails_the_stream_however_the_rest_went(self):
        for stream in ("ok 1\\nhung 2\\nerr 3", "ok 1\\nhung 2\\nskip 3", "hung 1", "ok 1\\nok 2\\nhung 3"):
            with self.subTest(stream=stream):
                out = self.run_removal('printf "%s\\n" > "@D/s"' % stream, 'stream_verdict "@D/s" stream',
                                       'echo "counts $pass $fail $hungs"')
                # its own outcome: neither a PASS nor a FAIL, so "it hung" never reads as "not interrupted"
                self.assertIn("HUNG/ERROR", out, out)
                self.assertIn("interruption not measured", out, out)
                self.assertNotIn("PASS", out, out)
                self.assertNotIn("FAIL", out, out)
                self.assertIn("counts 0 0 1", out, out)

    def test_a_stream_with_both_outcomes_and_no_hang_passes(self):
        # control: the same verdict passes when the removal really interrupted the stream
        for stream in ("ok 1\\nerr 2", "ok 1\\nskip 2"):
            with self.subTest(stream=stream):
                out = self.run_removal('printf "%s\\n" > "@D/s"' % stream, 'stream_verdict "@D/s" stream')
                self.assertIn("PASS", out, out)
                self.assertIn("interrupted the stream", out, out)
                self.assertNotIn("FAIL", out, out)

    def test_a_hung_run_exits_3_whatever_passed_or_failed(self):
        # the run's status tells a hang apart from a failed check: 3 if anything hung, else 1 on a failure, else 0
        text = REMOVAL.read_text()
        self.assertEqual(code(text)[-1].strip(), "result", "the drill's last command is not result")
        for counts, rc in (("pass=5 fail=0 hungs=0", 0), ("pass=5 fail=2 hungs=0", 1), ("pass=5 fail=0 hungs=1", 3),
                           ("pass=0 fail=4 hungs=2", 3)):
            with self.subTest(counts=counts):
                out = self.run_removal(counts, definition(text, "result"), 'result; echo "rc=$?"')
                self.assertIn("rc=%d" % rc, out, out)
                self.assertIn("%s hung" % counts.split("hungs=")[1], out, out)

    def test_both_streams_use_the_shared_outcome_and_verdict(self):
        lines = code(REMOVAL.read_text())
        self.assertEqual(sum('stream_line "$?" "$i"' in line for line in lines), 2, "a stream maps statuses itself")
        self.assertEqual(sum(line.strip().startswith("stream_verdict ") for line in lines), 2, "a section judges itself")
        self.assertEqual([n for n, line in enumerate(lines, 1) if 'echo "err' in line and "stream_line(){" not in line], [],
                         "a status is mapped to err outside stream_line")


@unittest.skipUnless(hang_guard.HAVE_PROC, "needs /proc")
class TheHelperEndsTheWholeGroup(unittest.TestCase):
    """bounded.py (#684): what timeout -k does with GNU coreutils, on any system, and the four cases 67 and de named."""

    def bounded(self, body, seconds=1, grace=2, before="", after=""):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(tools(d, body, "tool"), "tool")
            script = '%spython3 -I "%s" %s %s "%s"; rc=$?; %sprintf "rc=%%s\\n" "$rc"' % (before, HELPER, seconds, grace, tool, after)
            return run_bounded(script, limit=20)

    def test_a_leader_that_exits_on_term_leaves_a_deaf_child_that_still_gets_killed(self):
        result = self.bounded(LEADER_EXITS_CHILD_DEAF)
        self.assertFalse(result.hung, result.stdout)
        self.assertIn("rc=137", result.stdout, "SIGKILL was needed for the deaf child: " + result.stdout)
        self.assertGreaterEqual(result.seconds, 1 + 2 - 0.3, "the helper stopped waiting when the leader exited")
        self.assertEqual(result.leftovers, [], "the deaf child outlived the bound")

    def test_a_deaf_leader_and_its_fork_are_killed(self):
        result = self.bounded(DEAF_TO_TERM)
        self.assertIn("rc=137", result.stdout, result.stdout)
        self.assertEqual(result.leftovers, [])

    def test_a_tool_that_obeys_term_is_124_and_says_so(self):
        result = self.bounded("import time; time.sleep(600)\n")
        self.assertIn("rc=124", result.stdout, result.stdout)
        self.assertIn("timed out after 1 s", result.stdout, result.stdout)
        self.assertLess(result.seconds, 1 + 2, "a group that emptied on SIGTERM must not wait out the grace")
        self.assertEqual(result.leftovers, [])

    def test_a_tool_s_own_status_passes_through(self):
        for rc in (0, 3, 124):
            with self.subTest(rc=rc):
                result = self.bounded("import sys; sys.exit(%d)\n" % rc)
                self.assertIn("rc=%d" % rc, result.stdout, result.stdout)
                # how a caller tells a tool's own 124 from the bound's: the helper said nothing
                self.assertNotIn("timed out", result.stdout, result.stdout)

    def test_a_cancelled_helper_ends_the_group_first(self):
        # the helper is sent SIGTERM (a CI cancel) while its tool and the tool's deaf fork run
        with tempfile.TemporaryDirectory() as d:
            tool = Path(tools(d, DEAF_TO_TERM, "tool"), "tool")
            # the helper's own pid, from $!: it is signalled by pid, never found by name
            script = 'python3 -I "%s" 60 1 "%s" & h=$!; sleep 1; kill -TERM "$h"; wait "$h"; printf "rc=%%s\\n" "$?"' % (HELPER, tool)
            result = run_bounded(script, limit=20)
        self.assertFalse(result.hung, result.stdout)
        self.assertIn("rc=143", result.stdout, result.stdout)
        self.assertEqual(result.leftovers, [], "a cancelled helper left its tool running")

    def test_a_bad_grace_is_refused(self):
        result = self.bounded("import sys; sys.exit(0)\n", grace=0)
        self.assertIn("rc=125", result.stdout, result.stdout)


@unittest.skipUnless(hang_guard.HAVE_PROC, "needs /proc")
class TheHangCleanupLeavesNothing(unittest.TestCase):
    """f9 on #681: a cleanup that kills only the session's own group misses timeout(1)'s group, and the stuck tool
    (and its fork) keeps running after the suite."""

    def test_a_hang_is_cleaned_up_with_no_orphans(self):
        with tempfile.TemporaryDirectory() as d:
            # Unescalated on purpose, so the command really hangs and only the cleanup can end it.
            result = run_bounded('timeout 600 "$1/pkcs11-tool"; echo done', deaf_tools(d, "pkcs11-tool"), limit=3)
        self.assertTrue(result.hung, "the stand-in was meant to hang: " + result.stdout)
        # 67 on #684 (6): the helper itself reports what the hang left, read before its own kill
        self.assertGreaterEqual(len(result.leftovers), 2, "run_bounded did not see the hung tool and its fork")
        self.assertEqual(result.survivors, [], "the hang cleanup left processes running")

    def test_run_bounded_reports_a_leftover_of_a_command_that_returned(self):
        # a command that returns but leaves a process behind (its output closed, so the pipe does not hold the run)
        result = run_bounded('python3 -c "import time; time.sleep(600)" >/dev/null 2>&1 & echo started', limit=10)
        self.assertFalse(result.hung, result.stdout)
        self.assertEqual(len(result.leftovers), 1, "run_bounded did not report the planted leftover")
        self.assertEqual(result.survivors, [])

    def test_a_sweep_spares_the_runner_and_its_session(self):
        # The sweep kills whole process groups, so it must never reach the runner's. A sibling in the RUNNER's own
        # session (as the harness and CI's step shell are) must survive a hang's cleanup, and sweeping the
        # caller's own session is refused.
        sibling = subprocess.Popen(["python3", "-c", "import time; time.sleep(600)"])
        try:
            with tempfile.TemporaryDirectory() as d:
                result = run_bounded('timeout 600 "$1/pkcs11-tool"', deaf_tools(d, "pkcs11-tool"), limit=2)
            self.assertTrue(result.hung)
            self.assertEqual(result.survivors, [])
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
