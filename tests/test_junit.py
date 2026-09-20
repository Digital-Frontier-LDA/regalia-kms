"""The report must not be greener than the run it describes.

Every case here is a bug the tool actually had, found by RUNNING it against this repository's own
suite rather than by reading it. All three produced a file — none of them produced a wrong exit
code — so the only artifact that was wrong was the one the tool exists to make.

  1. Subtest failures were invisible. `unittest` delivers them through `addSubTest`, not
     `addFailure`, and this suite is mostly subtests: the first version reported `failures="0"`
     for a run with two real failures.
  2. The report did not parse. A traceback can carry characters XML 1.0 forbids; ElementTree
     writes them through unescaped, so writing succeeded and reading failed — later, in front of
     whoever opened the artifact to read the failure.
  3. Discovery could silently find nothing. A runner that discovers fewer tests than the suite has
     is worse than the plain invocation it replaces: green report, green gate, nothing ran.
"""

import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def parse_report(path):
    """Parse a JUnit report this suite just generated, refusing a document type declaration first.

    `xml.etree` is the stdlib parser and it does expand INTERNAL entities, which is the billion-
    laughs shape; external entities it does not fetch. Every file parsed here is written moments
    earlier by tools/junit.py into a temp directory, so neither vector is reachable — but "the
    input is trusted" is exactly the sentence that stops being true when someone reuses a helper.
    Rather than take a third-party parser into a test tree that is otherwise stdlib-only, the one
    construct both attacks need is refused outright: a JUnit report our converter produced has no
    DOCTYPE, so encountering one is itself a defect worth failing on, not something to parse
    safely and ignore.
    """
    raw = Path(path).read_bytes()
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise AssertionError(
            f"{path} carries a DOCTYPE or ENTITY declaration. tools/junit.py never writes one, so "
            f"this report did not come from it (or it has grown a way to embed caller-controlled "
            f"markup), and it is not parsed here.")
    return ET.fromstring(raw)


def convert(tmp, lines):
    """Run the converter over synthetic `go test -json` events and return the parsed report."""
    source = Path(tmp) / "gotest.json"
    source.write_text("\n".join(lines), encoding="utf-8")
    out = Path(tmp) / "junit.xml"
    done = subprocess.run(
        [sys.executable, "-m", "tools.junit", "--gotest", str(source), "--out", str(out)],
        cwd=ROOT, capture_output=True, text=True)
    return done, (parse_report(out) if out.exists() else None)


def failure_text(report, what):
    """The first <failure> element's text, or a message naming the report rather than a traceback.

    `ElementTree.find` returns None when nothing matches, so `report.find(…).text` raises
    AttributeError — and it raises BEFORE the assertion that exists to say what went wrong. A
    converter that regressed to emitting no <failure> would fail these tests with
    "'NoneType' object has no attribute 'text'", which names Python and not the defect.

    Same shape as indexing a fixture's first element to build a case: the crash precedes the
    control that was put there to catch exactly that.

    Takes the report ROOT — the search is `.//failure`, so it is any descendant, and naming the
    parameter for a testcase would invite someone to pass one and get a different search.
    """
    found = report.find(".//failure")
    if found is None:
        # THE MESSAGE SAYS WHAT WAS OBSERVED, NOT WHAT IT ASSUMES. A missing <failure> has two
        # causes and they are different defects: the converter recorded nothing as failing, or it
        # counted failures it did not emit. Claiming the first would send a reader looking in the
        # wrong half of the code on the day it is the second.
        raise AssertionError(
            f"{what}: the report has no <failure> element. It declares tests="
            f"{report.get('tests')} failures={report.get('failures')} — so either nothing was "
            f"recorded as failing, or the count and the elements disagree. Both are defects in a "
            f"converter whose whole job is to report failures.")
    return found.text or ""


class GoConversionTests(unittest.TestCase):
    def test_a_failing_run_produces_a_failing_report_and_a_failing_exit(self):
        """The property the whole tool rests on: a step that writes a report cannot turn red green."""
        with tempfile.TemporaryDirectory() as tmp:
            done, report = convert(tmp, [
                '{"Action":"run","Package":"p","Test":"TestOne"}',
                '{"Action":"pass","Package":"p","Test":"TestOne","Elapsed":0.01}',
                '{"Action":"run","Package":"p","Test":"TestTwo"}',
                '{"Action":"output","Package":"p","Test":"TestTwo","Output":"boom MARKER\\n"}',
                '{"Action":"fail","Package":"p","Test":"TestTwo","Elapsed":0.02}',
            ])
            self.assertEqual(1, done.returncode,
                             "the converter exited 0 for a run containing a failure: a step that "
                             "writes a report would turn a red suite green")
            self.assertEqual("1", report.get("failures"))
            self.assertIn("MARKER", failure_text(report, "a failing go run"),
                          "the failure output was dropped, so the report says a test failed and "
                          "not why")

    def test_a_run_whose_only_failure_is_a_build_error_is_not_green(self):
        """The property, stated as a property so no refactor can satisfy it accidentally.

        A compile error is the likeliest way this repository's CI goes red, and NONE of the events
        Go emits for one carries a `Test` field. The first version skipped every event without one,
        so a tree that does not compile converted to `0 tests, 0 failed` and exited zero.

        The fixture is the event stream MEASURED from a package that does not compile, not one
        invented from the documentation — `build-output` and `build-fail` carry `ImportPath` and no
        `Package`, and the package's own `fail` event carries `FailedBuild` naming that ImportPath.
        Guessing that shape is how a converter passes its own test and fails on real input.
        """
        with tempfile.TemporaryDirectory() as tmp:
            # EVERY LINE IS A RAW STRING. `\n` and `\t` here must reach the file as the JSON
            # escape sequences Go emits, not as real control characters: a literal tab or newline
            # inside a JSON string is invalid JSON, and the converter refuses corrupt input — which
            # is how the first version of this fixture was caught. The refusal did its job on the
            # test that was written carelessly, which is the same guard working either way.
            done, report = convert(tmp, [
                r'{"ImportPath":"p [p.test]","Action":"build-output","Output":"# p [p.test]\n"}',
                r'{"ImportPath":"p [p.test]","Action":"build-output",'
                r'"Output":"./x.go:3:22: syntax error: DISTINCTIVE\n"}',
                r'{"ImportPath":"p [p.test]","Action":"build-fail"}',
                r'{"Action":"start","Package":"p"}',
                r'{"Action":"output","Package":"p","Output":"FAIL\tp [build failed]\n"}',
                r'{"Action":"fail","Package":"p","Elapsed":0,"FailedBuild":"p [p.test]"}',
            ])
            self.assertEqual(
                1, done.returncode,
                "a run that did not compile converted to a passing report and a zero exit — the "
                "report is greener than the run, which is the one thing this tool must never do")
            self.assertNotEqual(
                "0", report.get("failures"),
                "the report records no failure for a tree that does not build")
            self.assertIn(
                "DISTINCTIVE", failure_text(report, "a build failure"),
                "the compiler's message is missing, so the report says the build failed without "
                "saying why — and the log it would otherwise be read from went to a file")

    def test_an_empty_stream_is_refused_rather_than_reported_as_a_passing_suite(self):
        """An empty file is not an empty run — it is a run that never started.

        `go test -json` emits events for every package it touches, including `[no test files]`, so
        a stream with nothing in it means the command died before writing one: a toolchain that
        failed to install, a `go` that exited to stderr, a redirect to the wrong path. All of those
        converted to `0 tests, 0 failed` and exit 0.

        Fifth instance of this tool's own contract, and the same reason the workflow's `test -s`
        guard was blind to the build-failure case: A FILE EXISTING IS NOT A RUN HAVING HAPPENED.
        The whitespace case is not pedantry — a redirect that captured only a trailing newline is
        indistinguishable from a truncated one, and both are the shape this refuses.
        """
        for label, lines in (("empty", []), ("whitespace", ["   ", "", "  "])):
            with self.subTest(stream=label):
                with tempfile.TemporaryDirectory() as tmp:
                    done, _ = convert(tmp, lines)
                    self.assertNotEqual(
                        0, done.returncode,
                        f"a {label} event stream converted to a passing report and a zero exit. "
                        f"Nothing ran, and the step that produced it went green.")
                    self.assertIn("no `go test -json` events", done.stderr + done.stdout)
                    self.assertFalse(
                        (Path(tmp) / "junit.xml").exists(),
                        "a report was written for a run that never happened, and a report on disk "
                        "is what the upload step carries out as evidence")

    def test_a_corrupt_event_stream_is_refused_rather_than_silently_shortened(self):
        """A converter that skips what it cannot parse makes a smaller green report from a bigger
        red run — the same under-reporting shape as a failed read counted as a clean file."""
        with tempfile.TemporaryDirectory() as tmp:
            done, _ = convert(tmp, ['{"Action":"run","Package":"p","Test":"TestOne"}', "not json"])
            self.assertNotEqual(0, done.returncode)
            self.assertIn("not `go test -json` output", done.stderr + done.stdout)


class PythonRunnerTests(unittest.TestCase):
    def run_suite(self, directory, minimum=0):
        out = Path(directory) / "junit.xml"
        done = subprocess.run(
            [sys.executable, "-m", "tools.junit", "--unittest", str(directory),
             "--out", str(out), "--minimum", str(minimum)],
            cwd=ROOT, capture_output=True, text=True)
        return done, out

    def write_suite(self, directory, body):
        (Path(directory) / "test_generated.py").write_text(body, encoding="utf-8")

    def test_a_failing_subtest_reaches_the_report(self):
        """The bug that mattered: `failures="0"` for a run that failed.

        A suite of subtests is not an exotic case here — this repository runs several hundred, so a
        report blind to them would have been green for most of the ways it can go red.
        """
        with tempfile.TemporaryDirectory() as tmp:
            self.write_suite(tmp, "import unittest\n"
                                  "class T(unittest.TestCase):\n"
                                  "    def test_subtests(self):\n"
                                  "        for n in range(60):\n"
                                  "            with self.subTest(n=n):\n"
                                  "                self.assertNotEqual(7, n, 'DISTINCTIVE')\n")
            done, out = self.run_suite(tmp)
            self.assertEqual(1, done.returncode, "a failing subtest did not fail the run")
            report = parse_report(out)
            self.assertEqual(
                "1", report.get("failures"),
                "a subtest failure is missing from the report. unittest delivers those through "
                "addSubTest, never addFailure, so a recorder that only overrides addFailure "
                "produces a green report for a red run — worse than no report at all.")
            failing = report.find(".//testcase[failure]")
            self.assertIsNotNone(
                failing, f"no <testcase> carries a <failure>: tests={report.get('tests')} "
                         f"failures={report.get('failures')} — the subtest failure is missing "
                         f"from the report entirely, which is what this test exists to detect")
            self.assertIn("n=7", failing.get("name"),
                          "the failing case is not named with the subtest parameters, so the "
                          "report says the test failed without saying which subtest")
            self.assertEqual(
                "T", failing.get("classname"),
                "the failing case is filed under the _SubTest wrapper instead of the TestCase that "
                "owns it. `addSubTest` hands over a `_SubTest`, so `type(test).__name__` is the "
                "literal string '_SubTest' — and in a suite that is mostly subtests that is most "
                "of the report, every failure attributed to a class that does not exist.")

    def test_a_report_whose_failure_text_is_hostile_still_parses(self):
        """Writing the report succeeds either way; only reading it tells you."""
        with tempfile.TemporaryDirectory() as tmp:
            self.write_suite(tmp, "import unittest\n"
                                  "class T(unittest.TestCase):\n"
                                  "    def test_control_characters(self):\n"
                                  "        for n in range(60):\n"
                                  "            self.assertTrue(True)\n"
                                  "        self.fail('ansi \\x1b[31mred\\x1b[0m and a bell \\x07 and a nul')\n")
            done, out = self.run_suite(tmp)
            self.assertEqual(1, done.returncode)
            try:
                report = parse_report(out)
            except ET.ParseError as error:
                self.fail(f"the report does not parse ({error}). XML 1.0 forbids most control "
                          f"characters and ElementTree writes them through unescaped, so the "
                          f"artifact fails in front of whoever opened it to read the failure.")
            self.assertEqual("1", report.get("failures"))

    def test_discovery_finding_almost_nothing_is_refused(self):
        """Green report, green gate, nothing ran — the one way this is worse than what it replaces."""
        with tempfile.TemporaryDirectory() as tmp:
            self.write_suite(tmp, "import unittest\n"
                                  "class T(unittest.TestCase):\n"
                                  "    def test_one(self):\n        pass\n")
            done, out = self.run_suite(tmp, minimum=50)
            self.assertNotEqual(0, done.returncode,
                               "a suite of one test was accepted, so a broken discovery would be "
                               "reported as a passing run")
            self.assertIn("fewer than the floor", done.stderr + done.stdout)
            self.assertFalse(out.exists(),
                             "a report was written for a run that was refused, and a report on "
                             "disk is what a later step uploads as evidence")


if __name__ == "__main__":
    unittest.main()
