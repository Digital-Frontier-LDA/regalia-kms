"""Turn a test run into a JUnit report, so a red pull request leaves evidence behind.

#30 AC4 asks for sanitized JUnit from the tiers. Today only the hardware battery produces one
(#185), so the contract holds for the job that runs least often and not for the one that runs on
every pull request — and a failure on the common path leaves nothing to read but a log that ages
out, which somebody has to reproduce locally.

WHAT "SANITIZED" MEANS FOR THIS TIER, MEASURED. The `kms` workflow references no `secrets.*` at
all, so unlike the staging battery there is no credential in scope to redact —
`tools/hsm-transcript-redact.sh` would be a no-op here because it removes the values THIS RUN
holds and this run holds none. The property is kept by a test asserting the workflow stays
secret-free rather than by a filter that would remove nothing; see
tests/test_ci_tiers.py::ArtifactTests.

Two modes, because the two suites emit different things and neither emits JUnit:

    python3 -m tools.junit --gotest gotest.json --out junit.xml
    python3 -m tools.junit --unittest kms/tests --out junit-python.xml

THE EXIT CODE IS THE VERDICT AND IT IS NOT SWALLOWED. Both modes exit non-zero when the run
failed, so a step that produces a report cannot turn a red suite green -- the failure this
repository has already paid for once, when `pytest | tail -1` reported tail's status and a red
suite was committed.
"""

import argparse
import json
import re
import time
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# THE DISCOVERY FLOOR IS AN ARGUMENT, NOT A CONSTANT, and that is the second design this had.
#
# A runner that silently finds fewer tests than the suite has is the one failure mode that makes
# this WORSE than the plain invocation it replaces: green report, green gate, nothing ran. So a
# floor is needed. Baking one in was wrong twice over -- it counts test METHODS, not subtests, so
# any number large enough to protect this repository's suite refuses every smaller one including
# the fixtures that test this tool; and the expectation "the kms suite has ~230 tests" is knowledge
# the CALLER has, not the converter. It belongs at the call site, where it reads as a claim
# somebody made rather than a magic number.
DEFAULT_MINIMUM = 0


# XML 1.0 FORBIDS MOST CONTROL CHARACTERS, and a traceback can carry them: an assertion message
# that quotes a terminal-coloured diff, a tool's output spliced into a failure, a stray NUL from a
# binary fixture. ElementTree writes them through unescaped and the result does not parse — found
# by parsing the tool's own output, which is the only way to find it, because writing succeeds.
#
# A report that cannot be parsed is not evidence, and it fails LATER than the run it describes:
# the suite goes red, the artifact uploads, and whoever opens it gets a parse error instead of the
# failure. Dropped characters are the right trade here -- the alternative is no readable report.
_ILLEGAL = re.compile(
    r"[^\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]")
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _xml_safe(text):
    return _ILLEGAL.sub("", _ANSI.sub("", text or ""))


def _case(suite, name, classname, seconds):
    element = ET.SubElement(suite, "testcase", name=name, classname=classname,
                            time=f"{seconds:.3f}")
    return element


def from_gotest(path):
    """Build a JUnit tree from `go test -json` output.

    Go emits one JSON object per event, not per test, so a case is assembled from its `run`/`pass`
    /`fail`/`skip` events and the `output` events in between. A malformed line is a corrupt input,
    not an empty run: it is reported rather than skipped, because a converter that silently drops
    what it cannot parse produces a smaller green report from a bigger red run.

    A FAILURE WITH NO TEST NAME IS STILL A FAILURE, and it is the one CI hits most. Measured
    against a package that does not compile:

        {"ImportPath":"p [p.test]","Action":"build-output","Output":"./x.go:3:22: syntax error..."}
        {"ImportPath":"p [p.test]","Action":"build-fail"}
        {"Action":"fail","Package":"p","FailedBuild":"p [p.test]"}

    None of those carries a `Test` field. The first version skipped every event without one, so a
    tree that DOES NOT COMPILE converted to `0 tests, 0 failed` and exited zero — a green report
    for a run that never executed a line. That is the fourth instance in this tool of the property
    it exists to hold, and the likeliest one to be hit in practice: a compile error is far more
    common than a failing assertion.

    So package-level and build-level failures become cases of their own. The build output is
    attached to the package that failed to build, because `FailedBuild` names the ImportPath and
    the error text is what the reader actually needs.
    """
    root = ET.Element("testsuite", name="go")
    output, results, order = {}, {}, []
    package_output, package_results, package_order = {}, {}, []
    build_output, build_failed = {}, set()
    events = 0
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"junit: {path}:{number} is not `go test -json` output: {error}")
        events += 1
        action = event.get("Action")
        if action in ("build-output", "build-fail"):
            import_path = event.get("ImportPath", "")
            build_output.setdefault(import_path, []).append(event.get("Output", ""))
            if action == "build-fail":
                build_failed.add(import_path)
            continue
        test = event.get("Test")
        package = event.get("Package", "")
        if not test:
            if package not in package_output:
                package_output[package], _ = [], package_order.append(package)
            if action == "output":
                package_output[package].append(event.get("Output", ""))
            elif action in ("pass", "fail", "skip"):
                package_results[package] = (action, event.get("Elapsed", 0.0) or 0.0,
                                            event.get("FailedBuild", ""))
            continue
        key = (package, test)
        if key not in output:
            output[key], _ = [], order.append(key)
        if action == "output":
            output[key].append(event.get("Output", ""))
        elif action in ("pass", "fail", "skip"):
            results[key] = (action, event.get("Elapsed", 0.0) or 0.0)

    # AN EMPTY FILE IS NOT AN EMPTY RUN. `go test -json` emits events for every package it
    # touches, including `[no test files]`, so a stream with nothing in it is what you get when
    # the command died before writing one — a toolchain that failed to install, a `go` that
    # exited to stderr, a redirect to the wrong path. All of those converted to `0 tests, 0
    # failed`, exit 0.
    #
    # It is the fifth instance in this tool of the property it exists to hold, and the same reason
    # the `test -s` guard in the workflow was blind to the build-failure case: A FILE EXISTING IS
    # NOT A RUN HAVING HAPPENED, and neither is a report with nothing in it.
    if events == 0:
        raise SystemExit(
            f"junit: {path} contains no `go test -json` events. An empty stream is what a run that "
            f"never started produces, not a run with no tests — refusing rather than reporting it "
            f"as a passing suite.")

    failed = skipped = 0
    for key in order:
        package, test = key
        action, elapsed = results.get(key, ("fail", 0.0))
        case = _case(root, test, package, elapsed)
        if action == "fail":
            failed += 1
            ET.SubElement(case, "failure", message="failed").text = _xml_safe("".join(output[key]))
        elif action == "skip":
            skipped += 1
            ET.SubElement(case, "skipped", message="skipped")

    # ONLY FAILING packages become cases. A passing package is already represented by its tests,
    # and emitting one case per package would double every count in the report.
    reported_builds = set()
    for package in package_order:
        action, elapsed, failed_build = package_results.get(package, ("", 0.0, ""))
        if action != "fail":
            continue
        failed += 1
        case = _case(root, f"{package} (package)", "go/package", elapsed)
        detail = "".join(package_output[package])
        if failed_build:
            detail += "".join(build_output.get(failed_build, []))
            reported_builds.add(failed_build)
        ET.SubElement(case, "failure", message="package failed").text = _xml_safe(detail)

    # A build that failed without a package event to carry it — `go vet`-only runs and some
    # tooling versions — must not vanish between the two loops.
    for import_path in sorted(build_failed - reported_builds):
        failed += 1
        case = _case(root, f"{import_path} (build)", "go/build", 0.0)
        ET.SubElement(case, "failure", message="build failed").text = _xml_safe(
            "".join(build_output.get(import_path, [])))

    root.set("tests", str(len(root.findall("testcase"))))
    root.set("failures", str(failed))
    root.set("skipped", str(skipped))
    return root, failed


class _Recorder(unittest.TextTestResult):
    """Records per-test timing and outcome for the report, and changes nothing about the verdict."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records, self._started = [], None

    def startTest(self, test):
        self._started = time.monotonic()
        super().startTest(test)

    def _record(self, test, outcome, detail="", owner=None):
        """`owner` is the TestCase a record belongs to, carried rather than derived.

        A subtest record's `test` is a `_SubTest` wrapper, so asking the recorded object for its
        class yields the literal string "_SubTest" and files every subtest failure under a class
        that does not exist — in a suite that is mostly subtests, most of the report. The wrapper
        does expose the owner, but `addSubTest` is already HANDED the owning TestCase as its first
        argument, so carrying it is both simpler and avoids naming an attribute whose name looks
        like a test function to this repository's own reference checker.
        """
        self.records.append((test, outcome, detail,
                             time.monotonic() - (self._started or 0), owner or test))

    def addSuccess(self, test):
        super().addSuccess(test); self._record(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err); self._record(test, "fail", self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err); self._record(test, "fail", self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self._record(test, "skip", reason)

    def addSubTest(self, test, subtest, outcome):
        """SUBTEST FAILURES DO NOT ARRIVE THROUGH addFailure, AND THIS SUITE IS MOSTLY SUBTESTS.

        Found by running the converter rather than reading it: the first version reported
        `failures="0"` for a run with two real failures, because both were subtest failures and
        `addSubTest` is the only method they reach. `wasSuccessful()` was False and the exit code
        was right, so the ONLY wrong artifact was the one this tool exists to produce -- a green
        report for a red run, which is worse than no report at all.

        A subtest is recorded as its own case, named with the parameters that identify it, because
        "TestFoo failed" is not actionable when the failure was one of forty subtests.
        """
        super().addSubTest(test, subtest, outcome)
        if outcome is not None:
            self._record(subtest, "fail", self._exc_info_to_string(outcome, test), owner=test)


def from_unittest(start_dir, minimum=DEFAULT_MINIMUM):
    """Discover and run the unittest suite exactly as `unittest discover` does, and report it."""
    loader = unittest.defaultTestLoader
    # NO top_level_dir, because CI passes none. `unittest discover -s kms/tests` defaults it to
    # the start directory and puts that on sys.path, so the tests import as top-level modules and
    # `kms` resolves from the working directory. Setting it to the repository root instead makes
    # discovery demand that kms/tests be an importable package, which it is not -- ImportError,
    # from a runner whose whole job is to run the same tests the same way.
    discovered = loader.discover(start_dir=start_dir, pattern="test_*.py")
    count = discovered.countTestCases()
    if count < minimum:
        raise SystemExit(
            f"junit: discovery found {count} tests under {start_dir}, fewer than the floor of "
            f"{minimum} this run was given. A runner that finds fewer tests than the suite has "
            f"produces a green report from a run that did not happen — refusing rather than "
            f"reporting it. NOTE the floor counts test methods, not subtests.")
    runner = unittest.TextTestRunner(resultclass=_Recorder, verbosity=1)
    result = runner.run(discovered)
    root = ET.Element("testsuite", name="python")
    failed = skipped = 0
    for test, outcome, detail, seconds, owner in result.records:
        # str(test) for a subtest carries its parameters; _testMethodName would collapse forty
        # distinct subtests into one repeated name and lose which one failed.
        name = str(test) if outcome == "fail" and " (" in str(test) else test._testMethodName
        # THE OWNING TestCase, NOT THE _SubTest WRAPPER — see _record. Same seam as the subtest
        # defect above: the recorder is handed something structurally different, and a naive read
        # of its type takes it without complaint.
        case = _case(root, _xml_safe(name), type(owner).__name__, seconds)
        if outcome == "fail":
            failed += 1
            ET.SubElement(case, "failure", message="failed").text = _xml_safe(detail)
        elif outcome == "skip":
            skipped += 1
            ET.SubElement(case, "skipped", message=_xml_safe(detail)[:200])
    root.set("tests", str(len(result.records)))
    root.set("failures", str(failed))
    root.set("skipped", str(skipped))
    return root, 0 if result.wasSuccessful() else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--gotest", metavar="FILE", help="`go test -json` output to convert")
    source.add_argument("--unittest", metavar="DIR", help="directory to discover and run")
    parser.add_argument("--out", required=True, help="where to write the JUnit report")
    parser.add_argument("--minimum", type=int, default=DEFAULT_MINIMUM, metavar="N",
                        help="refuse if discovery finds fewer than N test methods (unittest mode)")
    args = parser.parse_args(argv)

    root, failures = (from_gotest(args.gotest) if args.gotest
                      else from_unittest(args.unittest, args.minimum))
    ET.ElementTree(root).write(args.out, encoding="utf-8", xml_declaration=True)
    # THE FAILURES GO TO STDOUT TOO. In gotest mode the run's own output went to a file, so
    # without this the job log shows a red step and nothing about what failed — an artifact you
    # must download to learn anything is a worse log, not a better one.
    for case in root.findall("testcase"):
        failure = case.find("failure")
        if failure is not None:
            print(f"\n--- FAIL {case.get('classname')} {case.get('name')} ---")
            print((failure.text or "").rstrip()[:4000])
    print(f"junit: {root.get('tests')} tests, {root.get('failures')} failed, "
          f"{root.get('skipped')} skipped -> {args.out}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
