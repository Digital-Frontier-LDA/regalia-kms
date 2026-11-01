"""A Go test that needs root is invisible unless CI runs it as root (regalia-8zj, found on kms#641): build-test runs
`go test ./...` as the runner's user, where a root gate skips or takes its non-root branch and passes. So every test
with a root gate (`os.Getuid() != 0` / `os.Geteuid() != 0`) must be named, exactly, in ci.yml's privileged-and-fuzz
job, which runs it under sudo where a skip fails; and every name there must still be a test."""
import glob
import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
GATE = re.compile(r"os\.Gete?uid\(\)\s*!=\s*0")
FUNC = re.compile(r"^func (Test\w+)\(t \*testing\.T\)", re.M)


def root_gated_tests():
    found = set()
    for path in glob.glob(os.path.join(ROOT, "**", "*_test.go"), recursive=True):
        if "/vendor/" in path or "/.git/" in path:
            continue
        with open(path) as f:
            text = f.read()
        starts = [(m.start(), m.group(1)) for m in FUNC.finditer(text)] + [(len(text), None)]
        for (at, name), (end, _) in zip(starts, starts[1:]):
            if GATE.search(text[at:end]):
                found.add((os.path.relpath(os.path.dirname(path), ROOT), name))
    return found


def privileged_runs():
    with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
        steps = yaml.safe_load(f)["jobs"]["privileged-and-fuzz"]["steps"]
    return "\n".join(s.get("run", "") for s in steps if "sudo" in s.get("run", ""))


class RootOnlyGoTestsRunInCI(unittest.TestCase):
    def test_the_scan_finds_the_known_root_gated_tests(self):
        # a positive control: a scan that finds nothing would pass the check below vacuously
        self.assertLessEqual({("internal/pin", "TestACredentialOwnedByAThirdUserIsRefused"),
                              ("cmd/regalia-kms", "TestAdmitRunnerRefusesWorkUntilTheNodeIsAdmitted"),
                              ("internal/admission", "TestAFileOfAnotherOwnerInTheOwnersDirectoryIsRefused")}, root_gated_tests())

    def test_every_root_gated_test_runs_as_root_in_ci(self):
        runs = privileged_runs()
        for pkg, name in sorted(root_gated_tests()):
            with self.subTest(test=name):
                self.assertIn("^%s$" % name, runs, "%s (%s) has a root gate and no CI step runs it as root" % (name, pkg))
                self.assertRegex(runs, r"(\./|\|)%s\b" % re.escape(pkg), "no root step builds %s" % pkg)

    def test_every_name_ci_runs_as_root_is_a_root_gated_test(self):
        named = set(re.findall(r"\^(Test\w+)\$", privileged_runs()))
        self.assertTrue(named)
        self.assertEqual(named - {n for _, n in root_gated_tests()}, set())


if __name__ == "__main__":
    unittest.main()
