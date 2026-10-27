""".github/actions/tpm-diagnostics finds what the fixtures keep (regalia-afi, #605). threenode's close() keeps each node's
KEPT_LOGS through tpmdiag.keep; the action uploads only what its `find` matches. Run 40456967936 kept abrmd.log and
dbus.log on disk and uploaded none of them: the action named tpm.log only. So the action's own find expression, read
from its YAML, is run here against a tree tpmdiag.keep itself built, and every kept log must be found: its names and
its -maxdepth both."""
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "e2e", "lib"))
import threenode  # noqa: E402
import tpmdiag  # noqa: E402

ACTION = os.path.join(ROOT, ".github", "actions", "tpm-diagnostics", "action.yml")


def find_expression():
    """The action's `sudo find /tmp …` up to its -exec, its line continuations joined: (start, the rest as argv)."""
    text = open(ACTION).read()
    match = re.search(r"sudo find (/tmp)(.*?)-exec", text.replace("\\\n", " "), re.S)
    if match is None:
        raise AssertionError("the action has no `sudo find /tmp … -exec`: this test no longer reads what it uploads")
    return match.group(1), shlex.split(match.group(2))


def found(top, argv):
    """What the expression matches under `top`, NUL-separated (-print0): a path with a space is one path (CodeRabbit on
    #605; the tree below has one in it)."""
    done = subprocess.run(["find", top] + argv + ["-print0"], capture_output=True, check=True)
    return sorted(os.path.relpath(os.fsdecode(path), top) for path in done.stdout.split(b"\0") if path)


class Action(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(tempfile.mkdtemp(dir=os.environ.get("TMPDIR")), "a tmp with spaces")   # found() splits by NUL
        os.mkdir(self.tmp)
        self.addCleanup(subprocess.run, ["rm", "-rf", os.path.dirname(self.tmp)])
        work = os.path.join(self.tmp, "work")
        files = {}
        for node in ("a", "b", "c"):
            os.makedirs(os.path.join(work, node))
            for log in threenode.KEPT_LOGS:
                path = os.path.join(work, node, log)
                open(path, "w").write(log)
                files["%s/%s" % (node, log)] = path
        # as close() calls it, under the action's /tmp (KEEP_DIR's place in it kept), with the label a work dir has
        keep_root = os.path.join(self.tmp, os.path.relpath(tpmdiag.KEEP_DIR, "/tmp"))
        self.kept = tpmdiag.keep(files, "three-node-k1f53hwg", root=keep_root, environ={"RUNNER_ENVIRONMENT": "github-hosted"})
        subprocess.run(["rm", "-rf", work], check=True)        # as the scripts remove theirs after close()

    def test_every_log_the_fixture_keeps_is_found(self):
        top, argv = find_expression()
        self.assertEqual(top, "/tmp")
        self.assertEqual(len(self.kept), 3 * len(threenode.KEPT_LOGS))
        self.assertEqual(found(self.tmp, argv), sorted(os.path.relpath(path, self.tmp) for path in self.kept))

    def test_the_abrmd_route_logs_are_among_them(self):
        self.assertIn("abrmd.log", threenode.KEPT_LOGS)
        self.assertIn("dbus.log", threenode.KEPT_LOGS)

    def test_the_control_an_expression_naming_tpm_log_only_misses_them(self):
        """The test's power: the expression as it was before #605's fix finds 3 of the 9."""
        hits = found(self.tmp, ["-maxdepth", "4", "-type", "f", "-name", "tpm.log"])
        self.assertEqual(len(hits), 3)
        self.assertTrue(all(hit.endswith("/tpm.log") for hit in hits))


if __name__ == "__main__":
    unittest.main()
