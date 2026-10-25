"""e2e/lib/tpmdiag.py (regalia-zga): what a software-TPM run keeps. The log level each harness passes to swtpm, and
the versions line, which says what is absent rather than failing where a tool is not installed."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import tpmdiag  # noqa: E402


class TpmDiag(unittest.TestCase):
    def test_swtpm_logs_every_command(self):
        self.assertEqual(tpmdiag.log_arg("/tmp/x/tpm.log"), "file=/tmp/x/tpm.log,level=20")

    def test_the_versions_line_names_each_part_and_says_what_is_absent(self):
        with mock.patch.object(tpmdiag.shutil, "which", lambda name: None):
            line = tpmdiag.versions()
        for part in ("swtpm absent", "tpm2-tools absent", "qemu absent", "libtpms ?", "kernel "):
            self.assertIn(part, line)
        self.assertTrue(line.startswith("TPM stack: "))

    def test_keep_copies_the_logs_in_ci_only(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        log = os.path.join(d, "tpm.log")
        with open(log, "w") as f:
            f.write("swtpm level 20\n")
        files = {"a/tpm.log": log, "b/tpm.log": os.path.join(d, "missing.log")}
        self.assertEqual(tpmdiag.keep(files, "run1", root=d + "/kept", environ={}), [])                     # a laptop: nothing
        kept = tpmdiag.keep(files, "run1", root=d + "/kept", environ={"RUNNER_ENVIRONMENT": "github-hosted"})
        self.assertEqual(kept, [d + "/kept/run1/a/tpm.log"])                                               # a missing one skipped
        with open(kept[0]) as f:
            self.assertEqual(f.read(), "swtpm level 20\n")

    def test_every_harness_that_starts_swtpm_logs_it(self):
        """The three harnesses this covers pass tpmdiag.log_arg to each swtpm they start, never a bare --log."""
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
        for path in ("e2e/lib/threenode.py", "e2e/node-units-systemd.py", "tests/test_baremetal_unlock_boot.py"):
            with self.subTest(path), open(os.path.join(root, path)) as f:
                source = f.read()
            launches = source.count('"swtpm", "socket"') + source.count('"swtpm", "chardev"') + source.count('"swtpm", "cuse"')
            self.assertGreater(launches, 0, "no swtpm started in %s: this check reads nothing" % path)
            self.assertEqual(source.count("tpmdiag.log_arg("), launches, "%s starts a swtpm without its level-20 log" % path)


if __name__ == "__main__":
    unittest.main()
