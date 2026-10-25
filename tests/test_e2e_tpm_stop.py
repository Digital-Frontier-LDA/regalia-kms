"""e2e/lib/threenode.py tpm_stop_report (regalia-zga): when a software TPM does not stop, the failure says what the
process looked like, so its cause is observed rather than guessed. Read from a stand-in /proc."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode as tn  # noqa: E402


class TpmStopReport(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def proc(self, pid, **files):
        (self.d / "proc" / str(pid)).mkdir(parents=True)
        for name, text in files.items():
            (self.d / "proc" / str(pid) / name).write_bytes(text.encode())
        return str(self.d / "proc")

    def test_it_names_the_state_the_parent_the_wait_and_the_log(self):
        proc = self.proc(4242, cmdline="swtpm\0socket\0--tpm2\0", status="Name:\tswtpm\nState:\tZ (zombie)\nPPid:\t1\n",
                         wchan="do_exit", stack="[<0>] do_exit+0x1\n")
        log = self.d / "tpm.log"
        log.write_text("swtpm: ... TPM2_Shutdown\\n")
        shutdown = subprocess.CompletedProcess([], 1, "", "ERROR: Esys_Shutdown 0x1")
        report = tn.tpm_stop_report(4242, log, shutdown, proc=proc)
        for part in ("pid 4242", "'swtpm socket --tpm2'", "State Z (zombie)", "PPid 1", "wchan do_exit", "do_exit+0x1",
                     "tpm2_shutdown 1 'ERROR: Esys_Shutdown 0x1'", "TPM2_Shutdown"):
            self.assertIn(part, report)

    def test_what_cannot_be_read_is_said_never_a_crash(self):
        report = tn.tpm_stop_report(4243, self.d / "no-log", None, proc=str(self.d / "proc"))   # gone, and no log
        self.assertIn("pid 4243", report)
        self.assertIn("State ?", report)
        self.assertIn("log <", report)
        self.assertNotIn("tpm2_shutdown", report)                     # a cut: no orderly shutdown was asked


class JournalStalls(unittest.TestCase):
    def test_a_stalled_journal_is_said_and_the_report_still_returns(self):
        from unittest import mock

        def stalls(*argv, **kw):
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        with mock.patch.object(tn, "sh", stalls):
            report = tn.tpm_stop_report(1, "/nonexistent/tpm.log")          # the real /proc: pid 1 is there
        self.assertIn("apparmor <journalctl did not answer within 10 s>", report)


if __name__ == "__main__":
    unittest.main()
