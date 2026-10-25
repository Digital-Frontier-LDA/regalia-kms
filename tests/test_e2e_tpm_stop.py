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


class MoreEvidence(TpmStopReport):
    """#592: the third occurrence was misread from an 800-character slice of the log (its last command looked like an
    NV_ReadPublic; the artifact showed an orderly Shutdown). The report now says what swtpm was doing as it ignored
    SIGTERM: its signal masks, every thread's state and wait, its syscall, its open fds, and the log's last command."""

    def test_signals_threads_syscall_fds_and_the_last_command(self):
        proc = self.proc(4244, cmdline="swtpm\0socket\0", syscall="7 0x3 0x7ffd 0x1 0x0 0x0 0x0 0x7ffd 0x7f12\n",
                         status="Name:\tswtpm\nState:\tR (running)\nPPid:\t1\nSigPnd:\t0000000000000000\n"
                                "ShdPnd:\t0000000000004000\nSigBlk:\t0000000000000000\nSigIgn:\t0000000000001000\n"
                                "SigCgt:\t0000000000004002\n", wchan="0", stack="")
        for tid, state, wchan in ((4244, "R", "0"), (4250, "S", "do_sys_poll")):
            task = self.d / "proc" / "4244" / "task" / str(tid)
            task.mkdir(parents=True)
            (task / "stat").write_text("%d (swtpm) %s 1 1 1\n" % (tid, state))
            (task / "wchan").write_text(wchan)
        fd = self.d / "proc" / "4244" / "fd"
        fd.mkdir()
        os.symlink("socket:[91234]", fd / "3")
        os.symlink("/tmp/x/c/tpm.log", fd / "4")
        log = self.d / "tpm.log"
        log.write_text("".join(" line %d\n" % i for i in range(40)) + "    IsEnEnabled(0x169 = 'NV_ReadPublic'): 1\n"
                       "Data client disconnected\n    IsEnEnabled(0x145 = 'Shutdown'): 1\n SWTPM_IO_Write: length 10\n"
                       "Data client disconnected\n")
        report = tn.tpm_stop_report(4244, log, None, proc=proc)
        for part in ("ShdPnd 0000000000004000", "SigCgt 0000000000004002", "SigBlk 0000000000000000",
                     "SIGTERM pending (process-wide), caught", "threads 4244:R:0 4250:S:do_sys_poll",
                     "syscall '7 0x3 0x7ffd", "fds 3->socket:[91234] 4->/tmp/x/c/tpm.log",
                     "last command Shutdown (0x145)", "client attached no (it disconnected after its last command)"):
            self.assertIn(part, report)
        self.assertIn(" line 39", report)                          # the log's tail is whole lines, never a slice of one
        self.assertNotIn(" line 9\n", report)

    def test_sigterm_not_caught_and_a_client_still_attached(self):
        proc = self.proc(4245, status="State:\tS (sleeping)\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n"
                                       "SigBlk:\t0000000000004000\nSigCgt:\t0000000000000000\n")
        log = self.d / "tpm.log"
        log.write_text("    IsEnEnabled(0x169 = 'NV_ReadPublic'): 1\n SWTPM_IO_Write: length 94\n")
        report = tn.tpm_stop_report(4245, log, None, proc=proc)
        self.assertIn("SIGTERM not pending, blocked, not caught", report)
        self.assertIn("last command NV_ReadPublic (0x169)", report)
        self.assertIn("client attached yes (no disconnect after its last command)", report)


class StopAfterShutdown(unittest.TestCase):
    """#592: swtpm 0.10.1 took an orderly TPM2_Shutdown, its client left, and it did not exit on SIGTERM. A host would
    simply lose power: after a Shutdown that succeeded, the TPM is ended with SIGKILL and the run goes on, the full
    report printed as an anomaly. Anything else that does not stop is still a failure."""

    def run_stop(self, gone_after, orderly_ok):
        sent, alive = [], {"n": 0}

        def kill(pid, sig):
            sent.append(sig)

        def gone():
            alive["n"] += 1
            return sent and sent[-1] in gone_after
        said = []
        result = tn.stop_tpm_process(4246, orderly_ok, lambda: "REPORT", kill=kill, gone=gone, wait=lambda what, s, i: what(),
                                     say=said.append)
        return sent, result, said

    def test_sigterm_enough(self):
        import signal
        sent, result, said = self.run_stop({signal.SIGTERM}, orderly_ok=True)
        self.assertEqual((sent, result, said), ([signal.SIGTERM], None, []))

    def test_after_an_orderly_shutdown_sigkill_ends_it_and_the_anomaly_is_said(self):
        import signal
        sent, result, said = self.run_stop({signal.SIGKILL}, orderly_ok=True)
        self.assertEqual(sent, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(result, "REPORT")
        self.assertEqual(len(said), 1)
        self.assertTrue(said[0].startswith("TPM-STOP-ANOMALY (#592): swtpm pid 4246 ignored SIGTERM after an orderly Shutdown"))
        self.assertIn("REPORT", said[0])

    def test_without_an_orderly_shutdown_it_is_still_a_failure(self):
        import signal
        with self.assertRaisesRegex(RuntimeError, "did not stop: REPORT"):
            self.run_stop({signal.SIGKILL}, orderly_ok=False)

    def test_if_sigkill_does_not_end_it_either_it_is_a_failure(self):
        with self.assertRaisesRegex(RuntimeError, "did not stop, not even on SIGKILL: REPORT"):
            self.run_stop(set(), orderly_ok=True)


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
