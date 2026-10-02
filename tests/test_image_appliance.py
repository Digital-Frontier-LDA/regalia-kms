"""Unattended guest failures must not hang or publish a passing result."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest

from deploy.images.verify import VerificationError
from lab.appliance.build import install_guest


class ApplianceGuestTests(unittest.TestCase):
    def test_completed_guest_returns_and_preserves_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            install_guest([sys.executable, "-c", "import sys;print('public diagnostic',file=sys.stderr)"], log, 10)
            self.assertIn("public diagnostic", log.with_suffix(".stderr").read_text())

    def test_fixed_failure_marker_terminates_the_exact_child(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            pid = Path(directory) / "guest.pid"
            code = ("import os,pathlib,sys,time;pathlib.Path(sys.argv[2]).write_text(str(os.getpid()));"
                    "pathlib.Path(sys.argv[1]).write_text('REGALIA_BUILD_FAILED');time.sleep(60)")
            with self.assertRaisesRegex(VerificationError, "guest setup failed"):
                install_guest([sys.executable, "-c", code, str(log), str(pid)], log, 10)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid.read_text()), 0)

    def test_failure_marker_is_rejected_even_after_a_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            code = "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('REGALIA_BUILD_FAILED')"
            with self.assertRaisesRegex(VerificationError, "guest setup failed"):
                install_guest([sys.executable, "-c", code, str(log)], log, 10)

    def test_nonzero_guest_exit_and_timeout_are_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            with self.assertRaises(VerificationError):
                install_guest([sys.executable, "-c", "raise SystemExit(3)"], log, 10)
            with self.assertRaises(subprocess.TimeoutExpired):
                install_guest([sys.executable, "-c", "import time;time.sleep(60)"], log, 0.1)


if __name__ == "__main__":
    unittest.main()
