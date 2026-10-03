"""Unattended guest failures must not hang or publish a passing result."""

from pathlib import Path
import os
import json
import socket
import threading
import subprocess
import sys
import tempfile
import unittest

from deploy.images.verify import VerificationError
from lab.appliance.build import install_guest
from lab.appliance.probe import qmp_powerdown


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


class PowerdownTests(unittest.TestCase):
    def exchange(self, error=False):
        client, server = socket.socketpair()
        commands = []
        failures = []
        def producer():
            try:
                with server, server.makefile("rwb") as stream:
                    stream.write(b'{"QMP":{}}\n')
                    stream.flush()
                    for _ in range(2):
                        request = json.loads(stream.readline(65536))
                        commands.append(request["execute"])
                        # An unsolicited event must not be mistaken for an ACK.
                        stream.write(b'{"event":"POWERDOWN"}\n')
                        reply = {"id":request["id"], "error":{}} if error else {"id":request["id"], "return":{}}
                        stream.write(json.dumps(reply).encode() + b"\n")
                        stream.flush()
                        if error:
                            break
            except BaseException as exception:
                failures.append(exception)
        worker = threading.Thread(target=producer)
        worker.start()
        try:
            with client:
                client.settimeout(2)
                if error:
                    with self.assertRaisesRegex(VerificationError, "not acknowledged"):
                        qmp_powerdown(client)
                else:
                    qmp_powerdown(client)
        finally:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        return commands

    def test_capabilities_and_powerdown_require_acknowledgements(self):
        self.assertEqual(self.exchange(), ["qmp_capabilities", "system_powerdown"])

    def test_qmp_error_cannot_count_as_a_clean_powerdown(self):
        self.assertEqual(self.exchange(error=True), ["qmp_capabilities"])


if __name__ == "__main__":
    unittest.main()
