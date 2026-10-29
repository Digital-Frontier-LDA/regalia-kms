"""#592: a 0x903 (TPM_RC_SESSION_MEMORY) is a failure, said as the TPM said it: nothing flushes the TPM's sessions or
asks once more. #514 did both on a software TPM, because the three-node fixture reached each node's swtpm through its raw
socket, where a call that died connected kept its slot; the fixture now goes through one tpm2-abrmd per node (#605,
#607), which, like a host's /dev/tpmrm0, ends a dead connection's sessions with it, and e2e/abrmd-probe.sh is the
regression for the exhaustion itself. A retry kept there would only hide a slot leak the resource manager should have
made impossible. Run with python -B (a stale .pyc runs the previous case)."""
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import membership, signkey

NO_SLOT = "WARNING:esys:...: Esys_StartAuthSession(0x903) - tpm:warn(2.0): out of memory for session contexts"
SESSION_MEMORY = "out of memory for session contexts"


def done(rc=0, out=b"", err=b""):
    return subprocess.CompletedProcess([], rc, out, err)


class Recorder:
    """A fake `run`: answers in order, records what it was asked."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        if not self.answers:
            raise AssertionError("asked once more than expected: %s" % " ".join(argv))
        return self.answers.pop(0)


class NoSlotIsAFailure(unittest.TestCase):
    """Every TCTI, the software TPM's included: one call, its failure as it is, no flush."""
    TCTIS = ("swtpm:path=/x", "mssim:host=localhost", "device:/dev/tpmrm0", "tabrmd:bus_type=system")
    ERRORS = (NO_SLOT, "ERROR: Esys_StartAuthSession(0x903) - tpm:warn(2.0): (reworded)", "Esys Finish ErrorCode (0x00000903)")

    def test_the_anchor_reads_once_and_answers_the_tpms_failure(self):
        for tcti in self.TCTIS:
            for err in self.ERRORS:
                run = Recorder(done(1, err=err.encode()))
                hw = membership.HighWater("0x1500017", tcti=tcti, run=run)
                got = hw._tpm("nvread", "0x1500017")
                self.assertEqual((got.returncode, got.stderr), (1, err.encode()), (tcti, err))
                self.assertEqual([c[0] for c in run.calls], [["tpm2_nvread", "0x1500017"]], (tcti, err))

    def test_the_tcti_from_the_environment_changes_nothing(self):
        run = Recorder(done(1, err=NO_SLOT.encode()))
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI="mssim:host=localhost"):
            self.assertEqual(membership.HighWater("0x1500017", run=run)._tpm("nvread", "0x1500017").returncode, 1)
        self.assertEqual(len(run.calls), 1)

    def test_the_signing_key_refuses_with_what_the_tpm_said(self):
        run = Recorder(done(1, err=NO_SLOT.encode()), done())      # the call, then its transients' flush (-t), never -l
        with self.assertRaises(membership.Refused) as said:
            signkey._tpm(run, "swtpm:path=/x", "startauthsession", "--policy-session", "-S", "s")
        self.assertIn("0x903", str(said.exception))
        self.assertEqual([c[0] for c in run.calls], [["tpm2_startauthsession", "--policy-session", "-S", "s"],
                                                     ["tpm2_flushcontext", "-t"]])


def start_auth_sessions(sock, count):
    """`count` TPM2_StartAuthSession (policy, unbound, unsalted) on one raw connection, which then closes without a
    ContextSave or a flush: what a tpm2-tools call killed between ContextLoad and ContextSave leaves on a swtpm."""
    body = struct.pack(">II", 0x40000007, 0x40000007) + struct.pack(">H", 16) + os.urandom(16) + struct.pack(">H", 0) \
        + bytes([0x01]) + struct.pack(">HH", 0x0010, 0x000B)
    command = struct.pack(">HII", 0x8001, 10 + len(body), 0x00000176) + body
    with socket.socket(socket.AF_UNIX) as s:
        s.connect(sock)
        for _ in range(count):
            s.sendall(command)
            head = b""
            while len(head) < 10:
                head += s.recv(10 - len(head))
            _, size, rc = struct.unpack(">HII", head)
            rest = size - 10
            while rest > 0:
                rest -= len(s.recv(rest))
            if rc != 0:
                raise AssertionError("TPM2_StartAuthSession answered 0x%x" % rc)


class OnSwtpm(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_startauthsession", "tpm2_flushcontext", "tpm2_getcap")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm and tpm2-tools are expected here and were not found")
            self.skipTest("needs swtpm and tpm2-tools")
        self.d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
        self.addCleanup(shutil.rmtree, self.d, True)
        state, self.sock = self.d + "/tpm", self.d + "/tpm.sock"
        os.mkdir(state)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + self.sock,
                        "--ctrl", "type=unixio,path=" + self.sock + ".ctrl", "--flags", "not-need-init,startup-clear",
                        "--daemon", "--pid", "file=%s/pid" % self.d], check=True, capture_output=True)
        deadline = time.monotonic() + 10
        while True:
            try:
                with open(self.d + "/pid") as f:
                    pid = int(f.read())
                break
            except (FileNotFoundError, ValueError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.addCleanup(lambda: os.kill(pid, 15))
        self.tcti = "swtpm:path=" + self.sock
        self.env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)

    def loaded(self):
        out = subprocess.run(["tpm2_getcap", "handles-loaded-session"], capture_output=True, text=True, env=self.env, check=True).stdout
        return out.count("0x")

    def session(self, name):
        return ["tpm2_startauthsession", "--policy-session", "-S", os.path.join(self.d, name)]

    def test_orphans_take_every_slot_and_the_next_call_says_so(self):
        """What #514 absorbed on the raw socket, now a failure that names it: on a swtpm with no resource manager (what
        the fixture no longer is), three orphaned sessions leave the anchor's next call no slot."""
        start_auth_sessions(self.sock, 3)
        self.assertEqual(self.loaded(), 3)
        hw = membership.HighWater("0x1500017", tcti=self.tcti)
        got = hw._tpm("startauthsession", "--policy-session", "-S", os.path.join(self.d, "new.ctx"))
        self.assertNotEqual(got.returncode, 0)
        self.assertIn(SESSION_MEMORY, got.stderr.decode())
        self.assertEqual(self.loaded(), 3)                                    # nothing flushed them


if __name__ == "__main__":
    unittest.main()
