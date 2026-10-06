"""#512: a software TPM with no resource manager keeps the sessions of a call that died connected, and three of them
leave no slot (TPM_RC_SESSION_MEMORY, 0x903: three-node-recovery on #493). membership.run_tpm2 flushes the orphans and
asks once more, on a simulator only. Run with python -B (a stale .pyc runs the previous falsifier case)."""
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


class Gate(unittest.TestCase):
    def test_a_simulator_without_a_slot_is_flushed_and_asked_once_more(self):
        run = Recorder(done(1, err=NO_SLOT.encode()), done(), done(0, b"read"))
        got = membership.run_tpm2(run, ["tpm2_nvread", "0x1500017"], {"E": "1"}, "swtpm:path=/x", input=b"in")
        self.assertEqual(got.stdout, b"read")
        self.assertEqual([c[0] for c in run.calls], [["tpm2_nvread", "0x1500017"], ["tpm2_flushcontext", "-l"], ["tpm2_nvread", "0x1500017"]])
        self.assertEqual(run.calls[2][1], {"capture_output": True, "env": {"E": "1"}, "input": b"in"})   # the same call again

    def test_the_tcti_from_the_environment_counts(self):
        run = Recorder(done(1, err=NO_SLOT), done(), done())
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI="mssim:host=localhost"):
            self.assertEqual(membership.run_tpm2(run, ["tpm2_nvread"], None).returncode, 0)
        self.assertEqual(len(run.calls), 3)

    def test_a_host_resource_manager_is_never_flushed(self):
        for tcti in ("device:/dev/tpmrm0", "tabrmd:bus_type=system"):
            run = Recorder(done(1, err=NO_SLOT.encode()))
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                got = membership.run_tpm2(run, ["tpm2_nvread"], None, tcti)
            self.assertEqual((got.returncode, len(run.calls)), (1, 1), tcti)

    def test_the_code_alone_is_enough(self):
        for err in ("ERROR: Esys_StartAuthSession(0x903) - tpm:warn(2.0): (reworded)", "Esys Finish ErrorCode (0x00000903)"):
            run = Recorder(done(1, err=err.encode()), done(), done())
            self.assertEqual(membership.run_tpm2(run, ["tpm2_nvread"], None, "swtpm:path=/x").returncode, 0, err)
        run = Recorder(done(1, err=b"ERROR: Esys_ContextSave(0x901) - tpm:warn(2.0): gap for context ID is too large"))
        self.assertEqual(len((membership.run_tpm2(run, ["tpm2_nvread"], None, "swtpm:path=/x"), run.calls)[1]), 1)   # 0x901: not ours

    def test_any_other_failure_is_answered_as_it_is(self):
        run = Recorder(done(1, err=b"ERROR: Esys_NV_Read(0x98E) - tpm:session(1):the authorization HMAC check failed"))
        self.assertEqual((membership.run_tpm2(run, ["tpm2_nvread"], None, "swtpm:path=/x").returncode, len(run.calls)), (1, 1))

    def test_asked_once_more_only(self):
        run = Recorder(done(1, err=NO_SLOT.encode()), done(), done(1, err=NO_SLOT.encode()))
        self.assertEqual(membership.run_tpm2(run, ["tpm2_nvread"], None, "swtpm:path=/x").returncode, 1)
        self.assertEqual(len(run.calls), 3)

    def test_the_anchor_and_the_signing_key_take_it(self):
        run = Recorder(done(1, err=NO_SLOT.encode()), done(), done(0, b"x"))
        hw = membership.HighWater("0x1500017", tcti="swtpm:path=/x", run=run)
        self.assertEqual(hw._tpm("nvread", "0x1500017").stdout, b"x")
        run = Recorder(done(1, err=NO_SLOT.encode()), done(), done(0, b"y"), done())      # the last: its transients' flush
        self.assertEqual(signkey._tpm(run, "swtpm:path=/x", "startauthsession", "--policy-session", "-S", "s"), b"y")
        self.assertEqual(run.calls[1][0], ["tpm2_flushcontext", "-l"])


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

    def test_orphans_take_every_slot_and_the_next_call_gets_one(self):
        start_auth_sessions(self.sock, 3)
        self.assertEqual(self.loaded(), 3)
        plain = subprocess.run(self.session("plain.ctx"), capture_output=True, env=self.env)
        self.assertIn(membership.SESSION_MEMORY, plain.stderr.decode())      # the fixture's failure, reproduced
        got = membership.run_tpm2(subprocess.run, self.session("new.ctx"), self.env, self.tcti)
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertEqual(self.loaded(), 0)                                    # its own session saved, the orphans gone

    def test_a_live_flow_between_its_calls_is_not_touched(self):
        live = os.path.join(self.d, "live.ctx")
        subprocess.run(["tpm2_startauthsession", "--policy-session", "-S", live], check=True, capture_output=True, env=self.env)
        start_auth_sessions(self.sock, 3)
        got = membership.run_tpm2(subprocess.run, self.session("new.ctx"), self.env, self.tcti)
        self.assertEqual(got.returncode, 0, got.stderr)
        subprocess.run(["tpm2_policypcr", "-S", live, "-l", "sha256:11"], check=True, capture_output=True, env=self.env)
        subprocess.run(["tpm2_flushcontext", live], check=True, capture_output=True, env=self.env)


if __name__ == "__main__":
    unittest.main()
