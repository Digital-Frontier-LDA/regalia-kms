"""#242 step C2: the tools that make owner-authorized TPM calls take the owner authorization from the node's envelope.

  * the value on standard input (`gpg --decrypt ownerauth-<node>.yk.gpg | sudo <tool> ... --ownerauth RECORD`): sudo
    closes every descriptor above 2, so not another descriptor; what the operator types is read from the terminal;
  * enrol commit hands it to its regalia-sync steps through an inherited sealed memfd (--ownerauth-fd), closed after;
  * under v4 enrolment refuses a TPM whose owner or lockout authorization is empty, and a commit without the value;
  * an owner call refused for its authorization says what to give; set refuses before systemd's SRK is persistent;
  * reanchor and recount pass it to the anchor and the counter."""
import io
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import enrol, heartbeat, membership as m, ownerauth
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_ownerauth import PIN, RECORD, VECTOR, value


class Args:
    def __init__(self, record=None):
        self.ownerauth = record


class TheValueOnStandardInput(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.record = os.path.join(self.d, "ownerauth.record.json")
        with open(self.record, "w") as f:
            f.write(VECTOR["record_file"])

    def test_read_then_judged(self):
        auth, envelope = ownerauth.read_arguments(Args(self.record), value("a"))
        self.assertEqual(ownerauth.confirm(auth, envelope, PIN, "a").check("a"), RECORD["record"]["nodes"]["a"]["check"])
        with self.assertRaisesRegex(m.Refused, "is not b's"):
            ownerauth.from_arguments(Args(self.record), PIN, "b", value("a"))
        self.assertIsNone(ownerauth.read_arguments(Args(None), value("a")))

    def test_never_from_a_terminal(self):
        typed = io.BytesIO(VECTOR["values"]["a"].encode())
        typed.isatty = lambda: True
        with self.assertRaisesRegex(m.Refused, "standard input is a terminal: with --ownerauth it carries the decrypted envelope"):
            ownerauth.read_arguments(Args(self.record), typed)

    def test_what_is_typed_comes_from_the_terminal(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        os.write(master, b"6d0f fingerprint\n")
        self.assertEqual(ownerauth.console("Type: ", tty=os.ttyname(slave)), "6d0f fingerprint")
        with self.assertRaisesRegex(m.Refused, "there is no terminal to type at"):
            ownerauth.console("Type: ", tty=os.path.join(self.d, "no-tty"))


class TheChildDescriptor(unittest.TestCase):
    """enrol commit's regalia-sync steps (through runuser, which keeps descriptors; sudo does not)."""

    def test_a_sealed_memfd_read_once(self):
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        fd = ownerauth.child_fd(auth)
        self.assertFalse(os.get_inheritable(fd))                    # only the child named in pass_fds gets it (d9)
        with self.assertRaises(PermissionError):
            os.pwrite(fd, b"x", 0)
        self.assertEqual(ownerauth.read_fd(fd).check("a"), auth.check("a"))
        with self.assertRaises(OSError):
            os.fstat(fd)                                         # closed once read

    def test_never_a_terminal(self):
        master, slave = os.openpty()
        self.addCleanup(os.close, master)
        with self.assertRaisesRegex(m.Refused, "is a terminal"):
            ownerauth.read_fd(slave)

    def test_the_anchor_step_is_handed_it_and_the_descriptor_closed_after(self):
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        seen = {}

        def run(argv, **kw):
            if argv[0] == "pgrep":                                   # no process of regalia-sync
                return unittest.mock.Mock(returncode=1, stdout="", stderr="")
            fd = int(argv[argv.index("--ownerauth-fd") + 1])
            seen.update(fds=kw.get("pass_fds"), fd=fd, value=os.pread(fd, 100, 0))
            return unittest.mock.Mock(returncode=0, stdout="ANCHORED epoch 1 digest %s\n" % ("ab" * 32), stderr="")
        self.assertEqual(enrol.run_as_sync("/etc/regalia/node.json", [{}], run=run, owner_auth=auth), (1, "ab" * 32))
        self.assertEqual((seen["fds"], seen["value"]), ((seen["fd"],), VECTOR["values"]["a"].encode()))
        with self.assertRaises(OSError):
            os.fstat(seen["fd"])
        # regalia-kms-d9: never while a process of regalia-sync runs (it could read the memfd), and nothing is handed over
        handed = []

        def busy(argv, **kw):
            if argv[0] == "pgrep":
                return unittest.mock.Mock(returncode=0, stdout="4242\n", stderr="")
            handed.append(argv)
        with self.assertRaisesRegex(enrol.Refused, "a process of regalia-sync is running"):
            enrol.run_as_sync("/etc/regalia/node.json", [{}], run=busy, owner_auth=auth)
        self.assertEqual(handed, [])
        calls = []
        enrol.run_as_sync("/etc/regalia/node.json", [{}], run=lambda argv, **kw: calls.append((argv, kw)) or
                          unittest.mock.Mock(returncode=0, stdout="ANCHORED epoch 1 digest %s\n" % ("ab" * 32), stderr=""))
        self.assertNotIn("--ownerauth-fd", calls[0][0])
        self.assertNotIn("pass_fds", calls[0][1])


class EnrolmentUnderV4(unittest.TestCase):
    def setUp(self):
        self.tpm = FakeTpm()
        self.given = ownerauth.read_value(value("a")), RECORD
        self.v4, self.v3 = {"schema": m.SCHEMA_V4}, {"schema": m.SCHEMA_V3}

    def test_the_owner_and_lockout_authorizations_set_and_the_value_given(self):
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is empty: a v4 node's is set from its envelope first"):
            enrol.commit_owner_auth(self.v4, self.given, PIN, "a", run=self.tpm)
        self.tpm.owner_auth = bytes.fromhex(VECTOR["values"]["a"][:64])
        with self.assertRaisesRegex(m.Refused, "the TPM's lockout authorization is empty"):
            enrol.commit_owner_auth(self.v4, self.given, PIN, "a", run=self.tpm)
        self.tpm.lockout_set = True
        with self.assertRaisesRegex(enrol.Refused, "under regalia.membership/v4 the TPM's owner authorization is set and enrolment "
                                    "takes it from this node's envelope"):
            enrol.commit_owner_auth(self.v4, None, PIN, "a", run=self.tpm)
        self.assertEqual(enrol.commit_owner_auth(self.v4, self.given, PIN, "a", run=self.tpm).check("a"),
                         RECORD["record"]["nodes"]["a"]["check"])

    def test_judged_against_the_record_under_the_typed_root(self):
        with self.assertRaisesRegex(m.Refused, "names another root than the pinned one"):
            enrol.commit_owner_auth(self.v3, self.given, "ab" * 32, "a", run=self.tpm)
        with self.assertRaisesRegex(m.Refused, "is not b's"):
            enrol.commit_owner_auth(self.v3, self.given, PIN, "b", run=self.tpm)

    def test_a_lab_chain_without_it(self):
        self.assertIsNone(enrol.commit_owner_auth(self.v3, None, PIN, "a", run=self.tpm))


class TheOwnerCallSays(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm(owner_auth=bytes.fromhex(VECTOR["values"]["a"][:64]))

    def test_what_to_give_when_none_was_given(self):
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given: give this node's"):
            m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm).define()
        other = ownerauth.from_envelope(value("b"), RECORD, PIN, "b")
        with self.assertRaisesRegex(m.Refused, "the TPM refused the owner authorization given: it is not this TPM's"):
            heartbeat.Counter("0x1500018", lock_path=self.d + "/c.lock", run=self.tpm, owner_auth=other).define_at(3)


class SetNeedsTheSrk(unittest.TestCase):
    def test_refused_before_systemd_s_srk_is_persistent(self):
        tpm = FakeTpm()
        tpm.persistent.discard(ownerauth.SRK)
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        with self.assertRaisesRegex(m.Refused, "systemd's storage root key \\(0x81000001\\) is not persistent"):
            ownerauth.set_owner(auth, run=tpm)
        self.assertIsNone(tpm.owner_auth)
        tpm.persistent.add(ownerauth.SRK)
        ownerauth.set_owner(auth, run=tpm)
        self.assertTrue(ownerauth.holds(auth, run=tpm))


class ReanchorTakesIt(unittest.TestCase):
    """reanchor: the value on standard input, judged under --root-key before anything; the anchor built with it."""

    def test_the_anchor_is_built_with_it(self):
        from deploy.baremetal import reanchor
        from tests.test_baremetal_membership import ROOT, ROOT_PUB
        from tests.test_baremetal_ownerauth import resigned
        from tests.test_baremetal_reanchor import chain
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        envelope, root = resigned(lambda r: None, key=ROOT)          # the vector's record, under the chain's root
        self.assertEqual(root, ROOT_PUB)
        record = os.path.join(d, "ownerauth.record.json")
        with open(record, "w") as f:
            json.dump(envelope, f)
        for name in ("authority", "c"):
            with open("%s/%s.json" % (d, name), "wb") as f:
                f.write(m.canonical(chain(3)))
        built = {}

        def highwater(index, tcti, policy=None, define_policy=None, owner_auth=None):
            built["owner_auth"] = owner_auth
            raise m.Refused("stop after the anchor is built")
        stdin = unittest.mock.Mock(buffer=value("a"))
        stdin.buffer.isatty = lambda: False
        err = io.StringIO()
        argv = ["--membership", d + "/m.json", "--root-key", ROOT_PUB, "--tpm-index", "0x1500016", "--node-id", "a",
                "--authority", d + "/authority.json", "--peer", "c=%s/c.json" % d, "--ownerauth", record]
        with unittest.mock.patch("sys.stdin", stdin), unittest.mock.patch("sys.stderr", err):
            rc = reanchor.main(argv, ask=lambda prompt: None, highwater=highwater)
        self.assertEqual(rc, 1)
        self.assertIn("stop after the anchor is built", err.getvalue())
        self.assertEqual(built["owner_auth"].check("a"), RECORD["record"]["nodes"]["a"]["check"])
        # another node's value is refused before anything is read or built
        built.clear()
        stdin = unittest.mock.Mock(buffer=value("b"))
        stdin.buffer.isatty = lambda: False
        err = io.StringIO()
        with unittest.mock.patch("sys.stdin", stdin), unittest.mock.patch("sys.stderr", err):
            self.assertEqual(reanchor.main(argv, ask=lambda prompt: None, highwater=highwater), 1)
        self.assertIn("is not a's", err.getvalue())
        self.assertEqual(built, {})


class RecountTakesIt(unittest.TestCase):
    """recount: the value on standard input, judged under the node's pinned root; the counter built with it."""

    def test_the_counter_is_built_with_it(self):
        import pathlib
        import subprocess
        from deploy.baremetal import node, recount
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        example = json.loads((pathlib.Path(__file__).resolve().parent.parent / "deploy" / "baremetal" / "node.example.json").read_text())
        config = os.path.join(d, "node.json")
        with open(config, "w") as f:
            json.dump(dict(example, node_id="a", root_key=PIN, state_dir=d), f)
        record = os.path.join(d, "ownerauth.record.json")
        with open(record, "w") as f:
            f.write(VECTOR["record_file"])
        built = {}

        def counter(cfg, run=None, owner_auth=None):
            built["owner_auth"] = owner_auth
            raise m.Refused("stop after the counter is built")
        stdin = unittest.mock.Mock(buffer=value("a"))
        stdin.buffer.isatty = lambda: False
        err = io.StringIO()
        run = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"inactive\n", b"")
        with unittest.mock.patch("sys.stdin", stdin), unittest.mock.patch("sys.stderr", err), \
                unittest.mock.patch.object(node, "heartbeat_counter", counter), unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TPM2TOOLS_TCTI", None)
            rc = recount.main(["--config", config, "--audit-log", d + "/audit.jsonl", "--ownerauth", record], ask=lambda p: None, run=run)
        self.assertEqual(rc, 1, err.getvalue())
        self.assertIn("stop after the counter is built", err.getvalue())
        self.assertEqual(built["owner_auth"].check("a"), RECORD["record"]["nodes"]["a"]["check"])


if __name__ == "__main__":
    unittest.main()
