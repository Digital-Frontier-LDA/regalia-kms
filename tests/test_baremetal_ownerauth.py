"""#242 step C: the TPM owner authorization from the ceremony's envelope (deploy/baremetal/ownerauth.py).

  * regalia-kms-51's vector (tests/vectors/ownerauth-v1.json, regalia-ceremony offline-keys.py at ae0b1dc): the
    record verifies under its pinned root, and each node's value matches its check;
  * the record's refusals, each the one guard's own message; the value's form on standard input;
  * the channel: no value on any command line, `-C o` and `"hex:"` only in ownerauth.py (a grep of the package);
  * every owner call site of the anchor, the counters and enrolment gives the authorization (a FakeTpm whose owner
    authorization is set refuses any owner call without it), and set/check (enrol ownerauth);
  * on swtpm: set from empty, refused when set, proven by one call, and the anchor defined only with it."""
import copy
import hashlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import enrol, heartbeat, membership as m, ownerauth
from tests.test_baremetal_heartbeat import FakeTpm

ROOT = pathlib.Path(__file__).resolve().parent.parent
VECTOR = json.loads((ROOT / "tests" / "vectors" / "ownerauth-v1.json").read_text())
RECORD = json.loads(VECTOR["record_file"])
PIN = VECTOR["root"]


def value(node):
    return io.BytesIO(VECTOR["values"][node].encode())


def raw_pub(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def resigned(change, key=None):
    """The vector's record changed by `change` and signed by `key` as its root (pinned as raw_pub(key)): for the checks
    that come after the signature."""
    key = key or Ed25519PrivateKey.generate()
    record = copy.deepcopy(RECORD["record"])
    record["root_entry"]["key"] = raw_pub(key)
    record["root_fingerprint"] = hashlib.sha256(bytes.fromhex(raw_pub(key))).hexdigest()
    change(record)
    return {"record": record, "signature": key.sign(ownerauth.RECORD_DOMAIN + m.canonical(record)).hex()}, raw_pub(key)


class TheVector(unittest.TestCase):
    def test_the_record_verifies_and_each_value_is_its_node_s(self):
        self.assertEqual(VECTOR["record_file"], json.dumps(RECORD, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        for node in "abc":
            with self.subTest(node=node):
                entry = ownerauth.verify(RECORD, PIN, node)
                auth = ownerauth.from_envelope(value(node), RECORD, PIN, node)
                self.assertEqual(auth.check(node), entry["check"])
                self.assertEqual(auth.tool_form(), b"hex:" + VECTOR["values"][node][:64].encode())

    def test_another_node_s_value_is_refused_before_the_tpm(self):
        with self.assertRaisesRegex(m.Refused, "the owner authorization given is not b's \\(its check value is not the record's\\)"):
            ownerauth.from_envelope(value("a"), RECORD, PIN, "b")

    def test_the_value_is_never_printed(self):
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        for shown in (repr(auth), str(auth), "%s" % auth):
            self.assertNotIn(VECTOR["values"]["a"][:16], shown)


class TheRecordIsRefused(unittest.TestCase):
    def refused(self, reason, envelope, root=PIN, node="a"):
        with self.assertRaises(m.Refused) as caught:
            ownerauth.verify(envelope, root, node)
        self.assertIn(reason, str(caught.exception))

    def test_under_another_root(self):
        self.refused("names another root than the pinned one", RECORD, root="ab" * 32)

    def test_altered_after_signing(self):
        altered = copy.deepcopy(RECORD)
        altered["record"]["nodes"]["a"]["check"] = "00" * 32
        self.refused("the owner-authorization record's signature is not the pinned root's", altered)

    def test_a_field_missing_or_unknown(self):
        for change in (lambda r: r.pop("verify_keys"), lambda r: r.update(extra=1), lambda r: r["nodes"]["a"].update(extra="00" * 32)):
            with self.subTest(change=change):
                envelope, root = resigned(change)
                self.refused("fields mismatch", envelope, root)

    def test_non_ascii(self):
        envelope, root = resigned(lambda r: r.update(tool="offline-keys.py/1 é"))
        self.refused("holds a non-ASCII string", envelope, root)

    def test_another_schema_or_event(self):
        envelope, root = resigned(lambda r: r.update(event="cards"))
        self.refused("the record is not a regalia.ownerauth-record/v1 (ownerauth)", envelope, root)

    def test_no_entry_for_the_node(self):
        self.refused("has no entry for d: its envelope was made for other nodes (a, b, c)", RECORD, node="d")

    def test_the_recipients_are_the_two_developer_cards(self):
        envelope, root = resigned(lambda r: r["yk_recipients"].pop())
        self.refused("yk_recipients is not the two developer cards (D30.3)", envelope, root)
        envelope, root = resigned(lambda r: r["yk_recipients"].__setitem__(1, dict(r["yk_recipients"][0])))
        self.refused("yk_recipients names one card twice", envelope, root)
        envelope, root = resigned(lambda r: r["verify_keys"].pop(sorted(r["verify_keys"])[0]))
        self.refused("verify_keys does not name exactly the recipients' subkeys", envelope, root)


class TheValueOnStandardInput(unittest.TestCase):
    def test_exactly_64_lowercase_hex_and_a_newline(self):
        good = VECTOR["values"]["a"]
        for bad in (good[:64], good[:64].upper() + "\n", good[:63] + "\n", good + "x", "", "hex:" + good):
            with self.subTest(bad=bad), self.assertRaisesRegex(m.Refused, "is not 64 lowercase hex and a newline"):
                ownerauth.read_value(io.BytesIO(bad.encode()))


class TheDrillCheck(unittest.TestCase):
    """`python3 -Es -m deploy.baremetal.ownerauth check` (#242, the break-glass drill's last step): the value on standard
    input judged against the record under the pinned root, with no TPM."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.record = os.path.join(self.d, "ownerauth.record.json")
        with open(self.record, "w") as f:
            f.write(VECTOR["record_file"])

    def check(self, node, given, root=PIN):
        return subprocess.run([sys.executable, "-Es", "-m", "deploy.baremetal.ownerauth", "check", "--node-id", node,
                               "--root-key", root, "--record", self.record], input=given.encode(), capture_output=True,
                              cwd=str(ROOT), env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})

    def test_the_node_s_value_matches(self):
        done = self.check("a", VECTOR["values"]["a"])
        self.assertEqual((done.returncode, done.stderr), (0, b""))
        self.assertIn(b"the value is a's: it matches the check value of the record signed by the pinned root", done.stdout)
        self.assertNotIn(VECTOR["values"]["a"][:16].encode(), done.stdout)

    def test_another_node_s_value_another_root_or_the_wrong_form(self):
        for node, given, root, reason in (
                ("b", VECTOR["values"]["a"], PIN, b"the owner authorization given is not b's"),
                ("a", VECTOR["values"]["a"], "ab" * 32, b"names another root than the pinned one"),
                ("a", VECTOR["values"]["a"][:64], PIN, b"is not 64 lowercase hex and a newline")):
            with self.subTest(node=node, root=root, given=len(given)):
                done = self.check(node, given, root)
                self.assertEqual(done.returncode, 1)
                self.assertIn(b"REFUSED: ", done.stderr)
                self.assertIn(reason, done.stderr)
                self.assertNotIn(VECTOR["values"]["a"][:16].encode(), done.stderr)

    def test_a_terminal_on_standard_input_or_no_record_is_refused(self):
        """regalia-kms-ed: each its own message and exit 1 (2 is argparse's), never a traceback."""
        import contextlib

        class Terminal(io.BytesIO):
            def isatty(self):
                return True
        argv = ["check", "--node-id", "a", "--root-key", PIN, "--record", self.record]
        for label, args, stdin, reason in (
                ("a terminal", argv, Terminal(VECTOR["values"]["a"].encode()), "REFUSED: standard input is a terminal"),
                ("no record", argv[:-1] + [os.path.join(self.d, "absent.json")], value("a"), "REFUSED: [Errno 2] No such file or directory")):
            with self.subTest(label):
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(ownerauth.main(args, stdin=stdin), 1)
                self.assertTrue(err.getvalue().startswith(reason), err.getvalue())


class TheChannel(unittest.TestCase):
    def test_empty_gives_no_authorization(self):
        with ownerauth.owner_call(None) as (argv, kw):
            self.assertEqual((argv, kw), (["-C", "o"], {}))

    def test_a_memfd_never_the_command_line_and_closed_after(self):
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        with ownerauth.owner_call(auth) as (argv, kw):
            self.assertEqual(argv[:3], ["-C", "o", "-P"])
            self.assertNotIn(VECTOR["values"]["a"][:64], " ".join(argv))
            fd = kw["pass_fds"][0]
            self.assertEqual(argv[3], "file:/dev/fd/%d" % fd)
            self.assertEqual(os.read(fd, 200), b"hex:" + VECTOR["values"]["a"][:64].encode())
            with self.assertRaises(PermissionError):                 # sealed: nothing rewrites it under the call
                os.pwrite(fd, b"x", 0)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_the_tree_names_the_owner_only_through_it(self):
        """24 and regalia-kms-d9 (#242 C): no owner hierarchy but through ownerauth's channel, no authorization value on a
        command line, in deploy/ (Python and shell) and cmd/ (Go), so a new owner call cannot assume an empty owner
        authorization again unseen. KNOWN lists what may still: each entry must still match (none goes stale)."""
        found, used = [], set()
        for path in tree_files():
            rel = str(path.relative_to(ROOT))
            for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                for reason in forbidden(rel, line):
                    known = next((k for k in KNOWN if rel == k[0] and k[1] in line), None)
                    if known:
                        used.add(known)
                    else:
                        found.append("%s:%d %s: %s" % (rel, n, reason, line.strip()))
        self.assertEqual(found, [])
        self.assertEqual(sorted(set(KNOWN) - used), [], "a KNOWN entry no longer matches: remove it")

    def test_the_patterns_find_what_they_are_for(self):
        """forbidden() itself, on what it must catch and on what it must let be: the grep above uses the same function."""
        caught = [
            ("x.py", 'run(["tpm2_nvdefine", "0x1", "-C", "o"])'), ("x.py", 'tpm("evictcontrol", "-C", "owner", "-c", h)'),
            ("x.py", 'tpm("evictcontrol", "-C", "0x40000001")'), ("x.py", '"tpm2_evictcontrol -C o -c x".split()'),
            ("x.py", 'tpm("x", "--hierarchy=o")'), ("x.py", 'tpm("x", "-Co")'), ("x.py", "v = 'hex:' + value"),
            ("x.py", 'tpm("nvread", i, "-P", value)'), ("x.py", 'run(["tpm2_changeauth", "-c", "o", new])'),
            ("x.sh", "tpm2_evictcontrol -Q -C o -c k.ctx"), ("x.sh", 'tpm2_nvdefine 0x1 -P "$PASS"'),
            ("x.go", "AuthHandle: tpm2.TPMRHOwner,"),
        ]
        for rel, line in caught:
            with self.subTest(line=line):
                self.assertTrue(forbidden(rel, line), line)
        allowed = [
            ("x.py", 'tpm("loadexternal", "-C", "o", "-G", "rsa")'), ("x.py", '"""the owner (`-C o`)"""'),
            ("x.py", 'self._tpm(tool, index, "-P", "session:" + session)'), ("x.py", 'host.run(["systemctl", "show", s, "-p", "X"])'),
            ("x.sh", "tpm2_changeauth -Q -c lockout file:-"), ("x.py", "# -C o in a comment"),
        ]
        for rel, line in allowed:
            with self.subTest(allowed=line):
                self.assertEqual(forbidden(rel, line), [], line)


# What may still name the owner hierarchy, each with its reason (regalia-kms-d9: an explicit list, so none is forgotten)
KNOWN = (
    # stdlib-only and run as a standalone script (e2e/tpm-attest-swtpm.sh): the lab's CLI and the three-node fixture.
    # Production enrolment persists its AK through enrol.identity, which takes the owner authorization
    ("deploy/baremetal/attest.py", 'tpm2("evictcontrol", "-C", "o"'),
    # seal-hsm-pin.sh (shell, no ownerauth.py): --ownerauth-stdin, the value through a root-only tmpfs file (#242 C2)
    ("deploy/seal-hsm-pin.sh", "tpm2_evictcontrol -Q -C o"),
    ("deploy/seal-hsm-pin.sh", "tpm2_createprimary -Q -C o"),
)
OWNER = re.compile(r"-C\s*o\b|-C[\"']?\s*,\s*[\"'](?:o|owner|0x40000001)[\"']|--hierarchy\b")
CHANGEAUTH_OWNER = re.compile(r"changeauth.*-c[\"']?\s*,?\s*[\"']?(?:o|owner)\b")
PY_AUTH_LITERAL = re.compile(r"[\"'](?:hex|str):")
PY_AUTH_ARG = r"[\"']-[%s][\"']\s*,\s*([^,)]+)"
SH_AUTH_ARG = re.compile(r"tpm2_\w+\b.*\s-P\s+(?![\"']?(?:session|file):)")


def tree_files():
    for pattern, under in (("*.py", "deploy"), ("*.sh", "deploy"), ("*.go", "cmd")):
        for path in sorted((ROOT / under).rglob(pattern)):
            if path.name == "ownerauth.py" or path.name.endswith("_test.go"):
                continue
            yield path


def forbidden(rel, line):
    """Why `line` of file `rel` names the owner hierarchy or an authorization other than through ownerauth's channel."""
    code = line.split("//", 1)[0] if rel.endswith(".go") else line.split("#", 1)[0]
    code = re.sub(r"`[^`]*`", "", code)
    reasons = []
    if (OWNER.search(code) and "loadexternal" not in code) or CHANGEAUTH_OWNER.search(code) or "TPMRHOwner" in code:
        reasons.append("the owner hierarchy outside ownerauth")
    if rel.endswith(".py"):
        if PY_AUTH_LITERAL.search(code):
            reasons.append("an authorization literal")
        flags = "Pp" if "changeauth" in code else "P"       # -p is changeauth's old value (and systemctl's property)
        args = re.findall(PY_AUTH_ARG % flags, code)
        if any(not a.strip().startswith(("\"session:", "'session:")) for a in args):
            reasons.append("an authorization not through the channel")
    elif rel.endswith(".sh") and SH_AUTH_ARG.search(code):
        reasons.append("an authorization on the command line")
    return reasons


class OwnerCallsGiveIt(unittest.TestCase):
    """A TPM whose owner authorization is set refuses every owner call that does not give it: each call site of the
    anchor, the heartbeat counter's definition and recount's deletion gives it, through the channel."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        self.tpm = FakeTpm(owner_auth=self.auth._raw)

    def test_the_anchor_is_defined_written_and_redefined_only_with_it(self):
        bare = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm)
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            bare.define()
        hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm, owner_auth=self.auth)
        hw.define()
        digest = lambda epoch: "%02x" % epoch * 32
        hw.anchor(3, digest)                            # owner-written here: its run-time writes are the owner's too
        self.assertEqual((hw.value(), hw.record()[0]), (3, 3))
        hw.redefine(5, digest(5))
        self.assertEqual(hw.value(), 5)

    def test_asked_once_when_given_as_a_function(self):
        asked = []
        hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm, owner_auth=lambda: asked.append(1) or self.auth)
        hw.define()
        self.assertEqual(len(asked), 1)

    def test_the_heartbeat_counter_s_definition(self):
        with self.assertRaises(m.Refused):
            heartbeat.Counter("0x1500018", lock_path=self.d + "/c.lock", run=self.tpm).define_at(7)
        counter = heartbeat.Counter("0x1500018", lock_path=self.d + "/c.lock", run=self.tpm, owner_auth=self.auth)
        counter.define_at(7)
        self.assertEqual(counter.value(), 7)

    def test_a_wrong_value_is_refused_by_the_tpm(self):
        other = ownerauth.from_envelope(value("b"), RECORD, PIN, "b")
        with self.assertRaisesRegex(m.Refused, "the TPM refused the owner authorization given: it is not this TPM's"):
            m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm, owner_auth=other).define()


class SetAndCheck(unittest.TestCase):
    """`enrol ownerauth`: set from EMPTY, proven by one call; one already set is refused with the way on (24)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.record = os.path.join(self.d, "ownerauth.record.json")
        with open(self.record, "w") as f:
            f.write(VECTOR["record_file"])
        self.tpm = FakeTpm()

    def run_step(self, node="a", check=False, stream=None):
        return enrol.set_ownerauth(node, PIN, self.record, stream or value(node), check=check, run=self.tpm, directory=self.d,
                                   ek_name=self.tpm.ek_name.hex())

    def test_set_from_empty_then_checked(self):
        self.assertFalse(ownerauth.posture(run=self.tpm)["owner"])
        self.assertIn("is set to a's envelope value, and answers to it", self.run_step())
        self.assertEqual(enrol.ownerauth_current(self.d), hashlib.sha256(m.canonical(RECORD)).hexdigest())   # #456
        self.assertEqual(self.tpm.owner_auth, bytes.fromhex(VECTOR["values"]["a"][:64]))
        self.assertTrue(ownerauth.posture(run=self.tpm)["owner"])
        self.assertIn("is a's envelope value", self.run_step(check=True))

    def test_already_set_is_refused_never_overwritten(self):
        self.tpm.owner_auth = bytes.fromhex(VECTOR["values"]["b"][:64])
        with self.assertRaises(m.Refused) as caught:
            self.run_step()
        self.assertIn("the TPM's owner authorization is already set. If it is this envelope's value, there is nothing to do",
                      str(caught.exception))
        self.assertIn("Nothing was changed", str(caught.exception))
        self.assertEqual(self.tpm.owner_auth, bytes.fromhex(VECTOR["values"]["b"][:64]))
        with self.assertRaisesRegex(enrol.Refused, "is NOT a's envelope value"):
            self.run_step(check=True)

    def test_check_on_an_empty_owner_authorization(self):
        with self.assertRaisesRegex(enrol.Refused, "the TPM's owner authorization is empty: nothing to check"):
            self.run_step(check=True)

    def test_the_value_must_be_the_node_s_before_the_tpm_is_touched(self):
        with self.assertRaisesRegex(m.Refused, "is not a's"):
            self.run_step(node="a", stream=value("b"))
        self.assertIsNone(self.tpm.owner_auth)

    def test_a_set_that_cannot_be_proven_says_the_state_and_the_way_out(self):
        """regalia-kms-d9 (no stranding): the TPM accepted the new value but the proof failed."""
        for answer in (b"ERROR: Esys_HierarchyChangeAuth(0x9A2) - tpm:session(1):authorization failure", b"ERROR: Could not load tcti"):
            with self.subTest(answer=answer):
                tpm = FakeTpm()

                def run(argv, answer=answer, tpm=tpm, **kw):
                    if argv[0] == "tpm2_createprimary":                     # the proof (holds, #414)
                        return subprocess.CompletedProcess(argv, 1, b"", answer)
                    return tpm(argv, **kw)
                with self.assertRaises(m.Refused) as caught:
                    enrol.set_ownerauth("a", PIN, self.record, value("a"), run=run, ek_name=tpm.ek_name.hex(), directory=self.d)
                self.assertIn("the owner authorization may now be UNKNOWN. Re-run `enrol ownerauth --check` with this envelope; "
                              "if that fails, clear the owner hierarchy with the lockout authorization (tpm2_clear -c l, #57)",
                              str(caught.exception))

    def test_only_an_authorization_failure_reads_as_not_this_value(self):
        """regalia-kms-d9: a busy TPM or a TCTI error is a refusal, never "the wrong envelope"."""
        auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        self.tpm.owner_auth = bytes.fromhex(VECTOR["values"]["b"][:64])
        self.assertFalse(ownerauth.holds(auth, run=self.tpm))
        self.tpm.broken = True
        with self.assertRaisesRegex(m.Refused, "could not ask the TPM whether its owner authorization is this value: the TPM said no"):
            ownerauth.holds(auth, run=self.tpm)

    def test_production_posture(self):
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is empty: a v4 node's is set from its envelope first"):
            ownerauth.require_production(run=self.tpm)
        self.run_step()
        with self.assertRaisesRegex(m.Refused, "the TPM's lockout authorization is empty: set it first"):
            ownerauth.require_production(run=self.tpm)
        self.tpm.lockout_set = True
        ownerauth.require_production(run=self.tpm)

    def test_the_command_reads_the_value_from_standard_input_only(self):
        import contextlib
        import unittest.mock
        seen = {}

        def step(node_id, root_key, record_path, stream, check=False, **kw):
            seen.update(node_id=node_id, root_key=root_key, record=record_path, stream=stream, check=check)
            raise m.Refused("stop here")
        stdin = unittest.mock.Mock(buffer=value("a"))
        err = io.StringIO()
        with unittest.mock.patch("sys.stdin", stdin), unittest.mock.patch.object(enrol, "set_ownerauth", step), contextlib.redirect_stderr(err):
            code = enrol.main(["ownerauth", "--node-id", "a", "--root-key", PIN, "--record", self.record, "--check"])
        self.assertEqual((code, seen["stream"], seen["check"], seen["node_id"]), (1, stdin.buffer, True, "a"))
        self.assertIn("REFUSED: stop here", err.getvalue())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):     # no value option exists
            enrol.main(["ownerauth", "--node-id", "a", "--root-key", PIN, "--record", self.record, "--value", "00" * 32])


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_changeauth"), "needs swtpm and tpm2-tools")
class Rotation(unittest.TestCase):
    """`enrol ownerauth --rotate-from` (regalia-kms-24's assignment): a SET value changed to a new one, both checked against
    their records first, the change in a session salted to the EK, the new value proven, a rerun idempotent."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.key = Ed25519PrivateKey.generate()
        self.current, self.new = os.urandom(32), os.urandom(32)
        self.records = {}
        self.write("current", self.current, "2026-10-05T10:00:00Z")
        self.write("new", self.new, "2026-10-05T11:00:00Z")
        self.tpm = FakeTpm(owner_auth=self.current)
        enrol._ownerauth_hold(self.d, self.digest("current"))             # the node is on the current record

    def digest(self, name):
        with open(self.records[name], "rb") as f:
            return hashlib.sha256(m.canonical(json.loads(f.read()))).hexdigest()

    def write(self, name, raw, at):
        envelope, self.pin = resigned(lambda r: (r["nodes"]["a"].update(check=ownerauth.Auth(raw).check("a")), r.update(at=at)),
                                      self.key)
        self.records[name] = os.path.join(self.d, name + ".json")
        with open(self.records[name], "w") as f:
            f.write(json.dumps(envelope))

    def rotate(self, first=None, second=None):
        stream = io.BytesIO(((first or self.current).hex() + "\n" + (second or self.new).hex() + "\n").encode())
        return enrol.set_ownerauth("a", self.pin, self.records["new"], stream, run=self.tpm, ek_name=self.tpm.ek_name.hex(),
                                   rotate_from=self.records["current"], directory=self.d)

    def test_rotated_in_a_salted_session_then_a_rerun_changes_nothing(self):
        self.assertIn("is rotated to a's NEW envelope value, and answers to it", self.rotate())
        self.assertEqual(self.tpm.owner_auth, self.new)
        self.assertEqual(enrol.ownerauth_current(self.d), self.digest("new"))   # the node now holds the new record
        self.assertEqual(self.tpm.salted_with, [self.tpm.ek_name])          # one change, salted to the enrolled EK
        enrol._ownerauth_hold(self.d, self.digest("current"))             # a run that stopped before the node noted it
        self.assertIn("already answers to a's NEW envelope value: nothing was changed", self.rotate())
        self.assertEqual(enrol.ownerauth_current(self.d), self.digest("new"))
        self.assertEqual((self.tpm.owner_auth, self.tpm.salted_with), (self.new, [self.tpm.ek_name]))

    def test_either_value_not_its_record_s_is_refused_before_the_tpm(self):
        for first, second in ((os.urandom(32), None), (None, os.urandom(32))):
            with self.subTest(wrong="current" if first else "new"), \
                    self.assertRaisesRegex(m.Refused, "the owner authorization given is not a's"):
                self.rotate(first, second)
            self.assertEqual((self.tpm.owner_auth, self.tpm.salted_with), (self.current, []))

    def test_a_tpm_holding_neither_or_empty_and_a_same_value_are_refused(self):
        self.tpm.owner_auth = os.urandom(32)
        with self.assertRaisesRegex(m.Refused, "is neither the current value given nor the new one: this TPM was provisioned otherwise"):
            self.rotate()
        self.tpm.owner_auth = None
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is empty: there is nothing to rotate"):
            self.rotate()
        self.assertEqual(self.tpm.salted_with, [])
        with self.assertRaisesRegex(m.Refused, "the new owner authorization is the current one: nothing to rotate"):
            ownerauth.rotate_owner(ownerauth.Auth(self.current), ownerauth.Auth(self.current), self.tpm.ek_name.hex(), run=self.tpm)
        with self.assertRaisesRegex(enrol.Refused, "--check and --rotate-from are different commands"):
            enrol.set_ownerauth("a", self.pin, self.records["new"], io.BytesIO(b""), check=True, run=self.tpm,
                                rotate_from=self.records["current"], directory=self.d)


    def test_a_stale_or_unheld_current_record_is_refused_before_the_tpm(self):
        """regalia-kms-d9: the node remembers which record it is on; a rotation from another is refused with no TPM call."""
        enrol._ownerauth_hold(self.d, "ab" * 32)
        with self.assertRaisesRegex(enrol.Refused, "the current record given is not the one this node is on"):
            self.rotate()
        os.unlink(os.path.join(self.d, enrol.OWNERAUTH_STATE))
        with self.assertRaisesRegex(enrol.Refused, "this node holds no record of which owner-authorization record it is on"):
            self.rotate()
        self.assertEqual((self.tpm.owner_auth, self.tpm.salted_with), (self.current, []))

    def test_adopt_is_one_way_and_only_after_the_tpm_answers(self):
        os.unlink(os.path.join(self.d, enrol.OWNERAUTH_STATE))
        check = lambda record, raw, **kw: enrol.set_ownerauth("a", self.pin, self.records[record], io.BytesIO((raw.hex() + "\n").encode()),
                                                              check=True, run=self.tpm, directory=self.d, **kw)
        self.assertIn("the node holds NO record of it (--adopt)", check("current", self.current))
        with self.assertRaisesRegex(enrol.Refused, "is NOT a's envelope value"):             # the TPM does not answer to it
            check("new", self.new, adopt=True)
        self.assertIsNone(enrol.ownerauth_current(self.d))
        self.assertIn("the node now holds this record", check("current", self.current, adopt=True))
        self.assertEqual(enrol.ownerauth_current(self.d), self.digest("current"))
        self.tpm.owner_auth = self.new                                      # (as if rotated elsewhere)
        with self.assertRaisesRegex(enrol.Refused, "already holds another owner-authorization record"):
            check("new", self.new, adopt=True)
        self.assertIn("but the node holds ANOTHER record", check("new", self.new))
        self.assertEqual(enrol.ownerauth_current(self.d), self.digest("current"))
        with self.assertRaisesRegex(enrol.Refused, "--adopt goes with --check"):
            enrol.set_ownerauth("a", self.pin, self.records["new"], io.BytesIO(b""), run=self.tpm, directory=self.d, adopt=True)

    def test_no_salted_changeauth_near_dictionary_attack_lockout(self):
        """regalia-kms-d9: the one strike-capable call (a changeauth in the EK-salted session) is not made unless the TPM
        has min(3, MAX) tries left: at MAX the node's DA-protected keys lock out."""
        for counter, most in ((1, 3), (30, 32)):
            with self.subTest(counter=counter, max=most):
                self.tpm.da = [counter, most, 1000]
                with self.assertRaisesRegex(m.Refused, "the TPM's dictionary-attack counter is %d of %d: a rotation could lock "
                                            "the node's keys out" % (counter, most)):
                    self.rotate()
                self.assertEqual((self.tpm.owner_auth, self.tpm.salted_with), (self.current, []))
        self.tpm.da = [29, 32, 1000]
        self.assertIn("is rotated to a's NEW envelope value", self.rotate())

    def test_never_back_to_an_older_or_equal_record(self):
        """regalia-kms-51: an operator who picks an older root-signed record must not re-arm envelopes that retired or lost
        cards open; both `at` are root-signed, so the order is."""
        for at in ("2026-10-05T10:00:00Z", "2026-10-05T09:59:59Z"):
            with self.subTest(at=at):
                self.write("new", self.new, at)
                with self.assertRaisesRegex(enrol.Refused, "the new record is not newer than the current one \\(%s, not after "
                                            "2026-10-05T10:00:00Z\\)" % at):
                    self.rotate()
                self.assertEqual((self.tpm.owner_auth, self.tpm.salted_with), (self.current, []))
        self.write("new", self.new, "5 October")
        with self.assertRaisesRegex(enrol.Refused, "is not a UTC time"):
            self.rotate()


class OnSwtpm(unittest.TestCase):
    """A real TPM: the channel's hex form, set from empty, refused when set, and the anchor only with it."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        sock = self.d + "/swtpm.sock"
        r = subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=unixio,path=" + sock,
                            "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                            "--pid", "file=%s/pid" % self.d], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        with open(self.d + "/pid") as f:
            self.addCleanup(os.kill, int(f.read()), 15)
        time.sleep(0.5)
        self.tcti = "swtpm:path=" + sock
        # a value with 0x00 bytes: tpm2-tools would cut a raw one at the first (#242's probe); the hex form is whole
        self.auth = ownerauth.Auth(bytes.fromhex("00aa00bb00cc00dd00ee00ff001122334455667788990000aabbccddeeff0000"))

    def test_set_check_and_the_anchor(self):
        self.assertEqual(ownerauth.posture(self.tcti), {"owner": False, "lockout": False})
        env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        # the node's EK, persistent as `enrol init` leaves it; its Name is what enrolment records (#414: it salts the set)
        self.assertEqual(subprocess.run(["tpm2_createek", "-c", ownerauth.EK_HANDLE, "-G", "rsa", "-u", self.d + "/ek.pub"],
                                        env=env, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(["tpm2_readpublic", "-c", ownerauth.EK_HANDLE, "-n", self.d + "/ek.name"], env=env,
                                        capture_output=True).returncode, 0)
        with open(self.d + "/ek.name", "rb") as f:
            ek_name = f.read().hex()
        with self.assertRaisesRegex(m.Refused, "systemd's storage root key \\(0x81000001\\) is not persistent"):
            ownerauth.set_owner(self.auth, ek_name, self.tcti)
        # the SRK, as systemd-tpm2-setup persists it at boot (its default template), while the owner auth is empty
        for argv in (["tpm2_createprimary", "-C", "o", "-c", self.d + "/srk.ctx"], ["tpm2_evictcontrol", "-C", "o", "-c", self.d + "/srk.ctx", ownerauth.SRK]):
            self.assertEqual(subprocess.run(argv, env=env, capture_output=True).returncode, 0, argv)
        subprocess.run(["tpm2_flushcontext", "-t"], env=env, capture_output=True)
        with self.assertRaisesRegex(m.Refused, "is not the one enrolment recorded"):          # another EK: nothing sent
            ownerauth.set_owner(self.auth, "000b" + "00" * 32, self.tcti)
        self.assertFalse(ownerauth.posture(self.tcti)["owner"])
        ownerauth.set_owner(self.auth, ek_name, self.tcti)
        self.assertEqual(ownerauth.posture(self.tcti)["owner"], True)
        self.assertTrue(ownerauth.holds(self.auth, self.tcti))
        prefix = ownerauth.Auth(bytes.fromhex("00aa" + "00" * 30))          # the same bytes up to the first NUL
        self.assertFalse(ownerauth.holds(prefix, self.tcti))
        with self.assertRaisesRegex(m.Refused, "already set"):
            ownerauth.set_owner(self.auth, ek_name, self.tcti)
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock").define()
        hw = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock", owner_auth=self.auth)
        hw.define()
        hw.anchor(2, lambda epoch: "%02x" % epoch * 32)
        self.assertEqual((hw.value(), hw.record()[0]), (2, 2))
        hw.redefine(4, "04" * 32)
        self.assertEqual(hw.value(), 4)
        # rotation (regalia-kms-24's assignment): the set value to a new one, in a session salted to the EK, the current
        # value authorizing it (never sent); then the anchor answers to the new value only, and a rerun changes nothing
        new = ownerauth.Auth(bytes.fromhex("ff00ee00dd00cc00bb00aa00998877665544332211000000ffeeddccbbaa0000"))
        with self.assertRaisesRegex(m.Refused, "is not the one enrolment recorded"):
            ownerauth.rotate_owner(self.auth, new, "000b" + "00" * 32, self.tcti)
        self.assertTrue(ownerauth.holds(self.auth, self.tcti))                 # another EK: nothing was sent
        self.assertIs(ownerauth.rotate_owner(self.auth, new, ek_name, self.tcti), True)
        self.assertEqual((ownerauth.holds(new, self.tcti), ownerauth.holds(self.auth, self.tcti)), (True, False))
        rotated = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock", owner_auth=new)
        rotated.redefine(5, "05" * 32)
        self.assertEqual(rotated.value(), 5)
        self.assertIs(ownerauth.rotate_owner(self.auth, new, ek_name, self.tcti), False)    # resumed: nothing to change
        self.assertTrue(ownerauth.holds(new, self.tcti))


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_changeauth"), "needs swtpm and tpm2-tools")
class OnTheWire(unittest.TestCase):
    """#414, measured on every run: what the TPM receives (swtpm's level-20 log of each command it reads) never holds
    the owner authorization, and no owner call is a password session (TPM_RS_PW), for THIS tpm2-tools. A version that
    sent -P as a password session fails here (regalia-kms-d9), and ownerauth.MEASURED_TOOLS names those measured."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        sock, self.log = self.d + "/swtpm.sock", self.d + "/swtpm.log"
        r = subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=unixio,path=" + sock,
                            "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                            "--pid", "file=%s/pid" % self.d, "--log", "file=%s,level=20" % self.log], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        with open(self.d + "/pid") as f:
            self.addCleanup(os.kill, int(f.read()), 15)
        time.sleep(0.5)
        self.tcti = "swtpm:path=" + sock
        self.env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        self.auth = ownerauth.Auth(bytes.fromhex("5a5a5a5aa5a5a5a5" + "11223344556677889900aabbccddeeff" + "c3c3c3c3c3c3c3c3"))

    def commands(self, mark):
        """Every command the TPM read since `mark` (a log offset), reassembled from swtpm's hex dump."""
        with open(self.log, "rb") as f:
            f.seek(mark)
            text = f.read().decode("latin-1")
        out, cur = [], None
        for line in text.splitlines():
            if "SWTPM_IO_Read" in line:
                cur = bytearray()
                out.append(cur)
            elif cur is not None and re.fullmatch(r"\s*(?:[0-9A-Fa-f]{2}\s+)*[0-9A-Fa-f]{2}\s*", line):
                cur.extend(bytes.fromhex(line.replace(" ", "")))
            else:
                cur = None
        return [bytes(c) for c in out]

    def test_the_value_never_crosses_and_no_owner_call_is_a_password_session(self):
        version = ownerauth.tools_version()
        raw = self.auth._raw
        for argv in (["tpm2_createek", "-c", ownerauth.EK_HANDLE, "-G", "rsa", "-u", self.d + "/ek.pub"],
                     ["tpm2_readpublic", "-c", ownerauth.EK_HANDLE, "-n", self.d + "/ek.name"],
                     ["tpm2_createprimary", "-C", "o", "-c", self.d + "/srk.ctx"],
                     ["tpm2_evictcontrol", "-C", "o", "-c", self.d + "/srk.ctx", ownerauth.SRK], ["tpm2_flushcontext", "-t"]):
            self.assertEqual(subprocess.run(argv, env=self.env, capture_output=True).returncode, 0, argv)
        with open(self.d + "/ek.name", "rb") as f:
            ek_name = f.read().hex()
        mark = os.path.getsize(self.log)
        ownerauth.set_owner(self.auth, ek_name, self.tcti)               # the salted set, then the createprimary proof
        sent = self.commands(mark)
        self.assertTrue(sent, "swtpm logged no command: the wire test proves nothing")
        self.assertFalse(any(raw in c for c in sent), "tpm2-tools %s: setting the owner authorization sent it" % version)
        mark = os.path.getsize(self.log)
        m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock", owner_auth=self.auth).define()
        sent = self.commands(mark)
        defines = [c for c in sent if int.from_bytes(c[6:10], "big") == 0x12A]     # TPM_CC_NV_DefineSpace
        self.assertTrue(defines)
        self.assertFalse(any(raw in c for c in sent), "tpm2-tools %s: an owner call sent the owner authorization" % version)
        self.assertFalse(any(b"\x40\x00\x00\x09" in c[14:] for c in defines),
                         "tpm2-tools %s authorizes an owner call with a password session (TPM_RS_PW): the value crosses the "
                         "bus in clear; it must not be in ownerauth.MEASURED_TOOLS" % version)
        print("\ntpm2-tools %s: the owner authorization never crossed the bus (%d commands read)" % (version, len(sent)), file=sys.stderr)


def setUpModule():
    """The channel refuses an unmeasured tpm2-tools once per process (ownerauth.measured_once). These tests are about
    behaviour, and OnTheWire IS the measurement: the gate is marked passed for the module, and OnlyMeasuredTools
    tests it with the mark cleared."""
    global _saved_checked
    _saved_checked, ownerauth._tools_checked = ownerauth._tools_checked, True


def tearDownModule():
    ownerauth._tools_checked = _saved_checked


if __name__ == "__main__":
    unittest.main()
