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
    # #242 C2: seal-hsm-pin.sh takes the value from the envelope there
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
        with self.assertRaisesRegex(m.Refused, "cannot define"):
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
        with self.assertRaisesRegex(m.Refused, "cannot define"):
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
        return enrol.set_ownerauth(node, PIN, self.record, stream or value(node), check=check, run=self.tpm)

    def test_set_from_empty_then_checked(self):
        self.assertFalse(ownerauth.posture(run=self.tpm)["owner"])
        self.assertIn("is set to a's envelope value, and answers to it", self.run_step())
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
                    if argv[0] == "tpm2_changeauth" and "-p" in argv:        # the proof
                        return subprocess.CompletedProcess(argv, 1, b"", answer)
                    return tpm(argv, **kw)
                with self.assertRaises(m.Refused) as caught:
                    enrol.set_ownerauth("a", PIN, self.record, value("a"), run=run)
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

        def step(node_id, root_key, record_path, stream, check=False):
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
        ownerauth.set_owner(self.auth, self.tcti)
        self.assertEqual(ownerauth.posture(self.tcti)["owner"], True)
        self.assertTrue(ownerauth.holds(self.auth, self.tcti))
        prefix = ownerauth.Auth(bytes.fromhex("00aa" + "00" * 30))          # the same bytes up to the first NUL
        self.assertFalse(ownerauth.holds(prefix, self.tcti))
        with self.assertRaisesRegex(m.Refused, "already set"):
            ownerauth.set_owner(self.auth, self.tcti)
        with self.assertRaisesRegex(m.Refused, "cannot define"):
            m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock").define()
        hw = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock", owner_auth=self.auth)
        hw.define()
        hw.anchor(2, lambda epoch: "%02x" % epoch * 32)
        self.assertEqual((hw.value(), hw.record()[0]), (2, 2))
        hw.redefine(4, "04" * 32)
        self.assertEqual(hw.value(), 4)


if __name__ == "__main__":
    unittest.main()
