"""e2e/lib/p11_extract_probe.py against SoftHSM: the instrument must call a protected key protected AND
call an exposed key exposed, or its verdict on real hardware (#62) proves nothing."""
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from tests.hang_guard import DEAF_TO_TERM, run_bounded

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "e2e" / "lib" / "p11_extract_probe.py"
MODULE = next((m for m in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
               if os.path.exists(m)), None)
PIN, SO = "7310048261", "1234567890"
U = ctypes.c_ulong


class Attr(ctypes.Structure):
    _fields_ = [("type", U), ("pValue", ctypes.c_void_p), ("ulValueLen", U)]


def create_exposed_ec_key(module, key_id):
    """C_CreateObject an EC private key with CKA_SENSITIVE false and CKA_EXTRACTABLE true: a key whose
    CKA_VALUE the token will hand back. pkcs11-tool cannot make one (it always sets CKA_SENSITIVE)."""
    lib = ctypes.CDLL(module)
    lib.C_Initialize(None)
    try:
        n = U(0)
        lib.C_GetSlotList(ctypes.c_ubyte(1), None, ctypes.byref(n))
        slots = (U * n.value)()
        lib.C_GetSlotList(ctypes.c_ubyte(1), slots, ctypes.byref(n))
        h = U(0)
        assert lib.C_OpenSession(U(slots[0]), U(0x6), None, None, ctypes.byref(h)) == 0
        assert lib.C_Login(h, U(1), PIN.encode(), U(len(PIN))) == 0
        keep = []

        def val(t, b):
            buf = ctypes.create_string_buffer(b, len(b))
            keep.append(buf)
            return Attr(t, ctypes.cast(buf, ctypes.c_void_p), len(b))

        def ul(t, v):
            x = U(v)
            keep.append(x)
            return Attr(t, ctypes.cast(ctypes.byref(x), ctypes.c_void_p), ctypes.sizeof(x))

        def bl(t, v):
            x = ctypes.c_ubyte(1 if v else 0)
            keep.append(x)
            return Attr(t, ctypes.cast(ctypes.byref(x), ctypes.c_void_p), 1)
        p256_oid = bytes.fromhex("06082a8648ce3d030107")
        secret = bytes(range(1, 33))
        attrs = [ul(0x0, 3), ul(0x100, 3), bl(0x1, True), bl(0x2, True), bl(0x103, False), bl(0x162, True),
                 val(0x180, p256_oid), val(0x11, secret), val(0x102, bytes.fromhex(key_id))]
        tmpl = (Attr * len(attrs))(*attrs)
        obj = U(0)
        rv = lib.C_CreateObject(h, tmpl, U(len(attrs)), ctypes.byref(obj))
        assert rv == 0, "C_CreateObject 0x%x" % rv
    finally:
        lib.C_Finalize(None)


# In the CI job that installs SoftHSM2, REGALIA_EXPECT_SOFTHSM=1 turns a skip into a failure.
HAVE = bool(MODULE and shutil.which("softhsm2-util") and shutil.which("pkcs11-tool"))
if not HAVE and os.environ.get("REGALIA_EXPECT_SOFTHSM") == "1":
    raise RuntimeError("REGALIA_EXPECT_SOFTHSM=1 but SoftHSM2 or OpenSC is missing: the calibration would skip")


@unittest.skipUnless(HAVE, "needs SoftHSM2 and OpenSC")
class ExtractProbe(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d)
        (self.d / "tokens").mkdir()
        (self.d / "conf").write_text("directories.tokendir = %s/tokens\nobjectstore.backend = file\n" % self.d)
        self.env = dict(os.environ, SOFTHSM2_CONF=str(self.d / "conf"), REGALIA_Q_PIN=PIN)
        os.environ["SOFTHSM2_CONF"] = str(self.d / "conf")
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "probe", "--so-pin", SO, "--pin", PIN],
                       check=True, capture_output=True, env=self.env)
        out = subprocess.run(["softhsm2-util", "--show-slots"], capture_output=True, text=True, env=self.env).stdout
        self.serial = next(l.split(":", 1)[1].strip() for l in out.splitlines() if "Serial number" in l and l.split(":", 1)[1].strip())

    def probe(self, key_id):
        r = subprocess.run([sys.executable, str(PROBE), MODULE, self.serial, key_id], capture_output=True, text=True, env=self.env)
        return r.returncode, (json.loads(r.stdout) if r.stdout.strip() else {}), r.stderr

    def test_a_token_generated_key_is_refused(self):
        subprocess.run(["pkcs11-tool", "--module", MODULE, "--login", "--pin", "env:REGALIA_Q_PIN", "--keypairgen",
                        "--key-type", "EC:prime256v1", "--id", "01", "--label", "gen"], check=True, capture_output=True, env=self.env)
        rc, report, err = self.probe("01")
        self.assertEqual(rc, 0, err)
        self.assertEqual(report["CKA_VALUE"], {"rv": "0x11", "bytes_returned": 0})
        self.assertFalse(report["secret_bytes_returned"])
        self.assertIs(report["CKA_NEVER_EXTRACTABLE"], True)
        self.assertEqual((report["key_type"], report["verdict"]), ("EC", "REFUSED"))

    def test_an_exposed_key_is_reported_as_leaking(self):
        create_exposed_ec_key(MODULE, "0e")
        rc, report, err = self.probe("0e")
        self.assertEqual(rc, 1, "the probe must fail on a key whose secret the token returns")
        self.assertTrue(report["secret_bytes_returned"])
        self.assertEqual(report["CKA_VALUE"]["bytes_returned"], 32)
        self.assertEqual(report["verdict"], "LEAK")

    def test_the_pin_never_reaches_argv(self):
        self.assertNotIn("sys.argv[4]", PROBE.read_text())
        self.assertIn('os.environ.get("REGALIA_Q_PIN"', PROBE.read_text())


# The probe's OWN simple command: the text after the last shell separator before the probe's path. An assignment
# scoped to an earlier command (`REGALIA_Q_PIN="$Q_PIN" true; python3 .../p11_extract_probe.py`) hands the probe
# nothing, so the assignment must be in this command's prefix, before the interpreter.
# Each value is EITHER one quoted string OR an unquoted token that does not start with a quote, so the two never
# overlap: an ambiguous alternation here made rejection time exponential in the number of quoted tokens (CodeQL).
_SEPARATOR = re.compile(r"[;&|(){}`]")
_HANDS_PIN = re.compile(r'^\s*(?:\w+=(?:"[^"]*"|[^\s"]\S*)\s+)*REGALIA_Q_PIN="\$\w+"\s+(?:\w+=(?:"[^"]*"|[^\s"]\S*)\s+)*(?:timeout\s+(?:-k\s+(?:\d+|"\$\w+")\s+)?(?:\d+|"\$\w+")\s+)?python3(?:\s+-\w+)*\s+\S*$')


def probe_command_hands_it_the_pin(code):
    before = code[:code.index("p11_extract_probe.py")]
    own = _SEPARATOR.split(before)[-1]
    return bool(_HANDS_PIN.match(own))


class ScriptsHandTheProbeItsPIN(unittest.TestCase):
    """Static, so it runs everywhere: no SoftHSM needed to read a script."""

    def test_the_check_accepts_only_a_pin_in_the_probes_own_prefix(self):
        good = ['  REGALIA_Q_PIN="$Q_PIN" python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$@"; }',
                '  local rc; REGALIA_Q_PIN="$Q_PIN" timeout "$PROBE_BOUND" python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE"',
                'REGALIA_Q_PIN="$Q_PIN" timeout 60 python3 -Es "$HERE/lib/p11_extract_probe.py"',
                '  local rc; REGALIA_Q_PIN="$Q_PIN" timeout -k "$KILL_GRACE" "$PROBE_BOUND" python3 -Es "$HERE/lib/p11_extract_probe.py"',
                'REGALIA_Q_PIN="$Q_PIN" timeout -k 5 60 python3 -Es "$HERE/lib/p11_extract_probe.py"',
                'out="$(REGALIA_Q_PIN="$Q_PIN" python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$id" 2>&1)"']
        bad = ['REGALIA_Q_PIN="$Q_PIN" true; python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE"',
               'REGALIA_Q_PIN="$Q_PIN" true && python3 "$HERE/lib/p11_extract_probe.py"',
               'out="$(python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$id" 2>&1)"',
               'python3 -Es "$HERE/lib/p11_extract_probe.py" REGALIA_Q_PIN="$Q_PIN"',
               'REGALIA_Q_PIN="$Q_PIN" echo x | python3 "$HERE/lib/p11_extract_probe.py"',
               'REGALIA_Q_PIN="$Q_PIN" timeout 60 true; python3 "$HERE/lib/p11_extract_probe.py"',
               'timeout 60 REGALIA_Q_PIN="$Q_PIN" python3 "$HERE/lib/p11_extract_probe.py"',
               'REGALIA_Q_PIN="$Q_PIN" timeout -k 5 60 true; python3 "$HERE/lib/p11_extract_probe.py"',
               'timeout -k 5 60 REGALIA_Q_PIN="$Q_PIN" python3 "$HERE/lib/p11_extract_probe.py"',
               'REGALIA_Q_PIN="$Q_PIN" timeout -k python3 "$HERE/lib/p11_extract_probe.py"']
        for line in good:
            with self.subTest(good=line):
                self.assertTrue(probe_command_hands_it_the_pin(line), line)
        for line in bad:
            with self.subTest(bad=line):
                self.assertFalse(probe_command_hands_it_the_pin(line), line)

    def test_every_script_that_runs_the_probe_hands_it_the_pin(self):
        # The probe reads REGALIA_Q_PIN and nothing else. pkcs11-contract.sh stopped exporting its PIN
        # (#225) and kept calling the probe, which then refused on every card with "REGALIA_Q_PIN is
        # not set": the secret-attribute check could never pass. Each call must carry it in its own
        # environment prefix, on the same line, since the PIN is deliberately not exported.
        calls = []
        for script in sorted((ROOT / "e2e").glob("*.sh")):
            for number, line in enumerate(script.read_text().splitlines(), 1):
                code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
                if "p11_extract_probe.py" in code:
                    calls.append((script.name, number, code))
        self.assertTrue(calls, "no script runs p11_extract_probe.py: this check would pass by finding nothing")
        for name, number, code in calls:
            with self.subTest(script=name, line=number):
                self.assertTrue(probe_command_hands_it_the_pin(code),
                                f"{name}:{number} runs the probe without REGALIA_Q_PIN in its own environment prefix")


CONTRACT = ROOT / "e2e" / "pkcs11-contract.sh"


def p11probe_definition(text):
    """The p11probe function's source, from its opening line to the line that closes it."""
    lines, out = text.splitlines(), []
    for line in lines:
        if out or line.startswith("p11probe(){"):
            out.append(line)
            if line.rstrip().endswith("; }") and len(out) > 1:
                return "\n".join(out)
    raise AssertionError("pkcs11-contract.sh defines no p11probe(){ ... }")


class TheProbeIsBounded(unittest.TestCase):
    """#676: the script promises every token call is bounded; the extraction probe must be too."""

    def test_the_bound_is_set_and_no_looser_than_pkcs11_tools(self):
        text = CONTRACT.read_text()
        bound = re.search(r"^PROBE_BOUND=(\d+)$", text, re.M)
        self.assertIsNotNone(bound, "pkcs11-contract.sh sets no PROBE_BOUND")
        self.assertGreater(int(bound.group(1)), 0)
        self.assertLessEqual(int(bound.group(1)), 60, "the probe may not wait longer than pkcs11-tool's own 60 s bound")
        self.assertRegex(p11probe_definition(text), r'\btimeout -k "\$KILL_GRACE" "\$PROBE_BOUND" python3\b', "p11probe does not run the probe under PROBE_BOUND")

    def test_a_probe_that_hangs_fails_within_the_bound_and_says_so(self):
        # The REAL p11probe, with the gate stubbed open and a probe that never answers. Unbounded, it would sit for
        # 600 s; the outer timeout turns that into a named failure instead of a hung suite.
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d, "lib"); lib.mkdir()
            (lib / "p11_extract_probe.py").write_text("import time\ntime.sleep(600)\n")
            script = "\n".join(["set -u", "target_ok(){ return 0; }", 'SLOT=0 SERIAL=s MODULE=m Q_PIN=p HERE="$1"',
                                 "PROBE_BOUND=2", "KILL_GRACE=1", p11probe_definition(CONTRACT.read_text()),
                                 'out="$(p11probe x 2>&1)"; rc=$?; printf "rc=%s\\n%s\\n" "$rc" "$out"'])
            # A hang is cleaned up whole (tests/hang_guard.py): timeout(1) leaves the session's own process group.
            result = run_bounded(script, d)
        self.assertFalse(result.hung, "p11probe did not return within 30 s against a probe that never answers: it is unbounded")
        self.assertEqual(result.leftovers, [], "p11probe left processes running")
        stdout = result.stdout
        self.assertIn("rc=124", stdout, "a timed-out probe must return timeout's status, not swallow it: " + stdout)
        self.assertIn("did not answer within 2 s", stdout, stdout)


BOUND, GRACE = 2, 1


def bounded_calls(text):
    """(line number, code) for every executable line of TEXT that runs timeout(1); comment lines are skipped."""
    return [(n, line) for n, line in enumerate(text.splitlines(), 1)
            if not line.lstrip().startswith("#") and re.search(r"\btimeout\s", line.split(" #", 1)[0])]


class EveryBoundEscalatesToKill(unittest.TestCase):
    """#679: `timeout N` only sends SIGTERM. A call that ignores it still hangs; each bound must end in SIGKILL."""

    def test_the_grace_is_set_and_short(self):
        grace = re.search(r"^KILL_GRACE=(\d+)$", CONTRACT.read_text(), re.M)
        self.assertIsNotNone(grace, "pkcs11-contract.sh sets no KILL_GRACE")
        self.assertGreater(int(grace.group(1)), 0)
        self.assertLessEqual(int(grace.group(1)), 10, "a grace this long makes the bound a suggestion: at most 10 s")

    def test_every_timeout_call_in_the_script_escalates(self):
        calls = bounded_calls(CONTRACT.read_text())
        # Positive control: slot_of, the isolation count, target_ok, p11 and p11probe. Fewer means the scan went blind.
        self.assertGreaterEqual(len(calls), 5, f"found only {len(calls)} timeout calls: the scan is not seeing the script")
        for number, line in calls:
            with self.subTest(line=number):
                self.assertRegex(line, r'\btimeout -k "\$KILL_GRACE" (?:\d+|"\$\w+") ',
                                 f"pkcs11-contract.sh:{number} has a timeout with no SIGKILL escalation: {line.strip()}")

    def test_the_scan_sees_a_call_without_escalation(self):
        # The check above, fed a line it must refuse, so it cannot pass by matching nothing.
        calls = bounded_calls('# timeout 9 in a comment\nx(){ timeout 30 pkcs11-tool -L; }\ny(){ timeout -k "$KILL_GRACE" 30 z; }\n')
        self.assertEqual([n for n, _ in calls], [2, 3])
        self.assertNotRegex(calls[0][1], r'\btimeout -k "\$KILL_GRACE" (?:\d+|"\$\w+") ')

    def test_a_probe_deaf_to_term_is_killed_within_bound_and_grace(self):
        with tempfile.TemporaryDirectory() as d:
            lib = Path(d, "lib"); lib.mkdir()
            (lib / "p11_extract_probe.py").write_text(DEAF_TO_TERM)
            script = "\n".join(["set -u", "target_ok(){ return 0; }", 'SLOT=0 SERIAL=s MODULE=m Q_PIN=p HERE="$1"',
                                 f"PROBE_BOUND={BOUND}", f"KILL_GRACE={GRACE}", p11probe_definition(CONTRACT.read_text()),
                                 'out="$(p11probe x 2>&1)"; rc=$?; printf "rc=%s\\n%s\\n" "$rc" "$out"'])
            got = run_bounded(script, d)
        self.assertFalse(got.hung, "p11probe did not return within 30 s against a probe that ignores SIGTERM: no SIGKILL")
        self.assertEqual(got.leftovers, [], "p11probe left processes running")
        stdout, took = got.stdout, got.seconds
        self.assertIn("rc=137", stdout, "a probe killed after the grace must return SIGKILL's status: " + stdout)
        self.assertIn(f"did not answer within {BOUND} s", stdout, stdout)
        self.assertLess(took, BOUND + GRACE + 5, f"took {took:.1f} s against a bound of {BOUND} s and a grace of {GRACE} s")

    def test_a_token_call_deaf_to_term_is_killed_within_bound_and_grace(self):
        # p11 with its 60 s bound shortened to BOUND, and a pkcs11-tool that ignores SIGTERM.
        line = next(l for l in CONTRACT.read_text().splitlines() if l.startswith("p11(){"))
        self.assertIn(" 60 pkcs11-tool ", line)
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d, "pkcs11-tool"); tool.write_text("#!/usr/bin/env python3\n" + DEAF_TO_TERM); tool.chmod(0o755)
            script = "\n".join(["set -u", 'PATH="$1:$PATH" SLOT=0 MODULE=m', f"KILL_GRACE={GRACE}",
                                 line.replace(" 60 pkcs11-tool ", f" {BOUND} pkcs11-tool "),
                                 'p11 -L; printf "rc=%s\\n" "$?"'])
            got = run_bounded(script, d)
        self.assertFalse(got.hung, "p11 did not return within 30 s against a pkcs11-tool that ignores SIGTERM: no SIGKILL")
        self.assertEqual(got.leftovers, [], "p11 left processes running")
        stdout, took = got.stdout, got.seconds
        self.assertIn("rc=137", stdout, stdout)
        self.assertLess(took, BOUND + GRACE + 5, f"took {took:.1f} s against a bound of {BOUND} s and a grace of {GRACE} s")


if __name__ == "__main__":
    unittest.main()
