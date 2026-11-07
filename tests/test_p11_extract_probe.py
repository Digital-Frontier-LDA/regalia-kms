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
import unittest
from pathlib import Path

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
_HANDS_PIN = re.compile(r'^\s*(?:\w+=(?:"[^"]*"|[^\s"]\S*)\s+)*REGALIA_Q_PIN="\$\w+"\s+(?:\w+=(?:"[^"]*"|[^\s"]\S*)\s+)*python3(?:\s+-\w+)*\s+\S*$')


def probe_command_hands_it_the_pin(code):
    before = code[:code.index("p11_extract_probe.py")]
    own = _SEPARATOR.split(before)[-1]
    return bool(_HANDS_PIN.match(own))


class ScriptsHandTheProbeItsPIN(unittest.TestCase):
    """Static, so it runs everywhere: no SoftHSM needed to read a script."""

    def test_the_check_accepts_only_a_pin_in_the_probes_own_prefix(self):
        good = ['  REGALIA_Q_PIN="$Q_PIN" python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$@"; }',
                'out="$(REGALIA_Q_PIN="$Q_PIN" python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$id" 2>&1)"']
        bad = ['REGALIA_Q_PIN="$Q_PIN" true; python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE"',
               'REGALIA_Q_PIN="$Q_PIN" true && python3 "$HERE/lib/p11_extract_probe.py"',
               'out="$(python3 -Es "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$id" 2>&1)"',
               'python3 -Es "$HERE/lib/p11_extract_probe.py" REGALIA_Q_PIN="$Q_PIN"',
               'REGALIA_Q_PIN="$Q_PIN" echo x | python3 "$HERE/lib/p11_extract_probe.py"']
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


if __name__ == "__main__":
    unittest.main()
