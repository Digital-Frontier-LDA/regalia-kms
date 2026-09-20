#!/usr/bin/env python3
"""Tests for hsm-bench.py that need no card and no PyKCS11.

WHAT THEY PIN. The harness recovers from a failed operation by CLOSING the session and opening a
replacement, because a failed C_Sign can leave the operation ACTIVE and every later call then
returns CKR_OPERATION_ACTIVE. PKCS#11 guarantees an object handle only for the life of the session
that produced it, so every handle taken before that recovery may be invalid afterwards — and a
module is free to number them differently. Keeping them meant the recovery measured nothing: each
later key failed with CKR_OBJECT_HANDLE_INVALID, which reads in the output as a card that cannot
sign. That is worse than a crash, because it looks like a result.

A fake PyKCS11 module stands in for the library: the real one needs a card, and the property under
test is the harness's bookkeeping, not the card's behaviour.
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "hsm-bench.py"

CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKA_LABEL = 0, 1, 2, 3
CKA_EC_PARAMS, CKA_MODULUS_BITS = 4, 5
CKO_PRIVATE_KEY, CKO_PUBLIC_KEY = 10, 11
CKK_EC, CKK_RSA = 20, 21


class FakeError(Exception):
    pass


class FakeMechanism:
    def __init__(self, mech, param):
        self.mech = mech


class FakeSession:
    """One session. Handles are unique per session, as a real module is free to make them."""
    counter = [0]

    def __init__(self, keys):
        FakeSession.counter[0] += 1
        self.gen = FakeSession.counter[0]
        self.keys = keys                      # [(id bytes, ktype, label)]
        self.closed = False
        self.logins = 0
        self.fail_on = set()                  # handles whose sign() raises

    # -- handles are (generation, index), so a handle from another session is recognisable
    def findObjects(self, template):
        t = dict(template)
        if t.get(CKA_CLASS) == CKO_PUBLIC_KEY:
            return []
        out = []
        for i, (kid, _k, _l) in enumerate(self.keys):
            if CKA_ID in t and t[CKA_ID] != kid:
                continue
            out.append((self.gen, i))
        return out

    def getAttributeValue(self, obj, attrs):
        gen, i = obj
        if gen != self.gen or self.closed:
            raise FakeError("CKR_OBJECT_HANDLE_INVALID")
        kid, ktype, label = self.keys[i]
        vals = {CKA_ID: list(kid), CKA_KEY_TYPE: ktype, CKA_LABEL: label,
                CKA_EC_PARAMS: None, CKA_MODULUS_BITS: 2048}
        return [vals[a] for a in attrs]

    def sign(self, obj, data, mech):
        gen, i = obj
        if gen != self.gen or self.closed:
            raise FakeError("CKR_OBJECT_HANDLE_INVALID")
        if obj in self.fail_on:
            raise FakeError("CKR_OPERATION_ACTIVE")
        return b"\x00" * 64

    def decrypt(self, obj, data, mech):
        return self.sign(obj, data, mech)

    def login(self, pin):
        self.logins += 1

    def logout(self):
        pass

    def closeSession(self):
        self.closed = True


class FakeLib:
    def __init__(self, keys):
        self.keys = keys
        self.sessions = []

    def load(self, path):
        pass

    def getSlotList(self, tokenPresent=True):
        return [0]

    def getTokenInfo(self, slot):
        class I:
            label = "fake-token"
            firmwareVersion = (4, 1)
        return I()

    def openSession(self, slot, flags):
        s = FakeSession(self.keys)
        self.sessions.append(s)
        return s


def install_fake(keys):
    mod = type(sys)("PyKCS11")
    mod.PyKCS11Error = FakeError
    mod.Mechanism = FakeMechanism
    mod.CKA_CLASS, mod.CKA_ID = CKA_CLASS, CKA_ID
    mod.CKA_KEY_TYPE, mod.CKA_LABEL = CKA_KEY_TYPE, CKA_LABEL
    mod.CKA_EC_PARAMS, mod.CKA_MODULUS_BITS = CKA_EC_PARAMS, CKA_MODULUS_BITS
    mod.CKA_MODULUS, mod.CKA_PUBLIC_EXPONENT = 6, 7
    mod.CKO_PRIVATE_KEY, mod.CKO_PUBLIC_KEY = CKO_PRIVATE_KEY, CKO_PUBLIC_KEY
    mod.CKK_EC, mod.CKK_RSA = CKK_EC, CKK_RSA
    mod.CKM_ECDSA, mod.CKM_ECDSA_SHA256 = 30, 31
    mod.CKM_SHA256_RSA_PKCS, mod.CKM_RSA_PKCS = 32, 33
    mod.CKF_SERIAL_SESSION, mod.CKF_RW_SESSION = 1, 2
    lib = FakeLib(keys)
    mod.PyKCS11Lib = lambda: lib
    sys.modules["PyKCS11"] = mod
    return lib


def load_bench(env):
    for k, v in env.items():
        os.environ[k] = v
    sys.modules.pop("hsm_bench", None)
    spec = importlib.util.spec_from_file_location("hsm_bench", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class BenchTest(unittest.TestCase):
    def setUp(self):
        FakeSession.counter[0] = 0

    def run_bench(self, keys, fail_first_op=False, n="2"):
        lib = install_fake(keys)
        m = load_bench({"HSM_PIN": "123456", "BENCH_N": n, "PKCS11_MODULE": "/fake"})
        if fail_first_op:
            orig = lib.openSession

            def patched(slot, flags):
                s = orig(slot, flags)
                if len(lib.sessions) == 1:       # only the first session fails
                    s.fail_on.add((s.gen, 0))
                return s
            lib.openSession = patched
        out = []
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            m.main()
        out = buf.getvalue()
        return lib, out

    def test_measures_every_key_on_the_happy_path(self):
        keys = [(b"\x01", CKK_EC, "k1"), (b"\x02", CKK_EC, "k2")]
        _lib, out = self.run_bench(keys)
        self.assertIn("k1", out)
        self.assertIn("k2", out)
        self.assertNotIn("—", out, f"a row went unmeasured on the happy path:\n{out}")

    def test_a_failure_reopens_the_session(self):
        keys = [(b"\x01", CKK_EC, "k1"), (b"\x02", CKK_EC, "k2")]
        lib, _out = self.run_bench(keys, fail_first_op=True)
        self.assertGreater(len(lib.sessions), 1, "the failed operation did not reopen the session")
        self.assertTrue(lib.sessions[0].closed, "the old session was not closed")
        self.assertEqual(lib.sessions[1].logins, 1, "the replacement session was not logged in")

    def test_keys_after_a_failure_are_still_measured(self):
        # THE REGRESSION. With handles kept from the old session, every later operation raised
        # CKR_OBJECT_HANDLE_INVALID and the table showed dashes for the rest of the card.
        keys = [(b"\x01", CKK_EC, "k1"), (b"\x02", CKK_EC, "k2"), (b"\x03", CKK_EC, "k3")]
        _lib, out = self.run_bench(keys, fail_first_op=True)
        for label in ("k2", "k3"):
            rows = [l for l in out.splitlines() if l.startswith(label)]
            self.assertTrue(rows, f"no row for {label}")
            for r in rows:
                self.assertNotIn("HANDLE_INVALID", r, f"stale handle used after reopen: {r}")
                self.assertNotIn("—", r, f"{label} went unmeasured after an earlier failure:\n{out}")

    def test_the_same_key_is_re_resolved_after_its_own_failure(self):
        # k1 has two operations; the first fails, and the second must run on a handle from the
        # REPLACEMENT session rather than being skipped or timed against a stale one.
        keys = [(b"\x01", CKK_EC, "k1")]
        _lib, out = self.run_bench(keys, fail_first_op=True)
        rows = [l for l in out.splitlines() if l.startswith("k1")]
        self.assertEqual(len(rows), 2, out)
        self.assertNotIn("—", rows[1], f"the key's second operation was lost with the session:\n{out}")

    def test_a_sample_count_below_one_is_refused_before_the_card_is_touched(self):
        install_fake([(b"\x01", CKK_EC, "k1")])
        with self.assertRaises(SystemExit) as cm:
            load_bench({"HSM_PIN": "123456", "BENCH_N": "0", "PKCS11_MODULE": "/fake"})
        self.assertIn("1 or more", str(cm.exception))

    def test_a_non_numeric_sample_count_is_refused(self):
        install_fake([(b"\x01", CKK_EC, "k1")])
        with self.assertRaises(SystemExit) as cm:
            load_bench({"HSM_PIN": "123456", "BENCH_N": "twelve", "PKCS11_MODULE": "/fake"})
        self.assertIn("not an integer", str(cm.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
