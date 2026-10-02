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
CKA_DERIVE, CKA_VALUE, CKA_TOKEN, CKA_SENSITIVE, CKA_EXTRACTABLE = 40, 41, 42, 43, 44
CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKD_NULL = 12, 22, 1
P256 = bytes.fromhex("06082a8648ce3d030107")


class FakeError(Exception):
    pass


class FakeMechanism:
    def __init__(self, mech, param):
        self.mech = mech


class FakeECDHMechanism:
    def __init__(self, publicData, kdf=1, sharedData=None):
        self.publicData, self.kdf, self.sharedData = publicData, kdf, sharedData


class FakeSession:
    """One session. Handles are unique per session, as a real module is free to make them."""
    counter = [0]

    def __init__(self, keys):
        FakeSession.counter[0] += 1
        self.gen = FakeSession.counter[0]
        self.keys = keys                      # [(id bytes, ktype, label[, {"derive": bool, "params": bytes}])]
        self.closed = False
        self.logins = 0
        self.fail_on = set()                  # handles whose sign() raises
        self.derives = []                     # (key handle, mechanism, template) per deriveKey
        self.live = set()                     # derived session objects not yet destroyed
        self.derive_fails = False
        self.unreadable_secret = False

    # -- handles are (generation, index), so a handle from another session is recognisable
    def findObjects(self, template):
        t = dict(template)
        if t.get(CKA_CLASS) == CKO_PUBLIC_KEY:
            return []
        out = []
        for i, key in enumerate(self.keys):
            kid = key[0]
            if CKA_ID in t and t[CKA_ID] != kid:
                continue
            out.append((self.gen, i))
        return out

    def getAttributeValue(self, obj, attrs):
        if isinstance(obj, tuple) and obj[0] == "derived":
            if obj not in self.live:
                raise FakeError("CKR_OBJECT_HANDLE_INVALID")
            return [None if self.unreadable_secret else [7] * 32 for _ in attrs]
        gen, i = obj
        if gen != self.gen or self.closed:
            raise FakeError("CKR_OBJECT_HANDLE_INVALID")
        kid, ktype, label = self.keys[i][:3]
        extra = self.keys[i][3] if len(self.keys[i]) > 3 else {}
        vals = {CKA_ID: list(kid), CKA_KEY_TYPE: ktype, CKA_LABEL: label,
                CKA_EC_PARAMS: list(extra["params"]) if extra.get("params") else None,
                CKA_MODULUS_BITS: 2048, CKA_DERIVE: extra.get("derive", False)}
        return [vals[a] for a in attrs]

    def deriveKey(self, baseKey, template, mecha):
        gen, _i = baseKey
        if gen != self.gen or self.closed:
            raise FakeError("CKR_OBJECT_HANDLE_INVALID")
        if self.derive_fails:
            raise FakeError("CKR_FUNCTION_FAILED")
        self.derives.append((baseKey, mecha, dict(template)))
        handle = ("derived", self.gen, len(self.derives))
        self.live.add(handle)
        return handle

    def destroyObject(self, obj):
        self.live.discard(obj)

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
        self.calls = []          # every library call, so "no card was touched" is checkable

    def load(self, path):
        self.calls.append("load")

    def getSlotList(self, tokenPresent=True):
        self.calls.append("getSlotList")
        return [0]

    def getTokenInfo(self, slot):
        self.calls.append("getTokenInfo")
        class I:
            label = "fake-token"
            firmwareVersion = (4, 1)
        return I()

    def openSession(self, slot, flags):
        self.calls.append("openSession")
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
    mod.ECDH1_DERIVE_Mechanism = FakeECDHMechanism
    mod.CKA_DERIVE, mod.CKA_VALUE, mod.CKA_TOKEN = CKA_DERIVE, CKA_VALUE, CKA_TOKEN
    mod.CKA_SENSITIVE, mod.CKA_EXTRACTABLE = CKA_SENSITIVE, CKA_EXTRACTABLE
    mod.CKO_SECRET_KEY, mod.CKK_GENERIC_SECRET, mod.CKD_NULL = CKO_SECRET_KEY, CKK_GENERIC_SECRET, CKD_NULL
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


def PEER(curve_hex):
    """A stand-in peer point: 0x04 and 64 bytes, the shape of an uncompressed P-256 point."""
    return (b"\x04" + b"\x11" * 64, None) if curve_hex == P256.hex() else (None, "curve not known to this benchmark")


def ecdh_rows(out):
    return [l for l in out.splitlines() if "ECDH derive" in l]


class BenchTest(unittest.TestCase):
    def setUp(self):
        FakeSession.counter[0] = 0

    def run_bench(self, keys, fail_first_op=False, n="2", peer=PEER, prepare=None):
        lib = install_fake(keys)
        m = load_bench({"HSM_PIN": "123456", "BENCH_N": n, "PKCS11_MODULE": "/fake"})
        # The peer point comes from `cryptography` in a real run. Here it is supplied, so the tests
        # need neither that library nor a curve implementation: what is under test is what the
        # harness does with a point, and with the absence of one.
        if peer is not None:
            m.peer_point = peer
        if prepare is not None:
            orig_open = lib.openSession

            def prepared(slot, flags):
                s = orig_open(slot, flags)
                prepare(s, len(lib.sessions))
                return s
            lib.openSession = prepared
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
        # "Before the card is touched" is the claim, so it is the thing asserted: exiting is not
        # enough if the module was already loaded, the slot listed or a session opened — each of
        # those reaches the token, and one of them spends a PIN login.
        for bad in ("0", "-5"):
            with self.subTest(bench_n=bad):
                lib = install_fake([(b"\x01", CKK_EC, "k1")])
                with self.assertRaises(SystemExit) as cm:
                    load_bench({"HSM_PIN": "123456", "BENCH_N": bad, "PKCS11_MODULE": "/fake"})
                self.assertIn("1 or more", str(cm.exception))
                self.assertEqual([], lib.calls, f"the card was touched anyway: {lib.calls}")
                self.assertEqual([], lib.sessions, "a session was opened before the refusal")

    def test_a_non_numeric_sample_count_is_refused(self):
        lib = install_fake([(b"\x01", CKK_EC, "k1")])
        with self.assertRaises(SystemExit) as cm:
            load_bench({"HSM_PIN": "123456", "BENCH_N": "twelve", "PKCS11_MODULE": "/fake"})
        self.assertIn("not an integer", str(cm.exception))
        self.assertEqual([], lib.calls, f"the card was touched anyway: {lib.calls}")

    def test_two_keys_sharing_a_cka_id_are_refused_rather_than_confused(self):
        # Nothing stops a token from holding two private keys with the same CKA_ID. Taking the
        # first match would print one key's timings under the other key's label and curve — a
        # wrong number that looks exactly like a measurement.
        keys = [(b"\x01", CKK_EC, "k1"), (b"\x01", CKK_RSA, "k1-duplicate")]
        _lib, out = self.run_bench(keys)
        self.assertIn("ambiguous", out, f"an ambiguous CKA_ID was measured anyway:\n{out}")
        for line in out.splitlines():
            if line.startswith("k1") and "ambiguous" not in line:
                self.assertNotRegex(line, r"\d+\.\d", f"a timing was reported for an ambiguous id: {line}")

    # ---- ECDH (regalia#532: the figure D20 needs to choose the class KEK) --------------------

    DERIVE_KEY = (b"\x03", CKK_EC, "kek", {"derive": True, "params": P256})

    def test_a_key_that_allows_derive_gets_an_ecdh_row_measured_as_the_daemon_derives(self):
        lib, out = self.run_bench([self.DERIVE_KEY], n="3")
        rows = ecdh_rows(out)
        self.assertEqual(len(rows), 1, out)
        self.assertNotIn("—", rows[0], f"the ECDH row carries no timing:\n{out}")
        self.assertNotIn("not measured", out)
        session = lib.sessions[0]
        self.assertEqual(len(session.derives), 3, "one derive per sample")
        for _key, mechanism, template in session.derives:
            # CKD_NULL and a non-sensitive session object: the daemon's own template, so the number
            # is the cost of what the daemon does, not of some other derivation.
            self.assertEqual(mechanism.kdf, CKD_NULL)
            self.assertEqual(mechanism.publicData, b"\x04" + b"\x11" * 64)
            self.assertEqual(template, {CKA_CLASS: CKO_SECRET_KEY, CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                                        CKA_TOKEN: False, CKA_SENSITIVE: False, CKA_EXTRACTABLE: True})
        self.assertEqual(session.live, set(), "derived secrets were left in the session")

    def test_a_key_that_does_not_allow_derive_is_never_asked_and_the_output_says_so(self):
        # A refused derive is a failed operation, and a failed operation costs a session reopen and
        # a PIN verification. A sign-only key must not be asked.
        lib, out = self.run_bench([(b"\x01", CKK_EC, "signer", {"derive": False, "params": P256})])
        self.assertEqual(ecdh_rows(out), [], out)
        self.assertEqual(lib.sessions[0].derives, [])
        self.assertEqual(len(lib.sessions), 1, "the session was reopened although nothing failed")
        self.assertIn("ECDH    : not measured", out, "the absence of an ECDH figure is not stated")

    def test_no_peer_point_means_a_row_with_the_reason_and_no_derive(self):
        for why in ("install `cryptography` to measure ECDH", "curve not known to this benchmark"):
            with self.subTest(why=why):
                lib, out = self.run_bench([self.DERIVE_KEY], peer=lambda _curve, why=why: (None, why))
                rows = ecdh_rows(out)
                self.assertEqual(len(rows), 1, out)
                self.assertIn(why, rows[0])
                self.assertEqual(lib.sessions[0].derives, [], "a derive was attempted without a peer point")
                self.assertNotIn("ECDH    : not measured", out, "a key that allows derive was reported as none allowing it")

    def test_a_failed_derive_is_reported_and_the_session_recovers(self):
        def first_session_cannot_derive(session, count):
            session.derive_fails = count == 1
        keys = [self.DERIVE_KEY, (b"\x04", CKK_EC, "after", {"derive": False, "params": P256})]
        lib, out = self.run_bench(keys, prepare=first_session_cannot_derive)
        rows = ecdh_rows(out)
        self.assertEqual(len(rows), 1, out)
        self.assertIn("CKR_FUNCTION_FAILED", rows[0])
        self.assertGreater(len(lib.sessions), 1, "the failed derive did not reopen the session")
        for row in [l for l in out.splitlines() if l.startswith("after")]:
            self.assertNotIn("—", row, f"a key after the failed derive went unmeasured:\n{out}")

    def test_a_derived_secret_is_destroyed_even_when_it_cannot_be_read(self):
        def unreadable(session, _count):
            session.unreadable_secret = True
        lib, out = self.run_bench([self.DERIVE_KEY], prepare=unreadable)
        self.assertIn("could not be read", "\n".join(ecdh_rows(out)), out)
        for session in lib.sessions:
            self.assertEqual(session.live, set(), "a derived secret outlived a failed read")

    def test_the_real_peer_point_is_a_point_on_the_keys_curve(self):
        # The one test that uses `cryptography`, when it is installed: the shape of what the real
        # function hands CKM_ECDH1_DERIVE, per curve, and its refusal of a curve it does not know.
        install_fake([])
        m = load_bench({"HSM_PIN": "123456", "BENCH_N": "1", "PKCS11_MODULE": "/fake"})
        self.assertEqual(m.peer_point("0000"), (None, "curve not known to this benchmark"))
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.assertEqual(m.peer_point(P256.hex()), (None, "install `cryptography` to measure ECDH"))
            return
        for curve, size in (("06082a8648ce3d030107", 32), ("06052b81040022", 48), ("06052b8104000a", 32)):
            point, why = m.peer_point(curve)
            self.assertIsNone(why)
            self.assertEqual((point[0], len(point)), (4, 1 + 2 * size))
        self.assertNotEqual(m.peer_point(P256.hex())[0], m.peer_point(P256.hex())[0], "the peer key is not fresh")


if __name__ == "__main__":
    unittest.main(verbosity=2)
