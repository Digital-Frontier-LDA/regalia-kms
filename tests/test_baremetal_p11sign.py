"""deploy/baremetal/p11sign.py (#262, moved from the retired authority.py by #199): a key on a token in process, chosen by
serial in the session that logs in, a refused PIN latched and never presented again, every signature verified. Against
SoftHSM (the same PKCS#11 calls a Nitrokey or OpenSC's YubiKey driver gets) and a scripted token."""
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import membership as m, p11sign


SOFTHSM = next((c for c in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.exists(c)), None)


try:
    import PyKCS11
except ImportError:
    PyKCS11 = None
EXPECT_PKCS11 = os.environ.get("REGALIA_EXPECT_PYKCS11", "") not in ("", "0")


class Pkcs11(unittest.TestCase):
    """Pkcs11Signer against SoftHSM: the same PKCS#11 calls the Nitrokey gets, in this process."""

    def setUp(self):
        import gc
        import subprocess
        # A signer a holder kept (they may reference each other through on_latch) keeps its PyKCS11 library,
        # and so SoftHSM, initialised on the last test's token directory until it is collected: collect it.
        gc.collect()
        if not (PyKCS11 and SOFTHSM and shutil.which("pkcs11-tool") and shutil.which("softhsm2-util")):
            if EXPECT_PKCS11:
                self.fail("REGALIA_EXPECT_PYKCS11 is set, but PyKCS11, SoftHSM or pkcs11-tool is missing")
            self.skipTest("PyKCS11, SoftHSM and pkcs11-tool are not all installed")
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(self.d + "/tokens")
        with open(self.d + "/softhsm2.conf", "w") as f:
            f.write("directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" % self.d)
        patch = unittest.mock.patch.dict(os.environ, {"SOFTHSM2_CONF": self.d + "/softhsm2.conf"})
        patch.start()
        self.addCleanup(patch.stop)
        self.pin = "%08d" % (int.from_bytes(os.urandom(4), "big") % 10 ** 8)
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "revocation", "--so-pin", "12345678", "--pin", self.pin],
                       check=True, capture_output=True)
        listing = subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--list-slots"], check=True, capture_output=True, text=True).stdout
        self.serial = next(line.split(":", 1)[1].strip() for line in listing.splitlines() if "serial num" in line)
        subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--token-label", "revocation", "--login", "--pin", "env:P", "--keypairgen",
                        "--key-type", "EC:prime256v1", "--id", "51", "--label", "revocation"], check=True, capture_output=True, env=dict(os.environ, P=self.pin))
        os.makedirs(self.d + "/credentials")
        with open(self.d + "/credentials/revocation-pin", "w") as f:
            f.write(self.pin + "\n")

    def signer(self, **override):
        args = dict(module=SOFTHSM, serial=self.serial, key_id="51", pin_credential="revocation-pin", credentials=self.d + "/credentials")
        args.update(override)
        return p11sign.Pkcs11Signer(args.pop("module"), args.pop("serial"), args.pop("key_id"), args.pop("pin_credential"),
                                      credentials=args.pop("credentials"), **args)

    def test_it_signs_low_s_and_its_signatures_verify(self):
        signer = self.signer()
        self.assertEqual((signer.kind, signer.alg, len(signer.public())), ("pkcs11", "ecdsa-p256", 130))
        for n in range(12):
            message = b"regalia-heartbeat/v1\0" + str(n).encode()
            signature = signer.sign(message)
            self.assertLessEqual(int.from_bytes(signature[32:], "big"), m.P256_ORDER // 2)
            m.verify_revocation("ecdsa-p256", signer.public(), message, signature.hex(), "test")

    def test_an_ed25519_key_signs_with_eddsa_as_the_owners_approval_key_does(self):
        """#199: the owner's YubiKeys are Ed25519 (OpenPGP applet, CKM_EDDSA through OpenSC). SoftHSM's Ed25519 key stands in."""
        import subprocess
        subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--token-label", "revocation", "--login", "--pin", "env:P", "--keypairgen",
                        "--key-type", "EC:edwards25519", "--id", "52", "--label", "owner"], check=True, capture_output=True, env=dict(os.environ, P=self.pin))
        signer = self.signer(key_id="52", alg="ed25519")
        self.assertEqual((signer.alg, len(signer.public())), ("ed25519", 64))
        message = b"regalia-heartbeat/v1\0{}"
        signature = signer.sign(message)
        m.verify_revocation("ed25519", signer.public(), message, signature.hex(), "test")
        # the P-256 key named as Ed25519, and the Ed25519 key named as P-256: refused before any PIN
        with self.assertRaisesRegex(m.Refused, "is not an Ed25519 key"):
            self.signer(key_id="51", alg="ed25519")
        with self.assertRaisesRegex(m.Refused, "is not a P-256 key"):
            self.signer(key_id="52")
        with self.assertRaisesRegex(m.Refused, "algorithm is one of"):
            self.signer(alg="rsa")

    def test_the_wrong_serial_or_no_pin_is_refused_before_any_signature(self):
        with self.assertRaises(m.Refused) as caught:
            self.signer(serial="NOSUCHTOKEN")
        self.assertIn("no token with serial NOSUCHTOKEN", str(caught.exception))
        signer = self.signer(credentials=self.d + "/elsewhere")
        with self.assertRaises(OSError):
            signer.sign(b"x")

    def test_it_runs_no_program(self):
        """In process: no pkcs11-tool, so the PIN is in no argv and no child's environment."""
        with unittest.mock.patch("subprocess.run", side_effect=AssertionError("a program was run")), \
                unittest.mock.patch("subprocess.Popen", side_effect=AssertionError("a program was run")):
            signer = self.signer()
            m.verify_revocation("ecdsa-p256", signer.public(), b"y", signer.sign(b"y").hex(), "test")

    def test_a_key_that_is_not_p256_is_refused(self):
        import subprocess
        subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--token-label", "revocation", "--login", "--pin", "env:P", "--keypairgen",
                        "--key-type", "EC:secp384r1", "--id", "52"], check=True, capture_output=True, env=dict(os.environ, P=self.pin))
        with self.assertRaises(m.Refused) as caught:
            self.signer(key_id="52")
        self.assertIn("not a P-256 key", str(caught.exception))


class FakeToken:
    """A stand-in for PyKCS11 with one or more tokens, whose serials a test changes at a chosen call."""
    CKA_CLASS, CKA_ID, CKA_EC_POINT, CKA_EC_PARAMS, CKA_LABEL = "class", "id", "point", "params", "label"
    CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKM_ECDSA = "public", "private", "ecdsa"
    CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE, CKR_PIN_LOCKED, CKR_DEVICE_REMOVED = 0xA0, 0xA1, 0xA2, 0xA4, 0x32
    CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY, CKF_USER_PIN_LOCKED, CKF_TOKEN_INITIALIZED = 0x10000, 0x20000, 0x40000, 0x400

    class PyKCS11Error(Exception):
        def __init__(self, value):
            super().__init__("PKCS#11 error 0x%x" % value)
            self.value = value

    def __init__(self, serials, point):
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        self.serials, self.point, self.calls, self.logins = dict(serials), point, [], []
        self.swap_at, self.removed = None, False
        self.labels, self.objects = {}, None            # token labels by slot; objects: None (one of each class) or a list of dicts
        self.flags, self.login_error = self.CKF_TOKEN_INITIALIZED, None
        self.key = _ec.generate_private_key(_ec.SECP256R1())
        fake = self

        class Info:
            def __init__(self, serial):
                self.serialNumber, self.slotID, self.flags = serial, None, fake.flags

        class Session:
            def __init__(self, slot):
                self.slot = slot

            def _step(self, name):
                fake.calls.append(name)
                if fake.swap_at == name:
                    fake.serials[self.slot] = "SWAPPED"
                    fake.removed = True                  # the card left the reader: the session is gone
                if fake.removed and name in ("login", "sign"):
                    raise RuntimeError("CKR_DEVICE_REMOVED")

            def getSessionInfo(self):
                self._step("info")
                info = Info(None)
                info.slotID = self.slot
                return info

            def findObjects(self, template):
                if fake.objects is None:
                    return [dict(template)[fake.CKA_CLASS]]
                return [o[fake.CKA_CLASS] for o in fake.objects if all(o.get(k) == v for k, v in template)]

            def getAttributeValue(self, obj, attrs):
                return [list(fake.point), list(bytes.fromhex("06082a8648ce3d030107"))]

            def login(self, pin):
                self._step("login")
                fake.logins.append((self.slot, pin))
                if fake.login_error is not None:
                    raise FakeToken.PyKCS11Error(fake.login_error)

            def sign(self, key, digest, mechanism):
                self._step("sign")
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import utils
                der = fake.key.sign(digest, _ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s_ = utils.decode_dss_signature(der)
                return list(r.to_bytes(32, "big") + s_.to_bytes(32, "big"))

            def logout(self):
                pass

            def closeSession(self):
                pass

        class Lib:
            def load(self, module):
                pass

            def getSlotList(self, tokenPresent=True):
                fake.calls.append("slots")
                return sorted(fake.serials)

            def getTokenInfo(self, slot):
                fake.calls.append("token")
                info = Info(fake.serials[slot])
                info.label = fake.labels.get(slot, "")
                return info

            def openSession(self, slot):
                fake.calls.append("open")
                if fake.swap_at == "open":
                    fake.serials[slot] = "SWAPPED"
                return Session(slot)
        self.PyKCS11Lib = Lib
        self.Mechanism = lambda mechanism: mechanism


class TokenChosenInItsSession(unittest.TestCase):
    """#262 (regalia-kms-d9, decided by regalia-kms-24): the PIN reaches only the token whose serial was
    read in the session that logs in. A swap at every step between finding the token and signing."""

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.hazmat.primitives import serialization as _s
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(self.d + "/credentials")
        with open(self.d + "/credentials/pin", "w") as f:
            f.write("648219\n")
        self.fake = FakeToken({0: "DENK0404144", 1: "OTHERCARD"}, b"")
        self.fake.point = b"\x04\x41" + self.fake.key.public_key().public_bytes(_s.Encoding.X962, _s.PublicFormat.UncompressedPoint)

    def signer(self):
        return p11sign.Pkcs11Signer("module.so", "DENK0404144", "51", "pin", credentials=self.d + "/credentials", pkcs11=self.fake)

    def test_it_signs_with_the_token_of_its_serial(self):
        signer = self.signer()
        m.verify_revocation("ecdsa-p256", signer.public(), b"m", signer.sign(b"m").hex(), "test")
        self.assertEqual(self.fake.logins, [(0, "648219")])

    def test_a_token_swapped_before_the_session_s_own_check_never_gets_the_pin(self):
        signer = self.signer()
        self.fake.swap_at, self.fake.logins = "open", []
        with self.assertRaises(m.Refused) as caught:
            signer.sign(b"m")
        self.assertIn("refused before the PIN", str(caught.exception))
        self.assertEqual(self.fake.logins, [])

    def test_a_token_removed_after_the_check_ends_the_session_and_nothing_is_signed(self):
        signer = self.signer()
        for step in ("info", "login"):
            with self.subTest(step):
                self.fake.serials[0], self.fake.removed, self.fake.swap_at, self.fake.logins = "DENK0404144", False, step, []
                with self.assertRaises((m.Refused, RuntimeError)):
                    signer.sign(b"m")
                self.assertEqual(self.fake.logins, [])

    def test_a_serial_that_changed_while_it_signed_is_refused(self):
        signer = self.signer()
        self.fake.calls = []
        original = self.fake.serials.copy()
        # the token answers the signature, then reads as another serial: refused, no signature returned
        orig_lib_info = signer.lib.getTokenInfo

        def info_after_sign(slot):
            if "sign" in self.fake.calls:
                self.fake.serials[slot] = "SWAPPED"
            return orig_lib_info(slot)
        signer.lib.getTokenInfo = info_after_sign
        with self.assertRaises(m.Refused) as caught:
            signer.sign(b"m")
        self.assertIn("changed while it signed", str(caught.exception))
        self.fake.serials.update(original)

    def test_no_token_or_two_tokens_of_the_serial_are_refused_before_any_session(self):
        self.fake.serials = {0: "OTHERCARD"}
        with self.assertRaises(m.Refused):
            self.signer()
        self.fake.serials = {0: "DENK0404144", 1: "DENK0404144"}
        self.fake.calls = []
        with self.assertRaises(m.Refused) as caught:
            self.signer()
        self.assertIn("more than one", str(caught.exception))
        self.assertNotIn("open", self.fake.calls)


class PinLatch(unittest.TestCase):
    """#262 (regalia-kms-d9, decided by regalia-kms-24): a PIN the token refuses is never presented again,
    across beats and restarts, and the token's last tries are left for a human."""

    def setUp(self):
        from cryptography.hazmat.primitives import serialization as _s
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(self.d + "/credentials")
        with open(self.d + "/credentials/pin", "w") as f:
            f.write("648219\n")
        self.fake = FakeToken({0: "DENK0404144"}, b"")
        self.fake.point = b"\x04\x41" + self.fake.key.public_key().public_bytes(_s.Encoding.X962, _s.PublicFormat.UncompressedPoint)
        self.latch = self.d + "/pin-latch.json"

    def signer(self):
        return p11sign.Pkcs11Signer("module.so", "DENK0404144", "51", "pin", credentials=self.d + "/credentials", pkcs11=self.fake,
                                      latch_path=self.latch)

    def test_a_refused_pin_is_presented_once_across_many_beats_and_a_restart(self):
        for code in ("CKR_PIN_INCORRECT", "CKR_PIN_INVALID", "CKR_PIN_LEN_RANGE", "CKR_PIN_LOCKED"):
            with self.subTest(code):
                if os.path.exists(self.latch):
                    os.unlink(self.latch)
                self.fake.logins, self.fake.login_error = [], getattr(FakeToken, code)
                signer, latched = self.signer(), []
                signer.on_latch = latched.append
                for _ in range(6):
                    with self.assertRaises(m.Refused):
                        signer.sign(b"beat")
                restarted = self.signer()
                with self.assertRaises(m.Refused) as caught:
                    restarted.sign(b"beat")
                self.assertIn("clear-pin-latch", str(caught.exception))
                self.assertEqual((len(self.fake.logins), len(latched)), (1, 1))
                self.assertEqual(json.load(open(self.latch))["reason"], code)
                self.assertEqual(os.stat(self.latch).st_mode & 0o777, 0o600)

    def test_a_token_with_its_tries_running_low_is_not_logged_in_to(self):
        for flag in ("CKF_USER_PIN_COUNT_LOW", "CKF_USER_PIN_FINAL_TRY", "CKF_USER_PIN_LOCKED"):
            with self.subTest(flag):
                self.fake.logins, self.fake.flags = [], getattr(FakeToken, flag)
                with self.assertRaises(m.Refused) as caught:
                    self.signer().sign(b"beat")
                self.assertIn("kept for a human", str(caught.exception))
                self.assertEqual(self.fake.logins, [])
                self.assertFalse(os.path.exists(self.latch))                         # not ours to latch: no PIN was refused

    def test_a_transient_error_does_not_latch(self):
        self.fake.login_error = FakeToken.CKR_DEVICE_REMOVED
        signer = self.signer()
        for _ in range(2):
            with self.assertRaises(FakeToken.PyKCS11Error):
                signer.sign(b"beat")
        self.assertEqual((len(self.fake.logins), signer.latched, os.path.exists(self.latch)), (2, None, False))
        self.fake.login_error = None
        m.verify_revocation("ecdsa-p256", signer.public(), b"beat", signer.sign(b"beat").hex(), "test")

    def test_a_damaged_latch_file_still_latches(self):
        with open(self.latch, "w") as f:
            f.write("{not json")
        with self.assertRaises(m.Refused):
            self.signer().sign(b"beat")
        self.assertEqual(self.fake.logins, [])


if __name__ == "__main__":
    unittest.main()
