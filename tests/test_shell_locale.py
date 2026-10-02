"""The shell validators mean ASCII, whatever locale the operator's shell is in.

In a UTF-8 locale bash matches a bracket range by the locale's collation, so `[0-9]` takes full-width
and Arabic-Indic digits and `[a-z0-9]` takes accented letters (measured: bash 5.2, glibc 2.41,
en_US.UTF-8). deploy/seal-hsm-pin.sh accepted such look-alikes in --serial, --yubikey, --pcrs, --id and
--import-handle until it pinned LC_ALL=C. These tests run the real script under en_US.UTF-8, as an
operator's sudo would, and every script that validates input with a range must pin its locale.

Every case stops at an argument check, before the script needs root, a TPM or a card.
"""
import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEAL = ROOT / "deploy" / "seal-hsm-pin.sh"
LOCALE = "en_US.UTF-8"
# A machine without that locale can only skip, and a skip is a pass; CI generates it and sets this.
EXPECT = "REGALIA_EXPECT_UTF8_LOCALE"
# Scripts whose bracket ranges check what an operator or a caller supplies.
VALIDATING = ("deploy/seal-hsm-pin.sh", "deploy/baremetal/tpm-lockout.sh", "e2e/cosmos-hardware-sign-verify.sh")


def locale_available():
    try:
        out = subprocess.run(["locale", "-a"], capture_output=True, text=True, errors="replace").stdout
    except OSError:
        return False
    return any(re.fullmatch(r"en_US\.utf-?8", line.strip(), re.I) for line in out.splitlines())


def seal(*args, locale=LOCALE):
    env = dict(os.environ, LC_ALL=locale, LANG=locale)
    done = subprocess.run(["bash", str(SEAL), *args], capture_output=True, text=True, env=env, errors="replace")
    return done.returncode, done.stderr.strip().splitlines()[-1] if done.stderr.strip() else ""


class ShellLocale(unittest.TestCase):
    def setUp(self):
        if not locale_available():
            if os.environ.get(EXPECT) == "1":
                self.fail(f"{EXPECT} is set but {LOCALE} is not installed: the check that was expected to run did not")
            self.skipTest(f"{LOCALE} is not installed (locale-gen {LOCALE}); set {EXPECT}=1 to require it")

    def test_the_fixture_locale_really_widens_a_range(self):
        """The instrument: in this locale bash's [0-9] does take a full-width digit. Without this, the
        refusals below could pass on a machine whose locale never had the problem."""
        script = '[[ "７" =~ ^[0-9]$ ]] && echo widened || echo ascii'
        env = dict(os.environ, LC_ALL=LOCALE, LANG=LOCALE)
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(out, "widened", "this locale does not reproduce the range widening the tests guard against")
        env = dict(os.environ, LC_ALL="C", LANG="C")
        out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env).stdout.strip()
        self.assertEqual(out, "ascii")

    def test_seal_hsm_pin_refuses_look_alikes_under_a_utf8_locale(self):
        ok = ("--id", "hsm-a", "--serial", "DENK0404144", "--pcrs", "7")
        cases = {
            "an accented letter in --id": (("--id", "hsmé", "--serial", "DENK0404144", "--pcrs", "7"), "--id must be lower-case"),
            "full-width digits in --serial": (("--id", "hsm-a", "--serial", "DENK０４０４１４４", "--pcrs", "7"), "--serial must be a Nitrokey"),
            "full-width digits in --yubikey": (("--id", "yk-a", "--yubikey", "３６３４５４７１", "--pcrs", "7"), "--yubikey must be a YubiKey serial"),
            "a full-width PCR": (("--id", "hsm-a", "--serial", "DENK0404144", "--pcrs", "７"), "--pcrs is required"),
            # The one that matters most: PCR 11 written so that the refusal of 10 and 11 does not see it.
            "PCR 11 in full-width digits": (("--id", "hsm-a", "--serial", "DENK0404144", "--pcrs", "7+１１"), "--pcrs is required"),
            "Arabic-Indic digits in --retries": (ok + ("--retries", "٩"), "--retries is the card's configured"),
            "full-width digits in --import-handle": (("--init-import-key", "--import-handle", "0x81００0101"), "--import-handle must be a persistent handle"),
        }
        for label, (args, refusal) in cases.items():
            with self.subTest(label):
                rc, last = seal(*args)
                self.assertNotEqual(rc, 0)
                self.assertIn(refusal, last, f"{label}: the validator let it through; the script went on to: {last}")

    def test_plain_ascii_arguments_still_pass_the_validators(self):
        """The control: the same arguments in ASCII get past every argument check, to the first thing
        that needs the machine (root, as this test does not run as root, or the TPM)."""
        rc, last = seal("--id", "hsm-a", "--serial", "DENK0404144", "--pcrs", "7", "--retries", "9")
        self.assertNotEqual(rc, 0)
        self.assertRegex(last, r"run as root|no usable TPM2|is required")
        self.assertNotRegex(last, r"must be|--pcrs is required|--retries is")

    def test_every_script_that_validates_with_a_range_pins_its_locale(self):
        """Either the whole locale (LC_ALL=C), or the collation alone with LC_ALL moved out of the way:
        LC_ALL overrides LC_COLLATE, so LC_COLLATE=C on its own changes nothing for an operator whose
        shell sets LC_ALL."""
        for name in VALIDATING:
            with self.subTest(name):
                text = (ROOT / name).read_text(encoding="utf-8")
                whole = re.search(r"(?m)^export LC_ALL=C$", text)
                collation = re.search(r"(?m)^if \[ -n \"\$\{LC_ALL:-\}\" \]; then export LANG=\"\$LC_ALL\" LC_CTYPE=\"\$LC_ALL\"; unset LC_ALL; fi\nexport LC_COLLATE=C$", text)
                pin = whole or collation
                self.assertIsNotNone(pin, f"{name} validates input with bracket ranges and must pin LC_ALL=C, or LC_COLLATE=C with LC_ALL unset")
                # ...and before the first pattern it relies on.
                self.assertIsNotNone(re.search(r"=~|case .* in \*\[", text[pin.end():]), f"{name}: no range check after the locale is pinned")
                self.assertNotRegex(text[:pin.start()].split("\nset -", 1)[-1], r"=~", f"{name} matches a pattern before pinning the locale")

    def test_the_cosmos_script_keeps_counting_pin_characters_and_refuses_look_alikes(self):
        """Its checks run before it needs a token: a slot in full-width digits and a non-ASCII object id
        are refused, and a PIN of three two-byte letters is still shorter than six CHARACTERS (under
        LC_ALL=C bash would count six bytes and let it through)."""
        script = ROOT / "e2e" / "cosmos-hardware-sign-verify.sh"

        def run(**values):
            env = dict(os.environ, LC_ALL=LOCALE, LANG=LOCALE, REGALIA_COSMOS_PKCS11_MODULE=str(script),
                       REGALIA_COSMOS_PKCS11_SLOT="0", REGALIA_COSMOS_PKCS11_PIN="123456", REGALIA_COSMOS_PKCS11_OBJECT_ID="01")
            env.update({"REGALIA_COSMOS_PKCS11_" + k: v for k, v in values.items()})
            done = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, errors="replace")
            return done.returncode, (done.stderr.strip().splitlines() or [""])[-1]
        cases = {"a full-width slot": (dict(SLOT="７"), "slot must be a decimal number"),
                 "a full-width object id": (dict(OBJECT_ID="０１"), "must be hexadecimal"),
                 "an accented object id": (dict(OBJECT_ID="é1"), "must be hexadecimal"),
                 "a three-character PIN of two-byte letters": (dict(PIN="ééé"), "shorter than six characters")}
        for label, (values, refusal) in cases.items():
            with self.subTest(label):
                rc, last = run(**values)
                self.assertEqual(rc, 2, last)
                self.assertIn(refusal, last)
        # An inherited LC_CTYPE that LC_ALL was overriding must not come back when LC_ALL is moved away:
        # with LC_CTYPE=C bash would count the three letters as six bytes.
        env = dict(os.environ, LC_ALL=LOCALE, LANG=LOCALE, LC_CTYPE="C", REGALIA_COSMOS_PKCS11_MODULE=str(script),
                   REGALIA_COSMOS_PKCS11_SLOT="0", REGALIA_COSMOS_PKCS11_PIN="ééé", REGALIA_COSMOS_PKCS11_OBJECT_ID="01")
        done = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env, errors="replace")
        self.assertEqual(done.returncode, 2)
        self.assertIn("shorter than six characters", done.stderr)
        # The control: plain ASCII values get past all of them, to the first thing that needs a tool or a token.
        rc, last = run()
        self.assertNotRegex(last, r"decimal number|hexadecimal|shorter than six")


if __name__ == "__main__":
    unittest.main()
