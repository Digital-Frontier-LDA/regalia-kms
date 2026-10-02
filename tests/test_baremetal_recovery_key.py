"""deploy/baremetal/recovery-key.sh (#77, Phase 17): the KMS host's disk recovery key, a LUKS2 keyslot of
its own that opens the volume with no TPM and no peer.

Real cryptsetup on a LUKS2 header in a plain file: no root, no device-mapper. `cryptsetup open
--test-passphrase` is the volume's own answer to "does this open a keyslot"; the root-only half (a loop
device, a filesystem, a mount) is e2e/luks-recovery-key.sh. Without cryptsetup the class skips, unless
REGALIA_EXPECT_CRYPTSETUP=1 says this environment is the one that must run it."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from deploy.baremetal import host_probe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "deploy", "baremetal", "recovery-key.sh")
PATH = os.environ.get("PATH", "") + os.pathsep + "/usr/sbin" + os.pathsep + "/sbin"
CRYPTSETUP = shutil.which("cryptsetup", path=PATH)
INSTALLER = "the installer's passphrase"
# Two recovery keys in systemd's format. Test values: they open nothing but the images made here.
KEY = "cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"
NEW_KEY = "vvuuttrr-nnllkkjj-iihhggff-eeddccbb-cbdefghi-jklnrtuv-bcdefghi-jklnrtuc"
FAST = ["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"]


@unittest.skipUnless(CRYPTSETUP or os.environ.get("REGALIA_EXPECT_CRYPTSETUP") == "1", "cryptsetup is not installed")
class RecoveryKey(unittest.TestCase):
    def setUp(self):
        self.assertTrue(CRYPTSETUP, "REGALIA_EXPECT_CRYPTSETUP=1 and cryptsetup is not on PATH")
        self.dir = tempfile.mkdtemp(prefix="regalia-recovery-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.img = os.path.join(self.dir, "disk.img")
        with open(self.img, "wb") as f:
            f.truncate(32 << 20)
        self.cs("luksFormat", "--type", "luks2", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), self.img)
        # A shim in front of cryptsetup: it records every command line it is given, and can be told to
        # fail one subcommand. The script under test finds it first on PATH.
        self.bin = os.path.join(self.dir, "bin")
        os.mkdir(self.bin)
        self.argv_log = os.path.join(self.dir, "argv.log")
        shim = os.path.join(self.bin, "cryptsetup")
        with open(shim, "w", encoding="ascii") as f:
            f.write('#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n'
                    'case " $* " in *" $REGALIA_TEST_FAIL_SUBCOMMAND "*) [ -n "$REGALIA_TEST_FAIL_SUBCOMMAND" ] && exit 1;; esac\n'
                    'exec "%s" "$@"\n' % (self.argv_log, CRYPTSETUP))
        os.chmod(shim, os.stat(shim).st_mode | stat.S_IXUSR)

    def secret(self, value):
        path = os.path.join(self.dir, "secret-%d" % len(os.listdir(self.dir)))
        with open(path, "w", encoding="ascii") as f:
            f.write(value)
        return path

    def cs(self, *args, ok=True):
        done = subprocess.run([CRYPTSETUP, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        if ok:
            self.assertEqual(done.returncode, 0, "cryptsetup %s: %s" % (" ".join(args), done.stderr))
        return done

    def run_script(self, mode, *lines, fail_subcommand=""):
        env = dict(os.environ, PATH=self.bin + os.pathsep + PATH, REGALIA_TEST_FAIL_SUBCOMMAND=fail_subcommand)
        return subprocess.run(["bash", SCRIPT, "--" + mode, self.img], input="".join(l + "\n" for l in lines),
                              capture_output=True, text=True, env=env, timeout=120)

    def header(self):
        return json.loads(self.cs("luksDump", "--dump-json-metadata", self.img).stdout)

    def opens(self, value, slot=None):
        """The volume's own answer: does this value open a keyslot (that keyslot)?"""
        args = ["open", "--test-passphrase", "--key-file", self.secret(value)]
        return self.cs(*args, *(["--key-slot", str(slot)] if slot is not None else []), self.img, ok=False).returncode == 0

    def enrolled(self):
        done = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def test_the_recovery_key_becomes_a_keyslot_of_its_own_that_systemd_calls_recovery(self):
        self.assertEqual(self.run_script("status").returncode, 1, "a volume with no recovery keyslot passed --status")
        done = self.enrolled()
        self.assertIn("ENROLLED", done.stderr)
        meta = self.header()
        tokens = list(meta["tokens"].values())
        self.assertEqual([t["type"] for t in tokens], ["systemd-recovery"])
        slot = tokens[0]["keyslots"][0]
        # The script chose the keyslot itself (the lowest free one) and told cryptsetup, so that it
        # knows which keyslot to take back if a later step fails.
        self.assertEqual(slot, "1")
        with open(self.argv_log, encoding="utf-8") as f:
            self.assertIn("--new-key-slot 1", f.read())
        self.assertTrue(self.opens(KEY, slot))
        self.assertFalse(self.opens(KEY, 0), "the recovery key opens the installer's keyslot")
        self.assertFalse(self.opens(INSTALLER, slot), "the installer's passphrase opens the recovery keyslot")
        # systemd's own key-derivation choice for a high-entropy key, so the boot prompt does not wait.
        self.assertEqual(meta["keyslots"][slot]["kdf"]["type"], "pbkdf2")
        enroll = shutil.which("systemd-cryptenroll", path=PATH)
        if enroll:
            listing = subprocess.run([enroll, self.img], capture_output=True, text=True, timeout=60).stdout
            self.assertRegex(listing, r"(?m)^\s*%s\s+recovery\s*$" % slot)
        # While the installer's passphrase is still there, neither --status nor the host probe passes;
        # with it wiped (the last commissioning step), both do. The probe reads the header only.
        self.assertEqual(self.run_script("status").returncode, 1)
        self.assertIn("named by no token", host_probe.recovery_keyslots(meta)[1])
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        status = self.run_script("status")
        self.assertEqual(status.returncode, 0, status.stderr)
        self.assertIn("recovery key", status.stdout)
        ok, why = host_probe.recovery_keyslots(self.header())
        self.assertTrue(ok, why)

    def test_with_every_other_way_in_destroyed_the_recovery_key_alone_opens_the_volume(self):
        # A stand-in for the TPM (or a peer) keyslot: a random key with a token of its own.
        standin = self.secret(os.urandom(32).hex())
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "1", self.img, standin)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], input='{"type":"regalia-test-unlock","keyslots":["1"]}',
                       capture_output=True, text=True, check=True, timeout=60)
        self.enrolled()
        recovery = next(t["keyslots"][0] for t in self.header()["tokens"].values() if t["type"] == "systemd-recovery")
        # The total outage: the installer's passphrase is long gone, and the TPM and peer path is lost.
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.cs("luksKillSlot", "--batch-mode", self.img, "1")
        self.assertEqual(sorted(self.header()["keyslots"]), [recovery])
        self.assertFalse(self.opens(INSTALLER))
        self.assertTrue(self.opens(KEY), "the recovery key alone does not open the volume")
        check = self.run_script("check", KEY)
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn("Nothing was unlocked", check.stderr)

    def test_a_copy_that_is_not_exactly_the_key_opens_nothing(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        typo = KEY[:20] + ("c" if KEY[20] != "c" else "b") + KEY[21:]
        cases = {
            "another host's key": (NEW_KEY, "does NOT open"),
            "one letter wrong": (typo, "does NOT open"),
            "without the dashes": (KEY.replace("-", ""), "wrong grouping"),
            "grouped in fours": ("-".join(KEY.replace("-", "")[i:i + 4] for i in range(0, 64, 4)), "wrong grouping"),
            "with spaces for dashes": (KEY.replace("-", " "), "wrong grouping"),
            "in capitals": (KEY.upper(), "CAPITALS"),
            "one group short": (KEY[:-9], "not a recovery key"),
            "empty": ("", "not a recovery key"),
        }
        for name, (value, reason) in cases.items():
            with self.subTest(name=name):
                # What the DISK says, whatever this script thinks of the format: at a boot prompt there
                # is no script, and each of these is simply a wrong passphrase.
                if value:
                    self.assertFalse(self.opens(value), "%s opened the volume" % name)
                done = self.run_script("check", value)
                self.assertEqual(done.returncode, 1)
                self.assertIn(reason, done.stderr)
        self.assertEqual(self.run_script("check", KEY).returncode, 0)

    def test_enrol_refuses_and_changes_nothing(self):
        before = self.header()
        cases = {
            "a passphrase that does not open the volume": (("not the passphrase", KEY), "refused to add the keyslot"),
            "a key in capitals": ((INSTALLER, KEY.upper()), "CAPITALS"),
            "a key without dashes": ((INSTALLER, KEY.replace("-", "")), "wrong grouping"),
            "the lockout authorization typed here by mistake": ((INSTALLER, "ABCDEFGHJKMNPQRSTUVW"), "not a recovery key"),
            "no passphrase": (("", KEY), "no passphrase given"),
        }
        for name, (lines, reason) in cases.items():
            with self.subTest(name=name):
                done = self.run_script("enrol", *lines)
                self.assertEqual(done.returncode, 1)
                self.assertIn(reason, done.stderr)
                self.assertEqual(self.header(), before, "%s changed the header" % name)
        # The token cannot be written: the keyslot just added is destroyed again, so the key is never
        # left behind as an unlabelled passphrase. The script's own input is an open pipe here, which
        # is exactly when a keyslot removal that read standard input would wait for ever.
        # So the pipe is HELD OPEN here, as a terminal or a wrapper script would hold it: the lines are
        # written and the writing end is not closed until the script has returned.
        env = dict(os.environ, PATH=self.bin + os.pathsep + PATH, REGALIA_TEST_FAIL_SUBCOMMAND="token import")
        with subprocess.Popen(["bash", SCRIPT, "--enrol", self.img], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) as held:
            held.stdin.write(INSTALLER + "\n" + KEY + "\n")
            held.stdin.flush()
            try:
                held.wait(timeout=60)
            except subprocess.TimeoutExpired:
                held.kill()
                self.fail("the script waited on its open standard input while removing the keyslot")
            stderr = held.stderr.read()
        self.assertEqual(held.returncode, 1)
        self.assertIn("removed again", stderr)
        self.assertEqual(self.header(), before)
        self.assertFalse(self.opens(KEY))
        # The header cannot be read: nothing is attempted. (Without errexit, a failed read inside a
        # command substitution would otherwise go unnoticed and the key be added to a keyslot nobody
        # can then identify.)
        with open(self.argv_log, "w", encoding="utf-8"):
            pass
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="luksDump")
        self.assertEqual(done.returncode, 1)
        self.assertIn("cannot read the LUKS2 header", done.stderr)
        with open(self.argv_log, encoding="utf-8") as f:
            self.assertNotIn("luksAddKey", f.read())
        self.assertEqual(self.header(), before)
        # The new keyslot does not open with the key (cryptsetup's own test fails): it is taken back,
        # keyslot and token.
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="--test-passphrase")
        self.assertEqual(done.returncode, 1)
        self.assertIn("was removed again", done.stderr)
        self.assertEqual(self.header(), before)
        # One host, one recovery key.
        self.enrolled()
        again = self.run_script("enrol", INSTALLER, NEW_KEY)
        self.assertEqual(again.returncode, 1)
        self.assertIn("already has a recovery keyslot", again.stderr)
        self.assertFalse(self.opens(NEW_KEY))

    def test_replace_spends_the_used_key(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        before = self.header()
        for name, (lines, reason) in {
            "a used key that is not this host's": ((NEW_KEY, NEW_KEY), "does not open the recovery keyslot"),
            "the same key again": ((KEY, KEY), "the new key is the used key"),
            "a new key in capitals": ((KEY, NEW_KEY.upper()), "CAPITALS"),
        }.items():
            with self.subTest(name=name):
                done = self.run_script("replace", *lines)
                self.assertEqual(done.returncode, 1)
                self.assertIn(reason, done.stderr)
                self.assertEqual(self.header(), before, "%s changed the header" % name)
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("REPLACED", done.stderr)
        self.assertFalse(self.opens(KEY), "the used key still opens the volume")
        self.assertTrue(self.opens(NEW_KEY))
        ok, why = host_probe.recovery_keyslots(self.header())
        self.assertTrue(ok, why)
        self.assertEqual(self.run_script("status").returncode, 0)

    def test_no_secret_reaches_a_command_line(self):
        self.enrolled()
        self.assertEqual(self.run_script("check", KEY).returncode, 0)
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY).returncode, 0)
        with open(self.argv_log, encoding="utf-8") as f:
            argv = f.read()
        self.assertIn("luksAddKey", argv)
        for value in (INSTALLER, KEY, NEW_KEY, KEY[:8], NEW_KEY[:8]):
            self.assertNotIn(value, argv)
        # ... and the script takes no secret as an argument either.
        done = subprocess.run(["bash", SCRIPT, "--check", self.img, KEY], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 1)
        self.assertIn("one device", done.stderr)


if __name__ == "__main__":
    unittest.main()
