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
THIRD_KEY = "rtuvcbde-fghijkln-bcdefghi-jklnrtuv-vvttrrnn-llkkjjii-hhggffee-ddccbbcc"
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
        # REGALIA_TEST_FAIL: command-line fragments separated by "|"; a call containing one exits 1
        # without reaching cryptsetup. REGALIA_TEST_SIGNAL: "<fragment>" sends the script TERM at a
        # call containing it and fails the call. REGALIA_TEST_SIGNAL_AFTER: "<SIG>:<fragment>" runs
        # the real call, THEN signals the script (the call succeeded: where a half-done state lives).
        # REGALIA_TEST_SIGNAL_AT: "<SIG>:<fragment>" signals the script and then runs the real call.
        # REGALIA_TEST_KILL: KILL at a call. Each of the last three may list several with "|".
        shim = os.path.join(self.bin, "cryptsetup")
        with open(shim, "w", encoding="ascii") as f:
            f.write('#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\nline=" $* "\n'
                    'IFS="|" read -r -a at <<< "${REGALIA_TEST_SIGNAL_AT:-}"\n'
                    'for item in "${at[@]}"; do [ -n "$item" ] && [[ "$line" == *" ${item#*:} "* ]] && kill -"${item%%%%:*}" "$PPID"; done\n'
                    'IFS="|" read -r -a fragments <<< "${REGALIA_TEST_FAIL:-}"\n'
                    'for fragment in "${fragments[@]}"; do [ -n "$fragment" ] && [[ "$line" == *" $fragment "* ]] && exit 1; done\n'
                    '[ -n "${REGALIA_TEST_SIGNAL:-}" ] && [[ "$line" == *" $REGALIA_TEST_SIGNAL "* ]] && { kill -TERM "$PPID"; exit 1; }\n'
                    '[ -n "${REGALIA_TEST_KILL:-}" ] && [[ "$line" == *" $REGALIA_TEST_KILL "* ]] && { kill -KILL "$PPID"; exit 1; }\n'
                    '"%s" "$@"; rc=$?\n'
                    'IFS="|" read -r -a after <<< "${REGALIA_TEST_SIGNAL_AFTER:-}"\n'
                    'for item in "${after[@]}"; do [ -n "$item" ] && [[ "$line" == *" ${item#*:} "* ]] && kill -"${item%%%%:*}" "$PPID"; done\n'
                    'exit "$rc"\n' % (self.argv_log, CRYPTSETUP))
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

    def env(self, fail_subcommand="", signal="", kill="", signal_after="", signal_at=""):
        return dict(os.environ, PATH=self.bin + os.pathsep + PATH, REGALIA_TEST_FAIL=fail_subcommand, REGALIA_TEST_SIGNAL=signal,
                    REGALIA_TEST_KILL=kill, REGALIA_TEST_SIGNAL_AFTER=signal_after, REGALIA_TEST_SIGNAL_AT=signal_at)

    def run_script(self, mode, *lines, **faults):
        env = self.env(**faults)
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
            "a passphrase that does not open the volume": (("not the passphrase", KEY), "that passphrase does not open"),
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
        env = dict(os.environ, PATH=self.bin + os.pathsep + PATH, REGALIA_TEST_FAIL="token import")
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
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="--test-passphrase --key-slot 1")
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
            "a used key that is not this host's": ((THIRD_KEY, NEW_KEY), "does not open the recovery keyslot"),
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

    def tokens(self):
        return {i: (t["type"], t["keyslots"]) for i, t in self.header()["tokens"].items()}

    def generations(self):
        return {t["keyslots"][0]: t.get("regalia_generation") for t in self.header()["tokens"].values() if t["keyslots"]}

    def interrupted(self, mode, lines, close_stderr=False, **faults):
        """Run the script with faults that signal it; stderr may be a pipe whose reader has gone."""
        with subprocess.Popen(["bash", SCRIPT, "--" + mode, self.img], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, text=True, env=self.env(**faults)) as proc:
            if close_stderr:
                proc.stderr.close()
            proc.stdin.write("".join(l + "\n" for l in lines))
            proc.stdin.close()
            try:
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                self.fail("the script did not return")
            return proc.returncode, ("" if close_stderr else proc.stderr.read())

    def test_the_script_does_not_say_removed_when_its_own_removal_failed(self):
        """undo is the script's promise that a failed run changed nothing. It is checked against the
        header, and when the keyslot is still there the operator is told that the key just typed
        opens the disk, with the commands that remove it."""
        before = self.header()
        # The token cannot be written AND the keyslot cannot be taken back (a header that stopped
        # being writable after the key was added).
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="token import|luksKillSlot")
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("removed again", done.stderr)
        self.assertNotIn("Nothing was changed", done.stderr)
        self.assertIn("keyslot 1 of %s COULD NOT BE REMOVED and holds the key just typed" % self.img, done.stderr)
        self.assertIn("cryptsetup luksKillSlot %s 1" % self.img, done.stderr)
        self.assertTrue(self.opens(KEY), "the premise: the key is in the header, unlabelled")
        self.assertEqual(self.tokens(), {})
        # ... and the next --enrol does not enrol another key beside it: a keyslot no token names
        # that the typed passphrase does not open is refused.
        again = self.run_script("enrol", INSTALLER, NEW_KEY)
        self.assertEqual(again.returncode, 1)
        self.assertIn("keyslot 1 is a passphrase no token names, and it is not the one you typed", again.stderr)
        self.assertFalse(self.opens(NEW_KEY))
        self.cs("luksKillSlot", "--batch-mode", self.img, "1")
        self.assertEqual(self.header(), before)
        # The proof fails, the keyslot IS removed, and only the token removal fails: the message says
        # the keyslot is gone and which token is left; the next --enrol sweeps the empty token.
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="--test-passphrase --key-slot 1|token remove")
        self.assertEqual(done.returncode, 1)
        self.assertIn("an empty recovery token remains", done.stderr)
        self.assertIn("the empty token named above is all that is left", done.stderr)
        self.assertNotIn("Nothing was changed", done.stderr, "an empty token was left, and the run said nothing was changed")
        self.assertFalse(self.opens(KEY))
        self.assertEqual(self.tokens(), {"0": ("systemd-recovery", [])})
        self.assertEqual(self.run_script("enrol", INSTALLER, KEY).returncode, 0)
        self.assertEqual(sorted(k for _, k in self.tokens().values()), [["1"]], "the empty token was not swept")

    def test_replace_takes_back_its_new_keyslot_or_says_it_could_not(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        slot = next(t["keyslots"][0] for t in self.header()["tokens"].values())
        # The new keyslot does not prove, and cannot be removed: the new key opens the disk and the
        # script says so. It must not strip the new keyslot's token and call it "removed".
        done = self.run_script("replace", KEY, NEW_KEY, fail_subcommand="--test-passphrase --key-slot 0|luksKillSlot --batch-mode")
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("was removed", done.stderr)
        self.assertIn("COULD NOT BE REMOVED", done.stderr)
        self.assertTrue(self.opens(NEW_KEY) and self.opens(KEY))
        self.assertEqual(sorted(k for _, k in self.tokens().values()), [["0"], [slot]], "the stuck keyslot lost its token")

    def test_a_new_key_is_proven_the_way_a_boot_prompt_tries_it(self):
        """The new keyslot must open when it is named AND when no keyslot is named. If the second
        fails, the used key is not destroyed for a key that a console could not use."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        before = self.header()
        # only the open that names no keyslot fails ("--test-passphrase --key-file …")
        done = self.run_script("replace", KEY, NEW_KEY, fail_subcommand="--test-passphrase --key-file")
        self.assertEqual(done.returncode, 1)
        self.assertIn("did not open with the new key (the used key is still enrolled), and the keyslot was removed again. Nothing was changed", done.stderr)
        self.assertEqual(self.header(), before)
        self.assertTrue(self.opens(KEY))
        self.assertFalse(self.opens(NEW_KEY))

    def test_a_replace_that_stopped_half_way_is_finished_by_running_it_again(self):
        """Between adding the new keyslot and destroying the used one, BOTH keys open the disk. A
        failure or a kill there must not leave a state no mode of this script will touch."""
        for name, how in {"the used keyslot could not be destroyed": {"fail_subcommand": "luksKillSlot --key-file"},
                          "the script was killed at that step": {"kill": "luksKillSlot --key-file"}}.items():
            with self.subTest(name=name):
                self.setUp()
                self.enrolled()
                self.cs("luksKillSlot", "--batch-mode", self.img, "0")
                done = self.run_script("replace", KEY, NEW_KEY, **how)
                self.assertNotEqual(done.returncode, 0)
                if "fail_subcommand" in how:
                    self.assertIn("Run --replace again with the same two keys to finish", done.stderr)
                    self.assertIn("cryptsetup token remove --token-id", done.stderr)
                self.assertTrue(self.opens(KEY) and self.opens(NEW_KEY), "the premise: both keys open the disk")
                status = self.run_script("status")
                self.assertEqual(status.returncode, 1)
                self.assertIn("a --replace that did not finish", status.stderr)
                self.assertIn("a --replace that did not finish", self.run_script("check", NEW_KEY).stderr)
                # Not just any two keys finish it: the pair must be the used key of one and the new
                # key of the other.
                for wrong in ((THIRD_KEY, NEW_KEY), (KEY, THIRD_KEY)):
                    refused = self.run_script("replace", *wrong)
                    self.assertEqual(refused.returncode, 1)
                    self.assertIn("these are not the used key of keyslot", refused.stderr)
                # THE KEYS TYPED IN THE WRONG ORDER. Without a record of which keyslot is new, this
                # would destroy the NEW key and keep the one that was seen, and report success.
                header = self.header()
                swapped = self.run_script("replace", NEW_KEY, KEY)
                self.assertEqual(swapped.returncode, 1)
                self.assertIn("typed in the wrong order", swapped.stderr)
                self.assertEqual(self.header(), header)
                done = self.run_script("replace", KEY, NEW_KEY)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("an unfinished --replace was completed", done.stderr)
                self.assertFalse(self.opens(KEY), "the used key still opens the disk")
                self.assertTrue(self.opens(NEW_KEY))
                ok, why = host_probe.recovery_keyslots(self.header())
                self.assertTrue(ok, why)
                self.assertEqual(self.run_script("status").returncode, 0)
                self.assertEqual(len(self.tokens()), 1)

    def test_a_signal_while_the_new_keyslot_is_unproven_takes_it_back(self):
        before = self.header()
        done = self.run_script("enrol", INSTALLER, KEY, signal="token import")
        self.assertEqual(done.returncode, 130)
        self.assertIn("interrupted: keyslot 1, added by this run, was taken back; nothing was changed", done.stderr)
        self.assertEqual(self.header(), before)
        self.assertFalse(self.opens(KEY))
        # A kill cannot be caught: the key stays, as a keyslot no token names. The next --enrol
        # refuses to work beside it (above), and --status does not pass.
        done = self.run_script("enrol", INSTALLER, KEY, kill="token import")
        self.assertEqual(done.returncode, -9)
        self.assertTrue(self.opens(KEY))
        self.assertEqual(self.run_script("status").returncode, 1)
        self.assertIn("it is not the one you typed", self.run_script("enrol", INSTALLER, NEW_KEY).stderr)

    def test_a_keyslot_removed_by_hand_leaves_a_host_that_can_be_commissioned_again(self):
        """The documented revocation was 'kill the keyslot'. cryptsetup then leaves the recovery token
        behind, naming nothing: --status says so, and enrolling a new key gives a header the probe
        accepts (one recovery key, not 'two tokens')."""
        self.enrolled()
        slot = next(t["keyslots"][0] for t in self.header()["tokens"].values())
        self.cs("luksKillSlot", "--batch-mode", self.img, slot)
        self.assertEqual(self.tokens(), {"0": ("systemd-recovery", [])})
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1)
        self.assertIn("0 recovery keyslots", status.stderr)
        self.assertEqual(self.run_script("enrol", INSTALLER, NEW_KEY).returncode, 0)
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        ok, why = host_probe.recovery_keyslots(self.header())
        self.assertTrue(ok, why)
        self.assertEqual(self.run_script("status").returncode, 0)

    def test_a_keyslot_a_boot_prompt_would_skip_does_not_pass_check(self):
        self.enrolled()
        slot = next(t["keyslots"][0] for t in self.header()["tokens"].values())
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.cs("config", "--priority", "ignore", "--key-slot", slot, self.img)
        self.assertTrue(self.opens(KEY, slot))
        self.assertFalse(self.opens(KEY), "the premise: with no keyslot named, an ignored keyslot is not tried")
        done = self.run_script("check", KEY)
        self.assertEqual(done.returncode, 1)
        self.assertIn("priority 'ignore': a boot prompt would not try it", done.stderr)
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1, "--status passed a recovery keyslot a boot prompt skips")
        self.assertIn("priority 'ignore'", status.stderr)
        # ... and such a used keyslot is named as the reason a --replace cannot start, instead of
        # "does the first value open this volume?"
        self.assertIn("priority 'ignore', so the used key cannot authorise", self.run_script("replace", KEY, NEW_KEY).stderr)
        self.assertIn("priority 'ignore'", host_probe.recovery_keyslots(self.header())[1])

    def test_an_orphan_token_alone_is_reported_by_status(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], input='{"type":"systemd-recovery","keyslots":[]}',
                       capture_output=True, text=True, check=True, timeout=60)
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1)
        self.assertIn("is a recovery token that names no keyslot", status.stderr)
        self.assertIn("cryptsetup token remove --token-id", status.stderr)

    def test_signals_cannot_cut_the_rollback_short(self):
        """The undo runs to its end whatever arrives while it runs: a second signal, each of the three
        signals, and a standard error whose reader has gone (`… 2>&1 | tee log`, then Ctrl-C)."""
        before = self.header()
        for name, run in {
            "TERM after the token was written": dict(signal_after="TERM:token import"),
            "INT": dict(signal_after="INT:token import"),
            "HUP": dict(signal_after="HUP:token import"),
            "a second signal while the keyslot is being removed": dict(signal_after="TERM:token import", signal_at="TERM:luksKillSlot --batch-mode"),
            "a signal with standard error closed": dict(signal_after="INT:token import", close_stderr=True),
            "a signal right after the keyslot was added, before its token": dict(signal_after="TERM:luksAddKey"),
        }.items():
            with self.subTest(name=name):
                code, stderr = self.interrupted("enrol", [INSTALLER, KEY], **run)
                self.assertEqual(code, 130, stderr)
                self.assertEqual(self.header(), before, "%s: the header was left changed" % name)
                self.assertFalse(self.opens(KEY), "%s: the key just typed still opens the disk" % name)
                if not run.get("close_stderr"):
                    self.assertIn("was taken back; nothing was changed", stderr)
        # Before any keyslot exists, the message does not claim a removal.
        code, stderr = self.interrupted("enrol", [INSTALLER, KEY], signal_at="TERM:luksAddKey", fail_subcommand="luksAddKey")
        self.assertEqual(code, 130)
        self.assertIn("interrupted before a keyslot was added; nothing was changed", stderr)
        self.assertEqual(self.header(), before)

    def test_a_signal_while_the_used_keyslot_is_destroyed_never_costs_the_new_key(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        for name, fault in {"before the used keyslot is destroyed": dict(signal_at="TERM:luksKillSlot --key-file", fail_subcommand="luksKillSlot --key-file"),
                            "after it is destroyed": dict(signal_after="TERM:luksKillSlot --key-file")}.items():
            with self.subTest(name=name):
                used, new = (KEY, NEW_KEY) if self.opens(KEY) else (NEW_KEY, THIRD_KEY)
                code, stderr = self.interrupted("replace", [used, new], **fault)
                self.assertEqual(code, 130, stderr)
                self.assertIn("interrupted while the USED keyslot was being destroyed: the new key is enrolled", stderr)
                self.assertTrue(self.opens(new), "the NEW key was lost to a signal")
                if self.opens(used):
                    self.assertEqual(self.run_script("replace", used, new).returncode, 0)
                else:
                    self.run_script("status")   # an empty token may be left; a later run sweeps it
                self.assertTrue(self.opens(new))
                self.assertFalse(self.opens(used))

    def test_a_replace_killed_before_it_marked_its_keyslot_is_picked_up_not_duplicated(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        done = self.run_script("replace", KEY, NEW_KEY, kill="token import")
        self.assertEqual(done.returncode, -9)
        self.assertEqual(len(self.header()["keyslots"]), 2, "the premise: the new key is in a keyslot no token names")
        self.assertTrue(self.opens(NEW_KEY))
        # The same new key again: that keyslot is marked, not a second one added.
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("already holds the new key", done.stderr)
        self.assertEqual(len(self.header()["keyslots"]), 1)
        self.assertTrue(self.opens(NEW_KEY))
        self.assertFalse(self.opens(KEY))
        self.assertEqual(self.run_script("status").returncode, 0)
        # Killed again, and this time ANOTHER new key is brought: the replace is done, and the operator
        # is told that the abandoned key still opens the disk.
        self.assertEqual(self.run_script("replace", NEW_KEY, KEY, kill="token import").returncode, -9)
        done = self.run_script("replace", NEW_KEY, THIRD_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("WARNING: keyslot", done.stderr)
        self.assertIn("It still opens the disk", done.stderr)
        self.assertTrue(self.opens(KEY), "the premise: the abandoned key is still there")
        self.assertEqual(self.run_script("status").returncode, 1)

    def test_the_new_keyslot_is_recorded_as_newer_and_a_hand_made_pair_is_not_guessed(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(list(self.generations().values()), [1])
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY).returncode, 0)
        self.assertEqual(list(self.generations().values()), [2])
        # the unfinished state, in BOTH keyslot orders (the new key in the lower and in the higher slot)
        for used, new in ((NEW_KEY, THIRD_KEY), (THIRD_KEY, KEY)):
            self.assertNotEqual(self.run_script("replace", used, new, fail_subcommand="luksKillSlot --key-file").returncode, 0)
            generations = self.generations()
            newest = max(generations, key=generations.get)
            self.assertTrue(self.opens(new, newest), "the higher generation is not the new key's keyslot")
            self.assertEqual(self.run_script("replace", new, used).returncode, 1)
            # the new key must also open as a boot prompt tries it
            refused = self.run_script("replace", used, new, fail_subcommand="--test-passphrase --key-file")
            self.assertEqual(refused.returncode, 1)
            done = self.run_script("replace", used, new)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(self.opens(new) and not self.opens(used))
        # Two recovery keyslots that no --replace made (equal generations): refused, not guessed.
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(KEY), "--new-key-slot", "7", self.img, self.secret(NEW_KEY))
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["7"],"regalia_generation":%d}' % max(self.generations().values()))
        header = self.header()
        refused = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("do not say which is the newer", refused.stderr)
        self.assertEqual(self.header(), header)

    def test_one_token_naming_two_keyslots_is_not_treated_as_an_unfinished_replace(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        slot = next(iter(self.generations()))
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(KEY), "--new-key-slot", "5", self.img, self.secret(NEW_KEY))
        token = next(iter(self.header()["tokens"]))
        self.cs("token", "remove", "--token-id", token, self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s","5"]}' % slot)
        header = self.header()
        refused = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("one recovery token names both keyslots", refused.stderr)
        self.assertEqual(self.header(), header)

    def test_a_module_in_the_working_directory_is_not_what_reads_the_header(self):
        """The script is run by root from whatever directory root is in. Its Python runs isolated, so a
        json.py lying there is not imported."""
        planted = os.path.join(self.dir, "planted")
        os.mkdir(planted)
        marker = os.path.join(self.dir, "imported")
        with open(os.path.join(planted, "json.py"), "w", encoding="ascii") as f:
            f.write('open(%r, "w").close()\nraise SystemExit(0)\n' % marker)
        done = subprocess.run(["bash", SCRIPT, "--status", self.img], cwd=planted, capture_output=True, text=True,
                              env=dict(os.environ, PATH=PATH, PYTHONPATH=planted), timeout=60)
        self.assertFalse(os.path.exists(marker), "the planted json.py was imported")
        self.assertIn("keyslot 0", done.stdout)


if __name__ == "__main__":
    unittest.main()
