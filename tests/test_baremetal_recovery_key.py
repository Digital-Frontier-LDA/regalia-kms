"""deploy/baremetal/recovery-key.sh (#77, Phase 17): the KMS host's disk recovery key, a LUKS2 keyslot of
its own that opens the volume with no TPM and no peer.

Real cryptsetup on a LUKS2 header in a plain file: no root, no device-mapper. `cryptsetup open
--test-passphrase` is the volume's own answer to "does this open a keyslot"; the root-only half (a loop
device, a filesystem, a mount) is e2e/luks-recovery-key.sh. Without cryptsetup the class skips, unless
REGALIA_EXPECT_CRYPTSETUP=1 says this environment is the one that must run it."""
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

from deploy.baremetal import host_probe, trails

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


# trails.py beside a per-test copy of the script (#278) is the REAL one (copied as trails_real.py) behind a
# wrapper that changes only the path: the registry's /var/log/regalia/recovery-key.jsonl is root's, and no
# variable redirects it. While a file called "refuse" is beside it, an append refuses as the real one does when
# it cannot write. Every test that wrote a trail ends by verifying its chain (setUp's cleanup).
STUB_TRAILS = """import os, sys
d = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, d)
import trails_real as trails
real_where = trails.where
trails.where = lambda name, cfg=None: real_where(name, cfg) and os.path.join(d, "trail.jsonl")
if sys.argv[1:2] == ["append"] and os.path.exists(os.path.join(d, "refuse")):
    print("REFUSED: the test's trail refuses", file=sys.stderr)
    sys.exit(1)
sys.exit(trails.main(sys.argv[1:]))
"""


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
        self.tool = os.path.join(self.dir, "tool")
        os.mkdir(self.tool)
        for name in ("recovery-key.sh", "recovery_state.py"):
            shutil.copy(os.path.join(os.path.dirname(SCRIPT), name), self.tool)
        shutil.copy(os.path.join(os.path.dirname(SCRIPT), "trails.py"), os.path.join(self.tool, "trails_real.py"))
        with open(os.path.join(self.tool, "trails.py"), "w", encoding="ascii") as f:
            f.write(STUB_TRAILS)
        self.addCleanup(self.verify_trail)
        self.script = os.path.join(self.tool, "recovery-key.sh")
        # REGALIA_TEST_FAIL: command-line fragments separated by "|"; a call containing one exits 1
        # without reaching cryptsetup. REGALIA_TEST_SIGNAL: "<fragment>" sends the script TERM at a
        # call containing it and fails the call. REGALIA_TEST_SIGNAL_AFTER: "<SIG>:<fragment>" runs
        # the real call, THEN signals the script (the call succeeded: where a half-done state lives).
        # REGALIA_TEST_SIGNAL_AT: "<SIG>:<fragment>" signals the script and then runs the real call.
        # REGALIA_TEST_KILL: KILL at a call. Each of the last three may list several with "|".
        # REGALIA_TEST_ARMED_BY: SIGNAL_AT and FAIL fire only once a call containing this has been made.
        shim = os.path.join(self.bin, "cryptsetup")
        with open(shim, "w", encoding="ascii") as f:
            f.write('#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\nline=" $* "\n'
                    'IFS="|" read -r -a at <<< "${REGALIA_TEST_SIGNAL_AT:-}"\n'
                    'armed=1; [ -z "${REGALIA_TEST_ARMED_BY:-}" ] || grep -qF -- "$REGALIA_TEST_ARMED_BY" "%s" || armed=0\n'
                    'for item in "${at[@]}"; do [ "$armed" = 1 ] && [ -n "$item" ] && [[ "$line" == *" ${item#*:} "* ]] && kill -"${item%%%%:*}" "$PPID"; done\n'
                    'IFS="|" read -r -a fragments <<< "${REGALIA_TEST_FAIL:-}"\n'
                    'for fragment in "${fragments[@]}"; do [ "$armed" = 1 ] && [ -n "$fragment" ] && [[ "$line" == *" $fragment "* ]] && exit 1; done\n'
                    '[ -n "${REGALIA_TEST_SIGNAL:-}" ] && [[ "$line" == *" $REGALIA_TEST_SIGNAL "* ]] && { kill -TERM "$PPID"; exit 1; }\n'
                    '[ -n "${REGALIA_TEST_KILL:-}" ] && [[ "$line" == *" $REGALIA_TEST_KILL "* ]] && { kill -KILL "$PPID"; exit 1; }\n'
                    '"%s" "$@"; rc=$?\n'
                    'IFS="|" read -r -a after <<< "${REGALIA_TEST_SIGNAL_AFTER:-}"\n'
                    'for item in "${after[@]}"; do [ -n "$item" ] && [[ "$line" == *" ${item#*:} "* ]] && kill -"${item%%%%:*}" "$PPID"; done\n'
                    'exit "$rc"\n' % (self.argv_log, self.argv_log, CRYPTSETUP))
        os.chmod(shim, os.stat(shim).st_mode | stat.S_IXUSR)

    def fresh(self):
        """A new image for the next subtest, after removing the last one: setUp() again on its own would
        keep every subtest's 32 MiB image until the test ends, and a full /tmp then fails luksFormat
        ("Device wipe error"), which looked like a flaky signal test under load."""
        self.doCleanups()
        self.setUp()

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

    def env(self, fail_subcommand="", signal="", kill="", signal_after="", signal_at="", armed_by=""):
        return dict(os.environ, PATH=self.bin + os.pathsep + PATH, REGALIA_TEST_FAIL=fail_subcommand, REGALIA_TEST_SIGNAL=signal, REGALIA_TEST_ARMED_BY=armed_by,
                    REGALIA_TEST_KILL=kill, REGALIA_TEST_SIGNAL_AFTER=signal_after, REGALIA_TEST_SIGNAL_AT=signal_at)

    def run_script(self, mode, *lines, **faults):
        env = self.env(**faults)
        return subprocess.run(["bash", self.script, "--" + mode, self.img], input="".join(l + "\n" for l in lines),
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
        # The header cannot be read: nothing is attempted.
        with open(self.argv_log, "w", encoding="utf-8"):
            pass
        done = self.run_script("enrol", INSTALLER, KEY, fail_subcommand="luksDump")
        self.assertEqual(done.returncode, 1)
        self.assertIn("cannot read the LUKS2 header", done.stderr)
        with open(self.argv_log, encoding="utf-8") as f:
            self.assertNotIn("luksAddKey", f.read())
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
        done = subprocess.run(["bash", self.script, "--check", self.img, KEY], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 1)
        self.assertIn("one device", done.stderr)

    def tokens(self):
        return {i: (t["type"], t["keyslots"]) for i, t in self.header()["tokens"].items()}

    def generations(self):
        return {t["keyslots"][0]: t.get("regalia_generation") for t in self.header()["tokens"].values() if t["keyslots"]}

    def run_script_armed(self, mode, *lines, **faults):
        """The arming call must be one of THIS run's: the argv log is shared by every run of a test."""
        if os.path.exists(self.argv_log):
            os.unlink(self.argv_log)
        return subprocess.run(["bash", self.script, "--" + mode, self.img], capture_output=True, text=True, timeout=300,
                              input="".join(l + "\n" for l in lines), env=self.env(**faults))

    def interrupted(self, mode, lines, close_stderr=False, **faults):
        """Run the script with faults that signal it; stderr may be a pipe whose reader has gone."""
        with subprocess.Popen(["bash", self.script, "--" + mode, self.img], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
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

    def test_a_replace_that_stopped_half_way_is_finished_by_running_it_again(self):
        """Between marking the new keyslot and destroying the used one, BOTH keys open the disk."""
        for name, how in {"the used keyslot could not be destroyed": {"fail_subcommand": "luksKillSlot --key-file"},
                          "the script was killed at that step": {"kill": "luksKillSlot --key-file"}}.items():
            with self.subTest(name=name):
                self.fresh()
                self.enrolled()
                self.cs("luksKillSlot", "--batch-mode", self.img, "0")
                done = self.run_script("replace", KEY, NEW_KEY, **how)
                self.assertNotEqual(done.returncode, 0)
                if "fail_subcommand" in how:
                    self.assertIn("Run --replace again with the same two keys", done.stderr)
                    self.assertEqual(self.state(done), "added-unproven")
                self.assertTrue(self.opens(KEY) and self.opens(NEW_KEY), "the premise: both keys open the disk")
                status = self.run_script("status")
                self.assertEqual(status.returncode, 1)
                self.assertEqual(self.state(status), "added-unproven")
                self.assertIn("run --replace again with the used key and the new key, in that order", status.stdout)
                self.assertIn("a --replace that stopped", self.run_script("check", NEW_KEY).stderr)
                # a new key that is not the new keyslot's, or a used key that opens a keyslot other
                # than the used one, is refused
                header = self.header()
                for wrong in ((KEY, THIRD_KEY),):
                    refused = self.run_script("replace", *wrong)
                    self.assertEqual(refused.returncode, 1)
                    self.assertIn("these are not the used key of keyslot", refused.stderr)
                    self.assertEqual(self.header(), header)
                # THE KEYS TYPED IN THE WRONG ORDER: without the header's record of which keyslot is
                # new, this would destroy the NEW key and keep the one that was seen.
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

    def test_a_keyslot_removed_by_hand_leaves_a_host_that_can_be_commissioned_again(self):
        """cryptsetup leaves the recovery token behind a keyslot killed by hand, naming nothing."""
        self.enrolled()
        slot = next(t["keyslots"][0] for t in self.header()["tokens"].values())
        self.cs("luksKillSlot", "--batch-mode", self.img, slot)
        self.assertEqual(self.tokens(), {"0": ("systemd-recovery", [])})
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1)
        self.assertEqual(self.state(status), "orphan-token")
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
        self.assertEqual(self.state(done), "unknown")
        self.assertIn("priority ignore: a boot prompt would not try it", done.stdout)
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1, "--status passed a recovery keyslot a boot prompt skips")
        header = self.header()
        refused = self.run_script("replace", KEY, NEW_KEY)
        self.assertIn("will not guess which key to destroy", refused.stderr)
        self.assertEqual(self.header(), header)
        self.assertIn("priority 'ignore'", host_probe.recovery_keyslots(self.header())[1])

    def test_an_orphan_token_alone_is_reported_by_status(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], input='{"type":"systemd-recovery","keyslots":[]}',
                       capture_output=True, text=True, check=True, timeout=60)
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1)
        self.assertEqual(self.state(status), "orphan-token")
        self.assertIn("cryptsetup token remove --token-id", status.stdout)
        # the next run that writes removes it first; one that only checks leaves it
        self.assertEqual(self.run_script("check", KEY).returncode, 0)
        self.assertEqual(self.run_script("enrol", INSTALLER, KEY).returncode, 1)   # the installer's passphrase is gone
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.state(done), "clean")

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
        self.assertIn("will not guess which key to destroy", refused.stderr)
        self.assertIn("the header does not say that one replaces the other", refused.stdout)
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
        self.assertIn("one recovery token names more than one keyslot", refused.stdout)
        self.assertIn("will not guess which key to destroy", refused.stderr)
        self.assertEqual(self.header(), header)

    def test_a_module_in_the_working_directory_is_not_what_reads_the_header(self):
        """The script is run by root from whatever directory root is in. Its Python runs isolated, so a
        json.py lying there, or on PYTHONPATH, is not imported: in EVERY mode, so that each of the
        script's Python helpers (slots, kinds, token_of, orphans, generation_of, ignored, unfinished)
        has run beside it."""
        planted = os.path.join(self.dir, "planted")
        os.mkdir(planted)
        marker = os.path.join(self.dir, "imported")
        with open(os.path.join(planted, "json.py"), "w", encoding="ascii") as f:
            f.write('open(%r, "w").close()\nraise SystemExit(0)\n' % marker)

        def beside(mode, *lines, **faults):
            return subprocess.run(["bash", self.script, "--" + mode, self.img], cwd=planted, capture_output=True, text=True,
                                  input="".join(l + "\n" for l in lines), env=dict(self.env(**faults), PYTHONPATH=planted), timeout=120)

        self.assertIn("keyslot 0", beside("status").stdout)
        self.assertEqual(beside("enrol", INSTALLER, KEY).returncode, 0)
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(beside("check", KEY).returncode, 0)
        self.assertNotEqual(beside("replace", KEY, NEW_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        self.assertEqual(beside("replace", KEY, NEW_KEY).returncode, 0)     # the resume: unfinished()
        self.assertEqual(beside("status").returncode, 0)
        self.assertFalse(os.path.exists(marker), "the planted json.py was imported")

    def test_a_second_recovery_key_this_script_did_not_make_is_never_decided_by_it(self):
        """Two recovery keyslots are an unfinished --replace only if the header says so: one token
        says it replaces the other keyslot and carries its generation plus one. A recovery key that
        systemd-cryptenroll or a person added beside ours has no such mark; "the generations differ"
        is not enough, and obeying a "wrong order" message must never destroy the newer key."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        ours = next(iter(self.generations()))
        for name, token in {
            "a token with no generation (systemd-cryptenroll --recovery-key)": '{"type":"systemd-recovery","keyslots":["6"]}',
            "a token with a higher generation and no mark": '{"type":"systemd-recovery","keyslots":["6"],"regalia_generation":2}',
            "a token that says it replaces ours, with the wrong generation": '{"type":"systemd-recovery","keyslots":["6"],"regalia_generation":5,"regalia_replaces":"%s"}' % ours,
            "a generation at the edge of 64 bits": '{"type":"systemd-recovery","keyslots":["6"],"regalia_generation":9223372036854775807,"regalia_replaces":"%s"}' % ours,
            "a generation that is not a number": '{"type":"systemd-recovery","keyslots":["6"],"regalia_generation":"a[$(id)]","regalia_replaces":"%s"}' % ours,
        }.items():
            with self.subTest(name=name):
                self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(KEY), "--new-key-slot", "6", self.img, self.secret(NEW_KEY))
                subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], input=token, check=True, capture_output=True, text=True, timeout=60)
                header = self.header()
                for order in ((KEY, NEW_KEY), (NEW_KEY, KEY)):
                    refused = self.run_script("replace", *order)
                    self.assertEqual(refused.returncode, 1, refused.stderr)
                    self.assertIn("this script will not guess which key to destroy", refused.stderr)
                    self.assertNotIn("wrong order", refused.stderr)
                    self.assertEqual(self.header(), header, "%s: the header was changed" % name)
                self.assertEqual(self.run_script("status").returncode, 1)
                foreign = next(i for i, t in self.header()["tokens"].items() if t["keyslots"] == ["6"])
                self.cs("luksKillSlot", "--batch-mode", self.img, "6")
                self.cs("token", "remove", "--token-id", foreign, self.img)
        # A used token whose own generation is not one this script wrote: a fresh --replace refuses
        # before adding anything (the next generation would overflow, or mean nothing).
        token = next(iter(self.header()["tokens"]))
        self.cs("token", "remove", "--token-id", token, self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"],"regalia_generation":9223372036854775807}' % ours)
        header = self.header()
        refused = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("carries a generation this script did not write", refused.stderr)
        self.assertEqual(self.header(), header)

    def test_a_token_made_before_generations_can_still_be_replaced_and_resumed(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        slot = next(iter(self.generations()))
        token = next(iter(self.header()["tokens"]))
        self.cs("token", "remove", "--token-id", token, self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"]}' % slot)
        self.assertNotEqual(self.run_script("replace", KEY, NEW_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        marks = {t["keyslots"][0]: (t.get("regalia_generation"), t.get("regalia_replaces")) for t in self.header()["tokens"].values()}
        self.assertEqual(marks[slot], (None, None))
        self.assertEqual([m for s, m in marks.items() if s != slot], [(1, slot)], "the new token does not say which keyslot it replaces")
        self.assertEqual(self.run_script("replace", NEW_KEY, KEY).returncode, 1)
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.opens(NEW_KEY) and not self.opens(KEY))

    def test_a_keyslot_that_was_there_before_the_run_is_never_destroyed_by_it(self):
        """A --replace killed before it marked its keyslot leaves the new key unmarked. A retry that
        fails leaves that keyslot exactly as it was; the one that goes through marks it."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY, kill="token import").returncode, -9)
        stray = self.header()
        done = self.run_script("replace", KEY, NEW_KEY, fail_subcommand="--test-passphrase --key-file")
        self.assertEqual(done.returncode, 1)
        self.assertIn("The header is as it was before this run", done.stderr)
        self.assertEqual(self.header(), stray)
        self.assertTrue(self.opens(NEW_KEY) and self.opens(KEY))
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        token = next(iter(self.header()["tokens"].values()))
        self.assertEqual(token["regalia_generation"], 2)
        self.assertFalse(self.opens(KEY))
        # a picked-up keyslot, marked, then the used keyslot fails to go: the pair is resumable,
        # which needs the mark to carry the generation and the "replaces" record
        self.assertEqual(self.run_script("replace", NEW_KEY, THIRD_KEY, kill="token import").returncode, -9)
        self.assertNotEqual(self.run_script("replace", NEW_KEY, THIRD_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        self.assertEqual(self.run_script("replace", NEW_KEY, THIRD_KEY).returncode, 0)
        self.assertTrue(self.opens(THIRD_KEY) and not self.opens(NEW_KEY))

    def test_a_token_naming_two_keyslots_beside_another_is_refused_whatever_its_id(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        slot = next(iter(self.generations()))
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(KEY), "--new-key-slot", "5", self.img, self.secret(NEW_KEY))
        # the single-keyslot token has the LOWER id; the one naming both comes after it
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s","5"],"regalia_generation":2,"regalia_replaces":"%s"}' % (slot, slot))
        header = self.header()
        refused = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("this script will not guess which key to destroy", refused.stderr)
        self.assertEqual(self.header(), header)


    def test_a_key_added_later_in_a_recycled_keyslot_number_is_not_the_used_half_of_a_replace(self):
        """Keyslot numbers are reused, and the mark "replaces keyslot N" outlives a completed replace.
        A recovery key that systemd-cryptenroll (or a person) adds afterwards lands in number N again:
        the header then reads "keyslot M replaces N, generation 1 = 0 + 1" for a pair no replace made.
        The mark also names the replaced keyslot's SALT, which the newcomer does not have."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        first = next(iter(self.generations()))
        # a recovery token with no generation: systemd-cryptenroll's, or this script's before generations
        self.cs("token", "remove", "--token-id", next(iter(self.header()["tokens"])), self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"]}' % first)
        salt = self.header()["keyslots"][first]["kdf"]["salt"]
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY).returncode, 0)
        survivor = next(iter(self.header()["tokens"].values()))
        self.assertEqual((survivor["regalia_generation"], survivor["regalia_replaces"], survivor["regalia_replaces_salt"]), (1, first, salt))
        # the newcomer, in the recycled number, with a bare token
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(NEW_KEY), "--new-key-slot", first, self.img, self.secret(THIRD_KEY))
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"]}' % first)
        header = self.header()
        status = self.run_script("status")
        self.assertEqual(status.returncode, 1)
        self.assertIn("the header does not say that one replaces the other", status.stdout)
        self.assertEqual(self.state(status), "unknown")
        self.assertNotIn("run --replace again", status.stdout)
        for order in ((THIRD_KEY, NEW_KEY), (NEW_KEY, THIRD_KEY)):
            refused = self.run_script("replace", *order)
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn("this script will not guess which key to destroy", refused.stderr)
            self.assertNotIn("wrong order", refused.stderr)
            self.assertEqual(self.header(), header, "the header was changed")
        self.assertTrue(self.opens(THIRD_KEY) and self.opens(NEW_KEY))

    def test_the_last_generation_this_script_writes_is_one_it_reads(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        slot = next(iter(self.generations()))
        self.cs("token", "remove", "--token-id", next(iter(self.header()["tokens"])), self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"],"regalia_generation":2147483646}' % slot)
        # stopped half way at the last generation: it must still be resumable
        self.assertNotEqual(self.run_script("replace", KEY, NEW_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(next(iter(self.header()["tokens"].values()))["regalia_generation"], 2147483647)
        header = self.header()
        refused = self.run_script("replace", NEW_KEY, THIRD_KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("the last generation this script writes", refused.stderr)
        self.assertEqual(self.header(), header)


    def test_an_identical_retry_finishes_an_interrupted_enrol(self):
        """regalia-kms#194's crash matrix: an --enrol stopped after adding its keyslot, or after marking
        it, was refused by the identical retry. The keyslot holds the very key typed again: the retry
        adopts it (unmarked) or recognises it (marked), and ends with one recovery keyslot, proven."""
        for name, fault in {"killed before the mark": dict(kill="token import"),
                            "killed after the mark": dict(kill="--test-passphrase --key-slot 1")}.items():
            with self.subTest(name=name):
                self.fresh()
                self.assertEqual(self.run_script("enrol", INSTALLER, KEY, **fault).returncode, -9)
                done = self.run_script("enrol", INSTALLER, KEY)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("ENROLLED", done.stderr)
                self.assertEqual(len(self.generations()), 1)
                self.assertEqual(self.run_script("check", KEY).returncode, 0)
                self.cs("luksKillSlot", "--batch-mode", self.img, "0")
                self.assertEqual(self.run_script("status").returncode, 0)
                # a different key is still refused beside it
                self.assertEqual(self.run_script("enrol", INSTALLER, NEW_KEY).returncode, 1)

    def test_an_identical_retry_finishes_a_replace_stopped_after_the_used_keyslot_was_destroyed(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        for name, fault in {"TERM after the kill": dict(signal_after="TERM:luksKillSlot --key-file"),
                            "the header unreadable after the kill": dict(fail_subcommand="luksDump", armed_by="luksKillSlot --key-file")}.items():
            with self.subTest(name=name):
                used, new = (KEY, NEW_KEY) if self.opens(KEY) else (NEW_KEY, KEY)
                if "armed_by" in fault:
                    done = self.run_script_armed("replace", used, new, **fault)
                    self.assertNotIn("still opens the disk", done.stderr, "a failed read was reported as a key that still opens")
                else:
                    code, _ = self.interrupted("replace", [used, new], **fault)
                self.assertFalse(self.opens(used))
                done = self.run_script("replace", used, new)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("the header records that this keyslot replaced one that is gone", done.stderr)
                self.assertEqual(self.run_script("status").returncode, 0)
        # A "used" key that opens nothing is not enough on its own: on a header whose recovery token
        # records no replace (a first enrolment), it is refused, not called a finished replace.
        current = KEY if self.opens(KEY) else NEW_KEY
        token = next(iter(self.header()["tokens"]))
        slot = self.header()["tokens"][token]["keyslots"][0]
        self.cs("token", "remove", "--token-id", token, self.img)
        subprocess.run([CRYPTSETUP, "token", "import", "--json-file", "-", self.img], check=True, capture_output=True, text=True, timeout=60,
                       input='{"type":"systemd-recovery","keyslots":["%s"],"regalia_generation":1}' % slot)
        refused = self.run_script("replace", THIRD_KEY, current)
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertNotIn("REPLACED", refused.stderr)


    def test_an_unreadable_header_is_never_taken_for_a_used_key_that_opens_nothing(self):
        """regalia-kms-1e's read of #206: with luksKillSlot, luksDump and --test-passphrase all failing
        (exit 4, as for a device that cannot be read) after the kill was attempted, the run said
        "REPLACED: the used key opens nothing" while both keys still opened. Only cryptsetup's own
        "no key available" (exit 2) means that."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        shim = os.path.join(self.bin, "cryptsetup")
        with open(shim) as f:
            text = f.read()
        with open(shim, "w") as f:
            f.write(text.replace("&& exit 1; done", "&& exit 4; done", 1))
        done = self.run_script_armed("replace", KEY, NEW_KEY, armed_by="luksKillSlot --key-file",
                                     fail_subcommand="luksKillSlot --key-file|luksDump|--test-passphrase")
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn("REPLACED", done.stderr)
        self.assertNotIn("opens nothing", done.stderr.replace("cannot be shown to open nothing", "").replace("cannot show that the used key opens nothing", ""))
        self.assertTrue(self.opens(KEY), "the premise: the used key still opens")

    def test_enrol_checks_every_unnamed_keyslot_before_it_writes_anything(self):
        """regalia-kms-1e's read of #206: adoption ran inside the loop over unnamed keyslots, so a LATER
        one failing the check left the adopted keyslot labelled after "Nothing was changed", and the
        identical retry then skipped the check."""
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "1", self.img, self.secret(KEY))
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "2", self.img, self.secret(THIRD_KEY))
        header = self.header()
        for attempt in range(2):
            refused = self.run_script("enrol", INSTALLER, KEY)
            self.assertEqual(refused.returncode, 1, refused.stderr)
            self.assertIn("keyslot 2 is a passphrase no token names", refused.stderr)
            self.assertEqual(self.header(), header, "attempt %d wrote to the header" % attempt)
        # the recovery key in two unnamed keyslots: refused, nothing written
        self.cs("luksKillSlot", "--batch-mode", self.img, "2")
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "2", self.img, self.secret(KEY))
        header = self.header()
        refused = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("both hold the recovery key", refused.stderr)
        self.assertEqual(self.header(), header)
        # an unnamed keyslot holding a key other than the one typed is never adopted
        self.cs("luksKillSlot", "--batch-mode", self.img, "2")
        self.cs("luksKillSlot", "--batch-mode", self.img, "1")
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "1", self.img, self.secret(THIRD_KEY))
        refused = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertNotIn("already holds this recovery key", refused.stderr)
        self.assertEqual(self.tokens(), {})

    def test_enrolled_already_says_nothing_changed_and_a_stray_beside_it_is_refused(self):
        self.enrolled()
        again = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertIn("ENROLLED already", again.stderr)
        self.assertIn("Nothing was changed", again.stderr)
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "5", self.img, self.secret(THIRD_KEY))
        refused = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("keyslot 5 is a passphrase no token names", refused.stderr)
        # the recovery key also sitting in an unnamed keyslot beside the enrolled one: refused
        self.cs("luksKillSlot", "--batch-mode", self.img, "5")
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(INSTALLER), "--new-key-slot", "5", self.img, self.secret(KEY))
        header = self.header()
        refused = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(refused.returncode, 1)
        self.assertIn("holds the recovery key as well as keyslot", refused.stderr)
        self.assertEqual(self.header(), header)


    def test_the_exit_codes_opens_nothing_relies_on_hold_for_this_cryptsetup(self):
        """opens_nothing() reads cryptsetup's exit 2 ("no key available with this passphrase") as "the
        key opens nothing". Measured on 2.7.0 and 2.7.5. If an update gave 2 for a header or device
        it cannot read, a failed read would become "the used key opens nothing": this fails first."""
        self.enrolled()
        wrong = self.cs("open", "--test-passphrase", "--key-file", self.secret(THIRD_KEY), self.img, ok=False)
        self.assertEqual(wrong.returncode, 2, wrong.stderr)
        missing = self.cs("open", "--test-passphrase", "--key-file", self.secret(THIRD_KEY), self.img + ".absent", ok=False)
        self.assertNotIn(missing.returncode, (0, 2), missing.stderr)
        plain = os.path.join(self.dir, "not-luks.img")
        with open(plain, "wb") as f:
            f.truncate(1 << 20)
        notluks = self.cs("open", "--test-passphrase", "--key-file", self.secret(THIRD_KEY), plain, ok=False)
        self.assertNotIn(notluks.returncode, (0, 2), notluks.stderr)

    def state(self, done):
        """The state the run printed last: every mode ends with the header read again (#175)."""
        found = [l.split(" ", 2)[1] for l in done.stdout.splitlines() if l.startswith("STATE: ")]
        self.assertTrue(found, "the run printed no STATE line: %r" % done.stdout)
        return found[-1]

    def test_a_failed_enrol_says_what_the_header_holds_and_the_same_run_finishes_it(self):
        """No undo (#175): a step that fails leaves the keyslot it wrote, the run says so from the
        header (which keyslot, and that the key just typed opens it), and the identical retry picks the
        keyslot up. The standard input is HELD OPEN, as a terminal holds it: no cryptsetup call may
        wait on it."""
        before = self.header()
        # the second: only the boot prompt's open (no keyslot named) fails, once the keyslot exists
        for fault, armed, why in (("token import", "", "could not be marked"), ("--test-passphrase --key-file", "luksAddKey", "is NOT marked")):
            with self.subTest(fault=fault):
                if os.path.exists(self.argv_log):
                    os.unlink(self.argv_log)
                env = self.env(fail_subcommand=fault, armed_by=armed)
                with subprocess.Popen(["bash", self.script, "--enrol", self.img], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, env=env) as held:
                    held.stdin.write(INSTALLER + "\n" + KEY + "\n")
                    held.stdin.flush()
                    try:
                        held.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        held.kill()
                        self.fail("the script waited on its open standard input")
                    stdout, stderr = held.stdout.read(), held.stderr.read()
                self.assertEqual(held.returncode, 1, stderr)
                self.assertIn(why, stderr)
                self.assertNotIn("as it was before this run", stderr)
                self.assertIn("keyslot 1   passphrase (no token names it), opens with the recovery key typed", stdout)
                self.assertIn("STATE: no-recovery", stdout)
                self.assertTrue(self.opens(KEY), "the premise: the key is in the header, unmarked")
                # a different key is refused beside it ...
                refused = self.run_script("enrol", INSTALLER, NEW_KEY)
                self.assertIn("keyslot 1 is a passphrase no token names, and it is not the one you typed", refused.stderr)
                self.assertFalse(self.opens(NEW_KEY))
                # ... and the same one finishes it, in the same keyslot
                done = self.run_script("enrol", INSTALLER, KEY)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertIn("already holds this recovery key", done.stderr)
                self.assertEqual(self.tokens(), {"0": ("systemd-recovery", ["1"])})
                self.assertEqual(self.state(done), "orphan-keyslot")   # the installer's passphrase is still there
                self.cs("luksKillSlot", "--batch-mode", self.img, "1")
                self.cs("token", "remove", "--token-id", "0", self.img)
                self.assertEqual(self.header()["keyslots"].keys(), before["keyslots"].keys())

    def test_a_new_key_that_does_not_prove_never_costs_the_used_key(self):
        """The new keyslot must open when it is named AND when no keyslot is named (a boot prompt). If
        it does not, it is not marked, the used key is not destroyed, and the run says so."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        done = self.run_script("replace", KEY, NEW_KEY, fail_subcommand="--test-passphrase --key-file")
        self.assertEqual(done.returncode, 1)
        self.assertIn("it is NOT marked and the used key is still enrolled", done.stderr)
        self.assertEqual(self.state(done), "orphan-keyslot")
        self.assertTrue(self.opens(KEY), "the used key was lost")
        self.assertEqual(len(self.tokens()), 1)
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("already holds the new key", done.stderr)
        self.assertTrue(self.opens(NEW_KEY) and not self.opens(KEY))
        self.assertEqual(self.state(done), "clean")

    def test_a_destroy_stopped_after_it_wiped_the_used_keyslot_is_finished(self):
        """lab/recovery/matrix.py found it (#175): luksKillSlot wipes a keyslot's key material, syncs,
        and only then removes it from the metadata. Killed between the two, the used keyslot is still
        listed and marked as the replaced one, and the used key opens nothing. The identical retry
        must finish it, not refuse because the used key no longer opens its keyslot."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertNotEqual(self.run_script("replace", KEY, NEW_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        old = next(s for s, g in self.generations().items() if g == 1)
        area = self.header()["keyslots"][old]["area"]
        with open(self.img, "r+b") as f:     # what luksKillSlot's first sync leaves: the area wiped
            f.seek(int(area["offset"]))
            f.write(b"\0" * int(area["size"]))
        self.assertFalse(self.opens(KEY), "the premise: the used key opens nothing")
        status = self.run_script("status")
        self.assertEqual(self.state(status), "added-unproven")
        # a new key that is not the new keyslot's is still refused
        self.assertIn("these are not the used key", self.run_script("replace", KEY, THIRD_KEY).stderr)
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("key material was wiped by a destroy that stopped", done.stderr)
        self.assertEqual(self.state(done), "clean")
        self.assertEqual(list(self.header()["keyslots"]), [next(iter(self.generations()))])
        self.assertTrue(self.opens(NEW_KEY))

    def test_a_signal_during_the_writes_does_not_stop_the_run(self):
        """No undo (#175): once the first header write starts, INT, TERM and HUP are ignored, a closed
        standard error included. The run finishes; there is nothing half-done to take back."""
        for name, run in {
            "TERM after the keyslot was added": dict(signal_after="TERM:luksAddKey"),
            "INT after the token was written": dict(signal_after="INT:token import"),
            "HUP after the token was written": dict(signal_after="HUP:token import"),
            "TERM, then TERM again": dict(signal_after="TERM:luksAddKey|TERM:token import"),
            "INT with standard error closed": dict(signal_after="INT:token import", close_stderr=True),
        }.items():
            with self.subTest(name=name):
                self.fresh()
                code, stderr = self.interrupted("enrol", [INSTALLER, KEY], **run)
                self.assertEqual(code, 0, stderr)
                self.assertTrue(self.opens(KEY))
                self.assertEqual(self.tokens(), {"0": ("systemd-recovery", ["1"])})
        for name, run in {"TERM after the new keyslot": dict(signal_after="TERM:luksAddKey"),
                          "TERM after the used keyslot is destroyed": dict(signal_after="TERM:luksKillSlot --key-file"),
                          "INT while it is destroyed": dict(signal_at="INT:luksKillSlot --key-file")}.items():
            with self.subTest(name=name):
                self.fresh()
                self.enrolled()
                self.cs("luksKillSlot", "--batch-mode", self.img, "0")
                code, stderr = self.interrupted("replace", [KEY, NEW_KEY], **run)
                self.assertEqual(code, 0, stderr)
                self.assertIn("REPLACED", stderr)
                self.assertTrue(self.opens(NEW_KEY) and not self.opens(KEY))
                self.assertEqual(self.run_script("status").returncode, 0)

    def test_a_stray_keyslot_beside_a_finished_replace_is_reported(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY).returncode, 0)
        self.cs("luksAddKey", "--batch-mode", *FAST, "--key-file", self.secret(NEW_KEY), "--new-key-slot", "5", self.img, self.secret(THIRD_KEY))
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.state(done), "orphan-keyslot")
        self.assertIn("keyslot 5   passphrase (no token names it)", done.stdout)

    def test_every_mode_ends_with_the_state_read_from_the_header(self):
        for mode, lines in (("status", ()), ("enrol", (INSTALLER, KEY)), ("check", (KEY,)), ("replace", (KEY, NEW_KEY)), ("status", ())):
            done = self.run_script(mode, *lines)
            self.assertIn(self.state(done), ("no-recovery", "orphan-keyslot", "clean"), done.stdout)
            self.assertTrue(done.stdout.rstrip().splitlines()[-1].startswith("STATE: "), done.stdout)

    def test_there_is_one_source_of_recovery_keys_the_ceremony(self):
        """#175, decided 2026-10-03: no host-generated mode, no switch to one."""
        done = subprocess.run(["bash", self.script, "--enrol", "--host-generated", self.img], input=INSTALLER + "\n", capture_output=True, text=True, env=self.env(), timeout=60)
        self.assertEqual(done.returncode, 1)
        self.assertIn("unknown argument '--host-generated'", done.stderr)
        with open(SCRIPT, encoding="utf-8") as f:
            text = f.read()
        for gone in ("systemd-cryptenroll \"$DEV\" --recovery-key", "recovery-key.conf", "source=host"):
            self.assertNotIn(gone, text)

    def verify_trail(self):
        """The trail's chain, as the real trails.verify checks it; and every request answered exactly once."""
        path = os.path.join(self.tool, "trail.jsonl")
        if os.path.exists(path):
            trails.verify(path)

    def pairs(self):
        """{request seq: [the outcomes naming it]} of the trail."""
        events = self.trail()
        answers = {e["seq"]: [] for e in events if e["outcome"] == "REQUESTED"}
        for e in events:
            if e["outcome"] != "REQUESTED":
                answers.setdefault(e.get("request"), []).append(e["outcome"])
        return answers

    def trail(self):
        path = os.path.join(self.tool, "trail.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_every_run_that_takes_a_key_is_recorded_before_and_after_and_no_key_is(self):
        """#278: the request before a key is asked for, then exactly one outcome, each with the header's state.
        --status writes nothing. No key, used, new or installer's, is ever in the trail."""
        self.run_script("status")
        self.assertEqual(self.trail(), [])
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(self.run_script("check", KEY).returncode, 0)
        self.assertEqual(self.run_script("replace", THIRD_KEY, NEW_KEY).returncode, 1)          # not this host's key
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY).returncode, 0)
        events = [(e["mode"], e["outcome"]) for e in self.trail()]
        self.assertEqual(events, [("enrol", "REQUESTED"), ("enrol", "ALLOW"), ("check", "REQUESTED"), ("check", "ALLOW"),
                                  ("replace", "REQUESTED"), ("replace", "DENY"), ("replace", "REQUESTED"), ("replace", "ALLOW")])
        last = self.trail()[-1]
        self.assertEqual((last["event"], last["state"], last["device"]), ("recovery-key", "clean", self.img))
        self.assertTrue(all(len(outcomes) == 1 for outcomes in self.pairs().values()), self.pairs())
        with open(os.path.join(self.tool, "trail.jsonl"), encoding="utf-8") as f:
            text = f.read()
        for secret in (KEY, NEW_KEY, THIRD_KEY, INSTALLER, KEY[:8], NEW_KEY[:8]):
            self.assertNotIn(secret, text)

    def test_nothing_is_done_unrecorded(self):
        """The Vault rule: a request that cannot be written to the trail is refused before a key is asked for."""
        open(os.path.join(self.tool, "refuse"), "w").close()
        before = self.header()
        done = self.run_script("enrol", INSTALLER, KEY)
        self.assertEqual(done.returncode, 1)
        self.assertIn("the audit trail cannot be written: nothing was done", done.stderr)
        self.assertEqual(self.header(), before)
        os.unlink(os.path.join(self.tool, "trails.py"))
        done = self.run_script("enrol", INSTALLER, KEY)
        self.assertIn("nothing is done unrecorded", done.stderr)
        self.assertEqual(self.header(), before)

    def test_a_run_cut_after_a_write_is_recorded_incomplete(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertNotEqual(self.run_script("replace", KEY, NEW_KEY, fail_subcommand="luksKillSlot --key-file").returncode, 0)
        self.assertEqual(self.trail()[-1]["outcome"], "INCOMPLETE")
        self.assertEqual(self.trail()[-1]["state"], "added-unproven")

    def test_an_outcome_that_cannot_be_written_fails_the_run(self):
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        # the request is written; the outcome is refused: armed only after the first write
        refuse = os.path.join(self.tool, "refuse")
        shim = os.path.join(self.bin, "cryptsetup")
        with open(shim) as f:
            text = f.read()
        with open(shim, "w") as f:
            f.write(text.replace('"%s" "$@"; rc=$?' % CRYPTSETUP, '[ "$1" = luksKillSlot ] && touch %s\n"%s" "$@"; rc=$?' % (refuse, CRYPTSETUP), 1))
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertIn("could not be written to the audit trail", done.stderr)
        self.assertTrue(self.opens(NEW_KEY) and not self.opens(KEY), "the premise: the replace itself finished")
        self.assertEqual([e["outcome"] for e in self.trail()][-1], "REQUESTED")


    def test_a_run_killed_after_its_request_is_closed_by_the_next(self):
        """d9's read of #281: a kill -9 after REQUESTED leaves it unanswered; the next run closes it (INCOMPLETE,
        naming its seq) before its own request, so every request has exactly one outcome."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY, kill="luksAddKey").returncode, -9)
        killed = self.trail()[-1]
        self.assertEqual(killed["outcome"], "REQUESTED")
        done = self.run_script("replace", KEY, NEW_KEY)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("unanswered request (seq %d, --replace)" % killed["seq"], done.stderr)
        closing = [e for e in self.trail() if e.get("request") == killed["seq"]]
        self.assertEqual([(e["outcome"], e["mode"]) for e in closing], [("INCOMPLETE", "replace")])
        self.assertEqual(self.pairs()[killed["seq"]], ["INCOMPLETE"])
        self.assertTrue(all(len(outcomes) == 1 for outcomes in self.pairs().values()), self.pairs())

    def test_a_killed_request_is_closed_whatever_name_the_disk_is_given_next(self):
        """d9: the request is matched on the device's identity, not the path typed: a run killed on one name
        is closed by the next run on another name for the same disk."""
        self.enrolled()
        self.cs("luksKillSlot", "--batch-mode", self.img, "0")
        self.assertEqual(self.run_script("replace", KEY, NEW_KEY, kill="luksAddKey").returncode, -9)
        killed = self.trail()[-1]
        alias = os.path.join(self.dir, "by-partlabel-regalia-root")
        os.symlink(self.img, alias)
        done = subprocess.run(["bash", self.script, "--replace", alias], input=KEY + "\n" + NEW_KEY + "\n",
                              capture_output=True, text=True, env=self.env(), timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.pairs()[killed["seq"]], ["INCOMPLETE"])
        self.assertEqual({e["device_id"] for e in self.trail()}, {killed["device_id"]})


if __name__ == "__main__":
    unittest.main()
