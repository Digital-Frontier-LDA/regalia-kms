"""regalia-kms-dx7.14: the staging image variant, and the production image holding none of it.

The operator's decision of 2026-11-19: the staging DL360 runs a STAGING-ONLY image variant (a key-only operator sshd
refused without regalia.staging=1, systemd-networkd for the staging management net, a persistent journal), and a test
asserts the production image has none of it. imagevariant.check is what build-rootfs.sh runs on every build's listing
before writing anything (and e2e/rootfs-reproducible.sh on CI's production build); these tests hold its judgement and
the staging files' own refusals."""
import contextlib
import io
import json
import pathlib
import re
import subprocess
import tempfile
import unittest

from deploy.baremetal import imagevariant as v

REPO = pathlib.Path(__file__).resolve().parent.parent
STAGING = REPO / "deploy" / "baremetal" / "image" / "staging"
BUILD = REPO / "deploy" / "baremetal" / "image" / "build-rootfs.sh"
PACKAGES = REPO / "deploy" / "baremetal" / "image" / "packages.txt"
E2E = REPO / "e2e" / "rootfs-reproducible.sh"


def listing(*paths):
    return "".join("%s\tf\t644\t0\t0\t0\t\t\n" % p for p in ("./", "./usr/bin/python3") + paths)


def record(variant, *packages):
    return {"variant": variant, "packages": ["python3=3.13.5-1"] + ["%s=1" % p for p in packages]}


STAGING_PACKAGES = v.staging_packages()


class TheJudgement(unittest.TestCase):
    def test_a_clean_production_build_passes(self):
        self.assertEqual(v.check(listing(), record("production")), [])

    def test_each_staging_path_in_a_production_build_is_refused(self):
        for p in v.STAGING_PATHS:
            with self.subTest(path=p):
                problems = v.check(listing(p), record("production"))
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(p, problems[0])

    def test_any_other_regalia_staging_path_in_production_is_refused(self):
        problems = v.check(listing("./etc/systemd/system/regalia-staging-extra.service"), record("production"))
        self.assertEqual(len(problems), 1, problems)

    def test_the_inert_deploy_copy_is_not_judged(self):
        copy = v.DEPLOY_COPY + "baremetal/image/staging/regalia-staging-sshd.service"
        self.assertEqual(v.check(listing(copy), record("production")), [])

    def test_each_staging_package_in_a_production_build_is_refused(self):
        for name in STAGING_PACKAGES:
            with self.subTest(package=name):
                problems = v.check(listing(), record("production", name))
                self.assertEqual(len(problems), 1, problems)
                self.assertIn(name, problems[0])

    def test_a_complete_staging_build_passes_and_each_missing_piece_is_refused(self):
        self.assertEqual(v.check(listing(*v.STAGING_PATHS), record("staging", *STAGING_PACKAGES)), [])
        for p in v.STAGING_PATHS:
            with self.subTest(path=p):
                rest = [x for x in v.STAGING_PATHS if x != p]
                self.assertEqual(len(v.check(listing(*rest), record("staging", *STAGING_PACKAGES))), 1)
        for name in STAGING_PACKAGES:
            with self.subTest(package=name):
                rest = [x for x in STAGING_PACKAGES if x != name]
                self.assertEqual(len(v.check(listing(*v.STAGING_PATHS), record("staging", *rest))), 1)

    def test_a_record_without_a_known_variant_is_refused(self):
        for rec in ({"packages": []}, {"variant": "lab", "packages": []}):
            with self.subTest(record=rec):
                self.assertEqual(len(v.check(listing(), rec)), 1)


class TheStagingFiles(unittest.TestCase):
    def test_staging_packages_are_not_production_packages(self):
        text = PACKAGES.read_text()
        section, production = None, set()
        for line in text.splitlines():
            m = re.fullmatch(r"\[([a-z-]+)\]", line.strip())
            if m:
                section = m.group(1)
            elif section == "packages" and line.strip() and not line.startswith("#"):
                production.add(line.split("|")[0].strip())
        self.assertTrue(production)
        self.assertEqual(production & set(STAGING_PACKAGES), set())

    def test_sshd_is_refused_without_the_staging_flag_and_takes_keys_only(self):
        unit = (STAGING / "regalia-staging-sshd.service").read_text()
        self.assertIn("ConditionKernelCommandLine=regalia.staging=1\n", unit)
        self.assertIn("ConditionPathExists=/var/lib/regalia-staging/authorized_keys\n", unit)
        conf = [l for l in (STAGING / "sshd_config").read_text().splitlines() if l and not l.startswith("#")]
        for want in ("AuthenticationMethods publickey", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                     "PermitEmptyPasswords no", "PermitRootLogin prohibit-password", "UsePAM no"):
            self.assertIn(want, conf)
        # sshd keeps the first value of a keyword: the per-host Include comes last, so it cannot loosen these
        self.assertTrue(conf[-1].startswith("Include /var/lib/regalia-staging/"), conf[-1])

    def test_networkd_runs_only_on_a_staging_boot(self):
        self.assertIn("ConditionKernelCommandLine=regalia.staging=1\n", (STAGING / "networkd.conf").read_text())

    def test_networkd_can_reach_the_staging_network_file(self):
        # regalia-kms-dx7.34: networkd runs as systemd-network; a 0700 parent hid the .network file (Permission denied)
        modes = {}
        for line in (STAGING / "regalia-staging.tmpfiles.conf").read_text().splitlines():
            f = line.split()
            if f and f[0] == "d":
                modes[f[1]] = int(f[2], 8)
        top = "/var/lib/regalia-staging"
        self.assertTrue(modes[top] & 0o001, "others cannot traverse %s" % top)
        self.assertFalse(modes[top] & 0o004, "%s must not be listable by others" % top)
        self.assertEqual(modes[top + "/network"] & 0o005, 0o005)
        for private in ("/ssh", "/sshd_config.d"):
            self.assertEqual(modes[top + private], 0o700, private)

    def test_the_journal_is_persistent_on_staging(self):
        self.assertIn("Storage=persistent\n", (STAGING / "journald.conf").read_text())

    def test_every_staging_path_is_one_the_build_writes(self):
        text = BUILD.read_text()
        for p in v.STAGING_PATHS:
            if p == "./usr/sbin/sshd":
                continue                                   # openssh-server's own
            name = p[1:]
            with self.subTest(path=p):
                self.assertTrue(name in text or name.replace("/usr/lib/systemd/system/", "") in text, name)

    def test_every_build_is_judged_and_ci_judges_production(self):
        # -B: the build runs the checkout's Python as root and build-initrd.sh then refuses a checkout holding bytecode
        self.assertIn("python3 -BEs -m deploy.baremetal.imagevariant check", BUILD.read_text())
        self.assertIn("python3 -BEs -m deploy.baremetal.imagevariant check", E2E.read_text())
        self.assertNotRegex(BUILD.read_text(), r"python3 -Es[^\n]*imagevariant")
        self.assertIn("VARIANT=production", BUILD.read_text())

    def test_the_build_reads_the_staging_packages_through_the_module(self):
        # -m, not -c: tests/test_python_isolation.py's rule (a -c runs with the caller's sys.path)
        self.assertIn('STAGING_PACKAGES="$(python3 -BEs -m deploy.baremetal.imagevariant packages)"', BUILD.read_text())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(v.main(["packages"]), 0)
        self.assertEqual(out.getvalue(), ",".join(STAGING_PACKAGES) + "\n")



CHECK = STAGING / "sshd-dropins-check.sh"


def judge_dropin(text, name="10-staging.conf"):
    """Run the image's drop-in check on a directory holding one drop-in; (exit code, stderr)."""
    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, name).write_text(text)
        p = subprocess.run(["sh", str(CHECK), d], capture_output=True, text=True, timeout=30)
        return p.returncode, p.stderr


class TheSshdDropIns(unittest.TestCase):
    """PA decision on #741 (CodeRabbit, sshd_config:22): the per-host sshd drop-ins may hold ONLY ListenAddress and
    AllowUsers. First-value-wins does not hold for a Match block, so the unit refuses to start on anything else."""

    def test_the_check_runs_first_and_is_installed_where_the_unit_runs_it(self):
        unit = (STAGING / "regalia-staging-sshd.service").read_text()
        pre = [l for l in unit.splitlines() if l.startswith("ExecStartPre=")]
        self.assertEqual(pre[0], "ExecStartPre=/usr/lib/regalia-staging/sshd-dropins-check.sh")
        self.assertIn('install -D -m 0755 "$SRC/$STAGING_DIR/sshd-dropins-check.sh" '
                      '"$ROOT/usr/lib/regalia-staging/sshd-dropins-check.sh"', BUILD.read_text())
        self.assertIn("./usr/lib/regalia-staging/sshd-dropins-check.sh", v.STAGING_PATHS)
        # the check judges the very directory sshd_config includes
        include = (STAGING / "sshd_config").read_text().splitlines()[-1]
        self.assertEqual(include, "Include /var/lib/regalia-staging/sshd_config.d/*.conf")
        self.assertIn("dir=${1:-/var/lib/regalia-staging/sshd_config.d}", CHECK.read_text())

    def test_a_drop_in_with_only_listenaddress_and_allowusers_passes(self):
        rc, err = judge_dropin("# TEST per-host\n\nListenAddress 192.0.2.10\n  allowusers=root@192.0.2.1\n")
        self.assertEqual((rc, err), (0, ""))

    def test_match_all_password_authentication_yes_is_refused(self):
        # the review's case: a Match block's settings apply to what it matches, whatever came first
        rc, err = judge_dropin("ListenAddress 192.0.2.10\nMatch all\n  PasswordAuthentication yes\n")
        self.assertEqual(rc, 1)
        self.assertIn("10-staging.conf:2: Match is not allowed", err)
        self.assertIn("10-staging.conf:3: PasswordAuthentication is not allowed", err)
        self.assertIn("refusing to start regalia-staging-sshd", err)

    def test_every_other_keyword_is_refused_in_any_spelling(self):
        for line in ("PasswordAuthentication yes", "PermitRootLogin yes", "AuthenticationMethods none",
                     "match User root", "  MATCH all", "Include /tmp/x.conf", "HostKey /tmp/k",
                     "AuthorizedKeysFile /tmp/k", "PermitRootLogin=yes", "\tUsePAM yes", "ListenAddressX 1"):
            with self.subTest(line=line.strip()):
                rc, err = judge_dropin("ListenAddress 192.0.2.10\n%s\n" % line)
                self.assertEqual(rc, 1, err)

    def test_any_drop_in_file_is_judged_not_just_ours(self):
        rc, err = judge_dropin("Match all\nPermitRootLogin yes\n", name="99-other.conf")
        self.assertEqual(rc, 1)
        self.assertIn("99-other.conf:1: Match is not allowed", err)

    def test_a_missing_drop_in_dir_refuses(self):
        p = subprocess.run(["sh", str(CHECK), "/nonexistent/regalia-staging/sshd_config.d"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 1)

    def test_the_header_states_the_rule(self):
        head = (STAGING / "sshd_config").read_text()
        self.assertIn("ONLY ListenAddress and AllowUsers", head)
        self.assertIn("Match included", head)


HOSTKEY_CHECK = STAGING / "sshd-hostkey-check.sh"


class TheSshdHostKeyIsTheBundledOne(unittest.TestCase):
    """regalia-kms-u2t: the 2026-11-25 --wipe reinstall made a NEW host key at first start (the unit ran ssh-keygen
    when the key was missing), so the operator trusted it on first use. The key is made once off-box and installed by
    stage-perhost; the unit never makes one, and a missing or exposed key refuses the start by name."""

    def judge(self, setup):
        with tempfile.TemporaryDirectory() as d:
            key = pathlib.Path(d) / "ssh_host_ed25519_key"
            setup(key)
            p = subprocess.run(["sh", str(HOSTKEY_CHECK), str(key)], capture_output=True, text=True, timeout=30)
            return p.returncode, p.stderr

    @staticmethod
    def pair(key, mode=0o600, private=b"TEST PRIVATE\n", public=b"ssh-ed25519 AAAATEST test\n"):
        key.write_bytes(private)
        key.chmod(mode)
        if public is not None:
            key.with_name(key.name + ".pub").write_bytes(public)

    def test_the_unit_never_makes_a_key_and_checks_it_before_sshd(self):
        unit = (STAGING / "regalia-staging-sshd.service").read_text()
        self.assertNotIn("ssh-keygen", unit)
        pre = [l for l in unit.splitlines() if l.startswith("ExecStartPre=")]
        self.assertEqual(pre, ["ExecStartPre=/usr/lib/regalia-staging/sshd-dropins-check.sh",
                               "ExecStartPre=/usr/lib/regalia-staging/sshd-hostkey-check.sh",
                               "ExecStartPre=/usr/sbin/sshd -t -f /usr/lib/regalia-staging/sshd_config"])
        self.assertIn('install -D -m 0755 "$SRC/$STAGING_DIR/sshd-hostkey-check.sh" '
                      '"$ROOT/usr/lib/regalia-staging/sshd-hostkey-check.sh"', BUILD.read_text())
        self.assertIn("./usr/lib/regalia-staging/sshd-hostkey-check.sh", v.STAGING_PATHS)
        # the check judges the very key sshd_config serves
        self.assertIn("HostKey /var/lib/regalia-staging/ssh/ssh_host_ed25519_key", (STAGING / "sshd_config").read_text())
        self.assertIn("key=${1:-/var/lib/regalia-staging/ssh/ssh_host_ed25519_key}", HOSTKEY_CHECK.read_text())

    def test_the_bundled_pair_passes(self):
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.assertEqual(self.judge(lambda k: self.pair(k, mode=mode)), (0, ""))

    def test_each_wrong_key_refuses_by_name(self):
        cases = (
            (lambda k: None, "no host key at"),
            (lambda k: self.pair(k, private=b""), "is empty"),
            (lambda k: self.pair(k, mode=0o644), "is mode 644, not 0600"),
            (lambda k: self.pair(k, mode=0o640), "is mode 640, not 0600"),
            (lambda k: self.pair(k, public=None), "no public half at"),
            (lambda k: (k.with_name("real").write_bytes(b"x"), k.symlink_to(k.with_name("real"))), "is not a regular file"),
            (lambda k: k.symlink_to(k.with_name("nowhere")), "is not a regular file"),
            (lambda k: k.mkdir(), "is not a regular file"),
        )
        for setup, why in cases:
            with self.subTest(why=why):
                rc, err = self.judge(setup)
                self.assertEqual(rc, 1, err)
                self.assertIn(why, err)
                self.assertIn("refusing to start regalia-staging-sshd", err)
                self.assertIn("stage-perhost", err)


class TheSshdWaitsForItsAddress(unittest.TestCase):
    """regalia-kms-dx7.36: on build 8, sshd bound the static ListenAddress at 16.1s; eno1 gained carrier at 18.7s, and
    five quick restarts had run out the start limit at 17.1s."""

    def test_sshd_starts_after_network_online_with_a_restart_margin(self):
        unit = (STAGING / "regalia-staging-sshd.service").read_text().splitlines()
        self.assertIn("Wants=network-online.target", unit)
        self.assertIn("After=network-online.target", unit)
        self.assertIn("RestartSec=5s", unit)

    def test_the_staging_variant_enables_networkd_wait_online(self):
        link = "network-online.target.wants/systemd-networkd-wait-online.service"
        self.assertIn("./usr/lib/systemd/system/" + link, v.STAGING_PATHS)
        self.assertIn(link, BUILD.read_text())


if __name__ == "__main__":
    unittest.main()
