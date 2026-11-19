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


if __name__ == "__main__":
    unittest.main()
