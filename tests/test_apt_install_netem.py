"""e2e/lib/apt-install-netem.sh (regalia-1ur): the hosted runner's kernel can be ahead of the archive's linux-modules-extra
(7.0.0-1017-azure, #609's run 40506387532), so the running kernel's extra modules are installed only when its base
modules lack sch_netem, and netem is checked for after the install, naming the kernel. Run here with stand-ins for
sudo, apt-get, modinfo and uname; and every workflow that needs netem takes it through this one step."""
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "e2e/lib/apt-install-netem.sh"
KERNEL = "7.0.0-1017-azure"


class AptInstallNetem(unittest.TestCase):
    def run_script(self, base_has_netem, archive_has_extra=True, extra_has_netem=True, apt_fails=False):
        """(exit status, output, the apt-get calls), on a stand-in system."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        bin_ = Path(d, "bin")
        bin_.mkdir()
        state = Path(d, "state")
        state.mkdir()
        if base_has_netem:
            (state / "netem").write_text("/lib/modules/%s/kernel/net/sched/sch_netem.ko.zst\n" % KERNEL)
        stubs = {
            "sudo": 'exec "$@"',
            "uname": 'echo %s' % KERNEL,
            "modinfo": '[ "$*" = "-F filename sch_netem" ] && [ -s "$STATE/netem" ] && exec cat "$STATE/netem"; exit 1',
            "apt-get": textwrap.dedent('''\
                printf '%%s\\n' "$*" >> "$STATE/calls"
                [ "$1" = update ] && exit 0
                %s
                for p in "$@"; do
                  case "$p" in linux-modules-extra-*)
                    [ %s = 1 ] || { echo "E: Unable to locate package $p" >&2; exit 100; }
                    [ %s = 1 ] && echo /lib/modules/%s/kernel/net/sched/sch_netem.ko > "$STATE/netem";;
                  esac
                done
                exit 0''' % ("exit 100" if apt_fails else ":", int(archive_has_extra), int(extra_has_netem), KERNEL)),
        }
        for name, body in stubs.items():
            path = bin_ / name
            path.write_text("#!/bin/bash\n" + body + "\n")
            path.chmod(0o755)
        env = dict(os.environ, PATH="%s:/usr/bin:/bin" % bin_, STATE=str(state))
        r = subprocess.run(["bash", str(SCRIPT), "swtpm", "wireguard-tools"], env=env, capture_output=True, text=True, timeout=30)
        calls = (state / "calls").read_text().splitlines() if (state / "calls").exists() else []
        return r.returncode, r.stdout + r.stderr, calls

    def test_a_kernel_whose_base_modules_have_netem_installs_no_extra_package(self):
        rc, out, calls = self.run_script(base_has_netem=True, archive_has_extra=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls, ["update -qq", "install -y -qq --no-install-recommends swtpm wireguard-tools"])
        self.assertIn("kernel %s: sch_netem in the base modules" % KERNEL, out)

    def test_a_kernel_without_netem_gets_its_extra_modules(self):
        rc, out, calls = self.run_script(base_has_netem=False)
        self.assertEqual(rc, 0, out)
        self.assertEqual(calls[-1], "install -y -qq --no-install-recommends swtpm wireguard-tools linux-modules-extra-%s" % KERNEL)
        self.assertIn("kernel %s: sch_netem is /lib/modules/%s/kernel/net/sched/sch_netem.ko" % (KERNEL, KERNEL), out)

    def test_neither_having_netem_fails_naming_the_kernel(self):
        rc, out, _ = self.run_script(base_has_netem=False, archive_has_extra=False)
        self.assertEqual(rc, 100, out)
        self.assertIn("Unable to locate package linux-modules-extra-%s" % KERNEL, out)
        # the step's own line names the kernel; apt's error alone is not the explanation (df-grafana-7e)
        self.assertIn("kernel %s: apt-get install failed (exit 100), with linux-modules-extra-%s asked for" % (KERNEL, KERNEL), out)
        rc, out, _ = self.run_script(base_has_netem=False, extra_has_netem=False)
        self.assertEqual(rc, 1, out)
        self.assertIn("kernel %s: sch_netem is still missing after the install" % KERNEL, out)

    def test_an_apt_failure_is_the_step_s_failure(self):
        rc, out, _ = self.run_script(base_has_netem=True, apt_fails=True)
        self.assertEqual(rc, 100, out)
        self.assertIn("kernel %s: apt-get install failed (exit 100)\n" % KERNEL, out)

    def test_no_workflow_installs_the_kernel_s_extra_modules_by_itself(self):
        """vtpm-probe.yml is the exception: it is the deliberate re-check for a runner that has the package (regalia-afi)."""
        users = []
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            text = path.read_text()
            if path.name != "vtpm-probe.yml":
                with self.subTest(workflow=path.name):
                    self.assertNotRegex(text, r"linux-modules-extra-\$\(uname -r\)")
            if "e2e/lib/apt-install-netem.sh" in text:
                users.append(path.name)
        self.assertEqual(users, ["ci.yml", "node-units.yml"])
        self.assertTrue(re.search(r"linux-modules-extra-\$\(uname -r\)", (ROOT / ".github/workflows/vtpm-probe.yml").read_text()))


if __name__ == "__main__":
    unittest.main()
