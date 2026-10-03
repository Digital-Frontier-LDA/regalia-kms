"""deploy/baremetal/units (#80, step 3b): what each unit may do, pinned. The processes are node.py's; a run
of the units under a real systemd is the end-to-end step that follows."""
import configparser
import os
import pathlib
import re
import shutil
import subprocess
import unittest

from deploy.baremetal import node

UNITS = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "units"
SERVICES = ("regalia-authtime", "regalia-wg-apply", "regalia-boot-session", "regalia-admission", "regalia-sync")


def unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    parser.optionxform = str
    parser.read(UNITS / name)
    return parser


class Units(unittest.TestCase):
    def service(self, name):
        return unit(name + ".service")["Service"]

    def test_each_unit_runs_the_service_of_its_name_from_the_one_configuration(self):
        for name in SERVICES:
            with self.subTest(name):
                self.assertEqual(self.service(name)["ExecStart"],
                                 "/usr/bin/python3 -Es -m deploy.baremetal.node --config /etc/regalia/node.json %s" % name[len("regalia-"):])
        choices = re.search(r'choices=\(([^)]*)\)', pathlib.Path(node.__file__).read_text()).group(1)
        for name in SERVICES:
            self.assertIn('"%s"' % name[len("regalia-"):], choices)

    def test_each_unit_holds_at_most_the_one_capability_it_needs_and_the_two_that_talk_to_peers_are_not_root(self):
        expected = {"regalia-authtime": "CAP_DAC_OVERRIDE", "regalia-wg-apply": "CAP_NET_ADMIN", "regalia-boot-session": "",
                    "regalia-admission": "", "regalia-sync": ""}
        for name, capabilities in expected.items():
            with self.subTest(name):
                service = self.service(name)
                self.assertEqual(service["CapabilityBoundingSet"], capabilities)       # an empty assignment is the empty set
                self.assertEqual(service["AmbientCapabilities"], capabilities)
                self.assertEqual(service["NoNewPrivileges"], "yes")
                self.assertEqual(service["ProtectSystem"], "strict")
                self.assertEqual(service["LimitCORE"], "0")
                self.assertEqual(service["Environment"], "PATH=/usr/sbin:/usr/bin")
        # the two that parse what peers send (#191 for admission); its group is its own, the TPM through tss
        self.assertEqual(self.service("regalia-sync")["User"], "regalia-sync")
        self.assertEqual((self.service("regalia-admission")["User"], self.service("regalia-admission")["Group"]),
                         ("regalia-admission", "regalia-admission"))
        for name in ("regalia-authtime", "regalia-wg-apply", "regalia-boot-session"):
            self.assertEqual(self.service(name)["User"], "root")

    def test_what_each_unit_may_write_and_reach(self):
        self.assertEqual(self.service("regalia-authtime")["ReadWritePaths"], "/run/regalia /run/chrony")
        self.assertEqual(self.service("regalia-authtime")["SupplementaryGroups"], "_chrony")
        authtime_unit = self.service("regalia-authtime")
        # the one capability it holds could read any file: it is shown almost none
        self.assertEqual((authtime_unit["TemporaryFileSystem"], authtime_unit["ProtectProc"]), ("/etc:ro /var:ro /run:ro", "invisible"))
        self.assertEqual(authtime_unit["BindPaths"], "/run/regalia /run/chrony")
        self.assertEqual(authtime_unit["BindReadOnlyPaths"].split()[0], "/etc/regalia/node.json")
        self.assertNotIn("site.json", authtime_unit["BindReadOnlyPaths"])
        self.assertNotIn("wg-service", authtime_unit["BindReadOnlyPaths"])
        self.assertEqual(self.service("regalia-authtime")["PrivateNetwork"], "yes")
        self.assertEqual(self.service("regalia-authtime")["RestrictAddressFamilies"], "AF_UNIX")
        admission = self.service("regalia-admission")
        # its own directory only, inside root's /run/regalia; the boot session beside it is not its to write
        self.assertEqual((admission["ReadWritePaths"], admission["StateDirectory"], admission["StateDirectoryMode"]),
                         ("/run/regalia/admission", "regalia-admission", "0700"))
        admission_unit = unit("regalia-admission.service")["Unit"]
        self.assertEqual(admission_unit["Requires"], "regalia-boot-session.service")
        self.assertIn("regalia-boot-session.service", admission_unit["After"].split())
        boot_session = self.service("regalia-boot-session")
        # root, to write root's /run/regalia, and nothing else: no capability, no network, no device, and an
        # empty /etc, /var and /run around it but for its configuration and that one directory
        self.assertEqual((boot_session["Type"], boot_session["RemainAfterExit"]), ("oneshot", "yes"))
        self.assertEqual((boot_session["ReadWritePaths"], boot_session["BindPaths"]), ("/run/regalia", "/run/regalia"))
        self.assertEqual(boot_session["TemporaryFileSystem"], "/etc:ro /var:ro /run:ro")
        self.assertEqual(boot_session["BindReadOnlyPaths"].split()[0], "/etc/regalia/node.json")
        self.assertEqual((boot_session["PrivateNetwork"], boot_session["PrivateDevices"], boot_session["RestrictAddressFamilies"]),
                         ("yes", "yes", "AF_UNIX"))
        self.assertIn("regalia-admission.service", unit("regalia-boot-session.service")["Unit"]["Before"].split())
        # never in an initrd, where the unlock client owns the pair, whatever an image builder copies
        self.assertEqual(unit("regalia-boot-session.service")["Unit"]["ConditionPathExists"], "!/etc/initrd-release")
        self.assertEqual((admission["IPAddressDeny"], admission["IPAddressAllow"]), ("any", "fd72:6567:6c61::/48"))
        wg_apply = self.service("regalia-wg-apply")
        self.assertNotIn("ReadWritePaths", wg_apply)                                 # it writes nothing but the kernel's state
        self.assertEqual((wg_apply["IPAddressDeny"], wg_apply["TimeoutStartSec"]), ("any", "60"))
        self.assertEqual((wg_apply["Restart"], wg_apply["RestartSec"]), ("on-failure", "15s"))   # a failed run is retried
        self.assertEqual(unit("regalia-wg-apply.service")["Unit"]["StartLimitIntervalSec"], "0")
        sync = self.service("regalia-sync")
        self.assertEqual((sync["StateDirectory"], sync["SupplementaryGroups"]), ("regalia-sync", "tss"))
        self.assertNotIn("ReadWritePaths", sync)
        for name in SERVICES:
            service = self.service(name)
            with self.subTest(name):
                # /run/regalia is shared with the unlock client and the daemon: never a unit's RuntimeDirectory,
                # which systemd removes (boot-session included) when that unit stops
                self.assertNotIn("RuntimeDirectory", service)
                if name not in ("regalia-authtime", "regalia-boot-session"):
                    # the device cgroup lets it through; the file's mode (tss, 0660) needs the group
                    self.assertEqual((service.get("DevicePolicy"), service.get("DeviceAllow"), service.get("SupplementaryGroups")),
                                     ("closed", "/dev/tpmrm0 rw", "tss"))

    def test_the_node_configuration_s_directories_are_the_units(self):
        """The example configuration names the directories the units give each service, and the published
        chain is where the path unit watches."""
        import json
        example = node.validate(json.loads((UNITS.parent / "node.example.json").read_text()))
        self.assertEqual(example["state_dir"], "/var/lib/" + self.service("regalia-sync")["StateDirectory"])
        self.assertEqual(example["admission_dir"], "/var/lib/" + self.service("regalia-admission")["StateDirectory"])
        self.assertEqual(os.path.dirname(node.admission_file(example["run_dir"])), self.service("regalia-admission")["ReadWritePaths"])
        self.assertEqual(unit("regalia-wg-apply.path")["Path"]["PathChanged"], "/var/lib/regalia-sync/" + node.PUBLISHED)
        tmpfiles = (UNITS / "regalia.tmpfiles.conf").read_text()
        self.assertIn("d /run/regalia 0755 root root -", tmpfiles)
        # #191: the lease service's directory is its user's, inside root's, and no one else can write it
        self.assertIn("d /run/regalia/admission 0755 regalia-admission regalia-admission -", tmpfiles)
        users = (UNITS / "regalia.sysusers.conf").read_text()
        self.assertIn("u regalia-sync - ", users)
        self.assertIn("u regalia-admission - ", users)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_the_units_and_scores_them_well_exposed_at_most_a_little(self):
        paths = [str(UNITS / (name + ".service")) for name in SERVICES] + [str(UNITS / "regalia-wg-apply.path")]
        done = subprocess.run(["systemd-analyze", "verify", "--man=no", "--recursive-errors=no"] + paths, capture_output=True, text=True)
        problems = [line for line in done.stderr.splitlines() if "chrony.service" not in line and "network-online" not in line and line.strip()]
        self.assertEqual(problems, [])
        for name in SERVICES:
            with self.subTest(name):
                done = subprocess.run(["systemd-analyze", "security", "--offline=yes", "--no-pager", str(UNITS / (name + ".service"))],
                                      capture_output=True, text=True)
                if done.returncode != 0 and "Unknown option" in done.stderr:
                    self.skipTest("this systemd-analyze has no offline security scoring")
                score = float(re.search(r"Overall exposure level for \S+: ([0-9.]+)", done.stdout).group(1))
                self.assertLessEqual(score, 3.0)


if __name__ == "__main__":
    unittest.main()
