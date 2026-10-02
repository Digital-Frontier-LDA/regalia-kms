"""deploy/baremetal/units (#80, step 3b): what each unit may do, pinned. The processes are node.py's; a run
of the units under a real systemd is the end-to-end step that follows."""
import configparser
import pathlib
import re
import shutil
import subprocess
import unittest

from deploy.baremetal import node

UNITS = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "units"
SERVICES = ("regalia-authtime", "regalia-wg-apply", "regalia-admission", "regalia-sync")


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

    def test_only_the_tunnel_unit_holds_a_capability_and_only_sync_is_not_root(self):
        expected = {"regalia-authtime": "", "regalia-wg-apply": "CAP_NET_ADMIN", "regalia-admission": "", "regalia-sync": ""}
        for name, capabilities in expected.items():
            with self.subTest(name):
                service = self.service(name)
                self.assertEqual(service["CapabilityBoundingSet"], capabilities)       # an empty assignment is the empty set
                self.assertEqual(service["AmbientCapabilities"], capabilities)
                self.assertEqual(service["NoNewPrivileges"], "yes")
                self.assertEqual(service["ProtectSystem"], "strict")
                self.assertEqual(service["LimitCORE"], "0")
                self.assertEqual(service["Environment"], "PATH=/usr/sbin:/usr/bin")
        self.assertEqual(self.service("regalia-sync")["User"], "regalia-sync")       # the one that parses what peers send
        for name in ("regalia-authtime", "regalia-wg-apply", "regalia-admission"):
            self.assertEqual(self.service(name)["User"], "root")

    def test_what_each_unit_may_write_and_reach(self):
        self.assertEqual(self.service("regalia-authtime")["ReadWritePaths"], "/run/regalia")
        self.assertEqual(self.service("regalia-authtime")["PrivateNetwork"], "yes")
        self.assertEqual(self.service("regalia-authtime")["RestrictAddressFamilies"], "AF_UNIX")
        admission = self.service("regalia-admission")
        self.assertEqual((admission["ReadWritePaths"], admission["StateDirectory"], admission["StateDirectoryMode"]),
                         ("/run/regalia", "regalia-admission", "0700"))
        self.assertEqual((admission["IPAddressDeny"], admission["IPAddressAllow"]), ("any", "fd72:6567:6c61::/48"))
        self.assertNotIn("ReadWritePaths", self.service("regalia-wg-apply"))         # it writes nothing but the kernel's state
        sync = self.service("regalia-sync")
        self.assertEqual((sync["StateDirectory"], sync["SupplementaryGroups"]), ("regalia-sync", "tss"))
        self.assertNotIn("ReadWritePaths", sync)
        for name in SERVICES:
            service = self.service(name)
            with self.subTest(name):
                # /run/regalia is shared with the unlock client and the daemon: never a unit's RuntimeDirectory,
                # which systemd removes (boot-session included) when that unit stops
                self.assertNotIn("RuntimeDirectory", service)
                if name != "regalia-authtime":
                    self.assertEqual((service.get("DevicePolicy"), service.get("DeviceAllow")), ("closed", "/dev/tpmrm0 rw"))

    def test_the_node_configuration_s_directories_are_the_units(self):
        """The admission service writes in its StateDirectory and sync in its own; node.py's defaults name the
        same places, and the published chain is where the path unit watches."""
        self.assertEqual(unit("regalia-wg-apply.path")["Path"]["PathChanged"], "/var/lib/regalia-sync/" + node.PUBLISHED)
        tmpfiles = (UNITS / "regalia.tmpfiles.conf").read_text()
        self.assertIn("d /run/regalia 0755 root root -", tmpfiles)
        self.assertIn("u regalia-sync - ", (UNITS / "regalia.sysusers.conf").read_text())

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
