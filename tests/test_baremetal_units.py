"""deploy/baremetal/units (#80, step 3b): what each unit may do, pinned. The processes are node.py's; a run
of the units under a real systemd is the end-to-end step that follows."""
import configparser
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from deploy.baremetal import node

UNITS = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "units"
SERVICES = ("regalia-authtime", "regalia-wg-apply", "regalia-boot-session", "regalia-admission", "regalia-sync")


def unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    parser.optionxform = str
    parser.read(UNITS / name)
    return parser


class TrailsReachTheirShipper(unittest.TestCase):
    """#340: a node service's audit trail lives in that service's StateDirectory, and regalia-audit-ship@<trail> reads
    it as its own user with the trail's reader group and NO capability. It opens the file and LISTS the directory (for
    the trail's rotated archives), so the directory must be readable and searchable by others: with the admission
    service's at 0700, and then 0711 (searchable, not listable: the CI run of e2e/audit-ship-systemd.py showed
    "open .../regalia-admission: permission denied"), its trail never reached the collector."""

    def test_every_node_trail_s_directory_is_traversable_by_its_shipper(self):
        from deploy.baremetal import trails
        checked = []
        for name, entry in trails.TRAILS.items():
            if not entry[0].startswith(("state_dir/", "admission_dir/")):      # in a service's StateDirectory (the others: root's tools)
                continue
            writer = re.search(r"regalia-[a-z-]+\.service", entry[1]).group(0)      # the registry names the unit that writes it
            mode = int(unit(writer)["Service"]["StateDirectoryMode"], 8)
            with self.subTest(trail=name):
                self.assertEqual(mode & 0o005, 0o005, "%s's StateDirectoryMode %s: regalia-audit-ship@%s cannot list and reach %s"
                                 % (writer, oct(mode), name, entry[0]))
            checked.append((name, writer, oct(mode)))
        self.assertEqual(sorted(checked), [("admission", "regalia-admission.service", "0o755"), ("sync", "regalia-sync.service", "0o755")])
        self.assertEqual(unit("regalia-audit-ship@.service")["Service"]["CapabilityBoundingSet"], "")    # the reason: no way around it

    def test_traversal_exposes_no_file_the_admission_service_writes_there(self):
        """24 on #345: 0755 lets anyone pass and list, so nothing the service keeps there may be readable by others. The files it
        writes there (node.admission_service: lease.Holder's lease.json and its lock, the trail audit.jsonl), written
        as it writes them, under the most permissive umask."""
        from deploy.baremetal import lease, trails
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        old = os.umask(0)
        try:
            import tests.test_baremetal_lease as lt                   # lease v2: the stand-in state and session key
            holder = lease.Holder("a", "ab" * 32, lambda: (0, True), lambda: 0, os.path.join(d, "lease.json"), **lt.SOURCES)
            holder.request()                                      # the nonce, written to lease.json under its lock
            trails.append(os.path.join(d, "audit.jsonl"), {"event": "admission", "outcome": "ALLOW"})
        finally:
            os.umask(old)
        names = sorted(os.listdir(d))
        self.assertIn("lease.json", names)
        self.assertIn("audit.jsonl", names)
        for name in names:
            with self.subTest(file=name):
                self.assertEqual(os.stat(os.path.join(d, name)).st_mode & 0o007, 0, "%s is readable or writable by others" % name)


class ChronyDropIn(unittest.TestCase):
    """#303: chronyd from enrolment's configuration, the package's own file untouched."""

    def test_chronyd_runs_from_the_rendered_configuration_alone(self):
        from deploy.baremetal import enrol
        lines = (UNITS / "chrony.service.d" / "regalia.conf").read_text().splitlines()
        execs = [line for line in lines if line.startswith("ExecStart=")]
        # an empty ExecStart= first: a drop-in otherwise ADDS a second command instead of replacing the package's
        self.assertEqual(execs, ["ExecStart=", "ExecStart=!/usr/sbin/chronyd -f %s $DAEMON_OPTS" % enrol.CHRONY_CONF])
        self.assertTrue(enrol.CHRONY_CONF.startswith("/etc/chrony/") and enrol.CHRONY_CONF != "/etc/chrony/chrony.conf")
        self.assertIn("Conflicts=systemd-timesyncd.service", lines)
        self.assertIn("ConditionPathExists=%s" % enrol.CHRONY_CONF, lines)        # skipped, not latched, before enrolment
        # the latch (#303): any unclean stop recorded in root's directory, and no start while it is there
        from deploy.baremetal import authtime
        pre = [line for line in lines if line.startswith("ExecStartPre=")]
        post = [line for line in lines if line.startswith("ExecStopPost=")]
        self.assertEqual((len(pre), len(post)), (1, 1))
        self.assertTrue(pre[0].startswith("ExecStartPre=!/bin/sh -c ") and "[ -e %s ]" % authtime.LATCH in pre[0] and "exit 1" in pre[0])
        self.assertIn("[ ! -d %s ]" % authtime.LATCH_DIR, pre[0])                 # no directory: not started either
        self.assertTrue(post[0].startswith("ExecStopPost=!/bin/sh -c ") and '"$$SERVICE_RESULT" != success' in post[0])
        self.assertIn("set -C", post[0])                                         # the first record is kept
        self.assertIn("> %s;" % authtime.LATCH, post[0])
        self.assertIn("ReadWritePaths=%s" % authtime.LATCH_DIR, lines)
        tmpfiles = (UNITS / "regalia.tmpfiles.conf").read_text()
        self.assertIn("d %s 0700 root root -" % authtime.LATCH_DIR, tmpfiles)
        self.assertFalse([line for line in lines if line.startswith("Restart")])     # an exit on maxchange stays down
        # and nothing of ours starts it again: regalia-authtime orders itself after chrony, never Wants= or Requires= it
        authtime_unit = unit("regalia-authtime.service")["Unit"]
        self.assertIn("chrony.service", authtime_unit["After"])
        self.assertFalse({"Wants", "Requires", "BindsTo", "Requisite", "Upholds"} & set(authtime_unit))
        for name in UNITS.glob("*.service"):
            self.assertNotRegex(name.read_text(), r"(?m)^(Wants|Requires|BindsTo|Upholds|OnFailure)=.*chrony", name.name)


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
        self.assertEqual(self.service("regalia-authtime")["ReadWritePaths"],
                         "/run/regalia /run/chrony /var/log/regalia-time -/run/regalia-metrics/authtime")   # + the time trail (#303), its metrics (#305)
        self.assertEqual(self.service("regalia-authtime")["SupplementaryGroups"], "_chrony")
        authtime_unit = self.service("regalia-authtime")
        # the one capability it holds could read any file: it is shown almost none
        self.assertEqual((authtime_unit["TemporaryFileSystem"], authtime_unit["ProtectProc"]), ("/etc:ro /var:ro /run:ro", "invisible"))
        self.assertEqual(authtime_unit["BindPaths"], "/run/regalia /run/chrony /var/log/regalia-time -/run/regalia-metrics/authtime")
        self.assertEqual(authtime_unit["BindReadOnlyPaths"].split()[-1], "-/var/lib/regalia-time")      # the latch, read only (#305)
        self.assertEqual(authtime_unit["BindReadOnlyPaths"].split()[0], "/etc/regalia/node.json")
        self.assertNotIn("site.json", authtime_unit["BindReadOnlyPaths"])
        self.assertNotIn("wg-service", authtime_unit["BindReadOnlyPaths"])
        self.assertEqual(self.service("regalia-authtime")["PrivateNetwork"], "yes")
        self.assertEqual(self.service("regalia-authtime")["RestrictAddressFamilies"], "AF_UNIX")
        admission = self.service("regalia-admission")
        # its own directory only, inside root's /run/regalia; the boot session beside it is not its to write
        self.assertEqual((admission["ReadWritePaths"], admission["StateDirectory"], admission["StateDirectoryMode"]),
                         ("/run/regalia/admission -/run/regalia-metrics/admission", "regalia-admission", "0755"))   # listable by its trail's shipper (#340)
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
        self.assertEqual((sync["StateDirectory"], sync["SupplementaryGroups"]), ("regalia-sync", "tss regalia-audit-sync"))
        self.assertEqual(sync["ReadWritePaths"], "-/run/regalia-metrics/sync")      # its metrics only (#305); the rest is StateDirectory
        for name in SERVICES:
            service = self.service(name)
            with self.subTest(name):
                # /run/regalia is shared with the unlock client and the daemon: never a unit's RuntimeDirectory,
                # which systemd removes (boot-session included) when that unit stops
                self.assertNotIn("RuntimeDirectory", service)
                if name not in ("regalia-authtime", "regalia-boot-session"):
                    # the device cgroup lets it through; the file's mode (tss, 0660) needs the group; and a
                    # trail's writer, the trail's reader group (#286)
                    trail_group = {"regalia-sync": " regalia-audit-sync", "regalia-admission": " regalia-audit-admission"}.get(name, "")
                    self.assertEqual((service.get("DevicePolicy"), service.get("DeviceAllow"), service.get("SupplementaryGroups")),
                                     ("closed", "/dev/tpmrm0 rw", "tss" + trail_group))

    def test_the_node_configuration_s_directories_are_the_units(self):
        """The example configuration names the directories the units give each service, and the published
        chain is where the path unit watches."""
        import json
        example = node.validate(json.loads((UNITS.parent / "node.example.json").read_text()))
        self.assertEqual(example["state_dir"], "/var/lib/" + self.service("regalia-sync")["StateDirectory"])
        self.assertEqual(example["admission_dir"], "/var/lib/" + self.service("regalia-admission")["StateDirectory"])
        self.assertEqual(os.path.dirname(node.admission_file(example["run_dir"])), self.service("regalia-admission")["ReadWritePaths"].split()[0])
        self.assertEqual(unit("regalia-wg-apply.path")["Path"]["PathChanged"], "/var/lib/regalia-sync/" + node.PUBLISHED)
        tmpfiles = (UNITS / "regalia.tmpfiles.conf").read_text()
        self.assertIn("d /run/regalia 0755 root root -", tmpfiles)
        # #191: the lease service's directory is its user's, inside root's, and no one else can write it
        self.assertIn("d /run/regalia/admission 0755 regalia-admission regalia-admission -", tmpfiles)
        users = (UNITS / "regalia.sysusers.conf").read_text()
        self.assertIn("u regalia-sync - ", users)
        self.assertIn("u regalia-admission - ", users)

    def test_the_esp_advance_writes_the_esp_and_the_anchor_only(self):
        """#66 B3: root with no capability, its own command; it writes the ESP and nothing else on disk, reaches no
        network, and runs on every new published chain."""
        service = self.service("regalia-esp-advance")
        self.assertEqual(service["ExecStart"],
                         "/usr/bin/python3 -Es -m deploy.baremetal.node --config /etc/regalia/node.json esp-advance --esp /efi")
        self.assertIn('"esp-advance"', re.search(r'choices=\(([^)]*)\)', pathlib.Path(node.__file__).read_text()).group(1))
        self.assertEqual((service["User"], service["CapabilityBoundingSet"], service["AmbientCapabilities"], service["NoNewPrivileges"]),
                         ("root", "", "", "yes"))
        self.assertEqual((service["ProtectSystem"], service["ReadWritePaths"], service["PrivateNetwork"], service["RestrictAddressFamilies"]),
                         ("strict", "/efi -/run/regalia-metrics/esp-advance", "yes", "AF_UNIX"))
        self.assertEqual((service["DevicePolicy"], service["DeviceAllow"], service["SupplementaryGroups"]), ("closed", "/dev/tpmrm0 rw", "tss"))
        # the anchor's writer lock, its own (node.ESP_LOCK)
        self.assertEqual("/run/%s/highwater.lock" % service["RuntimeDirectory"], node.ESP_LOCK)
        self.assertEqual((service["Restart"], service["TimeoutStartSec"], service["LimitCORE"]), ("on-failure", "60", "0"))
        self.assertEqual(unit("regalia-esp-advance.service")["Unit"]["RequiresMountsFor"], "/efi")
        self.assertEqual(unit("regalia-esp-advance.service")["Unit"]["StartLimitIntervalSec"], "0")
        self.assertEqual(unit("regalia-esp-advance.path")["Path"],
                         {"PathChanged": "/var/lib/regalia-sync/" + node.PUBLISHED, "Unit": "regalia-esp-advance.service"})

    def test_no_unit_is_left_for_the_retired_authority_host(self):
        """#199 step 5c: the nodes sign heartbeats by quorum and revoke.py revokes; no unit, user or directory of the
        revocation authority's host remains."""
        self.assertEqual(sorted(p.name for p in UNITS.rglob("*") if "regalia-authority" in p.name), [])
        for p in UNITS.rglob("*"):
            if p.is_file():
                with self.subTest(p.name):
                    self.assertNotIn("regalia-authority", p.read_text(errors="replace"))

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_the_units_and_scores_them_well_exposed_at_most_a_little(self):
        paths = [str(UNITS / (name + ".service")) for name in SERVICES + ("regalia-esp-advance",)] + \
            [str(UNITS / "regalia-wg-apply.path"), str(UNITS / "regalia-esp-advance.path")]
        done = subprocess.run(["systemd-analyze", "verify", "--man=no", "--recursive-errors=no"] + paths, capture_output=True, text=True)
        problems = [line for line in done.stderr.splitlines() if "chrony.service" not in line and "network-online" not in line and line.strip()]
        self.assertEqual(problems, [])
        for name in SERVICES + ("regalia-esp-advance",):
            with self.subTest(name):
                done = subprocess.run(["systemd-analyze", "security", "--offline=yes", "--no-pager", str(UNITS / (name + ".service"))],
                                      capture_output=True, text=True)
                if done.returncode != 0 and "Unknown option" in done.stderr:
                    self.skipTest("this systemd-analyze has no offline security scoring")
                score = float(re.search(r"Overall exposure level for \S+: ([0-9.]+)", done.stdout).group(1))
                self.assertLessEqual(score, 3.0)


if __name__ == "__main__":
    unittest.main()


class AuditShipUnit(unittest.TestCase):
    """regalia-audit-ship@.service, one instance a trail (#278)."""

    def test_a_tampered_trail_stays_stopped_and_it_holds_no_capability(self):
        service = unit("regalia-audit-ship@.service")["Service"]
        self.assertTrue(service["ExecStart"].startswith("/usr/bin/regalia-audit-ship -trail %i -path ${TRAIL_PATH} "))
        self.assertEqual((service["Restart"], service["RestartPreventExitStatus"]), ("on-failure", "3"))   # cmd/regalia-audit-ship exitTampered
        self.assertEqual((service["User"], service["Group"], service["CapabilityBoundingSet"], service["AmbientCapabilities"], service["NoNewPrivileges"]),
                         ("regalia-audit-ship", "regalia-audit-ship", "", "", "yes"))
        self.assertNotIn("SupplementaryGroups", service)                           # each instance's, from its drop-in
        users = (UNITS / "regalia-audit-ship.sysusers.conf").read_text()
        self.assertIn("u regalia-audit-ship - ", users)
        self.assertIn("g regalia-audit -", users)
        self.assertEqual((service["ProtectSystem"], service["StateDirectory"]), ("strict", "regalia-audit-ship"))
        self.assertEqual(service["ReadWritePaths"], "-/run/regalia-metrics/audit-ship")      # its metrics only (#305)

    def test_each_service_trail_has_a_reader_group_its_writer_gives_it_and_nothing_else_has(self):
        """#286: a service trail's reader group is its own. The writer's unit belongs to it (so the writer can
        give the file that group) and the sysusers file of the writer's host creates it; the shipper's drop-in
        names it, and no other unit does, so the shipper reads the trail and nothing else of the writer's."""
        from deploy.baremetal import trails
        writers = {"sync": ("regalia-sync.service", "regalia.sysusers.conf"), "admission": ("regalia-admission.service", "regalia.sysusers.conf")}
        for name, (unit_file, sysusers) in writers.items():
            with self.subTest(name):
                group = trails.TRAILS[name][3]
                self.assertEqual(group, "regalia-audit-" + name)
                self.assertIn(group, unit(unit_file)["Service"]["SupplementaryGroups"].split())
                self.assertIn("g %s -" % group, (UNITS / sysusers).read_text())
                holders = [p.name for p in UNITS.rglob("*") if p.is_file() and re.search(r"^SupplementaryGroups=.*\b%s\b" % re.escape(group), p.read_text(errors="replace"), re.M)]
                self.assertEqual(sorted(holders), sorted([unit_file, "reader.conf"]))

    def test_each_trail_s_instance_reads_through_the_registry_s_group_and_only_that(self):
        """#283 (regalia-kms-24): one drop-in per trail in trails.py's registry, naming its group: the
        writer's own for a service's trail, regalia-audit for the operator tools'. No other drop-in."""
        from deploy.baremetal import trails
        dropins = sorted(p.name for p in UNITS.glob("regalia-audit-ship@*.service.d"))
        self.assertEqual(dropins, sorted("regalia-audit-ship@%s.service.d" % name for name in trails.TRAILS))
        for name, (_, _, _, group) in trails.TRAILS.items():
            with self.subTest(name):
                parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
                parser.optionxform = str
                parser.read(UNITS / ("regalia-audit-ship@%s.service.d" % name) / "reader.conf")
                self.assertEqual(dict(parser["Service"]), {"SupplementaryGroups": group})

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_an_instance_and_scores_it_well_exposed_at_most_a_little(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copy(UNITS / "regalia-audit-ship@.service", d)
            instance = os.path.join(d, "regalia-audit-ship@sync.service")
            done = subprocess.run(["systemd-analyze", "verify", "--man=no", "--recursive-errors=no", instance], capture_output=True, text=True)
            complaints = [line for line in done.stderr.splitlines() if "regalia-audit-ship" in line and "/usr/bin/regalia-audit-ship is not executable" not in line]
            self.assertEqual(complaints, [])
            done = subprocess.run(["systemd-analyze", "security", "--offline=yes", "--no-pager", instance], capture_output=True, text=True)
            if done.returncode != 0 and "offline" in done.stderr:
                self.skipTest("this systemd-analyze has no offline security scoring")
            score = float(re.search(r"exposure level for \S+: (\d+\.\d+)", done.stdout).group(1))
            self.assertLessEqual(score, 3.0)


class AuditPruneUnit(unittest.TestCase):
    """regalia-audit-prune@.service and .timer: archives removed only behind the collector (#278)."""

    def test_it_prunes_from_the_shipper_s_head_file_with_no_capability(self):
        service = unit("regalia-audit-prune@.service")["Service"]
        ship = unit("regalia-audit-ship@.service")["Service"]
        self.assertEqual(" ".join(service["ExecStart"].replace("\\\n", " ").split()),
                         "/usr/bin/python3 -Es /usr/lib/regalia-kms/deploy/baremetal/trails.py prune ${TRAIL_PATH} "
                         "/var/lib/regalia-audit-ship/%i.head.json --trail %i --site ${SITE} --client-cert "
                         "/etc/regalia/audit-ship/client.crt --receipt-keys /etc/regalia/audit-ship/collector-receipt.pub")
        self.assertIn("-head /var/lib/regalia-audit-ship/%i.head.json", ship["ExecStart"])   # the file the shipper writes
        self.assertIn("/etc/regalia/audit-ship/%i.env", open(UNITS / "regalia-audit-prune@.service").read())  # TRAIL_PATH
        self.assertIn("EnvironmentFile=/etc/regalia/audit-ship.env", open(UNITS / "regalia-audit-prune@.service").read())  # SITE
        self.assertEqual((service["CapabilityBoundingSet"], service["AmbientCapabilities"], service["NoNewPrivileges"]), ("", "", "yes"))
        self.assertNotIn("User", service)                                          # each instance's owner, from its drop-in
        self.assertEqual((service["ProtectSystem"], service["PrivateNetwork"]), ("strict", "yes"))
        from deploy.baremetal import trails
        writable = service["ReadWritePaths"].split()
        for name, (where, _, _, _) in trails.TRAILS.items():                   # every trail's directory, and nothing else
            base = where.partition("/")[0]
            directory = os.path.dirname(where) if where.startswith("/") else {"state_dir": None, "admission_dir": "/run/regalia/admission"}[base]
            if directory:
                self.assertIn("-" + directory, writable, name)
        self.assertEqual(unit("regalia-audit-prune@.timer")["Timer"]["OnCalendar"], "daily")

    def test_each_trail_s_prune_runs_as_its_directory_s_owner(self):
        """#288 (regalia-kms-24): no DAC override. A service's trail is pruned by its writer, which owns the
        directory; the operator tools' by root, which owns /var/log/regalia. One drop-in per trail."""
        from deploy.baremetal import trails
        dropins = sorted(p.name for p in UNITS.glob("regalia-audit-prune@*.service.d"))
        self.assertEqual(dropins, sorted("regalia-audit-prune@%s.service.d" % name for name in trails.TRAILS))
        for name, (where, _, _, group) in trails.TRAILS.items():
            with self.subTest(name):
                parser = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
                parser.optionxform = str
                parser.read(UNITS / ("regalia-audit-prune@%s.service.d" % name) / "owner.conf")
                owner = {"sync": "regalia-sync", "admission": "regalia-admission"}.get(name, "root")
                self.assertEqual(dict(parser["Service"]), {"User": owner})

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze is not installed")
    def test_systemd_accepts_it_and_scores_it_well_exposed_at_most_a_little(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("regalia-audit-prune@.service", "regalia-audit-prune@.timer"):
                shutil.copy(UNITS / name, d)
            instance = os.path.join(d, "regalia-audit-prune@sync.service")
            done = subprocess.run(["systemd-analyze", "verify", "--man=no", "--recursive-errors=no", instance, os.path.join(d, "regalia-audit-prune@sync.timer")],
                                  capture_output=True, text=True)
            self.assertEqual([line for line in done.stderr.splitlines() if "regalia-audit-prune" in line], [])
            done = subprocess.run(["systemd-analyze", "security", "--offline=yes", "--no-pager", instance], capture_output=True, text=True)
            if done.returncode != 0 and "offline" in done.stderr:
                self.skipTest("this systemd-analyze has no offline security scoring")
            self.assertLessEqual(float(re.search(r"exposure level for \S+: (\d+\.\d+)", done.stdout).group(1)), 3.0)


class NodeMetricsDirectories(unittest.TestCase):
    """#305: each writer's node_exporter textfile directory is its own (owner), group regalia-metrics, setgid 2750,
    made by tmpfiles; its unit may write there and nowhere new; node_exporter's user is the group's member."""
    OWNERS = {"authtime": ("regalia-authtime.service", "root"), "sync": ("regalia-sync.service", "regalia-sync"),
              "admission": ("regalia-admission.service", "regalia-admission"),
              "esp-advance": ("regalia-esp-advance.service", "root"),
              "audit-ship": ("regalia-audit-ship@.service", "regalia-audit-ship")}

    def test_each_writer_s_directory_is_its_own_and_its_unit_may_write_there(self):
        from deploy.baremetal import metrics
        self.assertEqual(set(self.OWNERS), set(metrics.WRITERS))
        tmpfiles = (UNITS / "regalia.tmpfiles.conf").read_text() + (UNITS / "regalia-audit-ship.tmpfiles.conf").read_text()
        for writer, (unit_name, owner) in self.OWNERS.items():
            with self.subTest(writer):
                directory = os.path.join(metrics.RUN_DIR, metrics.WRITERS[writer][0])
                self.assertIn("d %s 2750 %s %s -" % (directory, owner, metrics.GROUP), tmpfiles)
                self.assertIn("-" + directory, unit(unit_name)["Service"]["ReadWritePaths"].split())
        for name in ("regalia.sysusers.conf", "regalia-audit-ship.sysusers.conf"):
            text = (UNITS / name).read_text()
            self.assertIn("g %s -" % metrics.GROUP, text)
            self.assertNotIn("m prometheus", text)                 # the package owns its user (regalia-kms-24)
        dropin = unit("prometheus-node-exporter.service.d/regalia.conf")["Service"]
        self.assertEqual(dropin["SupplementaryGroups"], metrics.GROUP)
        names = [name for _, files in metrics.WRITERS.values() for name in (files or ())]
        from deploy.baremetal import trails
        self.assertFalse(set(names) & {name + ".prom" for name in trails.TRAILS})     # no basename shared with a shipper's file
        self.assertEqual(unit("regalia-audit-ship@.service")["Service"]["ExecStart"].count("-metrics /run/regalia-metrics/audit-ship/%i.prom"), 1)
