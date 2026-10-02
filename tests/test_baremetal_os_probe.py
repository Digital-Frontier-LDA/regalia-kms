"""deploy/baremetal/os_probe.py: the KMS host's OS-hardening probes (core dumps, hibernation, swap, an
unprivileged service) and the pcscd client check, against a fake host. Moved here with the probes from
the deprecated Proxmox host probe (ADR-0002 D22, #55)."""
import configparser
import unittest
from pathlib import Path

from deploy.baremetal import os_probe


def measure(host):
    return {name: dict(zip(("value", "why"), os_probe.PROBES[name](host))) for name in os_probe.MEASURED}


def measure_sandbox(host):
    return {name: dict(zip(("value", "why"), os_probe.SANDBOX_PROBES[name](host))) for name in os_probe.SANDBOX_MEASURED}


ROOT = Path(__file__).resolve().parents[1]
SANDBOX_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", ",".join(os_probe.SANDBOX_PROPERTIES) + ",LoadState")
CAPS_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "CapabilityBoundingSet,AmbientCapabilities,LoadState")
PID_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "MainPID")
# What `systemctl show` prints for a unit that sets none of this (measured, systemd 257).
UNSET_BOUNDING_SET = ("cap_chown cap_dac_override cap_dac_read_search cap_fowner cap_fsetid cap_kill cap_setgid "
                      "cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service cap_net_broadcast cap_net_admin "
                      "cap_net_raw cap_ipc_lock cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot cap_sys_ptrace "
                      "cap_sys_pacct cap_sys_admin cap_sys_boot cap_sys_nice cap_sys_resource cap_sys_time "
                      "cap_sys_tty_config cap_mknod cap_lease cap_audit_write cap_audit_control cap_setfcap "
                      "cap_mac_override cap_mac_admin cap_syslog cap_wake_alarm cap_block_suspend cap_audit_read "
                      "cap_perfmon cap_bpf cap_checkpoint_restore")


def show(**properties):
    return "".join(f"{k}={v}\n" for k, v in properties.items())


def hardened_sandbox(**changed):
    props = dict(ProtectSystem="strict", ProtectHome="yes", PrivateTmp="yes", ProtectKernelTunables="yes",
                 ProtectKernelModules="yes", ProtectKernelLogs="yes", ProtectControlGroups="yes",
                 RestrictSUIDSGID="yes", LockPersonality="yes", LoadState="loaded")
    props.update(changed)
    return show(**props)


def proc_status(**changed):
    caps = dict(CapInh="0000000000000000", CapPrm="0000000000000000", CapEff="0000000000000000",
                CapBnd="0000000000000000", CapAmb="0000000000000000")
    caps.update(changed)
    return "Name:\tregalia-kms\nUid:\t995\t995\t995\t995\n" + "".join(f"{k}:\t{v}\n" for k, v in caps.items())


class FakeHost:
    """A hardened KMS host by default; each test breaks exactly one thing and asks for the verdict."""

    def __init__(self):
        self.files = {
            "/proc/sys/fs/suid_dumpable": "0\n",
            "/proc/sys/kernel/core_pattern": "|/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
            "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/mapper/root ro quiet\n",
            "/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n",
            "/sys/module/apparmor/parameters/enabled": "Y\n",
            "/proc/20/status": proc_status(),
            "/proc/20/attr/apparmor/current": "regalia-kms (enforce)\n",
        }
        self.commands = {
            ("systemctl", "show", os_probe.SERVICE, "-p", "LimitCORE,LoadState"): "LimitCORE=0\nLoadState=loaded\n",
            ("systemctl", "show", os_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"):
                "User=regalia-kms\nNoNewPrivileges=yes\nLoadState=loaded\n",
            SANDBOX_SHOW: hardened_sandbox(),
            CAPS_SHOW: show(CapabilityBoundingSet="", AmbientCapabilities="", LoadState="loaded"),
            PID_SHOW: "MainPID=20\n",
            ("systemd-analyze", "cat-config", "systemd/coredump.conf"): "[Coredump]\n#Storage=external\nStorage=none\n",
            ("systemd-analyze", "cat-config", "systemd/sleep.conf"): "[Sleep]\n",
            # The real layout (measured with pcsc_scan): the server endpoint carries the socket path,
            # the client endpoint shows `*` and is found by inode.
            ("ss", "-xpn"): 'u_str ESTAB 0 0 /run/pcscd/pcscd.comm 111 * 222 users:(("pcscd",pid=10,fd=5))\n'
                            'u_str ESTAB 0 0 * 222 * 111 users:(("regalia-kms",pid=20,fd=9))\n',
        }
        self.links = {"/proc/20/exe": "/usr/local/sbin/regalia-kms", "/proc/10/exe": "/usr/sbin/pcscd"}
        for target in os_probe.HIBERNATING_TARGETS:
            self.commands[("systemctl", "is-enabled", target)] = "masked\n"
        self.installed = set()

    def read(self, path):
        return self.files.get(path)

    def listdir(self, path):
        return []

    def run(self, argv):
        out = self.commands.get(tuple(argv))
        return (0, out) if out is not None else (1, "")

    def which(self, tool):
        return f"/usr/bin/{tool}" if tool in self.installed else None

    def readlink(self, path):
        return self.links.get(path)


def add_pcscd_client(host, inode, name, pid, exe):
    server = str(900 + inode)
    host.commands[("ss", "-xpn")] += (
        f'u_str ESTAB 0 0 /run/pcscd/pcscd.comm {server} * {inode} users:(("pcscd",pid=10,fd=7))\n'
        f'u_str ESTAB 0 0 * {inode} * {server} users:(("{name}",pid={pid},fd=3))\n')
    if exe:
        host.links[f"/proc/{pid}/exe"] = exe


class OSProbeTests(unittest.TestCase):
    def verdict(self, host, control):
        return measure(host)[control]["value"]

    def test_a_hardened_host_passes_every_measured_control(self):
        results = measure(FakeHost())
        self.assertEqual({k: v["value"] for k, v in results.items()}, {k: True for k in os_probe.MEASURED})

    def test_each_control_fails_on_the_one_thing_that_breaks_it(self):
        cases = {
            "core_dumps_disabled": [
                lambda g: g.commands.__setitem__(("systemctl", "show", os_probe.SERVICE, "-p", "LimitCORE,LoadState"),
                                                 "LimitCORE=infinity\nLoadState=loaded\n"),
                lambda g: g.files.__setitem__("/proc/sys/fs/suid_dumpable", "2\n"),
                lambda g: g.commands.__setitem__(("systemd-analyze", "cat-config", "systemd/coredump.conf"), "[Coredump]\n"),
                # A Storage=none systemd ignores, because it is outside [Coredump].
                lambda g: g.commands.__setitem__(("systemd-analyze", "cat-config", "systemd/coredump.conf"),
                                                 "[Coredump]\nStorage=external\n[Other]\nStorage=none\n"),
                # The kernel ignores LimitCORE for ANY pipe: an unknown handler gets the memory.
                lambda g: g.files.__setitem__("/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport %p %s\n"),
                lambda g: g.commands.__setitem__(("systemctl", "show", os_probe.SERVICE, "-p", "LimitCORE,LoadState"),
                                                 "LimitCORE=0\nLoadState=not-found\n"),
            ],
            "hibernation_disabled": [
                lambda g: g.files.__setitem__("/proc/cmdline", "root=/dev/sda1 resume=/dev/sda2\n"),
                lambda g: g.commands.__setitem__(("systemctl", "is-enabled", "hybrid-sleep.target"), "static\n"),
            ],
            "swap_disabled_or_encrypted": [
                lambda g: g.files.__setitem__("/proc/swaps", "Filename\tType\n/dev/sda2 partition 1 0 -2\n"),
                lambda g: g.files.__setitem__("/proc/swaps", "Filename\tType\n/swapfile file 1 0 -2\n"),
                lambda g: g.files.pop("/proc/swaps"),
            ],
            "kms_service_unprivileged": [
                lambda g: g.commands.__setitem__(("systemctl", "show", os_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"),
                                                 "User=\nNoNewPrivileges=yes\nLoadState=loaded\n"),
                lambda g: g.commands.__setitem__(("systemctl", "show", os_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"),
                                                 "User=regalia-kms\nNoNewPrivileges=no\nLoadState=loaded\n"),
            ],
        }
        for control, breakers in cases.items():
            for index, breaker in enumerate(breakers):
                with self.subTest(control=control, case=index):
                    host = FakeHost()
                    breaker(host)
                    self.assertFalse(self.verdict(host, control), measure(host)[control]["why"])
                    # One broken thing breaks one control, not the whole report.
                    others = {k: v["value"] for k, v in measure(host).items() if k != control}
                    self.assertTrue(all(others.values()), others)

    def test_the_alternatives_that_are_also_hardened(self):
        host = FakeHost()
        for target in os_probe.HIBERNATING_TARGETS:
            host.commands[("systemctl", "is-enabled", target)] = "static\n"
        host.commands[("systemd-analyze", "cat-config", "systemd/sleep.conf")] = \
            "[Sleep]\nAllowHibernation=no\nAllowHybridSleep=no\nAllowSuspendThenHibernate=no\n"
        self.assertTrue(self.verdict(host, "hibernation_disabled"))
        host.commands[("systemd-analyze", "cat-config", "systemd/sleep.conf")] = \
            "[Sleep]\n[Other]\nAllowHibernation=no\nAllowHybridSleep=no\nAllowSuspendThenHibernate=no\n"
        self.assertFalse(self.verdict(host, "hibernation_disabled"), "keys outside [Sleep] are ignored by systemd")

        host = FakeHost()
        host.files["/proc/sys/kernel/core_pattern"] = "core\n"
        host.commands.pop(("systemd-analyze", "cat-config", "systemd/coredump.conf"))
        self.assertTrue(self.verdict(host, "core_dumps_disabled"), "a non-piped pattern relies on LimitCORE=0")

        host = FakeHost()
        host.files["/proc/swaps"] = "Filename\tType\n/dev/dm-3 partition 1 0 -2\n"
        host.files["/sys/class/block/dm-3/dm/uuid"] = "CRYPT-PLAIN-swap\n"
        self.assertTrue(self.verdict(host, "swap_disabled_or_encrypted"))
        host.files["/sys/class/block/dm-3/dm/uuid"] = "LVM-abcdef\n"
        self.assertFalse(self.verdict(host, "swap_disabled_or_encrypted"), "a plain LVM volume is not encrypted")

    def test_a_hardened_unit_passes_every_sandbox_control(self):
        results = measure_sandbox(FakeHost())
        self.assertEqual({k: v["value"] for k, v in results.items()}, {k: True for k in os_probe.SANDBOX_MEASURED}, results)
        self.assertIn("allowed: none", results["kms_capabilities_minimal"]["why"])
        self.assertIn("'regalia-kms' in enforce mode", results["kms_apparmor_enforced"]["why"])

    def test_each_sandbox_control_fails_on_the_one_thing_that_breaks_it(self):
        def sandbox(**changed):
            return lambda g: g.commands.__setitem__(SANDBOX_SHOW, hardened_sandbox(**changed))

        def caps(**changed):
            props = dict(CapabilityBoundingSet="", AmbientCapabilities="", LoadState="loaded")
            props.update(changed)
            return lambda g: g.commands.__setitem__(CAPS_SHOW, show(**props))

        def label(text):
            return lambda g: g.files.__setitem__("/proc/20/attr/apparmor/current", text)

        cases = {
            "kms_service_sandboxed": [
                # Each property alone, at the value a unit that never set it reports.
                sandbox(ProtectSystem="no"), sandbox(ProtectHome="no"), sandbox(PrivateTmp="no"),
                sandbox(ProtectKernelTunables="no"), sandbox(ProtectKernelModules="no"),
                sandbox(ProtectKernelLogs="no"), sandbox(ProtectControlGroups="no"),
                sandbox(RestrictSUIDSGID="no"), sandbox(LockPersonality="no"),
                # Weaker settings that still read as "set".
                sandbox(ProtectSystem="full"), sandbox(ProtectSystem="yes"), sandbox(ProtectHome="read-only"),
                sandbox(LoadState="not-found"),
                # A systemd too old to know a property prints nothing for it.
                lambda g: g.commands.__setitem__(SANDBOX_SHOW, hardened_sandbox().replace("LockPersonality=yes\n", "")),
            ],
            "kms_capabilities_minimal": [
                caps(CapabilityBoundingSet=UNSET_BOUNDING_SET),
                caps(CapabilityBoundingSet="cap_net_bind_service"),
                caps(AmbientCapabilities="cap_net_bind_service"),
                caps(LoadState="not-found"),
                lambda g: g.commands.__setitem__(CAPS_SHOW, "AmbientCapabilities=\nLoadState=loaded\n"),
                # The unit file is right but the process was started before it was: the kernel's view wins.
                lambda g: g.files.__setitem__("/proc/20/status", proc_status(CapBnd="000001ffffffffff")),
                lambda g: g.files.__setitem__("/proc/20/status", proc_status(CapEff="0000000000000400")),
                lambda g: g.files.__setitem__("/proc/20/status", proc_status(CapAmb="0000000000000400")),
                lambda g: g.files.__setitem__("/proc/20/status", "Name:\tregalia-kms\n"),
                lambda g: g.files.pop("/proc/20/status"),
            ],
            "kms_apparmor_enforced": [
                lambda g: g.files.__setitem__("/sys/module/apparmor/parameters/enabled", "N\n"),
                lambda g: g.files.pop("/sys/module/apparmor/parameters/enabled"),
                label("unconfined\n"), label("regalia-kms (complain)\n"), label("regalia-kms (kill)\n"),
                label("unconfined (enforce)\n"), label(""),
                lambda g: g.files.pop("/proc/20/attr/apparmor/current"),
            ],
        }
        for control, breakers in cases.items():
            for index, breaker in enumerate(breakers):
                with self.subTest(control=control, case=index):
                    host = FakeHost()
                    breaker(host)
                    results = measure_sandbox(host)
                    self.assertFalse(results[control]["value"], results[control]["why"])
                    others = {k: v["value"] for k, v in results.items() if k != control}
                    self.assertTrue(all(others.values()), others)
                    # And nothing here touches the controls the signed evidence already carries.
                    self.assertTrue(all(v["value"] for v in measure(host).values()))

    def test_a_stopped_service_cannot_prove_its_capabilities_or_its_confinement(self):
        for pid in ("MainPID=0\n", "MainPID=\n", ""):
            with self.subTest(pid=pid):
                host = FakeHost()
                host.commands[PID_SHOW] = pid
                results = measure_sandbox(host)
                self.assertTrue(results["kms_service_sandboxed"]["value"])
                for control in ("kms_capabilities_minimal", "kms_apparmor_enforced"):
                    self.assertFalse(results[control]["value"])
                    self.assertIn("not running", results[control]["why"])

    def test_the_sandbox_alternatives_that_are_also_hardened(self):
        host = FakeHost()
        host.commands[SANDBOX_SHOW] = hardened_sandbox(ProtectHome="tmpfs", PrivateTmp="disconnected", ProtectControlGroups="strict")
        self.assertTrue(measure_sandbox(host)["kms_service_sandboxed"]["value"])
        # A kernel older than 5.8 has only attr/current.
        host = FakeHost()
        host.files["/proc/20/attr/current"] = host.files.pop("/proc/20/attr/apparmor/current")
        self.assertTrue(measure_sandbox(host)["kms_apparmor_enforced"]["value"])

    def test_the_failure_names_the_capabilities_beyond_the_allowed_set(self):
        host = FakeHost()
        host.commands[CAPS_SHOW] = show(CapabilityBoundingSet="cap_net_bind_service cap_sys_admin", AmbientCapabilities="", LoadState="loaded")
        why = measure_sandbox(host)["kms_capabilities_minimal"]["why"]
        self.assertIn("2 capabilities beyond the allowed set: cap_net_bind_service cap_sys_admin", why)

    def test_an_allowed_capability_is_allowed_in_the_unit_and_in_the_kernel(self):
        host = FakeHost()
        host.commands[CAPS_SHOW] = show(CapabilityBoundingSet="cap_net_bind_service", AmbientCapabilities="", LoadState="loaded")
        host.files["/proc/20/status"] = proc_status(CapBnd="0000000000000400")
        allowed = os_probe.ALLOWED_CAPABILITIES
        try:
            os_probe.ALLOWED_CAPABILITIES = {"cap_net_bind_service": 10}
            self.assertTrue(measure_sandbox(host)["kms_capabilities_minimal"]["value"])
            host.files["/proc/20/status"] = proc_status(CapBnd="0000000000200400")   # + cap_sys_admin
            self.assertFalse(measure_sandbox(host)["kms_capabilities_minimal"]["value"])
        finally:
            os_probe.ALLOWED_CAPABILITIES = allowed

    def test_the_shipped_drop_in_states_every_measured_sandbox_setting(self):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        parser.optionxform = str
        parser.read(ROOT / "deploy" / "baremetal" / "regalia-kms-hardening.conf.example", encoding="utf-8")
        service = parser["Service"]
        for name, want in os_probe.SANDBOX_PROPERTIES.items():
            self.assertIn(service.get(name), want, name)
        # An empty assignment is the empty set; a missing line is every capability.
        self.assertEqual(service.get("CapabilityBoundingSet"), " ".join(sorted(os_probe.ALLOWED_CAPABILITIES)))
        self.assertEqual(service.get("AmbientCapabilities"), "")
        # No "-" prefix: with one, systemd starts the service unconfined when the profile is missing.
        self.assertRegex(service.get("AppArmorProfile", ""), r"^[A-Za-z0-9_.][A-Za-z0-9_.-]*$")

    def test_pcscd_clients_must_all_be_the_kms_binary(self):
        self.assertTrue(os_probe.pcscd_clients(FakeHost())[0])
        for breaker in (lambda g: add_pcscd_client(g, 444, "pcsc_scan", 30, "/usr/bin/pcsc_scan"),
                        lambda g: add_pcscd_client(g, 555, "regalia-kms", 31, "/tmp/regalia-kms"),
                        lambda g: g.commands.pop(("ss", "-xpn"))):
            with self.subTest():
                host = FakeHost()
                breaker(host)
                self.assertFalse(os_probe.pcscd_clients(host)[0])


if __name__ == "__main__":
    unittest.main()
