"""deploy/baremetal/os_probe.py: the KMS host's OS-hardening probes (core dumps, hibernation, swap, an
unprivileged service) and the pcscd client check, against a fake host. Moved here with the probes from
the Proxmox guest probe, since removed (ADR-0002 D22, #55)."""
import configparser
import json
import pathlib
import unittest
from pathlib import Path

from deploy.baremetal import os_probe


def measure(host):
    return {name: dict(zip(("value", "why"), os_probe.PROBES[name](host))) for name in os_probe.MEASURED}


SANDBOX = ("kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced")


def measure_sandbox(host):
    measured = measure(host)
    return {name: measured[name] for name in SANDBOX}


ROOT = Path(__file__).resolve().parents[1]
SANDBOX_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", ",".join(os_probe.SANDBOX_PROPERTIES) + ",LoadState")
CAPS_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "CapabilityBoundingSet,AmbientCapabilities,LoadState")
PID_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "MainPID")
EXEC_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "ExecStart,LoadState")
CONFIG = "/etc/regalia-kms/config.json"
ADMISSION = {"listen_address": "0.0.0.0:8443", "runtime_admission": "required", "runtime_admission_path": "/run/regalia/admission.json",
             "node_id": "site-a", "boot_session_path": "/run/regalia/boot-session"}


def exec_start(arguments="-config " + CONFIG, load="loaded"):
    """What `systemctl show -p ExecStart,LoadState` prints for the shipped unit (systemd 257)."""
    binary = "/usr/local/sbin/regalia-kms"
    return ("ExecStart={ path=%s ; argv[]=%s %s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; "
            "code=(null) ; status=0/0 }\nLoadState=%s\n" % (binary, binary, arguments, load))
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
            CONFIG: json.dumps(ADMISSION),
        }
        self.commands = {
            ("systemctl", "show", os_probe.SERVICE, "-p", "LimitCORE,LoadState"): "LimitCORE=0\nLoadState=loaded\n",
            ("systemctl", "show", os_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"):
                "User=regalia-kms\nNoNewPrivileges=yes\nLoadState=loaded\n",
            SANDBOX_SHOW: hardened_sandbox(),
            CAPS_SHOW: show(CapabilityBoundingSet="", AmbientCapabilities="", LoadState="loaded"),
            PID_SHOW: "MainPID=20\n",
            EXEC_SHOW: exec_start(),
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
        self.assertEqual({k: v["value"] for k, v in results.items()}, {k: True for k in SANDBOX}, results)
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
                    # And nothing here touches the host-role controls measured beside them.
                    self.assertTrue(all(v["value"] for k, v in measure(host).items() if k not in SANDBOX))

    def test_the_daemon_s_own_configuration_must_require_a_runtime_lease(self):
        """kms_runtime_admission_required reads the file the unit starts the daemon with (#74)."""
        results = measure(FakeHost())
        self.assertTrue(results["kms_runtime_admission_required"]["value"])
        self.assertIn("runtime_admission required, node site-a, admission file /run/regalia/admission.json",
                      results["kms_runtime_admission_required"]["why"])

        def config(**changed):
            document = dict(ADMISSION)
            for key, value in changed.items():
                if value is None:
                    document.pop(key)
                else:
                    document[key] = value
            return lambda g: g.files.__setitem__(CONFIG, json.dumps(document))

        def started(arguments, load="loaded"):
            return lambda g: g.commands.__setitem__(EXEC_SHOW, exec_start(arguments, load))
        cases = (
            ("the lab value", 'says runtime_admission "disabled-for-lab": this daemon serves with no runtime lease', config(runtime_admission="disabled-for-lab")),
            ("the setting left out", "does not state runtime_admission \"required\" (it says None)", config(runtime_admission=None)),
            ("another word", "does not state runtime_admission \"required\" (it says 'optional')", config(runtime_admission="optional")),
            ("true instead of the word", "does not state runtime_admission \"required\" (it says True)", config(runtime_admission=True)),
            ("no admission file", "requires runtime admission but lacks runtime_admission_path", config(runtime_admission_path=None)),
            ("an empty node ID", "requires runtime admission but lacks node_id", config(node_id="")),
            ("no boot session file", "requires runtime admission but lacks boot_session_path", config(boot_session_path=None)),
            ("a node ID that is not text", "requires runtime admission but lacks node_id", config(node_id=7)),
            ("a configuration that cannot be read", "cannot read the daemon's configuration " + CONFIG, lambda g: g.files.pop(CONFIG)),
            ("not JSON", CONFIG + " is not valid JSON", lambda g: g.files.__setitem__(CONFIG, "{")),
            ("not an object", CONFIG + " is not a JSON object", lambda g: g.files.__setitem__(CONFIG, "[]")),
            ("no -config", "is not started with exactly one absolute -config file", started("-listen 127.0.0.1:8443")),
            ("a relative -config", "is not started with exactly one absolute -config file", started("-config config.json")),
            ("two -config", "is not started with exactly one absolute -config file", started("-config /etc/a.json -config " + CONFIG)),
            ("-config last, with no value", "is not started with exactly one absolute -config file", started("-check-config -config")),
            ("the unit not loaded", "regalia-kms.service is not loaded", started("-config " + CONFIG, "not-found")),
            ("systemctl answers nothing", "regalia-kms.service is not loaded", lambda g: g.commands.pop(EXEC_SHOW)),
            ("another file than the one the unit names", "cannot read the daemon's configuration /etc/other.json", started("-config /etc/other.json")),
        )
        for label, reason, breaker in cases:
            with self.subTest(label):
                host = FakeHost()
                breaker(host)
                results = measure(host)
                self.assertFalse(results["kms_runtime_admission_required"]["value"])
                self.assertIn(reason, results["kms_runtime_admission_required"]["why"])
                # The other control read from that same file: where the file cannot be read at all, it
                # fails for the same reason (what the daemon is started with is unknown, so nothing can
                # be said about its token backends); where the file is readable and only its admission
                # setting is wrong, it is not affected.
                from_the_config = ("kms_runtime_admission_required", "kms_opensc_leaves_piv_cards")
                opensc = results["kms_opensc_leaves_piv_cards"]
                self.assertEqual(opensc["value"], reason not in opensc["why"], opensc["why"])
                self.assertTrue(all(v["value"] for k, v in results.items() if k not in from_the_config))
        # the other spellings of the flag are read too, and it is the file the unit names that counts
        for arguments in ("--config " + CONFIG, "-config=" + CONFIG, "--config=" + CONFIG, "-listen 0.0.0.0:8443 -config " + CONFIG):
            with self.subTest(arguments=arguments):
                host = FakeHost()
                host.commands[EXEC_SHOW] = exec_start(arguments)
                self.assertTrue(measure(host)["kms_runtime_admission_required"]["value"])
        host = FakeHost()
        host.files["/etc/other.json"] = json.dumps(dict(ADMISSION, runtime_admission="disabled-for-lab"))
        host.commands[EXEC_SHOW] = exec_start("-config /etc/other.json")
        self.assertFalse(measure(host)["kms_runtime_admission_required"]["value"])

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


ENV_SHOW = ("systemctl", "show", os_probe.SERVICE, "-p", "Environment,EnvironmentFiles")
OPENSC = "/etc/regalia-kms/opensc.conf"
BOTH_TOKENS = dict(ADMISSION, pkcs11_module_path="/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", yubikey_devices={"yubikey-site-a": "35718625"})
IGNORE_YUBIKEY = (pathlib.Path(__file__).resolve().parent.parent / "deploy/opensc/ignore-yubikey.conf").read_text()


class OpenSCLeavesThePIVCards(unittest.TestCase):
    """kms_opensc_leaves_piv_cards: a daemon with a PKCS#11 module AND YubiKey PIV devices is started with
    an OpenSC configuration that ignores the YubiKey's reader (regalia#541)."""

    control = "kms_opensc_leaves_piv_cards"

    def host(self, config=BOTH_TOKENS, environment="OPENSC_CONF=" + OPENSC, conf=IGNORE_YUBIKEY, environment_files=""):
        host = FakeHost()
        host.files[CONFIG] = json.dumps(config)
        if environment is not None:
            host.commands[ENV_SHOW] = "Environment=%s\nEnvironmentFiles=%s\n" % (environment, environment_files)
        if conf is not None:
            host.files[OPENSC] = conf
        return host

    def verdict(self, host):
        result = measure(host)[self.control]
        return result["value"], result["why"]

    def test_the_shipped_unit_and_the_shipped_configuration_pass(self):
        unit = (pathlib.Path(__file__).resolve().parent.parent / "deploy/systemd/regalia-kms.service").read_text()
        stated = [line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("Environment=")]
        self.assertEqual(stated, ["OPENSC_CONF=" + OPENSC], "the shipped unit must name the daemon's own OpenSC configuration")
        value, why = self.verdict(self.host(environment=" ".join(stated)))
        self.assertTrue(value, why)
        self.assertIn("ignored_readers 'Yubico'", why)
        # and nothing else on the host is disturbed by the measurement
        self.assertTrue(all(v["value"] for v in measure(self.host()).values()))

    def test_one_backend_or_none_has_nothing_to_keep_apart(self):
        for name, config in {"neither": ADMISSION,
                             "only the module": dict(ADMISSION, pkcs11_module_path="/usr/lib/opensc-pkcs11.so"),
                             "only the cards": dict(ADMISSION, yubikey_devices={"yubikey-site-a": "35718625"}),
                             "an empty device map": dict(BOTH_TOKENS, yubikey_devices={}),
                             "an empty module path": dict(BOTH_TOKENS, pkcs11_module_path="")}.items():
            with self.subTest(name):
                value, why = self.verdict(self.host(config=config, environment=None, conf=None))
                self.assertTrue(value, why)
                self.assertIn("nothing to keep apart", why)

    def test_both_backends_need_the_unit_to_name_a_configuration_that_ignores_the_yubikey(self):
        broken = {
            "the unit sets no Environment": (dict(environment=None), "does not set OPENSC_CONF"),
            "the unit sets another variable only": (dict(environment="SOFTHSM2_CONF=/etc/softhsm2.conf"), "does not set OPENSC_CONF"),
            "OPENSC_CONF is not absolute": (dict(environment="OPENSC_CONF=opensc.conf"), "does not set OPENSC_CONF"),
            "the named file is missing": (dict(conf=None), "cannot read the OpenSC configuration " + OPENSC),
            "the file ignores nothing": (dict(conf="app default {\n}\n"), "no ignored_readers entry"),
            "the line is commented out": (dict(conf='app default {\n  # ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            "it ignores another reader": (dict(conf='app default {\n  ignored_readers = "ACS ACR40U";\n}\n'), "no ignored_readers entry"),
            "an empty entry matches nothing": (dict(conf='app default {\n  ignored_readers = "";\n}\n'), "no ignored_readers entry"),
            "the applet configuration, which asks OpenSC to drive the card": (dict(conf=(
                pathlib.Path(__file__).resolve().parent.parent / "deploy/opensc/yubikey-openpgp.conf").read_text()), "no ignored_readers entry"),
            # where OpenSC would not apply the line
            "the line is in another application's block": (dict(conf='app opensc-tool {\n  ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            "the line is at the top level": (dict(conf='ignored_readers = "Yubico";\napp default {\n}\n'), "no ignored_readers entry"),
            "the line is in a nested block": (dict(conf='app default {\n  reader_driver pcsc {\n    ignored_readers = "Yubico";\n  }\n}\n'), "no ignored_readers entry"),
            "an opensc-pkcs11 block exists and the line is only in default": (dict(
                conf='app opensc-pkcs11 {\n  pkcs11 {\n    max_virtual_slots = 32;\n  }\n}\napp default {\n  ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            "a second statement in the block, where the first names another reader": (dict(
                conf='app default {\n  ignored_readers = "ACS";\n  ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            "a # inside a comment hides the rest of the line": (dict(conf='app default {\n  debug = 0; # ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            # entries that would take the HSM's reader too
            "an entry that matches every reader": (dict(conf='app default {\n  ignored_readers = " ";\n}\n'), "no ignored_readers entry"),
            "a single letter": (dict(conf='app default {\n  ignored_readers = "i";\n}\n'), "no ignored_readers entry"),
            "a second app default block has it, the first does not": (dict(
                conf='app default {\n}\napp default {\n  ignored_readers = "Yubico";\n}\n'), "no ignored_readers entry"),
            "the app block is inside another block": (dict(
                conf='reader_driver pcsc {\n  app default {\n    ignored_readers = "Yubico";\n  }\n}\n'), "no ignored_readers entry"),
            "a backslash before the name": (dict(conf='app default {\n  ignored_readers = "\\Yubico";\n}\n'), "no ignored_readers entry"),
            # what OpenSC might not parse proves nothing
            "a missing semicolon swallows the next statement": (dict(
                conf='app default {\n  ignored_readers = "ACS"\n  foo = "Yubico";\n}\n'), "cannot be read as an OpenSC configuration"),
            "braces round the value": (dict(conf='app default {\n  ignored_readers = { "Yubico" };\n}\n'), "cannot be read as an OpenSC configuration"),
            "a block that is not closed": (dict(conf='app default {\n  ignored_readers = "Yubico";\n'), "cannot be read as an OpenSC configuration"),
            "a } that closes nothing, after": (dict(conf='app default {\n  ignored_readers = "Yubico";\n}\n}\n'), "cannot be read as an OpenSC configuration"),
            "a } that closes nothing, before": (dict(conf='}\napp default {\n  ignored_readers = "Yubico";\n}\n'), "cannot be read as an OpenSC configuration"),
            "two values with no comma": (dict(conf='app default {\n  ignored_readers = "ACS" "Yubico";\n}\n'), "cannot be read as an OpenSC configuration"),
            "a list ending in a comma": (dict(conf='app default {\n  ignored_readers = "Yubico",;\n}\n'), "cannot be read as an OpenSC configuration"),
            # what cannot be read
            "a string that never ends": (dict(conf='app default {\n  ignored_readers = "Yubico;\n}\n'), "cannot be read as an OpenSC configuration"),
            "the unit has an EnvironmentFile": (dict(environment_files="/etc/default/regalia-kms (ignore_errors=no)"), "has an EnvironmentFile"),
            "the Environment cannot be parsed": (dict(environment='OPENSC_CONF="/etc/regalia-kms/opensc.conf'), "cannot read the Environment"),
            "OPENSC_CONF is set twice and the last one is not a path": (dict(environment="OPENSC_CONF=" + OPENSC + " OPENSC_CONF=relative.conf"), "does not set OPENSC_CONF"),
        }
        for name, (change, reason) in broken.items():
            with self.subTest(name):
                host = self.host(**change)
                value, why = self.verdict(host)
                self.assertFalse(value, why)
                self.assertIn(reason, why)
                self.assertTrue(all(v["value"] for k, v in measure(host).items() if k != self.control))

    def test_an_entry_counts_when_openSC_would_match_it_against_the_reader_name(self):
        for entry in ("Yubico", "YubiKey", "Yubico YubiKey", "Yubi"):
            with self.subTest(entry):
                value, why = self.verdict(self.host(conf='app default {\n  ignored_readers = "ACS", "%s";\n}\n' % entry))
                self.assertTrue(value, why)

    def test_the_configuration_is_read_as_openSC_reads_it(self):
        accepted = {
            "a list over several lines": 'app default {\n  ignored_readers = "ACS",\n    "Yubico";\n}\n',
            "a block on one line": 'app default { ignored_readers = "Yubico"; }\n',
            "after another statement on the line": 'app default {\n  debug = 0; ignored_readers = "Yubico";\n}\n',
            "an unquoted value": 'app default {\n  ignored_readers = Yubico;\n}\n',
            "a # inside an earlier string": 'app default {\n  ignored_readers = "A#1", "Yubico";\n}\n',
            "in the opensc-pkcs11 block, which is the one preferred": 'app default {\n}\napp opensc-pkcs11 {\n  ignored_readers = "Yubico";\n}\n',
            "the first of two app default blocks has it": 'app default {\n  ignored_readers = "Yubico";\n}\napp default {\n}\n',
            "the application name quoted": 'app "default" {\n  ignored_readers = "Yubico";\n}\n',
            "no space before the brace, CRLF line ends": 'app default{\r\n  ignored_readers = "Yubico";\r\n}\r\n',
            "after a nested block in the same application block": 'app default {\n  reader_driver pcsc {\n    max_send_size = 255;\n  }\n  ignored_readers = "Yubico";\n}\n',
        }
        for name, conf in accepted.items():
            with self.subTest(name):
                value, why = self.verdict(self.host(conf=conf))
                self.assertTrue(value, why)

    def test_a_variable_set_twice_counts_as_the_last(self):
        value, why = self.verdict(self.host(environment="OPENSC_CONF=/etc/other.conf OPENSC_CONF=" + OPENSC))
        self.assertTrue(value, why)

    def test_a_module_path_of_spaces_is_no_module(self):
        value, why = self.verdict(self.host(config=dict(BOTH_TOKENS, pkcs11_module_path="  "), environment=None, conf=None))
        self.assertTrue(value, why)
        self.assertIn("nothing to keep apart", why)

    def test_a_daemon_configuration_that_cannot_be_read_fails_the_control(self):
        host = self.host()
        host.files[CONFIG] = "{"
        value, why = self.verdict(host)
        self.assertFalse(value)
        self.assertIn("not valid JSON", why)


if __name__ == "__main__":
    unittest.main()
