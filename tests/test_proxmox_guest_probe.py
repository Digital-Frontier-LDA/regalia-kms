import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from deploy.proxmox import guest_probe
from deploy.proxmox.guest_probe import compare, measure

EXAMPLE = Path(__file__).parents[1] / "deploy" / "proxmox" / "evidence.example.json"


class FakeGuest:
    """A hardened guest by default; each test breaks exactly one thing and asks for the verdict."""

    def __init__(self):
        self.files = {
            "/proc/sys/fs/suid_dumpable": "0\n",
            "/proc/sys/kernel/core_pattern": "|/lib/systemd/systemd-coredump %P %u %g %s %t %c %h\n",
            "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/mapper/root ro quiet\n",
            "/proc/swaps": "Filename\tType\tSize\tUsed\tPriority\n",
        }
        self.commands = {
            ("systemctl", "show", guest_probe.SERVICE, "-p", "LimitCORE,LoadState"): "LimitCORE=0\nLoadState=loaded\n",
            ("systemctl", "show", guest_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"):
                "User=regalia-kms\nNoNewPrivileges=yes\nLoadState=loaded\n",
            ("systemd-analyze", "cat-config", "systemd/coredump.conf"): "[Coredump]\n#Storage=external\nStorage=none\n",
            ("systemd-analyze", "cat-config", "systemd/sleep.conf"): "[Sleep]\n",
            # The real layout (measured with pcsc_scan): the server endpoint carries the socket path,
            # the client endpoint shows `*` and is found by inode.
            ("ss", "-xpn"): 'u_str ESTAB 0 0 /run/pcscd/pcscd.comm 111 * 222 users:(("pcscd",pid=10,fd=5))\n'
                            'u_str ESTAB 0 0 * 222 * 111 users:(("regalia-kms",pid=20,fd=9))\n',
        }
        self.links = {"/proc/20/exe": "/usr/local/sbin/regalia-kms", "/proc/10/exe": "/usr/sbin/pcscd"}
        for target in guest_probe.HIBERNATING_TARGETS:
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


def add_pcscd_client(guest, inode, name, pid, exe):
    server = str(900 + inode)
    guest.commands[("ss", "-xpn")] += (
        f'u_str ESTAB 0 0 /run/pcscd/pcscd.comm {server} * {inode} users:(("pcscd",pid=10,fd=7))\n'
        f'u_str ESTAB 0 0 * {inode} * {server} users:(("{name}",pid={pid},fd=3))\n')
    if exe:
        guest.links[f"/proc/{pid}/exe"] = exe


class GuestProbeTests(unittest.TestCase):
    def verdict(self, guest, control):
        return measure(guest)[control]["value"]

    def test_a_hardened_guest_passes_every_measured_control(self):
        results = measure(FakeGuest())
        self.assertEqual({k: v["value"] for k, v in results.items()}, {k: True for k in guest_probe.MEASURED})

    def test_each_control_fails_on_the_one_thing_that_breaks_it(self):
        cases = {
            "core_dumps_disabled": [
                lambda g: g.commands.__setitem__(("systemctl", "show", guest_probe.SERVICE, "-p", "LimitCORE,LoadState"),
                                                 "LimitCORE=infinity\nLoadState=loaded\n"),
                lambda g: g.files.__setitem__("/proc/sys/fs/suid_dumpable", "2\n"),
                lambda g: g.commands.__setitem__(("systemd-analyze", "cat-config", "systemd/coredump.conf"), "[Coredump]\n"),
                # A Storage=none systemd ignores, because it is outside [Coredump].
                lambda g: g.commands.__setitem__(("systemd-analyze", "cat-config", "systemd/coredump.conf"),
                                                 "[Coredump]\nStorage=external\n[Other]\nStorage=none\n"),
                # The kernel ignores LimitCORE for ANY pipe: an unknown handler gets the memory.
                lambda g: g.files.__setitem__("/proc/sys/kernel/core_pattern", "|/usr/share/apport/apport %p %s\n"),
                lambda g: g.commands.__setitem__(("systemctl", "show", guest_probe.SERVICE, "-p", "LimitCORE,LoadState"),
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
                lambda g: g.commands.__setitem__(("systemctl", "show", guest_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"),
                                                 "User=\nNoNewPrivileges=yes\nLoadState=loaded\n"),
                lambda g: g.commands.__setitem__(("systemctl", "show", guest_probe.SERVICE, "-p", "User,NoNewPrivileges,LoadState"),
                                                 "User=regalia-kms\nNoNewPrivileges=no\nLoadState=loaded\n"),
            ],
            "direct_token_clients_absent": [
                lambda g: g.installed.add("ykman"),
                # Another client, visible only through the inode of its `*` endpoint.
                lambda g: add_pcscd_client(g, 444, "pcsc_scan", 30, "/usr/bin/pcsc_scan"),
                # A process that NAMES itself regalia-kms but runs another binary.
                lambda g: add_pcscd_client(g, 555, "regalia-kms", 31, "/tmp/regalia-kms"),
                # A client whose endpoint ss cannot attribute at all.
                lambda g: g.commands.__setitem__(("ss", "-xpn"), g.commands[("ss", "-xpn")] +
                                                 'u_str ESTAB 0 0 /run/pcscd/pcscd.comm 666 * 777 users:(("pcscd",pid=10,fd=8))\n'),
                lambda g: g.commands.pop(("ss", "-xpn")),
            ],
        }
        for control, breakers in cases.items():
            for index, breaker in enumerate(breakers):
                with self.subTest(control=control, case=index):
                    guest = FakeGuest()
                    breaker(guest)
                    self.assertFalse(self.verdict(guest, control), measure(guest)[control]["why"])
                    # One broken thing breaks one control, not the whole report.
                    others = {k: v["value"] for k, v in measure(guest).items() if k != control}
                    self.assertTrue(all(others.values()), others)

    def test_the_alternatives_that_are_also_hardened(self):
        guest = FakeGuest()
        for target in guest_probe.HIBERNATING_TARGETS:
            guest.commands[("systemctl", "is-enabled", target)] = "static\n"
        guest.commands[("systemd-analyze", "cat-config", "systemd/sleep.conf")] = \
            "[Sleep]\nAllowHibernation=no\nAllowHybridSleep=no\nAllowSuspendThenHibernate=no\n"
        self.assertTrue(self.verdict(guest, "hibernation_disabled"))
        guest.commands[("systemd-analyze", "cat-config", "systemd/sleep.conf")] = \
            "[Sleep]\n[Other]\nAllowHibernation=no\nAllowHybridSleep=no\nAllowSuspendThenHibernate=no\n"
        self.assertFalse(self.verdict(guest, "hibernation_disabled"), "keys outside [Sleep] are ignored by systemd")

        guest = FakeGuest()
        guest.files["/proc/sys/kernel/core_pattern"] = "core\n"
        guest.commands.pop(("systemd-analyze", "cat-config", "systemd/coredump.conf"))
        self.assertTrue(self.verdict(guest, "core_dumps_disabled"), "a non-piped pattern relies on LimitCORE=0")

        guest = FakeGuest()
        guest.files["/proc/swaps"] = "Filename\tType\n/dev/dm-3 partition 1 0 -2\n"
        guest.files["/sys/class/block/dm-3/dm/uuid"] = "CRYPT-PLAIN-swap\n"
        self.assertTrue(self.verdict(guest, "swap_disabled_or_encrypted"))
        guest.files["/sys/class/block/dm-3/dm/uuid"] = "LVM-abcdef\n"
        self.assertFalse(self.verdict(guest, "swap_disabled_or_encrypted"), "a plain LVM volume is not encrypted")

    def test_evidence_that_claims_what_the_guest_lacks_is_refused(self):
        evidence = json.loads(EXAMPLE.read_text())
        guest = FakeGuest()
        self.assertEqual(compare(measure(guest), evidence), [])
        guest.files["/proc/swaps"] = "Filename\tType\n/dev/sda2 partition 1 0 -2\n"
        problems = compare(measure(guest), evidence)
        self.assertEqual(len(problems), 1)
        self.assertIn("swap_disabled_or_encrypted", problems[0])
        # Evidence that does not claim the control is not contradicted by it.
        honest = copy.deepcopy(evidence)
        honest["guest"]["swap_disabled_or_encrypted"] = False
        self.assertEqual(compare(measure(guest), honest), [])

    def test_the_command_line_exit_status_follows_the_verdict(self):
        evidence = json.loads(EXAMPLE.read_text())
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(evidence, f)
            f.flush()
            guest = FakeGuest()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(guest_probe.main(["--evidence", f.name], host=guest), 0)
                guest.installed.add("pkcs11-tool")
                self.assertEqual(guest_probe.main(["--evidence", f.name], host=guest), 1)
                self.assertEqual(guest_probe.main([], host=guest), 1)
        report = io.StringIO()
        with contextlib.redirect_stdout(report):
            guest_probe.main([], host=FakeGuest())
        self.assertEqual(json.loads(report.getvalue())["attested_not_measured"], list(guest_probe.UNMEASURED))


if __name__ == "__main__":
    unittest.main()
