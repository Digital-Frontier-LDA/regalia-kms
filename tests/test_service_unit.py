import configparser
import json
import unittest
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy" / "systemd"

# Hardening every Regalia unit must carry, whatever it does.
SHARED_HARDENING = {
    "NoNewPrivileges": "yes",
    "PrivateDevices": "yes",
    "PrivateTmp": "yes",
    "ProtectHome": "yes",
    "ProtectSystem": "strict",
    "RestrictNamespaces": "yes",
    "RestrictSUIDSGID": "yes",
    "RestrictRealtime": "yes",
    "SystemCallArchitectures": "native",
    "UMask": "0077",
    "LimitCORE": "0",
}


def read_service(name):
    """Parse one unit's [Service] section.

    strict=False on purpose: systemd allows a directive to repeat, and repeats
    ACCUMULATE rather than override -- LoadCredential= is normally written once
    per credential. A strict parser raises DuplicateOptionError on a perfectly
    valid unit, which is why regalia-sops-kms.service could not be covered by
    the previous version of this file and went unverified.
    """
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(UNITS / name, encoding="utf-8")
    return parser["Service"]


class ServiceUnitTests(unittest.TestCase):
    """Both shipped units are checked, not just the daemon's.

    The sidecar unit was never parsed by any test. Its hardening happened to
    match, which is worth knowing rather than assuming: unverified, it could
    have drifted at any point and nothing would have said so. The sidecar holds
    the mTLS client key the daemon authenticates, so it is not the lesser of
    the two processes.
    """

    def test_every_shipped_unit_carries_the_shared_hardening(self):
        units = sorted(p.name for p in UNITS.glob("*.service"))
        self.assertGreaterEqual(len(units), 2, "fewer units than expected; this test may be checking only one")
        for name in units:
            service = read_service(name)
            with self.subTest(unit=name):
                for setting, expected in SHARED_HARDENING.items():
                    self.assertEqual(service.get(setting), expected, f"{name}: {setting}")

    def test_every_unit_runs_as_a_dedicated_unprivileged_identity(self):
        for name in sorted(p.name for p in UNITS.glob("*.service")):
            service = read_service(name)
            with self.subTest(unit=name):
                user = service.get("User")
                self.assertTrue(user, f"{name} does not set User")
                self.assertNotEqual(user, "root", f"{name} runs as root")
                self.assertEqual(service.get("Group"), user, f"{name}: Group should match User")

    def test_units_do_not_share_a_service_account(self):
        """Two services under one account can read each other's credentials."""
        accounts = {}
        for name in sorted(p.name for p in UNITS.glob("*.service")):
            accounts.setdefault(read_service(name).get("User"), []).append(name)
        shared = {user: names for user, names in accounts.items() if len(names) > 1}
        self.assertEqual(shared, {}, f"units share a service account: {shared}")

    def test_daemon_takes_its_config_from_a_fixed_path_and_keeps_state(self):
        service = read_service("regalia-kms.service")
        self.assertNotIn("--listen", service["ExecStart"])
        self.assertIn("-config /etc/regalia-kms/config.json", service["ExecStart"])
        self.assertEqual(service["StateDirectory"], "regalia-kms")
        self.assertEqual(service["StateDirectoryMode"], "0700")

    def test_sidecar_socket_directory_is_private(self):
        """The socket's protection is the directory, and nothing asserted it.

        net.Listen creates the socket with the umask applied and the adapter's
        Chmod to 0600 runs afterwards, so a permissive umask leaves a window in
        which the socket is world-connectable -- and a connection accepted in that
        window survives the Chmod. UMask=0077 is covered by SHARED_HARDENING;
        RuntimeDirectoryMode was in the unit and asserted by no test, so deleting
        it would have left the default 0755 with nothing to say so.

        ServeUnix now refuses to start on a group- or world-writable directory, so
        this is belt and braces rather than the only guard -- which is the point:
        the property is stated in the unit AND checked by the process that depends
        on it, because previously it was stated in one and assumed by the other.

        Be exact about what 0700 buys, because the modes gate different syscalls.
        connect(2) needs write on the SOCKET, so the single trust domain the
        sidecar's authorization model rests on comes from the socket being 0600
        under a dedicated account -- not from this. unlink(2) needs write on the
        DIRECTORY, so a writable one lets an attacker replace the socket with their
        own listener, which is what ServeUnix refuses at runtime. 0700 adds that
        other accounts cannot enumerate the runtime directory.

        Pinned because it was in the unit and asserted by nothing, not because it
        is the load-bearing invariant. The load-bearing one is the account plus the
        socket mode, and test_units_do_not_share_a_service_account covers the half
        of that which lives here.
        """
        service = read_service("regalia-sops-kms.service")
        self.assertEqual(service.get("RuntimeDirectory"), "regalia-sops-kms")
        self.assertEqual(service.get("RuntimeDirectoryMode"), "0700")

    def test_sidecar_socket_lives_inside_the_runtime_directory_it_is_protected_by(self):
        """The 0700 guarantee only covers the socket if the socket is in it.

        RuntimeDirectory=regalia-sops-kms gives /run/regalia-sops-kms at 0700, and
        the sidecar's config chooses socket_path independently. They agree by
        convention and nothing checked it -- so a socket_path pointing anywhere
        else silently leaves the directory protection covering an empty directory,
        which is the same declared-in-two-places defect as the capability matrix
        (#73) and the custody rules (#78).

        ServeUnix refuses a group- or world-writable directory at runtime, so the
        worst destinations still fail closed. This closes the quieter case: a
        directory that is merely not private, where the trust boundary the
        multiplexer model rests on is wider than the unit implies and nothing
        anywhere says so.
        """
        service = read_service("regalia-sops-kms.service")
        runtime = service.get("RuntimeDirectory")
        self.assertTrue(runtime, "the sidecar declares no RuntimeDirectory")

        config = json.loads((ROOT / "adapters" / "sops" / "config.example.json").read_text(encoding="utf-8"))
        socket_path = PurePosixPath(config["socket_path"])
        expected = PurePosixPath("/run") / runtime
        self.assertEqual(
            socket_path.parent, expected,
            f"socket_path {socket_path} is not inside {expected}, so RuntimeDirectoryMode=0700 "
            f"protects a directory the socket is not in")

    def test_no_two_units_share_a_runtime_directory(self):
        """A shared RuntimeDirectory is a shared trust domain.

        Two services pointed at one runtime directory can reach each other's
        sockets, which merges exactly the boundary the sidecar's authorization
        model depends on: every operation through it is authorized and audited as
        one principal, and that is only honest while one caller can reach it.
        """
        directories = {}
        for name in sorted(p.name for p in UNITS.glob("*.service")):
            runtime = read_service(name).get("RuntimeDirectory")
            if runtime:
                directories.setdefault(runtime, []).append(name)
        shared = {d: names for d, names in directories.items() if len(names) > 1}
        self.assertEqual(shared, {}, f"units share a runtime directory: {shared}")

    def test_sidecar_keeps_no_persistent_state(self):
        """The sidecar holds no journal and no policy state, so a StateDirectory
        would be somewhere for material to accumulate unwatched."""
        service = read_service("regalia-sops-kms.service")
        self.assertIsNone(service.get("StateDirectory"))
