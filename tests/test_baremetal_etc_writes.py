"""Nothing in deploy/ or the units writes one of this host's own /etc files by its /etc name (#61, the dm-verity design).

/ is a tmpfs on a verity-/usr host and /etc is made from the image at every boot (units/00-regalia-etc.tmpfiles.conf):
this host's own files live on /var and are written there (deploy/baremetal/hostpaths.py). The scanner is
tests/etc_writes.py. Every refusal names the file, the line and the path.

The MUTANT CONTROL: each regression below is planted into a copy of the real file (or a real file with a line
added) and must be refused BY NAME; each no-op must pass. Without it, a scanner that finds nothing would pass."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import etc_writes  # noqa: E402

ROOT = etc_writes.ROOT


def text(rel):
    return (ROOT / rel).read_text()


def mutate(rel, old, new):
    source = text(rel)
    if old is None:
        return {rel: source + new}
    assert source.count(old) == 1, "%s: the mutant's anchor %r is not exactly once in it" % (rel, old)
    return {rel: source.replace(old, new)}


def add_to_section(rel, section, line):
    source = text(rel)
    assert source.count("[%s]\n" % section) == 1
    return {rel: source.replace("[%s]\n" % section, "[%s]\n%s\n" % (section, line))}


# (name, overrides, the per-host /etc path the finding must name, the file it must be found in)
MUTANTS = [
    # the real regressions: each writer back to the /etc name
    ("enrol node.json", lambda: mutate("deploy/baremetal/enrol.py", '_install(journal, "config", stored(NODE_JSON)', '_install(journal, "config", NODE_JSON'),
     "/etc/regalia/node.json", "deploy/baremetal/enrol.py"),
    ("enrol chrony.conf", lambda: mutate("deploy/baremetal/enrol.py", '_install(journal, "config", stored(CHRONY_CONF)', '_install(journal, "config", CHRONY_CONF'),
     "/etc/chrony/regalia.conf", "deploy/baremetal/enrol.py"),
    ("enrol WG-SERVICE key", lambda: mutate("deploy/baremetal/enrol.py", 'wg_key(journal, "wg_service", stored(wg_service_key), run)', 'wg_key(journal, "wg_service", wg_service_key, run)'),
     "/etc/regalia/wg-service.key", "deploy/baremetal/enrol.py"),
    ("rejoin etcd.conf.yml", lambda: mutate("deploy/baremetal/rejoin.py", "host.write(etcdconf.STORED_CONFIG, text)", "host.write(etcdconf.CONFIG_PATH, text)"),
     "/etc/regalia/etcd.conf.yml", "deploy/baremetal/rejoin.py"),
    ("etcdconf's stored name", lambda: mutate("deploy/baremetal/etcdconf.py", "STORED_CONFIG = hostpaths.persistent(CONFIG_PATH)", "STORED_CONFIG = CONFIG_PATH"),
     "/etc/regalia/etcd.conf.yml", "deploy/baremetal/rejoin.py"),
    ("authtime chrony-conf --install", lambda: mutate("deploy/baremetal/authtime.py", "def install_chrony_conf(names, path=STORED_CHRONY_CONF):", "def install_chrony_conf(names, path=CHRONY_CONF):"),
     "/etc/chrony/regalia.conf", "deploy/baremetal/authtime.py"),
    ("seal-hsm-pin credstore", lambda: mutate("deploy/seal-hsm-pin.sh", 'CREDSTORE="${REGALIA_CREDSTORE:-/var/lib/regalia-etc/credstore.encrypted}"', 'CREDSTORE="${REGALIA_CREDSTORE:-/etc/credstore.encrypted}"'),
     "/etc/credstore.encrypted", "deploy/seal-hsm-pin.sh"),
    # planted writes of every kind the scanner reads
    ("python Path(...).open('w') (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    with Path("/etc/regalia/node.json").open("w") as f:\n        f.write("x")\n'),
     "/etc/regalia/node.json", "deploy/baremetal/node.py"),
    ("python an assigned Path's open(mode='w') (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    p = Path("/etc/regalia-kms/config.json")\n    with p.open(mode="w") as f:\n        f.write("x")\n'),
     "/etc/regalia-kms/config.json", "deploy/baremetal/node.py"),
    ("python open(file=..., mode='w') (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    with open(file="/etc/regalia/site.json", mode="w") as f:\n        f.write("x")\n'),
     "/etc/regalia/site.json", "deploy/baremetal/node.py"),
    ("python gzip.open(path, 'wb'), a module's open (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    import gzip\n    with gzip.open("/etc/regalia/node.json", "wb") as f:\n        f.write(b"x")\n'),
     "/etc/regalia/node.json", "deploy/baremetal/node.py"),
    ("python an aliased module's open(filename=..., mode='at') (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    import lzma as xz\n    with xz.open(filename="/etc/regalia/site.json", mode="at") as f:\n        f.write("x")\n'),
     "/etc/regalia/site.json", "deploy/baremetal/node.py"),
    ("shell a command-local assignment does not persist (review)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\nDEST=/etc/regalia/node.json\nDEST=/tmp/out /usr/bin/true\nprintf x > "$DEST"\n'),
     "/etc/regalia/node.json", "deploy/baremetal/tpm-lockout.sh"),
    ("shell assignments in command order (review)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\nDEST=/etc/regalia/node.json; echo x > "$DEST"; DEST=/tmp/out\n'),
     "/etc/regalia/node.json", "deploy/baremetal/tpm-lockout.sh"),
    ("python open w", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted():\n    with open("/etc/regalia/site.json", "w") as f:\n        f.write("x")\n'),
     "/etc/regalia/site.json", "deploy/baremetal/node.py"),
    ("python os.open O_CREAT through a constant", lambda: mutate("deploy/baremetal/node.py", None, '\n\nPLANTED = "/etc/ssh/ssh_host_ed25519_key"\n\n\ndef _planted():\n    os.open(PLANTED, os.O_WRONLY | os.O_CREAT, 0o600)\n'),
     "/etc/ssh/ssh_host_ed25519_key", "deploy/baremetal/node.py"),
    ("python another module's constant + a name", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(name):\n    from deploy.baremetal import enrol\n    os.replace("/tmp/x", enrol.CONFIG_DIR + name)\n'),
     "/etc/regalia/...", "deploy/baremetal/node.py"),
    ("python f-string, append", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(n):\n    open(f"/etc/regalia-kms/{n}.json", "a").close()\n'),
     "/etc/regalia-kms/...", "deploy/baremetal/node.py"),
    ("python a parameter's default", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(data, path="/etc/default/prometheus-node-exporter"):\n    shutil.copy(data, path)\n'),
     "/etc/default/prometheus-node-exporter", "deploy/baremetal/node.py"),
    ("python argv tee", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(run):\n    run(["tee", "/etc/nftables.d/regalia-kms.nft"])\n'),
     "/etc/nftables.d/regalia-kms.nft", "deploy/baremetal/node.py"),
    ("python argv sh -c", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(run):\n    run(["sh", "-c", "nft list ruleset > /etc/nftables.d/regalia-kms.nft"])\n'),
     "/etc/nftables.d/regalia-kms.nft", "deploy/baremetal/node.py"),
    ("python systemd-creds encrypt", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(run):\n    run(["systemd-creds", "encrypt", "--name=x", "-", "/etc/credstore.encrypted/x.cred"])\n'),
     "/etc/credstore.encrypted/x.cred", "deploy/baremetal/node.py"),
    ("python host.write", lambda: mutate("deploy/baremetal/takeover.py", None, '\n\ndef _planted(host):\n    host.write("/etc/regalia/etcd.conf.yml", "x")\n'),
     "/etc/regalia/etcd.conf.yml", "deploy/baremetal/takeover.py"),
    ("shell redirection", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\necho x > /etc/regalia/node.json\n'),
     "/etc/regalia/node.json", "deploy/baremetal/tpm-lockout.sh"),
    ("shell install through a variable", lambda: mutate("deploy/baremetal/recovery-key.sh", None, '\nDEST=/etc/chrony\ninstall -m 0644 conf "$DEST/regalia.conf"\n'),
     "/etc/chrony/regalia.conf", "deploy/baremetal/recovery-key.sh"),
    ("unit ReadWritePaths", lambda: add_to_section("deploy/baremetal/units/regalia-sync.service", "Service", "ReadWritePaths=-/etc/regalia"),
     "/etc/regalia", "deploy/baremetal/units/regalia-sync.service"),
    ("unit BindPaths", lambda: add_to_section("deploy/baremetal/units/regalia-admission.service", "Service", "BindPaths=/etc/credstore.encrypted"),
     "/etc/credstore.encrypted", "deploy/baremetal/units/regalia-admission.service"),
    ("unit ConfigurationDirectory", lambda: add_to_section("deploy/systemd/regalia-kms.service", "Service", "ConfigurationDirectory=regalia-kms"),
     "/etc/regalia-kms", "deploy/systemd/regalia-kms.service"),
    ("unit ExecStartPre sh -c", lambda: add_to_section("deploy/baremetal/units/regalia-wg-apply.service", "Service",
                                                       "ExecStartPre=/bin/sh -c 'umask 077; wg genkey > /etc/regalia/wg-service.key'"),
     "/etc/regalia/wg-service.key", "deploy/baremetal/units/regalia-wg-apply.service"),
    ("drop-in ExecStartPost", lambda: add_to_section("deploy/baremetal/units/chrony.service.d/regalia.conf", "Service",
                                                     "ExecStartPost=/usr/bin/cp /run/chrony/x /etc/chrony/regalia.conf"),
     "/etc/chrony/regalia.conf", "deploy/baremetal/units/chrony.service.d/regalia.conf"),
    ("tmpfiles makes a per-host file", lambda: mutate("deploy/baremetal/units/regalia.tmpfiles.conf", None, "f /etc/regalia/node.json 0644 root root -\n"),
     "/etc/regalia/node.json", "deploy/baremetal/units/regalia.tmpfiles.conf"),
    ("tmpfiles link to the wrong place", lambda: mutate("deploy/baremetal/units/00-regalia-etc.tmpfiles.conf",
                                                        "L /etc/regalia - - - - /var/lib/regalia-etc/regalia", "L /etc/regalia - - - - /run/regalia-etc"),
     "/etc/regalia", "deploy/baremetal/units/00-regalia-etc.tmpfiles.conf"),
    ("tmpfiles copy instead of link", lambda: mutate("deploy/baremetal/units/00-regalia-etc.tmpfiles.conf",
                                                     "L+ /etc/credstore.encrypted - - - - /var/lib/regalia-etc/credstore.encrypted",
                                                     "C /etc/credstore.encrypted - - - - /var/lib/regalia-etc/credstore.encrypted"),
     "/etc/credstore.encrypted", "deploy/baremetal/units/00-regalia-etc.tmpfiles.conf"),
    # /etc/systemd/system (regalia-kms-r1s.8): what README.md had the operator do, each planted in deploy code
    ("shell systemctl enable --now (r1s.8)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\nsystemctl enable --now regalia-audit-ship@sync nftables.service\n'),
     "/etc/systemd/system", "deploy/baremetal/tpm-lockout.sh"),
    ("shell sudo systemctl mask (r1s.8)", lambda: mutate("deploy/baremetal/recovery-key.sh", None, '\nsudo systemctl mask chronyd-restricted.service\n'),
     "/etc/systemd/system", "deploy/baremetal/recovery-key.sh"),
    ("shell a drop-in installed under /etc/systemd/system (r1s.8)", lambda: mutate("deploy/baremetal/recovery-key.sh", None,
        '\nD=/etc/systemd/system/regalia-kms.service.d\ninstall -D -m 0644 firewall.conf "$D/firewall.conf"\n'),
     "/etc/systemd/system/regalia-kms.service.d/firewall.conf", "deploy/baremetal/recovery-key.sh"),
    ("python argv systemctl enable (r1s.8)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _planted(run):\n    run(["systemctl", "--quiet", "enable", "regalia-sync.service"])\n'),
     "/etc/systemd/system", "deploy/baremetal/node.py"),
    ("python a drop-in written (r1s.8)", lambda: mutate("deploy/baremetal/node.py", None,
        '\n\ndef _planted():\n    with open("/etc/systemd/system/regalia-kms.service.d/credentials.conf", "w") as f:\n        f.write("x")\n'),
     "/etc/systemd/system/regalia-kms.service.d/credentials.conf", "deploy/baremetal/node.py"),
    ("unit ExecStartPost systemctl enable (r1s.8)", lambda: add_to_section("deploy/baremetal/units/regalia-sync.service", "Service",
                                                                         "ExecStartPost=/usr/bin/systemctl enable regalia-admission.service"),
     "/etc/systemd/system", "deploy/baremetal/units/regalia-sync.service"),
    ("tmpfiles a wants link under /etc (r1s.8)", lambda: mutate("deploy/baremetal/units/regalia.tmpfiles.conf", None,
        "L /etc/systemd/system/multi-user.target.wants/regalia-sync.service - - - - /usr/lib/systemd/system/regalia-sync.service\n"),
     "/etc/systemd/system/multi-user.target.wants/regalia-sync.service", "deploy/baremetal/units/regalia.tmpfiles.conf"),
    ("generator writes /etc instead of its output directory (r1s.8)", lambda: mutate("deploy/baremetal/generators/regalia-kms-credentials",
        'mkdir -p "$out/regalia-kms.service.d"', 'out=/etc/systemd/system; mkdir -p "$out/regalia-kms.service.d"'),
     "/etc/systemd/system/regalia-kms.service.d", "deploy/baremetal/generators/regalia-kms-credentials"),
]

# each must leave the scan clean: reads, mentions, the /var names, and writes to /etc paths that are not per-host
NO_OPS = [
    ("python read", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop():\n    with open("/etc/regalia/node.json") as f:\n        return f.read()\n')),
    ("python comment and docstring", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop():\n    """writes /etc/regalia/node.json? no"""\n    # open("/etc/regalia/node.json", "w")\n    return 0\n')),
    ("python the /var name", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop():\n    from deploy.baremetal import hostpaths\n    with open(hostpaths.persistent("/etc/regalia/node.json"), "w") as f:\n        f.write("x")\n')),
    ("python systemd-creds decrypt to /dev/null", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop(run):\n    run(["systemd-creds", "decrypt", "/etc/credstore.encrypted/x", "/dev/null"])\n')),
    ("shell read and comment", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\ncat /etc/regalia/node.json >/dev/null  # > /etc/regalia/node.json\n')),
    ("unit ReadOnlyPaths", lambda: add_to_section("deploy/baremetal/units/regalia-sync.service", "Service", "ReadOnlyPaths=/etc/regalia")),
    ("blank line", lambda: mutate("deploy/baremetal/enrol.py", None, "\n")),
    ("python Path(...).open() to read, a module's open to read (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop():\n    with Path("/etc/regalia/node.json").open() as f:\n        return f.read(), Path("/etc/regalia/site.json").open("r")\n')),
    ("python gzip.open to read (review)", lambda: mutate("deploy/baremetal/node.py", None, '\n\ndef _noop():\n    import gzip\n    with gzip.open("/etc/regalia/node.json", "rb") as f:\n        return f.read()\n')),
    ("shell a command-local /etc assignment, a /tmp write (review)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\nDEST=/tmp/out\nDEST=/etc/regalia/node.json /usr/bin/true\nprintf x > "$DEST"\n')),
    ("shell an assignment after the write, to a /etc name (review)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None, '\nDEST=/tmp/out; echo x > "$DEST"; DEST=/etc/regalia/node.json\n')),
    # systemctl that writes nothing under /etc (r1s.8): starting, reloading, a runtime enablement, another tree, a read
    ("shell systemctl start, daemon-reload, --runtime, --root=, a read (r1s.8)", lambda: mutate("deploy/baremetal/tpm-lockout.sh", None,
        '\nsystemctl start regalia-audit-ship@sync\nsystemctl daemon-reload\nsystemctl enable --runtime x.service\n'
        'chroot "$R" systemctl --root=/ preset-all\nsystemctl --root=/mnt enable x.service\ncat /etc/systemd/system/x.service >/dev/null\n')),
    ("python argv systemctl restart, a drop-in under /run (r1s.8)", lambda: mutate("deploy/baremetal/node.py", None,
        '\n\ndef _noop(run):\n    run(["systemctl", "restart", "regalia-sync.service"])\n'
        '    with open("/run/systemd/system/regalia-kms.service.d/x.conf", "w") as f:\n        f.write("x")\n')),
]


class EtcWrites(unittest.TestCase):
    def test_nothing_writes_a_per_host_etc_path_by_its_etc_name(self):
        found = etc_writes.scan()
        self.assertEqual(found, [], "\n" + "\n".join(etc_writes.describe(f) for f in found))

    def test_the_scan_reads_every_kind_of_file(self):
        """A scan that read nothing would pass: it must see the deploy package, the scripts, the units and tmpfiles."""
        kinds = {}
        for rel, kind in etc_writes.deploy_files().items():
            kinds.setdefault(kind, []).append(rel)
        self.assertGreater(len(kinds.get("python", [])), 50)
        for rel in ("deploy/seal-hsm-pin.sh", "deploy/baremetal/image/build-rootfs.sh", "deploy/baremetal/initrd/wg-boot",
                    "deploy/baremetal/generators/regalia-kms-credentials"):
            self.assertIn(rel, kinds.get("shell", []))
        for rel in ("deploy/systemd/regalia-kms.service", "deploy/baremetal/units/regalia-sync.service",
                    "deploy/baremetal/units/chrony.service.d/regalia.conf", "deploy/baremetal/units/regalia-etc-factory.service",
                    "deploy/baremetal/initrd/regalia-unlock.service"):
            self.assertIn(rel, kinds.get("unit", []))
        self.assertIn("deploy/baremetal/units/00-regalia-etc.tmpfiles.conf", kinds.get("tmpfiles", []))

    def test_each_mutant_is_refused_by_name(self):
        for name, overrides, path, where in MUTANTS:
            with self.subTest(mutant=name):
                found = etc_writes.scan(overrides=overrides())
                self.assertTrue(found, "the mutant %r passed the scan" % name)
                named = [f for f in found if f.path == path and f.file == where]
                self.assertTrue(named, "the mutant %r was refused, but not by %s in %s: %s" % (
                    name, path, where, [etc_writes.describe(f) for f in found]))
                self.assertIn(path, etc_writes.describe(named[0]))
                self.assertIn("%s:%d" % (where, named[0].line), etc_writes.describe(named[0]))

    def test_each_no_op_passes(self):
        for name, overrides in NO_OPS:
            with self.subTest(no_op=name):
                found = etc_writes.scan(overrides=overrides())
                self.assertEqual(found, [], "the no-op %r was refused: %s" % (name, [etc_writes.describe(f) for f in found]))

    def test_main_s_writers_are_each_found(self):
        """The scan against the writers as they were before this change (origin/main e9df7fa1, the /etc names):
        every one is found. Inlined, so the test needs no git."""
        before = {
            "deploy/baremetal/enrol.py": [('_install(journal, "config", stored(CHRONY_CONF)', '_install(journal, "config", CHRONY_CONF'),
                                          ('_install(journal, "config", stored(NODE_JSON)', '_install(journal, "config", NODE_JSON'),
                                          ('wg_key(journal, "wg_service", stored(wg_service_key), run)', 'wg_key(journal, "wg_service", wg_service_key, run)')],
            "deploy/baremetal/rejoin.py": [("host.write(etcdconf.STORED_CONFIG, text)", "host.write(etcdconf.CONFIG_PATH, text)")],
            "deploy/baremetal/authtime.py": [("def install_chrony_conf(names, path=STORED_CHRONY_CONF):", "def install_chrony_conf(names, path=CHRONY_CONF):")],
            "deploy/seal-hsm-pin.sh": [("${REGALIA_CREDSTORE:-/var/lib/regalia-etc/credstore.encrypted}", "${REGALIA_CREDSTORE:-/etc/credstore.encrypted}")],
        }
        overrides = {}
        for rel, edits in before.items():
            source = text(rel)
            for old, new in edits:
                self.assertEqual(source.count(old), 1, old)
                source = source.replace(old, new)
            overrides[rel] = source
        found = {(f.file, f.path) for f in etc_writes.scan(overrides=overrides)}
        for expected in [("deploy/baremetal/enrol.py", "/etc/regalia/node.json"), ("deploy/baremetal/enrol.py", "/etc/chrony/regalia.conf"),
                         ("deploy/baremetal/enrol.py", "/etc/regalia/wg-service.key"), ("deploy/baremetal/rejoin.py", "/etc/regalia/etcd.conf.yml"),
                         ("deploy/baremetal/authtime.py", "/etc/chrony/regalia.conf"), ("deploy/seal-hsm-pin.sh", "/etc/credstore.encrypted"),
                         ("deploy/seal-hsm-pin.sh", "/etc/credstore.encrypted/.seal-XXXXXX")]:
            self.assertIn(expected, found)


if __name__ == "__main__":
    unittest.main()
