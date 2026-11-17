"""deploy/baremetal/image/etc-inventory.txt (#61): every /etc path the deploy code and the units name is in it, each
per-host one moves to /var exactly as hostpaths.py and the tmpfiles links say, and /etc is made from the factory copy
BEFORE systemd-sysusers.

Held three ways equal: the inventory's [per-host] rows, deploy/baremetal/hostpaths.PER_HOST, and the L lines of
units/00-regalia-etc.tmpfiles.conf. The order against sysusers is checked here in the units (static); e2e/etc-factory.sh
shows it on the image (both orders, the image's own systemd), from rootfs-reproducible.sh."""
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import etc_writes  # noqa: E402
from source_lexing import python_code, shell_code  # noqa: E402
from deploy.baremetal import enrol, hostpaths  # noqa: E402

ROOT = etc_writes.ROOT
INVENTORY = ROOT / "deploy" / "baremetal" / "image" / "etc-inventory.txt"
UNITS = ROOT / "deploy" / "baremetal" / "units"
LINKS = UNITS / "00-regalia-etc.tmpfiles.conf"
FACTORY_UNIT = UNITS / "regalia-etc-factory.service"
# the one link under /etc that is the image's, not this host's (chronyd's AppArmor local include), and the /var lines
# that are not a per-host directory: the machine ID kept, the AppArmor cache emptied
IMAGE_LINKS = {"/etc/apparmor.d/local/usr.sbin.chronyd": "/usr/lib/regalia-kms/deploy/baremetal/apparmor/local/usr.sbin.chronyd"}
VAR_LINES = {"/var/lib/dbus/machine-id": ("C", "/etc/machine-id"), "/var/cache/apparmor": ("D", None)}
COLUMNS = {"per-host": 5, "boot": 3, "image": 2, "not-on-image": 2, "early": 3, "var-image": 3, "e2e": 3, "open": 3}


def parse(text):
    """{section: [[field, ...], ...]}, refused (ValueError) on a line outside a section, an unknown section, or a row
    with the wrong number of fields or an empty one."""
    sections, current = {}, None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[([a-z0-9-]+)\]", line)
        if m:
            if m.group(1) not in COLUMNS:
                raise ValueError("line %d: unknown section [%s]" % (number, m.group(1)))
            current = sections.setdefault(m.group(1), [])
            continue
        if current is None:
            raise ValueError("line %d: outside a section" % number)
        fields = [f.strip() for f in line.split(" | ")]
        name = [k for k, v in sections.items() if v is current][0]
        if len(fields) != COLUMNS[name] or not all(fields):
            raise ValueError("line %d: [%s] takes %d non-empty fields separated by ' | ': %r" % (number, name, COLUMNS[name], line))
        current.append(fields)
    return sections


def unit(path):
    """{key: [values]} of a unit file (every section together; the keys here are not repeated across sections)."""
    out = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith(("#", ";", "[")) and "=" in line:
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def tmpfiles_lines():
    return [line.split() for line in LINKS.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")]


class Inventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inv = parse(INVENTORY.read_text())

    def test_it_parses_and_has_every_section(self):
        self.assertEqual(set(self.inv), set(COLUMNS))

    def test_the_parser_refuses_a_malformed_row(self):
        for bad in ("/etc/x | y\n", "[nope]\n", "[image]\n/etc/x | \n", "[image]\n/etc/x | a | b\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse(bad)

    def test_per_host_rows_are_hostpaths_and_move_to_their_var_names(self):
        rows = self.inv["per-host"]
        covered = set()
        for path, var, writers, readers, why in rows:
            entry = hostpaths.covering(path)
            self.assertIsNotNone(entry, "%s is a [per-host] row that hostpaths.PER_HOST does not cover" % path)
            covered.add(entry)
            self.assertEqual(var, hostpaths.persistent(path), "%s moves to %s, not %s" % (path, hostpaths.persistent(path), var))
        self.assertEqual(covered, set(hostpaths.PER_HOST), "hostpaths.PER_HOST entries with no [per-host] row")
        for entry in hostpaths.PER_HOST:
            self.assertIn(entry, [r[0] for r in rows], "%s has no row of its own" % entry)

    def test_the_named_items_are_there(self):
        """The acceptance criteria's list (regalia-kms-r1s.4), each in its section."""
        where = {section: {row[0] for row in rows} for section, rows in self.inv.items()}
        for path in ("/etc/regalia/node.json", "/etc/regalia/wg-service.key", "/etc/credstore.encrypted"):
            self.assertIn(path, where["per-host"])
        self.assertIn("/etc/machine-id", where["boot"])
        self.assertIn("/var/cache/apparmor", where["var-image"])
        self.assertIn("/var/lib/dpkg", where["var-image"])
        self.assertTrue(any("e2e/" in row[1] for row in self.inv["e2e"]))
        self.assertTrue(any("credential" in " ".join(row).lower() for row in self.inv["e2e"]), "the e2e guests' test credentials")

    def test_every_etc_path_the_code_and_units_name_is_in_the_inventory(self):
        """Found by searching, not from memory: every /etc path in deploy/'s code (comments and docstrings aside) and in
        the units is a row, under a row's directory, or the parent of one."""
        rows = [row[0] for rows in self.inv.values() for row in rows if row[0].startswith("/etc")]
        pattern = re.compile(r"(?<![\w$}.-])/etc(?:/[A-Za-z0-9_.@+-]+)+")
        missing = {}
        for rel, kind in etc_writes.deploy_files().items():
            text = (ROOT / rel).read_text(errors="replace")
            text = python_code(text) if kind == "python" else shell_code(text) if kind == "shell" else \
                "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", ";")))
            for m in pattern.finditer(text):
                p = m.group(0)
                if not any(p == r or p.startswith(r + "/") or r.startswith(p) for r in rows):
                    missing.setdefault(p, []).append(rel)
        self.assertEqual(missing, {}, "/etc paths in the code that etc-inventory.txt does not name")


class Links(unittest.TestCase):
    def test_the_links_are_hostpaths_and_their_directories_are_made(self):
        lines = tmpfiles_lines()
        links = {f[1]: (f[0], f[6]) for f in lines if f[0] in ("L", "L+") and f[1] not in IMAGE_LINKS}
        self.assertEqual(set(links), set(hostpaths.PER_HOST))
        for path, target in IMAGE_LINKS.items():
            self.assertIn(["L+", path, "-", "-", "-", "-", target], lines)
            self.assertTrue((ROOT / target[len("/usr/lib/regalia-kms/"):]).is_file(), "%s is not in the deploy package" % target)
        for path, (kind, target) in links.items():
            self.assertEqual(target, hostpaths.persistent(path))
        made = {f[1]: (f[2], f[3], f[4]) for f in lines if f[0] == "d"}
        for path, (kind, target) in links.items():
            self.assertIn(os.path.dirname(target), made, "%s's directory is not made by a d line" % target)
        self.assertEqual(made[hostpaths.persistent("/etc/credstore.encrypted")], ("0700", "root", "root"))
        self.assertIn(hostpaths.VAR_ETC, made)

    def test_etc_is_copied_from_the_factory_first_and_nothing_else_is_made_under_it(self):
        lines = tmpfiles_lines()
        self.assertEqual(lines[0][:2], ["C+", "/etc"])
        self.assertEqual(len(lines[0]), 6, "C+ /etc takes no argument: the source is /usr/share/factory/etc")
        for f in lines[1:]:
            if f[1].startswith("/etc"):
                self.assertIn(f[0], ("L", "L+"), "only links under /etc: %s" % " ".join(f))
            elif f[1] in VAR_LINES:
                kind, source = VAR_LINES[f[1]]
                self.assertEqual(f[0], kind)
                self.assertEqual(f[6] if len(f) > 6 else None, source)
            else:
                self.assertTrue(f[1].startswith(hostpaths.VAR_ETC + "/") or f[1] == hostpaths.VAR_ETC,
                                "a /var line outside %s: %s" % (hostpaths.VAR_ETC, " ".join(f)))
        self.assertEqual({f[1] for f in lines if f[1] in VAR_LINES}, set(VAR_LINES))

    def test_the_file_sorts_before_the_systemd_files_that_name_the_same_paths(self):
        """systemd-tmpfiles applies, for a path two files name, the line of the file that sorts first: systemd's
        credstore.conf (d /etc/credstore.encrypted) and dbus.conf (L /var/lib/dbus/machine-id), measured on 257."""
        installed = LINKS.name[:-len(".tmpfiles.conf")] + ".conf"
        for theirs in ("credstore.conf", "dbus.conf", "debian.conf", "systemd.conf", "20-systemd-stub.conf", "var.conf"):
            self.assertLess(installed, theirs)

    def test_a_link_replaces_a_factory_file_only_where_a_package_ships_one(self):
        """L+ removes what is there: only where a package ships the path into the factory copy (measured on the
        Debian 13 tree: prometheus-node-exporter's /etc/default file, systemd's empty /etc/credstore.encrypted)."""
        plus = {f[1] for f in tmpfiles_lines() if f[0] == "L+"}
        self.assertEqual(plus, {"/etc/default/prometheus-node-exporter", "/etc/credstore.encrypted"} | set(IMAGE_LINKS))


class Readers(unittest.TestCase):
    def test_seal_hsm_pin_tells_the_unit_to_read_the_etc_name(self):
        """seal-hsm-pin.sh WRITES the credential at its /var name, and the drop-in line it prints is a READER's: the
        /etc name (the link), the only source PIN-CUSTODY.md's deployment check accepts. Printing the /var name sent
        the operator to a drop-in that check refuses (#723 review). An overridden credstore is read where it is."""
        script = (ROOT / "deploy" / "seal-hsm-pin.sh").read_text()
        self.assertIn("  LoadCredentialEncrypted=$NAME:$READ_AS\n", script)
        self.assertIn('READ_AS="$DEST"; [ -n "${REGALIA_CREDSTORE:-}" ] || READ_AS="/etc/credstore.encrypted/regalia-kms-$ID.pin"\n', script)
        self.assertIn("under `/etc/credstore.encrypted/regalia-kms-`", (ROOT / "PIN-CUSTODY.md").read_text())


class Order(unittest.TestCase):
    def test_the_factory_unit_runs_before_sysusers_tmpfiles_and_apparmor(self):
        u = unit(FACTORY_UNIT)
        self.assertEqual(u["DefaultDependencies"], ["no"])
        before = " ".join(u["Before"]).split()
        for name in ("systemd-sysusers.service", "systemd-tmpfiles-setup.service", "systemd-tmpfiles-setup-dev-early.service",
                     "apparmor.service", "sysinit.target"):
            self.assertIn(name, before)
        self.assertNotIn("After", u, "it waits for nothing: / (tmpfs) and /usr are there when PID 1 starts")
        self.assertEqual(u["ExecStart"], ["/usr/bin/systemd-tmpfiles --create --boot --prefix=/etc /usr/lib/tmpfiles.d/00-regalia-etc.conf"])
        self.assertEqual(u["Type"], ["oneshot"])
        self.assertNotIn("WantedBy", u, "nothing can enable it: /etc/systemd/system is empty when PID 1 loads the units")

    def test_the_units_that_need_etc_pull_it_in_and_wait_for_it(self):
        for name in ("systemd-tmpfiles-setup.service", "apparmor.service"):
            with self.subTest(unit=name):
                u = unit(UNITS / (name + ".d") / "regalia-etc.conf")
                self.assertEqual(u.get("Wants"), ["regalia-etc-factory.service"])
                self.assertEqual(u.get("After")[0].split()[0], "regalia-etc-factory.service")

    def test_sysusers_runs_only_after_a_successful_copy(self):
        """#723 review: with Wants= a FAILED copy still let systemd-sysusers run on an empty /etc and allocate the image's
        users again at other IDs (e2e/etc-factory.sh's CONTROL). Requires= fails sysusers' job instead, and the factory
        unit ASSERTS its tree (a Condition would skip it, which counts as success, and sysusers would run)."""
        u = unit(UNITS / "systemd-sysusers.service.d" / "regalia-etc.conf")
        self.assertEqual(u.get("Requires"), ["regalia-etc-factory.service"])
        self.assertNotIn("Wants", u)
        self.assertEqual(u.get("After"), ["regalia-etc-factory.service"])
        f = unit(FACTORY_UNIT)
        self.assertEqual(f.get("AssertPathIsDirectory"), ["/usr/share/factory/etc"])
        self.assertNotIn("ConditionPathIsDirectory", f)
        # the AppArmor cache is emptied by the full pass: apparmor loads after it
        self.assertIn("systemd-tmpfiles-setup.service", unit(UNITS / "apparmor.service.d" / "regalia-etc.conf")["After"][0].split())

    def test_the_image_builder_installs_them_where_systemd_reads_them(self):
        """build-rootfs.sh copies units/ (directories, *.service, *.conf) to /usr/lib/systemd/system and
        *.tmpfiles.conf to /usr/lib/tmpfiles.d/<name>.conf: the drop-in directories and this file are included."""
        script = (ROOT / "deploy" / "baremetal" / "image" / "build-rootfs.sh").read_text()
        self.assertIn("-type d -o -name '*.service'", script)
        self.assertIn("-o -name '*.conf'", script)
        self.assertIn("! -name '*.tmpfiles.conf'", script)
        self.assertIn('"$ROOT/usr/lib/tmpfiles.d/$(basename "$f" .tmpfiles.conf).conf"', script)
        self.assertIn('cp -a "$ROOT/etc/." "$ROOT/usr/share/factory/etc/"', script)
        self.assertIn("/usr/lib/tmpfiles.d/00-regalia-etc.conf", FACTORY_UNIT.read_text())

    def test_the_e2e_runs_on_every_rootfs_build(self):
        self.assertIn('e2e/etc-factory.sh "$OUT/build-1/rootfs.tar"', (ROOT / "e2e" / "rootfs-reproducible.sh").read_text())
        self.assertTrue(os.access(ROOT / "e2e" / "etc-factory.sh", os.X_OK))


class Directories(unittest.TestCase):
    def test_each_per_host_directory_is_made_on_var_and_linked(self):
        """hostpaths.DIRECTORIES (what e2e/etc-factory.sh checks is a directory in the booted layout, #723 review): each a
        PER_HOST entry, linked from its /etc name, its /var directory made by a `d` line, root's."""
        lines = tmpfiles_lines()
        self.assertTrue(hostpaths.DIRECTORIES)
        for path in hostpaths.DIRECTORIES:
            with self.subTest(path=path):
                self.assertIn(path, hostpaths.PER_HOST)
                stored = hostpaths.persistent(path)
                self.assertTrue(any(f[0] in ("L", "L+") and f[1] == path and f[6] == stored for f in lines), path)
                made = [f for f in lines if f[0] == "d" and f[1] == stored]
                self.assertEqual(len(made), 1, "no `d %s` line" % stored)
                self.assertEqual(made[0][3:5], ["root", "root"])


class Paths(unittest.TestCase):
    def test_persistent_maps_and_refuses(self):
        self.assertEqual(hostpaths.persistent("/etc/regalia/node.json"), "/var/lib/regalia-etc/regalia/node.json")
        self.assertEqual(hostpaths.persistent("/etc/credstore.encrypted"), "/var/lib/regalia-etc/credstore.encrypted")
        for bad in ("/etc/passwd", "/etc/regalia2/x", "/etc/regalia/../shadow", "etc/regalia/node.json", "/etc/regalia/",
                    "/etc/chrony/chrony.conf", "/etc/ssh/ssh_host_rsa_key", "/etc/regalia/x\0"):
            with self.subTest(path=bad), self.assertRaises(hostpaths.NotPerHost):
                hostpaths.persistent(bad)

    def test_enrol_stores_on_var_and_refuses_an_etc_path_not_per_host(self):
        self.assertEqual(enrol.stored(enrol.NODE_JSON), "/var/lib/regalia-etc/regalia/node.json")
        self.assertEqual(enrol.stored(enrol.WG_SERVICE_KEY), "/var/lib/regalia-etc/regalia/wg-service.key")
        self.assertEqual(enrol.stored("/tmp/x/node.json"), "/tmp/x/node.json")
        with self.assertRaises(enrol.Refused):
            enrol.stored("/etc/hostname")


if __name__ == "__main__":
    unittest.main()
