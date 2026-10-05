"""deploy/baremetal/image/packages.txt (#61): the KMS host image's packages are DERIVED from what the host runs and imports,
and checked here, without building anything.

The host's deploy modules are the import closure of the file's [roots]. Every other deploy module must be declared
[not-on-host], with a reason. In the host's modules, every command they run (an argv's first word, an absolute
/usr/bin, /sbin or systemd path, any tpm2_* tool) and every non-stdlib import must be provided by a [packages] line, or
named in [imported-not-run] with a reason. So must every absolute executable a unit's Exec*= line names. A new
command (the next efibootmgr) is refused by name until its package is listed."""
import ast
import os
import re
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
BASE = os.path.join(ROOT, "deploy", "baremetal")
LIST = os.path.join(BASE, "image", "packages.txt")
UNIT_DIRS = (os.path.join(BASE, "units"), os.path.join(ROOT, "deploy", "systemd"))
NOT_IMAGE_UNITS = {"regalia-sops-kms.service"}          # a workload-host sidecar, not part of the KMS host (regalia-kms-ed)
SECTIONS = ("roots", "packages", "built", "imported-not-run", "not-on-host")

CALL = re.compile(r"""(?:\brun|\bsh|_run|subprocess\.run|subprocess\.check_output|subprocess\.Popen|self\.run|self\._run|check_output|Popen|_efibootmgr)\(\s*\[\s*["']([^"'\s]+)["']""")
ABSOLUTE = re.compile(r"""["'](/usr/s?bin/[A-Za-z0-9_.+-]+|/s?bin/[A-Za-z0-9_.+-]+|/usr/lib/systemd/systemd-[A-Za-z0-9_-]+)["']""")
TPM2 = re.compile(r"""["']tpm2_[a-z]""")
EXEC = re.compile(r"^\s*Exec[A-Za-z]*=[-+!@:|]*(/\S+)")


def parse(text):
    """{section: [(name, [fields...]), ...]}, refused (ValueError) on a line outside a section, a section not
    known, or an entry without its reason."""
    out, section = {s: [] for s in SECTIONS}, None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.fullmatch(r"\[([a-z-]+)\]", line)
        if m:
            if m.group(1) not in SECTIONS:
                raise ValueError("line %d: unknown section [%s]" % (number, m.group(1)))
            section = m.group(1)
            continue
        if section is None:
            raise ValueError("line %d: an entry outside any section" % number)
        fields = [f.strip() for f in line.split("|")]
        want = 3 if section in ("roots", "packages", "built") else 2
        if len(fields) != want or not all(fields[:1]) or not fields[-1]:
            raise ValueError("line %d: [%s] entries are %d fields (%s), the last a reason: %r"
                             % (number, section, want, "name | what | why" if want == 3 else "name | why", line))
        out[section].append((fields[0], fields[1:]))
    return out


def local_modules():
    return {n[:-3] for n in os.listdir(BASE) if n.endswith(".py") and n != "__init__.py"}


def imports(name, local):
    """(the deploy modules `name` imports, its third-party top-level imports)."""
    with open(os.path.join(BASE, name + ".py")) as f:
        tree = ast.parse(f.read())
    mine, third = set(), set()
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module == "deploy.baremetal":
                mine |= {a.name for a in node.names}
                continue
            names = [node.module]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        for full in names:
            if full.startswith("deploy.baremetal."):
                mine.add(full.split(".")[2])
            elif full.split(".")[0] in local:
                mine.add(full.split(".")[0])
            elif full.split(".")[0] not in sys.stdlib_module_names and full.split(".")[0] != "deploy":
                third.add(full.split(".")[0])
    return mine & local, third


def closure(roots, local):
    seen, todo, third = set(), list(roots), {}
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        mine, theirs = imports(name, local)
        for t in theirs:
            third.setdefault(t, set()).add(name)
        todo += sorted(mine - seen)
    return seen, third


def commands(modules):
    found = {}
    for name in sorted(modules):
        with open(os.path.join(BASE, name + ".py")) as f:
            text = f.read()
        for rx in (CALL, ABSOLUTE):
            for command in rx.findall(text):
                found.setdefault(command, set()).add(name)
        if TPM2.search(text):
            found.setdefault("tpm2_*", set()).add(name)
    return found


def provides(provided, command, by_name=True):
    """Whether a [packages] line provides `command`: by its exact path or name, by a family ("tpm2_*" covers every
    tpm2_ tool), or, for a code's absolute path, by its bare name (a package listing `wg` provides /usr/bin/wg).
    A unit's executable must be listed by its exact absolute path (by_name=False): systemd runs that path."""
    if command in provided:
        return True
    if any(p.endswith("*") and os.path.basename(command).startswith(p[:-1]) for p in provided):
        return by_name
    return by_name and os.path.basename(command) in provided


def unit_executables():
    found = {}
    for directory in UNIT_DIRS:
        for dirpath, _, files in os.walk(directory):
            for f in files:
                if f in NOT_IMAGE_UNITS or not f.endswith((".service", ".conf", ".timer", ".path")):
                    continue
                with open(os.path.join(dirpath, f)) as fh:
                    for line in fh:
                        m = EXEC.match(line)
                        if m:
                            found.setdefault(m.group(1), set()).add(f)
    return found


class Parse(unittest.TestCase):
    def test_entries_need_a_reason_and_a_section(self):
        for text, why in (("dash | /bin/sh | x\n", "outside any section"), ("[packages]\ndash | /bin/sh\n", "3 fields"),
                          ("[packages]\ndash | /bin/sh | \n", "3 fields"), ("[imported-not-run]\ngit\n", "2 fields"),
                          ("[bogus]\n", "unknown section")):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, why):
                    parse(text)


class TheHostsPackages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(LIST) as f:
            cls.spec = parse(f.read())
        cls.local = local_modules()
        cls.roots = [name for name, _ in cls.spec["roots"]]
        cls.host, cls.third = closure(cls.roots, cls.local)
        cls.provided = set()
        for _, (what, _why) in cls.spec["packages"] + cls.spec["built"]:
            cls.provided |= {w for w in what.split() if w != "-"}
        cls.not_run = {name for name, _ in cls.spec["imported-not-run"]}

    def test_roots_are_deploy_modules(self):
        self.assertEqual(sorted(set(self.roots) - self.local), [], "a [roots] entry is not a deploy/baremetal module")

    def test_every_deploy_module_is_on_the_host_or_declared_off_it(self):
        off = {name for name, _ in self.spec["not-on-host"]}
        self.assertEqual(sorted(self.local - self.host - off), [], "deploy modules neither imported by the host nor declared [not-on-host]")
        self.assertEqual(sorted(off & self.host), [], "declared [not-on-host] but imported by the host's modules")
        self.assertEqual(sorted(off - self.local), [], "a [not-on-host] entry is not a deploy/baremetal module")

    def test_every_command_the_host_runs_has_a_package(self):
        found = commands(self.host)
        missing = {c: sorted(m) for c, m in found.items() if not provides(self.provided, c) and c not in self.not_run}
        self.assertEqual(missing, {}, "commands the host's modules run that no [packages] line provides: list the package")

    def test_every_unit_executable_has_a_package(self):
        found = unit_executables()
        missing = {e: sorted(u) for e, u in found.items() if not provides(self.provided, e, by_name=False)}
        self.assertEqual(missing, {}, "executables the units name that no [packages] line provides")

    def test_every_third_party_import_has_a_package(self):
        missing = {t: sorted(m) for t, m in self.third.items() if "py:" + t not in self.provided}
        self.assertEqual(missing, {}, "Python modules the host imports that no [packages] line provides (py:<module>)")

    def test_built_programs_exist(self):
        """A [built] line names a cmd/ directory of this repository and one absolute path: the builder installs it there."""
        for source, (path, _why) in self.spec["built"]:
            with self.subTest(source=source):
                self.assertTrue(os.path.isdir(os.path.join(ROOT, source)) and source.startswith("cmd/"), "%s is not a cmd/ program" % source)
                self.assertTrue(path.startswith("/") and len(path.split()) == 1, "%s installs to one absolute path" % source)

    def test_nothing_listed_is_stale(self):
        """An [imported-not-run] command must still be found in the host's modules: a stale exemption hides nothing."""
        found = commands(self.host)
        self.assertEqual(sorted(c for c in self.not_run if c not in found), [], "[imported-not-run] entries no longer found")

    def test_the_scan_finds_what_it_is_for(self):
        """The scanner, against the shapes it must catch (it would pass on anything if its patterns were wrong)."""
        text = ('run(["efibootmgr", "-v"])\nsubprocess.run(["wg", "show"])\nx = "/usr/sbin/cryptsetup"\n'
                'self._tpm("tpm2_nvread")\n_efibootmgr(run, "--bootnext")\n')
        got = set(CALL.findall(text)) | set(ABSOLUTE.findall(text))
        self.assertEqual(got, {"efibootmgr", "wg", "/usr/sbin/cryptsetup"})
        self.assertTrue(TPM2.search(text))


if __name__ == "__main__":
    unittest.main()
