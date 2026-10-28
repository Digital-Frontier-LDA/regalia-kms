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
SECTIONS = ("roots", "packages", "built", "upstream", "imported-not-run", "not-on-host")

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
        want = 3 if section in ("roots", "packages", "built", "upstream") else 2
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
        for _, (what, _why) in cls.spec["packages"] + cls.spec["built"] + cls.spec["upstream"]:
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

    def test_the_one_upstream_program_is_pinned(self):
        """[upstream] is etcd alone (ADR-0002 D32), built from etcd.pin's commit: a tag that names a 40-hex commit and the
        Go release upstream builds it with. build-rootfs.sh refuses a fetched tag at another commit."""
        self.assertEqual([name for name, _ in self.spec["upstream"]], ["etcd"])
        self.assertEqual(self.spec["upstream"][0][1][0].split(), ["/usr/bin/etcd", "/usr/bin/etcdctl", "/usr/bin/etcdutl"])
        with open(os.path.join(BASE, "image", "etcd.pin")) as f:
            pin = dict(line.strip().split("=", 1) for line in f if line.strip() and not line.startswith("#"))
        self.assertEqual(set(pin), {"ETCD_REPO", "ETCD_TAG", "ETCD_COMMIT", "ETCD_GO"})
        self.assertEqual(pin["ETCD_REPO"], "https://github.com/etcd-io/etcd")
        self.assertRegex(pin["ETCD_TAG"], r"^v3\.[0-9]+\.[0-9]+$")
        self.assertRegex(pin["ETCD_COMMIT"], r"^[0-9a-f]{40}$")
        self.assertRegex(pin["ETCD_GO"], r"^go1\.[0-9]+\.[0-9]+$")

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



def own_scope(node):
    """The nodes of `node`'s own scope: its body, without descending into a nested def, class or lambda (their names
    are theirs; each nested def has its own entry)."""
    todo = list(ast.iter_child_nodes(node))
    while todo:
        n = todo.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            todo += list(ast.iter_child_nodes(n))


def own_bindings(node):
    """The names `node` itself binds: its own arguments, and the names stored or deleted in its own scope."""
    bound = set()
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        a = node.args
        bound |= {x.arg for x in a.posonlyargs + a.args + a.kwonlyargs + [a.vararg, a.kwarg] if x}
    bound |= {n.id for n in own_scope(node) if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del))}
    return bound


def definitions(tree):
    """{name: [(the function or class node, the names it calls or reads: unbound names and attributes)]}, every def at
    any depth, a method under its own name: resolved by NAME, so an edge is drawn to every def so named."""
    defs = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # an edge for every name or attribute it calls or reads, a bare name only when it is not bound here: a
            # local variable or argument OF THIS DEF is no edge, whatever def it shares a name with (a nested def's
            # names do not count here). A class's walk covers its methods' bodies, so naming a class reaches
            # everything they call
            bound = own_bindings(node)
            used = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    f = inner.func
                    if isinstance(f, ast.Name):
                        used.add(f.id)
                    elif isinstance(f, ast.Attribute):
                        used.add(f.attr)
                elif isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load) and inner.id not in bound:
                    used.add(inner.id)
                elif isinstance(inner, ast.Attribute) and isinstance(inner.ctx, ast.Load):
                    used.add(inner.attr)                # x.f read, not called: a method passed as a value (run=self._git)
            defs.setdefault(node.name, []).append((node, used))
    return defs


def runs_of(text, tree, commands):
    """The defs of a module that run one of `commands`: by the scanner's own patterns over the def's source, or through
    a module-level table naming the command (TOOLS = {"measure": "/usr/lib/systemd/systemd-measure"}; tools["measure"])."""
    def found(segment):
        return {c for rx in (CALL, ABSOLUTE) for c in rx.findall(segment)} & commands
    keys = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
            for k, v in zip(node.value.keys, node.value.values):
                if isinstance(k, ast.Constant) and isinstance(v, ast.Constant) and isinstance(v.value, str):
                    hit = {c for c in commands if v.value == c or os.path.basename(v.value) == os.path.basename(c)}
                    if hit:
                        keys[k.value] = hit
    sinks = {}
    for name, entries in definitions(tree).items():
        for node, _ in entries:
            segment = ast.get_source_segment(text, node) or ""
            hit = found(segment)
            for inner in ast.walk(node):
                if isinstance(inner, ast.Subscript) and isinstance(inner.slice, ast.Constant) and inner.slice.value in keys:
                    hit |= keys[inner.slice.value]
            if hit:
                sinks.setdefault(name, set()).update(hit)
    return sinks


def reached(defs, entries):
    """{def name: the path from an entry} for every def the entries reach, over the by-name call graph."""
    path, todo = {}, [(e, (e,)) for e in sorted(entries)]
    while todo:
        name, via = todo.pop(0)
        if name in path or name not in defs:
            continue
        path[name] = via
        for _, used in defs[name]:
            todo += [(u, via + (u,)) for u in sorted(used) if u in defs and u not in path]
    return path


def import_shape(node, module):
    """How an import statement brings `module` in: "bare" (from deploy.baremetal import uki), "names" (from
    deploy.baremetal.uki import X), or another shape, which the entries below cannot see (an alias, import a.b.c);
    None when it does not import it."""
    if isinstance(node, ast.ImportFrom) and node.level == 0:
        if node.module == "deploy.baremetal":
            for a in node.names:
                if a.name == module:
                    return "bare" if a.asname is None else "aliased: as " + a.asname
            return None
        if node.module == "deploy.baremetal." + module:
            return "names"
    if isinstance(node, ast.Import):
        for a in node.names:
            if a.name == "deploy.baremetal." + module or a.name.startswith("deploy.baremetal." + module + "."):
                return "import " + a.name + ("" if a.asname is None else " as " + a.asname)
    return None


class TheLaptopOnlyCommandsAreUnreachedFromTheHost(unittest.TestCase):
    """uki.py is on the host (bootnext, enrol, node and signkey import it for measured, verify, credential_files and
    policy_digest), and it also signs on the laptop: git (Checkout, the build's provenance), keyctl and systemd-measure.
    [imported-not-run] exempts those commands for the whole module, so a host path that came to run one would pass
    every check above. Here, what the host's other modules refer to in uki (uki.NAME, or imported by name) must not
    reach, in uki.py's call graph, a def that runs one of them.

    The graph is by NAME: a call (f(), x.f()), an unbound read of a name or a read of an attribute (a def passed as
    a value: run=self._git) is an edge to every def so named; a class's walk covers its methods' bodies, so naming it reaches what they
    call. So it
    over-approximates: an unrelated def sharing a name can make it fail (a false red, read the path it prints), but a
    direct call or a def passed by name cannot pass unseen. It does not see getattr with a computed name or other
    dynamic dispatch, a def handed in from outside uki.py, or a command built at run time."""

    MODULE = "uki"

    @classmethod
    def setUpClass(cls):
        with open(LIST) as f:
            spec = parse(f.read())
        local = local_modules()
        cls.host, _ = closure([name for name, _ in spec["roots"]], local)
        with open(os.path.join(BASE, cls.MODULE + ".py")) as f:
            cls.text = f.read()
        cls.tree = ast.parse(cls.text)
        not_run = {name for name, _ in spec["imported-not-run"]}
        cls.laptop = not_run & set(commands({cls.MODULE}))
        cls.defs = definitions(cls.tree)
        cls.sinks = runs_of(cls.text, cls.tree, cls.laptop)
        cls.entries, cls.import_shapes = set(), {}
        for name in sorted(cls.host - {cls.MODULE}):
            with open(os.path.join(BASE, name + ".py")) as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    shape = import_shape(node, cls.MODULE)
                    if shape is not None:
                        cls.import_shapes.setdefault(shape, set()).add(name)
                if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == cls.MODULE:
                    cls.entries.add(node.attr)
                elif isinstance(node, ast.ImportFrom) and node.module == "deploy.baremetal." + cls.MODULE:
                    cls.entries |= {a.name for a in node.names}

    def test_the_host_reaches_no_def_that_runs_a_laptop_only_command(self):
        path = reached(self.defs, self.entries)
        bad = {name: (" -> ".join(path[name]), sorted(self.sinks[name])) for name in self.sinks if name in path}
        self.assertEqual(bad, {}, "the host reaches, through uki.py, a def that runs a command [imported-not-run] says "
                                  "runs only on the laptop: move the call off the host's path, or list the package")

    def test_every_host_import_of_uki_is_a_shape_the_entries_see(self):
        """An alias (from deploy.baremetal import uki as u) or a dotted import would bring in names the entries never
        count: refused, so they cannot pass unseen."""
        self.assertEqual({s: sorted(m) for s, m in self.import_shapes.items() if s not in ("bare", "names")}, {},
                         "a host module imports uki in a shape this guard does not follow")
        self.assertIn("bare", self.import_shapes)
        for text, want in (("from deploy.baremetal import uki as u", "aliased: as u"), ("import deploy.baremetal.uki", "import deploy.baremetal.uki"),
                           ("from deploy.baremetal import uki", "bare"), ("from deploy.baremetal.uki import verify", "names"),
                           ("from deploy.baremetal import sync", None)):
            with self.subTest(text):
                self.assertEqual(import_shape(ast.parse(text).body[0], self.MODULE), want)

    def test_a_nested_def_does_not_hide_its_parent_s_read(self):
        """A nested def's parameter or local is not the parent's binding: the parent's read of that name stays an edge."""
        for label, inner in (("a parameter", "    def inner(_git):\n        return _git\n"),
                             ("a local", "    def inner():\n        _git = 1\n        return _git\n"),
                             ("a lambda's parameter", "    inner = lambda _git: _git\n")):
            with self.subTest(label):
                tree = ast.parse("def outer():\n" + inner + "    return _git\n\n\ndef _git():\n    pass\n")
                used = {node.name: u for node, u in (e for es in definitions(tree).values() for e in es)}
                self.assertIn("_git", used["outer"])
                self.assertNotIn("_git", own_bindings(tree.body[0]))

    def test_the_guard_sees_what_it_is_for(self):
        """Not vacuous: the host does refer into uki, the laptop-only commands are found, each by a def of its own,
        and the defs that run git, keyctl and systemd-measure are the signing path's."""
        self.assertTrue({"measured", "verify", "credential_files", "policy_digest"} <= self.entries, sorted(self.entries))
        self.assertEqual(self.laptop & {"git", "keyctl", "/usr/lib/systemd/systemd-measure"},
                         {"git", "keyctl", "/usr/lib/systemd/systemd-measure"})
        runs = {c: n for n, cs in self.sinks.items() for c in cs}
        self.assertEqual(sorted(runs), ["/usr/lib/systemd/systemd-measure", "git", "keyctl"], self.sinks)
        self.assertIn("_git", self.sinks)
        # and the signing entry points do reach them: the graph walks as far as it must
        path = reached(self.defs, {"sign", "main"})
        self.assertTrue(all(name in path for name in self.sinks), sorted(set(self.sinks) - set(path)))

    def test_a_host_call_into_the_signing_path_is_refused(self):
        """The shapes this guards against, built on uki.py's real graph: verify coming to read the checkout by a call,
        by a method of an instance it was handed, passed on as a value (no class named: only the attribute read is an
        edge), or by handing the host a Checkout (no method named: only the class reaching its methods is an edge),
        or to run systemd-measure through the tool table."""
        for label, body, sink in (("a call", "Checkout().head()", "_git"),
                                  ("a method passed as a value", "run_with(checkout._git)", "_git"),
                                  ("an instance handed to the host", "return Checkout()", "_git"),
                                  ("the tool table", "run([tools['measure'], 'calculate'])", "verify")):
            with self.subTest(label):
                text = self.text.replace("def verify(", "def verify(*_a, checkout=None, tools=TOOLS, **_k):\n    %s\n\n\ndef verify_(" % body, 1)
                self.assertNotEqual(text, self.text)
                tree = ast.parse(text)
                path = reached(definitions(tree), self.entries)
                self.assertIn(sink, {name for name in runs_of(text, tree, self.laptop) if name in path})


if __name__ == "__main__":
    unittest.main()
