"""node-units.yml starts only when a listed path changes (#683). The list named the scripts its jobs run, but not
every file those scripts import or read: a change to e2e/lib/tpmdiag.py alone ran none of the jobs that load it.
This walks every e2e/ file the workflow runs, through its imports and the repository paths it names, and requires
each file reached to be inside the filter, so the filter cannot go stale when a script gains an import."""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "node-units.yml"
# What a step runs: an e2e/ script handed to python3 or bash.
RUNS = re.compile(r"(?:\bpython3(?:\s+-\w+)*|\bbash)\s+(e2e/[\w./-]+\.(?:py|sh))\b")


def filter_paths(text):
    """{event: [glob]} for each event's paths: list, in order."""
    found, event, in_paths = {}, None, False
    for line in text.splitlines():
        m = re.match(r"^  (\w+):\s*$", line)
        if m:
            event, in_paths = m.group(1), False
            continue
        if re.match(r"^\S", line):
            event, in_paths = None, False
            continue
        if event and re.match(r"^    paths:\s*$", line):
            in_paths = True
            found[event] = []
            continue
        m = re.match(r"^      - (\S+)\s*$", line)
        if event and in_paths and m:
            found[event].append(m.group(1))
        elif in_paths and not re.match(r"^      ", line):
            in_paths = False
    return found


def glob_regex(glob):
    """GitHub's paths glob: ** crosses directories, * stays inside one."""
    out, i = "", 0
    while i < len(glob):
        if glob.startswith("**", i):
            out, i = out + ".*", i + 2
        elif glob[i] == "*":
            out, i = out + "[^/]*", i + 1
        else:
            out, i = out + re.escape(glob[i]), i + 1
    return re.compile(out + r"\Z")


def covered(rel, globs):
    return any(glob_regex(g).match(rel) for g in globs)


def filter_mismatch(text):
    """The paths one event's filter lists and the other's does not (an event missing counts as an empty list)."""
    paths = filter_paths(text)
    push, pull = set(paths.get("push", [])), set(paths.get("pull_request", []))
    return sorted(push ^ pull)


def entry_points(text):
    """The e2e/ files the workflow's steps run (comments are not steps)."""
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return sorted(set(RUNS.findall(code)))


def _module_file(dotted, roots):
    for base in roots:
        p = base.joinpath(*dotted.split("."))
        for candidate in (p.with_suffix(".py"), p / "__init__.py"):
            if candidate.is_file():
                return candidate
    return None


def _path_bases(tree, path):
    """{name: directory} for module-level NAME = pathlib.Path(__file__).resolve().parent / .parents[N]."""
    bases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            src = ast.unparse(node.value)
            m = re.fullmatch(r"(?:pathlib\.)?Path\(__file__\)\.resolve\(\)\.(parent|parents\[(\d+)\])", src)
            if m:
                bases[node.targets[0].id] = path.parent if m.group(1) == "parent" else path.parents[int(m.group(2))]
    return bases


def _literal_paths(tree, bases):
    """Every BASE[.parent…] / "a" / "b" … chain whose base is a known directory: the repository path it names."""
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)):
            continue
        parts, left = [], node
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Div) and isinstance(left.right, ast.Constant) \
                and isinstance(left.right.value, str):
            parts.insert(0, left.right.value)
            left = left.left
        ups = 0
        while isinstance(left, ast.Attribute) and left.attr == "parent":
            ups, left = ups + 1, left.value
        if parts and isinstance(left, ast.Name) and left.id in bases:
            base = bases[left.id]
            for _ in range(ups):
                base = base.parent
            found.append(base.joinpath(*parts))
    return found


def reached(rel):
    """Every repository file one e2e/ entry point reaches: itself, what it imports (against the repository root and
    e2e/lib/, the two directories the scripts put on sys.path), and the repository paths it names, transitively."""
    roots, seen, todo = (ROOT, ROOT / "e2e" / "lib"), set(), [ROOT / rel]
    while todo:
        path = todo.pop()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        if path.suffix != ".py":
            continue
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                todo += [f for a in node.names for f in [_module_file(a.name, roots)] if f]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                mod = _module_file(node.module, roots)
                todo += [mod] if mod else []
                todo += [f for a in node.names for f in [_module_file(node.module + "." + a.name, roots)] if f]
        for named in _literal_paths(tree, _path_bases(tree, path)):
            if named.is_file():
                todo.append(named)
    return {p.relative_to(ROOT).as_posix() for p in seen if ROOT in p.parents}


def uncovered(text):
    """[(file reached, the entry point that reaches it)] for each reached file outside the pull_request filter."""
    globs = filter_paths(text).get("pull_request", [])
    out = {}
    for entry in entry_points(text):
        for rel in sorted(reached(entry)):
            if not covered(rel, globs):
                out.setdefault(rel, entry)
    return sorted(out.items())


class TheNodeUnitsFilterCoversWhatItsJobsRun(unittest.TestCase):

    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_every_file_a_job_reaches_is_in_the_filter(self):
        for rel, entry in uncovered(self.text):
            with self.subTest(file=rel):
                self.fail("%s is reached from %s, which node-units.yml runs, but is not in its paths filter: a change to it "
                          "alone runs none of the jobs that use it" % (rel, entry))

    def test_push_and_pull_request_filter_the_same_paths(self):
        self.assertEqual(sorted(filter_paths(self.text)), ["pull_request", "push"])
        self.assertEqual(filter_mismatch(self.text), [])

    def test_a_path_only_one_event_filters_is_named(self):
        planted = "on:\n  pull_request:\n    paths:\n      - a/**\n      - b.py\n  push:\n    paths:\n      - a/**\n"
        self.assertEqual(filter_mismatch(planted), ["b.py"])

    def test_the_walk_sees_what_was_traced_by_hand(self):
        # a walk gone blind finds nothing to miss: it must reach at least what #683 traced by hand
        entries = entry_points(self.text)
        self.assertGreaterEqual(len(entries), 13, entries)
        everything = set().union(*(reached(e) for e in entries))
        self.assertGreaterEqual(len(everything), 15, sorted(everything))
        # one of each way a file is reached: an import, a from-import, a named path, a step's bash
        for rel in ("e2e/lib/threenode.py", "e2e/lib/tpmdiag.py", "deploy/baremetal/lease.py", "deploy/baremetal/trails.py",
                    "deploy/systemd/regalia-kms.sysusers.conf", "tests/test_baremetal_heartbeat.py", "e2e/lib/apt-install-netem.sh"):
            self.assertIn(rel, everything)

    def test_a_file_left_out_of_the_filter_is_named(self):
        removed = self.text.replace("      - e2e/lib/threenode.py\n", "")
        self.assertNotEqual(removed, self.text)
        self.assertIn("e2e/lib/threenode.py", [rel for rel, _ in uncovered(removed)])

    def test_the_glob_follows_githubs_rules(self):
        self.assertTrue(covered("deploy/baremetal/a/b.py", ["deploy/baremetal/**"]))
        self.assertFalse(covered("deploy/baremetal/a/b.py", ["deploy/baremetal/*"]))
        self.assertTrue(covered("deploy/baremetal/b.py", ["deploy/baremetal/*"]))
        self.assertFalse(covered("e2e/lib/threenode.pyc", ["e2e/lib/threenode.py"]))


if __name__ == "__main__":
    unittest.main()
