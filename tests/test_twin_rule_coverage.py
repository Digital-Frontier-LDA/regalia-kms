"""EVERY RULE OF A TWIN HAS A CASE IN THE SHARED VECTOR (regalia-u1r).

internal/opstate's Go functions documented "X is opstate.<fn>" or "X is survivor.<fn>" mirror
deploy/baremetal/opstate.py and survivor.py, and tests/vectors/opstate-v1.json holds both sides to the same decisions
and reasons. That held only for the rules some case happened to reach: three times in two days a rule changed on one
side while no case reached it (#496's v2 binding, #516's redfish evidence and its fence set). So this iterates the
RULES: every require() and Refused() in those Python functions, and in the same module's helpers they call, must be
matched by the reason of a refused case. A rule added without a case fails here before any fixture exercises it.
internal/opstate/twin_coverage_test.go is the same check over the Go refuse()s. Never an exemption: a rule no case
can reach is either reached by giving the vector the input (a case's own chain, say) or is dead code to remove.
"""
import ast
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULES = ("opstate", "survivor")
TWIN = re.compile(r"^// [A-Za-z0-9_]+ is (%s)\.([a-z_]+)\b(?!['.])" % "|".join(MODULES), re.M)


def twins():
    """{module: {function}} as the Go twins' docs name them."""
    out = {m: set() for m in MODULES}
    for path in sorted((ROOT / "internal" / "opstate").glob("*.go")):
        if not path.name.endswith("_test.go"):
            for module, name in TWIN.findall(path.read_text()):
                out[module].add(name)
    return out


def _format(node):
    """The format string a refusal's message is made from (None if it is not made from literals)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return _format(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _format(node.left), _format(node.right)
        return None if left is None or right is None else left + right
    return None


def refusals(module, roots):
    """{format: [function]} for every require()/Refused() reachable from `roots` within `module`, and any unread."""
    tree = ast.parse((ROOT / "deploy" / "baremetal" / ("%s.py" % module)).read_text())
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    unknown = sorted(roots - set(funcs))
    found, unread, seen, todo = {}, [], set(), sorted(roots)
    while todo:
        name = todo.pop()
        if name in seen or name not in funcs:
            continue
        seen.add(name)
        for node in ast.walk(funcs[name]):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            callee = node.func.id
            message = node.args[1] if callee == "require" and len(node.args) > 1 else node.args[0] if callee == "Refused" and node.args else None
            if message is not None:
                f = _format(message)
                if f is None:
                    unread.append("%s.%s line %d" % (module, name, node.lineno))
                else:
                    found.setdefault(f, []).append(name)
            elif callee in funcs:
                todo.append(callee)
    return found, unread, unknown


def pattern(fmt):
    """What `fmt` can print: each %-conversion at least one character."""
    parts = re.split(r"%[-+ #0-9.]*[sdrx]", fmt.replace("%%", "\0"))
    return re.compile("^" + ".+?".join(re.escape(p).replace("\\\0", "%").replace("\0", "%") for p in parts) + "$", re.S)


def vector_reasons(doc):
    return [c["python_reason"] for section in doc.values() if isinstance(section, list)
            for c in section if isinstance(c, dict) and c.get("accept") is False and c.get("python_reason")]


def uncovered(module, roots, reasons):
    found, unread, unknown = refusals(module, roots)
    missing = sorted("%r (in %s)" % (f, ", ".join(sorted(set(where)))) for f, where in found.items()
                     if not any(pattern(f).match(r) for r in reasons))
    return missing, found, unread, unknown


class EveryRuleHasACase(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads((ROOT / "tests" / "vectors" / "opstate-v1.json").read_text())
        self.twins = twins()

    def test_the_go_twins_name_python_functions_that_exist(self):
        self.assertGreaterEqual(sum(len(v) for v in self.twins.values()), 15, "the Go doc convention this test reads has changed")
        for module in MODULES:
            _, _, unknown = refusals(module, self.twins[module])
            self.assertEqual(unknown, [], "a Go twin names %s.<fn> functions that do not exist" % module)

    def test_every_rule_of_a_python_twin_has_a_vector_case(self):
        reasons = vector_reasons(self.doc)
        for module in MODULES:
            with self.subTest(module):
                missing, found, unread, _ = uncovered(module, self.twins[module], reasons)
                self.assertEqual(unread, [], "refusals whose message is not built from literals: this test cannot read their rule")
                self.assertGreater(len(found), 10, "the scan read almost nothing from %s.py" % module)
                self.assertEqual(missing, [], "%d of %d rules of %s.py's twins have no refused case in opstate-v1.json (add one to "
                                 "make-opstate-v1.py; never an exemption)" % (len(missing), len(found), module))

    def test_the_scan_finds_a_rule_no_case_reaches(self):
        """A rule planted in a twin's source is seen as uncovered: a clean result above is not the scan reading nothing."""
        source = (ROOT / "deploy" / "baremetal" / "opstate.py").read_text()
        planted = source.replace('def validate(entry):\n    """Schema only. Returns the entry\'s kind."""\n',
                                 'def validate(entry):\n    """Schema only. Returns the entry\'s kind."""\n'
                                 '    require(entry != "planted", "a planted rule no case reaches")\n', 1)
        self.assertNotEqual(planted, source, "validate()'s first lines moved: the plant did not apply")
        tree = ast.parse(planted)
        validate = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "validate")
        formats = [_format(c.args[1]) for c in ast.walk(validate) if isinstance(c, ast.Call) and getattr(c.func, "id", "") == "require"]
        self.assertIn("a planted rule no case reaches", formats)
        self.assertFalse(any(pattern("a planted rule no case reaches").match(r) for r in vector_reasons(self.doc)))


if __name__ == "__main__":
    unittest.main()
