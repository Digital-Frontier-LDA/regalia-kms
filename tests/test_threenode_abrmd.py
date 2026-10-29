"""e2e/lib/threenode.py's tpm2-abrmd route (regalia-afi, #592, #605), its only one: each node's units reach their TPM
only through their own node's tpm2-abrmd (its bus, its raw socket hidden),
this process's TPM calls only inside tpm_of (outside, no session bus: a forgotten one fails closed), and the raw unlock
client only while none of the node's units runs. Unit tests on a Cluster with no machine behind it, so the rules are held
here and not only by a scenario that needs a runner."""
import ast
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import unittest.mock
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode  # noqa: E402


class RetiredSwitch(unittest.TestCase):
    """REGALIA_E2E_TPM chose the raw socket until #592: a job that still sets it, to any value, is refused, so neither
    route is ever read from a configuration written for the switch."""
    def test_unset_passes(self):
        threenode.refuse_retired_switch({})

    def test_any_value_is_refused(self):
        for value in ("socket", "abrmd", "", "ABRMD"):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, r"REGALIA_E2E_TPM=.*the switch is gone \(#592\)"):
                threenode.refuse_retired_switch({"REGALIA_E2E_TPM": value})

    def test_a_cluster_asks_before_anything_else(self):
        with unittest.mock.patch.dict(os.environ, REGALIA_E2E_TPM="socket"), \
                self.assertRaisesRegex(RuntimeError, "the switch is gone"):
            threenode.Cluster(pathlib.Path("/nonexistent"))


class Node(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.n = threenode.NodeHere(self.work, "a", 1)

    def test_its_tcti_is_the_raw_socket_while_no_abrmd_runs(self):
        self.assertEqual(self.n.tcti, "swtpm:path=%s" % (self.work / "a" / "tpm.sock"))

    def test_its_tcti_is_tabrmd_while_its_abrmd_runs(self):
        self.n.abrmd = object()
        self.assertEqual(self.n.tcti, "tabrmd:bus_name=com.intel.tss2.Tabrmd.a,bus_type=session")

    def test_each_nodes_tcti_names_its_own_abrmd(self):
        """TEAMLEAD-grafana: closed by construction. Every object made from a node's configuration carries its node's
        name, so under another node's bus it finds no owner and fails closed, whichever object makes the call."""
        tctis = {node: threenode.abrmd_tcti(node) for node in ("a", "b", "c", "d")}
        self.assertEqual(len(set(tctis.values())), 4)
        for node, tcti in tctis.items():
            with self.subTest(node):
                self.assertEqual(tcti, "tabrmd:bus_name=%s,bus_type=session" % threenode.abrmd_name(node))
                self.assertTrue(threenode.abrmd_name(node).endswith("." + node))

    def test_a_node_id_that_cannot_be_a_dbus_name_element_is_refused(self):
        for node in ("", "1a", "a-b", "a.b", "x" * 33):
            with self.subTest(node=node), self.assertRaisesRegex(RuntimeError, "D-Bus name element"):
                threenode.abrmd_name(node)

    def test_its_bus_is_under_its_own_directory(self):
        self.assertEqual(self.n.bus_address, "unix:path=%s" % (self.work / "a" / "dbus" / "bus"))

    def test_a_unit_is_given_its_bus_and_its_raw_tpm_hidden(self):
        sock = self.work / "a" / "tpm.sock"
        self.assertEqual(threenode.unit_tpm_properties(self.n),
                         ["Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=%s" % (self.work / "a" / "dbus" / "bus"),
                          "InaccessiblePaths=-%s" % sock, "InaccessiblePaths=-%s.ctrl" % sock])


class BusConfig(unittest.TestCase):
    def test_it_listens_on_the_node_socket_only_and_tss_alone_owns_the_name(self):
        name = threenode.abrmd_name("a")
        root = ET.fromstring(threenode.bus_config("/w/a/dbus/bus", name).split("\n", 2)[2])
        self.assertEqual([e.text for e in root.iter("listen")], ["unix:path=/w/a/dbus/bus"])
        owners = [(p.get("user"), p.get("context"), a.get("own")) for p in root.iter("policy") for a in p if a.get("own")]
        self.assertEqual(sorted(owners, key=str), sorted([(None, "default", "*"), ("tss", None, name)], key=str))
        denied = [a.get("own") for p in root.iter("policy") for a in p if a.tag == "deny" and a.get("own")]
        self.assertEqual(denied, ["*"])

    def test_it_lets_the_bus_replies_through(self):
        """#605 run 40449316347: a bus with no receive rules denied its own replies, and every client hung."""
        root = ET.fromstring(threenode.bus_config("/w/a/dbus/bus", threenode.abrmd_name("a")).split("\n", 2)[2])
        received = {a.get("receive_type") for p in root.iter("policy") for a in p if a.tag == "allow" and a.get("receive_type")}
        self.assertEqual(received, {"method_call", "method_return", "error", "signal"})


def cluster(work):
    c = object.__new__(threenode.Cluster)
    c._tpm_lock = threading.RLock()
    c.nodes = {name: threenode.NodeHere(work, name, i + 1) for i, name in enumerate("ab")}
    c.services = {"a": (), "b": ()}
    return c


class TpmOf(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.c = cluster(self.work)
        self.c.nodes["a"].abrmd = self.c.nodes["b"].abrmd = object()
        patch = unittest.mock.patch.dict(os.environ)
        patch.start()
        self.addCleanup(patch.stop)
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def test_the_node_bus_is_set_inside_and_gone_after(self):
        with self.c.tpm_of("a") as n:
            self.assertIs(n, self.c.nodes["a"])
            self.assertEqual(os.environ["DBUS_SESSION_BUS_ADDRESS"], self.c.nodes["a"].bus_address)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)

    def test_gone_after_a_call_that_raised(self):
        with self.assertRaises(ValueError), self.c.tpm_of("a"):
            raise ValueError
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)

    def test_another_node_inside_is_refused_loudly_and_the_outer_call_keeps_its_bus(self):
        """TEAMLEAD-grafana on a0dfa53d: one bus at a time, so a nested call for another node would reach the wrong TPM."""
        with self.c.tpm_of("a"):
            with self.assertRaisesRegex(RuntimeError, "a TPM call for node b inside one for node a"):
                with self.c.tpm_of("b"):
                    self.fail("b's call ran")
            self.assertEqual(os.environ["DBUS_SESSION_BUS_ADDRESS"], self.c.nodes["a"].bus_address)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)
        with self.c.tpm_of("b"):                      # and nothing was left held: b on its own is fine
            self.assertEqual(os.environ["DBUS_SESSION_BUS_ADDRESS"], self.c.nodes["b"].bus_address)

    def test_the_same_node_inside_is_allowed_and_keeps_its_bus(self):
        with self.c.tpm_of("a"):
            with self.c.tpm_of("a"):
                with self.c.tpm_of("a"):
                    self.assertEqual(os.environ["DBUS_SESSION_BUS_ADDRESS"], self.c.nodes["a"].bus_address)
            self.assertEqual(os.environ["DBUS_SESSION_BUS_ADDRESS"], self.c.nodes["a"].bus_address)
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)

    def test_a_node_with_no_abrmd_gets_no_bus(self):
        self.c.nodes["b"].abrmd = None
        with self.c.tpm_of("b") as n:
            self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)
            self.assertEqual(n.tcti, n.raw_tcti)

    def test_the_longest_hold_is_measured_by_the_outermost_call(self):
        clock = iter([100.0, 100.5, 200.0, 203.25])
        with unittest.mock.patch.object(threenode.time, "monotonic", side_effect=lambda: next(clock)):
            with self.c.tpm_of("a"):
                with self.c.tpm_of("a"):              # inner: not timed
                    pass
            with self.c.tpm_of("b"):
                pass
        self.assertEqual(self.c.tpm_longest_hold, (3.25, "b"))

    def test_one_node_at_a_time_across_threads(self):
        inside, release, other = threading.Event(), threading.Event(), []

        def hold():
            with self.c.tpm_of("a"):
                inside.set()
                release.wait(5)
        t = threading.Thread(target=hold)
        t.start()
        inside.wait(5)

        def enter():
            with self.c.tpm_of("b"):
                other.append(os.environ.get("DBUS_SESSION_BUS_ADDRESS"))
        u = threading.Thread(target=enter)
        u.start()
        u.join(0.3)
        self.assertEqual(other, [])                   # b waits while a's call is in
        release.set()
        t.join(5)
        u.join(5)
        self.assertEqual(other, [self.c.nodes["b"].bus_address])


class NodeThrough(unittest.TestCase):
    """A scenario's own `cluster.node(n).store().load()` (three-node-recovery's step 7 read one outside tpm_of, and failed
    closed): every call down the chain is made inside n's tpm_of, its bus set."""
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.seen = []
        seen = self.seen

        def bus():
            return os.environ.get("DBUS_SESSION_BUS_ADDRESS")
        Store = type("Store", (), {"__module__": "deploy.baremetal.membership", "load": lambda self: seen.append(("load", bus())) or {"epoch": 3}})

        class Node:
            def __init__(self, cfg):
                self.cfg = cfg

            def store(self):
                seen.append(("store", bus()))
                return Store()
        Node.__module__ = "deploy.baremetal.node"
        for target, value in ((threenode.node, "Node"), (threenode.node, "load")):
            patch = unittest.mock.patch.object(target, value, Node if value == "Node" else (lambda path: {"tcti": threenode.abrmd_tcti("a")}))
            patch.start()
            self.addCleanup(patch.stop)
        env = unittest.mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)

    def test_abrmd_mode_every_call_down_the_chain_is_inside_its_bus(self):
        c = cluster(self.work)
        c.nodes["a"].abrmd = object()
        here = c.node("a")
        self.assertEqual(here.cfg, {"tcti": threenode.abrmd_tcti("a")})            # an attribute, as it is
        self.assertEqual(here.store().load()["epoch"], 3)
        bus = c.nodes["a"].bus_address
        self.assertEqual(self.seen, [("store", bus), ("load", bus)])
        self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", os.environ)

    def test_what_is_not_deploy_baremetals_comes_back_as_it_is(self):
        c = cluster(self.work)
        self.assertEqual(threenode.through(c, "a", {"epoch": 3}), {"epoch": 3})
        self.assertIsInstance(threenode.through(c, "a", type("X", (), {"__module__": "deploy.baremetal.lease"})()), threenode.Through)
        self.assertNotIsInstance(threenode.through(c, "a", type("Y", (), {"__module__": "deploy.baremetalx"})()), threenode.Through)

class InitrdOnly(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.c = cluster(self.work)
        self.listed = ""
        patch = unittest.mock.patch.object(threenode, "sh", side_effect=lambda *a, **k: types.SimpleNamespace(stdout=self.listed, returncode=0))
        self.sh = patch.start()
        self.addCleanup(patch.stop)

    def test_nothing_running_passes(self):
        self.c._initrd_only("a", "unlock")
        self.assertIn("e2e3-a-*", self.sh.call_args[0])

    def test_its_services_running_is_refused(self):
        self.c.services["a"] = ("sync",)
        with self.assertRaisesRegex(RuntimeError, "unlock on a while its services run"):
            self.c._initrd_only("a", "unlock")

    def test_a_unit_of_its_still_active_is_refused(self):
        self.listed = "e2e3-a-deliver-3.service loaded active running deliver\n"
        with self.assertRaisesRegex(RuntimeError, "enrol on a while its units run .*e2e3-a-deliver-3.service"):
            self.c._initrd_only("a", "enrol")

    def test_another_nodes_units_and_the_collector_are_not_its(self):
        self.listed = "e2e3-b-sync.service loaded active running x\ne2e3-audit-collector.service loaded active running x\n"
        self.c._initrd_only("a", "unlock")

    def test_unlock_and_enrol_ask_it_before_they_touch_the_tpm(self):
        class Refused(Exception):
            pass
        self.c.loops = {"a": "/dev/loop9"}
        for method in (self.c.unlock, self.c.enrol):
            with self.subTest(method.__name__), unittest.mock.patch.object(self.c, "_initrd_only", side_effect=Refused) as guard, \
                    unittest.mock.patch.object(self.c, "tpm_of", side_effect=AssertionError("the TPM before the guard")), \
                    unittest.mock.patch.object(threenode.unlock, "luks_meta", side_effect=AssertionError("the disk before the guard")):
                with self.assertRaises(Refused):
                    method("a")
                guard.assert_called_once_with("a", method.__name__)


class Units(unittest.TestCase):
    """Both of the fixture's unit builders, the services' (properties: _run, _as_sync) and root's (as_root: deliver, the
    operator's tools), give a node's unit its TPM route: its bus, and its raw socket hidden."""
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.ran = []
        patch = unittest.mock.patch.object(threenode, "sh", side_effect=lambda *a, **k: self.ran.append(a))
        patch.start()
        self.addCleanup(patch.stop)

    def built(self):
        c = cluster(self.work)
        c.code = self.work
        c.members = lambda: list(c.nodes.values())
        c.member = lambda name: c.nodes[name]
        c.as_root("a", "deliver-2", ["true"])
        return {"properties": c.properties("a", "sync"), "as_root": [p for argv in self.ran for p in argv]}

    def test_both_builders(self):
        want = threenode.unit_tpm_properties(threenode.NodeHere(self.work, "a", 1))
        for builder, props in self.built().items():
            with self.subTest(builder):
                for prop in want:
                    self.assertIn(prop, props)
                self.assertNotIn("Environment=DBUS_SESSION_BUS_ADDRESS=" + threenode.NodeHere(self.work, "b", 2).bus_address, props)

class AbrmdAnswers(unittest.TestCase):
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.c = cluster(self.work)
        (self.work / "a").mkdir()
        (self.work / "a" / "abrmd.log").write_text("tpm2-abrmd: the end of its log\n")
        patch = unittest.mock.patch.dict(os.environ)
        patch.start()
        self.addCleanup(patch.stop)

    def answer(self, **done):
        return unittest.mock.patch.object(threenode, "sh", return_value=types.SimpleNamespace(**dict({"stdout": "", "stderr": "", "returncode": 0}, **done)))

    def test_a_stopped_tpm_has_none_to_ask(self):
        with self.answer(returncode=1) as sh:
            self.assertTrue(self.c.abrmd_answers("a"))
        sh.assert_not_called()

    def test_an_answer_is_sixteen_hex_digits(self):
        self.c.nodes["a"].abrmd = object()
        with self.answer(stdout="0123456789abcdef\n") as sh:
            self.assertIs(self.c.abrmd_answers("a"), True)
        self.assertEqual(sh.call_args[0][:3], ("tpm2_getrandom", "-T", threenode.abrmd_tcti("a")))
        self.assertEqual(sh.call_args[1]["timeout"], 5)

    def test_no_answer_fails_with_its_log(self):
        self.c.nodes["a"].abrmd = object()
        for done in ({"returncode": 1, "stderr": "Failed to get proxy"}, {"stdout": "not an answer"}):
            with self.subTest(done), self.answer(**done):
                self.assertFalse(self.c.abrmd_answers("a", check=False))
                with self.assertRaisesRegex(RuntimeError, "a's tpm2-abrmd does not answer.*the end of its log"):
                    self.c.abrmd_answers("a")

    def test_a_call_that_hangs_is_no_answer(self):
        self.c.nodes["a"].abrmd = object()
        with unittest.mock.patch.object(threenode, "sh", side_effect=subprocess.TimeoutExpired("tpm2_getrandom", 5)):
            with self.assertRaisesRegex(RuntimeError, "no answer in 5 s"):
                self.c.abrmd_answers("a")



# the units a scenario starts whose own command line takes a node's tcti (with its bus, which the unit carries): only a
# "--tcti" in a sequence that names one of these is the unit's. tpm2-tools take --tcti too (the long -T), so the flag
# alone says nothing (df-grafana-7e on #608)
UNITS_TAKING_A_TCTI = ("deploy.baremetal.reanchor",)          # three-node-reanchor's re-anchor tool at b's console


def around_the_route(source):
    """The lines of `source` that read a node's tcti anywhere but inside the route, read from the parse and not a line
    pattern (df-grafana-7e on #607 and #608, regalia-u90). Reported:
    - `.tcti` / `.raw_tcti` read off anything but the name a `with ….tpm_of(…) as n:` binds, lexically inside that block,
      so a node kept under another name (`node = cluster.nodes[b]`, then `node.tcti`) is found too;
    - that name rebound inside its block (`n = cluster.nodes[c]`, `for n in …`), after which `n.tcti` is another node's;
    - `getattr(…, "tcti")` and `attrgetter("tcti")`, whatever they are read from.
    One exception: the value right after a "--tcti" in a call's arguments or a list that also names a unit in
    UNITS_TAKING_A_TCTI, which is that unit's own command line. Lexical: a function defined inside the block and called
    after it reads as inside; the abrmd jobs still fail that closed at run time, with no bus outside tpm_of."""
    found = []
    attrs = ("tcti", "raw_tcti")

    def unit_args(seq):
        if not any(isinstance(e, ast.Constant) and e.value in UNITS_TAKING_A_TCTI for e in seq):
            return set()
        return {id(seq[i]) for i in range(1, len(seq)) if isinstance(seq[i - 1], ast.Constant) and seq[i - 1].value == "--tcti"}

    def visit(node, bound):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            inner = set(bound)
            for item in node.items:
                visit(item.context_expr, bound)
                call = item.context_expr
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "tpm_of"
                        and isinstance(item.optional_vars, ast.Name)):
                    inner.add(item.optional_vars.id)
                elif item.optional_vars is not None:          # another manager's `as n` rebinds a route name: reported
                    visit(item.optional_vars, inner)
                    inner -= {t.id for t in ast.walk(item.optional_vars) if isinstance(t, ast.Name)}
            for statement in node.body:
                visit(statement, inner)
            return
        if (isinstance(node, ast.Attribute) and node.attr in attrs
                and not (isinstance(node.value, ast.Name) and node.value.id in bound)):
            found.append(node.lineno)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in bound:
            found.append(node.lineno)
        if (isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) in ("getattr", "attrgetter")
                and any(isinstance(a, ast.Constant) and a.value in attrs for a in node.args)):
            found.append(node.lineno)
        skip = unit_args(node.args) if isinstance(node, ast.Call) else unit_args(node.elts) if isinstance(node, (ast.List, ast.Tuple)) else set()
        for child in ast.iter_child_nodes(node):
            if id(child) not in skip:
                visit(child, bound)

    visit(ast.parse(source), frozenset())
    return found


class ScenariosUseTheRoute(unittest.TestCase):
    """#605's follow-up: a scenario's own TPM call on a node's tcti read anywhere but inside `cluster.tpm_of` skips the
    route. It has no bus and fails closed at run time (three-node-reanchor's step 3 and snapshot did); this
    finds it before a runner does. It reads the scenarios that use the three-node fixture."""

    def test_no_scenario_reads_a_tcti_around_tpm_of(self):
        e2e = pathlib.Path(__file__).resolve().parents[1] / "e2e"
        scenarios = sorted(p for p in e2e.glob("*.py") if "threenode" in p.read_text())
        self.assertGreater(len(scenarios), 5)                       # the glob reads the scenarios, not nothing
        found = ["%s:%d" % (p.name, line) for p in scenarios for line in around_the_route(p.read_text())]
        self.assertEqual(found, [], "use `with cluster.tpm_of(name) as n:` and n.tcti")

    def test_the_control_the_forms_reanchor_had_are_found(self):
        self.assertEqual(around_the_route('gone = sh("tpm2_nvundefine", "-T", cluster.nodes[b].tcti, "-C", "o", index)\n'), [1])
        self.assertEqual(around_the_route("tcti = cluster.nodes[b].tcti\n"), [1])        # its snapshot's, kept for "-T", tcti

    def test_a_node_kept_under_another_name_is_found(self):
        self.assertEqual(around_the_route('node = cluster.nodes[b]\nsh("tpm2_nvread", "-T", node.tcti)\n'), [2])
        self.assertEqual(around_the_route('n = cluster.node(b)\nsh("tpm2_getcap", "-T", n.raw_tcti)\n'), [2])

    def test_inside_the_route_is_not(self):
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    sh("tpm2_nvundefine", "-T", n.tcti)\n'), [])
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    return _snapshot(n.tcti)\n'), [])

    def test_the_routes_name_after_its_block_is_found(self):
        """`n` is still bound once the block ends, but the bus is gone: lexical, not by name."""
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    pass\nsh("-T", n.tcti)\n'), [3])

    def test_a_tcti_in_a_with_items_own_expression_is_found(self):
        self.assertEqual(around_the_route('with session(cluster.nodes[b].tcti) as h:\n    pass\n'), [1])

    def test_another_context_managers_name_is_not_the_route(self):
        self.assertEqual(around_the_route('with open(p) as n:\n    sh("-T", n.tcti)\n'), [2])

    def test_a_units_own_tcti_is_not(self):
        self.assertEqual(around_the_route('argv = ["-m", "deploy.baremetal.reanchor", "--tcti", cluster.nodes[b].tcti, "--node-id", b]\n'), [])
        self.assertEqual(around_the_route('run("-m", "deploy.baremetal.reanchor", "--tcti", cluster.nodes[b].tcti)\n'), [])

    def test_a_tpm2_tools_long_tcti_is_found(self):
        """7e on #608: tpm2-tools take --tcti as the long -T, so the flag alone is no unit's."""
        self.assertEqual(around_the_route('sh("tpm2_nvread", "--tcti", cluster.nodes[b].tcti, index)\n'), [1])
        self.assertEqual(around_the_route('argv = ["--tpm-index", index, "--tcti", cluster.nodes[b].tcti]\n'), [1])

    def test_the_route_name_rebound_inside_its_block_is_found(self):
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    n = cluster.nodes[c]\n    sh("-T", n.tcti)\n'), [2])
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    for n in cluster.nodes.values():\n        sh("-T", n.tcti)\n'), [2])

    def test_the_route_name_rebound_by_another_with_is_found(self):
        """7e on bb526069: an inner `with open(p) as n:` rebinds the route's n, and its n.tcti is not the route's."""
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    with open(p) as n:\n        sh("-T", n.tcti)\n'),
                         [2, 3])
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n, open(p) as n:\n    sh("-T", n.tcti)\n'), [1, 2])

    def test_the_same_nodes_route_re_entered_is_not(self):
        self.assertEqual(around_the_route('with cluster.tpm_of(b) as n:\n    with cluster.tpm_of(b) as n:\n        sh("-T", n.tcti)\n'), [])

    def test_a_tcti_read_by_getattr_is_found(self):
        self.assertEqual(around_the_route('t = getattr(cluster.nodes[b], "tcti")\n'), [1])
        self.assertEqual(around_the_route('t = operator.attrgetter("raw_tcti")(cluster.nodes[b])\n'), [1])

    def test_a_tcti_after_another_flag_is_found(self):
        self.assertEqual(around_the_route('argv = ["--node-id", cluster.nodes[b].tcti]\n'), [1])
        self.assertEqual(around_the_route('argv = ["-m", "deploy.baremetal.reanchor", "--node-id", cluster.nodes[b].tcti]\n'), [1])


if __name__ == "__main__":
    unittest.main()
