"""e2e/lib/threenode.py's tpm2-abrmd route (regalia-afi, #592, #605): REGALIA_E2E_TPM picks how the nodes reach their TPMs,
and with "abrmd" each node's units reach theirs only through their own node's tpm2-abrmd (its bus, its raw socket hidden),
this process's TPM calls only inside tpm_of (outside, no session bus: a forgotten one fails closed), and the raw unlock
client only while none of the node's units runs. Unit tests on a Cluster with no machine behind it, so the rules are held
here and not only by a scenario that needs a runner."""
import os
import pathlib
import re
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


class Mode(unittest.TestCase):
    def test_unset_is_the_socket(self):
        self.assertEqual(threenode.tpm_mode({}), "socket")

    def test_each_mode_by_name(self):
        for mode in ("socket", "abrmd"):
            with self.subTest(mode):
                self.assertEqual(threenode.tpm_mode({"REGALIA_E2E_TPM": mode}), mode)

    def test_anything_else_is_refused_never_read_as_the_default(self):
        for mode in ("", "vtpm", "ABRMD", "abrmd "):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, "REGALIA_E2E_TPM"):
                threenode.tpm_mode({"REGALIA_E2E_TPM": mode})


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

    def test_socket_mode_gives_a_unit_nothing_more(self):
        self.assertEqual(threenode.unit_tpm_properties("socket", self.n), [])

    def test_abrmd_mode_gives_a_unit_its_bus_and_hides_its_raw_tpm(self):
        sock = self.work / "a" / "tpm.sock"
        self.assertEqual(threenode.unit_tpm_properties("abrmd", self.n),
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


def cluster(work, mode="abrmd"):
    c = object.__new__(threenode.Cluster)
    c.tpm = mode
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
    closed): in abrmd mode every call down the chain is made inside n's tpm_of, its bus set; in socket mode the Node itself."""
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

    def test_socket_mode_is_the_node_itself(self):
        c = cluster(self.work, "socket")
        here = c.node("a")
        self.assertNotIsInstance(here, threenode.Through)
        here.store().load()
        self.assertEqual(self.seen, [("store", None), ("load", None)])


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

    def test_socket_mode_keeps_what_it_did(self):
        self.c.tpm, self.c.services["a"] = "socket", ("sync",)
        self.c._initrd_only("a", "unlock")
        self.sh.assert_not_called()

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
    operator's tools), give a node's unit its TPM route: in abrmd mode its bus and its raw socket hidden, else nothing."""
    def setUp(self):
        self.work = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.work, True)
        self.ran = []
        patch = unittest.mock.patch.object(threenode, "sh", side_effect=lambda *a, **k: self.ran.append(a))
        patch.start()
        self.addCleanup(patch.stop)

    def built(self, mode):
        c = cluster(self.work, mode)
        c.code = self.work
        c.members = lambda: list(c.nodes.values())
        c.member = lambda name: c.nodes[name]
        c.as_root("a", "deliver-2", ["true"])
        return {"properties": c.properties("a", "sync"), "as_root": [p for argv in self.ran for p in argv]}

    def test_abrmd_mode(self):
        want = threenode.unit_tpm_properties("abrmd", threenode.NodeHere(self.work, "a", 1))
        for builder, props in self.built("abrmd").items():
            with self.subTest(builder):
                for prop in want:
                    self.assertIn(prop, props)
                self.assertNotIn("Environment=DBUS_SESSION_BUS_ADDRESS=" + threenode.NodeHere(self.work, "b", 2).bus_address, props)

    def test_socket_mode(self):
        for builder, props in self.built("socket").items():
            with self.subTest(builder):
                self.assertFalse([p for p in props if "DBUS_SESSION_BUS_ADDRESS" in p or "tpm.sock" in p])


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

    def test_socket_mode_has_none_to_ask(self):
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



class ScenariosUseTheRoute(unittest.TestCase):
    """#605's follow-up: a scenario's own tpm2-tools call on a node's tcti, taken straight from cluster.nodes[x], skips
    tpm_of. In abrmd mode it has no bus and fails closed (three-node-reanchor's step 3 and snapshot did). A tcti handed to
    a unit's command line (--tcti) is the unit's, which carries its bus: that is not this."""
    DIRECT = re.compile(r'"-T",\s*cluster\.nodes\[|=\s*cluster\.nodes\[[^]]+\]\.(raw_)?tcti\b')   # a call, or a tcti kept for one

    def test_no_scenario_calls_a_tpm_on_a_tcti_taken_around_tpm_of(self):
        e2e = pathlib.Path(__file__).resolve().parents[1] / "e2e"
        scenarios = sorted(e2e.glob("*.py"))
        self.assertGreater(len(scenarios), 5)                       # the glob reads the scenarios, not nothing
        found = ["%s:%d" % (p.name, i) for p in scenarios for i, line in enumerate(p.read_text().splitlines(), 1)
                 if self.DIRECT.search(line)]
        self.assertEqual(found, [], "use `with cluster.tpm_of(name) as n:` and n.tcti")

    def test_the_control_the_form_reanchor_had_is_found(self):
        self.assertIsNotNone(self.DIRECT.search('    gone = sh("tpm2_nvundefine", "-T", cluster.nodes[b].tcti, "-C", "o", index)'))
        self.assertIsNotNone(self.DIRECT.search('        tcti = cluster.nodes[b].tcti'))       # its snapshot's, kept for "-T", tcti
        self.assertIsNone(self.DIRECT.search('"--tpm-index", index, "--tcti", cluster.nodes[b].tcti, "--node-id", b,'))


if __name__ == "__main__":
    unittest.main()
