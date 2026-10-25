"""e2e/lib/threenode.py Cluster.audit_complete's `trails` (#340, three-node-netns): a scenario that runs no admission
judges its sync and ESP-advance trails only, and each trail it names must still have been written. A unit test on a
Cluster with no machine behind it, so the rule is held here and not only by a scenario that needs a runner."""
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tempfile
import types
import unittest
import unittest.mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import threenode  # noqa: E402


class Subset(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        node = types.SimpleNamespace(state=self.d / "state", admission=self.d / "admission", log=self.d / "log")
        for p in (node.state, node.admission, node.log):
            p.mkdir()
        self.cluster = object.__new__(threenode.Cluster)
        self.cluster.nodes = {"a": node}
        self.cluster.tool_trails = {}
        self.streams = {}
        self.cluster._ship_start = lambda name: None
        self.cluster.audit_stream = lambda name, trail: self.streams.get(trail, [])
        self.cluster.journal = lambda *a, **k: ""
        self.cluster._receipt_problem = lambda *a: None
        self.write("sync", node.state / "sync-audit.jsonl")
        self.write("esp-advances", node.log / "esp-advances.jsonl")    # admission: never written

    def write(self, trail, path):
        line = (json.dumps({"event": "x", "outcome": "ALLOW"}) + "\n").encode()
        path.write_bytes(line)
        self.streams[trail] = [{"sequence": 1, "previous_hash": threenode.Cluster.GENESIS, "hash": "h1",
                                "detail": {"line_sha256": hashlib.sha256(line).hexdigest()}}]

    def complete(self, **kw):
        with unittest.mock.patch.object(threenode, "until", lambda what, *a, **k: what()):
            return self.cluster.audit_complete(timeout=0, **kw)

    def test_all_trails_by_default_so_an_unwritten_admission_is_wrong(self):
        self.assertEqual(self.complete(), {("a", "admission"): "the trail was never written"})

    def test_a_subset_judges_only_its_trails(self):
        self.assertEqual(self.complete(trails=("sync", "esp-advances")), {})

    def test_a_trail_it_names_must_still_have_been_written(self):
        self.assertEqual(self.complete(trails=("sync", "admission")), {("a", "admission"): "the trail was never written"})

    def test_a_subset_still_judges_the_lines(self):
        self.streams["sync"] = []
        self.assertIn("1 trail lines, 0 in the collector", self.complete(trails=("sync",))[("a", "sync")])

    def test_an_iterator_is_read_once_and_still_judged(self):
        # CodeRabbit on #587: a set() of an iterator consumed it, so nothing was judged and {} came back
        self.streams["sync"] = []
        self.assertIn(("a", "sync"), self.complete(trails=iter(("sync",))))
        with self.assertRaisesRegex(ValueError, "each must be one of"):
            self.complete(trails=iter(()))

    def test_an_unknown_or_empty_subset_is_refused(self):
        for bad in ((), ("sync", "time"), ("nonsense",)):
            with self.subTest(bad), self.assertRaisesRegex(ValueError, "each must be one of sync, admission, esp-advances"):
                self.complete(trails=bad)


class ToolTrail(Subset):
    """ship_tool_trail (#340, three-node-reanchor): an operator tool's trail on one node, shipped and judged with its own."""

    def test_it_lives_in_the_node_s_log_directory_and_is_judged_for_that_node(self):
        path = self.cluster.ship_tool_trail("a", "reanchor")
        self.assertEqual(path, self.d / "log" / "reanchor.jsonl")
        self.assertEqual(self.cluster._node_trails("a"), ["sync", "admission", "esp-advances", "reanchor"])
        self.assertEqual(self.complete(trails=("sync", "esp-advances")), {("a", "reanchor"): "the trail was never written"})
        self.write("reanchor", path)
        self.assertEqual(self.complete(trails=("sync", "esp-advances")), {})
        self.assertEqual(self.cluster._trail_group("reanchor"), "regalia-audit")
        self.assertEqual(self.cluster._trail_group("sync"), "regalia-audit-sync")

    def test_only_an_operator_tool_s_trail(self):
        for bad in ("sync", "esp-advances", "time", "nonsense"):
            with self.subTest(bad), self.assertRaisesRegex(ValueError, "not an operator tool's trail"):
                self.cluster.ship_tool_trail("a", bad)


if __name__ == "__main__":
    unittest.main()
