"""Sync's topology context is the verified manifest's designed size, not its live population."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from deploy.baremetal import membership, node


VECTORS = Path(__file__).parent / "vectors" / "membership-v5.json"


def runtime_document(value):
    """Undo the vectors' scanner-safe public/key spelling, as their existing replay test does."""
    if isinstance(value, dict):
        return {("key" if name == "public" else name): runtime_document(item) for name, item in value.items()}
    if isinstance(value, list):
        return [runtime_document(item) for item in value]
    return value


def accepted(predicate):
    for case in json.loads(VECTORS.read_text())["cases"]:
        manifest = runtime_document(case["envelope"]).get("manifest", {})
        if case.get("accepted") and predicate(manifest):
            result = membership.accept(runtime_document(case["current"]), runtime_document(case["envelope"]),
                                       runtime_document(case["root_public"]))
            if membership.digest(result) != case["accepted"]:
                raise AssertionError("the signed topology fixture did not reproduce its accepted digest")
            return result
    raise AssertionError("no accepted signed topology vector matches the test precondition")


class TopologyMetrics(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.target = Path(directory.name) / "membership.prom"
        self.sync = node.Sync.__new__(node.Sync)
        self.sync.node = SimpleNamespace(anchor=lambda: SimpleNamespace(value=lambda: 1))
        self.sync.store = SimpleNamespace(load=Mock())
        patched = patch.object(node.metrics, "path", return_value=str(self.target))
        self.addCleanup(patched.stop)
        patched.start()

    def assert_size(self, expected):
        self.assertTrue(self.target.exists(), "sync did not publish its verified topology context")
        self.assertIn(f"regalia_topology_nodes {expected}\n", self.target.read_text(),
                      "topology must report the genesis-fixed designed size, not listed or live nodes")
        self.assertIn("# TYPE regalia_topology_nodes gauge\n", self.target.read_text())

    def test_verified_topology_survives_revocation_and_retired_entries(self):
        cases = (
            ("single, sole node revoked", 1,
             lambda m: m.get("topology", {}).get("nodes") == 1
             and [n["state"] for n in m["nodes"]] == ["REVOKED_STOLEN"]),
            ("single, retired entry retained", 1,
             lambda m: m.get("topology", {}).get("nodes") == 1 and len(m["nodes"]) > 1),
            ("multi, retired entry retained", 3,
             lambda m: m.get("topology", {}).get("nodes") == 3 and len(m["nodes"]) > 3),
            ("legacy v4, only one node active", 3,
             lambda m: m.get("schema") == membership.SCHEMA_V4
             and sum(n["state"] == "ACTIVE" for n in m["nodes"]) == 1),
        )
        for name, size, predicate in cases:
            with self.subTest(name=name):
                self.sync.store.load = Mock(return_value=accepted(predicate))
                self.sync.membership_metrics()
                self.assert_size(size)

    def test_epoch_and_size_come_from_one_verified_snapshot(self):
        single = accepted(lambda m: m.get("topology", {}).get("nodes") == 1)
        multi = accepted(lambda m: m.get("topology", {}).get("nodes") == 3)
        self.sync.store.load = Mock(side_effect=[single, multi])
        self.sync.membership_metrics()
        self.sync.store.load.assert_called_once_with()
        self.assert_size(1)
        self.assertIn(f"regalia_membership_epoch {single['epoch']}\n", self.target.read_text())

    def test_refused_store_does_not_publish_unverified_topology(self):
        self.target.write_text("previous file\n")
        self.sync.store.load.side_effect = membership.Refused("unverified chain")
        self.sync.membership_metrics()
        self.assertEqual(self.target.read_text(), "previous file\n",
                         "a refused store must leave the previous file to age, not invent topology")

    def test_anchor_failure_keeps_publication_best_effort(self):
        self.sync.store.load.return_value = accepted(lambda m: m.get("topology", {}).get("nodes") == 1)
        self.sync.node.anchor = Mock(side_effect=OSError("anchor unavailable"))
        self.sync.membership_metrics()
        self.assertFalse(self.target.exists(), "failed publication must not leave a partial metrics file")


if __name__ == "__main__":
    unittest.main()
