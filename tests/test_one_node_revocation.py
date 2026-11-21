"""Exercise one-node's actual final revocation assertion without starting its Linux fixture.

Compile just the assertion's three statements from scenario(): the expected reason, the poll,
and its verdict. This keeps the inline predicate under test without adding a production helper
or importing code that manages namespaces, software TPMs, or services.
"""
import ast
import hashlib
import importlib.util
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "e2e" / "one-node.py"
spec = importlib.util.spec_from_file_location("one_node_revocation_fixture", SOURCE)
one_node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(one_node)
threenode = one_node.threenode

NO_LEASE = "the source refused: a may not serve under epoch 2: no lease"


def denial():
    return dict(event="admission-renew", outcome="DENY", peer="a", epoch=2, reason=NO_LEASE)


class RevocationDenial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse(SOURCE.read_text(), str(SOURCE))
        scenario = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "scenario")
        start = next(i for i, node in enumerate(scenario.body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "first_refusal" for target in node.targets))
        cls.assertion = compile(ast.Module(body=scenario.body[start:start + 3], type_ignores=[]), str(SOURCE), "exec")

    def accepted(self, events, *, collected=True, read_error=False):
        verdicts = []
        now = 0

        def sleep(seconds):
            nonlocal now
            now += seconds

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            lines = [json.dumps(dict(e, at=10)).encode() + b"\n" for e in events]
            path.write_bytes(b"".join(lines))
            cluster = threenode.Cluster.__new__(threenode.Cluster)
            cluster.nodes = {"a": SimpleNamespace(admission_log=path.parent)}
            stream = [{"detail": {"line_sha256": hashlib.sha256(line).hexdigest()}} for line in lines] if collected else []
            cluster.audit_stream = lambda *_: stream
            cluster._trail_path = lambda *_: path
            if read_error:
                cluster.audit_stream = lambda *_: (_ for _ in ()).throw(OSError("collector unavailable"))

            def trail(*args):
                if read_error and now < 60:
                    raise OSError("poll failed, diagnostic reread succeeds")
                return events

            with patch.object(threenode, "time", SimpleNamespace(monotonic=lambda: now, sleep=sleep)):
                exec(self.assertion, {"cluster": cluster, "admission_trail": trail, "committed_at": 10,
                                      "until": threenode.until, "ok": lambda condition, *_: verdicts.append(condition)})
        self.assertEqual(len(verdicts), 1)
        return verdicts[0]

    def test_polling_error_cannot_pass_even_if_diagnostic_reread_succeeds(self):
        self.assertFalse(self.accepted([], read_error=True))

    def test_local_denial_without_collector_record_cannot_pass(self):
        self.assertFalse(self.accepted([denial()], collected=False))

    def test_sync_s_peer_a_epoch_two_no_lease_denial_satisfies_the_assertion(self):
        self.assertTrue(self.accepted([denial()]), "the actual sync refusal must satisfy step 5")

    def test_another_peer_or_the_aggregate_denial_cannot_satisfy_the_assertion(self):
        for peer in ("b", ""):
            with self.subTest(peer=peer):
                event = denial()
                event["peer"] = peer
                self.assertFalse(self.accepted([event]), "another peer's refusal must not prove a's revocation")

    def test_a_denial_from_another_epoch_cannot_satisfy_the_assertion(self):
        for epoch in (1, 3):
            with self.subTest(epoch=epoch):
                event = denial()
                event["epoch"] = epoch
                self.assertFalse(self.accepted([event]), "only the committed revocation epoch may satisfy step 5")

    def test_a_different_reason_cannot_satisfy_the_assertion(self):
        for reason in ("the manifest leaves no node this peer could attest", "no lease",
                       "the source refused: b may not serve under epoch 2: no lease", NO_LEASE + " (unrelated)"):
            with self.subTest(reason=reason):
                event = denial()
                event["reason"] = reason
                self.assertFalse(self.accepted([event]), "step 5 needs the exact sync no-lease refusal")

    def test_a_different_event_or_outcome_cannot_satisfy_the_assertion(self):
        for field, value in (("event", "admission-serving"), ("outcome", "ALLOW")):
            with self.subTest(field=field):
                event = denial()
                event[field] = value
                self.assertFalse(self.accepted([event]))

    def test_an_empty_trail_or_missing_fields_cannot_satisfy_the_assertion(self):
        self.assertFalse(self.accepted([]))
        for field in denial():
            with self.subTest(field=field):
                event = denial()
                del event[field]
                self.assertFalse(self.accepted([event]))

    def test_the_expected_denial_is_found_among_unrelated_events(self):
        other = denial()
        other["peer"] = "b"
        self.assertTrue(self.accepted([{}, other, denial()]))


if __name__ == "__main__":
    unittest.main()
