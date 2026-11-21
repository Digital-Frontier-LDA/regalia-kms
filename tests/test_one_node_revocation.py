"""Exercise one-node's actual final revocation assertion without starting its Linux fixture.

Compile just the assertion's three statements from scenario(): the expected reason, the poll,
and its verdict. This keeps the inline predicate under test without adding a production helper
or importing code that manages namespaces, software TPMs, or services.
"""
import ast
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "e2e" / "one-node.py"
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

    def accepted(self, events):
        verdicts = []

        def poll(predicate, seconds, interval):
            self.assertEqual((seconds, interval), (60, 2))
            return predicate()

        exec(self.assertion, {"cluster": object(), "admission_trail": lambda cluster, name: events,
                              "until": poll, "ok": lambda condition, text, detail: verdicts.append(condition)})
        self.assertEqual(len(verdicts), 1, "the final revocation check must produce exactly one verdict")
        return verdicts[0]

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
