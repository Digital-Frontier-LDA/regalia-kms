"""CI and the daemon judge these manifests alike (regalia-kms-wd6).

tests/vectors/custody-slot-rules-v1.json holds whole manifests for the object_id spelling rule,
the declared-slot rule and the secret-KEK rule (regalia-kms-091), each with the one verdict both
validators must reach. TestCustodySlotRuleVectors in internal/registry/custody_slot_vectors_test.go
runs the same file through registry.Load, so a rule changed on one side only fails by name on the
other.
"""
import json
import unittest
from pathlib import Path

from tools.custody_manifest import ManifestError, validate_manifest

VECTORS = Path(__file__).resolve().parent / "vectors" / "custody-slot-rules-v1.json"


class CustodySlotRuleVectors(unittest.TestCase):
    def test_every_vector_gets_the_daemons_verdict(self):
        cases = json.loads(VECTORS.read_text(encoding="utf-8"))["cases"]
        self.assertTrue(cases, "the vector file holds no cases, so this test is checking nothing")
        for case in cases:
            with self.subTest(case=case["name"]):
                refused = case["refused"]
                try:
                    validate_manifest(case["manifest"])
                except ManifestError as error:
                    self.assertIsNotNone(refused, f"must validate, was refused: {error}")
                    self.assertIn(refused, str(error), "refused for something other than the rule under test")
                else:
                    self.assertIsNone(refused, f"must be refused ({refused!r}), validated")


if __name__ == "__main__":
    unittest.main()
