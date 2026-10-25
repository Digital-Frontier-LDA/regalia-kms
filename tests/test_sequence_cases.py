"""tests/vectors/sequence-cases-v1.json against opstate.py's transition (regalia-07k): every Cosmos account-sequence
case as documented, except the pairs the vector lists as divergent for "opstate.py", which must STILL diverge, so a
change of rule shows here and removes its pair. The Go backends read the same vector (internal/policy and
internal/opstate sequence_cases_test.go)."""
import json
import pathlib
import unittest

from deploy.baremetal import membership, opstate

VECTOR = json.loads((pathlib.Path(__file__).resolve().parent / "vectors" / "sequence-cases-v1.json").read_text())


def entry(value):
    return {"kind": "sequence", "sequence_key": "cosmoshub-4\x007", "value": value}


class SequenceCases(unittest.TestCase):
    def test_opstate_transition_answers_the_sequence_cases(self):
        divergent = VECTOR["divergent"]["cases"].get("opstate.py", [])
        self.assertTrue(VECTOR["cases"])
        for case in VECTOR["cases"]:
            with self.subTest(case["name"]):
                previous = None if case["previous"] is None else entry(case["previous"])
                try:
                    opstate.transition(previous, entry(case["value"]))
                    got = "accept"
                except membership.Refused as refusal:
                    self.assertIn("is not above it", str(refusal))      # the sequence's refusal, not another
                    got = "refuse"
                if case["name"] in divergent:
                    self.assertNotEqual(got, case["documented"],
                                        "%s: opstate.py now answers as documented (%s): the divergence is gone; remove it from "
                                        "the vector's divergent list (%s)" % (case["name"], got, VECTOR["divergent"]["bead"]))
                else:
                    self.assertEqual(got, case["documented"], "%s: opstate.py's transition answers %s" % (case["name"], got))

    def test_the_vector_names_every_divergence_by_its_bead(self):
        self.assertEqual(VECTOR["divergent"]["bead"], "regalia-07k")
        names = {case["name"] for case in VECTOR["cases"]}
        for backend, cases in VECTOR["divergent"]["cases"].items():
            self.assertLessEqual(set(cases), names, backend)
        self.assertNotIn("filestate", VECTOR["divergent"]["cases"], "FileState is the documented rule")


if __name__ == "__main__":
    unittest.main()
