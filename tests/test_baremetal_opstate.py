"""deploy/baremetal/opstate.py (ADR-0002 D32, #432): the entries the three servers share through etcd, each carrying its
own authorization. tests/vectors/opstate-v1.json, which the Go verifier reads, is replayed here and must be current."""
import json
import pathlib
import subprocess
import sys
import unittest

from deploy.baremetal import heartbeat, lease, membership as m, opstate

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "opstate-v1.json"
MAKE = ROOT / "tests" / "vectors" / "make-opstate-v1.py"


def load():
    with open(VECTORS) as f:
        return json.load(f)


class Vectors(unittest.TestCase):
    def test_every_case_is_decided_as_the_vector_says(self):
        doc = load()
        sessions = lambda node, boot: doc["sessions"].get("%s|%s" % (node, boot))      # noqa: E731
        for c in doc["cases"]:
            with self.subTest(c["name"]):
                try:
                    entry = opstate.verify(c["key"], c["value"], sessions, doc["approvers"], c["required"])
                    opstate.transition(c["previous"], entry)
                    got, why = True, ""
                except m.Refused as refused:
                    got, why = False, str(refused)
                self.assertEqual((got, why), (c["accept"], c["python_reason"]))
        for b in doc["batches"]:
            with self.subTest(b["name"]):
                try:
                    opstate.batch([(w["key"], w["value"], w["previous"]) for w in b["writes"]])
                    got, why = True, ""
                except m.Refused as refused:
                    got, why = False, str(refused)
                self.assertEqual((got, why), (b["accept"], b["python_reason"]))

    def test_the_vector_is_what_the_generator_makes_now(self):
        made = subprocess.run([sys.executable, "-Es", str(MAKE)], capture_output=True, text=True, check=True, cwd=ROOT).stdout
        self.assertEqual(json.loads(made), load(), "regenerate: python3 -Es tests/vectors/make-opstate-v1.py > tests/vectors/opstate-v1.json")

    def test_both_outcomes_and_every_kind_are_covered(self):
        doc = load()
        kinds = {c["value"]["entry"].get("kind") for c in doc["cases"]}
        self.assertTrue(set(opstate.KINDS) <= kinds)
        self.assertTrue(any(c["accept"] for c in doc["cases"]) and any(not c["accept"] for c in doc["cases"]))
        self.assertTrue(any(b["accept"] for b in doc["batches"]) and any(not b["accept"] for b in doc["batches"]))


class Format(unittest.TestCase):
    def test_its_own_domain(self):
        for other in (m.DOMAIN, heartbeat.DOMAIN, lease.DOMAIN):
            self.assertFalse(opstate.DOMAIN.startswith(other) or other.startswith(opstate.DOMAIN))

    def test_names_inside_a_key_are_hashed_so_a_slash_cannot_join_two_keys(self):
        a = {"schema": opstate.SCHEMA, "kind": "quota", "at": "2026-10-05T12:00:00Z", "principal": "spiffe://x/a", "utc_date": "2026-10-05",
             "counter": "b", "total": 1, "cap": 2, "nonce_digest": "00" * 32, "node_id": "a", "boot_id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"}
        b = dict(a, principal="spiffe://x", counter="a/2026-10-05/b")
        self.assertNotEqual(opstate.key_for(a), opstate.key_for(b))
        self.assertRegex(opstate.key_for(a), r"^/regalia/v1/quota/[0-9a-f]{64}/2026-10-05/[0-9a-f]{64}$")

    def test_a_nonce_is_spent_under_its_sha256(self):
        self.assertEqual(opstate.nonce_digest("n"), "1b16b1df538ba12dc3f97edbb85caa7050d46c148134290feba80f8236c83db9")
        with self.assertRaises(m.Refused):
            opstate.nonce_digest("")

    def test_a_reserve_fits_one_etcd_transaction(self):
        self.assertLessEqual(opstate.MAX_BATCH, 128 // 2)        # etcd's --max-txn-ops default, with room for the compares


if __name__ == "__main__":
    unittest.main()
