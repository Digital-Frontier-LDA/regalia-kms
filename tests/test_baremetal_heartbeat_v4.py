"""Heartbeats under a v4 manifest (#199): signed by a quorum of the nodes and the owner, the owner's an emergency
credential with a short life. The membership side (counting_parties, meets, the v4 fields) is #350's."""
import json
import pathlib
import unittest

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from tests.test_baremetal_membership_v4 import A, B, C, NODE_KEYS, O1, O2, OWNER_KEYS, STRANGER, manifest4, nodes4, p256_sig, pub

T0 = 1790000000
VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "heartbeat-v4.json"


def stamp(seconds):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def body(man, sequence=7, lifetime=3600, issued=T0):
    return {"schema": hb.SCHEMA, "epoch": man["epoch"], "sequence": sequence, "issued_at": stamp(issued),
            "expires_at": stamp(issued + lifetime), "manifest_digest": m.digest(man)}


def quorum(heartbeat, *signers, high=False):
    message = hb.DOMAIN + m.canonical(heartbeat)
    return {"heartbeat": heartbeat, "signatures": [{"party": party, "key": pub(key), "sig": p256_sig(key, message, high)}
                                                   for party, key in signers]}


class Quorum(unittest.TestCase):
    def setUp(self):
        self.man = manifest4(1, "", nodes4())

    def refused(self, reason, *args):
        with self.assertRaises(m.Refused) as caught:
            hb.verify(*args)
        self.assertIn(reason, str(caught.exception))

    def test_two_nodes_keep_it_fresh(self):
        heartbeat = body(self.man, lifetime=21600)
        self.assertEqual(hb.verify(quorum(heartbeat, A, B), self.man), heartbeat)
        self.assertEqual(hb.signed_by(quorum(heartbeat, B, C), self.man)[3], {"b", "c"})

    def test_a_node_and_the_owner_mixed_algorithms_for_an_hour_at_most(self):
        """The total-outage recovery: the node opened by hand (TPM P-256) and the operator's approval key (Ed25519)."""
        short = body(self.man, lifetime=3600)
        self.assertEqual(hb.verify(quorum(short, A, O1), self.man), short)
        self.refused("a heartbeat the owner signed lives at most 3600 s", quorum(body(self.man, lifetime=21600), A, O1), self.man)
        # the owner's signature caps it whoever else signed: two nodes and the owner, six hours, refused
        self.refused("a heartbeat the owner signed lives at most 3600 s", quorum(body(self.man, lifetime=21600), A, B, O1), self.man)

    def test_one_party_alone_never(self):
        for signers in ((A,), (O1,)):
            with self.subTest(signers[0][0]):
                self.refused("2 of a, b, c, owner are needed", quorum(body(self.man), *signers), self.man)

    def test_the_owner_counts_once_whichever_of_its_keys(self):
        self.refused("is named twice", quorum(body(self.man), O1, O2), self.man)

    def test_a_quarantined_retired_or_stolen_node_does_not_count(self):
        for state in ("QUARANTINED", "RETIRED", "REVOKED_STOLEN"):
            with self.subTest(state):
                man = manifest4(1, "", nodes4(b=state))
                self.refused("signed by a: 2 of", quorum(body(man), A, B), man)
                self.assertEqual(hb.verify(quorum(body(man), A, C), man)["sequence"], 7)

    def test_a_node_the_rule_does_not_name_does_not_count(self):
        """meets() counts only the rule's parties: c is a node of the manifest, its signature verifies, and it is not one."""
        man = manifest4(1, "", nodes4(), heartbeat_signers={"threshold": 2, "parties": ["a", "b", "owner"]})
        self.refused("2 of a, b, owner are needed", quorum(body(man), A, C), man)
        self.assertEqual(hb.verify(quorum(body(man), A, B), man)["sequence"], 7)

    def test_a_key_that_is_not_the_party_s_or_a_high_s_signature(self):
        self.refused("the key is not a's signing_key", quorum(body(self.man), ("a", STRANGER), B), self.man)
        self.refused("the key is not one of the current manifest's owner_keys", quorum(body(self.man), A, ("owner", STRANGER)), self.man)
        self.refused("the heartbeat (signatures[0], a) signature is not a low-S P-256 signature", quorum(body(self.man), A, B, high=True), self.man)

    def test_the_single_key_form_is_not_a_v4_heartbeat(self):
        heartbeat = body(self.man)
        single = {"heartbeat": heartbeat, "signature": {"key": pub(NODE_KEYS["a"]),
                                                          "sig": p256_sig(NODE_KEYS["a"], hb.DOMAIN + m.canonical(heartbeat))}}
        self.refused("envelope fields mismatch: missing=['signatures'] unknown=['signature']", single, self.man)

    def test_a_signature_over_another_body_does_not_count(self):
        heartbeat, other = body(self.man), body(self.man, sequence=8)
        envelope = quorum(heartbeat, A)
        envelope["signatures"].append(quorum(other, B)["signatures"][0])
        self.refused("the heartbeat (signatures[1], b) signature does not verify", envelope, self.man)

    def test_the_owner_lifetime_never_loosens_the_manifest_bound(self):
        self.refused("lives at most 21600 s", quorum(body(self.man, lifetime=21601), A, B), self.man)


def restored(document):
    """A document from the vectors file: every "public" read back as "key" (tests/vectors/make-heartbeat-v4.py)."""
    if isinstance(document, dict):
        return {("key" if k == "public" else k): restored(v) for k, v in document.items()}
    if isinstance(document, list):
        return [restored(v) for v in document]
    return document


class Vectors(unittest.TestCase):
    def test_the_shared_vectors_are_what_this_python_decides(self):
        """tests/vectors/heartbeat-v4.json, which the Go port reads, replayed here: a vector the Python no longer
        decides the same way fails, so the file cannot drift from the code."""
        cases = json.loads(VECTORS.read_text())["cases"]
        seen = {"accepted": 0, "refused": 0}
        for case in cases:
            with self.subTest(case["name"]):
                try:
                    outcome = {"accepted": hb.verify(restored(case["envelope"]), restored(case["current"]))}
                except m.Refused as refusal:
                    outcome = {"refused": str(refusal)}
                want = {k: case[k] for k in ("accepted", "refused") if k in case}
                self.assertEqual(outcome, want)
                seen[next(iter(want))] += 1
        self.assertTrue(seen["accepted"] >= 5 and seen["refused"] >= 12, seen)
        # the owner's lifetime, both ways, is in the file for the Go side's arithmetic
        self.assertTrue(any("owner signed lives at most" in c.get("refused", "") for c in cases))


if __name__ == "__main__":
    unittest.main()
