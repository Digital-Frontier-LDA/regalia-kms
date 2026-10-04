"""tests/vectors/membership-v1.json, which the Go port reads (cmd/regalia-unlock/membership), replayed by the Python
that wrote it: every recorded accept() and verify_envelope() call, every crafted case and every document is decided
here exactly as the file says, reason included. A change to the Python's rules or wording that is not carried into
the file fails here, on the side that changed, instead of surfacing later as a Go test failing on stale words
(regalia-kms#359: v4 reworded two refusals and the file kept the old ones). membership-v4.json has its own replay
in test_baremetal_membership_v4.py."""
import json
import pathlib
import unittest

from deploy.baremetal import membership as m

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "membership-v1.json"


def restored(value):
    """A value from the file as the Python gave it: every "public" read back as "key" (the file's composition,
    make-membership-v1.py)."""
    if isinstance(value, dict):
        return {("key" if k == "public" else k): restored(v) for k, v in value.items()}
    if isinstance(value, list):
        return [restored(v) for v in value]
    return value


def envelope_of(stored):
    """An envelope the file stores in parts: its signature's key beside it, as "signature_public"."""
    document = restored(stored["document"])
    if "signature_public" in stored:
        document["signature"]["key"] = stored["signature_public"]
    return document


def outcome(call):
    """What the Python decides now: {"accepted": digest} or {"refused": reason}, as make-membership-v1.py records
    it (a crafted case that fails outright is recorded with the exception's type)."""
    try:
        return {"accepted": m.digest(call())}
    except m.Refused as refusal:
        return {"refused": str(refusal)}


class Vectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text())

    def expected(self, record, keys):
        return {k: record[k] for k in keys if k in record}

    def test_every_recorded_accept_is_what_this_python_decides(self):
        calls = self.vectors["calls"]
        self.assertGreaterEqual(len(calls), 100)
        for i, call in enumerate(calls):
            with self.subTest(call=i):
                got = outcome(lambda: m.accept(restored(call["current"]), envelope_of(call["envelope"]), restored(call["root_public"])))
                self.assertEqual(got, self.expected(call, ("accepted", "refused")))

    def test_every_recorded_verification_is_what_this_python_decides(self):
        records = self.vectors["verified"]
        self.assertGreaterEqual(len(records), 100)
        for i, record in enumerate(records):
            with self.subTest(verification=i):
                try:
                    manifest, signer = m.verify_envelope(envelope_of(record["envelope"]), restored(record["root_public"]), restored(record["current"]))
                    got = {"verified": m.digest(manifest), "signer": signer}
                except m.Refused as refusal:
                    got = {"refused": str(refusal)}
                self.assertEqual(got, self.expected(record, ("verified", "signer", "refused")))

    def test_every_crafted_case_is_what_this_python_decides(self):
        crafted = self.vectors["crafted"]
        self.assertGreaterEqual(len(crafted), 30)
        for case in crafted:
            with self.subTest(case["name"]):
                envelope = envelope_of(case["envelope"])
                try:
                    got = outcome(lambda: m.accept(restored(case["current"]), envelope, restored(case["root_public"])))
                except Exception as error:  # noqa: BLE001  recorded as the generator records it
                    got = {"refused": "%s: %s" % (type(error).__name__, error)}
                self.assertEqual(got, self.expected(case, ("accepted", "refused")))
                try:
                    m.validate(envelope["manifest"])
                    valid = True
                except Exception:  # noqa: BLE001
                    valid = False
                self.assertEqual(valid, case["valid"])

    def test_every_document_is_read_as_recorded(self):
        for document in self.vectors["documents"]:
            with self.subTest(document["name"]):
                data = bytes.fromhex(document["hex"])
                try:
                    canonical = m.canonical(m.load(data)).decode()
                    taken = True
                except (m.Refused, UnicodeDecodeError):
                    canonical, taken = None, False
                self.assertEqual((taken, canonical), (document["taken"], document["canonical"]))


if __name__ == "__main__":
    unittest.main()
