"""regalia-node enrol, design step 8 of #190: the enrolment record, signed by the node's AK in a TPM quote over its
digest (attest.quote_document, its own label), written after every path and before local.bin goes; and its
verification against the root-signed manifest with no TPM. The AK is OpenSSL's here (tests.test_baremetal_lease.Key),
the TPM anchor a FakeTpm."""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from deploy.baremetal import attest, enrol
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_replacement as rt


class FakeNode:
    def __init__(self, d, root, anchor):
        self.d, self.tcti, self.anchor_ = d, None, anchor
        self.cfg = {"root_key": root, "pcrs": [7, 11, 12], "nv_heartbeat": "0x01500018"}

    def anchor(self):
        return self.anchor_

    def path(self, name):
        return os.path.join(self.d, name)


class Record(rt.Case):
    def setUp(self):
        super().setUp()
        self.addCleanup(os.umask, os.umask(0o022))
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.chmod(base, 0o755)
        self.dir = base + "/enrol"
        enrol._safe_directory(self.dir)
        a, entry = self.keys["a"], self.entry("a")
        b64 = lambda h: base64.b64encode(bytes.fromhex(h)).decode()          # noqa: E731
        with open(self.dir + "/bundle.json", "w") as f:
            json.dump({"schema": enrol.SCHEMA_BUNDLE, "node_id": "a", "ek_name": a.ek_name, "ak_name": a.ak_name,
                       "ak_public": a.ak_public.hex(), "wg_service_pub": b64(entry["wg_service_pub"]),
                       "wg_boot_pub": b64(entry["wg_boot_pub"])}, f)
        self.journal = enrol.Journal(self.dir, "a")
        self.journal.done("espcreds", pcr12="12" * 32, credentials=[])
        self.journal.done("path:b", path_epoch=1, keyslot=3)
        self.journal.done("path:c", existing=True)
        self.root = hbt.pub(hbt.ROOT)
        anchor = m.HighWater("0x1500016", lock_path=base + "/hw.lock", run=hbt.FakeTpm())
        anchor.define()
        self.node = FakeNode(base, self.root, anchor)
        self.quoted = []

    def tpm(self, argv, **kw):
        """tpm2_quote, by node a's AK (OpenSSL) under its EK: the quote and signature the TPM would write."""
        self.assertEqual(argv[0], "tpm2_quote")
        digest = bytes.fromhex(argv[argv.index("-q") + 1])
        self.quoted.append(digest)
        signed = self.keys["a"].signer()(digest)
        for flag, key in (("-m", "quote"), ("-s", "sig")):
            with open(argv[argv.index(flag) + 1], "wb") as f:
                f.write(bytes.fromhex(signed[key]))
        return subprocess.CompletedProcess(argv, 0, "", "")

    def write(self):
        return enrol.write_record(self.journal, self.dir, self.node, self.m1, ["b", "c"], run=self.tpm, now=lambda: 0,
                                  tool=lambda: "test")

    def document(self):
        with open(self.dir + "/" + enrol.RECORD_FILE) as f:
            return json.load(f)

    def test_the_record_is_quoted_by_the_ak_and_verifies_against_the_manifest(self):
        record = self.write()
        self.assertEqual(sorted(record), sorted(enrol.RECORD_KEYS))
        self.assertEqual((record["node_id"], record["epoch"], record["manifest_digest"]), ("a", 1, m.digest(self.m1)))
        self.assertEqual(record["paths"], [{"peer": "b", "path_epoch": 1, "keyslot": 3}, {"peer": "c", "path_epoch": None, "keyslot": None}])
        self.assertEqual(record["peers"], [{"peer": p, "ak_name": self.keys[p].ak_name} for p in ("b", "c")])
        self.assertEqual(self.quoted, [attest.record_qualifying(m.canonical(record))])
        document = self.document()
        self.assertEqual(stat_mode(self.dir + "/" + enrol.RECORD_FILE), 0o644)
        facts = enrol.verify_record(document, [rt.sign(self.m1)], self.root)
        self.assertEqual(facts["ak_name"], self.keys["a"].ak_name)
        self.assertEqual(enrol.Journal(self.dir, "a").state("record"), "done")
        with open(self.dir + "/enrol-audit.jsonl") as f:
            events = [json.loads(line) for line in f.read().splitlines()]
        self.assertEqual([(e["event"], e["node"], e["outcome"]) for e in events], [("enrol", "a", "INCOMPLETE"), ("enrol", "a", "ALLOW")])
        import hashlib
        self.assertEqual(events[1]["record_sha256"], hashlib.sha256(m.canonical(document)).hexdigest())
        self.assertNotIn("record_sha256", events[0])

    def test_a_changed_record_or_another_root_or_manifest_is_refused(self):
        self.write()
        document = self.document()
        changed = json.loads(json.dumps(document))
        changed["record"]["paths"][0]["keyslot"] = 9
        with self.assertRaisesRegex(attest.Refused, "does not sign this document"):
            enrol.verify_record(changed, [rt.sign(self.m1)], self.root)
        with self.assertRaisesRegex((enrol.Refused, m.Refused), "not the one the record names"):
            enrol.verify_record(document, [rt.sign(self.m1)], hbt.pub(hbt.OTHER))
        other = dict(self.m1, nodes=[self.entry("a", ak_name=self.keys["x"].ak_name), self.entry("b"), self.entry("c")])
        with self.assertRaisesRegex((enrol.Refused, m.Refused), "record's (ak_name|manifest)|no manifest at epoch 1 with the record's digest"):
            enrol.verify_record(document, [rt.sign(other)], self.root)

    def test_a_crash_before_the_file_leaves_incomplete_and_no_allow(self):
        """regalia-kms-3e on #277: the ALLOW comes only after the record is durably in place."""
        import unittest.mock
        with unittest.mock.patch.object(enrol, "_atomic_json", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.write()
        with open(self.dir + "/enrol-audit.jsonl") as f:
            self.assertEqual([json.loads(line)["outcome"] for line in f.read().splitlines()], ["INCOMPLETE"])
        self.assertFalse(os.path.exists(self.dir + "/" + enrol.RECORD_FILE))
        self.write()
        with open(self.dir + "/enrol-audit.jsonl") as f:
            outcomes = [json.loads(line)["outcome"] for line in f.read().splitlines()]
        self.assertEqual(outcomes, ["INCOMPLETE", "INCOMPLETE", "ALLOW"], "one ALLOW, naming the one record that exists")

    def test_the_tool_version_comes_from_the_package_file_never_from_git(self):
        import unittest.mock
        version = os.path.join(self.node.d, "VERSION")
        with unittest.mock.patch.object(enrol, "VERSION_FILE", version), unittest.mock.patch.object(enrol.subprocess, "run",
                                                                                                     side_effect=AssertionError("no git")):
            self.assertEqual(enrol._tool(), "unknown")
            with open(version, "w") as f:
                f.write("0.9.1+g1a2b3c\n")
            self.assertEqual(enrol._tool(), "0.9.1+g1a2b3c")
            with open(version, "w") as f:
                f.write("x; rm -rf /\n")
            self.assertEqual(enrol._tool(), "unknown")

    def test_a_session_quote_cannot_pass_as_a_record_quote(self):
        record = self.write()
        session_digest = attest.qualifying_data("a", 1, b"S" * 32, b"key", b"N" * 32)
        signed = self.keys["a"].signer()(session_digest)
        document = {"record": record, "quote": signed["quote"], "signature": signed["sig"]}
        with self.assertRaisesRegex(attest.Refused, "does not sign this document"):
            enrol.verify_record(document, [rt.sign(self.m1)], self.root)


def stat_mode(path):
    import stat
    return stat.S_IMODE(os.stat(path).st_mode)


if __name__ == "__main__":
    unittest.main()
