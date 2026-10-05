"""#361 C2: K_A's approvals, per node and per class, in the measurements set beside the system-phase key they approve
(signing.anchor_approvals), and the K_A signer that makes them on the offline laptop (anchorpolicy approve-first,
approve, approve-increment). Each guard by an input only it refuses, with its own words."""
import copy
import io
import json
import os
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from deploy.baremetal import anchorpolicy as ap
from deploy.baremetal import attest, measurements, membership as m, signkey
from tests.test_baremetal_enrol import OTHER_PUB, SYSTEM_PUB

K_A = ec.derive_private_key(0x361C1, ec.SECP256R1())
POINT = K_A.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
OTHER_K_A = ec.derive_private_key(0x0BAD, ec.SECP256R1())


def signed_set(pem=SYSTEM_PUB, label="image-1", eleven=("a1", "b2")):
    return {"label": label, "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
            "phases": {"initrd": {"11": eleven[0] * 32}, "system": {"11": eleven[1] * 32}},
            "signing": {"initrd": "11" * 32, "system": signkey.pcr_key_fingerprint(pem), "secure_boot_cert": "22" * 32}}


def document(*sets):
    return {"schema": measurements.SCHEMA, "name": "signed", "nodes": {n: {"accepted": [copy.deepcopy(s) for s in (sets or (signed_set(),))]}
                                                                         for n in "abc"}}


GENERATIONS = {"a": 3, "b": 4, "c": 5}


class Approvals(unittest.TestCase):
    def test_a_filled_document_carries_each_node_s_own_approvals(self):
        doc = ap.fill(document(), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        measurements.validate(doc)
        for node_id, g in GENERATIONS.items():
            approvals = doc["nodes"][node_id]["accepted"][0]["signing"]["anchor_approvals"]
            self.assertEqual(ap.check_approvals(approvals, SYSTEM_PUB, POINT, node_id), g)
            self.assertEqual(sorted(approvals["classes"]), sorted(attest.APPROVAL_CLASSES))

    def test_an_approval_is_one_node_s_one_key_s_one_generation_s(self):
        doc = ap.fill(document(), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        a = doc["nodes"]["a"]["accepted"][0]["signing"]["anchor_approvals"]
        for name, args, reason in (
                ("node b's approvals presented for node a", (doc["nodes"]["b"]["accepted"][0]["signing"]["anchor_approvals"], SYSTEM_PUB, POINT, "a"),
                 "does not verify under the K_A it names"),
                ("another generation", (dict(a, generation=4), SYSTEM_PUB, POINT, "a"), "does not verify under the K_A it names"),
                ("another system-phase key", (a, OTHER_PUB, POINT, "a"), "does not verify under the K_A it names"),
                ("another K_A", (a, SYSTEM_PUB, OTHER_K_A.public_key().public_bytes(serialization.Encoding.X962,
                                                                                    serialization.PublicFormat.UncompressedPoint).hex(), "a"),
                 "does not verify under the K_A it names"),
                ("one class's signature in another's place", (dict(a, classes=dict(a["classes"], slots=a["classes"]["anchor"])), SYSTEM_PUB, POINT, "a"),
                 "anchor_approvals.classes.slots does not verify")):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, reason):
                ap.check_approvals(*args)

    def test_the_form_is_checked_with_the_document(self):
        good = ap.fill(document(), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        approvals = good["nodes"]["a"]["accepted"][0]["signing"]["anchor_approvals"]
        for name, change, reason in (
                ("an unknown class", lambda x: x["classes"].update(rotation="00" * 64), "anchor_approvals.classes fields mismatch"),
                ("a class missing", lambda x: x["classes"].pop("signing"), "anchor_approvals.classes fields mismatch"),
                ("generation 0", lambda x: x.update(generation=0), "anchor_approvals.generation must be a count from 1"),
                ("generation true", lambda x: x.update(generation=True), "anchor_approvals.generation must be a count from 1"),
                ("a short signature", lambda x: x["classes"].update(anchor="ab"), "anchor_approvals.classes.anchor must be 128 lowercase hex"),
                ("an extra field", lambda x: x.update(note=1), "anchor_approvals fields mismatch")):
            with self.subTest(name):
                bad = copy.deepcopy(good)
                change(bad["nodes"]["a"]["accepted"][0]["signing"]["anchor_approvals"])
                with self.assertRaisesRegex(m.Refused, reason):
                    measurements.validate(bad)
        self.assertEqual(ap.check_approvals(approvals, SYSTEM_PUB, POINT, "a"), 3)

    def test_fill_touches_only_this_key_s_sets_and_refuses_a_node_without_g(self):
        doc = document(signed_set(), signed_set(OTHER_PUB, "image-2", ("d4", "e5")))
        filled = ap.fill(doc, SYSTEM_PUB, POINT, K_A, GENERATIONS)
        self.assertIn("anchor_approvals", filled["nodes"]["a"]["accepted"][0]["signing"])
        self.assertNotIn("anchor_approvals", filled["nodes"]["a"]["accepted"][1]["signing"])
        with self.assertRaisesRegex(m.Refused, "c has a set signed by this system-phase key and no generation to approve it at"):
            ap.fill(doc, SYSTEM_PUB, POINT, K_A, {"a": 3, "b": 4})
        unsigned = document(signed_set(OTHER_PUB))
        with self.assertRaisesRegex(m.Refused, "no set in the document is signed by this system-phase key"):
            ap.fill(unsigned, SYSTEM_PUB, POINT, K_A, GENERATIONS)

    def test_at_a_rotation_g_is_the_current_document_s(self):
        """R moves only at a retire, by one: a key the current document already approves keeps its G; a new key gets one
        above the highest G the node's current sets carry."""
        current = ap.fill(document(signed_set()), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        self.assertEqual(ap.rotation_generations(current, SYSTEM_PUB, POINT), GENERATIONS)
        self.assertEqual(ap.rotation_generations(current, OTHER_PUB, POINT), {n: g + 1 for n, g in GENERATIONS.items()})
        self.assertEqual(ap.rotation_generations(document(signed_set(OTHER_PUB)), SYSTEM_PUB, POINT), {})

    def test_a_third_live_key_is_refused(self):
        """regalia-kms-d9: CURRENT at G and NEXT at G+1 are live; a third key waits for the retire's bump."""
        third = ec.generate_private_key(ec.SECP256R1())          # stands in for nothing: its PEM is only fingerprinted
        from tests.test_baremetal_enrol import _rsa_pem
        third_pem = _rsa_pem()
        current = ap.fill(document(signed_set(), signed_set(OTHER_PUB, "image-2", ("d4", "e5"))), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        current = ap.fill(current, OTHER_PUB, POINT, K_A, {n: g + 1 for n, g in GENERATIONS.items()})
        with self.assertRaisesRegex(m.Refused, "keys at G 3 and 4 are live on node a; retire the older"):
            ap.rotation_generations(current, third_pem, POINT)
        self.assertEqual(ap.rotation_generations(current, OTHER_PUB, POINT), {n: g + 1 for n, g in GENERATIONS.items()})   # a known key: fine
        del third

    def test_the_increment_approval_is_one_node_s_from_one_value(self):
        doc = ap.increment_document(K_A, POINT, "a", 7)
        self.assertEqual((doc["schema"], doc["node_id"], doc["from"]), (ap.INCREMENT_SCHEMA, "a", 7))
        rotation_a = ap.rotation_name(int(ap.ROTATION_INDEX, 16), POINT, "a")
        ap.verify_approval(POINT, ap.increment_from(rotation_a, 7), ap.rotation_class("a"), doc["signature"], "it")
        rotation_b = ap.rotation_name(int(ap.ROTATION_INDEX, 16), POINT, "b")
        for policy, cls in ((ap.increment_from(rotation_b, 7), ap.rotation_class("b")), (ap.increment_from(rotation_a, 8), ap.rotation_class("a"))):
            with self.assertRaisesRegex(m.Refused, "does not verify under the K_A it names"):
                ap.verify_approval(POINT, policy, cls, doc["signature"], "it")


def pem_of(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def key_fd(key):
    r, w = os.pipe()
    os.write(w, pem_of(key))
    os.close(w)
    return r


class Signer(unittest.TestCase):
    """The CLI, as offline-keys runs it: the key on a pipe, the K_A source explicit, nothing printed before every check."""

    def setUp(self):
        import tempfile
        import shutil
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def path(self, name, value):
        p = os.path.join(self.d, name)
        with open(p, "wb" if isinstance(value, bytes) else "w") as f:
            if isinstance(value, bytes):
                f.write(value)
            else:
                json.dump(value, f)
        return p

    def state(self, root):
        """The laptop's state directory for `root`: its marker (as the card ceremony writes it) and its signing record."""
        from deploy.baremetal import cardrecord
        d = os.path.join(self.d, "state-" + root[:8])
        if not os.path.isdir(d):
            os.mkdir(d, 0o700)
            with open(os.open(os.path.join(d, cardrecord.SIGNING_STATE), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump({"schema": cardrecord.SIGNING_STATE_SCHEMA, "root": root}, f)
        return d

    def issued(self, root):
        from deploy.baremetal import cardrecord
        path = os.path.join(self.state(root), cardrecord.SIGNING_RECORD)
        return [json.loads(line) for line in open(path)] if os.path.exists(path) else []

    def run_cli(self, *argv, key=K_A):
        root = argv[list(argv).index("--root-key") + 1]
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stderr", err):
            code = ap.main(list(argv) + ["--key-fd", str(key_fd(key)), "--offline-session", "ab" * 16, "--state-dir", self.state(root)], out=out)
        return code, out.getvalue(), err.getvalue()

    def chain(self, doc):
        """A v4 chain whose tip pins this K_A and commits to `doc`."""
        from tests.test_baremetal_membership import ROOT, sign
        from tests.test_baremetal_membership_v4 import manifest4, nodes4
        man = manifest4(1, "", nodes4(), anchor_policy_key={"alg": "ecdsa-p256", "key": POINT}, policy_version=measurements.version(doc))
        return [sign(man, ROOT)]

    def test_approve_increment_from_the_chain_s_k_a(self):
        from tests.test_baremetal_membership import ROOT_PUB
        chain = self.path("chain.json", self.chain(document()))
        code, out, err = self.run_cli("approve-increment", "--root-key", ROOT_PUB, "--chain", chain, "--node-id", "a", "--from", "5")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), ap.increment_document(K_A, POINT, "a", 5) | {"signature": json.loads(out)["signature"]})
        self.assertEqual([(l["kind"], l["node_id"], l["from"], l["provenance"]) for l in self.issued(ROOT_PUB)],
                         [("anchor-increment", "a", 5, "offline-keys session " + "ab" * 16)])
        code, out, err = self.run_cli("approve-increment", "--root-key", ROOT_PUB, "--chain", chain, "--node-id", "a", "--from", "5", key=OTHER_K_A)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--key-fd: this key is not the pinned K_A", err)
        self.assertEqual(len(self.issued(ROOT_PUB)), 1, "a refusal recorded an issuance")
        code, out, err = self.run_cli("approve-increment", "--root-key", ROOT_PUB, "--chain", chain, "--node-id", "z", "--from", "5")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("z is not a node of the chain's tip", err)

    def test_flags_exactly_and_paths_absolute(self):
        """regalia-kms-51: no abbreviation of a flag (offline-keys checks the exact ones), and every path absolute (it runs
        tools from inside its own tree)."""
        from tests.test_baremetal_membership import ROOT_PUB
        chain = self.path("chain.json", self.chain(document()))
        err = io.StringIO()
        with unittest.mock.patch("sys.stderr", err), self.assertRaises(SystemExit):
            ap.main(["approve-increment", "--root-key", ROOT_PUB, "--chain", chain, "--node-id", "a", "--from", "5", "--key-fd", "9",
                     "--key-f", "0", "--offline-session", "ab" * 16, "--state-dir", self.state(ROOT_PUB)], out=io.StringIO())
        self.assertIn("unrecognized arguments: --key-f", err.getvalue())
        code, out, err = self.run_cli("approve-increment", "--root-key", ROOT_PUB, "--chain", os.path.relpath(chain), "--node-id", "a", "--from", "5")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--chain %s is not an absolute path" % os.path.relpath(chain), err)

    def test_the_state_directory_is_this_root_s(self):
        """The issuance record goes to the laptop's record of THIS root's uses (manifest.signing_state): another root's
        directory is refused before anything is read, and nothing is printed."""
        from tests.test_baremetal_membership import ROOT_PUB
        chain = self.path("chain.json", self.chain(document()))
        err, out = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stderr", err):
            code = ap.main(["approve-increment", "--root-key", ROOT_PUB, "--chain", chain, "--node-id", "a", "--from", "5", "--key-fd",
                            str(key_fd(K_A)), "--offline-session", "ab" * 16, "--state-dir", self.state("cd" * 32)], out=out)
        self.assertEqual((code, out.getvalue()), (2, ""))
        self.assertIn("is another root's signing state: nothing is signed", err.getvalue())

    def test_approve_at_a_rotation(self):
        from tests.test_baremetal_membership import ROOT_PUB
        current = ap.fill(document(), SYSTEM_PUB, POINT, K_A, GENERATIONS)
        new = document(signed_set(), signed_set(OTHER_PUB, "image-2", ("d4", "e5")))
        for n in "abc":
            new["nodes"][n]["accepted"][0] = current["nodes"][n]["accepted"][0]
        args = ["approve", "--root-key", ROOT_PUB, "--chain", self.path("chain.json", self.chain(current)), "--current",
                self.path("current.json", current), "--document", self.path("new.json", new), "--system-pub", self.path("k.pem", OTHER_PUB)]
        code, out, err = self.run_cli(*args)
        self.assertEqual(code, 0, err)
        filled = json.loads(out)
        for n, g in GENERATIONS.items():
            self.assertEqual(ap.check_approvals(filled["nodes"][n]["accepted"][1]["signing"]["anchor_approvals"], OTHER_PUB, POINT, n), g + 1)
        self.assertEqual([(l["kind"], l["node_id"], l["k_sys"], l["generation"]) for l in self.issued(ROOT_PUB)],
                         [("anchor-approval", n, signkey.pcr_key_fingerprint(OTHER_PUB), g + 1) for n, g in sorted(GENERATIONS.items())])
        # a current document the chain does not commit to is refused
        args[args.index("--current") + 1] = self.path("other.json", dict(current, name="other"))
        code, out, err = self.run_cli(*args)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("it is not the one the root approved, or it is an older or newer one", err)

    def test_approve_at_the_genesis_takes_each_node_s_quoted_first_value(self):
        """G at the genesis is the node's AK-quoted first value of R (enrol.rotation_of under THIS K_A): never typed. The
        proof itself is enrol's (stubbed here, as test_baremetal_manifest stubs it)."""
        from deploy.baremetal import enrol
        from tests.test_baremetal_manifest import ProposeGenesis
        case = ProposeGenesis("test_k_a_and_the_card_record_are_in_the_genesis")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.k_a = K_A
        nodes = []
        for e in case.entries:
            files = [self.path("%s-%s.json" % (k, e["node_id"]), v) for k, v in (("bundle", case.bundle_of(e)), ("keep", {"node_id": e["node_id"]}),
                                                                                 ("activation", {"node_id": e["node_id"]}))]
            nodes += ["--node"] + files
        args = ["approve", "--root-key", case.root, "--offline-keys-record", self.path("rec.json", case.generation_record()),
                "--document", self.path("d.json", document()), "--system-pub", self.path("k.pem", SYSTEM_PUB)] + nodes
        proven = lambda bundle, pem, keep, act, run=None: ({k: v for k, v in bundle.items() if k != "rotation"}, {})  # noqa: E731
        with unittest.mock.patch.object(enrol, "proven_entry", proven):
            code, out, err = self.run_cli(*args)
        self.assertEqual(code, 0, err)
        filled = json.loads(out)
        for n, g in (("a", 3), ("b", 4), ("c", 5)):
            self.assertEqual(ap.check_approvals(filled["nodes"][n]["accepted"][0]["signing"]["anchor_approvals"], SYSTEM_PUB, POINT, n), g)
        # a node enrolled under another K_A is refused before anything is printed
        bad = case.bundle_of(case.entries[1], OTHER_K_A)
        args[args.index(self.d + "/bundle-b.json")] = self.path("bundle-b2.json", bad)
        with unittest.mock.patch.object(enrol, "proven_entry", proven):
            code, out, err = self.run_cli(*args)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("b's rotation counter is not under this genesis's K_A", err)

    def test_approve_first_per_node_and_the_sources_are_explicit(self):
        from tests.test_baremetal_manifest import ProposeGenesis
        case = ProposeGenesis("test_k_a_and_the_card_record_are_in_the_genesis")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.k_a = K_A
        record = self.path("rec.json", case.generation_record())
        code, out, err = self.run_cli("approve-first", "--root-key", case.root, "--offline-keys-record", record, "--node-id", "b")
        self.assertEqual(code, 0, err)
        self.assertEqual(ap.read_first(json.loads(out), "b")[:2], ("b", POINT))
        self.assertEqual([(l["kind"], l["node_id"]) for l in self.issued(case.root)], [("anchor-first", "b")])
        code, out, err = self.run_cli("approve-first", "--root-key", case.root, "--offline-keys-record", record, "--node-id", "b", key=OTHER_K_A)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("--key-fd: this key is not the pinned K_A", err)
        # approve takes the genesis's sources or the rotation's, never both and never neither
        code, _, err = self.run_cli("approve", "--root-key", case.root, "--document", self.path("d.json", document()),
                                    "--system-pub", self.path("k.pem", SYSTEM_PUB))
        self.assertEqual(code, 2)
        self.assertIn("give --offline-keys-record and --node (the genesis), or --chain and --current (a rotation), not both", err)


if __name__ == "__main__":
    unittest.main()
