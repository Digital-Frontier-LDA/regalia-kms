"""#361 C4b: the re-sign at a retire (uki.resign, attest.validate_resigned; regalia-kms-05's conditions on #361). K_new
signs PolicyPCR(11) of each image a node may still run, only once K_new's own set carries K_A's approvals for that node;
a set the document no longer accepts gets nothing. The node's checks before it bumps are test_baremetal_anchor_catchup's."""
import base64
import copy
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from deploy.baremetal import anchorpolicy as ap
from deploy.baremetal import attest, measurements, signkey, uki
from deploy.baremetal import membership as m
from tests.test_baremetal_anchor_approvals import GENERATIONS, K_A, OTHER_K_A, POINT, document, signed_set
from tests.test_baremetal_enrol import SYSTEM_PUB

NEW = rsa.generate_private_key(public_exponent=65537, key_size=2048)
NEW_PUB = NEW.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
OTHER_POINT = OTHER_K_A.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
NEW_PRIVATE = NEW.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def documents():
    """(current, new): CURRENT approves SYSTEM_PUB's image at GENERATIONS; NEW adds K_new's image at G + 1."""
    current = ap.fill(document(), SYSTEM_PUB, POINT, K_A, GENERATIONS)
    new = copy.deepcopy(current)
    for node in new["nodes"].values():
        node["accepted"].append(signed_set(NEW_PUB, "image-2", ("d4", "e5")))
    return current, ap.fill(new, NEW_PUB, POINT, K_A, {n: g + 1 for n, g in GENERATIONS.items()})


class Resign(unittest.TestCase):
    def test_k_new_signs_each_still_accepted_image_s_policy(self):
        _, new = documents()
        out = uki.resign(new, NEW_PUB, NEW_PRIVATE, POINT)
        fp = signkey.pcr_key_fingerprint(NEW_PUB)
        for node_id, node in out["nodes"].items():
            with self.subTest(node_id):
                old, mine = node["accepted"]
                resigned = old["signing"]["resigned"]
                self.assertEqual((resigned["system"], resigned["pol"]), (fp, uki.policy_digest(old["phases"]["system"]["11"])))
                NEW.public_key().verify(base64.b64decode(resigned["sig"]), bytes.fromhex(resigned["pol"]), padding.PKCS1v15(), hashes.SHA256())
                self.assertNotIn("resigned", mine["signing"], "K_new's own image needs no re-sign")
        measurements.validate(out)
        self.assertNotIn("resigned", new["nodes"]["a"]["accepted"][0]["signing"], "the caller's document was changed")

    def test_a_retired_image_gets_nothing(self):
        """05's condition 1: an image the new document no longer accepts is not re-signed (it is not there)."""
        _, new = documents()
        for node in new["nodes"].values():
            del node["accepted"][0]                                  # image-1 retired at G + 1
        with self.assertRaisesRegex(m.Refused, "no image needed re-signing"):
            uki.resign(new, NEW_PUB, NEW_PRIVATE, POINT)

    def test_only_with_k_new_s_approvals_and_its_own_private_key(self):
        _, new = documents()
        unapproved = copy.deepcopy(new)
        del unapproved["nodes"]["b"]["accepted"][1]["signing"]["anchor_approvals"]
        with self.assertRaisesRegex(m.Refused, "b's set signed by the new key carries no K_A approvals: approve it"):
            uki.resign(unapproved, NEW_PUB, NEW_PRIVATE, POINT)
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        with self.assertRaisesRegex(m.Refused, "the private key on the descriptor is not the new system-phase key's"):
            uki.resign(new, NEW_PUB, other, POINT)
        with self.assertRaisesRegex(m.Refused, "does not verify under the K_A it names"):
            uki.resign(new, NEW_PUB, NEW_PRIVATE, OTHER_K_A.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex())     # another K_A than the approvals

    def test_the_form(self):
        _, new = documents()
        good = uki.resign(new, NEW_PUB, NEW_PRIVATE, POINT)["nodes"]["a"]["accepted"][0]["signing"]
        for name, change, reason in (
                ("its own key", lambda r: r.update(system=good["system"]), "another key than the set's own"),
                ("not a PEM", lambda r: r.update(pem="x"), "must be a PEM public key"),
                ("a short signature", lambda r: r.update(sig=base64.b64encode(b"x" * 10).decode()), "base64 of an RSA-2048 signature"),
                ("an unknown field", lambda r: r.update(at=1), "fields mismatch")):
            with self.subTest(name):
                resigned = copy.deepcopy(good["resigned"])
                change(resigned)
                with self.assertRaisesRegex(attest.Refused, reason):
                    attest.validate_resigned(resigned, good["system"], "resigned")


if __name__ == "__main__":
    unittest.main()


class NodeChecks(unittest.TestCase):
    """The node's checks before it bumps on a re-sign (node._resigned; 05's condition 2 and addition (a)), each refused
    with its own words; then the switch to the new key after the bump (node._switched) and the merged signatures."""

    def setUp(self):
        import os
        import tempfile
        from unittest import mock
        from deploy.baremetal import node
        self.node, self.mock = node, mock
        _, new = documents()
        self.doc = uki.resign(new, NEW_PUB, NEW_PRIVATE, POINT)
        self.cfg = {"node_id": "a", "tcti": None, "state_dir": "/nonexistent"}
        self.pcr11 = self.doc["nodes"]["a"]["accepted"][0]["phases"]["system"]["11"]
        d = tempfile.mkdtemp(prefix="resign-")
        self.addCleanup(__import__("shutil").rmtree, d, True)
        p = mock.patch.object(signkey, "RESIGNED_PATH", os.path.join(d, "run", "resigned.json"))
        p.start()
        self.addCleanup(p.stop)

    def resigned(self, change=None, pcr11=None):
        doc = copy.deepcopy(self.doc)
        if change:
            change(doc)
        return self.node._resigned(self.cfg, doc, SYSTEM_PUB, POINT, pcr11=pcr11 or self.pcr11)

    def test_a_good_re_sign_moves_the_node_to_the_new_key_s_generation(self):
        got = self.resigned()
        self.assertEqual((got["pem"], got["generation"]), (NEW_PUB, GENERATIONS["a"] + 1))
        self.assertEqual(got["entry"]["pkfp"], signkey.pcr_key_fingerprint(NEW_PUB))
        self.assertIsNone(self.node._resigned(self.cfg, documents()[1], SYSTEM_PUB, POINT, pcr11=self.pcr11), "nothing re-signed: None")

    def test_each_check_refuses_with_its_own_words(self):
        old = lambda d: d["nodes"]["a"]["accepted"][0]["signing"]                  # noqa: E731
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        for name, change, pcr11, reason in (
                ("a key no set is signed by", lambda d: old(d)["resigned"].update(system="ab" * 32), None,
                 "names a key (abababababababab...) no accepted set of a is signed by"),
                ("another PEM than the key named", lambda d: old(d)["resigned"].update(pem=other), None,
                 "the re-sign's public key is not the key it names"),
                ("a signature that does not verify", lambda d: old(d)["resigned"].update(sig=base64.b64encode(b"\0" * 256).decode()), None,
                 "the re-sign of a's booted image does not verify under the key it names"),
                ("another policy", lambda d: old(d)["resigned"].update(
                    pol=uki.policy_digest("00" * 32), sig=base64.b64encode(NEW.sign(bytes.fromhex(uki.policy_digest("00" * 32)),
                                                                                   padding.PKCS1v15(), hashes.SHA256())).decode()), None,
                 "is over another policy than PolicyPCR(11 = "),
                ("another boot", None, "77" * 32, "this TPM's PCR 11 is 7777777777777777..., not the "),
                ("no approvals on the new key's set", lambda d: d["nodes"]["a"]["accepted"][1]["signing"].pop("anchor_approvals"), None,
                 "the new key's set for a carries no K_A approvals"),
                # 05 on #517: the approvals are checked, not taken as given
                ("another node's approvals", lambda d: d["nodes"]["a"]["accepted"][1]["signing"].update(
                    anchor_approvals=copy.deepcopy(d["nodes"]["b"]["accepted"][1]["signing"]["anchor_approvals"])), None,
                 "does not verify under the K_A it names"),
                ("approvals under another K_A", lambda d: d["nodes"]["a"]["accepted"][1]["signing"].update(
                    anchor_approvals=ap.approvals_for(OTHER_K_A, NEW_PUB, OTHER_POINT, GENERATIONS["a"] + 1, "a")), None,
                 "does not verify under the K_A it names")):
            with self.subTest(name), self.assertRaises(m.Refused) as caught:
                self.resigned(change, pcr11)
            self.assertIn(reason, str(caught.exception))

    def test_after_the_bump_writes_go_under_the_new_key(self):
        import json
        import os
        manifest = {"schema": m.SCHEMA_V4, "anchor_policy_key": {"key": POINT}}
        g = GENERATIONS["a"]
        with self.mock.patch.object(self.node, "_pcr11", lambda cfg: self.pcr11):
            with self.mock.patch.object(ap, "read_rotation", lambda index, run: g):           # not bumped: the old key
                self.assertIsNone(self.node._switched(self.cfg, manifest, self.doc, SYSTEM_PUB))
            with self.mock.patch.object(ap, "read_rotation", lambda index, run: g + 1):       # bumped: the new key
                self.assertEqual(self.node._switched(self.cfg, manifest, self.doc, SYSTEM_PUB)["pem"], NEW_PUB)
        with open(signkey.RESIGNED_PATH) as f:
            kept = json.load(f)
        self.assertEqual(kept["sha256"][0]["pkfp"], signkey.pcr_key_fingerprint(NEW_PUB))
        # merged into the boot's own signatures: pcr_signature picks it by key and policy
        boot = os.path.join(os.path.dirname(signkey.RESIGNED_PATH), "boot.json")
        with open(boot, "w") as f:
            json.dump({"sha256": [{"pcrs": [11], "pkfp": "cd" * 32, "pol": "ef" * 32, "sig": "AA=="}]}, f)
        with self.mock.patch.object(signkey, "PCR_SIGNATURE_PATHS", (boot,)):
            merged = signkey.boot_signatures()
        self.assertEqual([e["pkfp"] for e in merged["sha256"]], ["cd" * 32, signkey.pcr_key_fingerprint(NEW_PUB)])

    def test_the_catch_up_bumps_on_the_re_sign_s_generation(self):
        from deploy.baremetal import measurements as ms
        manifest = {"schema": m.SCHEMA_V4, "anchor_policy_key": {"key": POINT}}
        rotations = [{"from": GENERATIONS["a"], "signature": "00" * 64}]
        seen = []
        patches = [self.mock.patch.object(self.node, "_image", lambda cfg, pem_path, manifest: (None, SYSTEM_PUB)),
                   self.mock.patch.object(self.node, "_chain_tip", lambda cfg: manifest),
                   self.mock.patch.object(ms, "held", lambda d, man: self.doc),
                   self.mock.patch.object(ms, "rotations", lambda doc, node_id: rotations),
                   self.mock.patch.object(ms, "anchor_approval", lambda man, doc, node_id, pem, cls: {"generation": GENERATIONS["a"]}),
                   self.mock.patch.object(self.node, "_pcr11", lambda cfg: self.pcr11),
                   self.mock.patch.object(ap, "catch_up", lambda index, point, node_id, rot, booted, run: seen.append(booted) or booted)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.node.catch_up_rotation(self.cfg)
        self.assertEqual(seen, [GENERATIONS["a"] + 1], "the catch-up did not take the re-sign's generation")
        # 05 on #517: a re-sign whose approvals are at another generation than the published one bumps nothing
        rotations.append({"from": GENERATIONS["a"] + 1, "signature": "00" * 64})          # published G is now G + 2
        del seen[:]
        with self.assertRaisesRegex(m.Refused, "the re-sign moves a to approvals at generation %d, not the published %d: nothing is "
                                    "bumped" % (GENERATIONS["a"] + 1, GENERATIONS["a"] + 2)):
            self.node.catch_up_rotation(self.cfg)
        self.assertEqual(seen, [])
