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
