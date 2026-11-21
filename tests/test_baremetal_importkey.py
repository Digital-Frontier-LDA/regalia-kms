"""deploy/baremetal/importkey.py's verifier (#702), with no TPM: every check refuses on its own, by its name.

A software stand-in plays the TPM: an AK key pair with the AK's template, an EK public area, an import key with the
import template, and a TPMS_ATTEST for TPM2_Certify built and signed here. That proves the VERIFIER's logic; that a
real TPM's certification passes, and what a real TPM will and will not certify, is e2e/import-key-certify-swtpm.sh's.
"""
import hashlib
import os
import struct
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from deploy.baremetal import attest, importkey, signkey


def tpm2b(data):
    return struct.pack(">H", len(data)) + data


def point(key):
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")


def import_public(x, y, attributes=importkey.ATTRIBUTES, sym=(importkey.ALG_AES, importkey.AES_BITS, importkey.ALG_CFB),
                  curve=attest.CURVE_P256, policy=b""):
    area = (struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, attributes) + tpm2b(policy) + struct.pack(">HHH", *sym)
            + struct.pack(">HHH", attest.ALG_NULL, curve, attest.ALG_NULL) + tpm2b(x) + tpm2b(y))
    return tpm2b(area)


def ak_public(key):
    x, y = point(key)
    return tpm2b(struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, attest.AK_ATTRIBUTES) + tpm2b(b"")
                 + struct.pack(">HHHHH", attest.ALG_NULL, attest.ALG_ECDSA, attest.ALG_SHA256, attest.CURVE_P256, attest.ALG_NULL)
                 + tpm2b(x) + tpm2b(y))


def qn(parent_qn, name):
    return struct.pack(">H", attest.ALG_SHA256) + hashlib.sha256(parent_qn + name).digest()


class Stand_in:
    """One software 'TPM': its EK, its AK, its import key, and a certification of it."""

    def __init__(self):
        self.ak = ec.generate_private_key(ec.SECP256R1())
        self.ak_public = ak_public(self.ak)
        self.ak_name, _ = attest.ak_identity(self.ak_public)
        self.ek_public = tpm2b(b"\x00\x01\x00\x0b" + os.urandom(56))      # any area: the verifier hashes it to a Name
        self.ek_name = attest.name_of(attest.public_area(self.ek_public, "ek"))
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.import_public = import_public(*point(self.key))
        self.answer = os.urandom(32)
        self.keep = {"schema": importkey.CHALLENGE_SCHEMA, "ek_name": self.ek_name.hex(), "ak_name": self.ak_name.hex(),
                     "secret_sha256": hashlib.sha256(self.answer).hexdigest()}

    def certify(self, name=None, qualified=None, signer=None, extra=signkey.TOOLS_QUALIFYING, magic=attest.TPM_GENERATED):
        name = name or importkey.identity(self.import_public)[0]
        qualified = qualified or qn(os.urandom(34), name)             # a child of some storage key
        signer = signer or attest.qualified_name(self.ek_name, self.ak_name)
        return (struct.pack(">IH", magic, signkey.ST_ATTEST_CERTIFY) + tpm2b(signer) + tpm2b(extra)
                + struct.pack(">QIIBQ", 5, 1, 0, 1, 0) + tpm2b(name) + tpm2b(qualified))

    def document(self, certify=None, key=None, **over):
        certify = certify or self.certify()
        doc = {"schema": importkey.SCHEMA, "import_public": self.import_public.hex(), "ek_public": self.ek_public.hex(),
               "ak_public": self.ak_public.hex(), "certify": certify.hex(),
               "signature": (key or self.ak).sign(certify, ec.ECDSA(hashes.SHA256())).hex(), "answer": self.answer.hex()}
        doc.update(over)
        return doc

    def fingerprint(self):
        return importkey.fingerprint(self.import_public)


class Verify(unittest.TestCase):
    def setUp(self):
        self.t = Stand_in()

    def verify(self, doc, keep=None, ek_name=None, fingerprint=None):
        return importkey.verify(doc, keep or self.t.keep, ek_name or self.t.ek_name.hex(), fingerprint or self.t.fingerprint())

    def refused(self, check, doc, **kw):
        with self.assertRaises(attest.Refused) as caught:
            self.verify(doc, **kw)
        self.assertTrue(str(caught.exception).startswith(check + ": "), "%s: %s" % (check, caught.exception))

    def test_a_certified_key_passes(self):
        facts = self.verify(self.t.document())
        self.assertEqual(facts["fingerprint"], self.t.fingerprint())
        self.assertEqual(facts["ak_name"], self.t.ak_name.hex())

    def test_missing(self):
        self.refused("missing", None)

    def test_template(self):
        x, y = point(self.t.key)
        for label, public in (("AES-256", import_public(x, y, sym=(importkey.ALG_AES, 256, importkey.ALG_CFB))),
                              ("P-384 curve id", import_public(x, y, curve=0x0004)),
                              ("an extra attribute (sign)", import_public(x, y, attributes=importkey.ATTRIBUTES | 0x00040000)),
                              ("no noDA", import_public(x, y, attributes=importkey.ATTRIBUTES & ~0x400)),
                              ("an auth policy", import_public(x, y, policy=b"\x01" * 32))):
            with self.subTest(label):
                self.refused("template", self.t.document(import_public=public.hex()), fingerprint=hashlib.sha256(
                    attest.P256_SPKI_PREFIX + b"\x04" + x + y).hexdigest())

    def test_attributes_named(self):
        x, y = point(self.t.key)
        for bit, label in ((importkey.FIXED_TPM, "fixedTPM"), (importkey.FIXED_PARENT, "fixedParent"),
                           (importkey.SENSITIVE_DATA_ORIGIN, "sensitiveDataOrigin")):
            with self.subTest(label):
                public = import_public(x, y, attributes=importkey.ATTRIBUTES & ~bit)
                with self.assertRaises(attest.Refused) as caught:
                    self.verify(self.t.document(import_public=public.hex()))
                self.assertIn("attributes: the import key is not %s" % label, str(caught.exception))

    def test_fingerprint(self):
        self.refused("fingerprint", self.t.document(), fingerprint="ab" * 32)

    def test_ek(self):
        self.refused("ek", self.t.document(), ek_name="000b" + "cd" * 32)

    def test_binding(self):
        self.refused("binding", self.t.document(answer=os.urandom(32).hex()))
        other = Stand_in()
        self.refused("binding", self.t.document(), keep=dict(self.t.keep, ak_name=other.ak_name.hex()))

    def test_binding_a_software_ak(self):
        # the attacker's whole certification, signed by a software 'AK' under the real EK's Name: only binding refuses it
        fake = ec.generate_private_key(ec.SECP256R1())
        fake_name, _ = attest.ak_identity(ak_public(fake))
        certify = self.t.certify(signer=attest.qualified_name(self.t.ek_name, fake_name))
        self.refused("binding", self.t.document(certify=certify, key=fake, ak_public=ak_public(fake).hex()))

    def test_signature(self):
        doc = self.t.document()
        sig = bytearray(bytes.fromhex(doc["signature"]))
        sig[-1] ^= 1
        self.refused("signature", dict(doc, signature=sig.hex()))
        self.refused("signature", self.t.document(key=ec.generate_private_key(ec.SECP256R1())))

    def test_signer(self):
        self.refused("signer", self.t.document(certify=self.t.certify(signer=attest.qualified_name(b"\x00\x0b" + b"\x01" * 32, self.t.ak_name))))
        self.refused("signer", self.t.document(certify=self.t.certify(extra=b"\x01\x02")))

    def test_name(self):
        other = Stand_in()
        self.refused("name", self.t.document(certify=self.t.certify(name=importkey.identity(other.import_public)[0])))

    def test_parent(self):
        name = importkey.identity(self.t.import_public)[0]
        for h in importkey.HIERARCHIES:
            with self.subTest(hex(h)):
                self.refused("parent", self.t.document(certify=self.t.certify(qualified=qn(struct.pack(">I", h), name))))

    def test_not_a_tpm_attestation(self):
        self.refused("certify", self.t.document(certify=self.t.certify(magic=0x12345678)))

    def test_the_document_shape(self):
        doc = self.t.document()
        for label, bad, why in (("an extra field", dict(doc, note="x"), "fields mismatch"),
                                ("a field missing", {k: v for k, v in doc.items() if k != "answer"}, "fields mismatch"),
                                ("upper-case hex", dict(doc, certify=doc["certify"].upper()), "not lowercase hex"),
                                ("an oversized signature", dict(doc, signature="00" * 300), "oversized"),
                                ("another schema", dict(doc, schema="x"), "schema must be")):
            with self.subTest(label):
                with self.assertRaises(attest.Refused) as caught:
                    self.verify(bad)
                self.assertIn(why, str(caught.exception))

    def test_the_recorded_values_in_their_forms(self):
        with self.assertRaises(attest.Refused):
            importkey.verify(self.t.document(), self.t.keep, self.t.ek_name.hex().upper(), self.t.fingerprint())
        with self.assertRaises(attest.Refused):
            importkey.verify(self.t.document(), self.t.keep, self.t.ek_name.hex(), self.t.fingerprint()[:16])


if __name__ == "__main__":
    unittest.main()
