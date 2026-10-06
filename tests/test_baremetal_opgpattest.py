"""#400: a YubiKey's OpenPGP key attestations, verified offline (deploy/baremetal/opgpattest.py), and the card record's
owner keys checked against them (cardrecord.attested). The real certificates are YubiKey 35718625's (firmware 5.7.4,
regalia-kms-24, 2026-10-05), chained to the pinned Yubico root; the card record's own cases use a stand-in Yubico
hierarchy (Hierarchy), since a ceremony record names two non-bench cards and only a bench card was attested."""
import copy
import datetime
import hashlib
import os
import shutil
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509.oid import NameOID

from deploy.baremetal import cardrecord as cr
from deploy.baremetal import opgpattest as oa
from tests.test_baremetal_cardrecord import Case, raw

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "opgp-attestation-35718625")


def load(name):
    with open(os.path.join(FIXTURES, name), "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


class RealCard(unittest.TestCase):
    """YubiKey 35718625's own attestations, under the vendored, pinned Yubico trust."""

    def setUp(self):
        self.card = [load("attestation-intermediate.pem")]

    def test_each_slot_chains_to_the_pinned_root_and_says_what_the_card_signed(self):
        expected = {"attest-sig.pem": ("SIG", "ed25519", "9BD0EE976073BCC1DDB9F62B80AAF76618C619EB", 0),
                    "attest-sig-touch-fixed.pem": ("SIG", "ed25519", "9BD0EE976073BCC1DDB9F62B80AAF76618C619EB", 2),
                    "attest-dec.pem": ("DEC", "x25519", "2AB74A10A7CFB5333948F8875136DD77A828D681", 0),
                    "attest-aut.pem": ("AUT", "ed25519", "2C32EB6C4EACDD151BA91CE3C009B5D897B62937", 0)}
        for name, (slot, kind, fingerprint, touch) in expected.items():
            with self.subTest(name):
                got = oa.verify(load(name), self.card, slot)
                self.assertEqual((got["serial"], got["source"], got["firmware"], got["key_type"], got["fingerprint"], got["touch"]),
                                 ("35718625", oa.GENERATED, "5.7.4", kind, fingerprint, touch))
        # the same SIG key before and after its touch policy was fixed
        self.assertEqual(oa.verify(load("attest-sig.pem"), self.card, "SIG")["key"].hex(),
                         "60a5a2bc8c527e7634b1a1c7e6419de5dae411894fe24d2dbe2a0391b781c31d")

    def test_another_slot_s_certificate_is_refused_by_name(self):
        with self.assertRaisesRegex(oa.Refused, r"is 'YubiKey OPGP Attestation DEC', not the SIG slot's attestation"):
            oa.verify(load("attest-dec.pem"), self.card, "SIG")

    def test_without_the_card_s_attestation_certificate_nothing_chains(self):
        with self.assertRaisesRegex(oa.Refused, r"no card attestation certificate \(YubiKey OPGP Attestation\) given signs the SIG"):
            oa.verify(load("attest-sig.pem"), [], "SIG")

    def test_a_leaf_whose_signature_was_altered_is_refused(self):
        data = bytearray(der(load("attest-sig.pem")))
        data[-5] ^= 0x01                                   # inside the signature value, at the end of the DER
        with self.assertRaisesRegex(oa.Refused, r"no card attestation certificate \(YubiKey OPGP Attestation\) given signs the SIG"):
            oa.verify(x509.load_der_x509_certificate(bytes(data)), self.card, "SIG")

    def test_the_vendored_root_must_be_the_pinned_one(self):
        with self.assertRaisesRegex(oa.Refused, r"the vendored Yubico Attestation Root is not the pinned one \(00000000"):
            oa.trust(pinned="00" * 32)
        root, _ = oa.trust()
        self.assertEqual(hashlib.sha256(der(root)).hexdigest(), oa.PINNED_ROOT)

    def test_a_stand_in_root_trusts_nothing_yubico_signed(self):
        hierarchy = Hierarchy()
        with self.assertRaisesRegex(oa.Refused, r"'Yubico OPGP Attestation B 1', which no vendored Yubico certificate is"):
            oa.verify(load("attest-sig.pem"), self.card, "SIG", anchors=hierarchy.anchors)


class ProducerRun(unittest.TestCase):
    """The producer's REAL output (regalia-ceremony#140, owner-cards.py, run by regalia-kms-24 on YubiKey 35718625, fw 5.7.4,
    2026-10-06): the disc's owner-card-<serial>/ as written, its attestations read by certificates() and each verified
    under the real, pinned Yubico trust, and everything the producer's facts file states about the card checked against
    what the card signed. The card is a bench card, so cardrecord refuses it at genesis; this is the consumer's half of
    the cross-repo check, not a ceremony."""

    def setUp(self):
        import json
        self.dir = os.path.join(FIXTURES, "owner-card-run")
        with open(os.path.join(self.dir, "owner-card-35718625", "owner-card-35718625.json")) as f:
            self.facts = json.load(f)
        self.certs = oa.certificates(self.dir)
        self.cards = oa.devices(self.certs)

    def test_each_slot_is_what_the_producer_recorded(self):
        from deploy.baremetal import cardrecord
        self.assertEqual(len(self.cards), 1)
        for slot in ("sig", "dec", "aut"):
            with self.subTest(slot):
                digest = self.facts["attestation_sha256"][slot]
                self.assertIn(digest, self.certs, "the facts' %s digest is not one of the disc's certificates" % slot)
                got = oa.verify(self.certs[digest], self.cards, slot.upper())
                self.assertEqual((got["serial"], got["source"], got["touch"], got["firmware"]),
                                 (self.facts["serial"], oa.GENERATED, cardrecord.TOUCH_FIXED, self.facts["firmware"]))
                self.assertEqual(got["key"].hex(), self.facts["keys"][slot]["key"])
                self.assertEqual(got["fingerprint"], self.facts["keys"][slot]["fingerprint"])
        self.assertEqual(self.facts["keys"]["sig"]["fingerprint"], self.facts["primary"])
        self.assertEqual(cardrecord._ssh_ed25519(self.facts["ssh"], "ssh"), self.facts["keys"]["aut"]["key"])


class Hierarchy:
    """A stand-in for Yubico's: a root, "Yubico Attestation Intermediate B 1", "Yubico OPGP Attestation B 1" and one card
    certificate "YubiKey OPGP Attestation" (shared by the cards, as Yubico's batch key is), signing leaves with Yubico's
    extensions as the card writes them (DER values)."""

    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._cert("Yubico Attestation Root 1", self.root_key.public_key(), "Yubico Attestation Root 1", self.root_key, ca=True)
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        inter = self._cert("Yubico Attestation Intermediate B 1", self.inter_key.public_key(), "Yubico Attestation Root 1", self.root_key, ca=True)
        self.opgp_key = ec.generate_private_key(ec.SECP256R1())
        opgp = self._cert("Yubico OPGP Attestation B 1", self.opgp_key.public_key(), "Yubico Attestation Intermediate B 1", self.inter_key, ca=True)
        self.card_key = ec.generate_private_key(ec.SECP256R1())
        self.card = self._cert(oa.DEVICE_CN, self.card_key.public_key(), "Yubico OPGP Attestation B 1", self.opgp_key, ca=True)
        self.anchors = (self.root, [inter, opgp])

    @staticmethod
    def _cert(subject, public, issuer, signer, ca=False, extensions=()):
        name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])          # noqa: E731
        builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(public)
                   .serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime(2024, 12, 1))
                   .not_valid_after(datetime.datetime(9999, 12, 31, 23, 59, 59)))
        if ca:
            builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        for oid, value in extensions:
            builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier(oid), value), critical=False)
        return builder.sign(signer, hashes.SHA256())

    def leaf(self, slot, public, serial, fingerprint, source=1, touch=2):
        n = int(serial)
        values = {2: bytes([0x02, 1, source]), 3: bytes([0x04, 3, 5, 7, 4]), 4: bytes([0x04, 20]) + bytes.fromhex(fingerprint),
                  7: bytes([0x02, 4]) + n.to_bytes(4, "big"), 8: bytes([0x04, 1, touch])}
        return self._cert("%s %s" % (oa.DEVICE_CN, slot), public, oa.DEVICE_CN, self.card_key,
                          extensions=[(oa.OID % k, v) for k, v in sorted(values.items())])


def ssh_key(public_raw):
    import base64
    import struct
    blob = b"".join(struct.pack(">I", len(p)) + p for p in (b"ssh-ed25519", public_raw))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


class CardRecord(Case):
    """The card record's owner keys against their attestations (cardrecord.attested): every tie, and each one broken."""

    def setUp(self):
        super().setUp()
        self.h = Hierarchy()
        self.d = tempfile.mkdtemp(prefix="opgpattest-")
        self.addCleanup(shutil.rmtree, self.d)
        self.write("att.der", der(self.h.card))
        self.slots = {}
        for i, (entry, recipient, signer) in enumerate(zip(self.record["owner_keys"], self.record["ownerauth_recipients"], self.record["ssh_signers"])):
            sig_key, aut_key, dec_key = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
            entry["key"], signer["key"] = raw(sig_key), ssh_key(bytes.fromhex(raw(aut_key)))
            prints = {"sig": recipient["primary"], "dec": recipient["subkey"], "aut": "%040X" % (0xA0 + i)}
            publics = {"sig": sig_key.public_key(), "dec": dec_key.public_key(), "aut": aut_key.public_key()}
            entry["attestation_sha256"] = {}
            for f in cr.ATTESTED_SLOTS:
                cert = self.h.leaf(f.upper(), publics[f], entry["serial"], prints[f])
                self.slots[(entry["serial"], f)] = (publics[f], prints[f])
                entry["attestation_sha256"][f] = self.write("%s.%s.attest.der" % (entry["serial"], f), der(cert))
        if self.main != self.record["owner_keys"][0]["key"]:
            self.main, self.backup = self.record["owner_keys"][0]["key"], self.record["owner_keys"][1]["key"]

    def write(self, name, data):
        with open(os.path.join(self.d, name), "wb") as f:
            f.write(data)
        return hashlib.sha256(data).hexdigest()

    def replace(self, card, f, **change):
        """Card `card`'s `f` attestation re-issued with `change` (leaf()'s keywords), written, and named in the record."""
        public, fingerprint = self.slots[(card, f)]
        args = dict(public=public, serial=card, fingerprint=fingerprint)
        args.update(change)
        digest = self.write("%s.%s.attest.der" % (card, f), der(self.h.leaf(f.upper(), **args)))
        entry = next(e for e in self.record["owner_keys"] if e["serial"] == card)
        entry["attestation_sha256"][f] = digest

    def verify(self, record=None):
        record = record or self.record
        return cr.verify(self.sign(record), self.root, [self.line(record)], attestations=self.d, anchors=self.h.anchors)

    def refused(self, reason):
        with self.assertRaises(cr.Refused) as caught:
            self.verify()
        self.assertIn(reason, str(caught.exception))

    def test_every_owner_key_is_attested_on_its_own_card(self):
        self.assertEqual(self.verify()["attestations"], "verified")
        # and without a directory, nothing is claimed
        self.assertEqual(cr.verify(self.sign(self.record), self.root, [self.line(self.record)])["attestations"], "not given")

    def test_a_certificate_missing_from_the_directory(self):
        os.unlink(os.path.join(self.d, "22222222.dec.attest.der"))
        self.refused("owner card 22222222 (owner-backup): no certificate in %s has the DEC attestation's SHA-256" % self.d)

    def test_another_card_s_serial(self):
        self.replace("11111111", "aut", serial="55555555")
        self.refused("owner card 11111111 (owner-main): its AUT attestation names the card 55555555, not 11111111")

    def test_an_imported_key(self):
        self.replace("22222222", "sig", source=0)
        self.refused("owner card 22222222 (owner-backup): its SIG attestation says the key was imported, not generated on the card (D5)")

    def test_a_touch_policy_not_fixed(self):
        self.replace("11111111", "dec", touch=1)
        self.refused("owner card 11111111 (owner-main): its DEC attestation gives the touch policy 1, not fixed (2, D30.7)")

    def test_the_sig_key_is_the_recorded_owner_key(self):
        self.replace("11111111", "sig", public=ed25519.Ed25519PrivateKey.generate().public_key())
        self.refused("owner card 11111111 (owner-main): its SIG attestation is of another key than the recorded owner key")

    def test_sig_and_dec_fingerprints_are_the_ownerauth_recipient_s(self):
        self.replace("11111111", "sig", fingerprint="F" * 40)
        self.refused("owner card 11111111 (owner-main): its SIG attestation's fingerprint %s is not the card's ownerauth recipient's primary A"
                     % ("F" * 40))
        self.setUp()
        self.replace("22222222", "dec", fingerprint="F" * 40)
        self.refused("owner card 22222222 (owner-backup): its DEC attestation's fingerprint %s is not the card's ownerauth recipient's subkey D"
                     % ("F" * 40))

    def test_the_aut_key_is_the_card_s_ssh_signing_key(self):
        self.replace("22222222", "aut", public=ed25519.Ed25519PrivateKey.generate().public_key())
        self.refused("owner card 22222222 (owner-backup): its AUT attestation is of another key than the card's SSH signing key")

    def test_one_slot_s_certificate_named_for_another(self):
        record = copy.deepcopy(self.record)
        entry = record["owner_keys"][0]
        entry["attestation_sha256"]["sig"], entry["attestation_sha256"]["aut"] = entry["attestation_sha256"]["aut"], entry["attestation_sha256"]["sig"]
        with self.assertRaisesRegex(cr.Refused, r"is 'YubiKey OPGP Attestation AUT', not the SIG slot's attestation"):
            self.verify(record)

    def test_a_stand_in_hierarchy_not_the_given_trust_is_refused(self):
        with self.assertRaisesRegex(cr.Refused, r"'Yubico OPGP Attestation B 1', which no vendored Yubico certificate is"):
            cr.verify(self.sign(self.record), self.root, [self.line(self.record)], attestations=self.d)    # the real, pinned trust

    def test_the_disc_layout_and_what_is_refused_in_it(self):
        """regalia-kms-51's layout: one owner-card-<serial>/ per card, its .der beside a .gpg and a .json that are not
        read; a *.der that is no certificate, or a link, is refused by name."""
        card = os.path.join(self.d, "owner-card-11111111")
        os.mkdir(card)
        for name in os.listdir(self.d):
            if name.startswith("11111111."):
                os.rename(os.path.join(self.d, name), os.path.join(card, name.split(".", 1)[1]))
        for name, data in (("owner-card-11111111.gpg", b"public certificate"), ("owner-card-11111111.json", b"{}")):
            with open(os.path.join(card, name), "wb") as f:
                f.write(data)
        self.assertEqual(self.verify()["attestations"], "verified")
        self.write("notes.der", b"not a certificate")
        self.refused("notes.der is not a DER certificate")
        os.unlink(os.path.join(self.d, "notes.der"))
        os.symlink(os.path.join(self.d, "att.der"), os.path.join(self.d, "link.der"))
        with self.assertRaises(cr.Refused):
            self.verify()

if __name__ == "__main__":
    unittest.main()
