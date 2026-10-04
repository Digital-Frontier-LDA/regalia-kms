"""deploy/baremetal/cardrecord.py: the card-ceremony record (regalia-ceremony#111 step 2, ADR-0002 D30), verified by its
consumer with the root pinned. Records are made here with a throwaway root; each content case is validly signed, so it
is refused by its content rule alone, by that rule's own message. regalia-ceremony's own signed vectors join these once
published (qubes/emulator/tests/vectors/card-ceremony-record/)."""
import base64
import copy
import hashlib
import struct
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import cardrecord as cr
from deploy.baremetal import membership as m


def raw(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def ssh(key):
    blob = b"".join(struct.pack(">I", len(p)) + p for p in (b"ssh-ed25519", bytes.fromhex(raw(key))))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


class Case(unittest.TestCase):
    def setUp(self):
        self.root_key = Ed25519PrivateKey.generate()
        self.root = raw(self.root_key)
        keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        self.main, self.backup, self.release = raw(keys[0]), raw(keys[1]), raw(keys[2])
        self.record = {
            "schema": cr.SCHEMA, "event": cr.EVENT, "session": "ab" * 16, "tool": "offline-keys.py test", "at": "2026-10-04T12:00:00Z",
            "root_entry": {"alg": "ed25519", "key": self.root}, "root_fingerprint": hashlib.sha256(bytes.fromhex(self.root)).hexdigest(),
            "owner_keys": [{"role": "dev-main", "serial": "11111111", "alg": "ed25519", "key": self.main, "attested": True,
                            "attestation_sha256": {"sig": "a1" * 32, "dec": "a2" * 32}},
                           {"role": "dev-backup", "serial": "22222222", "alg": "ed25519", "key": self.backup, "attested": True,
                            "attestation_sha256": {"sig": "b1" * 32, "dec": "b2" * 32}}],
            "ownerauth_recipients": [{"serial": "11111111", "primary": "A" * 40, "subkey": "B" * 40},
                                     {"serial": "22222222", "primary": "C" * 40, "subkey": "D" * 40}],
            "ssh_signers": [{"serial": "11111111", "key": ssh(keys[3])}, {"serial": "22222222", "key": ssh(keys[4])}],
            "release_key": {"alg": "ed25519", "key": self.release, "fingerprint": "E" * 40, "cards": ["33333333", "44444444"],
                            "imported": True, "attested": False}}

    def sign(self, record, key=None, domain=cr.RECORD_DOMAIN):
        return {"record": record, "signature": (key or self.root_key).sign(domain + m.canonical(record)).hex()}

    def changed(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        return self.sign(record)

    def refused(self, reason, envelope, root=None):
        with self.assertRaises(m.Refused) as caught:
            cr.verify(envelope, root or self.root)
        self.assertIn(reason, str(caught.exception))


class Signature(Case):
    def test_a_record_the_pinned_root_signed_gives_its_owner_and_release_keys(self):
        got = cr.verify(self.sign(self.record), self.root)
        self.assertEqual(got["owners"], {"11111111": self.main, "22222222": self.backup})
        self.assertEqual((got["roles"], got["release_key"]), ({"dev-main": "11111111", "dev-backup": "22222222"}, self.release))

    def test_a_bad_signature_a_wrong_domain_and_another_root_are_refused(self):
        bad = self.sign(self.record)
        bad["signature"] = ("00" if bad["signature"][:2] != "00" else "11") + bad["signature"][2:]
        self.refused("the card record's signature is not the pinned root's", bad)
        self.refused("the card record's signature is not the pinned root's", self.sign(self.record, domain=b"regalia-ceremony-record/v2\x00"))
        other = Ed25519PrivateKey.generate()
        record = dict(copy.deepcopy(self.record), root_entry={"alg": "ed25519", "key": raw(other)},
                      root_fingerprint=hashlib.sha256(bytes.fromhex(raw(other))).hexdigest())
        self.refused("names another root than the pinned one", self.sign(record, other))       # consistent, by another root

    def test_the_envelope_and_the_root_fingerprint(self):
        self.refused("fields mismatch", dict(self.sign(self.record), note="x"))
        self.refused("signature is not 128 hex", dict(self.sign(self.record), signature="AB" * 64))
        self.refused("root_fingerprint is not the root's", self.changed(lambda r: r.update(root_fingerprint="00" * 32)))

    def test_a_non_ascii_string_is_refused_before_anything_else(self):
        self.refused("holds a non-ASCII string", self.changed(lambda r: r.update(tool="offline-keys.py tést")))


class Content(Case):
    """Each validly signed: refused by its content rule, by that rule's message."""

    def test_an_unknown_or_missing_field_at_any_level(self):
        self.refused("the card record fields mismatch", self.changed(lambda r: r.update(extra=1)))
        self.refused("owner_keys[0] fields mismatch", self.changed(lambda r: r["owner_keys"][0].pop("attested")))
        self.refused("release_key fields mismatch", self.changed(lambda r: r["release_key"].update(note="x")))

    def test_owner_keys_two_roles_two_cards_two_keys_attested(self):
        self.refused("owner_keys is not exactly two keys", self.changed(lambda r: r["owner_keys"].pop()))
        self.refused("the role 'dev-main' is not one of", self.changed(lambda r: r["owner_keys"][1].update(role="dev-main")))
        self.refused("the card 11111111 holds two owner keys", self.changed(lambda r: r["owner_keys"][1].update(serial="11111111")))
        self.refused("the two owner cards hold the same key", self.changed(lambda r: r["owner_keys"][1].update(key=self.main)))
        self.refused("is not attested as made on its card", self.changed(lambda r: r["owner_keys"][0].update(attested=False)))
        self.refused("owner_keys[1].serial is not a card serial", self.changed(lambda r: r["owner_keys"][1].update(serial="0222")))

    def test_each_owner_key_names_its_own_two_attestation_certificates(self):
        """regalia-ceremony#121 after d9's read: the evidence behind "attested", re-checkable from the disc."""
        self.refused("owner_keys[0].attestation_sha256 fields mismatch", self.changed(lambda r: r["owner_keys"][0]["attestation_sha256"].pop("dec")))
        self.refused("owner_keys[1].attestation_sha256.sig (a certificate's SHA-256, 64 hex)",
                     self.changed(lambda r: r["owner_keys"][1]["attestation_sha256"].update(sig="B1" * 32)))
        self.refused("an attestation certificate is named twice: each key has its own",
                     self.changed(lambda r: r["owner_keys"][1]["attestation_sha256"].update(dec="a1" * 32)))

    def test_a_bench_yubikey_is_never_a_ceremony_card(self):
        """D28.5, D30: regalia-ceremony refuses the bench serials; so does this reader, from membership's one list."""
        for bench in m.BENCH_YUBIKEYS:
            with self.subTest(owner=bench):
                self.refused("a bench YubiKey is named (%s): the ceremony never uses a bench serial" % bench,
                             self.changed(lambda r: [e.update(serial=bench) for e in r["ownerauth_recipients"] + r["ssh_signers"]
                                                     + r["owner_keys"] if e["serial"] == "22222222"]))
        self.refused("a bench YubiKey is named (35718625)", self.changed(lambda r: r["release_key"].update(cards=["33333333", "35718625"])))

    def test_the_release_key_is_never_an_owner_key_nor_on_an_owner_card(self):
        self.refused("the release key is an owner key", self.changed(lambda r: r["release_key"].update(key=self.backup)))
        self.refused("a release card is an owner card (D30.3): 22222222", self.changed(lambda r: r["release_key"].update(cards=["22222222", "44444444"])))
        self.refused("release_key is not an imported (unattested) key", self.changed(lambda r: r["release_key"].update(attested=True)))
        self.refused("release_key.cards is not two distinct cards", self.changed(lambda r: r["release_key"].update(cards=["33333333", "33333333"])))
        self.refused("release_key.fingerprint is not 40 HEX", self.changed(lambda r: r["release_key"].update(fingerprint="e" * 40)))

    def test_a_card_that_is_not_a_serial_is_refused_not_a_crash(self):
        """regalia-kms-95's read: a dict among the release cards raised TypeError (unhashable) before it was checked."""
        self.refused("release_key.cards[0] is not a card serial", self.changed(lambda r: r["release_key"].update(cards=[{"a": 1}, "44444444"])))

    def test_two_owner_cards_never_name_one_openpgp_key(self):
        """regalia-kms-95's read: one decryption key named for both owner cards is not two cards."""
        self.refused("an OpenPGP key is named twice among the ownerauth recipients",
                     self.changed(lambda r: r["ownerauth_recipients"][1].update(subkey="B" * 40)))
        self.refused("an OpenPGP key is named twice among the ownerauth recipients",
                     self.changed(lambda r: r["ownerauth_recipients"][1].update(primary="A" * 40)))

    def test_recipients_and_ssh_signers_are_the_owner_cards(self):
        self.refused("ownerauth_recipients names other cards than the owner cards",
                     self.changed(lambda r: r["ownerauth_recipients"][1].update(serial="99999999")))
        self.refused("ssh_signers names other cards than the owner cards", self.changed(lambda r: r["ssh_signers"].pop()))
        self.refused("ssh_signers[0].key is not an ssh-ed25519 key", self.changed(lambda r: r["ssh_signers"][0].update(key="ssh-rsa AAAA")))

    def test_every_key_is_distinct(self):
        self.refused("a key appears twice among the owner, release, SSH and root keys",
                     self.changed(lambda r: r["ssh_signers"][0].update(key="ssh-ed25519 " + base64.b64encode(
                         b"".join(struct.pack(">I", len(p)) + p for p in (b"ssh-ed25519", bytes.fromhex(self.main)))).decode())))

    def test_the_header_fields(self):
        self.refused("is not a regalia.card-ceremony-record/v1", self.changed(lambda r: r.update(event="other")))
        self.refused("session is not 32 hex", self.changed(lambda r: r.update(session="xyz")))
        self.refused("at is not YYYY-MM-DDTHH:MM:SSZ", self.changed(lambda r: r.update(at="2026-10-04")))


class ProducersVectors(unittest.TestCase):
    """regalia-ceremony's own signed vectors (regalia-ceremony#121, copied into tests/vectors/card-ceremony-record/):
    valid.json accepted under the pinned root.hex, every other one refused. expect.json carries the producer's reasons;
    this verifier's words may differ, and its refusal must be about the same thing."""

    # the producer's refusal, and the words this verifier refuses the same record with
    SAME = {"bad-signature.json": "signature is not the pinned root's", "wrong-domain.json": "signature is not the pinned root's",
            "other-root.json": "names another root than the pinned one", "release-is-owner.json": "the release key is an owner key",
            "missing-dev-backup.json": "owner_keys is not exactly two keys", "unknown-field.json": "owner_keys[0] fields mismatch"}

    def test_every_vector_as_the_producer_judges_it(self):
        import json
        import pathlib
        here = pathlib.Path(__file__).parent / "vectors" / "card-ceremony-record"
        root = (here / "root.hex").read_text().strip()
        expect = json.loads((here / "expect.json").read_text())
        self.assertEqual(sorted(expect), sorted(list(self.SAME) + ["valid.json"]))
        for name, want in sorted(expect.items()):
            with self.subTest(vector=name):
                envelope = json.loads((here / name).read_text())
                if want == "ok":
                    got = cr.verify(envelope, root)
                    self.assertEqual(sorted(got["roles"]), sorted(cr.ROLES))
                    continue
                with self.assertRaises(m.Refused) as caught:
                    cr.verify(envelope, root)
                self.assertIn(self.SAME[name], str(caught.exception))


if __name__ == "__main__":
    unittest.main()
