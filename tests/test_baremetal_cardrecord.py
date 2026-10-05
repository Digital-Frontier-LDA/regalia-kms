"""deploy/baremetal/cardrecord.py: the card-ceremony record (regalia-ceremony#111 step 2, ADR-0002 D30), verified by its
consumer with the root pinned. Records are made here with a throwaway root; each content case is validly signed, so it
is refused by its content rule alone, by that rule's own message. regalia-ceremony's own signed vectors join these once
published (qubes/emulator/tests/vectors/card-ceremony-record/)."""
import base64
import copy
import hashlib
import json
import os
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
                            "imported": True, "attested": False},
            "sequence": 1, "supersedes": ""}

    def sign(self, record, key=None, domain=cr.RECORD_DOMAIN):
        return {"record": record, "signature": (key or self.root_key).sign(domain + m.canonical(record)).hex()}

    def line(self, record, sequence=None, key=None):
        """The laptop's signing-record line for `record`, as the card ceremony appends it (#403)."""
        return {"kind": "card-record", "sequence": record["sequence"] if sequence is None else sequence, "digest": cr.digest(record),
                "key": key or self.root, "at": "2026-10-04T12:00:01Z"}

    def changed(self, change):
        record = copy.deepcopy(self.record)
        change(record)
        return self.sign(record)

    def refused(self, reason, envelope, root=None, lines=None):
        """Refused by `reason`; by default the signing record names this very record, so only its content is judged."""
        record = envelope.get("record") if isinstance(envelope, dict) else None
        default = [self.line(record)] if isinstance(record, dict) and type(record.get("sequence")) is int else []
        with self.assertRaises(m.Refused) as caught:
            cr.verify(envelope, root or self.root, default if lines is None else lines)
        self.assertIn(reason, str(caught.exception))


class Signature(Case):
    def test_a_record_the_pinned_root_signed_gives_its_owner_and_release_keys(self):
        got = cr.verify(self.sign(self.record), self.root, [self.line(self.record)])
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


class Freshness(Case):
    """#403: only the NEWEST card record the root signed, by the laptop's signing record; d9's read of the proposal."""

    def second(self):
        record = copy.deepcopy(self.record)
        record.update(sequence=2, supersedes=cr.digest(self.record), at="2026-10-05T12:00:00Z")
        return record

    def test_the_newest_record_gives_its_place(self):
        two = self.second()
        got = cr.verify(self.sign(two), self.root, [{"kind": "manifest", "epoch": 1, "digest": "ab" * 32}, self.line(self.record), self.line(two)])
        self.assertEqual((got["sequence"], got["of"], got["digest"], got["supersedes"]), (2, 2, cr.digest(two), cr.digest(self.record)))

    def test_an_older_record_that_still_verifies_is_refused(self):
        two = self.second()
        self.refused("this card record (sequence 1) is not the newest the root signed (sequence 2", self.sign(self.record),
                     lines=[self.line(self.record), self.line(two)])

    def test_no_card_record_line_refuses_never_accepts_sequence_1(self):
        self.refused("the signing record holds no card-record line", self.sign(self.record), lines=[{"kind": "manifest", "epoch": 1, "digest": "ab" * 32}])
        self.refused("the signing record holds no card-record line", self.sign(self.record), lines=[])

    def test_a_gap_a_repeat_or_a_bool_sequence_is_refused(self):
        two = self.second()
        for lines in ([self.line(two)], [self.line(self.record), self.line(self.record, 1), self.line(two)],
                      [self.line(self.record, True), self.line(two)]):
            with self.subTest(lines=[l["sequence"] for l in lines]):
                self.refused("card-record lines are not 1..", self.sign(two), lines=lines)

    def test_a_line_under_another_root_or_malformed_is_refused(self):
        other = raw(Ed25519PrivateKey.generate())
        self.refused("card-record line 1 names another root than the pinned one", self.sign(self.record), lines=[self.line(self.record, key=other)])
        self.refused("card-record line 1 fields mismatch", self.sign(self.record), lines=[dict(self.line(self.record), note="x")])
        self.refused("line 1's digest is not a raw Ed25519 key", self.sign(self.record), lines=[dict(self.line(self.record), digest="AB")])
        self.refused("the signing record's line 2 is not an object with a kind", self.sign(self.record), lines=[self.line(self.record), ["x"]])

    def test_the_supersedes_chain(self):
        two = self.second()
        broken = dict(two, supersedes="cd" * 32)
        self.refused("does not supersede the one before it", self.sign(broken), lines=[self.line(self.record), self.line(broken)])
        self.refused("supersedes is not \"\" at sequence 1", self.changed(lambda r: r.update(supersedes="ab" * 32)))
        self.refused("supersedes is not \"\" at sequence 1, or the previous record's digest", self.sign(dict(two, supersedes="")),
                     lines=[self.line(self.record), self.line(dict(two, supersedes=""))])
        self.refused("sequence is not a count from 1", self.changed(lambda r: r.update(sequence=0)))
        self.refused("sequence is not a count from 1", self.changed(lambda r: r.update(sequence=True)))


class SigningState(unittest.TestCase):
    """read_signing_state: the laptop's state directory, its marker and its signing record, read whole (#403)."""

    ROOT = "8a" * 32

    def setUp(self):
        import tempfile
        import shutil
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o700)
        self.write(cr.SIGNING_STATE, json.dumps({"schema": cr.SIGNING_STATE_SCHEMA, "root": self.ROOT}))
        self.write(cr.SIGNING_RECORD, '{"kind": "manifest", "epoch": 1}\n{"kind": "card-record"}\n')

    def write(self, name, text, mode=0o600):
        path = os.path.join(self.d, name)
        with open(path, "w") as f:
            f.write(text)
        os.chmod(path, mode)
        return path

    def refused(self, reason):
        with self.assertRaises(m.Refused) as caught:
            cr.read_signing_state(self.d, self.ROOT)
        self.assertIn(reason, str(caught.exception))

    def test_every_line_in_order(self):
        self.assertEqual(cr.read_signing_state(self.d, self.ROOT), [{"kind": "manifest", "epoch": 1}, {"kind": "card-record"}])

    def test_the_marker_is_required_and_names_the_pinned_root(self):
        self.write(cr.SIGNING_STATE, json.dumps({"schema": cr.SIGNING_STATE_SCHEMA, "root": "9b" * 32}))
        self.refused("the state directory is another root's signing state")
        self.write(cr.SIGNING_STATE, json.dumps({"schema": "regalia.signing-state/v2", "root": self.ROOT}))
        self.refused("the state directory's marker is not a regalia.signing-state/v1")
        os.unlink(os.path.join(self.d, cr.SIGNING_STATE))
        self.refused("has no regalia-signing-state.json: it is not the root's signing state (wrong --state-dir?)")

    def test_a_torn_or_unparsable_line_refuses_the_whole_record(self):
        self.write(cr.SIGNING_RECORD, '{"kind": "manifest", "epoch": 1}\n{"kind": "card-rec')
        self.refused("the signing record's last line is torn")
        self.write(cr.SIGNING_RECORD, '{"kind": "manifest", "epoch": 1}\nnot json\n{"kind": "card-record"}\n')
        self.refused("the signing record's line 2 is not JSON")
        self.write(cr.SIGNING_RECORD, '')
        self.refused("holds no signing record")
        os.unlink(os.path.join(self.d, cr.SIGNING_RECORD))
        self.refused("holds no signing record")

    def test_never_through_a_link_nor_a_file_others_can_write(self):
        real = self.write("elsewhere.jsonl", '{"kind": "manifest", "epoch": 1}\n')
        os.unlink(os.path.join(self.d, cr.SIGNING_RECORD))
        os.symlink(real, os.path.join(self.d, cr.SIGNING_RECORD))
        self.refused("cannot be opened")
        os.unlink(os.path.join(self.d, cr.SIGNING_RECORD))
        self.write(cr.SIGNING_RECORD, '{"kind": "manifest", "epoch": 1}\n', mode=0o620)
        self.refused("is not a regular file of this user's, mode 0600")
        os.chmod(os.path.join(self.d, cr.SIGNING_RECORD), 0o640)                         # readable by the group: not 0600 either
        self.refused("is not a regular file of this user's, mode 0600")

    def test_the_record_is_read_whole_or_refused_whole(self):
        """51 and d9 on #403: a record cut at a line boundary would make an older card record "line M"."""
        from unittest import mock
        self.write(cr.SIGNING_RECORD, '{"kind": "manifest", "epoch": 1}\n' * 4)
        with mock.patch.object(cr, "MAX_SIGNING_RECORD", 64):
            self.refused("the signing record signing-record.jsonl is larger than 64 bytes")
        with mock.patch.object(cr, "MAX_SIGNING_RECORD", 4 * len('{"kind": "manifest", "epoch": 1}\n')):
            self.assertEqual(len(cr.read_signing_state(self.d, self.ROOT)), 4)

    def test_the_directory_is_this_user_s_0700_and_not_a_link(self):
        os.chmod(self.d, 0o750)
        self.refused("must be a directory of this user's, mode 0700, not a link")
        os.chmod(self.d, 0o700)
        link = self.d + ".link"
        os.symlink(self.d, link)
        self.addCleanup(os.unlink, link)
        with self.assertRaises(m.Refused) as caught:
            cr.read_signing_state(link, self.ROOT)
        self.assertIn("not a link", str(caught.exception))


class ProducersVectors(unittest.TestCase):
    """regalia-ceremony's own signed vectors (regalia-ceremony#121, copied into tests/vectors/card-ceremony-record/):
    valid.json accepted under the pinned root.hex, every other one refused. expect.json carries the producer's reasons;
    this verifier's words may differ, and its refusal must be about the same thing."""

    # the producer's refusal, and the words this verifier refuses the same record with
    SAME = {"bad-signature.json": "signature is not the pinned root's", "wrong-domain.json": "signature is not the pinned root's",
            "other-root.json": "names another root than the pinned one", "release-is-owner.json": "the release key is an owner key",
            "missing-dev-backup.json": "owner_keys is not exactly two keys", "unknown-field.json": "owner_keys[0] fields mismatch",
            "first-supersedes.json": "supersedes is not \"\" at sequence 1"}

    def test_every_vector_as_the_producer_judges_it(self):
        """Each record judged by the signing record as it stood when that record was the newest (its first `sequence`
        lines of the producer's signing-record.jsonl): the producer's "ok" for valid.json and sequence-2.json."""
        import pathlib
        here = pathlib.Path(__file__).parent / "vectors" / "card-ceremony-record"
        root = (here / "root.hex").read_text().strip()
        expect = json.loads((here / "expect.json").read_text())
        log = [json.loads(line) for line in (here / "signing-record.jsonl").read_text().splitlines()]
        self.assertEqual(sorted(expect), sorted(list(self.SAME) + ["valid.json", "sequence-2.json"]))
        for name, want in sorted(expect.items()):
            with self.subTest(vector=name):
                envelope = json.loads((here / name).read_text())
                if want == "ok":
                    got = cr.verify(envelope, root, log[:envelope["record"]["sequence"]])
                    self.assertEqual(sorted(got["roles"]), sorted(cr.ROLES))
                    continue
                with self.assertRaises(m.Refused) as caught:
                    cr.verify(envelope, root, log[:1])
                self.assertIn(self.SAME[name], str(caught.exception))

    def test_the_producer_s_first_record_is_superseded_by_its_second(self):
        """#403 on the producer's own vectors: valid.json, still validly signed, is refused once sequence-2 is on the log."""
        import pathlib
        here = pathlib.Path(__file__).parent / "vectors" / "card-ceremony-record"
        log = [json.loads(line) for line in (here / "signing-record.jsonl").read_text().splitlines()]
        with self.assertRaises(m.Refused) as caught:
            cr.verify(json.loads((here / "valid.json").read_text()), (here / "root.hex").read_text().strip(), log)
        self.assertIn("this card record (sequence 1) is not the newest the root signed (sequence 2", str(caught.exception))


class ProducersFreshness(unittest.TestCase):
    """regalia-ceremony's shared freshness vectors (#403; freshness/<case>/ and freshness-expect.json): each case's state
    directory, copied with the modes git does not keep (0700 directory, 0600 files), read whole by read_signing_state
    and judged with its record. The producer's reasons, and the words this reader refuses the same thing with."""

    SAME = {"bool-sequence": "card-record lines are not 1..", "foreign-key": "names another root than the pinned one",
            "gap": "card-record lines are not 1..", "marker-other-root": "the state directory is another root's signing state",
            "no-marker": "has no regalia-signing-state.json", "not-an-object": "line 2 is not an object with a kind",
            "superseded": "this card record (sequence 1) is not the newest the root signed (sequence 2",
            "torn-line": "the signing record's line 2 is not JSON"}

    def test_every_case_as_the_producer_judges_it(self):
        import pathlib
        import shutil
        import tempfile
        here = pathlib.Path(__file__).parent / "vectors" / "card-ceremony-record"
        root = (here / "root.hex").read_text().strip()
        cases = json.loads((here / "freshness-expect.json").read_text())
        self.assertEqual(sorted(cases), sorted(list(self.SAME) + ["current-1", "current-2"]))
        for case, want in sorted(cases.items()):
            with self.subTest(case=case):
                state = tempfile.mkdtemp()
                self.addCleanup(shutil.rmtree, state, True)
                for source in (here / "freshness" / case).iterdir():
                    shutil.copyfile(source, os.path.join(state, source.name))
                    os.chmod(os.path.join(state, source.name), 0o600)
                os.chmod(state, 0o700)
                envelope = json.loads((here / want["record"]).read_text())
                if want["expect"] == "ok":
                    got = cr.verify(envelope, root, cr.read_signing_state(state, root))
                    self.assertEqual((got["sequence"], got["of"]), (envelope["record"]["sequence"],) * 2)
                    continue
                with self.assertRaises(m.Refused) as caught:
                    cr.verify(envelope, root, cr.read_signing_state(state, root))
                self.assertIn(self.SAME[case], str(caught.exception))

    def test_a_line_without_a_kind_is_refused(self):
        """Every line of the laptop's record says what it is: manifest.py's lines carry "kind": "manifest" (#403)."""
        import tempfile
        import shutil
        state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, state, True)
        os.chmod(state, 0o700)
        for name, text in ((cr.SIGNING_STATE, json.dumps({"schema": cr.SIGNING_STATE_SCHEMA, "root": "8a" * 32})),
                           (cr.SIGNING_RECORD, '{"epoch": 1, "digest": "ab"}\n')):
            with open(os.path.join(state, name), "w") as f:
                f.write(text)
            os.chmod(os.path.join(state, name), 0o600)
        with self.assertRaises(m.Refused) as caught:
            cr.read_signing_state(state, "8a" * 32)
        self.assertIn("the signing record's line 1 is not an object with a kind", str(caught.exception))


class ProducersWriterRun(unittest.TestCase):
    """The producer's REAL output, not a vector: regalia-ceremony#128's writer (offline-keys card-record, head c688584)
    run once, 2026-10-04, by regalia-kms-1e through that PR's test_card_record_writer.Writer setup: a 2-of-3 Shamir lab
    root (ok.generate, real age; the shares not kept), then card_record(first=True) and card_record(). Kept: the state
    directory it left (marker, signing-record.jsonl with card-record lines 1 and 2) and both records
    (tests/vectors/card-ceremony-record/writer-run/). Its output is not byte-reproducible, so it is a fixture made once,
    not regenerated. This side must read it as the writer meant it (regalia-kms-24's cross-repo check)."""

    def setUp(self):
        import pathlib
        import shutil
        import tempfile
        self.here = pathlib.Path(__file__).parent / "vectors" / "card-ceremony-record" / "writer-run"
        self.root = (self.here / "root.hex").read_text().strip()
        self.state = tempfile.mkdtemp()                                    # git keeps no modes: as the writer left them
        self.addCleanup(shutil.rmtree, self.state, True)
        for source in (self.here / "state").iterdir():
            shutil.copyfile(source, os.path.join(self.state, source.name))
            os.chmod(os.path.join(self.state, source.name), 0o600)
        os.chmod(self.state, 0o700)

    def record(self, n):
        return json.loads((self.here / ("card-record-%d.record.json" % n)).read_text())

    def test_the_writer_s_second_record_is_the_newest_and_its_first_is_superseded(self):
        lines = cr.read_signing_state(self.state, self.root)
        got = cr.verify(self.record(2), self.root, lines)
        self.assertEqual((got["sequence"], got["of"], got["supersedes"]), (2, 2, cr.digest(self.record(1)["record"])))
        self.assertEqual(got["roles"], {"dev-main": "40000001", "dev-backup": "40000002"})
        with self.assertRaises(m.Refused) as caught:
            cr.verify(self.record(1), self.root, lines)
        self.assertIn("this card record (sequence 1) is not the newest the root signed (sequence 2", str(caught.exception))

    def test_propose_genesis_takes_the_writer_s_record_and_state(self):
        import io
        import shutil
        import tempfile
        from unittest import mock
        from deploy.baremetal import manifest as tool, measurements
        from tests.test_baremetal_membership_v4 import nodes4
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        entries = [{k: v for k, v in n.items() if k != "state"} for n in nodes4()]
        doc = {"schema": measurements.SCHEMA, "name": "genesis", "nodes": {
            e["node_id"]: {"accepted": [{"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
                                         "phases": {"initrd": {"11": "aa" * 32}, "system": {"11": "bb" * 32}}}]} for e in entries}}
        with open(os.path.join(d, "doc.json"), "w") as f:
            json.dump(doc, f)
        with open(os.path.join(d, "system.pem"), "w") as f:
            f.write("stub\n")
        from tests.test_baremetal_membership_v4 import K_A, typed
        # K_A's generation record is signed by the root of its sealed set, and this writer run's lab root is gone (its shares
        # were not kept): the record is stood in for here, as this test is the card record's (K_A's is test_baremetal_manifest's)
        with open(os.path.join(d, "offline-keys.record.json"), "w") as f:
            json.dump({"stand-in": True}, f)
        generated = {"at": "2026-10-04T10:00:00Z", "master_id": "ab" * 16, "threshold": 2, "shares": 3}
        args = ["--offline-keys-record", os.path.join(d, "offline-keys.record.json")]
        args = ["propose", "--genesis", *args, "--root-key", self.root, "--card-record", str(self.here / "card-record-2.record.json"),
                "--state-dir", self.state, "--measurements", os.path.join(d, "doc.json"), "--out", os.path.join(d, "e1.json"),
                "--issued-at", "2026-10-04T12:00:00Z", "--system-pub", os.path.join(d, "system.pem")]
        for e in entries:                   # each node as `enrol` proves it (#399; stubbed here: its proof is enrol's own test)
            path = os.path.join(d, "bundle-%s.json" % e["node_id"])
            with open(path, "w") as f:
                json.dump(e, f)
            args += ["--node", path, path, path]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err), mock.patch.object(tool.keyfd, "tty_line", lambda p: "40000001 40000002"), \
                mock.patch.object(tool.enrol, "proven_entry", lambda bundle, pub, keep, act, run=None: (bundle, {"7": "00" * 32, "11": "bb" * 32})), \
                mock.patch.object(tool, "offline_keys_record", lambda envelope, root: (typed(K_A), generated)):
            self.assertEqual(tool.main(args), 0, err.getvalue())
        self.assertIn("card record 2 of 2 (the newest on this laptop's signing record)", out.getvalue())
        with open(os.path.join(d, "e1.json")) as f:
            written = json.load(f)
        owners = self.record(2)["record"]["owner_keys"]
        self.assertEqual(written["owner_keys"], [{"alg": "ed25519", "key": k["key"]} for k in sorted(owners, key=lambda k: k["serial"])])
        # the writer's own record, pinned by sequence and digest (#405), and K_A (#361; from the stood-in record)
        self.assertEqual(written["card_record"], {"sequence": 2, "digest": cr.digest(self.record(2)["record"])})
        self.assertEqual(written["anchor_policy_key"], typed(K_A))


if __name__ == "__main__":
    unittest.main()
