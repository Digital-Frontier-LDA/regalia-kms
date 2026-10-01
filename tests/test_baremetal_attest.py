"""deploy/baremetal/attest.py without a TPM: the TPM structures are built here (and two are bytes captured
from swtpm), the AK is an OpenSSL P-256 key, and tpm2_makecredential is faked. A good quote is accepted;
a replayed nonce, each substituted transcript field, wrong PCRs, another signer, a changed firmware
version and every counter violation is refused with its own reason (regalia-kms#65 PoC 5.1/5.4/5.5).
The real TPM2_MakeCredential/ActivateCredential and TPM2_Quote run in e2e/tpm-attest-swtpm.sh."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from deploy.baremetal import attest

# Captured from swtpm (tpm2-tools 5.7): an AK made by tpm2_createak under the EK, a quote it signed over
# PCRs 0 and 7, and the names tpm2-tools printed for them.
AK_PUB = bytes.fromhex(
    "00580023000b00050072000000100018000b000300100020808c238852e24e666fd210b168742c22f2279eac79951eeb376170e5238df338"
    "0020686fe72bed5092b0b6a48249a873418f10f69239cba419b4c8883b807b48a613")
AK_NAME = "000b224f6257ea76ccb9187001cfbfb83b466e1436167822ace985a535dba8fed7ea"
AK_SPKI = ("3059301306072a8648ce3d020106082a8648ce3d03010703420004808c238852e24e666fd210b168742c22f2279eac79951eeb376170e5"
           "238df338686fe72bed5092b0b6a48249a873418f10f69239cba419b4c8883b807b48a613")
EK_NAME = "000bb329cee2c3be25a16c0ff9face3d1b7d005bb070f53ad8887d18957cc89dbcd8"
AK_QUALIFIED_NAME = "000b605f2f7d75e98e60cb0570503cb8a471ad9149a99fb07b9c91eb276761dca0c5"
QUOTE = bytes.fromhex(
    "ff54434780180022000b605f2f7d75e98e60cb0570503cb8a471ad9149a99fb07b9c91eb276761dca0c500202577cfae95e6c2d68b7776e1"
    "2f034985e2e9897d38d724f765329c7b4e4a37af00000000000003b3000000010000000001201910230016363600000001000b0381000000"
    "20f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")

FW = "2019102300163636"
PCRS = {"0": "11" * 32, "7": "77" * 32}
EK_PUB = struct.pack(">H", 6) + b"ek-pub"   # a stand-in public area: only its Name matters to the verifier
SESSION, KEY, EPOCH = b"S" * 32, b"ephemeral public key (DER)", 7


def b2(data):
    return struct.pack(">H", len(data)) + data


def ak_public(x=b"\x01" * 32, y=b"\x02" * 32, kind=attest.ALG_ECC, attributes=attest.AK_ATTRIBUTES, policy=b"",
              symmetric=attest.ALG_NULL, scheme=attest.ALG_ECDSA, curve=attest.CURVE_P256, name_alg=attest.ALG_SHA256,
              kdf=attest.ALG_NULL, trailing=b""):
    area = struct.pack(">HHI", kind, name_alg, attributes) + b2(policy) + struct.pack(
        ">HHHHH", symmetric, scheme, attest.ALG_SHA256, curve, kdf) + b2(x) + b2(y)
    return b2(area) + trailing


def quote(extra, signer, pcrs=(0, 7), digest=None, reset=1, restart=0, clock=1000, firmware=FW,
          magic=attest.TPM_GENERATED, kind=attest.ST_ATTEST_QUOTE, banks=1, bank=attest.ALG_SHA256, trailing=b""):
    bitmap = bytearray(3)
    for i in pcrs:
        bitmap[i // 8] |= 1 << (i % 8)
    digest = attest.expected_pcr_digest(PCRS) if digest is None else digest
    return (struct.pack(">IH", magic, kind) + b2(signer) + b2(extra) + struct.pack(">QIIB", clock, reset, restart, 1)
            + bytes.fromhex(firmware) + struct.pack(">IHB", banks, bank, 3) + bytes(bitmap) + b2(digest) + trailing)


class Structures(unittest.TestCase):
    def refused(self, reason, fn, *args):
        with self.assertRaises(attest.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_an_ak_from_a_real_tpm_gets_the_name_and_key_the_tpm_reports(self):
        name, spki = attest.ak_identity(AK_PUB)
        self.assertEqual(name.hex(), AK_NAME)
        self.assertEqual(spki.hex(), AK_SPKI)

    def test_the_qualified_name_is_the_one_the_tpm_puts_in_its_quotes(self):
        self.assertEqual(attest.qualified_name(bytes.fromhex(EK_NAME), bytes.fromhex(AK_NAME)).hex(), AK_QUALIFIED_NAME)
        self.assertEqual(attest.parse_quote(QUOTE)["qualified_signer"].hex(), AK_QUALIFIED_NAME)

    def test_a_real_quote_parses_to_what_tpm2_print_shows(self):
        q = attest.parse_quote(QUOTE)
        self.assertEqual((q["clock"], q["reset_count"], q["restart_count"], q["safe"]), (947, 1, 0, 1))
        self.assertEqual(q["firmware_version"], "2019102300163636")
        self.assertEqual(q["pcrs"], [0, 7])
        self.assertEqual(q["extra_data"].hex(), "2577cfae95e6c2d68b7776e12f034985e2e9897d38d724f765329c7b4e4a37af")
        self.assertEqual(q["pcr_digest"].hex(), "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b")

    def test_only_a_restricted_sign_only_tpm_made_p256_key_is_an_ak(self):
        attest.ak_identity(ak_public())
        for label, reason, blob in (
                ("unrestricted", "restricted, sign-only", ak_public(attributes=0x00040072)),
                ("also decrypts", "restricted, sign-only", ak_public(attributes=0x00070072)),
                ("not fixedTPM", "restricted, sign-only", ak_public(attributes=0x00050070)),
                ("made outside the TPM", "restricted, sign-only", ak_public(attributes=0x00050052)),
                ("RSA", "must be an ECC key", ak_public(kind=0x0001)),
                ("SHA-1 name", "name algorithm", ak_public(name_alg=0x0004)),
                ("auth policy", "auth policy", ak_public(policy=b"\x00" * 32)),
                ("symmetric", "symmetric", ak_public(symmetric=0x0006)),
                ("ECDAA", "ECDSA with SHA-256", ak_public(scheme=0x001A)),
                ("P-384", "P-256", ak_public(curve=0x0004)),
                ("KDF", "KDF", ak_public(kdf=0x0020)),
                ("short point", "not a P-256 point", ak_public(x=b"\x01" * 31)),
                ("trailing bytes", "trailing bytes", ak_public(trailing=b"\x00")),
                ("truncated", "truncated", ak_public()[:-1])):
            with self.subTest(label):
                self.refused(reason, attest.ak_identity, blob)

    def test_only_a_tpm_generated_quote_over_one_sha256_bank_parses(self):
        for label, reason, blob in (
                ("magic", "not generated by a TPM", quote(b"", b"", magic=0)),
                ("a certify structure", "not a quote", quote(b"", b"", kind=0x8017)),
                ("two banks", "exactly one PCR bank", quote(b"", b"", banks=2)),
                ("SHA-1 bank", "SHA-256 PCR bank", quote(b"", b"", bank=0x0004)),
                ("trailing bytes", "trailing bytes", quote(b"", b"", trailing=b"\x00")),
                ("truncated", "truncated", quote(b"", b"")[:-1])):
            with self.subTest(label):
                self.refused(reason, attest.parse_quote, blob)

    def test_no_two_sessions_share_a_transcript(self):
        base = ("site-a", EPOCH, SESSION, KEY, b"N" * 32)
        seen = {attest.transcript(*base)}
        for i, other in enumerate(("site-b", EPOCH + 1, b"T" * 32, KEY + b"x", b"M" * 32)):
            changed = attest.transcript(*(base[:i] + (other,) + base[i + 1:]))
            self.assertNotIn(changed, seen)
            seen.add(changed)
        # bytes moved from one field into its neighbour must not encode the same
        self.assertNotEqual(attest.transcript("a", 1, b"SS", b"K", b"N"), attest.transcript("a", 1, b"S", b"SK", b"N"))
        self.assertTrue(attest.transcript(*base).startswith(struct.pack(">I", 21) + b"regalia-kms/attest/v1"))

    def test_the_policy_is_strict(self):
        good = {"ek_name": EK_NAME, "tpm_firmware_version": FW, "pcrs": PCRS}
        attest.validate_policy({"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": good}})
        for label, reason, node in (
                ("unknown field", "fields mismatch", dict(good, extra=1)),
                ("missing field", "fields mismatch", {k: v for k, v in good.items() if k != "pcrs"}),
                ("EK name not a SHA-256 Name", "ek_name", dict(good, ek_name="0004" + "a" * 64)),
                ("uppercase firmware", "tpm_firmware_version", dict(good, tpm_firmware_version=FW.replace("2", "A"))),
                ("no PCRs", "at least one PCR", dict(good, pcrs={})),
                ("PCR 24", "not a PCR 0-23", dict(good, pcrs={"24": "0" * 64})),
                ("PCR 07", "not a PCR 0-23", dict(good, pcrs={"07": "0" * 64})),
                ("short PCR value", "64 lowercase hex", dict(good, pcrs={"7": "0" * 62}))):
            with self.subTest(label):
                self.refused(reason, attest.validate_policy, {"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": node}})
        self.refused("schema", attest.validate_policy, {"schema": "v0", "nodes": {"site-a": good}})
        self.refused("policy must be an object", attest.validate_policy, [good])
        self.refused("not a plain name", attest.validate_policy, {"schema": attest.POLICY_SCHEMA, "nodes": {"site a": good}})
        self.refused("exceeds 128 KiB", attest.load_json, b" " * (attest.MAX_BYTES + 1), "policy")
        self.refused("at least one node", attest.validate_policy, {"schema": attest.POLICY_SCHEMA, "nodes": {}})
        self.refused("duplicate", attest.load_json, b'{"schema": 1, "schema": 2}', "policy")

    def test_session_values_are_checked_on_the_node_side_too(self):
        good = ("site-a", EPOCH, SESSION, KEY, b"N" * 32)
        attest.check_session(*good)
        for i, bad, reason in ((0, "site a", "plain name"), (0, b"site-a", "plain name"), (1, True, "uint64"),
                               (2, b"S" * 31, "32 bytes"), (3, b"", "1-512 bytes"), (4, b"N" * 31, "nonce must be 32 bytes")):
            with self.subTest(reason=reason, bad=repr(bad)[:12]):
                self.refused(reason, attest.check_session, *(good[:i] + (bad,) + good[i + 1:]))

    def test_the_expected_pcr_digest_is_over_the_values_in_pcr_order(self):
        self.assertEqual(attest.expected_pcr_digest({"7": "77" * 32, "0": "11" * 32, "10": "aa" * 32}),
                         hashlib.sha256(b"\x11" * 32 + b"\x77" * 32 + b"\xaa" * 32).digest())
        # two zeroed PCRs: the digest swtpm quoted above
        self.assertEqual(attest.expected_pcr_digest({"0": "00" * 32, "7": "00" * 32}), attest.parse_quote(QUOTE)["pcr_digest"])


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class Verification(unittest.TestCase):
    """A verifier with one node in its policy, and an AK whose private half OpenSSL holds."""

    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.keys)
        cls.ak, cls.ak_pub = cls.make_key("ak")
        cls.other, cls.other_pub = cls.make_key("other")

    @classmethod
    def make_key(cls, name):
        key = os.path.join(cls.keys, name + ".pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key],
                       check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        return key, ak_public(x=der[-64:-32], y=der[-32:])

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.clock = [1000.0]
        self.secrets = []
        self.ek_name = attest.name_of(attest.public_area(EK_PUB, "EK"))
        self.policy = {"schema": attest.POLICY_SCHEMA, "nodes": {
            "site-a": {"ek_name": self.ek_name.hex(), "tpm_firmware_version": FW, "pcrs": dict(PCRS)},
            "site-b": {"ek_name": "000b" + "b" * 64, "tpm_firmware_version": FW, "pcrs": dict(PCRS)}}}
        self.v = self.verifier()
        self.enroll()

    def verifier(self):
        return attest.Verifier(self.policy, os.path.join(self.d, "state.json"), now=lambda: self.clock[0], run=self.run_tool)

    def run_tool(self, argv, **kw):
        """tpm2_makecredential, faked: it records the secret it was asked to wrap. OpenSSL is real."""
        if argv[0] != "tpm2_makecredential":
            return subprocess.run(argv, **kw)
        self.assertEqual(argv[1:3], ["--tcti", "none"])
        if getattr(self, "fail_makecredential", False):
            return subprocess.CompletedProcess(argv, 1, "", "no")
        with open(argv[argv.index("-s") + 1], "rb") as f:
            self.secrets.append((argv[argv.index("-n") + 1], f.read()))
        with open(argv[argv.index("-o") + 1], "wb") as f:
            f.write(b"credential")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def enroll(self, ak_pub=None, **kw):
        self.v.challenge("site-a", EK_PUB, ak_pub or self.ak_pub, **kw)
        return self.v.enroll("site-a", self.secrets[-1][1])

    def sign(self, blob, key=None):
        path = os.path.join(self.d, "q")
        with open(path, "wb") as f:
            f.write(blob)
        return subprocess.run(["openssl", "dgst", "-sha256", "-sign", key or self.ak, path], check=True, capture_output=True).stdout

    def signer(self, ak_pub=None):
        return attest.qualified_name(self.ek_name, attest.ak_identity(ak_pub or self.ak_pub)[0])

    def attempt(self, session=SESSION, key=KEY, epoch=EPOCH, node="site-a", quoted=None, sign_with=None, nonce=None,
                signature=None, **fields):
        """The node quotes `quoted` (default: exactly what the verifier holds); the verifier checks its own values."""
        nonce = nonce or self.v.nonce("site-a")
        told = dict(node_id=node, epoch=epoch, session_id=session, ephemeral_public=key, nonce=nonce)
        extra = attest.qualifying_data(*dict(told, **(quoted or {})).values())
        blob = quote(extra, fields.pop("signer", self.signer()), **fields)
        return self.v.verify(node, epoch, session, key, nonce, blob, signature or self.sign(blob, sign_with))

    def refused(self, reason, **kw):
        with self.assertRaises(attest.Refused) as caught:
            self.attempt(**kw)
        self.assertIn(reason, str(caught.exception))

    # ---- enrollment ----

    def test_the_credential_is_made_for_the_computed_ak_name_and_a_fresh_secret(self):
        self.assertEqual(self.secrets[0][0], attest.ak_identity(self.ak_pub)[0].hex())
        self.enroll(replace=True)
        self.assertNotEqual(self.secrets[0][1], self.secrets[1][1])
        self.assertEqual(len(self.secrets[1][1]), 32)

    def test_enrollment_refusals(self):
        def refused(reason, fn, *args, **kw):
            with self.assertRaises(attest.Refused) as caught:
                fn(*args, **kw)
            self.assertIn(reason, str(caught.exception))
        refused("unknown node", self.v.challenge, "site-z", EK_PUB, self.ak_pub)
        refused("not the one recorded", self.v.challenge, "site-a", b2(b"another ek"), self.ak_pub)
        refused("not the one recorded", self.v.challenge, "site-b", EK_PUB, self.ak_pub)
        refused("restricted, sign-only", self.v.challenge, "site-a", EK_PUB, ak_public(attributes=0x00040072), replace=True)
        refused("already has an enrolled AK", self.v.challenge, "site-a", EK_PUB, self.other_pub)
        refused("no enrollment challenge is outstanding", self.v.enroll, "site-a", self.secrets[-1][1])
        self.v.challenge("site-a", EK_PUB, self.other_pub, replace=True)
        refused("not the secret that was wrapped", self.v.enroll, "site-a", b"\x00" * 32)
        refused("no enrollment challenge is outstanding", self.v.enroll, "site-a", self.secrets[-1][1])   # one attempt
        self.v.challenge("site-a", EK_PUB, self.other_pub, replace=True)
        self.clock[0] += attest.NONCE_TTL + 1
        refused("challenge expired", self.v.enroll, "site-a", self.secrets[-1][1])
        refused("no enrolled AK", self.v.nonce, "site-b")
        refused("exceeds 1 KiB", self.v.challenge, "site-a", EK_PUB, self.ak_pub + b"\x00" * 1024, replace=True)
        self.fail_makecredential = True
        refused("tpm2_makecredential failed", self.v.challenge, "site-a", EK_PUB, self.ak_pub, replace=True)
        self.attempt()   # every failed re-enrollment left the first AK in place

    def test_a_replaced_ak_takes_over_and_keeps_the_boot_history(self):
        self.attempt(reset=5)
        self.enroll(self.other_pub, replace=True)
        self.refused("signature does not verify", session=b"T" * 32, key=b"k2", reset=6)
        new = dict(sign_with=self.other, signer=self.signer(self.other_pub))
        self.refused("counters went backwards", session=b"T" * 32, key=b"k2", reset=4, **new)
        self.attempt(session=b"T" * 32, key=b"k2", reset=6, **new)

    # ---- one quote ----

    def test_a_fresh_quote_is_accepted_and_the_state_file_is_private(self):
        verdict = self.attempt(reset=3, restart=1, clock=42)
        self.assertEqual(verdict, {"node": "site-a", "epoch": EPOCH, "session_id": SESSION.hex(), "reset_count": 3,
                                   "restart_count": 1, "clock": 42, "pcrs": [0, 7]})
        self.assertEqual(os.stat(os.path.join(self.d, "state.json")).st_mode & 0o777, 0o600)

    def test_a_nonce_is_single_use_issued_by_this_verifier_for_this_node_and_short_lived(self):
        nonce = self.v.nonce("site-a")
        self.attempt(nonce=nonce)
        self.refused("nonce is not outstanding", nonce=nonce)
        self.refused("nonce is not outstanding", nonce=b"\x07" * 32)
        nonce = self.v.nonce("site-a")
        self.refused("signature does not verify", nonce=nonce, signature=b"\x30\x00")
        self.refused("nonce is not outstanding", nonce=nonce)   # consumed by the failed attempt
        nonce = self.v.nonce("site-a")
        self.clock[0] += attest.NONCE_TTL + 1
        self.refused("nonce expired", nonce=nonce)
        other = dict(self.policy["nodes"]["site-a"])
        self.policy["nodes"]["site-b"] = other
        self.v = self.verifier()
        self.refused("issued to another node", node="site-b")

    def test_another_verifier_instance_on_the_same_state_sees_a_used_nonce(self):
        nonce = self.v.nonce("site-a")
        self.attempt(nonce=nonce)
        self.v = self.verifier()
        self.refused("nonce is not outstanding", nonce=nonce)

    def test_each_transcript_field_substituted_on_its_own_is_refused(self):
        for field, value in (("node_id", "site-b"), ("epoch", EPOCH - 1), ("session_id", b"T" * 32),
                             ("ephemeral_public", b"another key"), ("nonce", b"\x01" * 32)):
            with self.subTest(field):
                self.refused("not bound to this transcript", quoted={field: value})

    def test_wrong_pcrs_signer_or_firmware_are_refused(self):
        self.refused("covers PCRs [0], not the expected [0, 7]", pcrs=(0,))
        self.refused("covers PCRs [0, 7, 11]", pcrs=(0, 7, 11))
        self.refused("not the expected PCR values", digest=hashlib.sha256(b"other values").digest())
        self.refused("signature does not verify", sign_with=self.other)
        self.refused("not the enrolled AK under the recorded EK", signer=self.signer(self.other_pub))
        self.refused("not the enrolled AK under the recorded EK",
                     signer=attest.qualified_name(b"\x00\x0b" + b"e" * 32, attest.ak_identity(self.ak_pub)[0]))
        self.refused("firmware version 2019102300163637", firmware="2019102300163637")
        self.refused("not generated by a TPM", magic=0x12345678)
        self.refused("oversized", trailing=b"\x00" * 1024)
        self.attempt()   # and none of those poisoned the node's record

    def test_malformed_session_values_are_refused_before_any_state_changes(self):
        nonce = self.v.nonce("site-a")
        for kw, reason in ((dict(session=b"short"), "32 bytes"), (dict(key=b""), "1-512 bytes"), (dict(key=b"k" * 513), "1-512 bytes"),
                           (dict(epoch=-1, quoted={"epoch": 0}), "uint64"), (dict(epoch=2 ** 64, quoted={"epoch": 0}), "uint64"), (dict(node="site-z"), "unknown node")):
            with self.subTest(reason=reason, **{k: repr(v)[:20] for k, v in kw.items()}):
                self.refused(reason, nonce=nonce, **kw)
        self.attempt(nonce=nonce)   # the nonce was not spent on input that never reached the checks

    def test_state_of_another_schema_or_without_the_ak_is_refused(self):
        path = os.path.join(self.d, "state.json")
        with open(path) as f:
            state = json.load(f)
        nonce = self.v.nonce("site-a")
        with open(path) as f:
            issued = json.load(f)
        del issued["nodes"]["site-a"]["ak_public"]
        with open(path, "w") as f:
            json.dump(issued, f)
        self.refused("no enrolled AK", nonce=nonce)
        with open(path, "w") as f:
            json.dump(dict(state, schema="regalia-kms/attest-state/v0"), f)
        with self.assertRaises(attest.Refused) as caught:
            self.v.nonce("site-a")
        self.assertIn("state schema", str(caught.exception))

    # ---- TPMS_CLOCK_INFO ----

    def test_one_boot_carries_one_session(self):
        self.attempt(clock=100)
        self.attempt(clock=200)   # the same session again, later in the same boot
        self.refused("second boot session in the same boot", session=b"T" * 32, clock=300)
        self.refused("second boot session in the same boot", key=b"another key", clock=300)
        self.refused("clock went backwards", clock=150)

    def test_a_session_never_outlives_a_reboot(self):
        self.attempt(reset=1)
        self.refused("from an earlier boot", reset=2)
        self.refused("from an earlier boot", reset=2, session=b"T" * 32)   # a new session ID, the old ephemeral key
        self.refused("from an earlier boot", restart=1, key=b"k2")         # resume counts as a new boot too
        self.attempt(reset=2, session=b"T" * 32, key=b"k2")
        self.attempt(reset=3, session=b"U" * 32, key=b"k3")
        self.refused("from an earlier boot", reset=4)   # and the first boot's session is still remembered

    def test_counters_never_go_backwards(self):
        self.attempt(reset=5, restart=2)
        self.refused("counters went backwards ([4, 9] after [5, 2])", reset=4, restart=9, session=b"T" * 32, key=b"k2")
        self.refused("counters went backwards", reset=5, restart=1, session=b"T" * 32, key=b"k2")
        self.attempt(reset=5, restart=2)

    def test_a_refused_quote_does_not_advance_the_counters(self):
        self.attempt(reset=1)
        self.refused("not the expected PCR values", reset=9, session=b"T" * 32, key=b"k2", digest=b"\x00" * 32)
        self.attempt(reset=2, session=b"T" * 32, key=b"k2")


class Node(unittest.TestCase):
    """The node's half, with tpm2-tools faked: what it asks the TPM for, and what it does when the TPM refuses."""

    def run_tool(self, argv, **kw):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 1 if argv[0] in self.failing else 0, "certinfodata:5ec7e7", "the TPM said no")

    def setUp(self):
        self.calls, self.failing = [], ()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)

    def refused(self, reason, fn, *args):
        with self.assertRaises(attest.Refused) as caught:
            fn(*args, run=self.run_tool)
        self.assertIn(reason, str(caught.exception))

    def test_the_quote_is_asked_for_over_the_transcript_hash_with_the_persistent_ak(self):
        attest.node_quote("site-a", EPOCH, SESSION, KEY, b"N" * 32, [7, 0, 7], "q", "s", run=self.run_tool)
        argv = self.calls[0]
        self.assertEqual(argv[0], "tpm2_quote")
        self.assertEqual(argv[argv.index("-c") + 1], attest.AK_HANDLE)
        self.assertEqual(argv[argv.index("-l") + 1], "sha256:0,7")
        self.assertEqual(argv[argv.index("-q") + 1], attest.qualifying_data("site-a", EPOCH, SESSION, KEY, b"N" * 32).hex())

    def test_a_bad_pcr_list_or_a_tpm_failure_is_a_refusal(self):
        for pcrs in ([], [24], [-1], ["7"]):
            with self.subTest(pcrs=pcrs):
                self.refused("PCRs must be 0-23", attest.node_quote, "site-a", EPOCH, SESSION, KEY, b"N" * 32, pcrs, "q", "s")
        self.assertEqual(self.calls, [])
        self.failing = ("tpm2_quote",)
        self.refused("tpm2_quote failed: the TPM said no", attest.node_quote, "site-a", EPOCH, SESSION, KEY, b"N" * 32, [7], "q", "s")

    def test_a_failed_activation_is_a_refusal_and_the_session_is_still_flushed(self):
        self.failing = ("tpm2_activatecredential",)
        self.refused("does not hold the EK and AK", attest.node_activate, "cred", os.path.join(self.d, "secret"))
        self.assertEqual([c[0] for c in self.calls], ["tpm2_startauthsession", "tpm2_policysecret", "tpm2_activatecredential", "tpm2_flushcontext"])

    def test_the_command_line_refuses_a_malformed_pcr_list_and_an_oversized_file(self):
        big = os.path.join(self.d, "big")
        with open(big, "wb") as f:
            f.write(b"k" * 513)
        common = ["node-quote", "--node-id", "a", "--epoch", "1", "--session-id", "00" * 32, "--nonce", "00" * 32,
                  "--quote", os.path.join(self.d, "q"), "--signature", os.path.join(self.d, "s")]
        for extra, reason in ((["--pcrs", "0;7", "--ephemeral-public", big], "--pcrs must be a list"),
                              (["--pcrs", "0,7", "--ephemeral-public", big], "is oversized")):
            with self.subTest(reason), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(attest.main(common + extra), 1)
                self.assertIn(reason, err.getvalue())


class CommandLine(unittest.TestCase):
    def test_a_refusal_exits_nonzero_with_the_reason_and_no_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            policy = os.path.join(d, "policy.json")
            with open(policy, "w") as f:
                f.write('{"schema": "nope", "nodes": {}}')
            for argv, reason in (
                    (["nonce", "--policy", policy, "--state", os.path.join(d, "s"), "--node-id", "site-a"], "REFUSED: policy schema"),
                    (["nonce", "--policy", os.path.join(d, "absent"), "--state", os.path.join(d, "s"), "--node-id", "a"], "REFUSED: "),
                    (["node-quote", "--node-id", "a", "--epoch", "1", "--session-id", "zz", "--ephemeral-public", policy,
                      "--nonce", "00", "--pcrs", "0,7", "--quote", os.path.join(d, "q"), "--signature", os.path.join(d, "s")],
                     "REFUSED: --session-id must be lowercase hex")):
                with self.subTest(argv[0]), contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(attest.main(argv), 1)
                    self.assertIn(reason, err.getvalue())


if __name__ == "__main__":
    unittest.main()
