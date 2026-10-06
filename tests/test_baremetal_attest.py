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
from unittest import mock

from deploy.baremetal import attest
from deploy.baremetal import membership as m

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
NEXT_PCRS = {"0": "11" * 32, "7": "88" * 32}   # the same selection, another image
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
          magic=attest.TPM_GENERATED, kind=attest.ST_ATTEST_QUOTE, banks=1, bank=attest.ALG_SHA256, safe=1, trailing=b""):
    bitmap = bytearray(3)
    for i in pcrs:
        bitmap[i // 8] |= 1 << (i % 8)
    digest = attest.expected_pcr_digest(PCRS) if digest is None else digest
    return (struct.pack(">IH", magic, kind) + b2(signer) + b2(extra) + struct.pack(">QIIB", clock, reset, restart, safe)
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
        self.refused("policy exceeds 128 KiB", attest.load_json, b" " * (attest.MAX_BYTES + 1), "policy")
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

    def test_the_state_holds_no_float_whatever_the_clock_reads(self):
        """update.Host.own_state reads this file with the strict document loader, which refuses floats: an outstanding
        nonce or enrolment challenge timed by a wall clock with a fraction made a node refuse its own state (#369's
        rolling run: "floats are not allowed")."""
        from deploy.baremetal import membership
        self.clock[0] = 1791137837.396
        self.v.nonce("site-a")
        self.v.challenge("site-a", EK_PUB, self.ak_pub, replace=True)
        with open(os.path.join(self.d, "state.json"), "rb") as f:
            state = membership.load(f.read())
        self.assertTrue(state["nonces"] and all(isinstance(v["expires"], int) for v in state["nonces"].values()))
        self.assertIsInstance(state["nodes"]["site-a"]["pending"]["expires"], int)

    def run_tool(self, argv, **kw):
        """tpm2_makecredential, faked: it records the secret it was asked to wrap. OpenSSL is real."""
        if argv[0] != "tpm2_makecredential":
            return subprocess.run(argv, **kw)
        self.assertEqual(argv[1:3], ["--tcti", "none"])
        if getattr(self, "fail_makecredential", False):
            return subprocess.CompletedProcess(argv, 1, b"", b"no")
        self.assertEqual(argv[argv.index("-s") + 1], "-")   # on stdin: the secret is never a file
        self.secrets.append((argv[argv.index("-n") + 1], kw["input"]))
        with open(argv[argv.index("-o") + 1], "wb") as f:
            f.write(b"credential")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

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
                signature=None, phase=None, pcr_values=None, **fields):
        """The node quotes `quoted` (default: exactly what the verifier holds); the verifier checks its own values."""
        nonce = nonce or self.v.nonce("site-a")
        told = dict(node_id=node, epoch=epoch, session_id=session, ephemeral_public=key, nonce=nonce)
        extra = attest.qualifying_data(*dict(told, **(quoted or {})).values())
        blob = quote(extra, fields.pop("signer", self.signer()), **fields)
        kw = dict({"phase": phase} if phase else {}, **({"pcr_values": pcr_values} if pcr_values is not None else {}))
        return self.v.verify(node, epoch, session, key, nonce, blob, signature or self.sign(blob, sign_with), **kw)

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

    def test_the_ak_offered_must_be_the_one_the_manifest_names(self):
        """#190: given the manifest's AK Name, the challenge refuses any other AK, before anything is wrapped or held."""
        manifest_ak = attest.ak_identity(self.other_pub)[0].hex()
        made = len(self.secrets)
        with self.assertRaises(attest.Refused) as caught:
            self.v.challenge("site-a", EK_PUB, self.ak_pub, replace=True, ak_name=manifest_ak)
        self.assertIn("not the one the manifest names", str(caught.exception))
        self.assertEqual(len(self.secrets), made, "no credential is made for an AK the manifest does not name")
        for spelling in (manifest_ak.upper(), manifest_ak[:-2] + "\u00e9a", manifest_ak[:-2], None.__class__.__name__):
            with self.assertRaises(attest.Refused) as caught:     # never a TypeError, never another spelling
                self.v.challenge("site-a", EK_PUB, self.other_pub, replace=True, ak_name=spelling)
            self.assertIn("must be 68 lowercase hex", str(caught.exception))
        self.assertEqual(len(self.secrets), made)
        self.v.challenge("site-a", EK_PUB, self.other_pub, replace=True, ak_name=manifest_ak)
        self.assertEqual(self.secrets[-1][0], manifest_ak)
        self.assertEqual(self.v.enroll("site-a", self.secrets[-1][1]).hex(), manifest_ak)

    def test_enroll_refuses_an_ak_the_manifest_no_longer_names(self):
        """regalia-kms-1e on #272: the manifest moved between the challenge and the answer."""
        before = attest.ak_identity(self.other_pub)[0].hex()
        self.v.challenge("site-a", EK_PUB, self.other_pub, replace=True, ak_name=before)
        with self.assertRaises(attest.Refused) as caught:
            self.v.enroll("site-a", self.secrets[-1][1], ak_name=attest.ak_identity(self.ak_pub)[0].hex())
        self.assertIn("not the one the manifest names for this node now", str(caught.exception))
        self.attempt()                                       # the first AK is still the enrolled one

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
        self.assertEqual(verdict, {"node": "site-a", "epoch": EPOCH, "session_id": SESSION.hex(),
                                   "ak_name": attest.ak_identity(self.ak_pub)[0].hex(), "reset_count": 3,
                                   "restart_count": 1, "clock": 42, "clock_safe": True, "pcrs": [0, 7],
                                   "measurement": "", "phase": None})   # the one-set form has no label, and no phase
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

    # ---- CURRENT and NEXT: one or two accepted measurement sets (#75) ----

    def staged(self, *sets):
        """The verifier with site-a's policy replaced by `sets` of (label, firmware, pcrs); the AK stays enrolled."""
        self.policy["nodes"]["site-a"] = {"ek_name": self.ek_name.hex(), "accepted": [
            {"label": label, "tpm_firmware_version": fw, "pcrs": dict(pcrs)} for label, fw, pcrs in sets]}
        self.v = self.verifier()

    def measurement(self):
        with open(os.path.join(self.d, "state.json")) as f:
            return json.load(f)["nodes"]["site-a"].get("measurement")

    def test_during_an_update_either_accepted_set_passes_and_the_verdict_names_it(self):
        self.staged(("image-1", FW, PCRS), ("image-2", FW, NEXT_PCRS))
        self.assertEqual(self.attempt()["measurement"], "image-1")
        self.assertEqual(self.measurement(), {"label": "image-1", "epoch": EPOCH, "phase": None})
        # the same node after its update: a new boot, the NEXT image
        verdict = self.attempt(session=b"T" * 32, key=b"k2", reset=2, digest=attest.expected_pcr_digest(NEXT_PCRS))
        self.assertEqual(verdict["measurement"], "image-2")
        self.assertEqual(self.measurement(), {"label": "image-2", "epoch": EPOCH, "phase": None})
        # and a node that fell back to CURRENT is still accepted while both are approved
        self.assertEqual(self.attempt(session=b"U" * 32, key=b"k3", reset=3)["measurement"], "image-1")

    def test_an_image_in_neither_set_is_refused_and_leaves_the_record_alone(self):
        self.staged(("image-1", FW, PCRS), ("image-2", FW, NEXT_PCRS))
        self.attempt()
        self.refused("none of the accepted measurement sets (image-1, image-2)", digest=hashlib.sha256(b"image 3").digest())
        self.assertEqual(self.measurement(), {"label": "image-1", "epoch": EPOCH, "phase": None})

    def test_after_retirement_the_old_image_is_refused(self):
        self.staged(("image-1", FW, PCRS), ("image-2", FW, NEXT_PCRS))
        self.attempt()
        self.staged(("image-2", FW, NEXT_PCRS))
        self.refused("not the expected PCR values")                      # CURRENT, now retired
        self.assertEqual(self.attempt(digest=attest.expected_pcr_digest(NEXT_PCRS))["measurement"], "image-2")

    def test_a_tpm_firmware_update_is_staged_the_same_way(self):
        newer = "2026010100000001"
        self.staged(("fw-2019", FW, PCRS), ("fw-2026", newer, PCRS))
        self.assertEqual(self.attempt()["measurement"], "fw-2019")
        self.assertEqual(self.attempt(firmware=newer)["measurement"], "fw-2026")
        self.refused("firmware version 2019102300163637 is not the recorded %s or %s" % (FW, newer), firmware="2019102300163637")

    def test_a_set_must_match_whole_not_one_half_from_each(self):
        """NEXT's PCRs under CURRENT's TPM firmware is a combination nobody approved."""
        newer = "2026010100000001"
        self.staged(("old", FW, PCRS), ("new", newer, NEXT_PCRS))
        self.refused("firmware version %s is not the recorded %s" % (FW, newer), digest=attest.expected_pcr_digest(NEXT_PCRS))
        self.refused("firmware version %s is not the recorded %s" % (newer, FW), firmware=newer)
        self.assertEqual(self.attempt(digest=attest.expected_pcr_digest(NEXT_PCRS), firmware=newer)["measurement"], "new")

    def test_the_accepted_list_is_one_or_two_distinct_sets_over_one_selection(self):
        def policy(sets):
            return {"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": {"ek_name": self.ek_name.hex(), "accepted": sets}}}

        def one(label="a", fw=FW, pcrs=PCRS):
            return {"label": label, "tpm_firmware_version": fw, "pcrs": dict(pcrs)}
        attest.validate_policy(policy([one()]))
        attest.validate_policy(policy([one(), one("b", pcrs=NEXT_PCRS)]))
        cases = (
            ("no set", "one or two measurement sets", []),
            ("three sets", "one or two measurement sets", [one(), one("b", pcrs=NEXT_PCRS), one("c", fw="0" * 16)]),
            ("not a list", "one or two measurement sets", one()),
            ("one label twice", "share the label", [one(), one(pcrs=NEXT_PCRS)]),
            ("the same measurements twice", "the same measurements under two labels", [one(), one("b")]),
            ("two PCR selections", "select different PCRs", [one(), one("b", pcrs={"0": "11" * 32})]),
            ("a label with a space", "short plain name", [one("image 1")]),
            ("an empty label", "short plain name", [one("")]),
            ("a set with an extra field", "fields mismatch", [dict(one(), note="x")]),
            ("a set with no PCRs", "at least one PCR", [one(pcrs={})]),
            ("an uppercase PCR value", "64 lowercase hex", [one(pcrs={"0": "AA" * 32})]),
        )
        for label, reason, sets in cases:
            with self.subTest(label):
                with self.assertRaises(attest.Refused) as caught:
                    attest.validate_policy(policy(sets))
                self.assertIn(reason, str(caught.exception))
        # both forms on one node is neither form
        mixed = policy([one()])
        mixed["nodes"]["site-a"].update(tpm_firmware_version=FW, pcrs=dict(PCRS))
        with self.assertRaises(attest.Refused) as caught:
            attest.validate_policy(mixed)
        self.assertIn("fields mismatch", str(caught.exception))

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

    def test_the_one_session_is_retried_in_its_boot_with_a_fresh_nonce_each_time(self):
        """Phase 7: the initramfs keeps one session and asks B and C, at once and again later. Here peer B
        is down at first, so C is asked, twice; B answers when it is back. Each peer keeps its own state."""
        peer_b = self.v
        self.v = peer_c = attest.Verifier(self.policy, os.path.join(self.d, "c.json"), now=lambda: self.clock[0], run=self.run_tool)
        self.enroll()
        first, second = peer_c.nonce("site-a"), peer_c.nonce("site-a")   # two requests outstanding at once
        self.attempt(nonce=second, clock=200)
        self.attempt(nonce=first, clock=100)    # the earlier quote arrives last: still this boot's session
        self.refused("nonce is not outstanding", nonce=first, clock=300)
        for clock in (400, 500, 600):
            self.attempt(clock=clock)
        self.refused("second boot session in the same boot", session=b"T" * 32, key=b"k2", clock=700)
        self.v = peer_b
        self.attempt(clock=800)                 # B is back, later in the same boot: same session, its own nonce
        self.refused("second boot session in the same boot", session=b"T" * 32, key=b"k2", clock=900)

    def test_a_session_never_outlives_a_reboot(self):
        self.attempt(reset=1)
        self.refused("from an earlier boot", reset=2)
        self.refused("from an earlier boot", reset=2, session=b"T" * 32)   # a new session ID, the old ephemeral key
        self.refused("from an earlier boot", restart=1, key=b"k2")         # resume counts as a new boot too
        self.attempt(reset=2, session=b"T" * 32, key=b"k2")
        self.attempt(reset=3, session=b"U" * 32, key=b"k3")
        self.refused("from an earlier boot", reset=4)   # and the first boot's session is still remembered

    def test_no_accepted_session_is_ever_forgotten(self):
        self.attempt(reset=1)
        for boot in range(2, 80):
            self.attempt(reset=boot, session=hashlib.sha256(b"s%d" % boot).digest(), key=b"k%d" % boot)
        self.refused("from an earlier boot", reset=80)
        self.refused("from an earlier boot", reset=80, session=b"T" * 32)
        self.refused("from an earlier boot", reset=80, key=b"k80")

    def test_a_full_state_refuses_and_stays_readable(self):
        self.attempt(reset=1)
        path = os.path.join(self.d, "state.json")
        with open(path, "rb") as f:
            before = f.read()
        with mock.patch.object(attest, "STATE_MAX_BYTES", len(before) + 10):
            with self.assertRaises(attest.Refused) as caught:
                self.v.nonce("site-a")
            self.assertIn("state is full", str(caught.exception))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), before)
        self.attempt(reset=1)

    def test_asking_for_nonces_cannot_fill_the_state_and_the_newest_stay_valid(self):
        nonces = [self.v.nonce("site-a") for _ in range(50)]
        with open(os.path.join(self.d, "state.json")) as f:
            self.assertEqual(len(json.load(f)["nonces"]), attest.MAX_OUTSTANDING)
        self.refused("nonce is not outstanding", nonce=nonces[0])
        self.refused("nonce is not outstanding", nonce=nonces[-attest.MAX_OUTSTANDING - 1])
        self.attempt(nonce=nonces[-attest.MAX_OUTSTANDING])
        self.attempt(nonce=nonces[-1])

    def test_the_state_is_synced_file_then_directory_before_a_verdict(self):
        synced = []
        real = os.fsync
        with mock.patch.object(attest.os, "fsync", side_effect=lambda fd: (synced.append(os.path.isdir("/proc/self/fd/%d" % fd)), real(fd))[1]):
            self.v.nonce("site-a")
        self.assertEqual(synced, [False, True])

    def test_an_unsafe_clock_is_reported_and_does_not_block_a_node_after_a_power_loss(self):
        self.assertFalse(self.attempt(safe=0)["clock_safe"])

    def test_counters_never_go_backwards(self):
        self.attempt(reset=5, restart=2)
        self.refused("counters went backwards ([4, 9] after [5, 2])", reset=4, restart=9, session=b"T" * 32, key=b"k2")
        self.refused("counters went backwards", reset=5, restart=1, session=b"T" * 32, key=b"k2")
        self.attempt(reset=5, restart=2)

    def test_a_refused_quote_does_not_advance_the_counters(self):
        self.attempt(reset=1)
        self.refused("not the expected PCR values", reset=9, session=b"T" * 32, key=b"k2", digest=b"\x00" * 32)
        self.attempt(reset=2, session=b"T" * 32, key=b"k2")


    # ---- PCR values per boot phase (#57, #156): one image, two PCR 11 values, each request accepted from one only ----

    IMAGE1 = {"initrd": {"11": "a1" * 32}, "system": {"11": "a2" * 32}}
    IMAGE2 = {"initrd": {"11": "b1" * 32}, "system": {"11": "b2" * 32}}

    @staticmethod
    def one(label, phases, pcrs=PCRS, fw=FW):
        entry = {"label": label, "tpm_firmware_version": fw, "pcrs": dict(pcrs)}
        return dict(entry, phases={k: dict(v) for k, v in phases.items()}) if phases else entry

    def phased(self, *sets):
        self.policy["nodes"]["site-a"] = {"ek_name": self.ek_name.hex(), "accepted": list(sets)}
        self.v = self.verifier()

    def fresh(self, **kw):
        """A new boot: its own session, ephemeral key and reset count."""
        self.boots = getattr(self, "boots", 0) + 1
        return dict(session=bytes([self.boots]) * 32, key=b"key %d" % self.boots, reset=self.boots, **kw)

    def boot(self, image, phase):
        """A quote from `image` in `phase`, over PCRs 0, 7 and 11."""
        return self.fresh(pcrs=(0, 7, 11), digest=attest.expected_pcr_digest(dict(PCRS, **image[phase])))

    def test_each_phase_of_an_image_is_accepted_for_its_own_request_only(self):
        self.phased(self.one("image-1", self.IMAGE1))
        verdict = self.attempt(phase="initrd", **self.boot(self.IMAGE1, "initrd"))
        self.assertEqual((verdict["measurement"], verdict["phase"], verdict["pcrs"]), ("image-1", "initrd", [0, 7, 11]))
        self.assertEqual(self.attempt(phase="system", **self.boot(self.IMAGE1, "system"))["phase"], "system")
        # the booted system asks for what only an initrd gets (a disk key), and the reverse (a lease)
        self.refused("the node is in the system phase of image-1; this request is accepted only from the initrd phase",
                     phase="initrd", **self.boot(self.IMAGE1, "system"))
        self.refused("the node is in the initrd phase of image-1; this request is accepted only from the system phase",
                     phase="system", **self.boot(self.IMAGE1, "initrd"))
        # another image is refused as before, in either phase
        for phase in attest.PHASES:
            self.refused("the quoted PCR digest is not the expected PCR values", phase=phase, **self.boot(self.IMAGE2, phase))
        # a quote that leaves PCR 11 out does not pass on the other PCRs
        self.refused("the quote covers PCRs [0, 7], not the expected [0, 7, 11]", phase="initrd")

    def test_a_refused_phase_leaves_the_record_alone(self):
        self.phased(self.one("image-1", self.IMAGE1), self.one("image-2", self.IMAGE2))
        self.attempt(phase="initrd", **self.boot(self.IMAGE1, "initrd"))
        self.assertEqual(self.measurement(), {"label": "image-1", "epoch": EPOCH, "phase": "initrd"})
        self.refused("the node is in the system phase of image-2", phase="initrd", **self.boot(self.IMAGE2, "system"))
        self.assertEqual(self.measurement(), {"label": "image-1", "epoch": EPOCH, "phase": "initrd"})
        # the record says in which phase the node was last seen: asking for its disk is not being up (rollout.py)
        self.attempt(phase="system", **self.boot(self.IMAGE1, "system"))
        self.assertEqual(self.measurement(), {"label": "image-1", "epoch": EPOCH, "phase": "system"})

    def test_per_phase_sets_refuse_a_verification_that_names_no_phase(self):
        self.phased(self.one("image-1", self.IMAGE1))
        self.refused("the accepted measurements of site-a are per boot phase (image-1): the verification must name the phase",
                     **self.boot(self.IMAGE1, "initrd"))
        for bad in ("boot", "", 1, ["initrd"]):
            with self.subTest(phase=bad), self.assertRaises(attest.Refused) as caught:
                self.v.verify("site-a", EPOCH, SESSION, KEY, bytes(32), b"q", b"s", phase=bad)
            self.assertIn("the phase must be one of initrd, system", str(caught.exception))
        # the refusal comes before the nonce is looked at: the node's nonce is not burnt by a caller's mistake
        nonce = self.v.nonce("site-a")
        with self.assertRaises(attest.Refused):
            self.v.verify("site-a", EPOCH, SESSION, KEY, nonce, b"q", b"s")
        self.attempt(nonce=nonce, phase="initrd", **self.boot(self.IMAGE1, "initrd"))

    def test_another_phase_under_another_firmware_set_is_still_called_a_wrong_phase(self):
        """Two sets may share a PCR state when their TPM firmware differs. A's initrd quote asking for a lease
        then matches B's system values and not B's firmware: the refusal is the phase, not the firmware."""
        newer = "2026010100000001"
        shared = {"11": "ab" * 32}
        self.phased(self.one("old-fw", {"initrd": shared, "system": {"11": "a2" * 32}}),
                    self.one("new-fw", {"initrd": {"11": "b1" * 32}, "system": shared}, fw=newer))
        quote = self.fresh(pcrs=(0, 7, 11), digest=attest.expected_pcr_digest(dict(PCRS, **shared)))
        self.refused("the node is in the initrd phase of old-fw; this request is accepted only from the system phase", phase="system", **quote)
        self.assertEqual(self.attempt(phase="initrd", **self.fresh(pcrs=(0, 7, 11), digest=quote["digest"]))["measurement"], "old-fw")
        self.assertEqual(self.attempt(phase="system", firmware=newer, **self.fresh(pcrs=(0, 7, 11), digest=quote["digest"]))["measurement"], "new-fw")
        # a firmware that is neither set's is still a firmware refusal
        self.refused("the TPM firmware version 2019102300163637 is not the recorded", phase="system", firmware="2019102300163637",
                     **self.fresh(pcrs=(0, 7, 11), digest=quote["digest"]))

    def test_a_set_with_one_value_per_pcr_is_judged_the_same_in_any_phase(self):
        """A host that does not boot a UKI: its PCR 11 never moves. Naming the phase changes nothing."""
        self.phased(self.one("grub", None))
        for phase in (None, "initrd", "system"):
            self.assertEqual(self.attempt(phase=phase, **self.fresh())["phase"], None)

    def test_the_move_to_a_uki_is_a_rollout_like_any_other(self):
        """CURRENT gives PCR 11 once (it stays zero under GRUB), NEXT gives it per phase: one selection."""
        grub = self.one("grub", None, pcrs=dict(PCRS, **{"11": "00" * 32}))
        self.phased(grub, self.one("uki", self.IMAGE2))
        zero = dict(pcrs=(0, 7, 11), digest=attest.expected_pcr_digest(dict(PCRS, **{"11": "00" * 32})))
        for phase in attest.PHASES:
            self.assertEqual(self.attempt(phase=phase, **self.fresh(**zero))["measurement"], "grub")
            verdict = self.attempt(phase=phase, **self.boot(self.IMAGE2, phase))
            self.assertEqual((verdict["measurement"], verdict["phase"]), ("uki", phase))
        self.refused("the node is in the system phase of uki", phase="initrd", **self.boot(self.IMAGE2, "system"))

    def test_a_signed_images_set_may_name_its_signing_keys(self):
        """#190/#265: the keys a signed image's PCR policy and Secure Boot signature are made with, by fingerprint, so
        that whoever seals to a PCR-signing key takes only one the approved set names. Peers never read them."""
        def policy(*sets):
            return {"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": {"ek_name": self.ek_name.hex(), "accepted": list(sets)}}}
        signing = {"initrd": "1a" * 32, "system": "5b" * 32, "secure_boot_cert": "5c" * 32}
        root = "6e" * 32
        attest.validate_policy(policy(dict(self.one("a", self.IMAGE1), signing=signing, rootfs_sha256=root)))
        # ... and the root filesystem it is installed with (#61): required with "signing", allowed nowhere else. No PCR
        # covers it, so two sets that differ only there cannot be told apart by a quote: the same measurements
        roots = (
            ("a signed set naming no root", "a signed image's set must name its root filesystem",
             dict(self.one("a", self.IMAGE1), signing=signing)),
            ("a root not hex", "rootfs_sha256 must be 64 lowercase hex", dict(self.one("a", self.IMAGE1), signing=signing, rootfs_sha256="6E" * 32)),
            ("a root too short", "rootfs_sha256 must be 64 lowercase hex", dict(self.one("a", self.IMAGE1), signing=signing, rootfs_sha256="6e" * 31)),
            ("a root not a string", "rootfs_sha256 must be 64 lowercase hex", dict(self.one("a", self.IMAGE1), signing=signing, rootfs_sha256=None)),
            ("a root on an unsigned set", "only a signed image's set (one that names its signing keys) names its root filesystem",
             dict(self.one("a", self.IMAGE1), rootfs_sha256=root)),
            ("a root on a set with no per-phase PCR 11", "only a signed image's set (one that names its signing keys) names its root",
             dict(self.one("a", None), rootfs_sha256=root)),
        )
        for label, reason, entry in roots:
            with self.subTest(label), self.assertRaises(attest.Refused) as caught:
                attest.validate_policy(policy(entry))
            self.assertIn(reason, str(caught.exception))
        with self.assertRaises(attest.Refused) as caught:
            attest.validate_policy(policy(dict(self.one("a", self.IMAGE1), signing=signing, rootfs_sha256=root),
                                          dict(self.one("b", self.IMAGE1), signing=signing, rootfs_sha256="7f" * 32)))
        self.assertIn("the two sets are the same measurements under two labels", str(caught.exception))
        cases = (
            ("a field missing", "signing fields mismatch", dict(self.one("a", self.IMAGE1), signing={"initrd": "1a" * 32, "system": "5b" * 32})),
            ("a field more", "signing fields mismatch", dict(self.one("a", self.IMAGE1), signing=dict(signing, pcrpkey="77" * 32))),
            ("not hex", "signing.system must be 64 lowercase hex", dict(self.one("a", self.IMAGE1), signing=dict(signing, system="5B" * 32))),
            ("one key for both phases", "the two phases' PCR keys must be two keys",
             dict(self.one("a", self.IMAGE1), signing=dict(signing, system="1a" * 32))),
            ("not an object", "signing must be an object", dict(self.one("a", self.IMAGE1), signing=[])),
            ("on a set with no per-phase PCR 11", "only a set with per-phase PCR 11", dict(self.one("a", None), signing=signing)),
        )
        for label, reason, entry in cases:
            with self.subTest(label), self.assertRaises(attest.Refused) as caught:
                attest.validate_policy(policy(entry))
            self.assertIn(reason, str(caught.exception))

    def test_what_a_per_phase_set_may_hold(self):
        def policy(*sets):
            return {"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": {"ek_name": self.ek_name.hex(), "accepted": list(sets)}}}
        one = self.one
        attest.validate_policy(policy(one("a", self.IMAGE1)))
        attest.validate_policy(policy(one("a", self.IMAGE1), one("b", self.IMAGE2)))
        self.assertEqual(attest.selection(one("a", self.IMAGE1)), [0, 7, 11])
        self.assertEqual(attest.values(one("a", self.IMAGE1), "system"), dict(PCRS, **{"11": "a2" * 32}))
        swapped = {"initrd": self.IMAGE1["system"], "system": self.IMAGE1["initrd"]}
        cases = (
            ("one phase only", "phases fields mismatch", [one("a", {"initrd": {"11": "a1" * 32}})]),
            ("a third phase", "phases fields mismatch", [one("a", dict(self.IMAGE1, shutdown={"11": "a3" * 32}))]),
            ("phases that is not an object", "phases must be an object", [dict(one("a", None), phases=[])]),
            ("a phase with no PCR", "phases.initrd must expect at least one PCR", [one("a", {"initrd": {}, "system": {"11": "a2" * 32}})]),
            ("a phase value that is not hex", "phases.system.11 must be 64 lowercase hex", [one("a", {"initrd": {"11": "a1" * 32}, "system": {"11": "A2" * 32}})]),
            ("a PCR that is no PCR", "phases.initrd: '24' is not a PCR 0-23", [one("a", {"initrd": {"24": "a1" * 32}, "system": {"24": "a2" * 32}})]),
            ("the phases give different PCRs", "the two phases give different PCRs", [one("a", {"initrd": {"11": "a1" * 32}, "system": {"12": "a2" * 32}})]),
            ("a PCR given once and per phase", "PCR 7 is given once for every phase and again per phase",
             [one("a", {"initrd": {"7": "a1" * 32}, "system": {"7": "a2" * 32}})]),
            ("both phases the same", "the two phases hold the same values", [one("a", {"initrd": {"11": "a1" * 32}, "system": {"11": "a1" * 32}})]),
            ("two sets, one without PCR 11", "select different PCRs", [one("a", None), one("b", self.IMAGE2)]),
            ("the same per-phase measurements twice", "the same measurements under two labels", [one("a", self.IMAGE1), one("b", self.IMAGE1)]),
            ("one image's initrd value is the other's system value", "'a' and 'b' hold the same PCR values in one of their phases",
             [one("a", self.IMAGE1), one("b", {"initrd": {"11": "a2" * 32}, "system": {"11": "b2" * 32}})]),
            ("the same image with its phases swapped", "'a' and 'b' hold the same PCR values in one of their phases", [one("a", self.IMAGE1), one("b", swapped)]),
            ("a one-value set equal to a phase of the other", "'a' and 'b' hold the same PCR values in one of their phases",
             [one("a", None, pcrs=dict(PCRS, **{"11": "b1" * 32})), one("b", self.IMAGE2)]),
        )
        for label, reason, sets in cases:
            with self.subTest(label), self.assertRaises(attest.Refused) as caught:
                attest.validate_policy(policy(*sets))
            self.assertIn(reason, str(caught.exception))
        # the one-set form (the fields beside the EK) has no phases
        flat = {"schema": attest.POLICY_SCHEMA, "nodes": {"site-a": dict(one("", self.IMAGE1), ek_name=self.ek_name.hex())}}
        del flat["nodes"]["site-a"]["label"]
        with self.assertRaises(attest.Refused) as caught:
            attest.validate_policy(flat)
        self.assertIn("fields mismatch", str(caught.exception))


class ReportedValues(Verification):
    """Protocol v2: the node sends its PCR values beside the quote. They are used only once they hash to the
    quoted digest under the verifier's selection, and then only to name each PCR that differs."""

    def test_values_that_match_the_quote_name_every_differing_pcr(self):
        other = {"0": "11" * 32, "7": "99" * 32}
        digest = attest.expected_pcr_digest(other)
        with self.assertRaises(attest.Refused) as caught:
            self.attempt(digest=digest, pcr_values=dict(other))
        self.assertEqual(str(caught.exception), "the quoted PCR digest is not the expected PCR values. the set: PCR 7 is %s, expected %s"
                         % ("99" * 32, "77" * 32))
        # two sets, two PCRs off in one of them: each set named, PCRs in index order
        self.staged(("image-1", FW, PCRS), ("image-2", FW, NEXT_PCRS))
        third = {"0": "10" * 32, "7": "99" * 32}
        with self.assertRaises(attest.Refused) as caught:
            self.attempt(digest=attest.expected_pcr_digest(third), pcr_values=dict(third), session=b"T" * 32, key=b"k2", reset=2)
        self.assertEqual(str(caught.exception), "the quoted PCR digest is none of the accepted measurement sets (image-1, image-2). "
                         "image-1: PCR 0 is %s, expected %s; PCR 7 is %s, expected %s | image-2: PCR 0 is %s, expected %s; PCR 7 is %s, expected %s"
                         % ("10" * 32, "11" * 32, "99" * 32, "77" * 32, "10" * 32, "11" * 32, "99" * 32, "88" * 32))

    def test_the_whole_refusal_reaches_the_audit_trail(self):
        """The names are for the operator: a two-set, two-PCR refusal must reach the audit event whole, not cut
        at the 240 characters a name is allowed (convergence.audited, regalia-kms-24's read)."""
        from deploy.baremetal import convergence
        self.staged(("image-1", FW, PCRS), ("image-2", FW, NEXT_PCRS))
        third = {"0": "10" * 32, "7": "99" * 32}
        events = []
        def decide():                       # as lease.reattest hands an attestation refusal on
            try:
                self.attempt(digest=attest.expected_pcr_digest(third), pcr_values=dict(third))
            except attest.Refused as refusal:
                raise m.Refused("the subject's attestation is refused: %s" % refusal)
        with self.assertRaises(m.Refused) as caught:
            convergence.audited(events.append, "unlock", None, "site-a", "b", decide)
        self.assertGreater(len(str(caught.exception)), 240)
        self.assertEqual(events[-1]["outcome"], "DENY")
        self.assertEqual(events[-1]["reason"], str(caught.exception))
        self.assertTrue(events[-1]["reason"].endswith("image-2: PCR 0 is %s, expected %s; PCR 7 is %s, expected %s"
                                                       % ("10" * 32, "11" * 32, "99" * 32, "88" * 32)))
        # names stay short, and a reason is still one printable line, and still bounded
        self.assertEqual(len(convergence._printable("x" * 1000)), 240)
        self.assertEqual(len(convergence._printable("x" * 10000, m.REASON_LIMIT)), 4096)
        self.assertEqual(convergence._printable("a\nb\x1b[31m"), "a?b?[31m")

    def test_values_that_do_not_match_the_quote_are_refused_and_never_used(self):
        tampered = dict(PCRS, **{"7": "78" * 32})                   # the quote is of PCRS, the values say otherwise
        self.refused("the reported PCR values do not match the quote", pcr_values=tampered)
        self.refused("the reported PCR values cover PCRs ['0', '7', '8'], not the quoted selection [0, 7]",
                     pcr_values=dict(PCRS, **{"8": "00" * 32}))     # a PCR outside the selection
        self.refused("the reported PCR values cover PCRs ['7'], not the quoted selection [0, 7]", pcr_values={"7": "77" * 32})   # one missing
        for bad in ({"0": "11" * 32, "7": "77" * 31}, {"0": "11" * 32, "7": "AA" * 32}, {0: "11" * 32, "7": "77" * 32}, ["11" * 32], "x"):
            with self.subTest(bad=str(bad)[:20]):
                self.refused("must map PCR indices to 64 lowercase hex", pcr_values=bad)
        self.refused("cover PCRs ['7', '00']", pcr_values={"00": "11" * 32, "7": "77" * 32})   # an index in another spelling

    def test_matching_values_change_nothing_on_an_accepted_quote_and_v1_is_as_before(self):
        verdict = self.attempt(pcr_values=dict(PCRS))
        self.assertEqual(verdict["measurement"], "")
        with self.assertRaises(attest.Refused) as caught:
            self.attempt(digest=attest.expected_pcr_digest({"0": "11" * 32, "7": "99" * 32}), session=b"T" * 32, key=b"k2", reset=2)
        self.assertEqual(str(caught.exception), "the quoted PCR digest is not the expected PCR values")      # v1: no values, no names

    def test_per_phase_sets_are_named_with_their_phase(self):
        self.policy["nodes"]["site-a"] = {"ek_name": self.ek_name.hex(), "accepted": [
            {"label": "uki-1", "tpm_firmware_version": FW, "pcrs": dict(PCRS), "phases": {"initrd": {"11": "a1" * 32}, "system": {"11": "a2" * 32}}}]}
        self.v = self.verifier()
        got = dict(PCRS, **{"11": "a9" * 32})
        with self.assertRaises(attest.Refused) as caught:
            self.attempt(pcrs=(0, 7, 11), digest=attest.expected_pcr_digest(got), pcr_values=got, phase="initrd")
        self.assertEqual(str(caught.exception), "the quoted PCR digest is not the expected PCR values. uki-1 (initrd phase): PCR 11 is %s, expected %s"
                         % ("a9" * 32, "a1" * 32))


class ReportedValuesVector(unittest.TestCase):
    """tests/vectors/pcr-values-v2.json, the vector the Go client's test reads too: a real quote from a software
    TPM and the values read beside it. The verifier takes those values, and refuses each case the vector
    lists with the very reason it records, so the two sides of the exchange agree on one file. The reasons were
    written by check_reported_values itself when the vector was made: they pin today's wording against drift,
    they are not an outside oracle. The independent part is the real swtpm quote and the values read beside it."""

    def setUp(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "pcr-values-v2.json")
        with open(path) as f:
            self.vector = json.load(f)
        self.quote = attest.parse_quote(bytes.fromhex(self.vector["quote"]))

    def test_the_quote_selects_and_digests_what_the_vector_says(self):
        self.assertEqual(self.quote["pcrs"], self.vector["selection"])
        self.assertEqual(self.quote["pcr_digest"].hex(), self.vector["pcr_digest"])

    def test_the_values_read_beside_the_quote_are_taken(self):
        values = self.vector["pcr_values"]
        self.assertEqual(attest.check_reported_values(values, self.quote["pcrs"], self.quote["pcr_digest"]), values)
        self.assertIsNone(attest.check_reported_values(None, self.quote["pcrs"], self.quote["pcr_digest"]))

    def test_every_refused_case_is_refused_with_the_reason_the_vector_records(self):
        self.assertEqual(sorted(self.vector["refused"]), ["another_spelling", "malformed", "missing", "outside_the_selection", "tampered"])
        for name, case in self.vector["refused"].items():
            with self.subTest(name), self.assertRaises(attest.Refused) as refused:
                attest.check_reported_values(case["pcr_values"], self.quote["pcrs"], self.quote["pcr_digest"])
            self.assertEqual(str(refused.exception), case["reason"])


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

    def test_transient_objects_are_flushed_globally_only_on_a_private_simulator(self):
        for tcti, flushed in (("swtpm:path=/x", True), ("mssim:port=1", True), ("device:/dev/tpmrm0", False), (None, False)):
            with self.subTest(tcti=tcti), mock.patch.dict(os.environ):
                os.environ.pop("TPM2TOOLS_TCTI", None)
                if tcti:
                    os.environ["TPM2TOOLS_TCTI"] = tcti
                self.calls = []
                attest.node_init(self.d, run=self.run_tool)
                self.assertEqual([c[0] for c in self.calls][:3], ["tpm2_createek", "tpm2_createak", "tpm2_evictcontrol"])
                self.assertEqual(["tpm2_flushcontext", "-t"] in self.calls, flushed)

    def test_a_bad_pcr_list_or_a_tpm_failure_is_a_refusal(self):
        for pcrs in ([], [24], [-1], ["7"]):
            with self.subTest(pcrs=pcrs):
                self.refused("PCRs must be 0-23", attest.node_quote, "site-a", EPOCH, SESSION, KEY, b"N" * 32, pcrs, "q", "s")
        self.assertEqual(self.calls, [])
        self.failing = ("tpm2_quote",)
        self.refused("tpm2_quote failed: the TPM said no", attest.node_quote, "site-a", EPOCH, SESSION, KEY, b"N" * 32, [7], "q", "s")

    def test_a_failed_activation_is_a_refusal_and_the_session_is_still_flushed(self):
        self.failing = ("tpm2_activatecredential",)
        secret = os.path.join(self.d, "secret")
        self.refused("does not hold the EK and AK", attest.node_activate, "cred", secret)
        self.assertFalse(os.path.exists(secret))   # so the same path can be retried

        def absent(argv, **kw):   # the tool cannot even be started
            if argv[0] == "tpm2_activatecredential":
                raise FileNotFoundError(argv[0])
            return self.run_tool(argv, **kw)
        with self.assertRaises(FileNotFoundError):
            attest.node_activate("cred", secret, run=absent)
        self.assertFalse(os.path.exists(secret))
        self.assertEqual(self.calls[-1][0], "tpm2_flushcontext")
        self.calls = self.calls[:4]
        self.failing = ()
        attest.node_activate("cred", secret, run=self.run_tool)
        self.assertEqual(os.stat(secret).st_mode & 0o777, 0o600)
        self.calls = self.calls[:4]
        self.assertEqual(" ".join(c[0][len("tpm2_"):] for c in self.calls),
                         "startauthsession policysecret activatecredential flushcontext")

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


class QuoteLabels(unittest.TestCase):
    """#399 (regalia-kms-d9): every purpose a node's AK quotes for has its own label, so a quote made for one never
    verifies for another by construction, not by every reader checking a schema. (The identity's qualifying data also
    has a third field, the challenge secret's hash, so it could not equal a record's even under one label: the label
    is the structural guard, the field count a second one.)"""

    def test_the_labels_are_distinct(self):
        labels = [attest.TRANSCRIPT_LABEL, attest.BINDING_LABEL, attest.RECORD_LABEL, attest.IDENTITY_LABEL]
        self.assertEqual(len(set(labels)), len(labels), labels)

    def test_an_identity_is_bound_to_its_challenge(self):
        payload = b'{"schema":"regalia.enrol-identity/v1"}'
        one, two = attest.identity_qualifying(payload, b"\x01" * 32), attest.identity_qualifying(payload, b"\x02" * 32)
        self.assertNotEqual(one, two)
        self.assertNotEqual(one, attest.record_qualifying(payload))
        with self.assertRaisesRegex(attest.Refused, "the challenge secret's SHA-256 is 32 bytes"):
            attest.identity_qualifying(payload, b"\x01" * 31)


if __name__ == "__main__":
    unittest.main()
