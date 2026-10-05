"""deploy/baremetal/anchorpolicy.py (#361): every Name and policy digest, recomputed without a TPM, equal to the TPM's
own (tests/vectors/anchor-policy-v1.json, measured on swtpm by tests/vectors/make-anchor-policy-v1.py)."""
import hashlib
import json
import os
import re
import unittest

from deploy.baremetal import anchorpolicy as ap
from deploy.baremetal import membership as m

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "vectors", "anchor-policy-v1.json")) as f:
    V = json.load(f)


class TheTpmsOwnValues(unittest.TestCase):
    def setUp(self):
        self.index = int(V["rotation"]["index"], 16)
        self.rotation = ap.rotation_name(self.index, V["k_a"]["point"])

    def test_k_a_s_name_is_the_one_loadexternal_gives(self):
        self.assertEqual(ap.k_a_name(V["k_a"]["point"]).hex(), V["k_a"]["name"])

    def test_each_class_policy(self):
        self.assertEqual(sorted(V["refs"]), sorted(ap.REFS))
        for cls, want in V["refs"].items():
            with self.subTest(cls=cls):
                self.assertEqual(ap.REFS[cls].hex(), want["policy_ref_hex"])
                self.assertEqual(ap.class_policy(V["k_a"]["point"], cls).hex(), want["auth_policy"])

    def test_the_rotation_counter_s_name_before_and_after_its_first_write(self):
        self.assertEqual(ap.rotation_name(self.index, V["k_a"]["point"], written=False).hex(), V["rotation"]["name_unwritten"])
        self.assertEqual(self.rotation.hex(), V["rotation"]["name_written"])

    def test_the_approved_policies_and_the_increment_approvals(self):
        """G and n are the NODE's: its R starts at the TPM's saved highest count (regalia-kms-95), here 6, not 1."""
        start = V["rotation"]["first_value"]
        self.assertGreater(start, 1)
        self.assertEqual(sorted(V["approved"], key=int), [str(start), str(start + 1)])
        k_sys = bytes.fromhex(V["k_sys"]["name"])
        self.assertEqual(ap.policy_authorize(k_sys, b"").hex(), V["k_sys"]["policy_authorize"])
        for g, want in V["approved"].items():
            with self.subTest(generation=g):
                self.assertEqual(ap.approved(k_sys, self.rotation, int(g)).hex(), want)
        self.assertEqual(ap.increment_first().hex(), V["increment"]["first"])
        for n, want in V["increment"]["from"].items():
            with self.subTest(n=n):
                self.assertEqual(ap.increment_from(self.rotation, int(n)).hex(), want)

    def test_the_k_sys_name_is_signkey_s(self):
        """K_sys is loaded as signkey.py loads the system-phase PCR key: the same Name, so the same PolicyAuthorize."""
        from deploy.baremetal import signkey
        self.assertEqual(signkey.pcr_key_name(V["k_sys"]["pem"].encode()).hex(), V["k_sys"]["name"])


class Regenerated(unittest.TestCase):
    """The committed vectors are what a TPM gives today: regenerated on a private swtpm (fixed public test keys), the
    output is byte-identical, so a vector edited by hand, or a tpm2-tools that computes otherwise, is seen here."""

    def test_the_vectors_regenerate_identically_on_swtpm(self):
        import shutil
        import subprocess
        if not (shutil.which("swtpm") and shutil.which("tpm2_getpolicydigest")):
            if os.environ.get("CI"):
                self.fail("swtpm and tpm2-tools are expected in CI")
            self.skipTest("needs swtpm and tpm2-tools")
        done = subprocess.run(["python3", "-B", os.path.join(HERE, "vectors", "make-anchor-policy-v1.py")], capture_output=True, text=True,
                              timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr[-600:])
        fresh = json.loads(done.stdout)
        fresh.pop("measured_with"), dict(V).pop("measured_with")
        self.assertEqual(fresh, {k: v for k, v in V.items() if k != "measured_with"})


class Refusals(unittest.TestCase):
    def test_bad_inputs_are_refused_by_name(self):
        with self.assertRaisesRegex(m.Refused, "K_A is an uncompressed P-256 point"):
            ap.k_a_name("02" + "11" * 32)
        with self.assertRaisesRegex(m.Refused, "no policy class 'nope'"):
            ap.class_policy(V["k_a"]["point"], "nope")
        with self.assertRaisesRegex(m.Refused, "the generation is a 64-bit count"):
            ap.approved(bytes(34), bytes(34), True)
        with self.assertRaisesRegex(m.Refused, "n is a 64-bit count"):
            ap.increment_from(bytes(34), -1)

    def test_the_anchor_policy_file_is_read_by_name(self):
        """#361 C1: `enrol init --anchor-policy`'s file. K_A's approval of R's first increment is verified under the K_A the
        file names before any TPM is asked; each guard by an input only it refuses."""
        from tests.test_baremetal_enrol import FIRST, K_A_POINT, first_file
        node_id, point, der = ap.read_first(FIRST)
        self.assertEqual((node_id, point), ("a", K_A_POINT))
        with self.assertRaisesRegex(m.Refused, "the anchor-policy file is for node a, not b"):
            ap.read_first(FIRST, "b")
        bad, _ = first_file(0x0BAD)
        sig = FIRST["increment_first"]
        high = "%s%064x" % (sig[:64], m.P256_ORDER - int(sig[64:], 16))              # the high-S twin of a valid signature
        for name, doc, reason in (
                ("another schema", dict(FIRST, schema="x"), "the anchor-policy file is not a regalia.anchor-policy-first/v1"),
                ("an extra field", dict(FIRST, note=1), "the anchor-policy file fields mismatch"),
                ("an Ed25519 K_A", dict(FIRST, anchor_policy_key={"alg": "ed25519", "key": "00" * 32}), "alg must be one of ecdsa-p256"),
                ("another key's signature", dict(FIRST, increment_first=bad["increment_first"]), "increment_first does not verify under the K_A it names"),
                ("the high-S twin", dict(FIRST, increment_first=high), "increment_first is not a low-S P-256 signature"),
                ("a short signature", dict(FIRST, increment_first="ab"), "increment_first is not a P-256 signature (128 lowercase hex"),
                ("not an object", [], "the anchor-policy file is not an object")):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, re.escape(reason)):
                ap.read_first(doc)
        # an approval for another class (the anchor's) does not start R: the TPM would refuse it, and so does this check
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        key = ec.derive_private_key(0x361C1, ec.SECP256R1())
        r, s_ = decode_dss_signature(key.sign(ap.authorize_message(ap.increment_first(), "anchor"), ec.ECDSA(hashes.SHA256())))
        # ... and node b's approval does not start node a's R (per-node classes, #361 issuecomment-5996727713)
        theirs, _ = first_file(node_id="b")
        with self.assertRaisesRegex(m.Refused, "does not verify under the K_A it names"):
            ap.read_first(dict(FIRST, increment_first=theirs["increment_first"]))
        with self.assertRaisesRegex(m.Refused, "does not verify under the K_A it names"):
            ap.read_first(dict(FIRST, increment_first="%064x%064x" % (r, min(s_, m.P256_ORDER - s_))))

    def test_a_failed_read_is_not_absence(self):
        """regalia-kms-95 on #462: nv_name_of returns None only when the TPM's list lacks the index."""
        import subprocess

        def tpm(listed, answers=True):
            def run(argv, **kw):
                if argv[0] == "tpm2_nvreadpublic":
                    return subprocess.CompletedProcess(argv, 1, b"", b"busy")
                return subprocess.CompletedProcess(argv, 0 if answers else 1, b"- 0x1500016\n" + (b"- 0x1500020\n" if listed else b""), b"no TCTI")
            return run
        self.assertIsNone(ap.nv_name_of("0x01500020", tpm(listed=False)))
        with self.assertRaisesRegex(m.Refused, "the TPM lists NV index 0x01500020 and did not give its public area"):
            ap.nv_name_of("0x01500020", tpm(listed=True))
        with self.assertRaisesRegex(m.Refused, "listing the TPM's NV indices \\(the TPM does not answer\\) failed"):
            ap.nv_name_of("0x01500020", tpm(listed=False, answers=False))

    def test_each_node_s_rotation_counter_has_its_own_name(self):
        """#361 (1e, d9, 95): R is defined under PolicyAuthorize(Name(K_A), SHA-256("regalia-rotation/v1\\0" || node_id)), so
        its Name, and every approval naming it, is one node's; the ref is 32 bytes, within any TPM 2.0's TPM2B_NONCE."""
        index, point = int(ap.ROTATION_INDEX, 16), V["k_a"]["point"]
        names = {n: ap.rotation_name(index, point, node_id=n) for n in ("a", "b", "c", "x" * 32)}
        self.assertEqual(len(set(names.values())), 4)
        self.assertNotIn(ap.rotation_name(index, point), names.values())                 # nor the shared class's
        for n in names:
            self.assertEqual(len(ap._ref(ap.rotation_class(n))), 32)
        self.assertEqual(ap._ref("rotation/a"), hashlib.sha256(b"regalia-rotation/v1\x00a").digest())
        k_sys = bytes.fromhex(V["k_sys"]["name"])
        self.assertNotEqual(ap.approved(k_sys, names["a"], 7), ap.approved(k_sys, names["b"], 7))
        for bad in ("A", "", "a" * 33, "a/b", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(m.Refused, "is not a node ID|no policy class"):
                ap.rotation_class(bad) if bad is not None else ap.rotation_class(bad)

    def test_classes_never_share_a_policy(self):
        policies = {ap.class_policy(V["k_a"]["point"], c) for c in ap.REFS}
        self.assertEqual(len(policies), len(ap.REFS))


if __name__ == "__main__":
    unittest.main()
