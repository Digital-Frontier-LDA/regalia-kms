"""deploy/baremetal/anchorpolicy.py (#361): every Name and policy digest, recomputed without a TPM, equal to the TPM's
own (tests/vectors/anchor-policy-v1.json, measured on swtpm by tests/vectors/make-anchor-policy-v1.py)."""
import json
import os
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

    def test_classes_never_share_a_policy(self):
        policies = {ap.class_policy(V["k_a"]["point"], c) for c in ap.REFS}
        self.assertEqual(len(policies), len(ap.REFS))


if __name__ == "__main__":
    unittest.main()
