"""#361 C3 on a real (software) TPM: an object defined under PolicyAuthorize(Name(K_A), its class) is written by the
composite session signkey.policy_session(anchor=...): PolicyPCR(11), PolicyAuthorize(K_sys) with this boot's signature,
PolicyNV(R <= G) on this node's rotation counter, PolicyAuthorize(K_A, class) with K_A's approval for THIS node, class and
G. The approval of another node, class or generation, or an R moved past G (a retire), writes nothing."""
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import signed_boot as sb                       # noqa: E402
from deploy.baremetal import anchorpolicy as ap  # noqa: E402
from deploy.baremetal import membership as m  # noqa: E402
from deploy.baremetal import signkey  # noqa: E402
from tests.test_baremetal_anchor_approvals import K_A, POINT  # noqa: E402
from tests.test_baremetal_enrol import first_file  # noqa: E402
import tests.test_baremetal_policy_writes as pw  # noqa: E402  (the module: its test classes are not run again here)

INDEX = "0x01500030"                             # an object of the "anchor" class, apart from the anchor's own indices


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_policyauthorize") or os.environ.get("REGALIA_EXPECT_SWTPM") == "1",
                     "needs swtpm and tpm2-tools")
class CompositeSession(unittest.TestCase):
    tpm = pw.PolicyWrites.tpm                                  # its swtpm, signed image and boot signatures, not its tests

    def setUp(self):
        pw.PolicyWrites.setUp(self)
        sb.boot(self.image, env=self.env)
        doc, _ = first_file(node_id="a")
        _, point, der = ap.read_first(doc, "a")
        self.r = ap.start_rotation(ap.ROTATION_INDEX, point, der, "a", run=lambda argv, **kw: subprocess.run(argv, env=self.env, **kw))
        policy = self.d + "/anchor.pol"
        with open(policy, "wb") as f:
            f.write(ap.class_policy(POINT, "anchor"))
        self.assertEqual(self.tpm("nvdefine", INDEX, "-C", "o", "-s", "8", "-a", "nt=counter|policywrite|ownerwrite|authread|ownerread",
                                  "-L", policy).returncode, 0)

    def approval(self, node_id="a", cls="anchor", generation=None):
        g = self.r["value"] if generation is None else generation
        policy = ap.approved_for(self.pem, POINT, g, node_id)
        return {"k_a": POINT, "node_id": node_id, "generation": g, "class": cls, "signature": ap.sign(K_A, policy, cls)}

    def increment(self, anchor):
        with signkey.policy_session(self.pem, self.tcti, signatures=self.signatures, anchor=anchor) as session:
            return self.tpm("nvincrement", INDEX, "-C", INDEX, "-P", "session:" + session)

    def test_the_approved_image_writes_under_k_a_with_no_owner(self):
        self.assertEqual(self.increment(self.approval()).returncode, 0)
        self.assertEqual(self.increment(self.approval(generation=self.r["value"] + 5)).returncode, 0)   # R <= a higher G: still fine

    def test_another_node_class_or_g_writes_nothing(self):
        """Refused in software before the TPM is asked: K_A's approval is checked over THIS node's R, class and G."""
        good = self.approval()
        for name, anchor in (("node b's approval", dict(self.approval(node_id="b"), node_id="a")),
                             ("the slots class's approval", dict(self.approval(cls="slots"), **{"class": "anchor"})),
                             ("another G's", dict(good, generation=good["generation"] + 1))):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, "does not verify under the K_A it names"):
                self.increment(anchor)
        # the slots class's approval, presented AS the slots class, satisfies another authPolicy: the TPM refuses the write
        with self.assertRaises(m.Refused):
            with signkey.policy_session(self.pem, self.tcti, signatures=self.signatures, anchor=self.approval(cls="slots")) as session:
                written = self.tpm("nvincrement", INDEX, "-C", INDEX, "-P", "session:" + session)
                m.require(written.returncode == 0, "the TPM refused the write: %s" % written.stderr.decode()[-120:])

    def test_a_retire_bump_revokes_the_old_approval_in_the_tpm(self):
        """R moved past G by K_A's single-use increment approval: P(K_sys, G) no longer satisfies PolicyNV."""
        old = self.approval()
        self.assertEqual(self.increment(old).returncode, 0)
        inc = ap.increment_document(K_A, POINT, "a", self.r["value"])
        rotation = ap.rotation_name(int(ap.ROTATION_INDEX, 16), POINT, "a")
        with open(self.d + "/inc.pol", "wb") as f:
            f.write(ap.increment_from(rotation, self.r["value"]))
        with open(self.d + "/inc.msg", "wb") as f:
            f.write(ap.authorize_message(ap.increment_from(rotation, self.r["value"]), ap.rotation_class("a")))
        with open(self.d + "/inc.sig", "wb") as f:
            f.write(ap.verify_approval(POINT, ap.increment_from(rotation, self.r["value"]), ap.rotation_class("a"), inc["signature"], "it"))
        with open(self.d + "/ka.pem", "wb") as f:
            f.write(ap.k_a_pem(POINT))
        g = self.d + "/n"
        with open(g, "wb") as f:
            f.write(self.r["value"].to_bytes(8, "big"))
        for argv in (["loadexternal", "-C", "o", "-G", "ecc", "-u", self.d + "/ka.pem", "-c", self.d + "/ka.ctx", "-n", self.d + "/ka.name"],
                     ["verifysignature", "-c", self.d + "/ka.ctx", "-g", "sha256", "-m", self.d + "/inc.msg", "-s", self.d + "/inc.sig",
                      "-f", "ecdsa", "-t", self.d + "/inc.tkt"],
                     ["flushcontext", "-t"],
                     ["startauthsession", "--policy-session", "-S", self.d + "/s.ctx"],
                     ["policycommandcode", "-S", self.d + "/s.ctx", "TPM2_CC_NV_Increment"],
                     ["policynv", "-S", self.d + "/s.ctx", "-i", g, ap.ROTATION_INDEX, "eq"],
                     ["policyauthorize", "-S", self.d + "/s.ctx", "-i", self.d + "/inc.pol", "-n", self.d + "/ka.name", "-q",
                      ap._ref(ap.rotation_class("a")).hex(), "-t", self.d + "/inc.tkt"],
                     ["nvincrement", ap.ROTATION_INDEX, "-C", ap.ROTATION_INDEX, "-P", "session:" + self.d + "/s.ctx"]):
            done = self.tpm(*argv)
            self.assertEqual(done.returncode, 0, (argv[0], done.stderr.decode()[-200:]))
        self.assertEqual(ap.read_rotation(ap.ROTATION_INDEX, lambda argv, **kw: subprocess.run(argv, env=self.env, **kw)), self.r["value"] + 1)
        with self.assertRaises(m.Refused):                    # PolicyNV(R <= G) fails in the TPM: the old approval is dead
            self.increment(old)
        self.assertEqual(self.increment(self.approval(generation=self.r["value"] + 1)).returncode, 0)   # the next G's works


if __name__ == "__main__":
    unittest.main()
