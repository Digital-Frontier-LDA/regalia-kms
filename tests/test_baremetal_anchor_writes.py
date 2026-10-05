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

    def bump(self, n):
        """K_A's single-use increment of this node's R from n (C4's retire bump), as the TPM takes it."""
        inc = ap.increment_document(K_A, POINT, "a", n)
        rotation = ap.rotation_name(int(ap.ROTATION_INDEX, 16), POINT, "a")
        with open(self.d + "/inc.pol", "wb") as f:
            f.write(ap.increment_from(rotation, n))
        with open(self.d + "/inc.msg", "wb") as f:
            f.write(ap.authorize_message(ap.increment_from(rotation, n), ap.rotation_class("a")))
        with open(self.d + "/inc.sig", "wb") as f:
            f.write(ap.verify_approval(POINT, ap.increment_from(rotation, n), ap.rotation_class("a"), inc["signature"], "it"))
        with open(self.d + "/ka.pem", "wb") as f:
            f.write(ap.k_a_pem(POINT))
        g = self.d + "/n"
        with open(g, "wb") as f:
            f.write(n.to_bytes(8, "big"))
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

    def test_the_approved_image_writes_under_k_a_with_no_owner(self):
        self.assertEqual(self.increment(self.approval()).returncode, 0)
        self.assertEqual(self.increment(self.approval(generation=self.r["value"] + 5)).returncode, 0)   # R <= a higher G: still fine

    def test_one_session_authorizes_one_command(self):
        """regalia-kms-95: the TPM resets a policy session's digest when the session is used, so the composite session
        authorizes ONE write; a second command on it is refused, and each write opens its own (as HighWater._write does)."""
        with signkey.policy_session(self.pem, self.tcti, signatures=self.signatures, anchor=self.approval()) as session:
            self.assertEqual(self.tpm("nvincrement", INDEX, "-C", INDEX, "-P", "session:" + session).returncode, 0)
            self.assertNotEqual(self.tpm("nvincrement", INDEX, "-C", INDEX, "-P", "session:" + session).returncode, 0)
        self.assertEqual(self.increment(self.approval()).returncode, 0)

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
        self.bump(self.r["value"])
        self.assertEqual(ap.read_rotation(ap.ROTATION_INDEX, lambda argv, **kw: subprocess.run(argv, env=self.env, **kw)), self.r["value"] + 1)
        with self.assertRaises(m.Refused):                    # PolicyNV(R <= G) fails in the TPM: the old approval is dead
            self.increment(old)
        self.assertEqual(self.increment(self.approval(generation=self.r["value"] + 1)).returncode, 0)   # the next G's works


    def test_a_commit_writes_with_the_approval_of_the_epoch_it_commits(self):
        """regalia-kms-95 on #467: once a retire has moved R past G, only the NEW epoch's document carries the approval
        at G+1. The anchor's write during that commit takes its approval from the manifest being judged (judge_by_tip),
        not the held one: judged by the old epoch it is refused in the TPM with nothing written; by the new, it writes."""
        g = self.r["value"]
        by_epoch = {1: g, 2: g + 1}

        def approvals(cls, manifest=None):
            return self.approval(cls=cls, generation=by_epoch[manifest["epoch"]])
        hw = m.HighWater("0x01500040", tcti=self.tcti, lock_path=self.d + "/hw.lock", schema=m.SCHEMA_V4, anchor_key=POINT,
                         image_key=lambda: self.pem, signatures=self.signatures, approvals=approvals)
        tip = lambda epoch: {"schema": m.SCHEMA_V4, "epoch": epoch, "anchor_policy_key": {"alg": "ecdsa-p256", "key": POINT}}  # noqa: E731
        digest = lambda epoch: "%02x" % epoch * 32                                                                            # noqa: E731
        hw.judge_by_tip(tip(1))
        hw.define()
        hw.anchor(1, digest)
        self.assertEqual(hw.value(), 1)
        self.bump(g)                                                              # the retire: R = G + 1
        with self.assertRaises(m.Refused):
            hw.anchor(2, digest)                                                  # judged by epoch 1: its G is dead in the TPM
        self.assertEqual(hw.value(), 1, "a refused write moved the anchor")
        hw.judge_by_tip(tip(2))
        hw.anchor(2, digest)                                                      # judged by epoch 2: G + 1's approval
        self.assertEqual((hw.value(), hw.record()[0]), (2, 2))

    def test_an_anchor_write_with_no_judged_tip_writes_nothing(self):
        """#361 C4: under v4 the membership anchor writes only when judged by a verified tip; an anchor told only the
        schema and K_A (no judge_by_tip) is refused before any approval is looked up, with nothing written."""
        asked = []

        def approvals(cls, manifest=None):
            asked.append(cls)
            return self.approval(cls=cls)
        hw = m.HighWater("0x01500040", tcti=self.tcti, lock_path=self.d + "/hw.lock", schema=m.SCHEMA_V4, anchor_key=POINT,
                         image_key=lambda: self.pem, signatures=self.signatures, approvals=approvals)
        tip = {"schema": m.SCHEMA_V4, "epoch": 1, "anchor_policy_key": {"alg": "ecdsa-p256", "key": POINT}}
        hw.judge_by_tip(tip)
        hw.define()
        hw.anchor(1, lambda epoch: "%02x" % epoch * 32)
        asked.clear()
        unjudged = m.HighWater("0x01500040", tcti=self.tcti, lock_path=self.d + "/hw.lock", schema=m.SCHEMA_V4, anchor_key=POINT,
                               image_key=lambda: self.pem, signatures=self.signatures, approvals=approvals)
        with self.assertRaisesRegex(m.Refused, r"\(the (anchor|slots) class\) is written under the anchor-policy authority only "
                                    r"when the anchor is judged by a verified chain tip \(judge_by_tip\): nothing is written"):
            unjudged.anchor(2, lambda epoch: "%02x" % epoch * 32)
        self.assertEqual((asked, unjudged.value()), ([], 1))


if __name__ == "__main__":
    unittest.main()
