"""#361 C4 on a software TPM: a node's catch-up. The measurements document's `rotations` for the node (K_A's single-use
increment approvals, one per retire) take its rotation counter R up to G_pub, in order; until R has, the node writes and
signs nothing (require_current). Refused, with R as it was: a missing entry, an entry for another node, and a node not
yet booted on an image approved at G_pub (local no-stranding)."""
import os
import re
import shutil
import subprocess
import unittest

from deploy.baremetal import anchorpolicy as ap
from deploy.baremetal import membership as m
from tests.test_baremetal_anchor_approvals import K_A, POINT
import tests.test_baremetal_anchor_writes as aw     # the module: its test class is not run again here


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_policyauthorize") or os.environ.get("REGALIA_EXPECT_SWTPM") == "1",
                     "needs swtpm and tpm2-tools")
class CatchUp(unittest.TestCase):
    tpm = aw.CompositeSession.tpm
    approval = aw.CompositeSession.approval
    increment = aw.CompositeSession.increment

    def setUp(self):
        aw.CompositeSession.setUp(self)
        self.g = self.r["value"]

    def run_(self, argv, **kw):
        return subprocess.run(argv, env=self.env, **kw)

    def R(self):
        return ap.read_rotation(ap.ROTATION_INDEX, self.run_)

    def rotations(self, *froms, node_id="a"):
        return [{"from": n, "signature": ap.increment_document(K_A, POINT, node_id, n)["signature"]} for n in froms]

    def catch_up(self, rotations, booted):
        return ap.catch_up(ap.ROTATION_INDEX, POINT, "a", rotations, booted, self.run_)

    def test_a_node_offline_across_two_retires_catches_up_in_order(self):
        old = self.approval()
        self.assertEqual(self.increment(old).returncode, 0)
        rotations = self.rotations(self.g, self.g + 1)
        with self.assertRaisesRegex(m.Refused, r"rotation counter is %d, below the published %d: it bumps first" % (self.g, self.g + 2)):
            ap.require_current(ap.ROTATION_INDEX, "a", rotations, self.run_)
        self.assertEqual(self.catch_up(rotations, self.g + 2), self.g + 2)
        ap.require_current(ap.ROTATION_INDEX, "a", rotations, self.run_)
        with self.assertRaises(m.Refused):                    # G's approval no longer opens the anchor's index
            self.increment(old)
        self.assertEqual(self.increment(self.approval(generation=self.g + 2)).returncode, 0)
        self.assertEqual(self.catch_up(rotations, self.g + 2), self.g + 2)     # again: nothing to do, nothing replayed

    def test_a_missing_entry_bumps_nothing(self):
        with self.assertRaisesRegex(m.Refused, r"a's rotation counter is %d and the document's rotations start at %d: an entry is "
                                    r"missing, nothing is bumped" % (self.g, self.g + 1)):
            self.catch_up(self.rotations(self.g + 1), self.g + 2)
        self.assertEqual(self.R(), self.g)

    def test_a_node_not_booted_on_the_new_approvals_keeps_its_old_one(self):
        old = self.approval()
        with self.assertRaisesRegex(m.Refused, r"a is booted on an image whose approvals are at generation %d, below the published "
                                    r"%d: bumping would leave it no approval to write with" % (self.g, self.g + 1)):
            self.catch_up(self.rotations(self.g), self.g)
        self.assertEqual(self.R(), self.g)
        self.assertEqual(self.increment(old).returncode, 0)  # still writes on the approval it has

    def test_another_node_s_increment_is_refused_before_the_tpm(self):
        with self.assertRaisesRegex(m.Refused, r"K_A's approval of a's rotation counter from %d does not verify under the K_A it names" % self.g):
            self.catch_up(self.rotations(self.g, node_id="b"), self.g + 1)
        self.assertEqual(self.R(), self.g)

    def test_the_rotations_form(self):
        for name, rotations, reason in (("a gap", [{"from": 1, "signature": "00" * 64}, {"from": 3, "signature": "00" * 64}],
                                         r"rotations\[1\].from is 3, not 2: a retire moves R by exactly 1"),
                                        ("an extra field", [{"from": 1, "signature": "00" * 64, "at": 1}], r"rotations\[0\] is not \{from, signature\}"),
                                        ("not a list", {}, "rotations is not a list")):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, reason):
                ap.published(rotations)
        self.assertIsNone(ap.published([]))


    def ak(self):
        """This TPM's EK and AK (attest.node_init, as `enrol init` makes them): (ak_public, ek_name hex, ak_name hex)."""
        from unittest import mock
        from deploy.baremetal import attest
        with mock.patch.dict(os.environ, {"TPM2TOOLS_TCTI": self.env["TPM2TOOLS_TCTI"]}):
            attest.node_init(self.d)
        with open(self.d + "/ak.pub", "rb") as f:
            ak_public = f.read()
        with open(self.d + "/ek.pub", "rb") as f:
            ek_name = attest.name_of(attest.public_area(f.read(), "the EK")).hex()
        return ak_public, ek_name, attest.ak_identity(ak_public)[0].hex()

    def test_a_lease_request_s_certified_rotation_counter(self):
        """#361 C4 in D32's lease request (24, 48, 95): R certified by the AK over the request; a peer co-signs nothing for
        a node below G_pub, nor for a certification of another request, node, value or AK."""
        from unittest import mock
        ak_public, ek_name, ak_name = self.ak()
        digest = b"\x11" * 32
        with mock.patch.dict(os.environ, {"TPM2TOOLS_TCTI": self.env["TPM2TOOLS_TCTI"]}):
            got = ap.certify_rotation(digest)
        self.assertEqual(got["value"], self.g)
        check = lambda rotation=got, qualifying=digest, node_id="a", rotations=(), name=ak_name, ek=ek_name: ap.check_rotation(  # noqa: E731
            rotation, qualifying, ak_public, ek, name, POINT, node_id, list(rotations))
        self.assertEqual(check(), self.g)
        if self.g > 1:                     # G_pub == R: current (R starts at the TPM's saved count + 1, so from >= 1)
            self.assertEqual(check(rotations=self.rotations(self.g - 1)), self.g)
        for name, kw, reason in (
                ("behind", dict(rotations=self.rotations(self.g)),
                 "a's rotation counter is %d, below the published %d: no lease is co-signed until it has caught up" % (self.g, self.g + 1)),
                ("another request", dict(qualifying=b"\x22" * 32), "a's rotation certification is not for this request"),
                ("another node", dict(node_id="b"), "b's rotation certification is not of its rotation counter under the anchor-policy authority"),
                ("a claimed value", dict(rotation=dict(got, value=self.g + 1)), "a's rotation value %d is not the certified %d" % (self.g + 1, self.g)),
                ("another AK named", dict(name="00" * 34), "the AK given is not the one the manifest names for a"),
                ("under another EK", dict(ek="000b" + "ee" * 32), "a's rotation certification is not by its AK under its EK")):
            with self.subTest(name), self.assertRaisesRegex(m.Refused, re.escape(reason)):
                check(**kw)
        with self.assertRaisesRegex(m.Refused, "a's rotation certification does not verify under its AK"):
            check(rotation=dict(got, signature=__import__("base64").b64encode(b"\x30\x06\x02\x01\x01\x02\x01\x01").decode()))

if __name__ == "__main__":
    unittest.main()


class Wiring(unittest.TestCase):
    """#361 C4 in the node (deploy/baremetal/node.py): every write and signature under K_A takes its approval through
    node.anchor_approval, which refuses while R < G_pub; and catch_up_rotation bumps from the node's own document with the
    generation of the set it is booted on. The bump and the refusal themselves are CatchUp's, on swtpm."""

    def setUp(self):
        from unittest import mock
        from deploy.baremetal import measurements, node
        self.node, self.mock = node, mock
        self.cfg = {"node_id": "a", "tcti": "swtpm:path=/x", "state_dir": "/nonexistent"}
        self.rotations = [{"from": 4, "signature": "00" * 64}]
        manifest = {"anchor_policy_key": {"key": POINT}}
        patches = [mock.patch.object(node, "_image", lambda cfg, pem_path, manifest: (None, b"pem")),
                   mock.patch.object(node, "_chain_tip", lambda cfg: manifest),
                   mock.patch.object(measurements, "held", lambda directory, manifest: {"held": True}),
                   mock.patch.object(measurements, "rotations", lambda document, node_id: self.rotations),
                   mock.patch.object(measurements, "anchor_approval", lambda manifest, document, node_id, pem, cls:
                                     {"class": cls, "generation": 6})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_every_approval_under_k_a_requires_a_current_rotation_counter(self):
        calls = []
        with self.mock.patch.object(ap, "require_current", lambda index, node_id, rotations, run: calls.append((index, node_id, rotations))):
            self.assertEqual(self.node.anchor_approval(self.cfg, "heartbeat")["class"], "heartbeat")
        self.assertEqual(calls, [(ap.ROTATION_INDEX, "a", self.rotations)])

        def behind(index, node_id, rotations, run):
            raise m.Refused("a's rotation counter is 4, below the published 5: it bumps first")
        with self.mock.patch.object(ap, "require_current", behind), self.assertRaisesRegex(m.Refused, "below the published 5: it bumps first"):
            self.node.anchor_approval(self.cfg, "signing")

    def test_the_catch_up_uses_the_node_s_rotations_and_its_booted_generation(self):
        seen = []
        with self.mock.patch.object(ap, "catch_up", lambda index, point, node_id, rotations, booted, run: seen.append(
                (index, point, node_id, rotations, booted)) or 5):
            self.assertEqual(self.node.catch_up_rotation(self.cfg), 5)
        self.assertEqual(seen, [(ap.ROTATION_INDEX, POINT, "a", self.rotations, 6)])
