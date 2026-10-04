"""#242 B2a: the TPM anchor's readers derive this node's approved-image write policy from root-signed sources only.

  * tests/vectors/pcr-key-policy-v1.json, shared with the Go initrd: signkey's Name, fingerprint and policy for
    fixed PCR keys, replayed here and, on a software TPM, against the TPM's own Name and trial-session digest;
  * measurements.approved_image_policy: the running image's key must be a system-phase key the signed
    measurements document approves for THIS node, then signkey.policy(pem);
  * node.image_policy: the node's verified chain, the document its newest manifest commits to, the key file;
  * HighWater: the policy is asked for only when an index is written by policy, at most once, and a policy
    that cannot be established is a refusal (Refused), not an Unusable anchor a re-anchor would "repair";
  * reanchor and rollout: without --node-config, a policy-written anchor is that refusal."""
import copy
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

from deploy.baremetal import measurements, node, reanchor, rollout, signkey
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_rollout as rt
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import POLICY, sign

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "pcr-key-policy-v1.json"
CASES = json.loads(VECTORS.read_text())["cases"]
KEY, OTHER = (case["pem"].encode() for case in CASES[:2])


UKI_ONE = rt.document("v1", **{n: [rt.uki("image-1", "a1", "b1")] for n in "abc"})
UKI_BOTH = rt.document("v2", **{n: [rt.uki("image-1", "a1", "b1"), rt.uki("image-2", "a2", "b2")] for n in "abc"})


def signed(document, **system):
    """`document` with each node's sets naming a system-phase key: system={"a": pem, ...}."""
    out = copy.deepcopy(document)
    for node_id, pem in system.items():
        for entry in out["nodes"][node_id]["accepted"]:
            entry["signing"] = {"initrd": "11" * 32, "system": signkey.pcr_key_fingerprint(pem), "secure_boot_cert": "22" * 32}
    return out


class SharedVectors(unittest.TestCase):
    def test_signkey_gives_what_the_file_says(self):
        self.assertGreaterEqual(len(CASES), 3)
        for case in CASES:
            with self.subTest(case["name"]):
                pem = case["pem"].encode()
                self.assertEqual((signkey.pcr_key_name(pem).hex(), signkey.pcr_key_fingerprint(pem), signkey.policy(pem).hex()),
                                 (case["tpm_name"], case["pkfp"], case["policy"]))

    def test_the_tpm_gives_what_the_file_says(self):
        """The file is checked against a real TPM when it is written; CI checks it again, so a file edited by hand
        or a tool that changes how it loads a key fails here, not on a host."""
        if not shutil.which("swtpm") or not shutil.which("tpm2_policyauthorize"):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("REGALIA_EXPECT_SWTPM is set and swtpm or tpm2-tools is missing")
            self.skipTest("needs swtpm and tpm2-tools")
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sock = d + "/swtpm.sock"
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + d, "--server", "type=unixio,path=" + sock, "--ctrl",
                        "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon", "--pid", "file=%s/pid" % d],
                       check=True, capture_output=True)
        time.sleep(0.5)
        self.addCleanup(lambda: os.kill(int(pathlib.Path(d + "/pid").read_text()), 15))
        env = dict(os.environ, TPM2TOOLS_TCTI="swtpm:path=" + sock)
        tpm = lambda *argv: subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=env, capture_output=True, check=True)
        pathlib.Path(d + "/zero").write_bytes(bytes(32))
        for case in CASES:
            with self.subTest(case["name"]):
                pathlib.Path(d + "/key.pem").write_text(case["pem"])
                tpm("loadexternal", "-C", "o", "-G", "rsa", "-u", d + "/key.pem", "-c", d + "/key.ctx", "-n", d + "/key.name")
                tpm("flushcontext", "-t")
                self.assertEqual(pathlib.Path(d + "/key.name").read_bytes().hex(), case["tpm_name"])
                tpm("startauthsession", "-S", d + "/trial.ctx")
                tpm("policyauthorize", "-S", d + "/trial.ctx", "-L", d + "/policy", "-n", d + "/key.name", "-i", d + "/zero")
                tpm("flushcontext", d + "/trial.ctx")
                self.assertEqual(pathlib.Path(d + "/policy").read_bytes().hex(), case["policy"])


class ApprovedImagePolicy(rt.Case):
    def setUp(self):
        super().setUp()
        self.doc = signed(UKI_ONE, a=KEY, b=KEY, c=KEY)
        self.current = self.under(self.doc)

    def test_the_policy_of_a_key_the_document_approves_for_this_node(self):
        self.assertEqual(measurements.approved_image_policy(self.current, self.doc, "a", KEY), signkey.policy(KEY).hex())
        # two sets (CURRENT and NEXT) under two keys: either one
        both = signed(UKI_BOTH, a=KEY, b=KEY, c=KEY)
        both["nodes"]["a"]["accepted"][1]["signing"]["system"] = signkey.pcr_key_fingerprint(OTHER)
        self.assertEqual(measurements.approved_image_policy(self.under(both), both, "a", OTHER), signkey.policy(OTHER).hex())

    def test_anything_else_is_a_refusal(self):
        unsigned = self.under(UKI_ONE)
        for name, args, reason in (
                ("a key the document does not approve", (self.current, self.doc, "a", OTHER), "is not one the root approved for a"),
                ("approved for another node only", (self.under(signed(UKI_ONE, b=OTHER, c=KEY, a=KEY)), signed(UKI_ONE, b=OTHER, c=KEY, a=KEY),
                                                    "a", OTHER), "is not one the root approved for a"),
                ("no set names a system key", (unsigned, UKI_ONE, "a", KEY), "names a system-phase PCR key"),
                ("a document the manifest does not commit to", (unsigned, self.doc, "a", KEY), "commits to measurements"),
                ("a node the document does not list", (self.current, self.doc, "z", KEY), "no entry for 'z'"),
                ("not a PEM key", (self.current, self.doc, "a", b"nonsense"), "not a PEM public key")):
            with self.subTest(name):
                self.refused(reason, measurements.approved_image_policy, *args)


class NodePolicy(rt.Case):
    """node.image_policy, from the files a node holds: its verified chain, the measurements its newest manifest
    commits to (from the store by digest, #332), and the key file."""

    def setUp(self):
        super().setUp()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        doc = signed(UKI_ONE, a=KEY, b=KEY, c=KEY)
        envelope = sign(self.under(doc), hbt.ROOT)
        self.cfg = {"state_dir": self.d, "measurements": self.d + "/measurements.json", "root_key": hbt.pub(hbt.ROOT), "node_id": "a"}
        self.store = measurements.Documents(os.path.join(self.d, measurements.STORE_DIR))
        self.store.put(doc)
        pathlib.Path(self.d + "/membership.json").write_text(json.dumps([envelope]))
        pathlib.Path(self.d + "/pcr.pem").write_bytes(KEY)

    def test_the_policy_from_the_node_s_own_files(self):
        self.assertEqual(node.image_policy(self.cfg, self.d + "/pcr.pem"), signkey.policy(KEY).hex())
        # the services that cannot read sync's store read the chain it publishes
        os.rename(self.d + "/membership.json", self.d + "/" + node.PUBLISHED)
        self.assertEqual(node.image_policy(self.cfg, self.d + "/pcr.pem"), signkey.policy(KEY).hex())

    def test_the_document_is_the_one_the_manifest_commits_to_never_the_legacy_file(self):
        """d9: the retired single file (cfg["measurements"]) holding another document that approves ANOTHER key is
        not read; the store's document, the one the newest manifest commits to, decides."""
        pathlib.Path(self.d + "/measurements.json").write_text(json.dumps(signed(UKI_BOTH, a=OTHER, b=OTHER, c=OTHER)))
        self.assertEqual(node.image_policy(self.cfg, self.d + "/pcr.pem"), signkey.policy(KEY).hex())
        pathlib.Path(self.d + "/pcr.pem").write_bytes(OTHER)
        self.refused("is not one the root approved for a", node.image_policy, self.cfg, self.d + "/pcr.pem")

    def test_a_missing_file_is_a_refusal(self):
        self.refused("cannot be established", node.image_policy, self.cfg, self.d + "/absent.pem")
        shutil.rmtree(os.path.join(self.d, measurements.STORE_DIR))
        self.refused("which this node does not hold", node.image_policy, self.cfg, self.d + "/pcr.pem")
        os.remove(self.d + "/membership.json")
        self.refused("no verified chain", node.image_policy, self.cfg, self.d + "/pcr.pem")

    def test_another_image_s_key_is_a_refusal(self):
        pathlib.Path(self.d + "/pcr.pem").write_bytes(OTHER)
        self.refused("is not one the root approved for a", node.image_policy, self.cfg, self.d + "/pcr.pem")


class LazyPolicy(unittest.TestCase):
    """HighWater asks for the policy only when it meets a policy-written index, and at most once."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm, self.asked = FakeTpm(), []
        first = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm)
        first.define()
        first.anchor(2, lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32)

    def hw(self, answer):
        def policy():
            self.asked.append(1)
            if isinstance(answer, Exception):
                raise answer
            return answer
        return m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm, policy=policy)

    def by_policy(self):
        for index in ("0x1500016", "0x150001a", "0x150001b"):
            self.tpm.nv[index][0] |= FakeTpm.BITS["policywrite"]
            self.tpm.policies[index] = POLICY

    def test_an_owner_written_anchor_never_asks(self):
        hw = self.hw(m.Refused("must not be asked"))
        self.assertEqual((hw.value(), hw.unusable(), self.asked), (2, None, []))

    def test_a_policy_written_anchor_asks_once(self):
        self.by_policy()
        hw = self.hw(POLICY)
        self.assertEqual((hw.value(), hw.record()[0], hw.unusable(), len(self.asked)), (2, 2, None, 1))

    def test_a_policy_that_cannot_be_established_is_a_refusal_not_an_unusable_anchor(self):
        self.by_policy()
        hw = self.hw(m.Refused("no verified chain"))
        with self.assertRaises(m.Refused) as caught:
            hw.value()
        self.assertNotIsInstance(caught.exception, m.Unusable)
        with self.assertRaisesRegex(m.Refused, "must be 64 lowercase hex"):
            self.hw("not hex").value()

    def test_reanchor_and_rollout_say_what_to_give(self):
        self.by_policy()
        for policy in (reanchor.node_policy(None, "a"), rollout._node_policy(None)):
            hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm, policy=policy)
            with self.assertRaisesRegex(m.Refused, "give --node-config"):
                hw.value()


if __name__ == "__main__":
    unittest.main()
