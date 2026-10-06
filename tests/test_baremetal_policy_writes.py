"""#242 B2b on a real (software) TPM: the anchor and the heartbeat counter are written by policy.

A node whose image the root approved defines its counter and record slots under PolicyAuthorize(system-phase PCR
key), and its booted system advances them through a policy session (signkey.policy_session) with NO owner
authorization: the point of #242, shown here with the owner authorization set to something the node does not know.
Another image's PCR 11, the initrd phase, and a key that is not the node's write nothing. A re-anchor from a recovery
boot (no approved image) still works, with the owner's authorization, because the indices keep ownerwrite. The boot
is e2e/lib/signed_boot.py's stand-in (checked against systemd-measure by tests/test_e2e_signed_boot.py)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import signed_boot as sb                       # noqa: E402
from deploy.baremetal import heartbeat, signkey, uki  # noqa: E402
from deploy.baremetal import membership as m  # noqa: E402

DIGEST = lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32
OWNER = "owner-secret-of-this-test"


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_policyauthorize") or os.environ.get("REGALIA_EXPECT_SWTPM") == "1",
                     "needs swtpm and tpm2-tools")
class PolicyWrites(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        sock = self.d + "/swtpm.sock"
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=unixio,path=" + sock, "--ctrl",
                        "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon", "--pid",
                        "file=%s/pid" % self.d], check=True, capture_output=True)
        time.sleep(0.5)
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(os.kill, pid, 15)
        self.tcti = "swtpm:path=" + sock
        self.env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        os.mkdir(self.d + "/keys")
        private, public = sb.key(self.d + "/keys")
        with open(public, "rb") as f:
            self.pem = f.read()
        self.image = sb.image("approved")
        self.signatures = {"sha256": [sb.signature(self.image, private, public)[0]]}
        self.policy = signkey.policy(self.pem).hex()

    def tpm(self, *argv, **kw):
        return subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=self.env, capture_output=True, **kw)

    def anchor(self, cls=m.HighWater, index="0x1500016", pem=None):
        return cls(index, tcti=self.tcti, lock_path=self.d + "/%s.lock" % index, define_policy=self.policy,
                   image_key=lambda: pem or self.pem, signatures=self.signatures)

    def public(self, index):
        return self.tpm("nvreadpublic", index).stdout.decode()

    def test_an_approved_image_defines_and_writes_the_anchor_by_policy_without_the_owner(self):
        sb.boot(self.image, env=self.env)
        hw = self.anchor()
        hw.define()
        for index, value in (("0x1500016", "0x2006001A"), ("0x150001a", "0x2006000A"), ("0x150001b", "0x2006000A"), ("0x1500017", "0x20062802")):
            with self.subTest(index=index):
                self.assertRegex(self.public(index), r"value: %s\b" % value)
        self.assertIn("authorization policy: %s" % self.policy.upper(), self.public("0x1500016"))
        self.assertNotIn("authorization policy", self.public("0x1500017"))          # the base: never a policy
        self.assertEqual(hw.anchor(3, DIGEST), 3)
        # the owner authorization set to what this node does not know: the booted system still writes
        self.assertEqual(self.tpm("changeauth", "-c", "o", OWNER).returncode, 0)
        self.assertEqual((hw.anchor(5, DIGEST), hw.record(), hw.unusable()), (5, (5, DIGEST(5)), None))
        self.assertNotEqual(self.tpm("nvincrement", "0x1500016", "-C", "o").returncode, 0)     # and the owner's empty password does not

    def test_another_image_the_initrd_or_another_key_writes_nothing(self):
        sb.boot(self.image, env=self.env)
        hw = self.anchor()
        hw.define()
        hw.anchor(2, DIGEST)
        self.assertEqual(self.tpm("changeauth", "-c", "o", OWNER).returncode, 0)
        # a key that is not the one the node's policy names is refused before any session is opened
        os.makedirs(self.d + "/other")
        _, other_public = sb.key(self.d + "/other")
        with open(other_public, "rb") as f:
            other = f.read()
        with self.assertRaisesRegex(m.Refused, "is not the one this node's write policy names"):
            self.anchor(pem=other).advance(3)
        # another image booted: PCR 11 moves, this boot's signature file has nothing for it
        self.tpm("pcrextend", "11:sha256=" + "ab" * 32, check=True)
        with self.assertRaisesRegex(m.Refused, "no signature by the system-phase PCR key"):
            hw.advance(3)
        self.assertEqual(hw.value(), 2)

    def test_the_initrd_phase_writes_nothing(self):
        sb.boot(self.image, uki.PHASE_PATHS["initrd"], env=self.env)
        hw = self.anchor()
        hw.define()                                         # definition is the owner's (empty here): fine in any phase
        with self.assertRaisesRegex(m.Refused, "no signature by the system-phase PCR key"):
            hw.advance(1)
        self.assertEqual(hw.value(), 0)

    def test_a_re_anchor_from_a_recovery_boot_writes_with_the_owner(self):
        sb.boot(self.image, env=self.env)
        hw = self.anchor()
        hw.define()
        hw.anchor(4, DIGEST)
        self.tpm("pcrextend", "11:sha256=" + "cd" * 32, check=True)          # a recovery boot: no approved image
        hw.redefine(7, DIGEST(7))
        self.assertEqual((hw.value(), hw.record(), hw.unusable()), (7, (7, DIGEST(7)), None))
        self.assertRegex(self.public("0x150001a"), r"value: 0x2006000A\b")

    def test_the_heartbeat_counter_is_written_by_policy_too(self):
        sb.boot(self.image, env=self.env)
        counter = self.anchor(heartbeat.Counter, "0x1500018")
        self.assertEqual(counter.define_at(41), 41)
        self.assertRegex(self.public("0x1500018"), r"value: 0x2006001A\b")
        self.assertEqual(self.tpm("changeauth", "-c", "o", OWNER).returncode, 0)
        self.assertEqual(counter.advance(44), 44)
        self.tpm("pcrextend", "11:sha256=" + "ef" * 32, check=True)
        with self.assertRaisesRegex(m.Refused, "no signature by the system-phase PCR key"):
            counter.advance(45)
        self.assertEqual(counter.value(), 44)

    def test_a_node_without_a_policy_keeps_the_owner_layout(self):
        hw = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock")
        hw.define()
        self.assertRegex(self.public("0x1500016"), r"value: 0x20060012\b")
        self.assertEqual(hw.anchor(2, DIGEST), 2)


import json                                   # noqa: E402
import unittest.mock                          # noqa: E402

from deploy.baremetal import enrol, measurements  # noqa: E402
import tests.test_baremetal_enrol_anchor as ea   # noqa: E402
import tests.test_baremetal_heartbeat as hbt     # noqa: E402
import tests.test_baremetal_replacement as rt    # noqa: E402


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_policyauthorize") or os.environ.get("REGALIA_EXPECT_SWTPM") == "1",
                     "needs swtpm and tpm2-tools")
class Enrolment(ea.Anchor):
    """Enrolment is the anchor's definer: when the signed measurements the chain commits to name a system-phase key for
    this node, it defines the anchor in the policy-written layout and commits the chain by policy sessions, on the
    booted approved image; the running image's key must be the one they name."""

    def setUp(self):
        super().setUp()
        sock = self.d + "/swtpm.sock"
        os.makedirs(self.d + "/tpm")
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d + "/tpm", "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon", "--pid",
                        "file=%s/tpm.pid" % self.d], check=True, capture_output=True)
        time.sleep(0.5)
        with open(self.d + "/tpm.pid") as f:
            pid = int(f.read())
        self.addCleanup(os.kill, pid, 15)
        self.tcti = "swtpm:path=" + sock
        self.cfg["tcti"] = self.tcti
        with open(self.path, "w") as f:
            json.dump(self.cfg, f)
        self.tpm = subprocess.run
        os.makedirs(self.d + "/keys")
        private, public = sb.key(self.d + "/keys")
        with open(public, "rb") as f:
            self.pem = f.read()
        image = sb.image("approved")
        entry, _ = sb.signature(image, private, public)
        with open(self.d + "/tpm2-pcr-signature.json", "w") as f:
            json.dump({"sha256": [entry]}, f)
        sb.boot(image, env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti))
        signed = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
                  "phases": {"initrd": {"11": "a1" * 32}, "system": {"11": "b1" * 32}},
                  "signing": {"initrd": "11" * 32, "system": signkey.pcr_key_fingerprint(self.pem), "secure_boot_cert": "22" * 32},
                  "rootfs_sha256": "6e" * 32}
        self.document = {"schema": measurements.SCHEMA, "name": "signed-images", "nodes": {n: {"accepted": [signed]} for n in "abc"}}
        enrol.store_documents(self.cfg["state_dir"], self.document, chown=False)
        for name, value in (("PCR_PUBLIC_KEY_PATH", public), ("PCR_SIGNATURE_PATHS", (self.d + "/tpm2-pcr-signature.json",))):
            patcher = unittest.mock.patch.object(signkey, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def chain(self, n):
        envs, prev = [], None
        for epoch in range(1, n + 1):
            man = dict(hbt.manifest(epoch, m.digest(prev) if prev else ""), policy_version=measurements.version(self.document))
            envs.append(rt.sign(man))
            prev = man
        return envs

    def public(self, index):
        return subprocess.run(["tpm2_nvreadpublic", index], env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti), capture_output=True).stdout.decode()

    def test_enrolment_defines_by_policy_and_commits_by_policy(self):
        chain = self.chain(3)
        epoch, digest = self.anchor(chain)
        self.assertEqual((epoch, digest), (3, m.digest(chain[-1]["manifest"])))
        self.assertIn("authorization policy: %s" % signkey.policy(self.pem).hex().upper(), self.public(self.cfg["nv_epoch"]))
        self.assertRegex(self.public(self.cfg["nv_epoch"]), r"value: 0x2006001A\b")
        # the node's services read it, with the policy they derive from the store and the image's key
        self.assertEqual((self.node().anchor().value(), self.node().anchor().record()), (3, (3, digest)))
        # the signing counter (#199), defined at 0 under the same policy, and advanced by the node's own construction by policy
        self.assertRegex(self.public(self.cfg["nv_signing"]), r"value: 0x2006001A\b")
        from deploy.baremetal import node as node_module
        signing = node_module.signing_counter(self.node().cfg)
        self.assertEqual((signing.value(), signing.advance(1)), (0, 1))

    def set_owner_auth(self, raw, lockout=True):
        """The TPM's owner authorization set as `enrol ownerauth` leaves it (and its lockout one, #57), test-side."""
        from deploy.baremetal import ownerauth
        env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        for hierarchy in ("o", "l") if lockout else ("o",):
            with open(self.d + "/auth-" + hierarchy, "w") as f:
                f.write("hex:" + raw.hex())
            r = subprocess.run(["tpm2_changeauth", "-c", hierarchy, "file:" + self.d + "/auth-" + hierarchy], env=env, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            os.unlink(self.d + "/auth-" + hierarchy)
        return ownerauth.Auth(raw)

    def defined(self):
        """The NV indices this TPM holds (tpm2_getcap handles-nv-index), as integers: an index's absence is checked
        here, never by a public area that cannot be read (regalia-kms-1e on #428)."""
        out = subprocess.run(["tpm2_getcap", "handles-nv-index"], env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti), capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", out.stdout)}

    def test_enrolment_with_the_owner_authorization_set(self):
        """#420, on a real TPM whose owner (and lockout) authorizations are set, as production's are (#242): the anchor
        step and the heartbeat counter's definition refuse without the value, nothing defined, and with it define the
        anchor and the counters by policy and commit the chain by policy; commit's v4 decision reads the TPM's own
        posture. (The rest of `enrol commit` around these steps: tests/test_baremetal_enrol.py.)"""
        from deploy.baremetal import node as node_module
        from deploy.baremetal import ownerauth
        auth = self.set_owner_auth(bytes.fromhex("00aa" * 16))      # 0x00 bytes: the channel's hex form keeps them
        chain = self.chain(3)
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            self.anchor(chain)
        enrolment = {int(self.cfg[k], 16) + d for k in ("nv_epoch", "nv_heartbeat", "nv_signing") for d in range(6)}
        self.assertEqual(self.defined() & enrolment, set())                              # nothing defined, no index at all
        epoch, digest = enrol.anchor_and_store(self.path, chain, run=self.tpm, owner_auth=auth)
        self.assertEqual((epoch, digest), (3, m.digest(chain[-1]["manifest"])))
        # the control: the same listing now holds the anchor's and the signing counter's indices
        self.assertTrue({int(self.cfg["nv_epoch"], 16), int(self.cfg["nv_signing"], 16)} <= self.defined())
        self.assertIn("authorization policy: %s" % signkey.policy(self.pem).hex().upper(), self.public(self.cfg["nv_epoch"]))
        self.assertEqual((self.node().anchor().value(), self.node().anchor().record()), (3, (3, digest)))   # read with no auth
        signing = node_module.signing_counter(self.node().cfg)
        self.assertEqual((signing.value(), signing.advance(1)), (0, 1))                  # run-time writes: by policy, no auth
        # the heartbeat counter's one definition (the first heartbeat's), by the owner: with the value only
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            node_module.heartbeat_counter(self.node().cfg).define_at(5)
        heartbeat_indices = {int(self.cfg["nv_heartbeat"], 16), int(self.cfg["nv_heartbeat"], 16) + 1}
        self.assertEqual(self.defined() & heartbeat_indices, set())                      # the refusal left nothing half-defined
        counter = node_module.heartbeat_counter(self.node().cfg, owner_auth=auth)
        counter.define_at(5)
        self.assertEqual(counter.value(), 5)
        self.assertTrue(heartbeat_indices <= self.defined())                            # the control: now both are there
        # commit's decision under v4, on this TPM's own posture (both authorizations set): the value is required
        record = json.load(open(os.path.join(os.path.dirname(__file__), "vectors", "ownerauth-v1.json")))
        self.assertEqual(ownerauth.posture(self.tcti), {"owner": True, "lockout": True})
        with self.assertRaisesRegex(enrol.Refused, "under regalia.membership/v4 the TPM's owner authorization is set"):
            enrol.commit_owner_auth({"schema": m.SCHEMA_V4}, None, record["root"], "a",
                                    run=lambda argv, env=None, **kw: subprocess.run(argv, env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti), **kw))

    def test_another_image_s_key_defines_nothing(self):
        os.makedirs(self.d + "/other")
        _, other = sb.key(self.d + "/other")
        with unittest.mock.patch.object(signkey, "PCR_PUBLIC_KEY_PATH", other):
            with self.assertRaisesRegex(m.Refused, "is not one the root approved for"):
                self.anchor(self.chain(1))
        self.assertNotIn("value", self.public(self.cfg["nv_epoch"]))            # refused before the first write

    # the FakeTpm cases of the base class are not this class's
    test_a_fresh_enrolment_anchors_the_chain_at_its_last_epoch = None
    test_no_node_gets_a_counter_from_the_anchor_step = None
    test_a_longer_chain_continues_a_shorter_enrolment = None
    test_a_store_of_another_chain_is_refused_and_left = None
    test_indices_without_a_store_are_taken_only_as_define_leaves_them = None
    test_a_heartbeat_counter_already_moved_is_refused = None


if __name__ == "__main__":
    unittest.main()
