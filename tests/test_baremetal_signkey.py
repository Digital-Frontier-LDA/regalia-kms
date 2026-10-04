"""A node's TPM signing key (#199, deploy/baremetal/signkey.py): made in a real swtpm under PolicyAuthorize of a
system-phase PCR key, certified by the node's AK and checked as the root checks it, and signing only under a PCR 11
that key signed."""
import base64
import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from deploy.baremetal import attest, membership, signkey, uki

Refused = membership.Refused


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def pem_of(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def pcr_signatures(key, *pcr11_values):
    """A tpm2-pcr-signature.json as systemd-measure writes it: one entry per PCR 11 value, signed by `key`."""
    entries = []
    for value in pcr11_values:
        pol = uki.policy_digest(value)
        sig = key.sign(bytes.fromhex(pol), padding.PKCS1v15(), hashes.SHA256())
        entries.append({"pcrs": [11], "pkfp": signkey.pcr_key_fingerprint(pem_of(key)), "pol": pol, "sig": base64.b64encode(sig).decode()})
    return {"sha256": entries}


class WithoutTpm(unittest.TestCase):
    def test_the_policy_is_policy_authorize_of_the_key_name(self):
        key = rsa_key()
        name = signkey.pcr_key_name(pem_of(key))
        self.assertEqual(name[:2], b"\x00\x0b")
        self.assertEqual(signkey.policy(pem_of(key)), hashlib.sha256(hashlib.sha256(bytes(32) + bytes.fromhex("0000016a") + name).digest()).digest())
        self.assertNotEqual(signkey.policy(pem_of(key)), signkey.policy(pem_of(rsa_key())))

    def test_only_an_rsa_2048_pcr_key(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaisesRegex(Refused, "RSA-2048"):
            signkey.pcr_key_name(pem_of(small))
        with self.assertRaisesRegex(Refused, "not a PEM public key"):
            signkey.pcr_key_name(b"nonsense")

    def test_the_pcr_signature_for_this_boot_and_this_key_only(self):
        key, other = rsa_key(), rsa_key()
        here, elsewhere = "11" * 32, "22" * 32
        pol, sig = signkey.pcr_signature(pcr_signatures(key, elsewhere, here), pem_of(key), here)
        self.assertEqual(pol.hex(), uki.policy_digest(here))
        for document, value in ((pcr_signatures(key, elsewhere), here), (pcr_signatures(other, here), here), ({"sha256": []}, here)):
            with self.assertRaisesRegex(Refused, "no signature by the system-phase PCR key"):
                signkey.pcr_signature(document, pem_of(key), value)

    def test_low_s(self):
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        n = signkey.P256_ORDER
        self.assertEqual(signkey.low_s(encode_dss_signature(5, n - 7)), (5).to_bytes(32, "big").hex() + (7).to_bytes(32, "big").hex())
        self.assertEqual(signkey.low_s(encode_dss_signature(5, 7)), (5).to_bytes(32, "big").hex() + (7).to_bytes(32, "big").hex())


SEAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "seal-hsm-pin.sh")


def seal(*args, env=None):
    done = subprocess.run(["bash", SEAL, *args], capture_output=True, text=True, env=env)
    return done.returncode, done.stderr


class ReservedHandles(unittest.TestCase):
    def test_the_pin_tool_refuses_every_node_identity_handle(self):
        """attest.RESERVED_HANDLES is the one list; the PIN tool's refusal of 0x810100xx must cover all of it, in any case,
        before it needs root or a TPM: with --replace-import-key it would otherwise evict the key there."""
        self.assertIn(signkey.HANDLE, attest.RESERVED_HANDLES)
        for handle in attest.RESERVED_HANDLES + tuple(h.upper().replace("0X", "0x") for h in attest.RESERVED_HANDLES):
            with self.subTest(handle):
                rc, err = seal("--init-import-key", "--replace-import-key", "--import-handle", handle)
                self.assertNotEqual(rc, 0)
                self.assertIn("the node's identity keys", err)
        rc, err = seal("--init-import-key", "--replace-import-key", "--import-handle", "0x81000101")
        self.assertNotIn("the node's identity keys", err)         # the default is not refused for this


class OnSwtpm(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createprimary", "tpm2_policyauthorize", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools and openssl")
        self.d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
        self.addCleanup(shutil.rmtree, self.d, True)
        state, sock = self.d + "/tpm", self.d + "/tpm.sock"
        os.mkdir(state)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear",
                        "--daemon", "--pid", "file=%s/pid" % self.d], check=True, capture_output=True)
        time.sleep(0.5)
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(lambda: os.kill(pid, 15))
        patcher = unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI="swtpm:path=" + sock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.key = rsa_key()
        self.pem = pem_of(self.key)

    def pcr11(self):
        out = os.path.join(self.d, "pcr11-%d" % time.monotonic_ns())
        subprocess.run(["tpm2_pcrread", "sha256:11", "-o", out], check=True, capture_output=True)
        with open(out, "rb") as f:
            return f.read().hex()

    def extend(self, data):
        subprocess.run(["tpm2_pcrextend", "11:sha256=" + hashlib.sha256(data).hexdigest()], check=True, capture_output=True)

    def test_made_certified_and_signing_only_under_a_signed_pcr_11(self):
        self.extend(b"an approved image, booted")
        blob = signkey.create(self.pem)
        name, point = signkey.identity(blob, self.pem)
        self.assertEqual(signkey.public(), blob)

        # the root's check: the node's AK under its EK certified this very key
        attest.node_init(self.d)
        with open(self.d + "/ek.pub", "rb") as f:
            ek_name = attest.name_of(attest.public_area(f.read(), "ek")).hex()
        with open(self.d + "/ak.pub", "rb") as f:
            ak_public = f.read()
        info, sig = signkey.certify()
        self.assertEqual(signkey.verify_certification(blob, info, sig, ak_public, ek_name, self.pem), {"alg": "ecdsa-p256", "key": point})
        with self.assertRaisesRegex(Refused, "policy is not PolicyAuthorize of this system-phase PCR key"):
            signkey.verify_certification(blob, info, sig, ak_public, ek_name, pem_of(rsa_key()))
        with self.assertRaisesRegex(Refused, "signer is not this AK under this EK"):
            signkey.verify_certification(blob, info, sig, ak_public, "000b" + "00" * 32, self.pem)
        with self.assertRaisesRegex(Refused, "does not verify under the AK"):
            signkey.verify_certification(blob, info[:-1] + bytes([info[-1] ^ 1]), sig, ak_public, ek_name, self.pem)

        # signing: under the PCR 11 the system-phase key signed, and verified as a v4 party's signature is
        message = b"regalia-heartbeat/v1\0{}"
        here = self.pcr11()
        out = signkey.sign(message, self.pem, signatures=pcr_signatures(self.key, here))
        membership.verify_revocation("ecdsa-p256", point, message, out, "the heartbeat")
        self.assertLessEqual(int(out[64:], 16), signkey.P256_ORDER // 2)

        # another key's signature over this PCR 11, or a PCR 11 nobody signed (another image, the initrd): no signature
        with self.assertRaisesRegex(Refused, "no signature by the system-phase PCR key"):
            signkey.sign(message, self.pem, signatures=pcr_signatures(rsa_key(), here))
        self.extend(b"something else measured")
        with self.assertRaisesRegex(Refused, "no signature by the system-phase PCR key"):
            signkey.sign(message, self.pem, signatures=pcr_signatures(self.key, here))
        # and the TPM itself refuses a policy approved for another PCR 11: the old signature's policy does not match
        # this boot's PolicyPCR (the check above is only the early, readable refusal)
        stale = pcr_signatures(self.key, here)
        with unittest.mock.patch.object(signkey, "pcr_signature", lambda doc, pem, value: (bytes.fromhex(stale["sha256"][0]["pol"]),
                                                                                            base64.b64decode(stale["sha256"][0]["sig"]))):
            with self.assertRaisesRegex(Refused, "tpm2_policyauthorize failed"):
                signkey.sign(message, self.pem, signatures=stale)

    def test_the_key_cannot_be_used_without_its_policy(self):
        signkey.create(self.pem)
        digest = os.path.join(self.d, "digest")
        with open(digest, "wb") as f:
            f.write(hashlib.sha256(b"x").digest())
        done = subprocess.run(["tpm2_sign", "-c", signkey.HANDLE, "-g", "sha256", "-d", "-o", os.path.join(self.d, "sig"), digest], capture_output=True)
        self.assertNotEqual(done.returncode, 0, "a password session signed with the key: userWithAuth is set")

    def test_the_pin_tool_leaves_the_signing_key_alone(self):
        blob = signkey.create(self.pem)
        rc, err = seal("--init-import-key", "--replace-import-key", "--import-handle", signkey.HANDLE, env=dict(os.environ))
        self.assertNotEqual(rc, 0)
        self.assertIn("the node's identity keys", err)
        self.assertEqual(signkey.public(), blob)

    def test_made_once(self):
        recorded = []
        blob = signkey.create(self.pem, record=recorded.append)
        self.assertEqual(recorded, [signkey.identity(blob, self.pem)[0].hex()])
        with self.assertRaisesRegex(Refused, "already holds a key"):
            signkey.create(self.pem)

    def test_a_key_made_otherwise_is_refused_by_its_public_area(self):
        """A key with userWithAuth set (usable by password, not only by its policy) is not a signing key."""
        policy = os.path.join(self.d, "policy")
        with open(policy, "wb") as f:
            f.write(signkey.policy(self.pem))
        p = {n: os.path.join(self.d, n) for n in ("srk", "pub", "priv")}
        subprocess.run(["tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc256", "-c", p["srk"]], check=True, capture_output=True)
        subprocess.run(["tpm2_create", "-C", p["srk"], "-g", "sha256", "-G", "ecc256:ecdsa-sha256", "-a", signkey.TOOL_ATTRIBUTES + "|userwithauth",
                        "-L", policy, "-u", p["pub"], "-r", p["priv"]], check=True, capture_output=True)
        with open(p["pub"], "rb") as f:
            with self.assertRaisesRegex(Refused, "usable only through its policy"):
                signkey.identity(f.read(), self.pem)


if __name__ == "__main__":
    unittest.main()
