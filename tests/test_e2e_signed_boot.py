"""e2e/lib/signed_boot.py, on a software TPM (#242 B0).

The helper stands in for a booted, signed image in every swtpm test of the anchor's policy writes, so it is
checked twice here. Against systemd: what it signs is byte for byte what `systemd-measure sign` writes, and the
PCR 11 it extends is what `systemd-measure calculate` predicts. Against the TPM: a policy session built from its
signature file authorizes a write to an index whose authPolicy is PolicyAuthorize(the PCR key) only at the
booted system's PCR 11. Not with another key's signature, not for an image signed but not booted, and not
in the initrd phase. That session is the one #242's writer will open.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
import signed_boot as sb                       # noqa: E402
from deploy.baremetal import uki               # noqa: E402

MEASURE = shutil.which("systemd-measure") or ("/usr/lib/systemd/systemd-measure" if os.path.exists("/usr/lib/systemd/systemd-measure") else None)
SLOT = "0x1500050"


def needs(*tools):
    missing = [t for t in tools if not shutil.which(t)]
    if missing and os.environ.get("REGALIA_EXPECT_SWTPM"):
        raise AssertionError("REGALIA_EXPECT_SWTPM is set and %s is missing" % ", ".join(missing))
    return unittest.skipIf(missing, "needs %s" % ", ".join(missing))


@needs("swtpm", "tpm2_pcrextend", "tpm2_policyauthorize", "openssl")
class SignedBoot(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        sock = self.d + "/swtpm.sock"
        r = subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=unixio,path=" + sock,
                            "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                            "--pid", "file=%s/pid" % self.d], capture_output=True)
        self.assertEqual(r.returncode, 0, "swtpm did not start: %s" % r.stderr.decode(errors="replace"))
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(os.kill, pid, 15)
        time.sleep(0.5)
        self.env = dict(os.environ, TPM2TOOLS_TCTI="swtpm:path=" + sock)
        os.mkdir(self.d + "/keys")
        self.private, self.public = sb.key(self.d + "/keys")

    def tpm(self, *argv, **kw):
        return subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=self.env, capture_output=True, **kw)

    def file(self, name, data):
        path = os.path.join(self.d, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    # ---- against systemd ----

    def test_it_signs_and_boots_what_systemd_measure_signs_and_predicts(self):
        if MEASURE is None:
            self.assertFalse(os.environ.get("REGALIA_EXPECT_SWTPM"), "REGALIA_EXPECT_SWTPM is set and systemd-measure is missing")
            self.skipTest("needs systemd-measure")
        parts = sb.image()
        options = ["--%s=%s" % (name, self.file(name, data)) for name, data in parts.items()]
        for phases in (sb.SYSTEM, uki.PHASE_PATHS["initrd"]):
            with self.subTest(phases=phases):
                done = subprocess.run([MEASURE, "sign", *options, "--bank=sha256", "--phase=" + phases, "--private-key=" + self.private,
                                       "--public-key=" + self.public], capture_output=True, check=True)
                self.assertEqual(json.loads(done.stdout), {"sha256": [sb.signature(parts, self.private, self.public, phases)[0]]})
                done = subprocess.run([MEASURE, "calculate", *options, "--bank=sha256", "--phase=" + phases], capture_output=True, check=True)
                self.assertIn("11:sha256=" + uki.pcr11(parts, phases), done.stdout.decode().split())

    def test_the_boot_gives_the_signed_value_once(self):
        parts = sb.image()
        self.assertEqual(sb.boot(parts, env=self.env), uki.pcr11(parts, sb.SYSTEM))
        self.assertEqual(sb.pcr11(self.env), uki.pcr11(parts, sb.SYSTEM))
        with self.assertRaisesRegex(SystemExit, "PCR 11 is not zero"):
            sb.boot(parts, env=self.env)
        self.assertNotEqual(sb.image("approved"), sb.image("retired"))

    def test_the_command_writes_the_signature_file_and_boots(self):
        out = subprocess.run([sys.executable, "-B", sb.__file__, self.d + "/node", "--key", self.private], env=self.env,
                             capture_output=True, check=True).stdout
        said = json.loads(out)
        with open(self.d + "/node/tpm2-pcr-signature.json") as f:
            entry = json.load(f)["sha256"][0]
        self.assertEqual((said["pcr11"], said["pol"], said["pkfp"], entry["pol"]),
                         (uki.pcr11(sb.image(), sb.SYSTEM), uki.policy_digest(said["pcr11"]), sb.fingerprint(self.public), said["pol"]))
        self.assertEqual(sb.pcr11(self.env), said["pcr11"])
        self.assertFalse(os.path.exists(self.d + "/node/pcr-key.pem"))        # --key: no new key
        # a key that is not FILE.pem beside FILE.pub.pem is refused, never paired with a wrong public half
        os.rename(self.private, self.d + "/keys/pcr-key")
        for given in (self.d + "/keys/pcr-key", self.d + "/keys/absent.pem"):
            with self.subTest(key=given):
                done = subprocess.run([sys.executable, "-B", sb.__file__, self.d + "/bad", "--key", given, "--no-boot"], env=self.env, capture_output=True)
                self.assertEqual(done.returncode, 2)
                self.assertIn(b"--key must name FILE.pem", done.stderr)
        # --no-boot signs another image and leaves PCR 11 as it is
        subprocess.run([sys.executable, "-B", sb.__file__, self.d + "/other", "--image", "retired", "--no-boot"], env=self.env,
                       capture_output=True, check=True)
        self.assertEqual(sb.pcr11(self.env), said["pcr11"])

    # ---- against the TPM: the policy session #242's writer will open ----

    def authorize(self, public):
        """The authPolicy PolicyAuthorize(key), by a trial session: what an anchor index is defined with."""
        self.tpm("flushcontext", "-t")
        self.assertEqual(self.tpm("loadexternal", "-C", "o", "-G", "rsa", "-u", public, "-c", self.d + "/key.ctx", "-n", self.d + "/key.name").returncode, 0)
        self.tpm("flushcontext", "-t")
        self.tpm("startauthsession", "-S", self.d + "/trial.ctx", check=True)
        self.tpm("policyauthorize", "-S", self.d + "/trial.ctx", "-L", self.d + "/auth.policy", "-n", self.d + "/key.name",
                 "-i", self.file("zero.pol", bytes(32)), check=True)
        self.tpm("flushcontext", self.d + "/trial.ctx", check=True)
        return self.d + "/auth.policy"

    def write(self, entry, public, data):
        """Write `data` to SLOT through PolicyPCR(11) + PolicyAuthorize, from one entry of a signature file.
        Returns the step that failed, or None."""
        pol, sig = self.file("pol", bytes.fromhex(entry["pol"])), self.file("sig", base64.b64decode(entry["sig"]))
        session = self.d + "/session.ctx"
        self.tpm("flushcontext", "-t")
        steps = (("loadexternal", "-C", "o", "-G", "rsa", "-u", public, "-c", self.d + "/key.ctx", "-n", self.d + "/key.name"),
                 ("verifysignature", "-c", self.d + "/key.ctx", "-g", "sha256", "-m", pol, "-s", sig, "-f", "rsassa", "-t", self.d + "/ticket"),
                 ("startauthsession", "--policy-session", "-S", session),
                 ("policypcr", "-S", session, "-l", "sha256:11"),
                 ("policyauthorize", "-S", session, "-i", pol, "-n", self.d + "/key.name", "-t", self.d + "/ticket"),
                 ("nvwrite", SLOT, "-P", "session:" + session, "-i", "-"))
        try:
            for step in steps:
                if self.tpm(*step, input=data if step[0] == "nvwrite" else None).returncode != 0:
                    return step[0]
                if step[0] == "loadexternal":
                    self.tpm("flushcontext", "-t")       # a bare swtpm has no resource manager: the key is reloaded from its context
            return None
        finally:
            if os.path.exists(session):
                self.tpm("flushcontext", session)
            self.tpm("flushcontext", "-t")

    def define(self, policy):
        self.assertEqual(self.tpm("nvdefine", SLOT, "-C", "o", "-s", "8", "-a", "policywrite|ownerwrite|authread|ownerread", "-L", policy).returncode, 0)

    def read(self):
        return self.tpm("nvread", SLOT, "-C", SLOT, "-s", "8").stdout

    def test_a_policy_write_needs_the_booted_system_of_an_image_the_key_signed(self):
        approved = sb.image("approved")
        mine = sb.signature(approved, self.private, self.public)[0]
        os.mkdir(self.d + "/other")
        other_private, other_public = sb.key(self.d + "/other")
        theirs = sb.signature(approved, other_private, other_public)[0]
        retired = sb.signature(sb.image("retired"), self.private, self.public)[0]
        self.define(self.authorize(self.public))
        sb.boot(approved, env=self.env)
        # the signature of the image that booted, by the key the index names: written
        self.assertIsNone(self.write(mine, self.public, b"approved"))
        self.assertEqual(self.read(), b"approved")
        # another key's signature of the same boot: the session is authorized for another key's name
        self.assertEqual(self.write(theirs, other_public, b"theirs!!"), "nvwrite")
        # a signed image that did not boot: its PolicyPCR is not the session's
        self.assertEqual(self.write(retired, self.public, b"retired!"), "policyauthorize")
        self.assertEqual(self.read(), b"approved")

    def test_the_initrd_phase_cannot_write(self):
        approved = sb.image("approved")
        self.define(self.authorize(self.public))
        sb.boot(approved, uki.PHASE_PATHS["initrd"], env=self.env)
        # the system phase's signature does not match a PCR 11 still in the initrd phase
        self.assertEqual(self.write(sb.signature(approved, self.private, self.public)[0], self.public, b"initrd!!"), "policyauthorize")
        self.assertEqual(self.tpm("nvreadpublic", SLOT).stdout.count(b"written"), 0)

    def test_the_owner_authorization_does_not_stand_in_the_way(self):
        """Step C sets the owner authorization: loading the PCR key (TPM2_LoadExternal under the owner
        hierarchy) takes none, so the run-time writer never needs it."""
        approved = sb.image("approved")
        self.define(self.authorize(self.public))
        sb.boot(approved, env=self.env)
        self.assertEqual(self.tpm("changeauth", "-c", "o", "owner-secret-of-this-test").returncode, 0)
        self.assertIsNone(self.write(sb.signature(approved, self.private, self.public)[0], self.public, b"approved"))
        self.assertEqual(self.read(), b"approved")


if __name__ == "__main__":
    unittest.main()
