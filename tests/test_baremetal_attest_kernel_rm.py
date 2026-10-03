"""Credential activation behind the KERNEL's resource manager (/dev/tpmrmN), which is what a host uses.

attest.node_activate runs three tpm2-tools processes on one policy session: startauthsession,
policysecret, activatecredential. Each opens /dev/tpmrm0 anew, and the kernel resource manager
flushes what a closed connection left loaded. The question for #190 was whether the session survives
between them. tpm2-tools saves the session's context to the -S file when the process ends and loads it
in the next, and the kernel lets a saved session be loaded again from another connection. Measured
2026-10-03 on Linux 6.18 with tpm2-tools 5.7 (this test, against swtpm behind tpm_vtpm_proxy): the
activation succeeds and the peer enrols the AK.

tpm2-abrmd is NOT a substitute for this test: it keeps a disconnected client's sessions reclaimable
where the kernel does not, so a pass behind it proves nothing about a host (e2e/node-units-systemd.py
says the same). Hosted CI runners have no vTPM proxy (CONFIG_TCG_VTPM_PROXY is not set), so this runs
where /dev/vtpmx exists and it runs as root (a development machine, a bench host), and is skipped
elsewhere unless REGALIA_EXPECT_KERNEL_RM=1, which makes a skip a failure.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from deploy.baremetal import attest  # noqa: E402


class OnKernelResourceManager(unittest.TestCase):
    def setUp(self):
        missing = [t for t in ("swtpm", "tpm2_createek", "tpm2_activatecredential") if not shutil.which(t)]
        reason = None
        if missing:
            reason = "needs %s" % ", ".join(missing)
        elif not os.path.exists("/dev/vtpmx"):
            reason = "needs the kernel's vTPM proxy (/dev/vtpmx)"
        elif os.geteuid() != 0:
            reason = "needs root (it creates a TPM device)"
        if reason:
            if os.environ.get("REGALIA_EXPECT_KERNEL_RM") == "1":
                self.fail(reason + ", and REGALIA_EXPECT_KERNEL_RM=1 says it must run here")
            self.skipTest(reason)
        self.d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR", "/tmp"))
        self.addCleanup(shutil.rmtree, self.d, True)
        os.mkdir(self.d + "/state")
        done = subprocess.run(["swtpm", "chardev", "--vtpm-proxy", "--tpm2", "--tpmstate", "dir=%s/state" % self.d,
                               "--flags", "startup-clear", "--daemon", "--pid", "file=%s/pid" % self.d],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        device = re.search(r"/dev/tpm(\d+)", done.stdout + done.stderr)
        self.assertIsNotNone(device, done.stdout + done.stderr)
        time.sleep(0.5)
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(lambda: os.kill(pid, 15))
        self.rm = "/dev/tpmrm" + device.group(1)
        self.assertTrue(os.path.exists(self.rm), "the kernel made no resource-manager device for the new TPM")

    def test_a_credential_is_activated_through_the_kernel_resource_manager(self):
        os.environ["TPM2TOOLS_TCTI"] = "device:" + self.rm
        self.addCleanup(os.environ.pop, "TPM2TOOLS_TCTI", None)
        node = self.d + "/node"
        os.mkdir(node)
        attest.node_init(node)
        with open(node + "/ek.pub", "rb") as f:
            ek = f.read()
        with open(node + "/ak.pub", "rb") as f:
            ak = f.read()
        policy = {"schema": attest.POLICY_SCHEMA, "nodes": {"a": {
            "tpm_firmware_version": "00" * 8, "pcrs": {"7": "00" * 32},
            "ek_name": attest.name_of(attest.public_area(ek, "the EK")).hex()}}}
        verifier = attest.Verifier(policy, self.d + "/attest.json")
        with open(self.d + "/cred", "wb") as f:
            f.write(verifier.challenge("a", ek, ak))
        attest.node_activate(self.d + "/cred", self.d + "/secret")       # three processes, one session
        with open(self.d + "/secret", "rb") as f:
            verifier.enroll("a", f.read())
        with open(self.d + "/attest.json") as f:
            self.assertIn(ak.hex(), f.read(), "the AK was not enrolled")


if __name__ == "__main__":
    unittest.main()
