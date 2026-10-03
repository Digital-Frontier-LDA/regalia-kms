"""regalia-node enrol init (#190), on a software TPM: the keys are made on the host, the bundle names them,
nothing that this enrolment did not make is touched, and a crash at any call is finished by running it again."""
import base64
import datetime
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, enrol


class Crash(BaseException):
    """A kill: not an Exception, so nothing in the code under test can catch it."""


class InitOnSwtpm(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createek", "wg", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools, wireguard-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools, wireguard-tools and openssl")
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
        self.dir, self.wg = self.d + "/enrol", self.d + "/etc/wg-service.key"

    def init(self, run=subprocess.run, node_id="a"):
        return enrol.init(node_id, self.dir, self.wg, run=run, out=io.StringIO())

    def test_init_makes_the_keys_on_the_host_and_names_them_in_the_bundle(self):
        bundle = self.init()
        self.assertEqual(bundle["schema"], enrol.SCHEMA_BUNDLE)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        for path in (self.wg, self.dir + "/wg-boot.key"):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, path)
        with open(self.dir + "/ak.pub", "rb") as f:
            self.assertEqual(attest.name_of(attest.public_area(f.read(), "ak")).hex(), bundle["ak_name"])
        self.assertIsNone(bundle["ek_certificate"])            # a plain swtpm carries none
        on_disk = json.load(open(self.dir + "/bundle.json"))
        self.assertEqual(on_disk, bundle)
        self.assertNotIn(open(self.wg).read().strip(), json.dumps(on_disk), "a private key reached the bundle")
        # the same command again: the same keys, nothing new
        self.assertEqual(self.init(), bundle)
        # a key it made and recorded, gone since: refused, not made again behind the bundle's back
        subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", attest.AK_HANDLE], check=True, capture_output=True)
        with self.assertRaisesRegex(enrol.Refused, "no longer in the TPM"):
            self.init()

    def test_what_this_enrolment_did_not_make_is_refused_and_left_alone(self):
        os.mkdir(self.d + "/other")
        attest.node_init(self.d + "/other")                    # an EK and AK that are not this enrolment's
        with self.assertRaisesRegex(enrol.Refused, "persistent object at .*replacement \\(#76\\)"):
            self.init()
        self.assertIn(attest.AK_HANDLE.lower(), enrol.persistent_handles(subprocess.run))
        # a WG-SERVICE key it did not make
        shutil.rmtree(self.d + "/enrol")
        for handle in (attest.AK_HANDLE, attest.EK_HANDLE):
            subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", handle], check=True, capture_output=True)
        os.makedirs(os.path.dirname(self.wg))
        with open(self.wg, "w") as f:
            f.write("somebody's key\n")
        with self.assertRaisesRegex(enrol.Refused, "already exists and this enrolment did not make it"):
            self.init()
        self.assertEqual(open(self.wg).read(), "somebody's key\n")
        # and one host is one node
        os.unlink(self.wg)
        self.init()
        with self.assertRaisesRegex(enrol.Refused, "started as node 'a', not 'b'"):
            self.init(node_id="b")

    def test_a_crash_at_any_call_is_finished_by_running_init_again(self):
        calls = []
        self.init(run=lambda argv, *a, **k: (calls.append(argv[0]), subprocess.run(argv, *a, **k))[1])
        total = len(calls)
        self.assertGreater(total, 8)
        for k in range(1, total + 1):
            with self.subTest(crash_at=k):
                shutil.rmtree(self.dir, True)
                if os.path.exists(self.wg):
                    os.unlink(self.wg)
                for handle in (attest.AK_HANDLE, attest.EK_HANDLE):
                    subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", handle], capture_output=True)
                seen = []

                def crashing(argv, *a, **kw):
                    seen.append(argv)
                    if len(seen) == k:
                        raise Crash()
                    return subprocess.run(argv, *a, **kw)
                with self.assertRaises(Crash):
                    self.init(run=crashing)
                # what a host's resource manager does when the killed process's connection closes: a bare
                # swtpm keeps the transient objects the interrupted call loaded
                subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
                bundle = self.init()                            # run again, as an operator would
                with open(self.dir + "/ak.pub", "rb") as f:
                    self.assertEqual(attest.name_of(attest.public_area(f.read(), "ak")).hex(), bundle["ak_name"])
                self.assertEqual(enrol._wg_public_of(self.wg, subprocess.run), bundle["wg_service_pub"])
                self.assertEqual(enrol._wg_public_of(self.dir + "/wg-boot.key", subprocess.run), bundle["wg_boot_pub"])

    def _plant_certificate(self, key_pem_path):
        """A certificate for the key in key_pem_path, signed by a throwaway CA, at the RSA EK cert index."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        ca = ec.generate_private_key(ec.SECP256R1())
        with open(key_pem_path, "rb") as f:
            subject_key = serialization.load_pem_public_key(f.read())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test TPM manufacturer")])
        now = datetime.datetime.now(datetime.timezone.utc)
        der = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(name).public_key(subject_key)
               .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.SubjectAlternativeName([x509.DirectoryName(name)]), critical=True)
               .sign(ca, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
        with open(self.d + "/cert.der", "wb") as f:
            f.write(der)
        subprocess.run(["tpm2_nvdefine", "0x01c00002", "-C", "o", "-s", str(len(der)),
                        "-a", "ownerread|ownerwrite|authread|authwrite"], check=True, capture_output=True)
        subprocess.run(["tpm2_nvwrite", "0x01c00002", "-C", "o", "-i", self.d + "/cert.der"], check=True, capture_output=True)
        return der

    def test_an_ek_certificate_must_certify_this_ek(self):
        # the EK is derived from the TPM's seed: made transiently here, it is the key init will persist
        subprocess.run(["tpm2_createek", "-c", self.d + "/ek.ctx", "-G", "rsa", "-u", self.d + "/ek.pub"], check=True, capture_output=True)
        subprocess.run(["tpm2_readpublic", "-c", self.d + "/ek.ctx", "-f", "pem", "-o", self.d + "/ek.pem"], check=True, capture_output=True)
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        der = self._plant_certificate(self.d + "/ek.pem")
        bundle = self.init()
        self.assertEqual(base64.b64decode(bundle["ek_certificate"]["der"]), der)
        self.assertTrue(bundle["ek_certificate"]["certifies_this_ek"])

    def test_a_certificate_for_another_key_is_refused(self):
        subprocess.run(["openssl", "genrsa", "-out", self.d + "/other.key", "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", self.d + "/other.key", "-pubout", "-out", self.d + "/other.pem"], check=True, capture_output=True)
        self._plant_certificate(self.d + "/other.pem")
        with self.assertRaisesRegex(enrol.Refused, "certifies another key than this TPM's EK"):
            self.init()


if __name__ == "__main__":
    unittest.main()
