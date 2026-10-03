"""regalia-node enrol init (#190), on a software TPM: the keys are made on the host, the bundle names them,
nothing that this enrolment did not make is touched, and a crash at any call is finished by running it again."""
import base64
import copy
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
        # root's umask on a host; under a looser one the directories the tests make would be group-writable,
        # and enrolment refuses to write below those (_check_ancestor)
        self.addCleanup(os.umask, os.umask(0o022))
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
        foreign = enrol._name_at(attest.AK_HANDLE, self.d, subprocess.run)
        self.assertEqual(json.load(open(self.d + "/enrol/journal.json"))["steps"], {}, "the refusal wrote a step")
        # a "started" journal does not license evicting an AK whose Name it never recorded
        with open(self.d + "/enrol/journal.json") as f:
            journal = json.load(f)
        journal["steps"]["identity"] = {"state": "started", "at": 0}
        with open(self.d + "/enrol/journal.json", "w") as f:
            json.dump(journal, f)
        with self.assertRaisesRegex(enrol.Refused, "persistent object at 0x81010002"):
            self.init()
        self.assertEqual(enrol._name_at(attest.AK_HANDLE, self.d, subprocess.run), foreign, "a foreign AK was evicted")
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

    def _plant(self, index, data):
        with open(self.d + "/nv.bin", "wb") as f:
            f.write(data)
        subprocess.run(["tpm2_nvdefine", index, "-C", "o", "-s", str(len(data)),
                        "-a", "ownerread|ownerwrite|authread|authwrite"], check=True, capture_output=True)
        subprocess.run(["tpm2_nvwrite", index, "-C", "o", "-i", self.d + "/nv.bin"], check=True, capture_output=True)

    def _certificate(self, key_pem_path, ends_in_zero=False):
        """DER of a certificate for the key in key_pem_path, by a throwaway CA; with ends_in_zero, one whose
        last byte is 0x00 (about one signature in 256 is), which a NUL-stripping reader would truncate."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        with open(key_pem_path, "rb") as f:
            subject_key = serialization.load_pem_public_key(f.read())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test TPM manufacturer")])
        now = datetime.datetime.now(datetime.timezone.utc)
        for serial in range(1, 5000):
            ca = ec.generate_private_key(ec.SECP256R1())
            der = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(name).public_key(subject_key)
                   .serial_number(serial).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                   .sign(ca, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
            if not ends_in_zero or der[-1] == 0:
                return der
        self.fail("no certificate ending in 00 was made")

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


    def _this_ek_pem(self):
        subprocess.run(["tpm2_createek", "-c", self.d + "/ek.ctx", "-G", "rsa", "-u", self.d + "/ek.pub"], check=True, capture_output=True)
        subprocess.run(["tpm2_readpublic", "-c", self.d + "/ek.ctx", "-f", "pem", "-o", self.d + "/ek.pem"], check=True, capture_output=True)
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        return self.d + "/ek.pem"

    def test_a_certificate_ending_in_a_zero_byte_is_read_whole_and_padding_is_allowed(self):
        der = self._certificate(self._this_ek_pem(), ends_in_zero=True)
        self._plant("0x01c00002", der + b"\x00" * 7)
        bundle = self.init()
        self.assertEqual(base64.b64decode(bundle["ek_certificate"]["der"]), der)

    def test_a_certificate_that_is_there_but_unreadable_is_a_refusal_not_an_absence(self):
        der = self._certificate(self._this_ek_pem())
        for name, data in (("truncated", der[:-10]), ("not padding after it", der + b"\x01\x02"),
                           ("not DER", b"\x00" * 64), ("a broken body", der[:20] + b"\x00" * (len(der) - 20))):
            with self.subTest(name=name):
                subprocess.run(["tpm2_nvundefine", "0x01c00002", "-C", "o"], capture_output=True)
                subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", attest.AK_HANDLE], capture_output=True)
                shutil.rmtree(self.dir, True)
                self._plant("0x01c00002", data)
                with self.assertRaises(enrol.Refused) as caught:
                    self.init()
                self.assertIn("0x01c00002", str(caught.exception))

    def test_an_ecc_only_tpm_is_not_refused(self):
        """The ECC EK certificate certifies the ECC EK, which this enrolment does not use: recorded, not judged."""
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", self.d + "/ecc.key"], check=True, capture_output=True)
        subprocess.run(["openssl", "ec", "-in", self.d + "/ecc.key", "-pubout", "-out", self.d + "/ecc.pem"], check=True, capture_output=True)
        self._plant("0x01c0000a", self._certificate(self.d + "/ecc.pem"))
        bundle = self.init()
        self.assertIsNone(bundle["ek_certificate"])
        self.assertTrue(json.load(open(self.dir + "/journal.json"))["steps"]["ek_certificate"]["ecc_certificate_present"])

    def test_resume_refuses_what_appeared_at_its_handle_or_path_after_a_crash(self):
        """regalia-kms-1e's reproductions on #234: a crash, then something foreign at our AK handle or our key
        path; the rerun must refuse and leave it, not evict or unlink it."""
        def crash_at(word):
            def run(argv, *a, **kw):
                if argv[0] == word or argv[:2] == ["wg", word]:
                    raise Crash()
                return subprocess.run(argv, *a, **kw)
            return run
        # (A) killed at tpm2_createak, then a foreign AK at 0x81010002
        with self.assertRaises(Crash):
            self.init(run=crash_at("tpm2_createak"))
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        os.mkdir(self.d + "/foreign")
        subprocess.run(["tpm2_createak", "-C", attest.EK_HANDLE, "-c", self.d + "/foreign/ak.ctx", "-G", "ecc", "-g", "sha256",
                        "-s", "ecdsa", "-u", self.d + "/foreign/ak.pub"], check=True, capture_output=True)
        subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", self.d + "/foreign/ak.ctx", attest.AK_HANDLE], check=True, capture_output=True)
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        foreign = enrol._name_at(attest.AK_HANDLE, self.d, subprocess.run)
        with self.assertRaisesRegex(enrol.Refused, "persistent object at 0x81010002"):
            self.init()
        self.assertEqual(enrol._name_at(attest.AK_HANDLE, self.d, subprocess.run), foreign)
        subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", attest.AK_HANDLE], check=True, capture_output=True)
        # (B) killed at `wg genkey` for the WG-SERVICE key, then somebody's key at its path
        with self.assertRaises(Crash):
            self.init(run=crash_at("genkey"))
        os.makedirs(os.path.dirname(self.wg), exist_ok=True)
        with open(self.wg, "w") as f:
            f.write("somebody's key\n")
        with self.assertRaisesRegex(enrol.Refused, "already exists and this enrolment did not make it"):
            self.init()
        self.assertEqual(open(self.wg).read(), "somebody's key\n")
        # ...and after the public half was journalled: a DIFFERENT valid key there is still not ours
        os.unlink(self.wg)
        journal = json.load(open(self.dir + "/journal.json"))
        private, public = enrol._wg_pair(subprocess.run)
        journal["steps"]["wg_service"] = {"state": "started", "at": 0, "public": public}
        with open(self.dir + "/journal.json", "w") as f:
            json.dump(journal, f)
        other, _ = enrol._wg_pair(subprocess.run)
        with open(self.wg, "w") as f:
            f.write(other + "\n")
        with self.assertRaisesRegex(enrol.Refused, "already exists and this enrolment did not make it"):
            self.init()
        self.assertEqual(open(self.wg).read(), other + "\n")
        # and the key it recorded IS removed and made again
        with open(self.wg, "w") as f:
            f.write(private + "\n")
        bundle = self.init()
        self.assertNotEqual(bundle["wg_service_pub"], public)

    def test_the_enrolment_directory_must_be_safe(self):
        os.symlink(self.d + "/elsewhere", self.dir)
        os.mkdir(self.d + "/elsewhere")
        with self.assertRaisesRegex(enrol.Refused, "not a real directory"):
            self.init()
        os.unlink(self.dir)
        # a sticky world-writable parent (/tmp, 1777) with our own entry below it is safe
        os.chmod(self.d, 0o1777)
        try:
            self.init()
        finally:
            os.chmod(self.d, 0o700)
        shutil.rmtree(self.dir)
        for handle in (attest.AK_HANDLE,):
            subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", handle], capture_output=True)
        os.unlink(self.wg)
        os.chmod(self.d, 0o775)
        try:
            with self.assertRaisesRegex(enrol.Refused, "closed to group and others"):
                self.init()
        finally:
            os.chmod(self.d, 0o700)


    def test_under_a_sticky_parent_only_our_own_entry_is_trusted(self):
        """The rule #233's gate uses (admission.ancestorsTrusted): a world-writable sticky ancestor is
        trusted only if the entry below it, on our path, is owned by root or by us. A foreign owner could
        rename or remove that entry, and so swap the enrolment directory."""
        os.mkdir(self.dir, 0o700)
        os.chmod(self.d, 0o1777)
        self.addCleanup(os.chmod, self.d, 0o700)
        real, ino = os.fstat, os.lstat(self.dir).st_ino

        def foreign_child(fd):
            st = real(fd)
            if st.st_ino == ino:
                return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, 65534, st.st_gid,
                                       st.st_size, int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
            return st
        with unittest.mock.patch.object(enrol.os, "fstat", foreign_child):
            with self.assertRaisesRegex(enrol.Refused, "nor a sticky one|not a real directory owned"):
                enrol._safe_directory(self.dir)
        enrol._safe_directory(self.dir)          # our own entry under the sticky parent: trusted


    def test_commit_anchors_the_checked_chain_on_this_tpm(self):
        """init, then commit with a root-signed manifest that names this host: the configuration installed and
        the anchor, the store and the heartbeat counter set up on THIS TPM (in-process here; on a host, as
        regalia-sync through runuser)."""
        import tests.test_baremetal_heartbeat as hbt
        import tests.test_baremetal_node as nt
        import tests.test_baremetal_replacement as rt
        from deploy.baremetal import measurements
        from deploy.baremetal import membership as m
        bundle = self.init()
        etc = self.d + "/etc-regalia/"
        os.makedirs(etc)
        entry = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}
        document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {n: {"accepted": [entry]} for n in "abc"}}
        man = hbt.manifest()
        man["policy_version"] = measurements.version(document)
        man["nodes"][0].update(ek_name=bundle["ek_name"], ak_name=bundle["ak_name"],
                               wg_service_pub=base64.b64decode(bundle["wg_service_pub"]).hex(),
                               wg_boot_pub=base64.b64decode(bundle["wg_boot_pub"]).hex())
        root = hbt.pub(hbt.ROOT)
        example = {"schema": "regalia.node/v1", "node_id": "x", "site": etc + "site.json", "root_key": "00" * 32,
                   "tcti": os.environ["TPM2TOOLS_TCTI"], "nv_epoch": "0x01500016", "nv_heartbeat": "0x01500018",
                   "state_dir": self.d + "/state", "admission_dir": self.d + "/admission", "run_dir": self.d + "/run",
                   "wg_service_key": self.wg, "measurements": etc + "measurements.json", "pcrs": [7, 11],
                   "time_servers": ["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"], "pull_interval": 60}
        with unittest.mock.patch.object(enrol, "CONFIG_DIR", etc), unittest.mock.patch.object(enrol, "NODE_JSON", etc + "node.json"):
            in_process = lambda config, chain: enrol.anchor_and_store(config, chain)   # noqa: E731
            epoch, digest = enrol.commit(self.dir, rt.sign(man), root, enrol.fingerprint(root), document, nt.SITE, example,
                                         as_sync=in_process, out=io.StringIO())
            self.assertEqual((epoch, digest), (1, m.digest(man)))
            hw = m.HighWater("0x01500016", os.environ["TPM2TOOLS_TCTI"], lock_path=self.d + "/state/highwater.lock")
            self.assertEqual((hw.value(), hw.record()), (1, (1, digest)))
            # the commit re-checks: a manifest for another host is refused before anything is written again
            other = copy.deepcopy(man)
            other["nodes"][0]["ak_name"] = "000b" + "77" * 32
            with self.assertRaisesRegex(enrol.Refused, "manifest's ak_name for a is not this host's"):
                enrol.commit(self.dir, rt.sign(other), root, enrol.fingerprint(root), document, nt.SITE, example,
                             as_sync=in_process, out=io.StringIO())
            # and run again with the same inputs, it changes nothing
            self.assertEqual(enrol.commit(self.dir, rt.sign(man), root, enrol.fingerprint(root), document, nt.SITE, example,
                                          as_sync=in_process, out=io.StringIO()), (1, digest))


if __name__ == "__main__":
    unittest.main()
