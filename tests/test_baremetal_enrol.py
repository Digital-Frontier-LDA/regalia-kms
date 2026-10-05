"""regalia-node enrol init (#190), on a software TPM: the keys are made on the host, the bundle names them,
nothing that this enrolment did not make is touched, and a crash at any call is finished by running it again."""
import base64
import copy
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from deploy.baremetal import attest, enrol, membership, signkey


def _rsa_pem():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


SYSTEM_PUB, OTHER_PUB = _rsa_pem(), _rsa_pem()          # the system-phase PCR key the signing key is made for, and another
TOKENS = ["DENK0500001", "35718625"]                    # a SmartCard-HSM's PKCS#11 serial and a YubiKey's


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
        # swtpm --daemon writes its pid file after the fork: wait for it (a loaded runner can take more than 0.5 s)
        deadline = time.monotonic() + 10
        while True:
            try:
                with open(self.d + "/pid") as f:
                    pid = int(f.read())
                break
            except (FileNotFoundError, ValueError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.addCleanup(lambda: os.kill(pid, 15))
        patcher = unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI="swtpm:path=" + sock)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.dir, self.wg = self.d + "/enrol", self.d + "/etc/wg-service.key"
        # the host's tokens, stood in for: a test never reaches a card on the machine that runs it
        patcher = unittest.mock.patch.object(enrol, "token_serials", lambda module, run=None: list(TOKENS))
        patcher.start()
        self.addCleanup(patcher.stop)

        self.ssh = self.d + "/ssh_host_ed25519_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", self.ssh], check=True)

    def init(self, run=subprocess.run, node_id="a", system_pub=None):
        return enrol.init(node_id, system_pub or SYSTEM_PUB, self.dir, self.wg, run=run, out=io.StringIO(), ssh_host_key=self.ssh + ".pub")

    def test_init_makes_the_keys_on_the_host_and_names_them_in_the_bundle(self):
        bundle = self.init()
        self.assertEqual(bundle["schema"], enrol.SCHEMA_BUNDLE)
        self.assertEqual(bundle["hsm_serials"], TOKENS, "#363: the tokens' serials, read at init")
        keep, activation = self.proven(bundle)
        self.assertEqual(enrol.entry(bundle, SYSTEM_PUB, keep, activation)["hsm_serials"], TOKENS)
        with open(self.ssh + ".pub") as f:
            raw = base64.b64decode(f.read().split()[1])[-32:].hex()
        self.assertEqual((bundle["ssh_host_pub"], enrol.entry(bundle, SYSTEM_PUB, keep, activation)["ssh_host_pub"]), (raw, raw),
                         "the host's SSH key, read at init, as the manifest carries it")
        with self.assertRaisesRegex(enrol.Refused, "it was made before #371"):
            enrol.entry({k: v for k, v in bundle.items() if k != "ssh_host_pub"}, SYSTEM_PUB, keep, activation)
        os.rename(self.ssh + ".pub", self.ssh + ".pub.kept")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", self.d + "/other"], check=True)
        os.rename(self.d + "/other.pub", self.ssh + ".pub")
        with self.assertRaisesRegex(enrol.Refused, "this host's SSH host key \\([0-9a-f]{64}\\) is not the one this enrolment recorded"):
            self.init()
        os.replace(self.ssh + ".pub.kept", self.ssh + ".pub")
        with unittest.mock.patch.object(enrol, "token_serials", lambda module, run=None: ["DENK0599999", "35718625"]):
            with self.assertRaisesRegex(enrol.Refused, "not the ones this enrolment recorded"):
                self.init()
        with self.assertRaisesRegex(enrol.Refused, "it was made before #363"):
            enrol.entry({k: v for k, v in bundle.items() if k != "hsm_serials"}, SYSTEM_PUB, keep, activation)
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

    def proven(self, bundle, rand=os.urandom):
        """The AK's proof, as the ceremony runs it: `challenge` on the root's side, `activate` on this host's TPM."""
        credential, keep = enrol.challenge(bundle, rand=rand)
        return keep, enrol.activate(credential, bundle)

    def test_the_ak_is_proven_to_be_in_the_ek_s_tpm_before_its_certification_counts(self):
        """CodeRabbit on #358: the AK's certification of the signing key is worth something only once the AK is shown to be
        in the TPM the EK names (credential activation). Without the right answer, entry prints nothing."""
        bundle = self.init()
        keep, activation = self.proven(bundle)
        self.assertNotIn(activation["answer"], json.dumps(keep), "the root's machine keeps the secret itself")
        self.assertEqual(enrol.entry(bundle, SYSTEM_PUB, keep, activation)["node_id"], "a")
        with self.assertRaisesRegex(enrol.Refused, "the answer is not the challenge's secret"):
            enrol.entry(bundle, SYSTEM_PUB, keep, dict(activation, answer="00" * 32))
        with self.assertRaisesRegex(enrol.Refused, "the activation's answer is not 64 hex"):
            enrol.entry(bundle, SYSTEM_PUB, keep, dict(activation, answer=None))
        with self.assertRaisesRegex(enrol.Refused, "a bare answer, from before #399, is not taken"):
            enrol.entry(bundle, SYSTEM_PUB, keep, activation["answer"])
        other_keep = dict(keep, ak_name="000b" + "11" * 32)
        with self.assertRaisesRegex(enrol.Refused, "made for another bundle"):
            enrol.entry(bundle, SYSTEM_PUB, other_keep, activation)
        # a bundle naming an AK its public area is not: no challenge is made for it
        with self.assertRaisesRegex(enrol.Refused, "the bundle's AK Name is not its AK's"):
            enrol.challenge(dict(bundle, ak_name="000b" + "22" * 32))
        # a credential made to another AK under this EK (one the TPM holds no persistent object for at the AK handle):
        # this host's TPM releases nothing for it
        other = self.d + "/other-ak"
        subprocess.run(["tpm2_createak", "-C", attest.EK_HANDLE, "-c", other + ".ctx", "-G", "ecc", "-g", "sha256", "-s", "ecdsa",
                        "-u", other + ".pub"], check=True, capture_output=True)
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        with open(other + ".pub", "rb") as f:
            other_ak = f.read()
        credential, _ = enrol.challenge(dict(bundle, ak_public=other_ak.hex(), ak_name=attest.name_of(attest.public_area(other_ak, "ak")).hex()))
        with self.assertRaises(attest.Refused):
            enrol.activate(credential, bundle)

    def test_the_ak_quotes_the_whole_identity_bound_to_this_challenge(self):
        """#399 (regalia-kms-d9's read): `activate` has the AK quote PCRs 7 and 11 over the bundle's identity fields, bound to
        THIS challenge's secret. A field changed on the way, a quote from an earlier challenge, or PCR values that are
        not the quoted ones are refused, each by its own guard; the values are the TPM's own."""
        bundle = self.init()
        keep, activation = self.proven(bundle)
        got, pcrs = enrol.proven_entry(bundle, SYSTEM_PUB, keep, activation)
        out = self.d + "/pcrs"
        subprocess.run(["tpm2_pcrread", "sha256:7,11", "-o", out], check=True, capture_output=True)
        with open(out, "rb") as f:
            raw = f.read()
        self.assertEqual(pcrs, {"7": raw[:32].hex(), "11": raw[32:].hex()})
        other_wg = base64.b64encode(bytes(range(32))).decode()
        for field, value in (("wg_service_pub", other_wg), ("wg_boot_pub", other_wg), ("hsm_serials", ["DENK0599999"]),
                             ("ssh_host_pub", "ab" * 32), ("signing_key", "04" + "cd" * 64)):
            with self.subTest(changed=field), self.assertRaisesRegex(attest.Refused, "the quote does not sign this identity under this challenge"):
                enrol.entry(dict(bundle, **{field: value}), SYSTEM_PUB, keep, activation)
        # a second ceremony's challenge: the first activation's quote does not answer it, though this TPM made both
        keep2, activation2 = self.proven(bundle)
        with self.assertRaisesRegex(attest.Refused, "the quote does not sign this identity under this challenge"):
            enrol.entry(bundle, SYSTEM_PUB, keep2, dict(activation2, quote=activation["quote"], signature=activation["signature"]))
        real = activation["pcr_values"]["11"]                            # a fresh swtpm's PCR 11 may be all zeros: flip it
        moved = dict(activation["pcr_values"], **{"11": ("ff" if real[:2] != "ff" else "00") + real[2:]})
        with self.assertRaisesRegex(attest.Refused, "the reported PCR values do not match the quote"):
            enrol.entry(bundle, SYSTEM_PUB, keep, dict(activation, pcr_values=moved))
        with self.assertRaisesRegex(enrol.Refused, "the activation is another node's \\(b\\)"):
            enrol.entry(bundle, SYSTEM_PUB, keep, dict(activation, node_id="b"))
        with self.assertRaisesRegex(membership.Refused, "the activation fields mismatch"):
            enrol.entry(bundle, SYSTEM_PUB, keep, dict(activation, note="x"))
        # quotes this TPM's AK made for something else: an enrolment record's (#190) over the same payload, and an identity
        # quote over another PCR selection. Neither stands in for the identity quote.
        secret_sha = hashlib.sha256(bytes.fromhex(activation["answer"])).digest()
        q, sg = self.d + "/q", self.d + "/s"
        for make, reason in ((lambda: attest.quote_document(enrol.identity_payload(bundle), list(enrol.IDENTITY_PCRS), q, sg),
                              "the quote does not sign this identity under this challenge"),
                             (lambda: attest.quote_identity(enrol.identity_payload(bundle), secret_sha, [7], q, sg),
                              "the identity quote covers PCRs \\[7\\], not \\[7, 11\\]")):
            for path in (q, sg):
                if os.path.exists(path):
                    os.unlink(path)
            make()
            with open(q, "rb") as fq, open(sg, "rb") as fs:
                forged = dict(activation, quote=fq.read().hex(), signature=fs.read().hex())
            with self.subTest(reason=reason), self.assertRaisesRegex((attest.Refused, enrol.Refused), reason):
                enrol.entry(bundle, SYSTEM_PUB, keep, forged)

    def test_commit_rechecks_the_signing_key_before_it_writes(self):
        """CodeRabbit on #358: commit re-checks the signing key at its handle by the Name the journal recorded, and that
        bundle.json still names it, before its first write."""
        self.init()
        journal = enrol.Journal(self.dir, "a")
        enrol.recheck_signing_key(journal, self.dir, subprocess.run)
        with open(self.dir + "/bundle.json") as f:
            bundle = json.load(f)
        with open(self.dir + "/bundle.json", "w") as f:
            json.dump(dict(bundle, signing_key="04" + "ab" * 64), f)
        with self.assertRaisesRegex(enrol.Refused, "bundle.json names another signing key"):
            enrol.recheck_signing_key(journal, self.dir, subprocess.run)
        with open(self.dir + "/bundle.json", "w") as f:
            json.dump(bundle, f)
        subprocess.run(["tpm2_evictcontrol", "-C", "o", "-c", signkey.HANDLE], check=True, capture_output=True)
        with self.assertRaisesRegex(enrol.Refused, "no longer at 0x81010003: nothing was written"):
            enrol.recheck_signing_key(journal, self.dir, subprocess.run)

    def test_the_signing_key_is_made_certified_and_checked_as_the_root_checks_it(self):
        """#199: the bundle carries the signing key's public area and the AK's certification; `entry` (the root's side)
        accepts it only for the system-phase key the root names, and a second init keeps the same key."""
        bundle = self.init()
        keep, activation = self.proven(bundle)
        got = enrol.entry(bundle, SYSTEM_PUB, keep, activation)
        self.assertEqual(sorted(got), sorted(enrol.ENTRY_KEYS))
        self.assertEqual((got["node_id"], got["ek_name"], got["ak_name"]), ("a", bundle["ek_name"], bundle["ak_name"]))
        self.assertEqual(got["signing_key"], {"alg": "ecdsa-p256", "key": bundle["signing_key"]})
        self.assertEqual(self.init()["signing_key"], bundle["signing_key"])
        with self.assertRaisesRegex(membership.Refused, "not PolicyAuthorize of this system-phase PCR key"):
            enrol.entry(bundle, OTHER_PUB, keep, activation)
        with self.assertRaisesRegex(enrol.Refused, "made for another system-phase PCR key"):
            self.init(system_pub=OTHER_PUB)
        # a bundle whose signing key another TPM certified: the AK's signature does not cover it
        last = bundle["signing_public"][-2:]                    # always another byte: "00" over a "00" changed nothing (1 in 256)
        forged = dict(bundle, signing_public=bundle["signing_public"][:-2] + ("00" if last != "00" else "01"))
        with self.assertRaises(membership.Refused):
            enrol.entry(forged, SYSTEM_PUB, keep, activation)
        # another AK of this TPM, named consistently in the bundle (its Name recomputes): the certification is not its
        other = self.d + "/other-ak"
        subprocess.run(["tpm2_createak", "-C", attest.EK_HANDLE, "-c", other + ".ctx", "-G", "ecc", "-g", "sha256", "-s", "ecdsa",
                        "-u", other + ".pub"], check=True, capture_output=True)
        subprocess.run(["tpm2_flushcontext", "-t"], capture_output=True)
        with open(other + ".pub", "rb") as f:
            other_ak = f.read()
        swapped = dict(bundle, ak_public=other_ak.hex(), ak_name=attest.name_of(attest.public_area(other_ak, "ak")).hex())
        # proven as if its activation had passed (a fixed secret): the certification check still refuses it on its own
        secret = os.urandom(32)
        _, sw_keep = enrol.challenge(swapped, rand=lambda n: secret)
        with self.assertRaisesRegex(membership.Refused, "does not verify under the AK"):
            enrol.entry(swapped, SYSTEM_PUB, sw_keep, dict(activation, answer=secret.hex()))
        for k in ("signing_public", "signing_certify", "signing_sig"):
            with self.subTest(missing=k), self.assertRaisesRegex(enrol.Refused, "no %s: it was made before #199" % k):
                enrol.entry({x: v for x, v in bundle.items() if x != k}, SYSTEM_PUB, keep, activation)

    def test_a_signing_key_this_enrolment_did_not_make_is_refused_and_left_alone(self):
        foreign = signkey.create(OTHER_PUB)                      # somebody's key at the signing handle
        with self.assertRaisesRegex(enrol.Refused, "persistent object at 0x81010003"):
            self.init()
        self.assertEqual(signkey.public(), foreign)
        # "started" without a recorded Name does not license evicting it either
        with open(self.d + "/enrol/journal.json") as f:
            journal = json.load(f)
        journal["steps"]["signing_key"] = {"state": "started", "at": 0}
        with open(self.d + "/enrol/journal.json", "w") as f:
            json.dump(journal, f)
        with self.assertRaisesRegex(enrol.Refused, "persistent object at 0x81010003"):
            self.init()
        self.assertEqual(signkey.public(), foreign, "a foreign signing key was evicted")

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
                for handle in (attest.AK_HANDLE, attest.EK_HANDLE, signkey.HANDLE):
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
                self.assertEqual(signkey.identity(signkey.public(), SYSTEM_PUB)[1], bundle["signing_key"])
                keep, activation = self.proven(bundle)
                self.assertEqual(enrol.entry(bundle, SYSTEM_PUB, keep, activation)["signing_key"], {"alg": "ecdsa-p256", "key": bundle["signing_key"]})

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
                               wg_boot_pub=base64.b64decode(bundle["wg_boot_pub"]).hex(), hsm_serials=bundle["hsm_serials"])
        root = hbt.pub(hbt.ROOT)
        example = {"schema": "regalia.node/v1", "node_id": "x", "site": etc + "site.json", "root_key": "00" * 32,
                   "tcti": os.environ["TPM2TOOLS_TCTI"], "nv_epoch": "0x01500016", "nv_heartbeat": "0x01500018",
                   "nv_signing": "0x0150001c", "state_dir": self.d + "/state", "admission_dir": self.d + "/admission", "run_dir": self.d + "/run",
                   "wg_service_key": self.wg, "measurements": etc + "measurements.json", "pcrs": [7, 11],
                   "time_servers": ["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"], "pull_interval": 60, "beat_interval_s": 900}
        with unittest.mock.patch.object(enrol, "CONFIG_DIR", etc), unittest.mock.patch.object(enrol, "NODE_JSON", etc + "node.json"), \
                unittest.mock.patch.object(enrol, "CHRONY_CONF", self.d + "/etc-chrony/regalia.conf"):
            in_process = lambda config, chain: enrol.anchor_and_store(config, chain)   # noqa: E731

            def first_beat(config, bootstrap=False):      # the regalia-sync step, in process, with no source to ask
                from deploy.baremetal import node as nm
                n = nm.Node(nm.load(config))
                return enrol.take_first_heartbeat(n.node_id, n.store().load(), n.store(), n.freshness(), {}, lambda e: None, bootstrap)
            with self.assertRaisesRegex(enrol.Refused, "no peer gave a heartbeat"):
                enrol.commit(self.dir, rt.sign(man), root, enrol.fingerprint(root), document, nt.SITE, example,
                             as_sync=in_process, out=io.StringIO(), first_beat=first_beat)       # nobody answers: resumable
            epoch, digest = enrol.commit(self.dir, rt.sign(man), root, enrol.fingerprint(root), document, nt.SITE, example,
                                         as_sync=in_process, out=io.StringIO(), first_beat=first_beat, bootstrap=True)
            self.assertEqual((epoch, digest), (1, m.digest(man)))
            self.assertTrue(open(self.d + "/etc-chrony/regalia.conf").read().startswith("# Generated by deploy/baremetal/authtime.py"))
            hw = m.HighWater("0x01500016", os.environ["TPM2TOOLS_TCTI"], lock_path=self.d + "/state/highwater.lock")
            self.assertEqual((hw.value(), hw.record()), (1, (1, digest)))
            self.assertEqual(enrol.Journal(self.dir, "a").get("heartbeat_first")["bootstrap"], True)
            # the commit re-checks: a manifest for another host is refused before anything is written again
            other = copy.deepcopy(man)
            other["nodes"][0]["ak_name"] = "000b" + "77" * 32
            with self.assertRaisesRegex(enrol.Refused, "manifest's ak_name for a is not this host's"):
                enrol.commit(self.dir, rt.sign(other), root, enrol.fingerprint(root), document, nt.SITE, example,
                             as_sync=in_process, out=io.StringIO(), first_beat=first_beat)
            # and run again with the same inputs, it changes nothing
            self.assertEqual(enrol.commit(self.dir, rt.sign(man), root, enrol.fingerprint(root), document, nt.SITE, example,
                                          as_sync=in_process, out=io.StringIO(), first_beat=first_beat), (1, digest))


    def test_commit_under_v4_with_the_owner_authorization_set(self):
        """#420: the production enrolment, on a real TPM whose owner and lockout authorizations are set (#242). init on
        this TPM; the root's challenge, activate and entry; a v4 manifest naming this host; the measurements naming the
        image's system-phase key; the signed image booted. `enrol commit` without the owner authorization refuses before
        anything is written, and with it (from the envelope's record, under the root the fingerprint confirms) defines
        the anchor and the counters by policy, through the owner channel, and commits epoch 1."""
        import tests.test_baremetal_membership as tm
        import tests.test_baremetal_membership_v4 as v4
        import tests.test_baremetal_node as nt
        import tests.test_baremetal_ownerauth as toa
        from deploy.baremetal import measurements, ownerauth, signkey
        from deploy.baremetal import membership as m
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "e2e", "lib"))
        import signed_boot as sb
        tcti = os.environ["TPM2TOOLS_TCTI"]
        os.makedirs(self.d + "/keys")
        private, public = sb.key(self.d + "/keys")
        with open(public, "rb") as f:
            pem = f.read()
        serials = ["DENK0500001", "36000001"]                        # not bench tokens: a v4 chain refuses those
        with unittest.mock.patch.object(enrol, "token_serials", lambda module, run=None: list(serials)):
            bundle = self.init(system_pub=pem)
        keep, answer = self.proven(bundle)
        nodes = v4.nodes4()
        nodes[0] = dict(nodes[0], **enrol.entry(bundle, pem, keep, answer))
        # the signed image this host booted, and the measurements naming its system-phase key for every node
        image = sb.image("approved")
        signature, _ = sb.signature(image, private, public)
        with open(self.d + "/tpm2-pcr-signature.json", "w") as f:
            json.dump({"sha256": [signature]}, f)
        sb.boot(image)
        signed = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
                  "phases": {"initrd": {"11": "a1" * 32}, "system": {"11": "b1" * 32}},
                  "signing": {"initrd": "11" * 32, "system": signkey.pcr_key_fingerprint(pem), "secure_boot_cert": "22" * 32}}
        document = {"schema": measurements.SCHEMA, "name": "signed-images", "nodes": {n: {"accepted": [signed]} for n in "abc"}}
        man = v4.manifest4(1, "", nodes, policy_version=measurements.version(document))
        envelope, root = tm.sign(man, tm.ROOT), tm.ROOT_PUB
        # the TPM as production's: systemd's SRK persistent, then the owner and lockout authorizations set
        value = toa.VECTOR["values"]["a"][:64]
        for argv in (["tpm2_createprimary", "-C", "o", "-c", self.d + "/srk.ctx"],
                     ["tpm2_evictcontrol", "-C", "o", "-c", self.d + "/srk.ctx", ownerauth.SRK], ["tpm2_flushcontext", "-t"]):
            self.assertEqual(subprocess.run(argv, capture_output=True).returncode, 0, argv)
        for hierarchy in ("o", "l"):
            with open(self.d + "/auth", "w") as f:
                f.write("hex:" + value)
            self.assertEqual(subprocess.run(["tpm2_changeauth", "-c", hierarchy, "file:" + self.d + "/auth"], capture_output=True).returncode, 0)
        os.unlink(self.d + "/auth")
        record, record_root = toa.resigned(lambda r: None, key=tm.ROOT)     # the envelope's record, under this chain's root
        self.assertEqual(record_root, root)
        given = (ownerauth.read_value(io.BytesIO((value + "\n").encode())), record)
        etc = self.d + "/etc-regalia/"
        os.makedirs(etc)
        example = {"schema": "regalia.node/v1", "node_id": "x", "site": etc + "site.json", "root_key": "00" * 32, "tcti": tcti,
                   "nv_epoch": "0x01500016", "nv_heartbeat": "0x01500018", "nv_signing": "0x0150001c", "state_dir": self.d + "/state",
                   "admission_dir": self.d + "/admission", "run_dir": self.d + "/run", "wg_service_key": self.wg,
                   "measurements": etc + "measurements.json", "pcrs": [7, 11],
                   "time_servers": ["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"], "pull_interval": 60, "beat_interval_s": 900}

        def in_process(config, chain, owner_auth=None):         # the regalia-sync step, in process
            return enrol.anchor_and_store(config, chain, owner_auth=owner_auth)

        def first_beat(config, bootstrap=False, owner_auth=None):
            from deploy.baremetal import node as nm
            n = nm.Node(nm.load(config))
            return enrol.take_first_heartbeat(n.node_id, n.store().load(), n.store(), n.freshness(owner_auth), {}, lambda e: None, bootstrap)
        with unittest.mock.patch.object(enrol, "CONFIG_DIR", etc), unittest.mock.patch.object(enrol, "NODE_JSON", etc + "node.json"), \
                unittest.mock.patch.object(enrol, "CHRONY_CONF", self.d + "/etc-chrony/regalia.conf"), \
                unittest.mock.patch.object(signkey, "PCR_PUBLIC_KEY_PATH", public), \
                unittest.mock.patch.object(signkey, "PCR_SIGNATURE_PATHS", (self.d + "/tpm2-pcr-signature.json",)):
            with self.assertRaisesRegex(enrol.Refused, "under regalia.membership/v4 the TPM's owner authorization is set"):
                enrol.commit(self.dir, envelope, root, enrol.fingerprint(root), document, nt.SITE, example, as_sync=in_process,
                             out=io.StringIO(), first_beat=first_beat, bootstrap=True)
            listed = {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", subprocess.run(["tpm2_getcap", "handles-nv-index"],
                                                                                         capture_output=True, text=True).stdout)}
            enrolment = {int(example[k], 16) + d for k in ("nv_epoch", "nv_heartbeat", "nv_signing") for d in range(6)}
            self.assertEqual(listed & enrolment, set())          # nothing defined: no anchor, slot or counter index (1e)
            epoch, digest = enrol.commit(self.dir, envelope, root, enrol.fingerprint(root), document, nt.SITE, example,
                                         as_sync=in_process, out=io.StringIO(), first_beat=first_beat, bootstrap=True,
                                         ownerauth_given=given)
            self.assertEqual((epoch, digest), (1, m.digest(man)))
            listed = {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", subprocess.run(["tpm2_getcap", "handles-nv-index"],
                                                                                         capture_output=True, text=True).stdout)}
            self.assertTrue({int(example[k], 16) for k in ("nv_epoch", "nv_heartbeat", "nv_signing")} <= listed)   # the control
            public_area = subprocess.run(["tpm2_nvreadpublic", "0x01500016"], capture_output=True, text=True).stdout
            self.assertIn("authorization policy: %s" % signkey.policy(pem).hex().upper(), public_area)    # policy-written
            from deploy.baremetal import node as nm
            here = nm.Node(nm.load(etc + "node.json"))
            self.assertEqual((here.anchor().value(), here.anchor().record()), (1, (1, digest)))          # read with no auth
            self.assertEqual(enrol.Journal(self.dir, "a").get("heartbeat_first")["bootstrap"], True)


class Tokens(unittest.TestCase):
    """#363 (#72 G1): the serials the daemon compares, read from the devices in every form a backend pins: the
    SmartCard-HSM's PKCS#11 serial, the YubiKey's decimal serial (PIV) and its OpenPGP-applet PKCS#11 serial, never typed.
    The listings are the bench's, 2026-10-04 (Nitrokey DENK0404144, YubiKey 35718625, OpenSC 0.26)."""

    # OpenSC's default drivers: the YubiKey FIRST, as its PIV token (whose serial is not the YubiKey's), then the HSM
    SLOTS = ("Available slots:\n"
             "Slot 0 (0x4): Yubico YubiKey OTP+FIDO+CCID 01 00\n"
             "  token label        : PIV_II\n"
             "  token manufacturer : piv_II\n"
             "  serial num         : b9ab85b1d5d5846c\n"
             "Slot 1 (0x8): Nitrokey Nitrokey HSM (DENK04041440000         ) 02 00\n"
             "  token label        : regalia-staging\n"
             "  token manufacturer : www.CardContact.de\n"
             "  token model        : PKCS#15 emulated\n"
             "  serial num         : DENK0404144\n"
             "Slot 2 (0xc): Generic reader with no card 00 00\n"
             "  (empty)\n")
    # OpenSC told to use its openpgp driver only: the YubiKey's OpenPGP applet, two tokens under one serial
    OPENPGP = ("Available slots:\n"
               "Slot 0 (0x4): Yubico YubiKey OTP+FIDO+CCID 01 00\n"
               "  token label        : OpenPGP card (User PIN)\n"
               "  token manufacturer : Yubico\n"
               "  serial num         : 000635718625\n"
               "Slot 1 (0x5): Yubico YubiKey OTP+FIDO+CCID 01 00\n"
               "  token label        : OpenPGP card (User PIN (sig))\n"
               "  token manufacturer : Yubico\n"
               "  serial num         : 000635718625\n")

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def usb(self, yubikeys):
        """A sysfs USB tree with this many Yubico devices and one Nitrokey (20a0)."""
        root = tempfile.mkdtemp(dir=self.d)
        for i, vendor in enumerate(["20a0"] + ["1050"] * yubikeys):
            os.makedirs("%s/1-%d" % (root, i))
            with open("%s/1-%d/idVendor" % (root, i), "w") as f:
                f.write(vendor + "\n")
        return root

    def serials(self, run, yubikeys=1):
        return enrol.token_serials("m.so", run, usb_root=self.usb(yubikeys))

    def run_with(self, slots=SLOTS, ykman="35718625\n", openpgp=OPENPGP):
        def run(argv, env=None, **kw):
            if argv[0] == "pkcs11-tool":
                if env and env.get("OPENSC_CONF"):
                    with open(env["OPENSC_CONF"]) as f:
                        self.assertEqual(f.read(), enrol.OPENPGP_ONLY)
                    return subprocess.CompletedProcess(argv, 0, openpgp, "")
                return subprocess.CompletedProcess(argv, 0, slots, "")
            if argv[:2] == ["ykman", "list"]:
                return subprocess.CompletedProcess(argv, 0, ykman, "")
            raise AssertionError("no other tool reaches a card: %s" % argv)
        return run

    def test_the_hsm_and_the_yubikey_in_each_form(self):
        with unittest.mock.patch.object(enrol.shutil, "which", lambda t: "/usr/bin/" + t):
            self.assertEqual(self.serials(self.run_with()), ["DENK0404144", "35718625", "000635718625"])
            self.assertEqual(self.serials(self.run_with(openpgp="Available slots:\n")), ["DENK0404144", "35718625"],
                             "a YubiKey whose OpenPGP applet OpenSC does not present: its PIV form only")
            self.assertEqual(self.serials(self.run_with(ykman="", openpgp=""), 0), ["DENK0404144"], "no YubiKey (Pico alone)")

    def test_refusals(self):
        with unittest.mock.patch.object(enrol.shutil, "which", lambda t: "/usr/bin/" + t):
            two = self.SLOTS + self.SLOTS.replace("Slot 1", "Slot 3").replace("DENK0404144", "DENK0404380")
            with self.assertRaisesRegex(enrol.Refused, "2 SmartCard-HSM tokens are attached"):
                self.serials(self.run_with(slots=two))
            with self.assertRaisesRegex(enrol.Refused, "0 SmartCard-HSM tokens"):
                self.serials(self.run_with(slots="Available slots:\n"))
            with self.assertRaisesRegex(enrol.Refused, "appears twice"):
                self.serials(self.run_with(ykman="35718625\n35718625\n"), 2)
            with self.assertRaisesRegex(enrol.Refused, "not a YubiKey's"):
                self.serials(self.run_with(ykman="3571-8625\n"))
            with self.assertRaisesRegex(enrol.Refused, "an OpenPGP card is attached that is not one of this host's YubiKeys \\(000699999999\\)"):
                self.serials(self.run_with(openpgp=self.OPENPGP.replace("000635718625", "000699999999", 1)))
            with self.assertRaisesRegex(enrol.Refused, "not one the manifest can list"):
                self.serials(self.run_with(slots=self.SLOTS.replace("DENK0404144\n", "DENK-0404144\n")))
            with self.assertRaisesRegex(enrol.Refused, "2 YubiKeys are attached and ykman read 1 serials: a YubiKey's serial is not readable"):
                self.serials(self.run_with(), 2)
            with self.assertRaisesRegex(enrol.Refused, "1 YubiKeys are attached and ykman read 0 serials"):
                self.serials(self.run_with(ykman="", openpgp=""), 1)
        with unittest.mock.patch.object(enrol.shutil, "which", lambda t: None):
            with self.assertRaisesRegex(enrol.Refused, "a YubiKey is attached and ykman is not installed"):
                self.serials(self.run_with())
            self.assertEqual(self.serials(self.run_with(), 0), ["DENK0404144"])


class SshHostKey(unittest.TestCase):
    """#371: the manifest's ssh_host_pub, read from the host's own public key file."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def key_file(self, line):
        path = os.path.join(self.d, "k.pub")
        with open(path, "w") as f:
            f.write(line)
        return path

    def blob(self, *parts):
        return base64.b64encode(b"".join(len(p).to_bytes(4, "big") + p for p in parts)).decode()

    def test_an_ed25519_key_is_read_as_64_hex(self):
        self.assertEqual(enrol.ssh_host_pub(self.key_file("ssh-ed25519 %s root@a\n" % self.blob(b"ssh-ed25519", b"\x07" * 32))), "07" * 32)

    def test_refusals(self):
        with self.assertRaisesRegex(enrol.Refused, "is missing: this host has no Ed25519 SSH host key"):
            enrol.ssh_host_pub(os.path.join(self.d, "absent.pub"))
        for line, reason in (("ssh-rsa %s" % self.blob(b"ssh-rsa", b"\x01" * 32), "is not an ssh-ed25519 public key"),
                             ("ssh-ed25519", "is not an ssh-ed25519 public key"),
                             ("ssh-ed25519 !!!", "does not hold a base64 key"),
                             ("ssh-ed25519 %s" % self.blob(b"ssh-rsa", b"\x01" * 32), "does not hold exactly one 32-byte Ed25519 key"),
                             ("ssh-ed25519 %s" % self.blob(b"ssh-ed25519", b"\x01" * 31), "does not hold exactly one 32-byte Ed25519 key"),
                             ("ssh-ed25519 %s" % self.blob(b"ssh-ed25519", b"\x01" * 32, b"x"), "does not hold exactly one 32-byte Ed25519 key"),
                             ("ssh-ed25519 %s" % base64.b64encode(b"\x00\x00\x00\x40ssh").decode(), "does not hold exactly one 32-byte")):
            with self.subTest(line=line), self.assertRaisesRegex(enrol.Refused, reason):
                enrol.ssh_host_pub(self.key_file(line))


class ChronyPath(unittest.TestCase):
    def test_enrolment_and_authtime_install_chrony_s_configuration_in_one_place(self):
        from deploy.baremetal import authtime
        self.assertEqual(enrol.CHRONY_CONF, authtime.CHRONY_CONF)


if __name__ == "__main__":
    unittest.main()
