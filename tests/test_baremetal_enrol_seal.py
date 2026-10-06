"""regalia-node enrol, design step 4 of #190: the local contribution and the WG-BOOT key sealed to this TPM and the
initrd key, onto the ESP, never replacing a file; and the boot image they are sealed for, checked against the
measurements the manifest commits to. systemd-creds and uki.verify are stood in for; no TPM."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import enrol, measurements, unlock

PEM = b"-----BEGIN PUBLIC KEY-----\ninitrd-phase key\n-----END PUBLIC KEY-----\n"
WITH_PUBLIC_KEY = bytes.fromhex(next(k for k, v in unlock.LOCAL_KEY_TYPES.items() if v == "tpm2-with-public-key"))
HOST_KEY = bytes(16)


class Crash(BaseException):
    pass


class FakeCreds:
    """systemd-creds encrypt, as on a host as root: a credential with the tpm2-with-public-key header, new
    random bytes on every seal. `kind` = HOST_KEY is what it makes when it is not root."""

    def __init__(self, kind=WITH_PUBLIC_KEY):
        self.kind, self.calls = kind, []

    def __call__(self, argv, input=None, capture_output=False, **kw):
        assert argv[:2] == ["systemd-creds", "encrypt"], argv
        key = next(a.split("=", 1)[1] for a in argv if a.startswith("--tpm2-public-key="))
        with open(key, "rb") as f:
            self.calls.append({"argv": argv, "key": f.read(), "input": input})
        blob = base64.b64encode(self.kind + os.urandom(64)) + b"\n"
        return subprocess.CompletedProcess(argv, 0, blob, b"")


class Seal(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))     # root's umask on a host
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.dir, self.esp = self.d + "/enrol", self.d + "/esp"
        enrol._safe_directory(self.dir)
        enrol._ensure_trusted_dir(self.esp)
        self.journal = enrol.Journal(self.dir, "a")
        self.boot_key = os.path.join(self.dir, "wg-boot.key")
        self.wg_private = base64.b64encode(os.urandom(32)).decode()
        enrol._write_private(self.boot_key, (self.wg_private + "\n").encode())
        self.journal.done("wg_boot", public="(public)", path=self.boot_key)
        self.creds = self.esp + "/loader/credentials"

    def seal(self, run=None):
        return enrol.seal_credentials(self.journal, self.dir, self.esp, PEM, run or FakeCreds())

    def on_esp(self, name):
        with open(os.path.join(self.creds, name + ".cred"), "rb") as f:
            return f.read()

    def test_both_are_sealed_to_pcr7_and_the_initrd_key_and_recorded(self):
        run = FakeCreds()
        files = self.seal(run)
        self.assertEqual(sorted(files), ["regalia.unlock-local.cred", "regalia.wg-boot-key.cred"])
        for call in run.calls:
            self.assertEqual(call["key"], PEM)
            self.assertIn("--tpm2-pcrs=7", call["argv"])
            self.assertIn("--tpm2-public-key-pcrs=11", call["argv"])
            self.assertIn("--with-key=tpm2-with-public-key", call["argv"])
        names = {c["argv"][2]: c["input"] for c in run.calls}
        with open(os.path.join(self.dir, enrol.LOCAL_FILE), "rb") as f:
            local = f.read()
        self.assertEqual(names["--name=regalia.unlock-local"], local)
        self.assertEqual(len(local), unlock.SECRET_BYTES)
        self.assertEqual(names["--name=regalia.wg-boot-key"], (self.wg_private + "\n").encode())
        for filename, fact in files.items():
            data = self.on_esp(filename[:-5])
            self.assertEqual(fact, {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        self.assertFalse(os.path.exists(self.boot_key), "the WG-BOOT key in the clear is removed once sealed")
        self.assertEqual(sorted(os.listdir(self.creds)), ["regalia.unlock-local.cred", "regalia.wg-boot-key.cred"])
        self.assertEqual([n for n in os.listdir(self.esp + "/loader") if n.endswith(".enrol-new")], [])
        # again, as a resumed run: nothing is sealed again, the files are checked
        again = FakeCreds()
        self.assertEqual(self.seal(again), files)
        self.assertEqual(again.calls, [])

    def test_a_credential_already_on_the_esp_is_refused_and_left(self):
        os.makedirs(self.creds, exist_ok=True)
        with open(self.creds + "/regalia.unlock-local.cred", "wb") as f:
            f.write(b"someone else's\n")
        run = FakeCreds()
        with self.assertRaisesRegex(enrol.Refused, "this enrolment did not write it"):
            self.seal(run)
        self.assertEqual(self.on_esp("regalia.unlock-local"), b"someone else's\n")
        self.assertEqual(run.calls, [], "nothing is sealed for a name that is taken")
        self.assertTrue(os.path.exists(self.boot_key))

    def test_a_credential_sealed_with_the_host_key_is_refused_and_not_written(self):
        with self.assertRaisesRegex(enrol.Refused, "did not seal regalia.unlock-local to the TPM"):
            self.seal(FakeCreds(HOST_KEY))
        self.assertFalse(os.path.exists(self.creds + "/regalia.unlock-local.cred"))

    def test_a_crash_before_the_rename_is_sealed_again_on_resume(self):
        real = os.rename

        def crash(src, dst):                 # the publish only: the journal is written by rename too
            if dst.endswith(".cred"):
                raise Crash()
            return real(src, dst)
        with unittest.mock.patch.object(enrol.os, "rename", crash):
            with self.assertRaises(Crash):
                self.seal()
        self.assertFalse(os.path.exists(self.creds + "/regalia.unlock-local.cred"))
        self.assertEqual([n for n in os.listdir(self.esp + "/loader") if n.endswith(".enrol-new")], [".regalia.unlock-local.cred.enrol-new"])
        with unittest.mock.patch.object(enrol.os, "rename", real):
            files = self.seal()
        self.assertEqual(len(files), 2)
        self.assertEqual([n for n in os.listdir(self.esp + "/loader") if n.endswith(".enrol-new")], [])

    def test_a_crash_after_the_rename_keeps_what_was_published(self):
        real, published = os.rename, []

        def rename_then_crash(src, dst):
            real(src, dst)
            if dst.endswith(".cred"):
                published.append(dst)
                raise Crash()
        with unittest.mock.patch.object(enrol.os, "rename", rename_then_crash):
            with self.assertRaises(Crash):
                self.seal()
        first = self.on_esp("regalia.unlock-local")
        run = FakeCreds()
        files = self.seal(run)
        self.assertEqual(self.on_esp("regalia.unlock-local"), first, "the published file is this enrolment's (pending digest)")
        self.assertEqual([c["argv"][2] for c in run.calls], ["--name=regalia.wg-boot-key"])
        self.assertEqual(files["regalia.unlock-local.cred"]["sha256"], hashlib.sha256(first).hexdigest())

    def test_a_local_contribution_this_enrolment_did_not_make_is_refused(self):
        with open(os.path.join(self.dir, enrol.LOCAL_FILE), "wb") as f:
            f.write(os.urandom(32))
        with self.assertRaisesRegex(enrol.Refused, "this enrolment did not make it"):
            self.seal()

    def test_a_lost_local_contribution_is_made_again_and_resealed(self):
        """local.bin gone before the peers' paths use it: its sealed copy could never be paired with a path, so
        the enrolment makes a new one and reseals it, replacing only its own unlock-local.cred (no stranding)."""
        first = self.seal()
        boot_before = self.on_esp("regalia.wg-boot-key")
        os.unlink(os.path.join(self.dir, enrol.LOCAL_FILE))
        run = FakeCreds()
        files = self.seal(run)
        self.assertEqual([c["argv"][2] for c in run.calls], ["--name=regalia.unlock-local"])
        with open(os.path.join(self.dir, enrol.LOCAL_FILE), "rb") as f:
            self.assertEqual(run.calls[0]["input"], f.read())
        self.assertNotEqual(files["regalia.unlock-local.cred"], first["regalia.unlock-local.cred"])
        self.assertEqual(files["regalia.wg-boot-key.cred"], first["regalia.wg-boot-key.cred"])
        self.assertEqual(self.on_esp("regalia.wg-boot-key"), boot_before)
        self.assertEqual(self.journal.get("seal")["files"], files)

    def test_a_lost_local_contribution_with_a_foreign_sealed_file_is_refused(self):
        self.seal()
        os.unlink(os.path.join(self.dir, enrol.LOCAL_FILE))
        with open(self.creds + "/regalia.unlock-local.cred", "wb") as f:
            f.write(b"replaced by someone\n")
        with self.assertRaisesRegex(enrol.Refused, "not the one this enrolment sealed"):
            self.seal()
        self.assertEqual(self.on_esp("regalia.unlock-local"), b"replaced by someone\n")

    def test_a_lost_local_contribution_after_a_publish_whose_digest_was_still_pending_is_resealed(self):
        """regalia-kms-d9's LOW on #265: unlock-local.cred renamed in, the run killed before its digest moved from
        "pending:" to the file's key, then local.bin lost. The pending digest is exactly what this run published."""
        real = os.rename

        def rename_then_crash(src, dst):
            real(src, dst)
            if dst.endswith("regalia.unlock-local.cred"):
                raise Crash()
        with unittest.mock.patch.object(enrol.os, "rename", rename_then_crash):
            with self.assertRaises(Crash):
                self.seal()
        os.unlink(os.path.join(self.dir, enrol.LOCAL_FILE))
        files = self.seal()
        self.assertEqual(sorted(files), ["regalia.unlock-local.cred", "regalia.wg-boot-key.cred"])

    def test_no_reseal_once_the_enrolment_record_exists(self):
        """regalia-kms-d9 on #265: the record publishes PCR 12 to the peers; a reseal after it would strand the node."""
        self.seal()
        self.journal.done("record")
        os.unlink(os.path.join(self.dir, enrol.LOCAL_FILE))
        with self.assertRaisesRegex(enrol.Refused, "after the enrolment record was written"):
            self.seal()

    def test_a_clear_wg_boot_key_left_by_a_crash_is_removed_on_resume(self):
        self.seal()
        enrol._write_private(self.boot_key, (self.wg_private + "\n").encode())    # as if the unlink never ran
        self.seal()
        self.assertFalse(os.path.exists(self.boot_key))

    def test_a_changed_sealed_file_is_found_on_resume(self):
        self.seal()
        with open(self.creds + "/regalia.wg-boot-key.cred", "ab") as f:
            f.write(b"x")
        with self.assertRaisesRegex(enrol.Refused, "changed since this enrolment sealed it"):
            self.seal()


class ApprovedImage(unittest.TestCase):
    """The initrd key is the one the signed image verifies under, and the image is one the measurements accept."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.paths = {}
        self.signing = {"initrd": "1a" * 32, "system": "5b" * 32, "secure_boot_cert": "5c" * 32}
        self.record = {"schema": "stand-in", "signed": {"pcr_signatures": {"initrd": {"pkfp": "1a" * 32}, "system": {"pkfp": "5b" * 32}},
                                                         "secure_boot_cert_sha256": "5c" * 32}}
        for name, data in (("record", json.dumps(self.record).encode()), ("initrd", PEM), ("system", b"system key")):
            self.paths[name] = os.path.join(self.d, name)
            with open(self.paths[name], "wb") as f:
                f.write(data)
        self.pcr11 = {"initrd": "aa" * 32, "system": "bb" * 32}

    def document(self, pcr11, signing=True):
        entry = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32},
                 "phases": {phase: {"11": value} for phase, value in pcr11.items()}}
        if signing:
            entry["signing"] = self.signing if signing is True else signing
            entry["rootfs_sha256"] = "6e" * 32
        document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {"a": {"accepted": [entry]}}}
        measurements.validate(document)
        return document

    def approve(self, document, verify):
        with unittest.mock.patch("deploy.baremetal.uki.verify", verify):
            return enrol.approved_image("image.efi", self.paths["record"], self.paths["initrd"], self.paths["system"],
                                        "sb.crt", document, "a")

    def test_an_image_the_measurements_accept_gives_its_initrd_key(self):
        seen = {}

        def verify(image, record, keys, cert, run):
            seen.update(image=image, record=record, keys=keys, cert=cert)
            return dict(self.pcr11)
        self.assertEqual(self.approve(self.document(self.pcr11), verify), PEM)
        self.assertEqual(seen["keys"], {"initrd": PEM, "system": b"system key"})
        self.assertEqual((seen["image"], seen["cert"], seen["record"]), ("image.efi", "sb.crt", self.record))

    def test_an_image_the_measurements_do_not_accept_is_refused(self):
        other = dict(self.pcr11, initrd="cc" * 32)
        with self.assertRaisesRegex(enrol.Refused, "accept no set with this image's PCR 11"):
            self.approve(self.document(other), lambda *a: dict(self.pcr11))

    def test_a_set_that_names_no_signing_keys_is_refused(self):
        with self.assertRaisesRegex(enrol.Refused, "names no signing keys"):
            self.approve(self.document(self.pcr11, signing=False), lambda *a: dict(self.pcr11))

    def test_a_re_signed_copy_of_an_approved_image_is_refused(self):
        """regalia-kms-d9 on #265: the same measured sections, its own .pcrsig, Secure Boot signature and record. The
        PCR 11 matches; the keys do not."""
        for field in ("initrd", "system", "secure_boot_cert"):
            with self.subTest(field):
                other = dict(self.signing, **{field: "77" * 32})
                with self.assertRaisesRegex(enrol.Refused, "a re-signed copy of an approved image is not an approved image"):
                    self.approve(self.document(self.pcr11, signing=other), lambda *a: dict(self.pcr11))

    def test_an_image_that_does_not_verify_is_refused(self):
        def verify(*a):
            raise measurements.Refused("the initrd-phase key given is not the one the record names")
        with self.assertRaisesRegex(enrol.Refused, "the boot image is refused: the initrd-phase key"):
            self.approve(self.document(self.pcr11), verify)


if __name__ == "__main__":
    unittest.main()
