"""deploy/baremetal/host_probe.py against a fake host: a fully commissioned DL360 measures every
platform control true, each control broken on its own measures false with a reason, and evidence that
claims a control the host lacks is refused (ADR-0002 D21, regalia#46)."""
import base64
import datetime
import shutil
import subprocess
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from deploy.baremetal import evidence, host_probe

SB_ON = b"\x06\x00\x00\x00\x01"
DER = b"stand-in DER public key of the import key"
FP = hashlib.sha256(DER).hexdigest()
PEM = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % base64.b64encode(DER).decode()
# tpm2_readpublic's YAML for the template seal-hsm-pin.sh --init-import-key creates (captured from swtpm)
IMPORT_YAML = """name: 000b87fe
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
  raw: 0x20072
type:
  value: rsa
  raw: 0x1
exponent: 65537
bits: 3072
"""
USB = "/sys/bus/usb/devices"
KMS_BYTES = b"stand-in regalia-kms executable"
KMS_SHA256 = hashlib.sha256(KMS_BYTES).hexdigest()


class FakeHost:
    def __init__(self):
        self.files = {
            "/sys/class/tpm/tpm0/tpm_version_major": "2\n",
            "/etc/crypttab": "# <name> <device> <key> <options>\nroot_crypt UUID=abcd none tpm2-device=auto,tpm2-pcrs=7\n",
            "/sys/kernel/security/ima/policy": "dont_measure fsmagic=0x9fa0\nmeasure func=BPRM_CHECK mask=MAY_EXEC\n",
            host_probe.IMA_LOG: "10 ab ima-ng sha256:cd /usr/bin/bash\n10 ef ima-ng sha256:%s %s\n" % (KMS_SHA256, host_probe.KMS_BINARY),
            USB + "/1-1.4/idVendor": "20a0\n", USB + "/1-1.4/idProduct": "4230\n",
            USB + "/1-1/idVendor": "1d6b\n", USB + "/1-1/idProduct": "0002\n",
        }
        self.bytes = {host_probe.SECURE_BOOT_VAR: SB_ON, host_probe.KMS_BINARY: KMS_BYTES}
        self.dirs = {"/sys/class/tpm/tpm0/pcr-sha256": [str(i) for i in range(24)], USB: ["1-1", "1-1.4", "usb1"]}
        self.paths = {"/sys/firmware/efi", "/dev/tpmrm0"}
        self.tools = {"tpm2_readpublic", "opensc-tool", "pkcs11-tool"}
        self.stats = {"/usr/bin/opensc-tool": (0, 0, 0o100700), "/usr/bin/pkcs11-tool": (0, 0, 0o100700)}
        self.runs = {
            # LVM on LUKS: the root is a logical volume whose ancestor is the crypt device
            ("findmnt", "-n", "-o", "SOURCE", "/"): (0, "/dev/mapper/vg-root\n"),
            ("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-root"): (0, "vg-root lvm\nroot_crypt crypt\nsda3 part\nsda disk\n"),
            ("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE): (0, IMPORT_YAML),
            ("tpm2_readpublic", "-Q", "-c", host_probe.IMPORT_HANDLE, "-f", "pem", "-o", "/dev/stdout"): (0, PEM),
            ("ss", "-xpn"): (0, ""),
        }

    def read(self, path): return self.files.get(path)
    def read_bytes(self, path): return self.bytes.get(path)
    def listdir(self, path): return self.dirs.get(path, [])
    def exists(self, path): return path in self.paths
    def which(self, tool): return "/usr/bin/" + tool if tool in self.tools else None
    def readlink(self, path): return None
    def stat(self, path): return self.stats.get(path)
    def which_all(self, tool): return [p for p in self.stats if p.rsplit("/", 1)[1] == tool]
    def run(self, argv): return self.runs.get(tuple(argv), (1, ""))


def probe(host, name):
    return host_probe.import_key(host, FP[:16]) if name == "pin_import_key_present" else host_probe.PROBES[name](host)


def platform(host):
    return {n: probe(host, n) for n in host_probe.PLATFORM}


class HostProbe(unittest.TestCase):
    def test_a_commissioned_host_measures_every_platform_control(self):
        for name, (value, why) in platform(FakeHost()).items():
            with self.subTest(name=name):
                self.assertTrue(value, why)

    def test_each_control_broken_alone_fails_with_its_reason(self):
        cases = {
            "uefi_boot": (lambda h: h.paths.discard("/sys/firmware/efi"), "legacy BIOS"),
            "secure_boot_enabled": (lambda h: h.bytes.__setitem__(host_probe.SECURE_BOOT_VAR, b"\x06\x00\x00\x00\x00"), "SecureBoot = 0"),
            "tpm2_present": (lambda h: h.files.__setitem__("/sys/class/tpm/tpm0/tpm_version_major", "1\n"), "no TPM 2.0"),
            "tpm_sha256_bank": (lambda h: h.dirs.pop("/sys/class/tpm/tpm0/pcr-sha256"), "SHA-256 bank"),
            "root_disk_tpm_unlocked": (lambda h: h.files.__setitem__("/etc/crypttab", "root_crypt UUID=abcd none luks\n"), "not TPM-unlocked"),
            "ima_policy_loaded": (lambda h: h.files.pop("/sys/kernel/security/ima/policy"), "no IMA policy"),
            "pin_import_key_present": (lambda h: h.runs.pop(("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE)), "--init-import-key"),
            "hsm_token_attached": (lambda h: h.files.__setitem__(USB + "/1-1.4/idProduct", "4108\n"), "no Nitrokey HSM"),
            "token_clients_root_only": (lambda h: h.stats.__setitem__("/usr/bin/opensc-tool", (0, 0, 0o100755)), "the KMS user can run"),
        }
        for name, (breakit, reason) in cases.items():
            with self.subTest(name=name):
                h = FakeHost()
                breakit(h)
                value, why = probe(h, name)
                self.assertFalse(value, "%s still measured true" % name)
                self.assertIn(reason, why)
                others = {n: v for n, (v, _) in platform(h).items() if n != name}
                self.assertTrue(all(others.values()), "breaking %s broke %s" % (name, others))

    def test_raw_tpm0_without_the_resource_manager_fails(self):
        h = FakeHost()
        h.paths.discard("/dev/tpmrm0")
        value, why = host_probe.tpm2(h)
        self.assertFalse(value)
        self.assertIn("/dev/tpmrm0", why)

    def test_root_not_on_dm_crypt_fails(self):
        h = FakeHost()
        h.runs[("findmnt", "-n", "-o", "SOURCE", "/")] = (0, "/dev/mapper/vg-root\n")
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-root")] = (0, "vg-root lvm\nsda3 part\nsda disk\n")
        value, why = host_probe.root_unlock(h)
        self.assertFalse(value, "an unencrypted LVM volume under /dev/mapper passed")
        self.assertIn("not on dm-crypt", why)

    def test_luks_directly_under_root_passes(self):
        h = FakeHost()
        h.runs[("findmnt", "-n", "-o", "SOURCE", "/")] = (0, "/dev/mapper/root_crypt[/@]\n")
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/root_crypt")] = (0, "root_crypt crypt\nsda3 part\nsda disk\n")
        self.assertTrue(host_probe.root_unlock(h)[0])

    def test_ima_needs_an_executable_rule_and_the_kms_binary_in_the_log(self):
        h = FakeHost()
        h.files["/sys/kernel/security/ima/policy"] = "dont_measure fsmagic=0x9fa0\nmeasure func=FILE_CHECK mask=MAY_READ uid=0\n"
        value, why = host_probe.ima(h)
        self.assertFalse(value)
        self.assertIn("no executable-measurement rule", why)
        h = FakeHost()
        h.files[host_probe.IMA_LOG] = "10 ab ima-ng sha256:cd /usr/bin/bash\n"
        value, why = host_probe.ima(h)
        self.assertFalse(value)
        self.assertIn("not in the measurement log", why)

    def test_an_unrelated_key_at_the_import_handle_fails(self):
        h = FakeHost()
        other = base64.b64encode(b"some other key").decode()
        h.runs[("tpm2_readpublic", "-Q", "-c", host_probe.IMPORT_HANDLE, "-f", "pem", "-o", "/dev/stdout")] = (0, "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % other)
        value, why = host_probe.import_key(h, FP[:16])
        self.assertFalse(value)
        self.assertIn("NOT the recorded import key", why)
        h = FakeHost()
        h.runs[("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE)] = (0, IMPORT_YAML.replace("|decrypt", "|sign"))
        value, why = host_probe.import_key(h, FP[:16])
        self.assertFalse(value)
        self.assertIn("template", why)
        value, why = host_probe.import_key(FakeHost(), None)
        self.assertFalse(value)
        self.assertIn("no recorded fingerprint", why)

    def test_hsm_detection_needs_no_token_client(self):
        h = FakeHost()
        h.tools.clear()
        self.assertTrue(host_probe.hsm_token(h)[0])

    def test_a_runnable_copy_behind_a_root_only_one_fails(self):
        h = FakeHost()
        h.stats["/usr/local/sbin/opensc-tool"] = (0, 0, 0o100700)     # root-only, first on PATH
        h.stats["/usr/bin/opensc-tool"] = (0, 0, 0o100755)            # world-executable, later
        value, why = host_probe.token_clients_root_only(h)
        self.assertFalse(value)
        self.assertIn("/usr/bin/opensc-tool", why)

    def test_token_clients_owned_by_another_user_fail(self):
        h = FakeHost()
        h.stats["/usr/bin/pkcs11-tool"] = (1000, 0, 0o100700)
        self.assertFalse(host_probe.token_clients_root_only(h)[0])

    def test_the_token_usb_path_is_reported(self):
        self.assertIn("1-1.4", host_probe.hsm_token(FakeHost())[1])

    def test_a_stale_ima_entry_for_a_replaced_binary_fails(self):
        h = FakeHost()
        h.bytes[host_probe.KMS_BINARY] = b"replaced after it last ran"
        value, why = host_probe.ima(h)
        self.assertFalse(value)
        self.assertIn("replaced after it last ran", why)
        h.files[host_probe.IMA_LOG] += "10 aa ima-ng sha256:%s %s\n" % (
            hashlib.sha256(b"replaced after it last ran").hexdigest(), host_probe.KMS_BINARY)
        self.assertTrue(host_probe.ima(h)[0], "the newest entry matches the current bytes")

    def test_crypttab_tpm2_device_must_be_an_exact_nonempty_option(self):
        for opts in ("tpm2-device=", "x-tpm2-device=disabled", "luks,discard"):
            with self.subTest(opts=opts):
                h = FakeHost()
                h.files["/etc/crypttab"] = "root_crypt UUID=abcd none %s\n" % opts
                self.assertFalse(host_probe.root_unlock(h)[0])

    def test_the_import_key_needs_exactly_the_init_template_attributes(self):
        for attrs in ("fixedtpm|fixedparent|sensitivedataorigin|decrypt",
                      "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"):
            with self.subTest(attrs=attrs):
                h = FakeHost()
                h.runs[("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE)] = (
                    0, IMPORT_YAML.replace("fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt", attrs))
                self.assertFalse(host_probe.import_key(h, FP[:16])[0])

    def test_firmware_only_settings_are_attested_not_measured(self):
        for n in ("ilo_isolated_or_disabled", "ac_power_recovery", "chassis_intrusion_armed", "used_hardware_intake"):
            self.assertIn(n, host_probe.UNMEASURED)
            self.assertNotIn(n, host_probe.MEASURED)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class SignedEvidence(unittest.TestCase):
    """The commissioning pass criterion: measured controls AND signed, complete, agreeing evidence."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.key, self.pub = os.path.join(self.d, "k.pem"), os.path.join(self.d, "pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", self.key],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", self.pub], check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", self.pub, "-outform", "DER"], check=True,
                             capture_output=True).stdout
        self.key_sha = hashlib.sha256(der).hexdigest()
        self.everything = {n: {"value": True, "why": ""} for n in host_probe.MEASURED}
        self.now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def doc(self, **host_overrides):
        host = {n: True for n in host_probe.MEASURED}
        host.update({n: True for n in evidence.ATTESTED})
        host.update(pin_import_key_sha256=FP, hsm_usb_path="1-1.4", credential_tpm2_pcrs="7",
                    system_rom_version="P89 v3.40 (2024-03-22)", ilo_firmware_version="2.82",
                    tpm_ek_certificate_present=True)
        host.update(host_overrides)
        return {"schema": evidence.SCHEMA, "site": "site-a", "host_serial": "CZJ1234567",
                "captured_at": self.now, "host": host}

    def write(self, doc):
        path = os.path.join(self.d, "e.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.key, "-out", path + ".sig", path], check=True)
        return path, path + ".sig"

    def run_probe(self, path, sig, measured=None, key_sha=None):
        args = ["--evidence", path, "--signature", sig, "--evidence-key", self.pub,
                "--evidence-key-sha256", key_sha or self.key_sha]
        with mock.patch.object(host_probe, "measure", return_value=measured or self.everything), \
                redirect_stdout(io.StringIO()) as out:
            rc = host_probe.main(args, host=FakeHost())
        return rc, json.loads(out.getvalue())

    def test_complete_signed_agreeing_evidence_passes(self):
        rc, report = self.run_probe(*self.write(self.doc()))
        self.assertEqual(rc, 0, report.get("evidence_problems"))

    def test_evidence_mode_still_requires_every_control(self):
        missing = dict(self.everything, uefi_boot={"value": False, "why": "legacy BIOS"})
        rc, report = self.run_probe(*self.write(self.doc()), measured=missing)
        self.assertEqual(rc, 1)
        self.assertTrue(any("uefi_boot" in p for p in report["evidence_problems"]))

    def test_refusals(self):
        full = self.doc()
        cases = {
            "an empty document": ({}, "fields mismatch"),
            "an unattested firmware setting": (self.doc(chassis_intrusion_armed=False), "chassis_intrusion_armed"),
            "a missing firmware setting": (dict(full, host={k: v for k, v in full["host"].items()
                                                           if k != "ilo_isolated_or_disabled"}), "missing"),
            "a bad import key record": (self.doc(pin_import_key_sha256="abc"), "64 lowercase hex"),
            "a PIN sealed to the IMA PCR": (self.doc(credential_tpm2_pcrs="7+10"), "PCR 10"),
            "a PIN sealed to PCR 11 directly": (self.doc(credential_tpm2_pcrs="7+11"), "PCR 11"),
            "a policy without PCR 7": (self.doc(credential_tpm2_pcrs="1"), "include PCR 7"),
            "a PCR out of range": (self.doc(credential_tpm2_pcrs="7+24"), "0-23"),
            "a duplicated PCR": (self.doc(credential_tpm2_pcrs="7+7"), "distinct"),
            "the token on another port": (self.doc(hsm_usb_path="2-1"), "the host has it at 1-1.4"),
            "no PSU attestation": (dict(full, host={k: v for k, v in full["host"].items()
                                                    if k != "redundant_power_supplies"}), "missing"),
            "no ROM version recorded": (self.doc(system_rom_version=""), "version string"),
            "evidence older than 24 hours": (dict(full, captured_at="2026-01-01T00:00:00Z"), "older than 24 hours"),
        }
        for label, (doc, why) in cases.items():
            with self.subTest(label):
                rc, report = self.run_probe(*self.write(doc))
                self.assertEqual(rc, 1)
                self.assertTrue(any(why in p for p in report["evidence_problems"]), report["evidence_problems"])

    def test_the_signature_is_checked_over_the_validated_snapshot(self):
        path, sig = self.write(self.doc())
        seen = {}
        real = host_probe.evidence_mod.verify_signature

        def spy(ev, sg, key, key_sha, **kw):
            seen.update(ev=ev, sg=sg, key=key)
            with open(path, "w") as f:          # the original changes after validation...
                f.write("{}")
            real(ev, sg, key, key_sha)                  # ...the snapshot does not
        with mock.patch.object(host_probe.evidence_mod, "verify_signature", side_effect=spy):
            rc, report = self.run_probe(path, sig)
        self.assertEqual(rc, 0, report.get("evidence_problems"))
        self.assertNotIn(seen["ev"], (path,))
        self.assertNotEqual(seen["key"], self.pub)
        self.assertFalse(os.path.exists(seen["ev"]), "the snapshot is removed afterwards")

    def test_an_altered_or_foreign_signed_document_is_refused(self):
        path, sig = self.write(self.doc())
        with open(path, "a") as f:
            f.write(" ")
        rc, report = self.run_probe(path, sig)
        self.assertEqual(rc, 1)
        self.assertIn("signature does not verify", " ".join(report["evidence_problems"]))
        rc, report = self.run_probe(*self.write(self.doc()), key_sha="0" * 64)
        self.assertEqual(rc, 1)
        self.assertIn("recorded fingerprint", " ".join(report["evidence_problems"]))


if __name__ == "__main__":
    unittest.main()
