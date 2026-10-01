"""deploy/baremetal/host_probe.py against a fake host: a fully commissioned DL360 measures every
platform control true, each control broken on its own measures false with a reason, and evidence that
claims a control the host lacks is refused (ADR-0002 D21, regalia#46)."""
import base64
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from deploy.baremetal import host_probe

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


class FakeHost:
    def __init__(self):
        self.files = {
            "/sys/class/tpm/tpm0/tpm_version_major": "2\n",
            "/etc/crypttab": "# <name> <device> <key> <options>\nroot_crypt UUID=abcd none tpm2-device=auto,tpm2-pcrs=7\n",
            "/sys/kernel/security/ima/policy": "dont_measure fsmagic=0x9fa0\nmeasure func=BPRM_CHECK mask=MAY_EXEC\n",
            host_probe.IMA_LOG: "10 ab ima-ng sha256:cd /usr/bin/bash\n10 ef ima-ng sha256:01 %s\n" % host_probe.KMS_BINARY,
            USB + "/1-1.4/idVendor": "20a0\n", USB + "/1-1.4/idProduct": "4230\n",
            USB + "/1-1/idVendor": "1d6b\n", USB + "/1-1/idProduct": "0002\n",
        }
        self.bytes = {host_probe.SECURE_BOOT_VAR: SB_ON}
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

    def test_token_clients_owned_by_another_user_fail(self):
        h = FakeHost()
        h.stats["/usr/bin/pkcs11-tool"] = (1000, 0, 0o100700)
        self.assertFalse(host_probe.token_clients_root_only(h)[0])

    def test_evidence_mode_still_requires_every_control(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"host": {"pin_import_key_sha256": FP}}, f)   # claims nothing the host lacks
        self.addCleanup(os.unlink, f.name)
        everything = {n: {"value": True, "why": ""} for n in host_probe.MEASURED}
        with mock.patch.object(host_probe, "measure", return_value=everything), redirect_stdout(io.StringIO()):
            self.assertEqual(host_probe.main(["--evidence", f.name], host=FakeHost()), 0)
        one_missing = dict(everything, uefi_boot={"value": False, "why": "legacy BIOS"})
        with mock.patch.object(host_probe, "measure", return_value=one_missing), redirect_stdout(io.StringIO()):
            self.assertEqual(host_probe.main(["--evidence", f.name], host=FakeHost()), 1,
                             "a host missing a control passed because the evidence was silent about it")

    def test_the_token_usb_path_is_reported(self):
        self.assertIn("1-1.4", host_probe.hsm_token(FakeHost())[1])

    def test_evidence_claiming_a_missing_control_is_refused(self):
        h = FakeHost()
        h.paths.discard("/sys/firmware/efi")
        measured = {n: dict(zip(("value", "why"), host_probe.PROBES[n](h))) for n in host_probe.PLATFORM}
        problems = host_probe.compare(
            {**measured, **{n: {"value": True, "why": ""} for n in host_probe.guest_probe.MEASURED}},
            {"host": {"uefi_boot": True, "secure_boot_enabled": True}})
        self.assertEqual(len(problems), 1)
        self.assertIn("uefi_boot", problems[0])

    def test_firmware_only_settings_are_attested_not_measured(self):
        for n in ("ilo_isolated_or_disabled", "ac_power_recovery", "chassis_intrusion_armed", "used_hardware_intake"):
            self.assertIn(n, host_probe.UNMEASURED)
            self.assertNotIn(n, host_probe.MEASURED)


if __name__ == "__main__":
    unittest.main()
