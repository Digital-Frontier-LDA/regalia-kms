"""deploy/baremetal/host_probe.py against a fake host: a fully commissioned DL360 measures every
platform control true, each control broken on its own measures false with a reason, and evidence that
claims a control the host lacks is refused (ADR-0002 D21, regalia#46)."""
import unittest

from deploy.baremetal import host_probe

SB_ON = b"\x06\x00\x00\x00\x01"


class FakeHost:
    def __init__(self):
        self.files = {
            "/sys/class/tpm/tpm0/tpm_version_major": "2\n",
            "/etc/crypttab": "# <name> <device> <key> <options>\nroot_crypt UUID=abcd none tpm2-device=auto,tpm2-pcrs=7\n",
            "/sys/kernel/security/ima/policy": "measure func=BPRM_CHECK mask=MAY_EXEC\n",
        }
        self.bytes = {host_probe.SECURE_BOOT_VAR: SB_ON}
        self.dirs = {"/sys/class/tpm/tpm0/pcr-sha256": [str(i) for i in range(24)]}
        self.paths = {"/sys/firmware/efi", "/dev/tpmrm0"}
        self.tools = {"tpm2_readpublic"}
        self.runs = {
            ("findmnt", "-n", "-o", "SOURCE", "/"): (0, "/dev/mapper/root_crypt\n"),
            ("tpm2_readpublic", "-Q", "-c", host_probe.IMPORT_HANDLE): (0, ""),
            ("opensc-tool", "-l"): (0, "0    Yes             Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00\n"),
        }

    def read(self, path): return self.files.get(path)
    def read_bytes(self, path): return self.bytes.get(path)
    def listdir(self, path): return self.dirs.get(path, [])
    def exists(self, path): return path in self.paths
    def which(self, tool): return "/usr/bin/" + tool if tool in self.tools else None
    def readlink(self, path): return None

    def run(self, argv):
        if argv[:2] == ["sh", "-c"]:
            return 0, "1-1.4\n"
        return self.runs.get(tuple(argv), (1, ""))


def platform(host):
    return {n: host_probe.PROBES[n](host) for n in host_probe.PLATFORM}


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
            "pin_import_key_present": (lambda h: h.runs.pop(("tpm2_readpublic", "-Q", "-c", host_probe.IMPORT_HANDLE)), "--init-import-key"),
            "hsm_token_attached": (lambda h: h.runs.__setitem__(("opensc-tool", "-l"), (0, "No smart card readers found.\n")), "no Nitrokey"),
        }
        for name, (breakit, reason) in cases.items():
            with self.subTest(name=name):
                h = FakeHost()
                breakit(h)
                value, why = host_probe.PROBES[name](h)
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
        h.runs[("findmnt", "-n", "-o", "SOURCE", "/")] = (0, "/dev/sda2\n")
        self.assertFalse(host_probe.root_unlock(h)[0])

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
