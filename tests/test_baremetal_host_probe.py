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
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|decrypt
  raw: 0x20072
type:
  value: rsa
  raw: 0x1
exponent: 65537
bits: 3072
"""
# tpm2_getcap properties-variable after deploy/baremetal/tpm-lockout.sh --set (captured from swtpm, tpm2-tools 5.7)
GETCAP = """TPM2_PT_PERMANENT:
  ownerAuthSet:              0
  endorsementAuthSet:        0
  lockoutAuthSet:            1
  reserved1:                 0
  disableClear:              0
  inLockout:                 0
  tpmGeneratedEPS:           1
  reserved2:                 0
TPM2_PT_STARTUP_CLEAR:
  phEnable:                  1
  shEnable:                  1
  ehEnable:                  1
  phEnableNV:                1
  reserved1:                 0
  orderly:                   0
TPM2_PT_HR_NV_INDEX: 0x0
TPM2_PT_HR_PERSISTENT: 0x1
TPM2_PT_LOCKOUT_COUNTER: 0x0
TPM2_PT_MAX_AUTH_FAIL: 0x20
TPM2_PT_LOCKOUT_INTERVAL: 0x258
TPM2_PT_LOCKOUT_RECOVERY: 0x15180
TPM2_PT_NV_WRITE_RECOVERY: 0x0
"""
GETCAP_CMD = ("tpm2_getcap", "properties-variable")
USB = "/sys/bus/usb/devices"
# nft -j list table inet regalia_kms, trimmed (captured from the rendered table in a network namespace)
NFT_JSON = json.dumps({"nftables": [
    {"table": {"family": "inet", "name": "regalia_kms"}},
    {"chain": {"family": "inet", "table": "regalia_kms", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "regalia_kms", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
    {"chain": {"family": "inet", "table": "regalia_kms", "name": "output", "type": "filter", "hook": "output", "prio": 0, "policy": "drop"}}]})
# cryptsetup luksDump --dump-json-metadata, trimmed: a passphrase slot 0 and the TPM2 slot 1 with the
# token systemd-cryptenroll --tpm2-device writes
LUKS_JSON = json.dumps({"keyslots": {"0": {"type": "luks2"}, "1": {"type": "luks2"}},
                        "tokens": {"0": {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": [7]}}})
# Real systemd encrypted credentials (systemd 257.7, a throwaway swtpm, the test PIN): one per key
# type, and the PCR-signing public key the signed one embeds.
CREDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "credentials")


def cred(name):
    with open(os.path.join(CREDS, name), encoding="ascii") as f:
        return f.read()


PKFP = "dcef0dc2e16a41f9d72045af7b7e04e813c83fd8da97fd295b3bf5b8c75ad3b0"   # openssl rsa -RSAPublicKey_out | sha256
PIN_FILE = host_probe.CREDSTORE + "/regalia-kms-hsm-site-a.pin"
# How the probe asks systemd to open a blob: by the name the unit loads it under, the secret to /dev/null.
OPEN_PIN = ("systemd-creds", "decrypt", "--name=hsm-site-a.pin", PIN_FILE, "/dev/null")
PCR7 = ([7], [], "")
SIGNED = ([7], [11], PKFP)


def retyped(text, kind):
    """The same credential with another key-type id: what a blob of that type starts with."""
    raw = base64.b64decode(text)
    return base64.b64encode(bytes.fromhex(kind) + raw[16:]).decode()


def rebanked(text, bank):
    raw = bytearray(base64.b64decode(text))
    assert raw[56:58] == b"\x0b\x00", "the fixture is bound to the SHA-256 bank"
    raw[56:58] = bank.to_bytes(2, "little")
    return base64.b64encode(raw).decode()


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
            PIN_FILE: cred("tpm2-7.cred"),
        }
        self.bytes = {host_probe.SECURE_BOOT_VAR: SB_ON, host_probe.KMS_BINARY: KMS_BYTES}
        self.dirs = {"/sys/class/tpm/tpm0/pcr-sha256": [str(i) for i in range(24)], USB: ["1-1", "1-1.4", "usb1"],
                     # a replaced credential's backup sits beside it and is not a credential the service loads
                     host_probe.CREDSTORE: ["regalia-kms-hsm-site-a.pin", "regalia-kms-hsm-site-a.pin.prev-20260930T100000Z"]}
        self.paths = {"/sys/firmware/efi", "/dev/tpmrm0"}
        self.tools = {"tpm2_readpublic", "tpm2_getcap", "opensc-tool", "pkcs11-tool"}
        self.stats = {"/usr/bin/opensc-tool": (0, 0, 0o100700), "/usr/bin/pkcs11-tool": (0, 0, 0o100700)}
        self.runs = {
            # LVM on LUKS: the root is a logical volume whose ancestor is the crypt device
            ("findmnt", "-n", "-o", "SOURCE", "/"): (0, "/dev/mapper/vg-root\n"),
            ("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-root"): (0, "vg-root lvm\nroot_crypt crypt\nsda3 part\nsda disk\n"),
            ("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE): (0, IMPORT_YAML),
            ("cryptsetup", "status", "root_crypt"): (0, "/dev/mapper/root_crypt is active and is in use.\n  type:    LUKS2\n  device:  /dev/sda3\n"),
            ("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda3"): (0, LUKS_JSON),
            ("tpm2_readpublic", "-Q", "-c", host_probe.IMPORT_HANDLE, "-f", "pem", "-o", "/dev/stdout"): (0, PEM),
            ("ss", "-xpn"): (0, ""),
            ("nft", "-j", "list", "table", "inet", "regalia_kms"): (0, NFT_JSON),
            GETCAP_CMD: (0, GETCAP),
            OPEN_PIN: (0, ""),
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
    if name == "pin_credentials_sealed_as_recorded":
        return host_probe.pin_credentials(host, PCR7)
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
            "pin_credentials_sealed_as_recorded": (lambda h: h.files.__setitem__(PIN_FILE, cred("host.cred")), "the host key (bench only)"),
            "hsm_token_attached": (lambda h: h.files.__setitem__(USB + "/1-1.4/idProduct", "4108\n"), "no Nitrokey HSM"),
            "token_clients_root_only": (lambda h: h.stats.__setitem__("/usr/bin/opensc-tool", (0, 0, 0o100755)), "others can run or change"),
            "firewall_default_deny": (lambda h: h.runs.pop(("nft", "-j", "list", "table", "inet", "regalia_kms")), "not loaded"),
            "tpm_lockout_policy": (lambda h: h.runs.__setitem__(GETCAP_CMD, (0, GETCAP.replace("MAX_AUTH_FAIL: 0x20", "MAX_AUTH_FAIL: 0x3"))), "not the commissioned ones"),
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

    def test_a_volume_without_a_tpm2_token_fails_even_if_crypttab_asks(self):
        h = FakeHost()
        h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda3")] = (
            0, json.dumps({"keyslots": {"0": {"type": "luks2"}}, "tokens": {}}))
        value, why = host_probe.root_unlock(h)
        self.assertFalse(value)
        self.assertIn("no systemd-tpm2 token", why)

    def test_the_disk_token_must_bind_exactly_pcr_7(self):
        for pcrs in ([], [9], [7, 9]):
            with self.subTest(pcrs=pcrs):
                h = FakeHost()
                h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda3")] = (0, json.dumps(
                    {"tokens": {"0": {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": pcrs}}}))
                value, why = host_probe.root_unlock(h)
                self.assertFalse(value)
                self.assertIn("not exactly [7]", why)

    def test_a_group_or_other_writable_client_fails(self):
        for mode in (0o100702, 0o100720, 0o100740):
            with self.subTest(mode=oct(mode)):
                h = FakeHost()
                h.stats["/usr/bin/pkcs11-tool"] = (0, 0, mode)
                self.assertFalse(host_probe.token_clients_root_only(h)[0])

    def test_a_bprm_rule_with_a_read_mask_is_not_executable_measurement(self):
        h = FakeHost()
        h.files["/sys/kernel/security/ima/policy"] = "measure func=BPRM_CHECK mask=MAY_READ\n"
        self.assertFalse(host_probe.ima(h)[0])
        h.files["/sys/kernel/security/ima/policy"] = "measure func=BPRM_CHECK\n"
        self.assertTrue(host_probe.ima(h)[0], "no mask is MAY_EXEC for BPRM_CHECK")

    def test_a_dormant_table_fails_the_firewall(self):
        h = FakeHost()
        d = json.loads(NFT_JSON)
        d["nftables"][0]["table"]["flags"] = "dormant"     # the shape nft -j prints (captured)
        h.runs[("nft", "-j", "list", "table", "inet", "regalia_kms")] = (0, json.dumps(d))
        value, why = host_probe.firewall(h)
        self.assertFalse(value)
        self.assertIn("DORMANT", why)

    def test_an_accept_policy_on_any_chain_fails_the_firewall(self):
        for hook in ("input", "output", "forward"):
            with self.subTest(hook=hook):
                h = FakeHost()
                d = json.loads(NFT_JSON)
                for c in d["nftables"]:
                    if c.get("chain", {}).get("hook") == hook:
                        c["chain"]["policy"] = "accept"
                h.runs[("nft", "-j", "list", "table", "inet", "regalia_kms")] = (0, json.dumps(d))
                value, why = host_probe.firewall(h)
                self.assertFalse(value)
                self.assertIn(hook, why)

    def test_ima_must_measure_into_pcr_10(self):
        h = FakeHost()
        h.files["/sys/kernel/security/ima/policy"] = "measure func=BPRM_CHECK mask=MAY_EXEC pcr=9\n"
        self.assertFalse(host_probe.ima(h)[0])
        h = FakeHost()
        h.files[host_probe.IMA_LOG] = h.files[host_probe.IMA_LOG].replace("10 ef ima-ng", "9 ef ima-ng")
        self.assertFalse(host_probe.ima(h)[0], "an entry in another PCR does not count")

    def test_crypttab_tpm2_device_must_be_an_exact_nonempty_option(self):
        for opts in ("tpm2-device=", "x-tpm2-device=disabled", "luks,discard"):
            with self.subTest(opts=opts):
                h = FakeHost()
                h.files["/etc/crypttab"] = "root_crypt UUID=abcd none %s\n" % opts
                self.assertFalse(host_probe.root_unlock(h)[0])

    def test_the_tpm_lockout_policy_fails_on_each_drift(self):
        value, why = host_probe.lockout_policy(FakeHost())
        self.assertTrue(value, why)
        self.assertIn("32 failed tries, one forgiven every 600 s", why)
        cases = {
            "the limit": ("TPM2_PT_MAX_AUTH_FAIL: 0x20", "TPM2_PT_MAX_AUTH_FAIL: 0x3", "TPM2_PT_MAX_AUTH_FAIL is 3, not 32"),
            "the healing time": ("TPM2_PT_LOCKOUT_INTERVAL: 0x258", "TPM2_PT_LOCKOUT_INTERVAL: 0x1C20", "TPM2_PT_LOCKOUT_INTERVAL is 7200, not 600"),
            "the lockout recovery": ("TPM2_PT_LOCKOUT_RECOVERY: 0x15180", "TPM2_PT_LOCKOUT_RECOVERY: 0x3E8", "TPM2_PT_LOCKOUT_RECOVERY is 1000, not 86400"),
            "no lockout authorization": ("lockoutAuthSet:            1", "lockoutAuthSet:            0", "no authorization value"),
            "in lockout": ("inLockout:                 0", "inLockout:                 1", "in dictionary-attack lockout"),
            "a property the TPM did not report": ("TPM2_PT_LOCKOUT_INTERVAL: 0x258\n", "", "did not report TPM2_PT_LOCKOUT_INTERVAL"),
        }
        for label, (old, new, reason) in cases.items():
            with self.subTest(label):
                h = FakeHost()
                self.assertIn(old, GETCAP)
                h.runs[GETCAP_CMD] = (0, GETCAP.replace(old, new))
                value, why = host_probe.lockout_policy(h)
                self.assertFalse(value, why)
                self.assertIn(reason, why)
        # Counted tries are reported, not refused: a power cut counts one and it heals (#57).
        h = FakeHost()
        h.runs[GETCAP_CMD] = (0, GETCAP.replace("TPM2_PT_LOCKOUT_COUNTER: 0x0", "TPM2_PT_LOCKOUT_COUNTER: 0x4"))
        value, why = host_probe.lockout_policy(h)
        self.assertTrue(value, why)
        self.assertIn("4 failed tries counted now", why)
        for broken in (lambda h: h.runs.pop(GETCAP_CMD), lambda h: h.tools.discard("tpm2_getcap")):
            h = FakeHost()
            broken(h)
            self.assertFalse(host_probe.lockout_policy(h)[0])

    def test_the_commissioning_script_sets_the_policy_the_probe_measures(self):
        script = open(os.path.join(os.path.dirname(CREDS), "..", "..", "deploy", "baremetal", "tpm-lockout.sh"), encoding="utf-8").read()
        policy = host_probe.LOCKOUT_POLICY
        self.assertIn("MAX_TRIES=%d; HEAL_SECONDS=%d; LOCKOUT_RECOVERY=%d" % (
            policy["TPM2_PT_MAX_AUTH_FAIL"], policy["TPM2_PT_LOCKOUT_INTERVAL"], policy["TPM2_PT_LOCKOUT_RECOVERY"]), script)

    def test_the_import_key_needs_exactly_the_init_template_attributes(self):
        for attrs in ("fixedtpm|fixedparent|sensitivedataorigin|noda|decrypt",
                      # the template before #57's decision: subject to the dictionary-attack counter
                      "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt",
                      "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|decrypt"):
            with self.subTest(attrs=attrs):
                h = FakeHost()
                h.runs[("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE)] = (
                    0, IMPORT_YAML.replace("fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|decrypt", attrs))
                self.assertFalse(host_probe.import_key(h, FP[:16])[0])

    def test_a_real_credential_header_says_what_the_blob_is_sealed_to(self):
        self.assertEqual(host_probe.credential_header(cred("tpm2-7.cred")), PCR7)
        self.assertEqual(host_probe.credential_header(cred("tpm2-7-14.cred")), ([7, 14], [], ""))
        self.assertEqual(host_probe.credential_header(cred("pk-7-11.cred")), SIGNED)
        self.assertEqual(host_probe.rsa_pkfp(cred("pcr.pub")), PKFP)

    def test_pin_credentials_must_be_sealed_exactly_as_recorded(self):
        signed = cred("pk-7-11.cred")
        cases = {
            # (the blob on the host, the record) -> the reason
            "PCR 7 recorded, PCR 7+14 sealed": (cred("tpm2-7-14.cred"), PCR7, "sealed to PCRs 7+14, no signed policy; the record says PCRs 7, no signed policy"),
            "a signed policy recorded, none sealed": (cred("tpm2-7.cred"), SIGNED, "the record says PCRs 7, signed PCRs 11 by key pkfp " + PKFP),
            "no signed policy recorded, one sealed": (signed, PCR7, "signed PCRs 11 by key pkfp " + PKFP),
            "signed by another key than the recorded one": (signed, ([7], [11], "0" * 64), "the record says PCRs 7, signed PCRs 11 by key pkfp " + "0" * 64),
            "the host key": (cred("host.cred"), PCR7, "the host key (bench only), not the TPM alone"),
            "the host key and the TPM": (retyped(signed, "93a894094874449090caf2fc93cab553"), PCR7, "the host key and the TPM"),
            "a null key": (retyped(cred("host.cred"), "058469daf6f54324800549da0f8ea2fb"), PCR7, "a null key"),
            "an unknown type": (retyped(signed, "00" * 16), SIGNED, "an unknown credential type"),
            # cut inside the signed-policy header, and inside the TPM header
            "a blob cut in its signing key": (base64.b64encode(base64.b64decode(signed)[:360]).decode(), SIGNED, "truncated"),
            "a blob cut in its TPM header": (base64.b64encode(base64.b64decode(signed)[:56]).decode(), SIGNED, "truncated"),
            # whole headers, but not enough left for the encrypted metadata and the tag
            "a blob cut after its headers": (base64.b64encode(base64.b64decode(cred("tpm2-7.cred"))[:-40]).decode(), PCR7, "truncated"),
            # the same PCR number in another bank is another PCR (bank u16 at offset 56: SHA-1 is 0x0004)
            "PCR 7 of the SHA-1 bank": (rebanked(cred("tpm2-7.cred"), 0x0004), PCR7, "bound to PCR bank 0x0004, not SHA-256"),
            "a signed blob in the SHA-1 bank": (rebanked(signed, 0x0004), SIGNED, "bound to PCR bank 0x0004, not SHA-256"),
            "a PIN in clear": ("7310048261\n", PCR7, "not base64"),
            "too short to be a credential": ("QUJD\n", PCR7, "too short"),
            "an unreadable file": (None, PCR7, "too short"),
            "nothing recorded to compare with": (cred("tpm2-7.cred"), None, "no recorded binding to compare"),
        }
        for label, (blob, record, reason) in cases.items():
            with self.subTest(label):
                h = FakeHost()
                h.files[PIN_FILE] = blob
                value, why = host_probe.pin_credentials(h, record)
                self.assertFalse(value, why)
                self.assertIn(reason, why)
        h = FakeHost()
        h.files[PIN_FILE] = signed
        value, why = host_probe.pin_credentials(h, SIGNED)
        self.assertTrue(value, why)
        self.assertIn("signed PCRs 11 by key pkfp " + PKFP, why)

    def test_a_blob_sealed_as_recorded_must_also_open_on_this_boot(self):
        """A blob cut by a few bytes keeps a whole header (measured: systemd says 'Encrypted file too
        short'); so does one sealed by another TPM, or under a name the unit does not load it by."""
        h = FakeHost()
        h.files[PIN_FILE] = base64.b64encode(base64.b64decode(cred("tpm2-7.cred"))[:-20]).decode()
        self.assertEqual(host_probe.credential_header(h.files[PIN_FILE]), PCR7)
        h.runs[OPEN_PIN] = (1, "")
        value, why = host_probe.pin_credentials(h, PCR7)
        self.assertFalse(value)
        self.assertIn("does NOT open on this boot", why)
        h = FakeHost()
        h.runs.pop(OPEN_PIN)          # no systemd-creds, or it failed to run
        self.assertFalse(host_probe.pin_credentials(h, PCR7)[0])
        value, why = host_probe.pin_credentials(FakeHost(), PCR7)
        self.assertTrue(value, why)
        self.assertIn("open on this boot", why)

    def test_every_pin_credential_is_checked_and_only_pin_credentials(self):
        h = FakeHost()
        h.runs[("systemd-creds", "decrypt", "--name=yubikey-site-a.pin",
                host_probe.CREDSTORE + "/regalia-kms-yubikey-site-a.pin", "/dev/null")] = (0, "")
        h.dirs[host_probe.CREDSTORE].append("regalia-kms-yubikey-site-a.pin")
        h.files[host_probe.CREDSTORE + "/regalia-kms-yubikey-site-a.pin"] = cred("host.cred")
        value, why = host_probe.pin_credentials(h, PCR7)
        self.assertFalse(value)
        self.assertIn("regalia-kms-yubikey-site-a.pin is sealed with the host key", why)
        h.files[host_probe.CREDSTORE + "/regalia-kms-yubikey-site-a.pin"] = cred("tpm2-7.cred")
        value, why = host_probe.pin_credentials(h, PCR7)
        self.assertTrue(value, why)
        self.assertIn("2 PIN credential(s)", why)
        h = FakeHost()
        h.dirs[host_probe.CREDSTORE] = ["regalia-kms-hsm-site-a.pin.prev-20260930T100000Z", "mtls.key"]
        value, why = host_probe.pin_credentials(h, PCR7)
        self.assertFalse(value)
        self.assertIn("no PIN credential", why)

    def test_a_signed_key_that_is_not_rsa_or_not_a_key_is_refused(self):
        for pem in ("", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
                    # a P-256 SubjectPublicKeyInfo
                    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n-----END PUBLIC KEY-----\n"):
            with self.subTest(pem=pem[:40]):
                with self.assertRaises(ValueError):
                    host_probe.rsa_pkfp(pem)

    def test_the_sandbox_controls_are_measured_on_bare_metal(self):
        for n in ("kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced", "pin_credentials_sealed_as_recorded"):
            self.assertIn(n, host_probe.MEASURED)
            self.assertIn(n, host_probe.PROBES)

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
                    credential_tpm2_signed_pcrs="", credential_tpm2_pcr_key_pkfp="",
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
            "a signed PCR other than 11": (self.doc(credential_tpm2_signed_pcrs="7", credential_tpm2_pcr_key_pkfp=PKFP), 'must be "11" or ""'),
            "a signed PCR with no signing key": (self.doc(credential_tpm2_signed_pcrs="11"), "go together"),
            "a signing key with no signed PCR": (self.doc(credential_tpm2_pcr_key_pkfp=PKFP), "go together"),
            "a signing key that is not a fingerprint": (self.doc(credential_tpm2_signed_pcrs="11", credential_tpm2_pcr_key_pkfp="abc"), "64 lowercase hex"),
            "no signed-policy record at all": (dict(full, host={k: v for k, v in full["host"].items()
                                                              if k != "credential_tpm2_signed_pcrs"}), "missing"),
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

    def test_the_recorded_binding_is_what_the_credentials_are_measured_against(self):
        """Not mocked: the evidence's record reaches the probe, which reads the blob on the host."""
        def run(doc, blob):
            path, sig = self.write(doc)
            host = FakeHost()
            host.files[PIN_FILE] = blob
            args = ["--evidence", path, "--signature", sig, "--evidence-key", self.pub, "--evidence-key-sha256", self.key_sha]
            with redirect_stdout(io.StringIO()) as out:
                host_probe.main(args, host=host)
            return json.loads(out.getvalue())["measured"]["pin_credentials_sealed_as_recorded"]
        signed_doc = self.doc(credential_tpm2_signed_pcrs="11", credential_tpm2_pcr_key_pkfp=PKFP)
        self.assertTrue(run(self.doc(), cred("tpm2-7.cred"))["value"])
        self.assertTrue(run(signed_doc, cred("pk-7-11.cred"))["value"])
        for doc, blob in ((self.doc(), cred("pk-7-11.cred")), (signed_doc, cred("tpm2-7.cred"))):
            result = run(doc, blob)
            self.assertFalse(result["value"])
            self.assertIn("the record says", result["why"])

    def test_without_evidence_the_binding_comes_from_the_command_line(self):
        def run(*args, blob="tpm2-7.cred"):
            host = FakeHost()
            host.files[PIN_FILE] = cred(blob)
            with redirect_stdout(io.StringIO()) as out:
                host_probe.main(["--import-key-sha256", FP[:16], *args], host=host)
            return json.loads(out.getvalue())["measured"]["pin_credentials_sealed_as_recorded"]
        self.assertTrue(run("--credential-pcrs", "7")["value"])
        self.assertTrue(run("--credential-pcrs", "7", "--credential-signed-pcrs", "11", "--credential-pcr-key-pkfp", PKFP,
                            blob="pk-7-11.cred")["value"])
        self.assertIn("no recorded binding to compare", run()["why"])
        self.assertFalse(run("--credential-pcrs", "7", blob="pk-7-11.cred")["value"])
        # The arguments are held to the evidence's rules: PCR 11 is never a directly bound PCR.
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            run("--credential-pcrs", "7+11")

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
