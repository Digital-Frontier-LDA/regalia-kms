"""deploy/baremetal/host_probe.py against a fake host: a fully commissioned DL360 measures every
platform control true, each control broken on its own measures false with a reason, and evidence that
claims a control the host lacks is refused (ADR-0002 D21, regalia#46)."""
import base64
import datetime
import shutil
import subprocess
import sys
import hashlib
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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
# cryptsetup luksDump --dump-json-metadata, trimmed: the TPM2 slot 1 with the token
# systemd-cryptenroll --tpm2-device --tpm2-pcrlock writes (NV-backed: the one shape today under which
# a retired boot image stops unlocking the disk, #135; captured from e2e/pcrlock-luks-swtpm.sh), and the
# recovery key's slot 2 with the systemd-recovery token recovery-key.sh --enrol writes. The installer's
# passphrase (slot 0) has been wiped.
NV_TOKEN = {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": [], "tpm2_pcrlock": True}
LUKS_META = {"keyslots": {"1": {"type": "luks2"}, "2": {"type": "luks2"}},
             "tokens": {"0": NV_TOKEN, "1": {"type": "systemd-recovery", "keyslots": ["2"]}}}
LUKS_JSON = json.dumps(LUKS_META)
# What deploy/baremetal/README.md's enrolment (systemd-cryptenroll --tpm2-pcrs=7) writes, and so what
# every host commissioned so far carries: bound to PCR 7, which no kernel update changes.
PCR7_TOKEN = {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": [7]}
LUKS_TODAY = json.dumps(dict(LUKS_META, tokens=dict(LUKS_META["tokens"], **{"0": PCR7_TOKEN})))
# /var/lib/systemd/pcrlock.json, as systemd-pcrlock make-policy writes it (trimmed to what the probe reads):
# the PCRs the NV index's policy covers, each with its accepted values.
PCRLOCK = {"pcrBank": "sha256", "nvIndex": 25661857,
           "pcrValues": [{"pcr": n, "values": [("%02x" % (0xa0 + n)) * 32]} for n in (0, 2, 4, 7, 11)]}


def secret_mount(path):
    """How the probe asks where a secret lives: the filesystem's device, type and UUID."""
    return ("findmnt", "-n", "-o", "SOURCE,FSTYPE,UUID", "-T", path)


ROOT_FS = (0, "/dev/mapper/vg-root ext4 1111-2222\n")
# Real systemd encrypted credentials (systemd 257.7, a throwaway swtpm, the test PIN): one per key
# type, and the PCR-signing public key the signed one embeds.
CREDS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "credentials")


LUKS_DUMP = ("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda3")


def cred(name):
    with open(os.path.join(CREDS, name), encoding="ascii") as f:
        return f.read()


PKFP = "dcef0dc2e16a41f9d72045af7b7e04e813c83fd8da97fd295b3bf5b8c75ad3b0"   # openssl rsa -RSAPublicKey_out | sha256
PIN_FILE = host_probe.CREDSTORE + "/regalia-kms-hsm-site-a.pin"
# How the probe asks systemd to open a blob: by the name the unit loads it under, the secret to /dev/null.
OPEN_PIN = ("systemd-creds", "decrypt", "--name=hsm-site-a.pin", PIN_FILE, "/dev/null")
HOST_KEY_STAT = ("stat", "-c", "%f|%u", host_probe.HOST_KEY)   # raw mode in hex: not the translated %F
HOST_KEY_MOUNT = ("findmnt", "-n", "-o", "SOURCE", "-T", host_probe.HOST_KEY)
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
            PIN_FILE: cred("host-tpm2-7.cred"),
            host_probe.PCRLOCK_POLICY: json.dumps(PCRLOCK),
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
            # "/", the host key and the credstore are all on the one LUKS volume under the root filesystem
            **{secret_mount(path): ROOT_FS for path in host_probe.SECRET_PATHS},
            # the host key: root's, 0400, on the LUKS root
            HOST_KEY_STAT: (0, "8100|0\n"),
            HOST_KEY_MOUNT: (0, "/dev/mapper/vg-root\n"),
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
            "root_disk_unlock_revocable": (lambda h: h.runs.__setitem__(LUKS_DUMP, (0, LUKS_TODAY)), "BLOCKING FOR PRODUCTION (#135)"),
            "root_disk_recovery_keyslot": (lambda h: h.runs.__setitem__(LUKS_DUMP, (0, json.dumps(dict(LUKS_META, tokens={"0": LUKS_META["tokens"]["0"]}, keyslots={"1": {}})))), "no recovery keyslot"),
            "ima_policy_loaded": (lambda h: h.files.pop("/sys/kernel/security/ima/policy"), "no IMA policy"),
            "pin_import_key_present": (lambda h: h.runs.pop(("tpm2_readpublic", "-c", host_probe.IMPORT_HANDLE)), "--init-import-key"),
            "pin_credentials_sealed_as_recorded": (lambda h: h.files.__setitem__(PIN_FILE, cred("host.cred")), "the host key alone (bench only)"),
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

    def test_a_host_enrolled_as_the_readme_says_today_fails_one_probe_and_only_that_one(self):
        """The known blocker (#135). A host that is otherwise fully commissioned must show it as its ONLY
        failing control, so that "commissioned except for the known blocker" can be told from "broken"."""
        h = FakeHost()
        h.runs[LUKS_DUMP] = (0, LUKS_TODAY)
        results = platform(h)
        self.assertEqual([n for n, (value, _) in results.items() if not value], ["root_disk_unlock_revocable"])
        self.assertTrue(results["root_disk_tpm_unlocked"][0])          # it IS TPM-unlocked, bound to PCR 7: that is the problem
        why = results["root_disk_unlock_revocable"][1]
        self.assertEqual(why, "root_crypt (/dev/sda3) is unlocked by the local TPM alone, under a policy that cannot retire a boot "
                         "image (PCRs [7]). An old signed kernel image unlocks this disk, reads the host key and opens the HSM PIN. "
                         "BLOCKING FOR PRODUCTION (#135). What clears it: a peer's contribution to the unlock (#67: deploy/baremetal/unlock.py), "
                         "or an NV-backed policy (systemd-cryptenroll --tpm2-pcrlock; measured on a software TPM only, "
                         "e2e/pcrlock-luks-swtpm.sh). There is no option to skip this check")

    def test_the_blocker_fails_the_whole_run_and_there_is_no_way_to_skip_it(self):
        h = FakeHost()
        h.runs[LUKS_DUMP] = (0, LUKS_TODAY)
        with redirect_stdout(io.StringIO()) as out:
            rc = host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7"], host=h)
        report = json.loads(out.getvalue())
        self.assertEqual(rc, 1)
        self.assertFalse(report["measured"]["root_disk_unlock_revocable"]["value"])
        self.assertIn("#135", report["measured"]["root_disk_unlock_revocable"]["why"])
        failing_platform = [n for n in host_probe.PLATFORM if not report["measured"][n]["value"]]
        self.assertEqual(failing_platform, ["root_disk_unlock_revocable"])
        # no option of the tool skips, allows, ignores or forces anything
        with redirect_stdout(io.StringIO()) as usage, self.assertRaises(SystemExit):
            host_probe.main(["--help"], host=h)
        options = set(re.findall(r"--[a-z0-9-]+", usage.getvalue()))
        self.assertTrue(options, "no options parsed from --help")
        self.assertEqual([o for o in sorted(options) if re.search(r"skip|allow|ignore|force|override|except|waive|known", o)], [])
        for attempt in ("--skip", "--skip=root_disk_unlock_revocable", "--allow-known-blockers", "--ignore", "--force"):
            with self.subTest(attempt), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as refused:
                host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7", attempt], host=h)
            self.assertEqual(refused.exception.code, 2)

    def judge(self, *tokens, keyslots=None, prepare=None):
        """A host whose root volume carries `tokens`. Its keyslots are the ones those tokens name, unless given."""
        if keyslots is None:
            keyslots = sorted({s for t in tokens for s in (t.get("keyslots") if isinstance(t.get("keyslots"), list) else [])
                               if isinstance(s, str)})
        h = FakeHost()
        h.runs[LUKS_DUMP] = (0, json.dumps({"keyslots": {k: {"type": "luks2"} for k in keyslots},
                                            "tokens": {str(i): t for i, t in enumerate(tokens)}}))
        if prepare:
            prepare(h)
        return h

    def test_what_makes_the_root_disk_unlock_revocable(self):
        recovery = LUKS_META["tokens"]["1"]
        value, why = host_probe.unlock_revocable(self.judge(NV_TOKEN, recovery))
        self.assertTrue(value, why)
        self.assertEqual(why, "root_crypt: every token that names a keyslot is the recovery key or needs more than a fixed TPM policy: "
                         "NV-backed (tpm2_pcrlock) tokens, and /var/lib/systemd/pcrlock.json covers PCRs 0, 2, 4, 7, 11. NOT measured: "
                         "that the NV index holds this policy; nor that a retired image is refused on this host")
        signed = dict(PCR7_TOKEN, tpm2_pubkey="LS0t", tpm2_pubkey_pcrs=[11])
        cases = {
            "PCR 7 only": ((PCR7_TOKEN, recovery), "(PCRs [7])"),
            "a signed PCR 11 policy": ((signed, recovery), "a signed policy on PCRs [11] (every image its key ever signed)"),
            "no PCRs at all and not NV-backed": ((dict(PCR7_TOKEN, **{"tpm2-pcrs": []}), recovery), "(PCRs none)"),
            # one NV-backed token does not excuse a second, PCR-only one: either keyslot opens the disk
            "an NV-backed token beside a PCR-only one": ((NV_TOKEN, dict(PCR7_TOKEN, keyslots=["3"]), recovery), "(PCRs [7])"),
            # the flag must be exactly true, and such a token lists no PCRs of its own
            "tpm2_pcrlock as text": ((dict(NV_TOKEN, tpm2_pcrlock="true"), recovery), "BLOCKING FOR PRODUCTION"),
            "tpm2_pcrlock as 1": ((dict(NV_TOKEN, tpm2_pcrlock=1), recovery), "BLOCKING FOR PRODUCTION"),
            "tpm2_pcrlock false": ((dict(NV_TOKEN, tpm2_pcrlock=False), recovery), "BLOCKING FOR PRODUCTION"),
            "NV-backed but with a PCR list": ((dict(NV_TOKEN, **{"tpm2-pcrs": [7]}), recovery), "BLOCKING FOR PRODUCTION"),
            "no TPM token": ((recovery,), "has no systemd-tpm2 token that names a keyslot: nothing to judge"),
            "a TPM token that names no keyslot": ((dict(NV_TOKEN, keyslots=[]), recovery), "nothing to judge"),
        }
        for label, (tokens, reason) in cases.items():
            with self.subTest(label):
                value, why = host_probe.unlock_revocable(self.judge(*tokens))
                self.assertFalse(value, why)
                self.assertIn(reason, why)
        h = FakeHost()
        h.runs.pop(LUKS_DUMP)
        self.assertEqual(host_probe.unlock_revocable(h), (False, "cannot read the LUKS2 header of /dev/sda3 (cryptsetup luksDump --dump-json-metadata)"))
        h = FakeHost()
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-root")] = (0, "vg-root lvm\nsda3 part\n")
        self.assertIn("not on dm-crypt", host_probe.unlock_revocable(h)[1])

    # ---- the peer-assisted shape (#67): the TPM and a peer, never the TPM alone ----

    RECORD = ("a", ("b", "c"))

    @staticmethod
    def path(peer, slot, local="tpm2-7.cred", **change):
        """A peer-path token as deploy/baremetal/unlock.py enrols it; its local share is a real TPM-only credential."""
        return dict({"type": "regalia-peer-unlock", "keyslots": [slot], "version": 1, "target": "a", "peer": peer,
                     "path_epoch": 1, "local": cred(local)}, **change)

    def peer_host(self, *tokens, crypttab="root_crypt UUID=abcd /run/regalia-unlock/key.sock luks\n", keyslots=None):
        recovery = LUKS_META["tokens"]["1"]
        tokens = tokens or (self.path("b", "1"), recovery, self.path("c", "3"))
        h = self.judge(*tokens, keyslots=keyslots)
        h.files["/etc/crypttab"] = crypttab
        h.files["/proc/cmdline"] = "BOOT_IMAGE=/vmlinuz root=/dev/mapper/vg-root ro quiet\n"
        return h

    def test_a_disk_that_needs_a_peer_passes_both_root_disk_controls(self):
        h = self.peer_host()
        value, why = host_probe.root_unlock(h, self.RECORD)
        self.assertTrue(value, why)
        self.assertEqual(why, "root_crypt unlocks with the TPM and a peer (peer-assisted unlock: b in keyslot 1 (path epoch 1), "
                         "c in keyslot 3 (path epoch 1))")
        value, why = host_probe.unlock_revocable(h, self.RECORD)
        self.assertTrue(value, why)
        self.assertIn("peer-assisted unlock (root_crypt: peer-assisted unlock: b in keyslot 1 (path epoch 1), c in keyslot 3 (path epoch 1))", why)
        self.assertIn("NOT measured: that the peers refuse a retired image", why)
        self.assertNotIn("pcrlock", why)                                   # no NV-backed token: the policy file is not consulted
        h.files.pop(host_probe.PCRLOCK_POLICY)
        self.assertTrue(host_probe.unlock_revocable(h, self.RECORD)[0])
        self.assertTrue(host_probe.recovery_keyslot(h)[0])
        # through main(): every platform control true, with the record from the command line
        with redirect_stdout(io.StringIO()) as out:
            host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7", "--node-id", "a",
                             "--unlock-peer", "b", "--unlock-peer", "c"], host=self.peer_host())
        report = json.loads(out.getvalue())["measured"]
        self.assertEqual([n for n in host_probe.PLATFORM if not report[n]["value"]], [])
        # a signed PCR 11 policy on the local share is the other accepted binding
        signed = self.peer_host(self.path("b", "1", "pk-7-11.cred"), LUKS_META["tokens"]["1"], self.path("c", "3", "pk-7-11.cred"))
        self.assertTrue(host_probe.root_unlock(signed, self.RECORD)[0])
        self.assertTrue(host_probe.unlock_revocable(signed, self.RECORD)[0])

    def test_the_peer_shape_is_judged_against_the_record_of_this_node_and_its_peers(self):
        h = self.peer_host()
        for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable):
            with self.subTest(probe_fn.__name__):
                value, why = probe_fn(h)                                  # no record at all
                self.assertFalse(value, why)
                self.assertIn("this run was not told which node this is: pass --node-id and one --unlock-peer per peer", why)
                for record, reason in ((("b", ("a", "c")), "is for node a, not b: this header was not enrolled for this host"),
                                       (("a", ("b",)), "the disk has paths from b, c; the record says b"),
                                       (("a", ("b", "c", "d")), "the disk has paths from b, c; the record says b, c, d"),
                                       (("a", ()), "the disk has paths from b, c; the record says none")):
                    value, why = probe_fn(h, record)
                    self.assertFalse(value, why)
                    self.assertIn(reason, why)
        self.assertIn("BLOCKING FOR PRODUCTION (#135)", host_probe.unlock_revocable(h, ("a", ("b",)))[1])
        with redirect_stdout(io.StringIO()) as out:                      # main() with no record: both controls fail, and say why
            rc = host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7"], host=self.peer_host())
        report = json.loads(out.getvalue())["measured"]
        self.assertEqual(rc, 1)
        self.assertEqual([n for n in host_probe.PLATFORM if not report[n]["value"]], ["root_disk_tpm_unlocked", "root_disk_unlock_revocable"])
        for bad in (["--unlock-peer", "b"], ["--node-id", "A"], ["--node-id", "a", "--unlock-peer", "a"],
                    ["--node-id", "a", "--unlock-peer", "b", "--unlock-peer", "b"], ["--node-id", "a", "--unlock-peer", "b c"]):
            with self.subTest(args=bad), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as refused:
                host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7", *bad], host=self.peer_host())
            self.assertEqual(refused.exception.code, 2)

    def test_nothing_the_local_tpm_opens_by_itself_may_sit_beside_the_peer_paths(self):
        recovery = LUKS_META["tokens"]["1"]
        b, c = self.path("b", "1"), self.path("c", "3")
        cases = {
            "an NV-backed systemd-tpm2 token": ((b, recovery, c, dict(NV_TOKEN, keyslots=["4"])), "a systemd-tpm2 token is still enrolled (keyslot 4)"),
            "a PCR-7 systemd-tpm2 token": ((b, recovery, c, dict(PCR7_TOKEN, keyslots=["4"])), "a systemd-tpm2 token is still enrolled (keyslot 4)"),
            "a clevis token": ((b, recovery, c, {"type": "clevis", "keyslots": ["4"]}), "token 3 of type 'clevis' names keyslot 4"),
            "a second recovery token": ((b, recovery, c, dict(recovery, keyslots=["4"])), "has 2 systemd-recovery tokens"),
            "a path that shares the recovery keyslot": ((b, recovery, dict(c, keyslots=["2"])), "keyslot 2 is named by"),
            "two paths from one peer": ((b, recovery, dict(c, peer="b")), "are both for peer b"),
            "a path token of another version": ((b, recovery, dict(c, version=2)), "a regalia-peer-unlock token of version 1 is expected"),
            "a path token with an extra field": ((b, recovery, dict(c, note="x")), "token fields mismatch"),
        }
        for label, (tokens, reason) in cases.items():
            with self.subTest(label):
                h = self.peer_host(*tokens)
                value, why = host_probe.unlock_revocable(h, self.RECORD)
                self.assertFalse(value, why)
                self.assertIn(reason, why)
                self.assertIn("BLOCKING FOR PRODUCTION (#135)", why)
        # a keyslot no token names, beside the paths
        value, why = host_probe.unlock_revocable(self.peer_host(keyslots=("0", "1", "2", "3")), self.RECORD)
        self.assertFalse(value, why)
        self.assertIn("keyslot 0 is named by no token", why)

    def test_the_peer_shaped_volume_takes_its_key_from_the_unlock_clients_socket_and_nowhere_else(self):
        from deploy.baremetal import unlock
        self.assertEqual(host_probe.PEER_KEY_SOCKET, unlock.KEY_SOCKET)       # one path, in two files
        sock = host_probe.PEER_KEY_SOCKET
        self.assertTrue(host_probe.root_unlock(self.peer_host(crypttab="# root\nroot_crypt UUID=abcd %s luks,discard\n" % sock), self.RECORD)[0])
        every = ",".join(sorted(o + "=1" if o in ("tries", "timeout", "token-timeout", "tpm2-measure-pcr", "tpm2-measure-bank") else o
                                for o in host_probe.PEER_CRYPTTAB_OPTIONS))
        self.assertTrue(host_probe.root_unlock(self.peer_host(crypttab="root_crypt UUID=abcd %s %s\n" % (sock, every)), self.RECORD)[0])
        self.assertEqual(host_probe.PEER_CRYPTTAB_OPTIONS, {"luks", "x-initrd.attach", "discard", "tries", "timeout", "token-timeout",
                                                             "no-read-workqueue", "no-write-workqueue", "same-cpu-crypt",
                                                             "submit-from-crypt-cpus", "tpm2-measure-pcr", "tpm2-measure-bank"})
        # ONLY options known to leave the unlock alone: each of these changes what opens the volume or where its key goes
        for option in ("header=/boot/root.hdr", "link-volume-key=@u::%logon:rootkey", "plain", "tcrypt", "bitlk", "swap", "tmp",
                       "try-empty-password", "noauto", "headless", "headless=true", "key-slot=1", "keyfile-size=16", "nofail",
                       "an-option-of-tomorrow"):
            with self.subTest(option=option):
                value, why = host_probe.root_unlock(self.peer_host(crypttab="root_crypt UUID=abcd %s luks,%s\n" % (sock, option)), self.RECORD)
                self.assertFalse(value, why)
                self.assertIn("its crypttab entry has %s: not among the options known to leave" % option, why)
        # the kernel command line configuring LUKS means the initrd did not go by crypttab
        for cmdline, named in (("root=/dev/mapper/vg-root rd.luks.name=abcd=root_crypt rd.luks.key=abcd=/etc/root.key", "rd.luks.key, rd.luks.name"),
                               ("rd.luks.options=tpm2-device=auto", "rd.luks.options"), ("rd.luks=0", "rd.luks"), ("luks.uuid=abcd", "luks.uuid")):
            with self.subTest(cmdline=cmdline):
                h = self.peer_host()
                h.files["/proc/cmdline"] = cmdline + "\n"
                value, why = host_probe.root_unlock(h, self.RECORD)
                self.assertFalse(value, why)
                self.assertIn("the kernel command line configures LUKS (%s)" % named, why)
        h = self.peer_host()
        h.files.pop("/proc/cmdline")
        self.assertIn("cannot read /proc/cmdline", host_probe.root_unlock(h, self.RECORD)[1])
        for label, crypttab, reason in (
                ("no entry", "", "is not listed in /etc/crypttab: nothing asks the unlock client for its key at boot"),
                ("only another volume listed", "swap UUID=ef01 %s luks\n" % sock, "is not listed in /etc/crypttab"),
                ("no key file", "root_crypt UUID=abcd none luks\n", "its crypttab key file is 'none', not the unlock client's socket"),
                ("no key file field at all", "root_crypt UUID=abcd\n", "its crypttab key file is 'none'"),
                ("a key file on disk", "root_crypt UUID=abcd /etc/keys/root.key luks\n", "its crypttab key file is '/etc/keys/root.key'"),
                ("another socket", "root_crypt UUID=abcd /run/other/key.sock luks\n", "its crypttab key file is '/run/other/key.sock'"),
                ("the TPM as well", "root_crypt UUID=abcd %s tpm2-device=auto\n" % sock, "its crypttab entry has tpm2-device=auto: not among"),
                ("a FIDO2 token as well", "root_crypt UUID=abcd %s luks,fido2-device=auto\n" % sock, "its crypttab entry has fido2-device=auto: not among"),
                ("a PKCS#11 token as well", "root_crypt UUID=abcd %s pkcs11-uri=auto\n" % sock, "its crypttab entry has pkcs11-uri=auto: not among")):
            with self.subTest(label):
                value, why = host_probe.root_unlock(self.peer_host(crypttab=crypttab), self.RECORD)
                self.assertFalse(value, why)
                self.assertIn(reason, why)

    def test_the_local_share_is_sealed_to_the_tpm_alone_under_pcr_7(self):
        """The one credential that must NOT need the host key (it is on the disk being opened), and the one
        place where the TPM-only key types are accepted. It opens nothing without the peer's contribution."""
        self.assertEqual(host_probe.local_share_binding(cred("tpm2-7.cred")), ([7], [], ""))
        self.assertEqual(host_probe.local_share_binding(cred("pk-7-11.cred")), SIGNED)
        recovery = LUKS_META["tokens"]["1"]
        for label, local, reason in (
                ("sealed with the host key as well", "host-tpm2-7.cred", "the local contribution is not a systemd credential sealed to the TPM alone"),
                ("sealed with the host key alone", "host.cred", "the local contribution is not a systemd credential sealed to the TPM alone"),
                ("bound to PCRs 7 and 14", "tpm2-7-14.cred", "the local share of token 0 is sealed to PCRs 7+14, no signed policy, not to PCR 7 exactly")):
            with self.subTest(label):
                h = self.peer_host(self.path("b", "1", local), recovery, self.path("c", "3"))
                for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable):
                    value, why = probe_fn(h, self.RECORD)
                    self.assertFalse(value, why)
                    self.assertIn(reason, why)
        for text, reason in ((cred("host-tpm2-7.cred"), "not sealed to the TPM alone"), (cred("host.cred"), "not sealed to the TPM alone"),
                             ("7310048261", "not base64"), ("", "too short"), (None, "too short"), (7, "not base64"),
                             (base64.b64encode(base64.b64decode(cred("tpm2-7.cred"))[:56]).decode(), "truncated"),
                             (rebanked(cred("tpm2-7.cred"), 0x0004), "bound to PCR bank 0x0004, not SHA-256")):
            with self.subTest(text=str(text)[:24]), self.assertRaises(ValueError) as caught:
                host_probe.local_share_binding(text)
            self.assertIn(reason, str(caught.exception))
        # and the PIN credential's parser still refuses the TPM-only types: the two are not interchangeable
        with self.assertRaises(ValueError) as caught:
            host_probe.credential_header(cred("tpm2-7.cred"))
        self.assertIn("the TPM alone, with no host key", str(caught.exception))

    def test_the_local_share_follows_the_recorded_binding_of_the_pin_credentials(self):
        """With a recorded binding (the evidence, or --credential-pcrs…), the local share must be sealed to
        exactly that: when the PINs get the signed PCR 11 policy, so must it."""
        recovery = LUKS_META["tokens"]["1"]
        plain = self.peer_host()
        signed = self.peer_host(self.path("b", "1", "pk-7-11.cred"), recovery, self.path("c", "3", "pk-7-11.cred"))
        mixed = self.peer_host(self.path("b", "1", "pk-7-11.cred"), recovery, self.path("c", "3"))
        for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable):
            with self.subTest(probe_fn.__name__):
                self.assertTrue(probe_fn(plain, self.RECORD, PCR7)[0])
                self.assertTrue(probe_fn(signed, self.RECORD, SIGNED)[0])
                value, why = probe_fn(plain, self.RECORD, SIGNED)
                self.assertFalse(value, why)
                self.assertIn("the local share of token 0 is sealed to PCRs 7, no signed policy; the recorded binding is PCRs 7, signed PCRs 11 by key pkfp " + PKFP, why)
                value, why = probe_fn(signed, self.RECORD, PCR7)
                self.assertFalse(value, why)
                self.assertIn("the recorded binding is PCRs 7, no signed policy", why)
                self.assertIn("the local share of token 2", probe_fn(mixed, self.RECORD, SIGNED)[1])
                self.assertFalse(probe_fn(signed, self.RECORD, ([7], [11], "0" * 64))[0])    # signed by another key
        # through main(): the binding given for the PINs is the one the local share is held to
        with redirect_stdout(io.StringIO()) as out:
            host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7", "--credential-signed-pcrs", "11",
                             "--credential-pcr-key-pkfp", PKFP, "--node-id", "a", "--unlock-peer", "b", "--unlock-peer", "c"], host=self.peer_host())
        report = json.loads(out.getvalue())["measured"]
        self.assertIn("the recorded binding is PCRs 7, signed PCRs 11", report["root_disk_unlock_revocable"]["why"])
        self.assertIn("the recorded binding is PCRs 7, signed PCRs 11", report["root_disk_tpm_unlocked"]["why"])

    def test_peer_paths_on_a_volume_that_is_not_the_root_one_fail(self):
        """The unlock client opens the root volume only. A second volume holding the host key with peer
        paths of its own could be opened at no boot; it is not judged like the root."""
        h = self.peer_host()
        h.runs[secret_mount(host_probe.HOST_KEY)] = (0, "/dev/mapper/var_crypt ext4 3333-4444\n")
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/var_crypt")] = (0, "var_crypt crypt\nsdb1 part\nsdb disk\n")
        h.runs[("cryptsetup", "status", "var_crypt")] = (0, "  type:    LUKS2\n  device:  /dev/sdb1\n")
        h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdb1")] = (0, json.dumps(
            {"keyslots": {"1": {}, "3": {}}, "tokens": {"0": self.path("b", "1"), "1": self.path("c", "3")}}))
        value, why = host_probe.unlock_revocable(h, self.RECORD)
        self.assertFalse(value, why)
        self.assertIn("var_crypt (/dev/sdb1, under %s) carries regalia-peer-unlock tokens, but it is not the root volume" % host_probe.HOST_KEY, why)
        self.assertIn("BLOCKING FOR PRODUCTION (#135)", why)

    def test_without_the_unlock_module_the_peer_shape_is_not_accepted(self):
        real_import = __import__

        def no_unlock(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "deploy.baremetal" and "unlock" in (fromlist or ()):
                raise ImportError("no module named deploy.baremetal.unlock")
            return real_import(name, globals, locals, fromlist, level)
        with mock.patch("builtins.__import__", side_effect=no_unlock):
            for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable):
                value, why = probe_fn(self.peer_host(), self.RECORD)
                self.assertFalse(value, why)
                self.assertIn("deploy/baremetal/unlock.py cannot be loaded (ImportError", why)

    def test_a_token_of_any_other_type_that_names_a_keyslot_fails(self):
        """clevis seals a key to the TPM under PCR values, in a token systemd never looks at. An NV-backed
        systemd token beside it does not make that keyslot revocable; nor does misspelling the type."""
        recovery = LUKS_META["tokens"]["1"]
        for kind in ("clevis", "acme-tpm2", "Systemd-tpm2", "systemd-tpm2 ", "SYSTEMD-TPM2", "", None, 7):
            with self.subTest(kind=repr(kind)):
                stranger = {"type": kind, "keyslots": ["3"], "tpm2-pcrs": [7]}
                value, why = host_probe.unlock_revocable(self.judge(NV_TOKEN, recovery, stranger))
                self.assertFalse(value, why)
                self.assertIn("token 2 of type %r names keyslot 3" % (kind,), why)
                self.assertIn("BLOCKING FOR PRODUCTION (#135)", why)
        # a token of another type that names no keyslot releases nothing
        self.assertTrue(host_probe.unlock_revocable(self.judge(NV_TOKEN, recovery, {"type": "note", "keyslots": []}))[0])

    def test_a_token_must_name_keyslots_that_exist(self):
        """A stale token naming a wiped keyslot unlocks nothing: "every TPM token is NV-backed" would be
        true of a volume the TPM cannot open at all."""
        recovery = LUKS_META["tokens"]["1"]
        for slots in (["9"], ["1", "9"], ["01"], [""], ["1 "]):
            with self.subTest(keyslots=repr(slots)):
                h = self.judge(dict(NV_TOKEN, keyslots=slots), recovery, keyslots=("1", "2"))
                value, why = host_probe.unlock_revocable(h)
                self.assertFalse(value, why)
                self.assertIn("which are not all keyslots of this header", why)
                value, why = host_probe.root_unlock(h)
                self.assertFalse(value, why)
                self.assertIn("no systemd-tpm2 token", why)
        # the recovery token too: one that names a keyslot which is gone is stale, not "the recovery key"
        h = self.judge(NV_TOKEN, dict(recovery, keyslots=["7"]), keyslots=("1",))
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("token 1 (systemd-recovery) names keyslots ['7'], which are not all keyslots of this header", why)
        # keyslots that are not a list of text make the header one no probe judges, and none raises
        for slots in ("1", 1, [1], [["1"]], {"1": 1}, [True], [None]):
            with self.subTest(keyslots=repr(slots)):
                h = self.judge(dict(NV_TOKEN, keyslots=slots), recovery, keyslots=("1", "2"))
                for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable, host_probe.recovery_keyslot):
                    value, why = probe_fn(h)
                    self.assertFalse(value, why)
                    self.assertIn("is malformed: token 0 names keyslots", why)

    def test_every_keyslot_of_a_secret_volume_is_named_by_exactly_one_token(self):
        """A keyslot no token names is opened by something this check cannot see. On the root volume the
        recovery probe says so too; on a second volume holding the host key, nothing else would."""
        recovery = LUKS_META["tokens"]["1"]
        value, why = host_probe.unlock_revocable(self.judge(NV_TOKEN, recovery, keyslots=("0", "1", "2")))
        self.assertFalse(value, why)
        self.assertIn("keyslot 0 is named by no token: a passphrase, a key file or a sealed key this check cannot judge", why)
        value, why = host_probe.unlock_revocable(self.judge(NV_TOKEN, dict(recovery, keyslots=["1"]), keyslots=("1",)))
        self.assertFalse(value, why)
        self.assertIn("keyslot 1 is named by more than one token (token 0, token 1)", why)
        value, why = host_probe.unlock_revocable(self.judge(NV_TOKEN, recovery, dict(recovery, keyslots=["3"])))
        self.assertFalse(value, why)
        self.assertIn("has 2 systemd-recovery tokens", why)

        # the same on the volume that holds the host key: a key file's keyslot beside an NV-backed token
        def var(tokens, keyslots):
            h = FakeHost()
            h.files["/etc/crypttab"] += "var_crypt UUID=ef01 /boot/efi/var.key luks\n"
            h.runs[secret_mount(host_probe.HOST_KEY)] = (0, "/dev/mapper/var_crypt ext4 3333-4444\n")
            h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/var_crypt")] = (0, "var_crypt crypt\nsdb1 part\nsdb disk\n")
            h.runs[("cryptsetup", "status", "var_crypt")] = (0, "  type:    LUKS2\n  device:  /dev/sdb1\n")
            h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdb1")] = (0, json.dumps({"keyslots": {k: {} for k in keyslots}, "tokens": tokens}))
            return h
        h = var({"0": NV_TOKEN}, ("0", "1"))
        self.assertEqual([n for n, (value, _) in platform(h).items() if not value], ["root_disk_unlock_revocable"])
        self.assertIn("var_crypt (/dev/sdb1, under %s): keyslot 0 is named by no token" % host_probe.HOST_KEY, host_probe.unlock_revocable(h)[1])
        self.assertTrue(host_probe.unlock_revocable(var({"0": NV_TOKEN}, ("1",)))[0])

    def test_the_nv_policy_must_be_shown_to_cover_pcr_7_and_the_boot_image(self):
        """systemd-pcrlock leaves out a PCR it cannot predict. An NV-backed token says nothing by itself
        about which PCRs bind the disk; the policy file does."""
        def policy(*pcrs, **change):
            doc = dict(PCRLOCK, pcrValues=[{"pcr": n, "values": ["%064x" % (n + 1)]} for n in pcrs], **change)
            return lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(doc))

        def zeros(pcr, beside=False):
            values = {7: ["07" * 32], 11: ["0b" * 32]}
            values[pcr] = ["00" * 32] + (values[pcr] if beside else [])
            doc = dict(PCRLOCK, pcrValues=[{"pcr": n, "values": v} for n, v in values.items()])
            return lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(doc))
        recovery = LUKS_META["tokens"]["1"]
        self.assertEqual(host_probe.IMAGE_PCRS, {4, 11})
        for pcrs in ((7, 11), (7, 4), (0, 4, 7, 11, 12)):
            with self.subTest(pcrs=pcrs):
                h = self.judge(NV_TOKEN, recovery, prepare=policy(*pcrs))
                self.assertTrue(host_probe.unlock_revocable(h)[0])
                self.assertTrue(host_probe.root_unlock(h)[0])
        cases = {
            "only PCR 7: every old image satisfies it": (policy(7), "binds PCRs [7] (with measured values): it must bind PCR 7 and a PCR that tells boot images apart", True),
            "the image but not PCR 7": (policy(4, 11), "binds PCRs [4, 11]", False),
            "neither": (policy(0, 2), "binds PCRs [0, 2]", False),
            "PCR 12 is not the image": (policy(7, 12), "binds PCRs [7, 12]", True),
            "PCR 9 is not the image": (policy(7, 9), "binds PCRs [7, 9]", True),
            # a PCR nothing was measured into is zero on every boot of every image
            "PCR 11 accepted as all zeros": (zeros(11), "binds PCRs [7] (with measured values)", True),
            "PCR 11 with a zero value beside a real one": (zeros(11, beside=True), "binds PCRs [7] (with measured values)", True),
            "PCR 7 accepted as all zeros": (zeros(7), "binds PCRs [11]", False),
            "PCR 11 listed twice, once with zeros": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(dict(
                PCRLOCK, pcrValues=[{"pcr": 7, "values": ["07" * 32]}, {"pcr": 11, "values": ["0b" * 32]}, {"pcr": 11, "values": ["00" * 32]}]))),
                "lists PCR 11 twice", False),
            "a value that is not 64 hex": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(dict(
                PCRLOCK, pcrValues=[{"pcr": 7, "values": ["07" * 32]}, {"pcr": 11, "values": ["xyz"]}]))), "has a PCR entry that is not", False),
            "a value in upper case": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(dict(
                PCRLOCK, pcrValues=[{"pcr": 7, "values": ["07" * 32]}, {"pcr": 11, "values": ["AB" * 32]}]))), "has a PCR entry that is not", False),
            "no policy file": (lambda h: h.files.pop(host_probe.PCRLOCK_POLICY), "there is no /var/lib/systemd/pcrlock.json", False),
            "not JSON": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, "{"), "is not a SHA-256 pcrlock policy", False),
            "the SHA-1 bank": (policy(7, 11, pcrBank="sha1"), "is not a SHA-256 pcrlock policy", False),
            "no PCR values": (policy(), "is not a SHA-256 pcrlock policy", False),
            "a PCR with no accepted value": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(dict(
                PCRLOCK, pcrValues=[{"pcr": 7, "values": []}, {"pcr": 11, "values": ["0b" * 32]}]))), "has a PCR entry that is not", False),
            "a PCR number as text": (lambda h: h.files.__setitem__(host_probe.PCRLOCK_POLICY, json.dumps(dict(
                PCRLOCK, pcrValues=[{"pcr": "7", "values": ["07" * 32]}, {"pcr": 11, "values": ["0b" * 32]}]))), "has a PCR entry that is not", False),
        }
        for label, (prepare, reason, still_tpm_unlocked) in cases.items():
            with self.subTest(label):
                h = self.judge(NV_TOKEN, recovery, prepare=prepare)
                value, why = host_probe.unlock_revocable(h)
                self.assertFalse(value, why)
                self.assertIn(reason, why)
                self.assertIn("BLOCKING FOR PRODUCTION (#135)", why)
                # and the widened root_disk_tpm_unlocked: an NV-backed token counts only when its policy binds PCR 7
                self.assertEqual(host_probe.root_unlock(h)[0], still_tpm_unlocked, host_probe.root_unlock(h)[1])
        # a PCR-7 token needs no policy file, with or without a stray tpm2_pcrlock flag: it is judged by its PCR list
        for token in (PCR7_TOKEN, dict(PCR7_TOKEN, tpm2_pcrlock=True)):
            h = self.judge(token, recovery, prepare=lambda h: h.files.pop(host_probe.PCRLOCK_POLICY))
            self.assertTrue(host_probe.root_unlock(h)[0], token)

    def test_every_volume_that_holds_a_secret_is_judged_not_only_the_root(self):
        """The host key on a separate /var whose LUKS volume a PCR-7 token opens: the root volume is
        revocable, and an old image reads the host key all the same."""
        def separate_var(h, tokens):
            h.runs[secret_mount(host_probe.HOST_KEY)] = (0, "/dev/mapper/vg-var ext4 3333-4444\n")
            h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-var")] = (0, "vg-var lvm\nvar_crypt crypt\nsdb1 part\nsdb disk\n")
            h.runs[("cryptsetup", "status", "var_crypt")] = (0, "/dev/mapper/var_crypt is active.\n  type:    LUKS2\n  device:  /dev/sdb1\n")
            h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdb1")] = (0, json.dumps(
                {"keyslots": {"1": {}, "2": {}}, "tokens": tokens}))
        h = FakeHost()
        separate_var(h, {"0": PCR7_TOKEN, "1": LUKS_META["tokens"]["1"]})
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("var_crypt (/dev/sdb1) is unlocked by the local TPM alone", why)
        self.assertTrue(host_probe.root_unlock(h)[0])                    # the root volume itself is fine
        h = FakeHost()
        separate_var(h, {"0": NV_TOKEN, "1": LUKS_META["tokens"]["1"]})
        value, why = host_probe.unlock_revocable(h)
        self.assertTrue(value, why)
        self.assertIn("root_crypt, var_crypt:", why)
        # a volume opened by a key file (no TPM token) cannot be judged, and says which secret is on it
        h = FakeHost()
        separate_var(h, {})
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("var_crypt (/dev/sdb1, under %s): keyslot 1, 2 is named by no token" % host_probe.HOST_KEY, why)
        # the credentials themselves on a volume a PCR-7 token opens
        self.assertEqual(host_probe.SECRET_PATHS, ("/", "/var/lib/systemd/credential.secret", "/etc/credstore.encrypted"))
        h = FakeHost()
        h.runs[secret_mount(host_probe.CREDSTORE)] = (0, "/dev/mapper/etc_crypt ext4 7777-8888\n")
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/etc_crypt")] = (0, "etc_crypt crypt\nsdc1 part\nsdc disk\n")
        h.runs[("cryptsetup", "status", "etc_crypt")] = (0, "  type:    LUKS2\n  device:  /dev/sdc1\n")
        h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdc1")] = (0, json.dumps({"keyslots": {"1": {}}, "tokens": {"0": PCR7_TOKEN}}))
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("etc_crypt (/dev/sdc1) is unlocked by the local TPM alone", why)
        # one filesystem over TWO encrypted devices (LVM over two PVs): both are judged, not the first
        h = FakeHost()
        h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/vg-root")] = (
            0, "vg-root lvm\nroot_crypt crypt\nsda3 part\nsda disk\npv2_crypt crypt\nsdb1 part\nsdb disk\n")
        h.runs[("cryptsetup", "status", "pv2_crypt")] = (0, "  type:    LUKS2\n  device:  /dev/sdb1\n")
        h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdb1")] = (0, json.dumps({"keyslots": {"1": {}}, "tokens": {"0": PCR7_TOKEN}}))
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("pv2_crypt (/dev/sdb1) is unlocked by the local TPM alone", why)
        # each secret path is looked up, and one that is on no dm-crypt device fails
        for path in host_probe.SECRET_PATHS:
            with self.subTest(path=path):
                h = FakeHost()
                h.runs[secret_mount(path)] = (0, "/dev/sdc1 ext4 5555-6666\n")
                h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/sdc1")] = (0, "sdc1 part\nsdc disk\n")
                self.assertEqual(host_probe.unlock_revocable(h), (False, "%s is on /dev/sdc1, which is not on dm-crypt" % path))
                h = FakeHost()
                h.runs.pop(secret_mount(path))
                self.assertEqual(host_probe.unlock_revocable(h), (False, "cannot find the filesystem that holds %s (findmnt)" % path))

    def test_every_member_of_a_multi_device_btrfs_is_judged(self):
        """findmnt names ONE device of a btrfs that spans two; the other's header must be read too."""
        def btrfs(h, second_tokens):
            for path in host_probe.SECRET_PATHS:
                h.runs[secret_mount(path)] = (0, "/dev/mapper/root_crypt[/@] btrfs aaaa-bbbb\n")
            h.runs[("lsblk", "-n", "-r", "-o", "PATH,UUID")] = (0, "/dev/sda \n/dev/mapper/root_crypt aaaa-bbbb\n/dev/mapper/second_crypt aaaa-bbbb\n/dev/sdd1 cccc-dddd\n")
            h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/root_crypt")] = (0, "root_crypt crypt\nsda3 part\nsda disk\n")
            h.runs[("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/mapper/second_crypt")] = (0, "second_crypt crypt\nsdb1 part\nsdb disk\n")
            h.runs[("cryptsetup", "status", "second_crypt")] = (0, "  type:    LUKS2\n  device:  /dev/sdb1\n")
            h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sdb1")] = (0, json.dumps({"keyslots": {"1": {}}, "tokens": second_tokens}))
        h = FakeHost()
        btrfs(h, {"0": PCR7_TOKEN})
        value, why = host_probe.unlock_revocable(h)
        self.assertFalse(value, why)
        self.assertIn("second_crypt (/dev/sdb1) is unlocked by the local TPM alone", why)
        h = FakeHost()
        btrfs(h, {"0": NV_TOKEN})
        self.assertTrue(host_probe.unlock_revocable(h)[0])
        h = FakeHost()
        btrfs(h, {"0": NV_TOKEN})
        h.runs.pop(("lsblk", "-n", "-r", "-o", "PATH,UUID"))
        self.assertEqual(host_probe.unlock_revocable(h), (False, "cannot list the devices of the btrfs filesystem that holds / (lsblk)"))

    def test_a_header_that_is_not_a_header_is_refused_by_every_root_disk_probe_and_never_raises(self):
        for label, meta in (("tokens as a list", {"keyslots": {"1": {}}, "tokens": [NV_TOKEN]}),
                            ("tokens null", {"keyslots": {"1": {}}, "tokens": None}),
                            ("a token that is a list", {"keyslots": {"1": {}}, "tokens": {"0": NV_TOKEN, "1": ["x"]}}),
                            ("a token that is text", {"keyslots": {"1": {}}, "tokens": {"0": "systemd-tpm2"}}),
                            ("keyslots as a list", {"keyslots": ["1"], "tokens": {"0": NV_TOKEN}}),
                            ("a keyslot that is a number", {"keyslots": {"1": 1}, "tokens": {"0": NV_TOKEN}}),
                            ("a token whose keyslots is a number", {"keyslots": {"1": {}}, "tokens": {"0": dict(NV_TOKEN, keyslots=1)}})):
            with self.subTest(label):
                h = FakeHost()
                h.runs[LUKS_DUMP] = (0, json.dumps(meta))
                for probe_fn in (host_probe.root_unlock, host_probe.unlock_revocable, host_probe.recovery_keyslot):
                    value, why = probe_fn(h)
                    self.assertFalse(value, why)
                    self.assertIn("the LUKS2 header of /dev/sda3 is malformed", why)

    def test_a_probe_that_raises_is_a_failing_control_in_the_report_not_a_crash(self):
        h = FakeHost()
        with mock.patch.dict(host_probe.PROBES, uefi_boot=lambda host: 1 / 0), redirect_stdout(io.StringIO()) as out:
            rc = host_probe.main(["--import-key-sha256", FP[:16], "--credential-pcrs", "7"], host=h)
        report = json.loads(out.getvalue())
        self.assertEqual(rc, 1)
        self.assertEqual(report["measured"]["uefi_boot"], {"value": False, "why": "the probe raised ZeroDivisionError: division by zero "
                                                                                 "(not measured: counted as failing)"})
        self.assertTrue(report["measured"]["secure_boot_enabled"]["value"])   # the others were still measured

    def test_an_nv_backed_token_counts_as_tpm_unlocked_and_a_pcr_list_must_still_be_exactly_7(self):
        value, why = host_probe.root_unlock(FakeHost())                  # the default fixture is NV-backed, with no PCR list
        self.assertTrue(value, why)
        h = FakeHost()
        h.runs[LUKS_DUMP] = (0, LUKS_TODAY)
        self.assertTrue(host_probe.root_unlock(h)[0])
        for token in (dict(NV_TOKEN, tpm2_pcrlock="true"), dict(NV_TOKEN, tpm2_pcrlock=False), dict(PCR7_TOKEN, **{"tpm2-pcrs": [9]}),
                      dict(NV_TOKEN, **{"tpm2-pcrs": [9]}), dict(NV_TOKEN, **{"tpm2-pcrs": [7, 9]})):   # tpm2_pcrlock true does not excuse a PCR list
            with self.subTest(token=token):
                h = FakeHost()
                h.runs[LUKS_DUMP] = (0, json.dumps(dict(LUKS_META, tokens=dict(LUKS_META["tokens"], **{"0": token}))))
                value, why = host_probe.root_unlock(h)
                self.assertFalse(value, why)
                self.assertIn("not exactly [7] and not NV-backed", why)

    def test_the_recovery_keyslot_is_one_keyslot_of_its_own_and_nothing_is_left_unlabelled(self):
        tpm, recovery = LUKS_META["tokens"]["0"], LUKS_META["tokens"]["1"]
        slots = lambda *names: {n: {"type": "luks2"} for n in names}
        cases = {
            "no systemd-recovery token": ({"keyslots": slots("1"), "tokens": {"0": tpm}}, "no recovery keyslot"),
            # cryptsetup leaves such a token behind when a keyslot is destroyed by hand: it is not a key
            "only a recovery token naming no keyslot": ({"keyslots": slots("1"), "tokens": {"0": tpm, "1": dict(recovery, keyslots=[])}}, "no recovery keyslot"),
            "a recovery keyslot a boot prompt would not try": ({"keyslots": dict(slots("1"), **{"2": {"type": "luks2", "priority": 0}}), "tokens": {"0": tpm, "1": recovery}}, "priority 'ignore'"),
            "two recovery keys": ({"keyslots": slots("1", "2", "3"), "tokens": {"0": tpm, "1": recovery, "2": dict(recovery, keyslots=["3"])}}, "ONE recovery key"),
            "one recovery token naming two keyslots": ({"keyslots": slots("1", "2", "3"), "tokens": {"0": tpm, "1": dict(recovery, keyslots=["2", "3"])}}, "ONE recovery key"),
            "a token naming a keyslot that is gone": ({"keyslots": slots("1"), "tokens": {"0": tpm, "1": recovery}}, "does not exist"),
            "the recovery token on the TPM's keyslot": ({"keyslots": slots("1"), "tokens": {"0": tpm, "1": dict(recovery, keyslots=["1"])}}, "a keyslot of its own"),
            "the installer's passphrase still there": ({"keyslots": slots("0", "1", "2"), "tokens": {"0": tpm, "1": recovery}}, "keyslot 0 is named by no token"),
            # A passphrase volume with a recovery key and no TPM: this check is about the recovery
            # keyslot only (root_disk_tpm_unlocked is the one that fails), so it passes.
        }
        for name, (meta, reason) in cases.items():
            with self.subTest(name=name):
                value, why = host_probe.recovery_keyslots(meta)
                self.assertFalse(value, "%s passed: %s" % (name, why))
                self.assertIn(reason, why)
        value, why = host_probe.recovery_keyslots(LUKS_META)
        self.assertTrue(value, why)
        # An empty recovery token beside the real one (a keyslot once removed by hand, a new key
        # enrolled since) does not make a second recovery key: the host is correctly commissioned.
        orphaned = dict(LUKS_META, tokens=dict(LUKS_META["tokens"], **{"7": dict(recovery, keyslots=[])}))
        value, why = host_probe.recovery_keyslots(orphaned)
        self.assertTrue(value, why)
        self.assertIn("recovery keyslot 2", why)
        self.assertIn("systemd-tpm2 in keyslot 1", why)
        # The probe reads the header and nothing else: it never runs a command that could take a key.
        h = FakeHost()
        seen = []
        real = h.run
        h.run = lambda argv: (seen.append(tuple(argv)), real(argv))[1]
        self.assertTrue(host_probe.recovery_keyslot(h)[0])
        self.assertEqual({c[:2] for c in seen}, {("findmnt", "-n"), ("lsblk", "-s"), ("cryptsetup", "status"), ("cryptsetup", "luksDump")})
        h.runs.pop(LUKS_DUMP)
        self.assertIn("cannot read the LUKS2 header", host_probe.recovery_keyslot(h)[1])

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
        for pcrs in ([], [9], [7, 9], [7, "7"], 7, "7", None, {"7": 1}):
            with self.subTest(pcrs=pcrs):
                h = FakeHost()
                h.runs[("cryptsetup", "luksDump", "--dump-json-metadata", "/dev/sda3")] = (0, json.dumps(
                    {"keyslots": {"1": {}}, "tokens": {"0": {"type": "systemd-tpm2", "keyslots": ["1"], "tpm2-pcrs": pcrs}}}))
                value, why = host_probe.root_unlock(h)
                self.assertFalse(value)
                self.assertIn("not exactly [7] and not NV-backed", why)

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
        self.assertEqual(host_probe.credential_header(cred("host-tpm2-7.cred")), PCR7)
        self.assertEqual(host_probe.credential_header(cred("host-tpm2-7-14.cred")), ([7, 14], [], ""))
        self.assertEqual(host_probe.credential_header(cred("host-pk-7-11.cred")), SIGNED)
        self.assertEqual(host_probe.rsa_pkfp(cred("pcr.pub")), PKFP)

    def test_pin_credentials_must_be_sealed_exactly_as_recorded(self):
        signed = cred("host-pk-7-11.cred")
        cases = {
            # (the blob on the host, the record) -> the reason
            "PCR 7 recorded, PCR 7+14 sealed": (cred("host-tpm2-7-14.cred"), PCR7, "sealed to PCRs 7+14, no signed policy; the record says PCRs 7, no signed policy"),
            "a signed policy recorded, none sealed": (cred("host-tpm2-7.cred"), SIGNED, "the record says PCRs 7, signed PCRs 11 by key pkfp " + PKFP),
            "no signed policy recorded, one sealed": (signed, PCR7, "signed PCRs 11 by key pkfp " + PKFP),
            "signed by another key than the recorded one": (signed, ([7], [11], "0" * 64), "the record says PCRs 7, signed PCRs 11 by key pkfp " + "0" * 64),
            "the host key alone": (cred("host.cred"), PCR7, "the host key alone (bench only)"),
            # what seal-hsm-pin.sh made before #75: any image the PCR key ever signed opens these without the disk
            "the TPM alone": (cred("tpm2-7.cred"), PCR7, "the TPM alone, with no host key"),
            "the TPM alone, under a signed policy": (cred("pk-7-11.cred"), SIGNED, "the TPM alone, with no host key"),
            "the TPM alone says how to fix it": (cred("pk-7-11.cred"), SIGNED, "Reseal it from the PIN card with seal-hsm-pin.sh --replace"),
            "a null key": (retyped(cred("host.cred"), "058469daf6f54324800549da0f8ea2fb"), PCR7, "a null key"),
            "an unknown type": (retyped(signed, "00" * 16), SIGNED, "an unknown credential type"),
            # cut inside the signed-policy header, and inside the TPM header
            "a blob cut in its signing key": (base64.b64encode(base64.b64decode(signed)[:360]).decode(), SIGNED, "truncated"),
            "a blob cut in its TPM header": (base64.b64encode(base64.b64decode(signed)[:56]).decode(), SIGNED, "truncated"),
            # whole headers, but not enough left for the encrypted metadata and the tag
            "a blob cut after its headers": (base64.b64encode(base64.b64decode(cred("host-tpm2-7.cred"))[:-40]).decode(), PCR7, "truncated"),
            # the same PCR number in another bank is another PCR (bank u16 at offset 56: SHA-1 is 0x0004)
            "PCR 7 of the SHA-1 bank": (rebanked(cred("host-tpm2-7.cred"), 0x0004), PCR7, "bound to PCR bank 0x0004, not SHA-256"),
            "a signed blob in the SHA-1 bank": (rebanked(signed, 0x0004), SIGNED, "bound to PCR bank 0x0004, not SHA-256"),
            "a PIN in clear": ("7310048261\n", PCR7, "not base64"),
            "too short to be a credential": ("QUJD\n", PCR7, "too short"),
            "an unreadable file": (None, PCR7, "too short"),
            "nothing recorded to compare with": (cred("host-tpm2-7.cred"), None, "no recorded binding to compare"),
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

    def test_the_host_key_must_be_roots_alone_and_on_the_encrypted_disk(self):
        """The credential's other half. On a clear disk it is one more file an old image can read."""
        value, why = host_probe.pin_credentials(FakeHost(), PCR7)
        self.assertTrue(value, why)
        self.assertIn("sealed to the host key and the TPM", why)
        self.assertIn("the host key is root's, 0400, on root_crypt", why)
        cases = {
            "no host key file": ({HOST_KEY_STAT: (1, "")}, "cannot be read"),
            "group-readable (0440)": ({HOST_KEY_STAT: (0, "8120|0\n")}, "mode 0x8120, owner 0"),
            "writable by root (0600)": ({HOST_KEY_STAT: (0, "8180|0\n")}, "must be a regular file, root's, mode 0400"),
            "owned by another user": ({HOST_KEY_STAT: (0, "8100|1000\n")}, "mode 0x8100, owner 1000"),
            "a symbolic link": ({HOST_KEY_STAT: (0, "a1ff|0\n")}, "must be a regular file"),
            "a directory": ({HOST_KEY_STAT: (0, "4100|0\n")}, "must be a regular file"),
            "an answer that is not a mode": ({HOST_KEY_STAT: (0, "\n")}, "must be a regular file"),
            "no filesystem found": ({HOST_KEY_MOUNT: (1, "")}, "cannot find the filesystem"),
            "on a clear disk": ({HOST_KEY_MOUNT: (0, "/dev/sdb1\n"),
                                 ("lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", "/dev/sdb1"): (0, "sdb1 part\nsdb disk\n")},
                                "is not on dm-crypt"),
            "on a tmpfs": ({HOST_KEY_MOUNT: (0, "tmpfs\n")}, "is not on dm-crypt"),
        }
        for label, (runs, reason) in cases.items():
            with self.subTest(label):
                h = FakeHost()
                h.runs.update(runs)
                value, why = host_probe.pin_credentials(h, PCR7)
                self.assertFalse(value, why)
                self.assertIn(reason, why)

    def test_a_blob_sealed_as_recorded_must_also_open_on_this_boot(self):
        """A blob cut by a few bytes keeps a whole header (measured: systemd says 'Encrypted file too
        short'); so does one sealed by another TPM, or under a name the unit does not load it by."""
        h = FakeHost()
        h.files[PIN_FILE] = base64.b64encode(base64.b64decode(cred("host-tpm2-7.cred"))[:-20]).decode()
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
        h.files[host_probe.CREDSTORE + "/regalia-kms-yubikey-site-a.pin"] = cred("host-tpm2-7.cred")
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
                    tpm_ek_certificate_present=True, node_id="a", unlock_peers=["b", "c"])
        host.update(host_overrides)
        return {"schema": evidence.SCHEMA, "site": "site-a", "host_serial": "CZJ1234567",
                "captured_at": self.now, "host": host}

    def write(self, doc):
        path = os.path.join(self.d, "e.json")
        with open(path, "w") as f:
            json.dump(doc, f)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.key, "-out", path + ".sig", path], check=True)
        return path, path + ".sig"

    def run_probe(self, path, sig, measured=None, key_sha=None, extra=()):
        args = ["--evidence", path, "--signature", sig, "--evidence-key", self.pub,
                "--evidence-key-sha256", key_sha or self.key_sha, *extra]
        with mock.patch.object(host_probe, "measure", return_value=measured or self.everything) as measure, \
                redirect_stdout(io.StringIO()) as out:
            rc = host_probe.main(args, host=FakeHost())
        self.judged_against = measure.call_args.args[3]
        return rc, json.loads(out.getvalue())

    def test_the_record_of_a_bad_unlock_record_is_refused_by_validate_itself(self):
        """evidence.validate refuses a malformed record on its own, whatever its caller does next."""
        bad = {"a node ID that is a number": dict(node_id=1), "an empty node ID": dict(node_id=""),
               "a node ID of 33 characters": dict(node_id="a" * 33), "a leading dash": dict(node_id="-a"),
               "a lookalike letter": dict(node_id="\uff41"), "a trailing newline": dict(node_id="a\n"),
               "peers as a string": dict(unlock_peers="bc"), "peers as a tuple-like object": dict(unlock_peers={"b": 1}),
               "a peer that is not a node ID": dict(unlock_peers=["b", "C"]), "a peer that is a bool": dict(unlock_peers=[True]),
               "seventeen peers": dict(unlock_peers=["p%d" % i for i in range(17)])}
        for label, change in bad.items():
            with self.subTest(label), self.assertRaises(evidence.InvalidEvidence):
                evidence.validate(self.doc(**change), host_probe.MEASURED)
        for good in (dict(node_id="a" * 32), dict(unlock_peers=[]), dict(unlock_peers=["p%d" % i for i in range(16)])):
            evidence.validate(self.doc(**good), host_probe.MEASURED)

    def test_the_root_disk_is_judged_against_the_signed_unlock_record(self):
        """#67: which node this is and who its peers are come from the signed evidence. Arguments may repeat
        them, in any order; arguments that differ are a failing problem, and never replace the record."""
        rc, report = self.run_probe(*self.write(self.doc()))
        self.assertEqual((rc, self.judged_against), (0, ("a", ("b", "c"))), report.get("evidence_problems"))
        rc, report = self.run_probe(*self.write(self.doc()), extra=["--node-id", "a", "--unlock-peer", "c", "--unlock-peer", "b"])
        self.assertEqual((rc, self.judged_against), (0, ("a", ("b", "c"))), report.get("evidence_problems"))
        for extra in (["--node-id", "b", "--unlock-peer", "a", "--unlock-peer", "c"], ["--node-id", "a", "--unlock-peer", "b"],
                      ["--node-id", "a", "--unlock-peer", "b", "--unlock-peer", "c", "--unlock-peer", "d"]):
            with self.subTest(extra):
                rc, report = self.run_probe(*self.write(self.doc()), extra=extra)
                self.assertEqual(rc, 1)
                self.assertTrue(any("they disagree, and the root disk is judged against the evidence" in p for p in report["evidence_problems"]),
                                report["evidence_problems"])
                self.assertEqual(self.judged_against, ("a", ("b", "c")))
        # a host not enrolled for peer unlock records no peers: the record is still there, and a disk WITH
        # peer tokens is then refused by unlock.judge_tokens for peers nobody recorded
        rc, report = self.run_probe(*self.write(self.doc(unlock_peers=[])))
        self.assertEqual((rc, self.judged_against), (0, ("a", ())), report.get("evidence_problems"))
        # and the other direction: recorded peers, a root disk that the TPM alone opens: not the recorded disk
        self.assertTrue(host_probe.root_unlock(FakeHost(), ("a", ()))[0])
        for control in (host_probe.root_unlock, host_probe.unlock_revocable):     # both controls, about the same disk
            ok, why = control(FakeHost(), ("a", ("b", "c")))
            self.assertFalse(ok, control.__name__)
            self.assertIn("carries no regalia-peer-unlock token, but the unlock record names the peers b, c", why)
        self.assertNotIn("unlock record", host_probe.unlock_revocable(FakeHost(), ("a", ()))[1])
        self.assertIn("node_id", report["attested_not_measured"])
        self.assertIn("unlock_peers", report["attested_not_measured"])

    def test_complete_signed_agreeing_evidence_passes(self):
        rc, report = self.run_probe(*self.write(self.doc()))
        self.assertEqual(rc, 0, report.get("evidence_problems"))

    def test_no_evidence_can_be_signed_for_a_host_with_the_known_blocker(self):
        """Evidence records a commissioned host: every measured control true. A host enrolled with
        --tpm2-pcrs=7 fails root_disk_unlock_revocable (#135), so an honest record of it is refused, and
        evidence captured before the control existed is refused for lacking it. Intended: such a host is
        not commissioned. Without --evidence the report shows the one failing control."""
        rc, report = self.run_probe(*self.write(self.doc(root_disk_unlock_revocable=False)))
        self.assertEqual(rc, 1)
        self.assertTrue(any("host.root_disk_unlock_revocable must be true" in p for p in report["evidence_problems"]), report["evidence_problems"])
        before = self.doc()
        del before["host"]["root_disk_unlock_revocable"]
        rc, report = self.run_probe(*self.write(before))
        self.assertEqual(rc, 1)
        self.assertTrue(any("root_disk_unlock_revocable" in p for p in report["evidence_problems"]), report["evidence_problems"])

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
            "no node ID": (dict(full, host={k: v for k, v in full["host"].items() if k != "node_id"}), "missing"),
            "no unlock peers record": (dict(full, host={k: v for k, v in full["host"].items() if k != "unlock_peers"}), "missing"),
            "a node ID that is not one": (self.doc(node_id="Site A"), "node_id must be a node ID"),
            "the node as its own peer": (self.doc(unlock_peers=["b", "a"]), "never the node itself"),
            "a peer twice": (self.doc(unlock_peers=["b", "b"]), "each peer once"),
            "peers as a string": (self.doc(unlock_peers="b,c"), "must be a list"),
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
        self.assertTrue(run(self.doc(), cred("host-tpm2-7.cred"))["value"])
        self.assertTrue(run(signed_doc, cred("host-pk-7-11.cred"))["value"])
        for doc, blob in ((self.doc(), cred("host-pk-7-11.cred")), (signed_doc, cred("host-tpm2-7.cred"))):
            result = run(doc, blob)
            self.assertFalse(result["value"])
            self.assertIn("the record says", result["why"])

    def test_without_evidence_the_binding_comes_from_the_command_line(self):
        def run(*args, blob="host-tpm2-7.cred"):
            host = FakeHost()
            host.files[PIN_FILE] = cred(blob)
            with redirect_stdout(io.StringIO()) as out:
                host_probe.main(["--import-key-sha256", FP[:16], *args], host=host)
            return json.loads(out.getvalue())["measured"]["pin_credentials_sealed_as_recorded"]
        self.assertTrue(run("--credential-pcrs", "7")["value"])
        self.assertTrue(run("--credential-pcrs", "7", "--credential-signed-pcrs", "11", "--credential-pcr-key-pkfp", PKFP,
                            blob="host-pk-7-11.cred")["value"])
        self.assertIn("no recorded binding to compare", run()["why"])
        self.assertFalse(run("--credential-pcrs", "7", blob="host-pk-7-11.cred")["value"])
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
