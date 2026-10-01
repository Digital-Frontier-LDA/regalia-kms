#!/usr/bin/env python3
"""Measure a bare-metal KMS host's platform, TPM and OS controls from the host itself (ADR-0002 D21).

The KMS runs on dedicated bare metal with a discrete TPM 2.0 (regalia#46: HPE DL360 Gen9). This probe
reads the running host and reports each control with the reason for its verdict; with an evidence
file it also refuses one that claims a control the host does not have. Same contract as
deploy/proxmox/guest_probe.py, whose OS probes (core dumps, hibernation, swap, an unprivileged service)
it reuses; its token-client probe is replaced (below), because on bare metal the host itself seals and
re-seals the PINs and so needs opensc-tool and pkcs11-tool.

    sudo python3 deploy/baremetal/host_probe.py --import-key-sha256 HEX                 # exit 1 unless every control is true
    sudo python3 deploy/baremetal/host_probe.py --import-key-sha256 HEX --evidence E.json   # and E agrees

PLATFORM AND TPM, measured:
  uefi_boot                 booted through UEFI (/sys/firmware/efi): TPM 2.0 measured boot needs it
  secure_boot_enabled       the SecureBoot EFI variable is 1
  tpm2_present              a TPM whose major version is 2, behind the kernel resource manager
                            (/dev/tpmrm0): seal-hsm-pin.sh refuses the raw /dev/tpm0
  tpm_sha256_bank           the TPM exposes an active SHA-256 PCR bank (/sys/class/tpm/tpm0/pcr-sha256)
  root_disk_tpm_unlocked    a dm-crypt device is among the root filesystem's block-device ancestors
                            (lsblk -s: LUKS directly or under LVM), and its crypttab entry unlocks with
                            the TPM (tpm2-device=)
  ima_policy_loaded         the IMA policy has an executable-measurement rule (measure func=BPRM_CHECK,
                            or MMAP_CHECK with MAY_EXEC), AND the regalia-kms binary is in the IMA
                            measurement log: the log, not the policy text, proves it was measured
  pin_import_key_present    the persistent key at the import handle (default 0x81000101) IS the one
                            recorded at --init-import-key: the sha256 of its DER public key starts with
                            --import-key-sha256 (or the evidence's host.pin_import_key_sha256), and it
                            is RSA-3072 with fixedtpm|fixedparent|sensitivedataorigin|decrypt, no sign
  hsm_token_attached        a Nitrokey HSM 2 (USB 20a0:4230) is on the bus (sysfs; no token client
                            needed); its USB path is reported so the evidence can pin the INTERNAL port
  token_clients_root_only   replaces the guest's direct_token_clients_absent: every token client tool on
                            PATH is root:root and not executable by group or others, so the KMS user
                            cannot run them, and every process connected to pcscd runs the KMS binary

ATTESTED, NOT MEASURED (firmware settings the OS cannot read; they stay in the signed evidence):
  ilo_isolated_or_disabled, ac_power_recovery, chassis_intrusion_armed, used_hardware_intake.

Standard library only, plus the tpm2-tools and opensc binaries the host already needs.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "proxmox"))
import guest_probe  # noqa: E402  (the same Host and the five OS probes)

SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMPORT_HANDLE = os.environ.get("REGALIA_PIN_IMPORT_HANDLE", "0x81000101")
IMA_LOG = "/sys/kernel/security/ima/ascii_runtime_measurements"
KMS_BINARY = guest_probe.ALLOWED_TOKEN_CLIENT_EXES[0]
NITROKEY_HSM = ("20a0", "4230")
IMPORT_KEY_ATTRS = {"fixedtpm", "fixedparent", "sensitivedataorigin", "decrypt"}
PLATFORM = ("uefi_boot", "secure_boot_enabled", "tpm2_present", "tpm_sha256_bank",
            "root_disk_tpm_unlocked", "ima_policy_loaded", "pin_import_key_present", "hsm_token_attached",
            "token_clients_root_only")
MEASURED = PLATFORM + tuple(n for n in guest_probe.MEASURED if n != "direct_token_clients_absent")
UNMEASURED = ("ilo_isolated_or_disabled", "ac_power_recovery", "chassis_intrusion_armed",
              "used_hardware_intake") + guest_probe.UNMEASURED


class Host(guest_probe.Host):
    def read_bytes(self, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError:
            return None

    def exists(self, path):
        return os.path.exists(path)

    def stat(self, path):
        try:
            st = os.stat(path)
            return st.st_uid, st.st_gid, st.st_mode
        except OSError:
            return None


def uefi_boot(host):
    return (True, "booted through UEFI") if host.exists("/sys/firmware/efi") else \
        (False, "no /sys/firmware/efi: booted in legacy BIOS mode; TPM 2.0 measured boot needs UEFI")


def secure_boot(host):
    raw = host.read_bytes(SECURE_BOOT_VAR)
    if not raw:
        return False, "the SecureBoot EFI variable is unreadable or absent"
    # efivarfs: 4 bytes of attributes, then the value byte
    return (True, "SecureBoot = 1") if raw[-1:] == b"\x01" else (False, "SecureBoot = %d" % raw[-1])


def tpm2(host):
    major = (host.read("/sys/class/tpm/tpm0/tpm_version_major") or "").strip()
    if major != "2":
        return False, "no TPM 2.0 (tpm_version_major=%r)" % major
    if not host.exists("/dev/tpmrm0"):
        return False, "TPM 2.0 present but no /dev/tpmrm0 (kernel resource manager)"
    return True, "TPM 2.0 behind /dev/tpmrm0"


def sha256_bank(host):
    pcrs = host.listdir("/sys/class/tpm/tpm0/pcr-sha256")
    return (True, "SHA-256 PCR bank active (%d PCRs)" % len(pcrs)) if pcrs else \
        (False, "no /sys/class/tpm/tpm0/pcr-sha256: enable the SHA-256 bank in the firmware (RBSU)")


def root_unlock(host):
    rc, out = host.run(["findmnt", "-n", "-o", "SOURCE", "/"])
    src = re.sub(r"\[.*\]$", "", out.strip())          # btrfs: /dev/mapper/x[/@]
    if rc != 0 or not src:
        return False, "cannot find the root filesystem's device"
    # The device and its ancestors (inverse tree): LUKS directly, or LVM on LUKS, both resolve here.
    rc, out = host.run(["lsblk", "-s", "-n", "-r", "-o", "NAME,TYPE", src])
    crypts = [f[0] for f in (l.split() for l in out.splitlines()) if len(f) == 2 and f[1] == "crypt"]
    if rc != 0 or not crypts:
        return False, "the root filesystem (%s) is not on dm-crypt" % src
    entries = {}
    for line in (host.read("/etc/crypttab") or "").splitlines():
        f = line.split()
        if f and not f[0].startswith("#"):
            entries[f[0]] = f[3] if len(f) > 3 else ""
    for name in crypts:
        if name not in entries:
            return False, "%s (under the root filesystem) is not listed in /etc/crypttab" % name
        if "tpm2-device=" not in entries[name]:
            return False, "%s is in crypttab but not TPM-unlocked (options: %s)" % (name, entries[name] or "none")
    return True, "%s unlocks with the TPM (%s)" % (", ".join(crypts), "; ".join(entries[n] for n in crypts))


def ima(host):
    policy = host.read("/sys/kernel/security/ima/policy")
    if policy is None:
        return False, "no IMA policy readable (securityfs, or IMA disabled)"
    exec_rules = []
    for line in policy.splitlines():
        f = line.split()
        if not f or f[0] != "measure":
            continue
        opts = dict(o.split("=", 1) for o in f[1:] if "=" in o)
        if opts.get("func") == "BPRM_CHECK" or (opts.get("func") == "MMAP_CHECK" and "MAY_EXEC" in opts.get("mask", "")):
            exec_rules.append("%s, PCR %s" % (opts["func"], opts.get("pcr", "10")))
    if not exec_rules:
        return False, "the IMA policy has no executable-measurement rule (measure func=BPRM_CHECK)"
    log = host.read(IMA_LOG) or ""
    if not any(l.rstrip().endswith(" " + KMS_BINARY) for l in log.splitlines()):
        return False, "the IMA policy measures executables (%s) but %s is not in the measurement log: " \
            "start regalia-kms, then re-run" % (exec_rules[0], KMS_BINARY)
    return True, "executables measured (%s); %s is in the IMA log" % (exec_rules[0], KMS_BINARY)


def import_key(host, expected=None):
    if not host.which("tpm2_readpublic"):
        return False, "tpm2_readpublic is not installed"
    rc, yaml = host.run(["tpm2_readpublic", "-c", IMPORT_HANDLE])
    if rc != 0:
        return False, "no key at %s: run seal-hsm-pin.sh --init-import-key" % IMPORT_HANDLE
    attrs = set((re.search(r"^attributes:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, ""])[1].split("|")) - {""}
    kind = (re.search(r"^type:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, "?"])[1]
    bits = (re.search(r"^bits:\s*(\d+)", yaml, re.M) or [None, "?"])[1]
    if kind != "rsa" or bits != "3072" or not IMPORT_KEY_ATTRS <= attrs or "sign" in attrs:
        return False, "the key at %s is not the import key's template (%s-%s, %s)" % (IMPORT_HANDLE, kind, bits, "|".join(sorted(attrs)))
    rc, pem = host.run(["tpm2_readpublic", "-Q", "-c", IMPORT_HANDLE, "-f", "pem", "-o", "/dev/stdout"])
    body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    try:
        fp = hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest() if rc == 0 and body else None
    except ValueError:
        fp = None
    if not fp:
        return False, "cannot export the public key at %s" % IMPORT_HANDLE
    want = re.sub(r"[\s:]", "", (expected or "")).lower()
    if not re.fullmatch(r"[0-9a-f]{16,64}", want):
        return False, "no recorded fingerprint to compare (pass --import-key-sha256, at least 16 hex): " \
            "the key at %s has sha256 %s" % (IMPORT_HANDLE, fp)
    if not fp.startswith(want):
        return False, "the key at %s (sha256 %s) is NOT the recorded import key (%s)" % (IMPORT_HANDLE, fp, want)
    return True, "the recorded import key is at %s (sha256 %s)" % (IMPORT_HANDLE, fp)


def hsm_token(host):
    base = "/sys/bus/usb/devices"
    ports = sorted(d for d in host.listdir(base)
                   if ((host.read("%s/%s/idVendor" % (base, d)) or "").strip(),
                       (host.read("%s/%s/idProduct" % (base, d)) or "").strip()) == NITROKEY_HSM)
    if not ports:
        return False, "no Nitrokey HSM (USB %s:%s) on the bus" % NITROKEY_HSM
    return True, "Nitrokey HSM attached at USB %s" % ", ".join(ports)


def token_clients_root_only(host):
    loose = []
    for tool in guest_probe.TOKEN_CLIENTS:
        path = host.which(tool)
        if not path:
            continue
        st = host.stat(path)
        if st is None:
            loose.append("%s (cannot stat)" % path)
        elif st[0] != 0 or st[1] != 0 or st[2] & 0o011:
            loose.append("%s (uid %d, gid %d, mode %o)" % (path, st[0], st[1], st[2] & 0o7777))
    if loose:
        return False, "token client tools the KMS user can run: %s (chown root:root, chmod 0700)" % ", ".join(loose)
    ok, why = guest_probe.pcscd_clients(host)
    return ok, ("token client tools root-only; %s" % why if ok else why)


PROBES = dict(guest_probe.PROBES, uefi_boot=uefi_boot, secure_boot_enabled=secure_boot, tpm2_present=tpm2,
              tpm_sha256_bank=sha256_bank, root_disk_tpm_unlocked=root_unlock, ima_policy_loaded=ima,
              pin_import_key_present=import_key, hsm_token_attached=hsm_token,
              token_clients_root_only=token_clients_root_only)


def measure(host, import_key_sha256=None):
    def run(name):
        return import_key(host, import_key_sha256) if name == "pin_import_key_present" else PROBES[name](host)
    return {name: dict(zip(("value", "why"), run(name))) for name in MEASURED}


def compare(measured, evidence):
    claims = dict(evidence.get("host", {}), **evidence.get("guest", {}))
    return ["evidence claims %s, the host measures false: %s" % (n, measured[n]["why"])
            for n in MEASURED if claims.get(n) is True and not measured[n]["value"]]


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="signed evidence JSON whose host section must agree with the host")
    ap.add_argument("--import-key-sha256", help="the import key fingerprint written down at --init-import-key "
                    "(at least 16 hex); default: the evidence's host.pin_import_key_sha256")
    args = ap.parse_args(argv)
    host = host or Host()
    evidence = None
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as f:
            evidence = json.load(f)
    want = args.import_key_sha256 or (evidence or {}).get("host", {}).get("pin_import_key_sha256")
    measured = measure(host, want)
    report = {"measured": measured, "attested_not_measured": list(UNMEASURED)}
    if evidence is not None:
        report["disagreements"] = compare(measured, evidence)
    print(json.dumps(report, indent=2))
    # Evidence never lowers the bar: every measured control must be true, AND the evidence must agree.
    ok = all(v["value"] for v in measured.values()) and not report.get("disagreements")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
