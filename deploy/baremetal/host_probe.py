#!/usr/bin/env python3
"""Measure a bare-metal KMS host's platform, TPM and OS controls from the host itself (ADR-0002 D21).

The KMS runs on dedicated bare metal with a discrete TPM 2.0 (regalia#46: HPE DL360 Gen9). This probe
reads the running host and reports each control with the reason for its verdict; with an evidence
file it refuses one that claims a control the host does not have. Same contract as
deploy/proxmox/guest_probe.py, whose five OS probes (core dumps, hibernation, swap, an unprivileged
service, no direct token clients) it reuses unchanged.

    sudo python3 deploy/baremetal/host_probe.py                     # the measured host, as JSON
    sudo python3 deploy/baremetal/host_probe.py --evidence E.json   # exit 1 if E claims what the host lacks

PLATFORM AND TPM, measured:
  uefi_boot                 booted through UEFI (/sys/firmware/efi): TPM 2.0 measured boot needs it
  secure_boot_enabled       the SecureBoot EFI variable is 1
  tpm2_present              a TPM whose major version is 2, behind the kernel resource manager
                            (/dev/tpmrm0): seal-hsm-pin.sh refuses the raw /dev/tpm0
  tpm_sha256_bank           the TPM exposes an active SHA-256 PCR bank (/sys/class/tpm/tpm0/pcr-sha256)
  root_disk_tpm_unlocked    the root filesystem sits on dm-crypt, and its crypttab entry unlocks with
                            the TPM (tpm2-device=)
  ima_policy_loaded         an IMA policy is loaded (it measures the regalia-kms binary into the PCRs)
  pin_import_key_present    the TPM holds the persistent PIN import key (seal-hsm-pin.sh
                            --init-import-key; default handle 0x81000101), checked with tpm2_readpublic
  hsm_token_attached        a Nitrokey HSM 2 answers (opensc-tool -l); its USB path is reported so the
                            evidence can pin it to the INTERNAL port

ATTESTED, NOT MEASURED (firmware settings the OS cannot read; they stay in the signed evidence):
  ilo_isolated_or_disabled, ac_power_recovery, chassis_intrusion_armed, used_hardware_intake.

Standard library only, plus the tpm2-tools and opensc binaries the host already needs.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "proxmox"))
import guest_probe  # noqa: E402  (the same Host and the five OS probes)

SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMPORT_HANDLE = os.environ.get("REGALIA_PIN_IMPORT_HANDLE", "0x81000101")
PLATFORM = ("uefi_boot", "secure_boot_enabled", "tpm2_present", "tpm_sha256_bank",
            "root_disk_tpm_unlocked", "ima_policy_loaded", "pin_import_key_present", "hsm_token_attached")
MEASURED = PLATFORM + guest_probe.MEASURED
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
    src = out.strip()
    if rc != 0 or not src.startswith("/dev/mapper/"):
        return False, "the root filesystem (%s) is not on dm-crypt" % (src or "unknown")
    name = src.rsplit("/", 1)[1]
    for line in (host.read("/etc/crypttab") or "").splitlines():
        f = line.split()
        if f and not f[0].startswith("#") and f[0] == name:
            opts = f[3] if len(f) > 3 else ""
            if "tpm2-device=" in opts:
                return True, "%s unlocks with the TPM (%s)" % (name, opts)
            return False, "%s is in crypttab but not TPM-unlocked (options: %s)" % (name, opts or "none")
    return False, "%s is not listed in /etc/crypttab" % name


def ima(host):
    policy = host.read("/sys/kernel/security/ima/policy")
    if policy is None:
        return False, "no IMA policy readable (securityfs, or IMA disabled)"
    rules = [l for l in policy.splitlines() if l.strip() and not l.startswith("#")]
    return (True, "%d IMA rule(s) loaded" % len(rules)) if rules else (False, "the IMA policy is empty")


def import_key(host):
    if not host.which("tpm2_readpublic"):
        return False, "tpm2_readpublic is not installed"
    rc, _ = host.run(["tpm2_readpublic", "-Q", "-c", IMPORT_HANDLE])
    return (True, "persistent key at %s" % IMPORT_HANDLE) if rc == 0 else \
        (False, "no key at %s: run seal-hsm-pin.sh --init-import-key" % IMPORT_HANDLE)


def hsm_token(host):
    rc, out = host.run(["opensc-tool", "-l"])
    rows = [l for l in out.splitlines() if "Nitrokey HSM" in l and " Yes " in " %s " % l]
    if not rows:
        return False, "no Nitrokey HSM answers (opensc-tool -l)"
    rc2, usb = host.run(["sh", "-c", "for d in /sys/bus/usb/devices/*; do [ \"$(cat $d/idVendor 2>/dev/null)\" = 20a0 ] && [ \"$(cat $d/idProduct 2>/dev/null)\" = 4230 ] && echo ${d##*/}; done"])
    return True, "Nitrokey HSM attached at USB %s" % (usb.strip() or "unknown")


PROBES = dict(guest_probe.PROBES, uefi_boot=uefi_boot, secure_boot_enabled=secure_boot, tpm2_present=tpm2,
              tpm_sha256_bank=sha256_bank, root_disk_tpm_unlocked=root_unlock, ima_policy_loaded=ima,
              pin_import_key_present=import_key, hsm_token_attached=hsm_token)


def measure(host):
    return {name: dict(zip(("value", "why"), PROBES[name](host))) for name in MEASURED}


def compare(measured, evidence):
    claims = dict(evidence.get("host", {}), **evidence.get("guest", {}))
    return ["evidence claims %s, the host measures false: %s" % (n, measured[n]["why"])
            for n in MEASURED if claims.get(n) is True and not measured[n]["value"]]


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="signed evidence JSON whose host section must agree with the host")
    args = ap.parse_args(argv)
    host = host or Host()
    measured = measure(host)
    report = {"measured": measured, "attested_not_measured": list(UNMEASURED)}
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as f:
            report["disagreements"] = compare(measured, json.load(f))
    print(json.dumps(report, indent=2))
    if args.evidence:
        return 1 if report["disagreements"] else 0
    return 0 if all(v["value"] for v in measured.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
