#!/usr/bin/env python3
"""Measure a bare-metal KMS host's platform, TPM and OS controls from the host itself (ADR-0002 D21).

The KMS runs on dedicated bare metal with a discrete TPM 2.0 (regalia#46: HPE DL360 Gen9). This probe
reads the running host and reports each control with the reason for its verdict; with an evidence
file it also checks the SIGNED commissioning evidence (deploy/baremetal/evidence.py: schema,
signature, every attested firmware setting) and refuses one that disagrees with the host. The OS
probes (core dumps, hibernation, swap, an unprivileged service) are deploy/baremetal/os_probe.py's.
Token clients are checked by token_clients_root_only (below): on bare metal the host itself seals and
re-seals the PINs and so needs opensc-tool and pkcs11-tool.

    sudo python3 deploy/baremetal/host_probe.py --import-key-sha256 HEX     # exit 1 unless every control is true
    sudo python3 deploy/baremetal/host_probe.py --evidence E.json --signature E.json.sig \
        --evidence-key commissioning-p256.pem --evidence-key-sha256 HEX      # the commissioning pass criterion

PLATFORM AND TPM, measured:
  uefi_boot                 booted through UEFI (/sys/firmware/efi): TPM 2.0 measured boot needs it
  secure_boot_enabled       the SecureBoot EFI variable is 1
  tpm2_present              a TPM whose major version is 2, behind the kernel resource manager
                            (/dev/tpmrm0): seal-hsm-pin.sh refuses the raw /dev/tpm0
  tpm_sha256_bank           the TPM exposes an active SHA-256 PCR bank (/sys/class/tpm/tpm0/pcr-sha256)
  root_disk_tpm_unlocked    a dm-crypt device is among the root filesystem's block-device ancestors
                            (lsblk -s: LUKS directly or under LVM), and its crypttab entry unlocks with
                            the TPM (a tpm2-device=<value> option, parsed exactly)
  ima_policy_loaded         the IMA policy has an executable-measurement rule (measure func=BPRM_CHECK,
                            or MMAP_CHECK with MAY_EXEC), AND the newest IMA log entry for the
                            regalia-kms binary carries the digest of the bytes at that path NOW (a
                            stale entry for a since-replaced binary fails). For attestation (quotes):
                            the PIN is not sealed to the IMA PCR (README, section 3)
  pin_import_key_present    the persistent key at the import handle (default 0x81000101) IS the one
                            recorded at --init-import-key: the sha256 of its DER public key starts with
                            --import-key-sha256 (or the evidence's host.pin_import_key_sha256), and it
                            is RSA-3072 with EXACTLY the attributes --init-import-key sets:
                            fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
  hsm_token_attached        a Nitrokey HSM 2 (USB 20a0:4230) is on the bus (sysfs; no token client
                            needed); its USB path is reported so the evidence can pin the INTERNAL port
  token_clients_root_only   replaces the guest's direct_token_clients_absent: every token client tool on
                            PATH is root:root and not executable by group or others, so the KMS user
                            cannot run them, and every process connected to pcscd runs the KMS binary

ATTESTED, NOT MEASURED (what the OS cannot read; in the signed evidence, deploy/baremetal/evidence.py):
  ilo_isolated_or_disabled, ac_power_recovery, chassis_intrusion_armed, used_hardware_intake,
  runtime_credentials_excluded_from_backup; and the records the measurements are checked against:
  pin_import_key_sha256, hsm_usb_path, credential_tpm2_pcrs (never PCR 10).

Standard library only, plus the tpm2-tools and openssl binaries the host already needs.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import os_probe  # noqa: E402  (the Host and the OS-hardening probes)
import evidence as evidence_mod  # noqa: E402

SECURE_BOOT_VAR = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMPORT_HANDLE = os.environ.get("REGALIA_PIN_IMPORT_HANDLE", "0x81000101")
IMA_LOG = "/sys/kernel/security/ima/ascii_runtime_measurements"
KMS_BINARY = os_probe.ALLOWED_TOKEN_CLIENT_EXES[0]
NITROKEY_HSM = ("20a0", "4230")
SYSTEM_BIN_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/bin")
IMPORT_KEY_ATTRS = {"fixedtpm", "fixedparent", "sensitivedataorigin", "userwithauth", "decrypt"}
PLATFORM = ("uefi_boot", "secure_boot_enabled", "tpm2_present", "tpm_sha256_bank",
            "root_disk_tpm_unlocked", "ima_policy_loaded", "pin_import_key_present", "hsm_token_attached",
            "token_clients_root_only")
MEASURED = PLATFORM + os_probe.MEASURED
UNMEASURED = evidence_mod.ATTESTED + evidence_mod.RECORDS


class Host(os_probe.Host):
    def read_bytes(self, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError:
            return None

    def exists(self, path):
        return os.path.exists(path)

    def which_all(self, tool):
        """Every executable named tool on PATH or in the standard system directories, by real path."""
        dirs = os.environ.get("PATH", "").split(os.pathsep) + list(SYSTEM_BIN_DIRS)
        found = []
        for d in dirs:
            p = os.path.join(d, tool)
            if d and os.path.isfile(p) and os.access(p, os.X_OK):
                real = os.path.realpath(p)
                if real not in found:
                    found.append(real)
        return found

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
        opts = dict((o.split("=", 1) + [""])[:2] for o in entries[name].split(",") if o)
        if not opts.get("tpm2-device"):
            return False, "%s is in crypttab but not TPM-unlocked (options: %s)" % (name, entries[name] or "none")
        # crypttab only ASKS for the TPM; the LUKS2 header must actually carry a TPM2 token (what
        # systemd-cryptenroll --tpm2-device writes), or a passphrase-only volume would pass here.
        rc, status = host.run(["cryptsetup", "status", name])
        dev = next((l.split(":", 1)[1].strip() for l in status.splitlines() if l.strip().startswith("device:")), "")
        if rc != 0 or not dev:
            return False, "cannot find the LUKS device under %s (cryptsetup status)" % name
        rc, meta = host.run(["cryptsetup", "luksDump", "--dump-json-metadata", dev])
        try:
            tokens = json.loads(meta).get("tokens", {}) if rc == 0 else None
        except ValueError:
            tokens = None
        if tokens is None:
            return False, "cannot read the LUKS2 header of %s (cryptsetup luksDump --dump-json-metadata)" % dev
        tpm = [t for t in tokens.values() if t.get("type") == "systemd-tpm2" and t.get("keyslots")]
        if not tpm:
            return False, "%s (%s) has no systemd-tpm2 token in its LUKS2 header: enrol it with " \
                "systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7" % (name, dev)
        # The commissioning policy binds the disk to PCR 7 exactly (README, section 3): a token with no
        # PCRs, or other ones, would release the disk key whatever the Secure Boot state.
        wrong = [t.get("tpm2-pcrs") for t in tpm if sorted(t.get("tpm2-pcrs") or []) != [7]]
        if wrong:
            return False, "%s (%s) has a TPM2 token bound to PCRs %s, not exactly [7]: re-enrol with " \
                "systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7" % (name, dev, wrong)
    return True, "%s unlocks with the TPM (%s; systemd-tpm2 token in the LUKS2 header)" % (
        ", ".join(crypts), "; ".join(entries[n] for n in crypts))


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
        # BPRM_CHECK measures executables only with no mask or MAY_EXEC; MMAP_CHECK only with MAY_EXEC.
        executable = (opts.get("func") == "BPRM_CHECK" and opts.get("mask", "MAY_EXEC").lstrip("^") == "MAY_EXEC") \
            or (opts.get("func") == "MMAP_CHECK" and opts.get("mask", "").lstrip("^") == "MAY_EXEC")
        if executable and opts.get("pcr", "10") == "10":
            # PCR 10: the PCR that attestation quotes (README, section 3); a rule extending another PCR
            # would leave the quoted one silent about the binary.
            exec_rules.append("%s, PCR 10" % opts["func"])
    if not exec_rules:
        return False, "the IMA policy has no executable-measurement rule into PCR 10 (measure func=BPRM_CHECK)"
    # ascii_runtime_measurements: PCR, template hash, template (ima-ng / ima-sig / ima-ngv2), file
    # digest "[ima:]alg:hex", path. IMA appends a new entry when changed bytes are executed, so the
    # NEWEST entry for the path is the one that must match the file as it is now.
    newest = None
    for line in (host.read(IMA_LOG) or "").splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == "10" and f[2] in ("ima-ng", "ima-sig", "ima-ngv2", "ima-sigv2") and f[4] == KMS_BINARY:
            newest = f[3].split(":")
    if not newest:
        return False, "the IMA policy measures executables (%s) but %s is not in the measurement log: " \
            "start regalia-kms, then re-run" % (exec_rules[0], KMS_BINARY)
    alg, logged = newest[-2], newest[-1]
    current = host.read_bytes(KMS_BINARY)
    if current is None or alg not in hashlib.algorithms_available:
        return False, "cannot hash %s (%s) to compare with its IMA entry" % (KMS_BINARY, alg)
    now = hashlib.new(alg, current).hexdigest()
    if now != logged:
        return False, "the newest IMA entry for %s (%s:%s…) is not the binary there now (%s…): it was " \
            "replaced after it last ran; restart regalia-kms, then re-run" % (KMS_BINARY, alg, logged[:12], now[:12])
    return True, "executables measured (%s); the running %s is in the IMA log (%s:%s…)" % (
        exec_rules[0], KMS_BINARY, alg, now[:12])


def import_key(host, expected=None):
    if not host.which("tpm2_readpublic"):
        return False, "tpm2_readpublic is not installed"
    rc, yaml = host.run(["tpm2_readpublic", "-c", IMPORT_HANDLE])
    if rc != 0:
        return False, "no key at %s: run seal-hsm-pin.sh --init-import-key" % IMPORT_HANDLE
    attrs = set((re.search(r"^attributes:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, ""])[1].split("|")) - {""}
    kind = (re.search(r"^type:\s*\n\s+value:\s*(\S+)", yaml, re.M) or [None, "?"])[1]
    bits = (re.search(r"^bits:\s*(\d+)", yaml, re.M) or [None, "?"])[1]
    if kind != "rsa" or bits != "3072" or attrs != IMPORT_KEY_ATTRS:
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


def hsm_ports(host):
    """The sysfs USB paths of every Nitrokey HSM 2 on the bus."""
    base = "/sys/bus/usb/devices"
    return sorted(d for d in host.listdir(base)
                  if ((host.read("%s/%s/idVendor" % (base, d)) or "").strip(),
                      (host.read("%s/%s/idProduct" % (base, d)) or "").strip()) == NITROKEY_HSM)


def hsm_token(host):
    ports = hsm_ports(host)
    if not ports:
        return False, "no Nitrokey HSM (USB %s:%s) on the bus" % NITROKEY_HSM
    return True, "Nitrokey HSM attached at USB %s" % ", ".join(ports)


def token_clients_root_only(host):
    loose = []
    # Every copy, not only the first on PATH: a root-only wrapper must not hide a runnable one.
    for path in (p for tool in os_probe.TOKEN_CLIENTS for p in host.which_all(tool)):
        st = host.stat(path)
        if st is None:
            loose.append("%s (cannot stat)" % path)
        elif st[0] != 0 or st[1] != 0 or st[2] & 0o077:
            # no group or other bit at all: a writable root-owned client is code root runs later
            loose.append("%s (uid %d, gid %d, mode %o)" % (path, st[0], st[1], st[2] & 0o7777))
    if loose:
        return False, "token client tools others can run or change: %s (chown root:root, chmod 0700)" % ", ".join(loose)
    ok, why = os_probe.pcscd_clients(host)
    return ok, ("token client tools root-only; %s" % why if ok else why)


PROBES = dict(os_probe.PROBES, uefi_boot=uefi_boot, secure_boot_enabled=secure_boot, tpm2_present=tpm2,
              tpm_sha256_bank=sha256_bank, root_disk_tpm_unlocked=root_unlock, ima_policy_loaded=ima,
              pin_import_key_present=import_key, hsm_token_attached=hsm_token,
              token_clients_root_only=token_clients_root_only)


def measure(host, import_key_sha256=None):
    def run(name):
        return import_key(host, import_key_sha256) if name == "pin_import_key_present" else PROBES[name](host)
    return {name: dict(zip(("value", "why"), run(name))) for name in MEASURED}


def compare(measured, host, ports=()):
    """Every measured control the evidence records must agree with the host, both ways; and the token
    must be on the USB port the evidence pins (the INTERNAL one)."""
    out = ["evidence records %s=%s, the host measures %s: %s" % (n, host.get(n), measured[n]["value"], measured[n]["why"])
           for n in MEASURED if host.get(n) is not measured[n]["value"]]
    if host.get("hsm_usb_path") not in ports:
        out.append("evidence pins the Nitrokey HSM to USB %s, the host has it at %s" % (
            host.get("hsm_usb_path"), ", ".join(ports) or "no port"))
    return out


def main(argv=None, host=None, run=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="the signed commissioning evidence (deploy/baremetal/evidence.py)")
    ap.add_argument("--signature", help="its detached signature (openssl dgst -sha256 -sign)")
    ap.add_argument("--evidence-key", help="the commissioning evidence public key (P-256 PEM)")
    ap.add_argument("--evidence-key-sha256", help="that key's recorded SHA-256 (DER), from the commissioning record")
    ap.add_argument("--import-key-sha256", help="without evidence: the import key fingerprint written down at "
                    "--init-import-key (at least 16 hex)")
    args = ap.parse_args(argv)
    host = host or Host()
    report = {"attested_not_measured": list(UNMEASURED)}
    problems, want = [], args.import_key_sha256
    if args.evidence:
        if not (args.signature and args.evidence_key and args.evidence_key_sha256):
            ap.error("--evidence needs --signature, --evidence-key and --evidence-key-sha256")
        try:
            # One snapshot of all three inputs: the bytes validated are the bytes verified.
            with evidence_mod.Snapshot(evidence=args.evidence, signature=args.signature, key=args.evidence_key) as snap:
                ev_host = evidence_mod.validate(evidence_mod.load(snap.data["evidence"]), MEASURED)
                evidence_mod.verify_signature(snap.paths["evidence"], snap.paths["signature"], snap.paths["key"],
                                              args.evidence_key_sha256, **({"run": run} if run else {}))
            want = ev_host["pin_import_key_sha256"]
        except (OSError, evidence_mod.InvalidEvidence) as error:
            problems.append("evidence REFUSED: %s" % error)
            ev_host = None
    measured = measure(host, want)
    report["measured"] = measured
    if args.evidence:
        if ev_host is not None:
            problems += compare(measured, ev_host, hsm_ports(host))
        report["evidence_problems"] = problems
    print(json.dumps(report, indent=2))
    # Evidence never lowers the bar: every measured control must be true, AND, when given, the evidence
    # must be well-formed, signed by the recorded key, attest every firmware setting, and agree.
    ok = all(v["value"] for v in measured.values()) and not problems
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
