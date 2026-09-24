#!/usr/bin/env python3
"""Measure the KMS guest's memory and credential controls from INSIDE the guest (regalia#49).

WHY THIS EXISTS. verify.py checks a signed description of the guest, and its `guest` section is a
set of booleans somebody typed: `core_dumps_disabled: true`, `swap_disabled_or_encrypted: true`.
Signing a claim does not make it true. A guest with an unencrypted swap partition passes the
verifier as long as the evidence says otherwise. This probe reads the guest itself, reports each
control it can measure with the reason for its verdict, and, given an evidence file, refuses one
that claims a control the guest does not have.

    sudo python3 deploy/proxmox/guest_probe.py                     # the measured guest section, as JSON
    sudo python3 deploy/proxmox/guest_probe.py --evidence E.json   # exit 1 if E claims what the guest lacks

WHAT IT MEASURES, AND HOW:
  core_dumps_disabled         the KMS unit's effective LimitCORE is 0, fs.suid_dumpable is 0, and a
                              core_pattern piped to systemd-coredump has Storage=none
  hibernation_disabled        no resume= on the kernel command line, and every hibernating sleep
                              target is masked, or sleep.conf forbids hibernation, hybrid sleep and
                              suspend-then-hibernate
  swap_disabled_or_encrypted  every active swap is zram (RAM) or a dm-crypt device
  kms_service_unprivileged    the unit runs as a non-root User= with NoNewPrivileges=yes
  direct_token_clients_absent no token client tool is installed on PATH, and nothing but pcscd and
                              the KMS holds the pcscd socket

WHAT IT CANNOT MEASURE, and says so rather than guessing: runtime_credentials_excluded_from_backup
(a property of the HOST's backup jobs) and credential_tpm2_pcrs (the PCR set inside a sealed blob).
Those stay attested in the evidence and are reported as "attested, not measured".

Standard library only. It must run on a hardened guest where nothing else is installed.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

SERVICE = "regalia-kms.service"
MEASURED = ("core_dumps_disabled", "hibernation_disabled", "swap_disabled_or_encrypted",
            "kms_service_unprivileged", "direct_token_clients_absent")
UNMEASURED = ("runtime_credentials_excluded_from_backup", "credential_tpm2_pcrs")
HIBERNATING_TARGETS = ("hibernate.target", "hybrid-sleep.target", "suspend-then-hibernate.target")
TOKEN_CLIENTS = ("ykman", "yubico-piv-tool", "pkcs11-tool", "pkcs15-tool", "opensc-tool", "sc-hsm-tool",
                 "pcsc_scan", "scdaemon", "gpg-card", "yubikey-agent", "age-plugin-yubikey")
PCSCD_SOCKET = "/run/pcscd/pcscd.comm"


class Host:
    """Every read of the guest goes through here, so a test can stand in a fake guest."""

    def read(self, path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None

    def listdir(self, path):
        try:
            return os.listdir(path)
        except OSError:
            return []

    def run(self, argv):
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=20)
            return out.returncode, out.stdout
        except (OSError, subprocess.TimeoutExpired):
            return 127, ""

    def which(self, tool):
        return shutil.which(tool)


def unit_properties(host, *names):
    rc, out = host.run(["systemctl", "show", SERVICE, "-p", ",".join(names)])
    props = {}
    for line in out.splitlines():
        key, _, value = line.partition("=")
        props[key] = value
    return rc, props


def config_value(text, key):
    """The last effective `key=` in systemd-analyze cat-config output ('' if never set)."""
    value = ""
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith(("#", ";")):
            continue
        k, sep, v = line.partition("=")
        if sep and k.strip() == key:
            value = v.strip()
    return value


def core_dumps(host):
    rc, props = unit_properties(host, "LimitCORE", "LoadState")
    if props.get("LoadState") != "loaded":
        return False, f"{SERVICE} is not loaded, so its core limit cannot be read"
    if props.get("LimitCORE") != "0":
        return False, f"{SERVICE} LimitCORE={props.get('LimitCORE')!r}, not 0"
    suid = (host.read("/proc/sys/fs/suid_dumpable") or "").strip()
    if suid != "0":
        return False, f"fs.suid_dumpable={suid or 'unreadable'}, not 0"
    pattern = (host.read("/proc/sys/kernel/core_pattern") or "").strip()
    if pattern.startswith("|") and "systemd-coredump" in pattern:
        _, conf = host.run(["systemd-analyze", "cat-config", "systemd/coredump.conf"])
        storage = config_value(conf, "Storage")
        if storage.lower() != "none":
            return False, f"core_pattern pipes to systemd-coredump with Storage={storage or 'external (default)'}"
    return True, f"LimitCORE=0, suid_dumpable=0, core_pattern {pattern!r}"


def hibernation(host):
    cmdline = host.read("/proc/cmdline") or ""
    if re.search(r"(^|\s)resume=", cmdline):
        return False, "the kernel command line names a resume= device"
    masked = []
    for target in HIBERNATING_TARGETS:
        _, out = host.run(["systemctl", "is-enabled", target])
        if out.strip() == "masked":
            masked.append(target)
    if len(masked) == len(HIBERNATING_TARGETS):
        return True, "hibernate, hybrid-sleep and suspend-then-hibernate targets are masked"
    _, conf = host.run(["systemd-analyze", "cat-config", "systemd/sleep.conf"])
    allow = {k: config_value(conf, k).lower() for k in ("AllowHibernation", "AllowHybridSleep", "AllowSuspendThenHibernate")}
    if all(v == "no" for v in allow.values()):
        return True, "sleep.conf forbids hibernation, hybrid sleep and suspend-then-hibernate"
    unmasked = [t for t in HIBERNATING_TARGETS if t not in masked]
    return False, f"not masked: {', '.join(unmasked)}; sleep.conf allows: " + \
        ", ".join(k for k, v in allow.items() if v != "no")


def swap(host):
    text = host.read("/proc/swaps")
    if text is None:
        return False, "/proc/swaps is unreadable"
    devices = [line.split()[0] for line in text.splitlines()[1:] if line.strip()]
    if not devices:
        return True, "no swap is active"
    for device in devices:
        name = os.path.basename(os.path.realpath(device)) if device.startswith("/dev/") else ""
        if name.startswith("zram"):
            continue
        uuid = (host.read(f"/sys/class/block/{name}/dm/uuid") or "").strip() if name.startswith("dm-") else ""
        if not uuid.startswith("CRYPT-"):
            return False, f"swap on {device} is neither zram nor dm-crypt"
    return True, f"every active swap is zram or dm-crypt ({', '.join(devices)})"


def unprivileged(host):
    rc, props = unit_properties(host, "User", "NoNewPrivileges", "LoadState")
    if props.get("LoadState") != "loaded":
        return False, f"{SERVICE} is not loaded"
    user = props.get("User", "")
    if user in ("", "root", "0"):
        return False, f"{SERVICE} runs as {user or 'root (no User=)'}"
    if props.get("NoNewPrivileges") != "yes":
        return False, f"{SERVICE} has NoNewPrivileges={props.get('NoNewPrivileges')!r}"
    return True, f"User={user}, NoNewPrivileges=yes"


def token_clients(host):
    installed = [t for t in TOKEN_CLIENTS if host.which(t)]
    if installed:
        return False, f"token client tools installed: {', '.join(installed)}"
    # Who holds the pcscd socket right now. `ss -xp` names each unix-socket peer's process.
    rc, out = host.run(["ss", "-xpn"])
    if rc != 0:
        return False, "cannot list unix-socket peers (ss failed), so other token clients cannot be ruled out"
    holders = set()
    for line in out.splitlines():
        if PCSCD_SOCKET in line:
            holders.update(re.findall(r'\("([^"]+)",pid=', line))
    others = sorted(holders - {"pcscd", "regalia-kms"})
    if others:
        return False, f"processes other than the KMS hold the pcscd socket: {', '.join(others)}"
    return True, "no token client tools installed; only pcscd and the KMS hold the pcscd socket"


PROBES = {"core_dumps_disabled": core_dumps, "hibernation_disabled": hibernation,
          "swap_disabled_or_encrypted": swap, "kms_service_unprivileged": unprivileged,
          "direct_token_clients_absent": token_clients}


def measure(host):
    return {name: dict(zip(("value", "why"), PROBES[name](host))) for name in MEASURED}


def compare(measured, evidence):
    """Refusals for every control the evidence claims and the guest does not have."""
    claims = evidence.get("guest", {})
    problems = []
    for name in MEASURED:
        if claims.get(name) is True and not measured[name]["value"]:
            problems.append(f"evidence claims {name}, the guest measures false: {measured[name]['why']}")
    return problems


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="signed evidence JSON whose guest section must agree with the guest")
    args = ap.parse_args(argv)
    host = host or Host()
    measured = measure(host)
    report = {"measured": measured, "attested_not_measured": list(UNMEASURED)}
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as f:
            problems = compare(measured, json.load(f))
        report["disagreements"] = problems
    print(json.dumps(report, indent=2))
    if args.evidence:
        return 1 if report["disagreements"] else 0
    return 0 if all(v["value"] for v in measured.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
