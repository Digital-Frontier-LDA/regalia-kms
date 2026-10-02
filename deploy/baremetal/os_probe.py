#!/usr/bin/env python3
"""The KMS host's OS-hardening probes, measured on the running system (ADR-0002 D21/D22).

Shared by deploy/baremetal/host_probe.py (the supported deployment) and, until its removal (#55),
the deprecated deploy/proxmox/guest_probe.py. Each probe reads the host and returns (verdict, reason):

  core_dumps_disabled         the KMS unit's effective LimitCORE is 0, fs.suid_dumpable is 0, and a
                              core_pattern piped to systemd-coredump has Storage=none
  hibernation_disabled        no resume= on the kernel command line, and every hibernating sleep
                              target is masked, or sleep.conf forbids hibernation, hybrid sleep and
                              suspend-then-hibernate
  swap_disabled_or_encrypted  every active swap is zram (RAM) or a dm-crypt device
  kms_service_unprivileged    the unit runs as a non-root User= with NoNewPrivileges=yes

and pcscd_clients(): every process connected to pcscd runs the KMS binary (matched by socket inode,
identified by /proc/<pid>/exe, never by the name a process gives itself).

The KMS unit's sandbox (#61), SANDBOX_MEASURED. Kept apart from MEASURED because the deprecated Proxmox
guest probe reads MEASURED and is frozen; host_probe.py measures both and the signed evidence requires both.

  kms_service_sandboxed       the unit's effective ProtectSystem=strict, ProtectHome, PrivateTmp,
                              ProtectKernelTunables/Modules/Logs, ProtectControlGroups,
                              RestrictSUIDSGID and LockPersonality, as `systemctl show` reports them
  kms_capabilities_minimal    the unit's CapabilityBoundingSet and AmbientCapabilities hold nothing
                              beyond ALLOWED_CAPABILITIES (nothing: an unprivileged KMS on a high
                              port needs none), and so do the bounding, permitted, effective and
                              ambient sets the kernel reports for the running process
  kms_apparmor_enforced       AppArmor is enabled and the running KMS process is confined by a
                              profile in enforce mode (read from /proc/<MainPID>/attr, not from the
                              unit: AppArmorProfile=-name starts unconfined when the profile is missing)

Standard library only.
"""
import os
import re
import shutil
import subprocess
import sys

SERVICE = "regalia-kms.service"
MEASURED = ("core_dumps_disabled", "hibernation_disabled", "swap_disabled_or_encrypted", "kms_service_unprivileged")
SANDBOX_MEASURED = ("kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced")
# property -> the values that count as hardened (systemd 257: ProtectHome=tmpfs also hides the home
# directories, PrivateTmp=disconnected and ProtectControlGroups=strict are stricter than yes).
SANDBOX_PROPERTIES = {
    "ProtectSystem": ("strict",), "ProtectHome": ("yes", "tmpfs"), "PrivateTmp": ("yes", "disconnected"),
    "ProtectKernelTunables": ("yes",), "ProtectKernelModules": ("yes",), "ProtectKernelLogs": ("yes",),
    "ProtectControlGroups": ("yes", "strict"), "RestrictSUIDSGID": ("yes",), "LockPersonality": ("yes",),
}
# What the KMS may hold, as `systemctl show` spells it (cap_net_bind_service), with the kernel's bit
# number for each. Empty: it runs unprivileged, listens on a high port, and locks its PIN pages within
# LimitMEMLOCK. A capability added here is a recorded decision, not a default.
ALLOWED_CAPABILITIES = {}
HIBERNATING_TARGETS = ("hibernate.target", "hybrid-sleep.target", "suspend-then-hibernate.target")
TOKEN_CLIENTS = ("ykman", "yubico-piv-tool", "pkcs11-tool", "pkcs15-tool", "opensc-tool", "sc-hsm-tool",
                 "pcsc_scan", "scdaemon", "gpg-card", "yubikey-agent", "age-plugin-yubikey")
PCSCD_SOCKET = "/run/pcscd/pcscd.comm"
# A pcscd client is identified by the binary its pid runs, not by the name ss prints: a process
# name is whatever the process set it to.
ALLOWED_TOKEN_CLIENT_EXES = ("/usr/local/sbin/regalia-kms",)


class Host:
    """Every read of the KMS host goes through here, so a test can stand in a fake host."""

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

    def readlink(self, path):
        try:
            return os.readlink(path)
        except OSError:
            return None


def unit_properties(host, *names):
    rc, out = host.run(["systemctl", "show", SERVICE, "-p", ",".join(names)])
    props = {}
    for line in out.splitlines():
        key, _, value = line.partition("=")
        props[key] = value
    return rc, props


def config_value(text, section, key):
    """The last effective `key=` inside `[section]` in systemd-analyze cat-config output ('' if never
    set). A key outside its section is ignored by systemd, so it is ignored here: a misplaced
    `Storage=none` must not make the probe report a control systemd does not apply."""
    value, current = "", None
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        k, sep, v = line.partition("=")
        if sep and current == section and k.strip() == key:
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
    if pattern.startswith("|"):
        # The kernel IGNORES RLIMIT_CORE for a piped core_pattern: the handler receives the memory
        # whatever LimitCORE says. Only a handler whose storage is verifiably off is acceptable.
        handler = pattern[1:].split()[0] if pattern[1:].split() else ""
        if os.path.basename(handler) != "systemd-coredump":
            return False, f"core_pattern pipes to an unrecognised handler {handler!r}; LimitCORE does not stop a pipe"
        _, conf = host.run(["systemd-analyze", "cat-config", "systemd/coredump.conf"])
        storage = config_value(conf, "Coredump", "Storage")
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
    allow = {k: config_value(conf, "Sleep", k).lower() for k in ("AllowHibernation", "AllowHybridSleep", "AllowSuspendThenHibernate")}
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


def sandboxed(host):
    rc, props = unit_properties(host, *SANDBOX_PROPERTIES, "LoadState")
    if props.get("LoadState") != "loaded":
        return False, f"{SERVICE} is not loaded"
    weak = [f"{name}={props.get(name, '')!r} (want {' or '.join(want)})"
            for name, want in SANDBOX_PROPERTIES.items() if props.get(name) not in want]
    if weak:
        return False, f"{SERVICE}: " + ", ".join(weak)
    return True, ", ".join(f"{name}={props[name]}" for name in SANDBOX_PROPERTIES)


def main_pid(host):
    """The pid systemd tracks as the unit's main process, or None when it is not running."""
    _, props = unit_properties(host, "MainPID")
    pid = props.get("MainPID", "")
    return pid if pid.isdigit() and pid != "0" else None


def capabilities(host):
    rc, props = unit_properties(host, "CapabilityBoundingSet", "AmbientCapabilities", "LoadState")
    if props.get("LoadState") != "loaded":
        return False, f"{SERVICE} is not loaded"
    for name in ("CapabilityBoundingSet", "AmbientCapabilities"):
        if name not in props:
            return False, f"{SERVICE}: {name} cannot be read"
        extra = sorted(set(props[name].split()) - set(ALLOWED_CAPABILITIES))
        if extra:
            # An unset bounding set is every capability the kernel knows: the list is long by design.
            return False, f"{SERVICE} {name} holds {len(extra)} capabilit{'y' if len(extra) == 1 else 'ies'} " \
                          f"beyond the allowed set: {' '.join(extra)}"
    # What the unit asks for is not what the process holds if the unit changed since it started.
    pid = main_pid(host)
    if pid is None:
        return False, f"{SERVICE} is not running, so the capabilities the kernel gave it cannot be read (start it first)"
    status = host.read(f"/proc/{pid}/status") or ""
    allowed_mask = sum(1 << bit for bit in ALLOWED_CAPABILITIES.values())
    for field in ("CapBnd", "CapPrm", "CapEff", "CapAmb"):
        found = re.search(rf"^{field}:\s*([0-9a-fA-F]+)\s*$", status, re.M)
        if not found:
            return False, f"/proc/{pid}/status has no {field}"
        if int(found.group(1), 16) & ~allowed_mask:
            return False, f"the running KMS (pid {pid}) has {field}={found.group(1)}, beyond the allowed set"
    allowed = " ".join(sorted(ALLOWED_CAPABILITIES)) or "none"
    return True, f"bounding set: {props['CapabilityBoundingSet'] or 'empty'}; ambient: " \
                 f"{props['AmbientCapabilities'] or 'empty'}; allowed: {allowed}; pid {pid} holds nothing beyond it"


def apparmor(host):
    if (host.read("/sys/module/apparmor/parameters/enabled") or "").strip() != "Y":
        return False, "AppArmor is not enabled in this kernel (/sys/module/apparmor/parameters/enabled)"
    pid = main_pid(host)
    if pid is None:
        return False, f"{SERVICE} is not running, so its confinement cannot be read (start it first)"
    # The process's own label: attr/apparmor/current where the kernel has it (5.8+), attr/current otherwise.
    label = host.read(f"/proc/{pid}/attr/apparmor/current")
    if label is None:
        label = host.read(f"/proc/{pid}/attr/current")
    label = (label or "").strip().rstrip("\x00")
    found = re.fullmatch(r"(\S.*) \((enforce|complain|kill|unconfined|mixed)\)", label)
    if not found:
        return False, f"the running KMS (pid {pid}) is {label or 'not labelled'}: no AppArmor profile confines it"
    profile, mode = found.groups()
    if mode != "enforce" or profile == "unconfined":
        return False, f"the running KMS (pid {pid}) is under {profile!r} in {mode} mode, not enforce"
    return True, f"pid {pid} is confined by {profile!r} in enforce mode"


def pcscd_clients(host):
    """(True, "<n> pcscd client(s), all the KMS binary") when every process connected to pcscd runs the
    KMS binary; (False, why) otherwise. Shared with deploy/baremetal/host_probe.py."""
    # Who is connected to pcscd right now. `ss -xpn` prints each unix-socket endpoint on its own line:
    # the server side carries the socket path, the CLIENT side usually shows `*`. So match
    # endpoints by inode (the server line's peer inode is the client line's local inode), then
    # identify each client by the binary its pid runs.
    rc, out = host.run(["ss", "-xpn"])
    if rc != 0:
        return False, "cannot list unix-socket peers (ss failed), so other token clients cannot be ruled out"
    endpoints, client_inodes = {}, set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[5].isdigit() or not fields[7].isdigit():
            continue
        endpoints[fields[5]] = re.findall(r'\("([^"]*)",pid=(\d+),', line)
        if fields[4] == PCSCD_SOCKET and fields[7] != "0":   # peer 0: a listener, not a connection
            client_inodes.add(fields[7])
    others = []
    for inode in sorted(client_inodes):
        holders = endpoints.get(inode)
        if not holders:
            others.append(f"an unidentified client (inode {inode})")
            continue
        for name, pid in holders:
            exe = host.readlink(f"/proc/{pid}/exe")
            if exe not in ALLOWED_TOKEN_CLIENT_EXES:
                others.append(f"{name} (pid {pid}, {exe or 'exe unreadable'})")
    if others:
        return False, f"pcscd clients other than the KMS: {', '.join(others)}"
    return True, f"{len(client_inodes)} pcscd client(s), all the KMS binary"


PROBES = {"core_dumps_disabled": core_dumps, "hibernation_disabled": hibernation,
          "swap_disabled_or_encrypted": swap, "kms_service_unprivileged": unprivileged}
SANDBOX_PROBES = {"kms_service_sandboxed": sandboxed, "kms_capabilities_minimal": capabilities,
                  "kms_apparmor_enforced": apparmor}
