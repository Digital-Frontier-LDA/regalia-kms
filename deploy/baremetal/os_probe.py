#!/usr/bin/env python3
"""The KMS host's OS-hardening probes, measured on the running system (ADR-0002 D21/D22).

Used by deploy/baremetal/host_probe.py. Each probe reads the host and returns (verdict, reason):

  core_dumps_disabled         the KMS unit's effective LimitCORE is 0, fs.suid_dumpable is 0, and a
                              core_pattern piped to systemd-coredump has Storage=none
  hibernation_disabled        no resume= on the kernel command line, and every hibernating sleep
                              target is masked, or sleep.conf forbids hibernation, hybrid sleep and
                              suspend-then-hibernate
  swap_disabled_or_encrypted  every active swap is zram (RAM) or a dm-crypt device
  kms_service_unprivileged    the unit runs as a non-root User= with NoNewPrivileges=yes

and pcscd_clients(): every process connected to pcscd runs the KMS binary (matched by socket inode,
identified by /proc/<pid>/exe, never by the name a process gives itself).

and the KMS unit's sandbox (#61):

  kms_service_sandboxed       the unit's effective ProtectSystem=strict, ProtectHome, PrivateTmp,
                              ProtectKernelTunables/Modules/Logs, ProtectControlGroups,
                              RestrictSUIDSGID and LockPersonality, as `systemctl show` reports them
  kms_capabilities_minimal    the unit's CapabilityBoundingSet and AmbientCapabilities hold nothing
                              beyond ALLOWED_CAPABILITIES (nothing: an unprivileged KMS on a high
                              port needs none), and so do the bounding, permitted, effective and
                              ambient sets the kernel reports for the running process
  kms_apparmor_enforced       AppArmor is enabled and the running KMS process is confined by
                              PROFILE in enforce mode (read from /proc/<MainPID>/attr, not from the
                              unit: AppArmorProfile=-name starts unconfined when the profile is missing).
                              Any other profile is refused, however strict. So is a stack, except
                              PROFILE stacked on unconfined: systemd 259 labels a User= service
                              'regalia-kms//&unconfined', and that still refuses what the profile denies
                              (regalia-kms#548)

and that the daemon needs a runtime lease to serve (#74):

  kms_runtime_admission_required  the configuration the unit starts the daemon with (the file after
                              -config in ExecStart) judges admissions against regalia-sync's chain
                              (membership_chain_path, #432) and states "runtime_admission": "required" with its
                              admission file, the lease service's user, this node's ID and the boot
                              session file. "disabled-for-lab" is a lab setting: a host carrying it is not
                              commissioned. And the lease service is not root (#191): regalia-admission.service
                              runs as that user (User=, NoNewPrivileges=yes, an empty capability bounding
                              set), and the kernel reports its running main process's real, effective,
                              saved and filesystem uids as that user's, none of them 0

and that the daemon's two token backends do not lock each other out (regalia#541):

  kms_opensc_leaves_piv_cards  when that same configuration names both a PKCS#11 module and YubiKey PIV
                              devices, the unit's Environment carries OPENSC_CONF and the file it names
                              has an ignored_readers entry that matches a YubiKey's reader. The PIV
                              backend needs the card to itself and OpenSC connects to every card it is
                              not told to ignore. With one backend or none there is nothing to check

and the host's kernel settings and its users (#61 K61V-6, regalia-kms-r1s.5):

  kernel_sysctl_baseline      every setting in SYSCTL_BASELINE (the image's /usr/lib/sysctl.d/90-regalia-kms.conf,
                              less fs.suid_dumpable, which core_dumps_disabled measures) has that value in /proc/sys on the running kernel. A value that differs, or that
                              cannot be read, fails the control. The file is not read: what counts is what the
                              kernel applies. A "*" key (net.ipv4.conf.*.rp_filter) holds on all, default and every
                              interface the kernel lists, and a conf directory without all and default fails it
  bootstrap_and_kms_users_separate
                              the KMS daemon (regalia-kms.service) and the bootstrap process (regalia-sync.service,
                              which serves booting peers their unlock contribution) each run as a user of their
                              own: two users, neither root, with different uids and different primary groups. This
                              is read from the units and from getent, and also from the kernel for each running
                              main process: real, effective, saved and filesystem uids are that user's, and so
                              are its four gids (its primary group is its user's own, whatever Group= says). Neither
                              process holds the other's primary group, as its gid or as a supplementary group.
                              Both must be running

and that the daemon, and only the daemon, may talk to pcscd (regalia#541):

  kms_pcscd_access_rule       /etc/polkit-1/rules.d/50-regalia-kms-pcscd.rules is the shipped rule
                              (deploy/polkit/): pcscd's two polkit actions are granted to the KMS user
                              and root and refused to everyone else. Debian's pcscd lets in only users
                              with an active session, so without the grant the daemon reaches no token;
                              without the refusal any user with a console session reaches them all. The
                              file is compared byte for byte and must be readable by polkitd; the only
                              other rules files allowed are the distribution's, known by path and digest;
                              and pkcheck must say polkit admits the running daemon. That a user WITH a
                              console session is refused is not measured: it follows from the rule

and that a production KMS host runs no SSH server (q-20: ABSENT, GA ruling under owner delegation 2026-11-25;
regalia-kms-r1s.12). Administration goes through the console or the iLO and the owner-run flows:

  sshd_absent                 no SSH server binary (SSHD_BINARIES, or sshd on PATH), no unit file whose name is an
                              SSH server's (SSH_UNIT_PATTERNS: ssh.service, ssh.socket, sshd@.service, the
                              systemd-ssh-generator's sshd-*.socket, the staging variant's regalia-staging-sshd.service,
                              dropbear), and nothing listening on TCP :22, on any address. Each is read from the host
                              (stat, systemctl list-unit-files, ss), never from what the image is supposed to hold, and
                              a read that does not answer fails the control. The STAGING image variant carries a
                              key-only operator sshd (image/staging/, gated by regalia.staging=1 and the /var files its
                              staging install writes): it fails this control, by design. Its reason then names the
                              variant, so a staging host's evidence cannot be read as a production host's

Standard library only.
"""
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

SERVICE = "regalia-kms.service"
PROFILE = "regalia-kms"            # deploy/baremetal/apparmor/usr.sbin.regalia-kms, the unit's AppArmorProfile=
MEASURED = ("core_dumps_disabled", "hibernation_disabled", "swap_disabled_or_encrypted", "kms_service_unprivileged",
            "kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced", "kms_runtime_admission_required",
            "kms_opensc_leaves_piv_cards", "kms_pcscd_access_rule", "kernel_sysctl_baseline", "bootstrap_and_kms_users_separate",
            "sshd_absent")
# The kernel settings the image ships as /usr/lib/sysctl.d/90-regalia-kms.conf (deploy/baremetal/regalia-kms.sysctl.conf,
# with each value's reason there). Measured from /proc/sys on the running host, never from the file. A test holds this
# table and the shipped file together.
SYSCTL_FILE = "/usr/lib/sysctl.d/90-regalia-kms.conf"
SYSCTL_BASELINE = {
    "kernel.kptr_restrict": "2",
    "kernel.dmesg_restrict": "1",
    "kernel.perf_event_paranoid": "3",
    "kernel.kexec_load_disabled": "1",
    "kernel.unprivileged_bpf_disabled": "1",
    "net.core.bpf_jit_harden": "2",
    "vm.unprivileged_userfaultfd": "0",
    "dev.tty.ldisc_autoload": "0",
    "kernel.sysrq": "0",
    "kernel.randomize_va_space": "2",
    "kernel.yama.ptrace_scope": "2",
    "fs.protected_symlinks": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_fifos": "2",
    "fs.protected_regular": "2",
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv4.conf.*.rp_filter": "1",
    "net.ipv4.conf.*.accept_redirects": "0",
    "net.ipv4.conf.*.secure_redirects": "0",
    "net.ipv6.conf.*.accept_redirects": "0",
    "net.ipv4.conf.*.send_redirects": "0",
    "net.ipv4.conf.*.accept_source_route": "0",
    "net.ipv6.conf.*.accept_source_route": "0",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
}
# Settings the shipped file also sets that another control measures, so that one broken setting fails one control:
# fs.suid_dumpable is core_dumps_disabled's. The file is held to SYSCTL_BASELINE plus these.
SYSCTL_MEASURED_ELSEWHERE = {"fs.suid_dumpable": ("0", "core_dumps_disabled")}
# The process that holds a booting peer's half of the disk credential and serves it (unlock.serve), and that runs
# heartbeats and leases: regalia-sync (units/regalia-sync.service). It is the bootstrap side of #61's "bootstrap and
# KMS processes have separate users". Each user is declared in /usr/lib/sysusers.d: regalia-sync in
# units/regalia.sysusers.conf, regalia-kms in deploy/systemd/regalia-kms.sysusers.conf.
BOOTSTRAP_SERVICE = "regalia-sync.service"
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
ALLOWED_TOKEN_CLIENT_EXES = ("/usr/sbin/regalia-kms",)


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

    def read_bytes(self, path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError:
            return None

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


def unit_properties(host, *names, service=SERVICE):
    rc, out = host.run(["systemctl", "show", service, "-p", ",".join(names)])
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
    # A stack is "a//&b": confined by each. unconfined adds nothing to one, so PROFILE on unconfined
    # is PROFILE; anything else (another profile, a child "a//b", a namespace ":ns:a") is not.
    stack = set(profile.split("//&"))
    if PROFILE not in stack or stack - {PROFILE, "unconfined"}:
        return False, f"the running KMS (pid {pid}) is under {profile!r}, not {PROFILE!r}"
    return True, f"pid {pid} is confined by {profile!r} in enforce mode"


def daemon_config(host):
    """The configuration the unit starts the daemon with: (config, path, "") or (None, None, why). Read
    from the unit's own ExecStart, not from a path assumed here: what matters is the file the running
    service was given."""
    rc, props = unit_properties(host, "ExecStart", "LoadState")
    if props.get("LoadState") != "loaded":
        return None, None, f"{SERVICE} is not loaded"
    found = re.search(r"argv\[\]=(.*?) ;", props.get("ExecStart", ""))
    argv = found.group(1).split() if found else []
    paths = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("-config", "--config")]
    paths += [a.split("=", 1)[1] for a in argv if a.startswith(("-config=", "--config="))]
    if len(paths) != 1 or not paths[0].startswith("/"):
        return None, None, f"{SERVICE} is not started with exactly one absolute -config file (ExecStart: {' '.join(argv) or 'unreadable'})"
    text = host.read(paths[0])
    if text is None:
        return None, None, f"cannot read the daemon's configuration {paths[0]}"
    try:
        config = json.loads(text)
    except ValueError:
        return None, None, f"{paths[0]} is not valid JSON"
    if not isinstance(config, dict):
        return None, None, f"{paths[0]} is not a JSON object"
    return config, paths[0], ""


MEMBERSHIP_CHAIN = "/var/lib/regalia-sync/chain.json"     # node.PUBLISHED in regalia-sync's state directory
SYNC_USER = "regalia-sync"


def runtime_admission(host):
    """The daemon is started with a configuration that REQUIRES a runtime lease."""
    config, path, why = daemon_config(host)
    if config is None:
        return False, why
    paths = [path]
    stated = config.get("runtime_admission")
    if stated == "disabled-for-lab":
        return False, f"{paths[0]} says runtime_admission \"disabled-for-lab\": this daemon serves with no runtime lease"
    if stated != "required":
        return False, f"{paths[0]} does not state runtime_admission \"required\" (it says {stated!r})"
    missing = [k for k in ("runtime_admission_path", "runtime_admission_owner", "node_id", "boot_session_path")
               if not (isinstance(config.get(k), str) and config[k])]
    if missing:
        return False, f"{paths[0]} requires runtime admission but lacks {', '.join(missing)}"
    # AN ADMISSION IS GOOD ONLY FOR THE EPOCH IT WAS JUDGED UNDER (#432): on a host, the daemon judges it against
    # regalia-sync's published chain. The setting is optional in the configuration (e2e and lab configs have no
    # chain), so a host states it, never assumes it (48 on #509)
    if config.get("membership_chain_path") != MEMBERSHIP_CHAIN or config.get("membership_chain_owner") != SYNC_USER:
        return False, (f"{paths[0]} does not judge admissions against the membership chain: membership_chain_path must be "
                       f"{MEMBERSHIP_CHAIN} and membership_chain_owner {SYNC_USER}")
    ok, why = lease_service_unprivileged(host, config["runtime_admission_owner"])
    if not ok:
        return False, why
    return True, (f"{paths[0]}: runtime_admission required, node {config['node_id']}, "
                  f"admission file {config['runtime_admission_path']}; {why}")


ADMISSION_SERVICE = "regalia-admission.service"


def lease_service_unprivileged(host, owner):
    """The lease service runs as `owner` (the daemon's runtime_admission_owner), which is not root: as the
    unit says, and as the kernel reports for its running main process (#191)."""
    if owner in ("root", "0"):
        return False, "runtime_admission_owner is root: the lease service, which parses what peers send, runs as root"
    rc, entry = host.run(["getent", "passwd", owner])
    fields = entry.strip().split(":") if rc == 0 else []
    if len(fields) < 3 or not fields[2].isdigit():
        return False, f"runtime_admission_owner {owner!r} is not a user on this host"
    uid = fields[2]
    if uid == "0":
        return False, f"runtime_admission_owner {owner!r} has uid 0"
    _, props = unit_properties(host, "User", "NoNewPrivileges", "CapabilityBoundingSet", "MainPID", "LoadState", service=ADMISSION_SERVICE)
    if props.get("LoadState") != "loaded":
        return False, f"{ADMISSION_SERVICE} is not loaded"
    if props.get("User") != owner:
        return False, f"{ADMISSION_SERVICE} runs as {props.get('User') or 'root (no User=)'}, not {owner}, the user the daemon trusts"
    if props.get("NoNewPrivileges") != "yes":
        return False, f"{ADMISSION_SERVICE} has NoNewPrivileges={props.get('NoNewPrivileges')!r}"
    if "CapabilityBoundingSet" not in props or props["CapabilityBoundingSet"].strip():
        return False, f"{ADMISSION_SERVICE} has a capability bounding set: {props.get('CapabilityBoundingSet', 'unreadable') or 'every capability'}"
    pid = props.get("MainPID", "")
    if not pid.isdigit() or pid == "0":
        return False, f"{ADMISSION_SERVICE} is not running, so the uid the kernel gave it cannot be read (start it first)"
    found = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", host.read(f"/proc/{pid}/status") or "", re.M)
    if not found:
        return False, f"/proc/{pid}/status has no Uid line"
    if set(found.groups()) != {uid}:
        return False, f"the running lease service (pid {pid}) has uids {' '.join(found.groups())}, not {owner}'s {uid} throughout"
    return True, f"the lease service runs as {owner} (uid {uid}, pid {pid}), NoNewPrivileges=yes, no capability"


# What a YubiKey's CCID reader is called by pcscd ("Yubico YubiKey OTP+FIDO+CCID 00 00", "Yubico YubiKey
# CCID 00 00", ...): every model's name starts with this.
YUBIKEY_READER = "Yubico YubiKey"
# The application blocks opensc-pkcs11.so reads, in the order it prefers them.
OPENSC_APPS = ("opensc-pkcs11", "default")


def opensc_tokens(text):
    """An OpenSC configuration as tokens: quoted strings ("s", text), bare words ("w", text) and the
    punctuation { } = , ; ("p", char). `#` starts a comment except inside a string. Raises ValueError
    on a string that never ends."""
    tokens, at, size = [], 0, len(text)
    while at < size:
        c = text[at]
        if c in " \t\r\n":
            at += 1
        elif c == "#":
            while at < size and text[at] != "\n":
                at += 1
        elif c == '"':
            end, value = at + 1, []
            while end < size and text[end] != '"':
                if text[end] == "\\" and end + 1 < size and text[end + 1] in '"\\':
                    end += 1          # \" and \\ are the character itself; any other backslash is kept
                value.append(text[end])
                end += 1
            if end >= size:
                raise ValueError("a string is not closed")
            tokens.append(("s", "".join(value)))
            at = end + 1
        elif c in "{}=,;":
            tokens.append(("p", c))
            at += 1
        else:
            end = at
            while end < size and text[end] not in ' \t\r\n#"{}=,;':
                end += 1
            tokens.append(("w", text[at:end]))
            at = end
    return tokens


def ignored_readers(text):
    """The ignored_readers list opensc-pkcs11.so applies, or [] when it applies none. Raises ValueError
    for a file that is not well formed.

    READ AS OPENSC READS IT, not as a line of text, and STRICTLY. OpenSC takes the list from the
    application block it selected: `app opensc-pkcs11 { }` if the file has one, else `app default { }`;
    from the first such block at the top level, its first ignored_readers statement, as a direct item
    of the block. A line inside another application's block, inside a nested block, or at the top level
    is not applied, and neither is one in `app default` when an `app opensc-pkcs11` block exists: some
    OpenSC versions consult only the first block they selected, so only that one is counted here.

    A file OpenSC might not parse proves nothing about what it applies, so one is refused rather than
    guessed at: braces that do not balance, and an ignored_readers statement that is not `= value, value
    ... ;` (a missing semicolon would otherwise swallow the next statement's words into the list)."""
    tokens = opensc_tokens(text or "")
    depth = 0
    for kind, value in tokens:
        if (kind, value) == ("p", "{"):
            depth += 1
        elif (kind, value) == ("p", "}"):
            depth -= 1
            if depth < 0:
                raise ValueError("a } closes nothing")
    if depth != 0:
        raise ValueError("a block is not closed")

    def statement(at):
        """The values of `ignored_readers = v, v, ... ;` starting at tokens[at], and where it ends."""
        if at + 1 >= len(tokens) or tokens[at + 1] != ("p", "="):
            raise ValueError("ignored_readers is not followed by =")
        values, at, want_value = [], at + 2, True
        while at < len(tokens) and tokens[at] != ("p", ";"):
            kind, value = tokens[at]
            if want_value and kind in "ws":
                values.append(value)
            elif not want_value and (kind, value) == ("p", ","):
                pass
            else:
                raise ValueError("the ignored_readers list is not values separated by commas and ended by ;")
            want_value, at = not want_value, at + 1
        if at >= len(tokens) or (want_value and values):
            raise ValueError("the ignored_readers list is not ended by ;")
        return values, at + 1

    blocks, at, depth = {}, 0, 0   # app name -> the ignored_readers lists of its first top-level block
    while at < len(tokens):
        if tokens[at] == ("p", "{"):
            depth += 1
        elif tokens[at] == ("p", "}"):
            depth -= 1
        elif (depth == 0 and tokens[at] == ("w", "app") and at + 2 < len(tokens) and tokens[at + 1][0] in "ws"
              and tokens[at + 2] == ("p", "{")):
            name, inner, at = tokens[at + 1][1], 1, at + 3
            lists = []
            while inner:
                if tokens[at] == ("p", "{"):
                    inner += 1
                elif tokens[at] == ("p", "}"):
                    inner -= 1
                elif inner == 1 and tokens[at] == ("w", "ignored_readers") and tokens[at - 1] in (("p", "{"), ("p", "}"), ("p", ";")):
                    values, at = statement(at)
                    lists.append(values)
                    continue
                at += 1
            blocks.setdefault(name, lists)   # a second block of the same name is not the one selected
            continue
        at += 1
    for app in OPENSC_APPS:
        if app in blocks:
            return blocks[app][0] if blocks[app] else []
    return []


def unit_environment(host):
    """The unit's Environment as a dict, or (None, why). A unit with an EnvironmentFile is refused: what
    such a file sets is not in the Environment property, and it overrides it."""
    rc, props = unit_properties(host, "Environment", "EnvironmentFiles")
    if props.get("EnvironmentFiles", "").strip():
        return None, f"{SERVICE} has an EnvironmentFile, which can set or override OPENSC_CONF and is not read here: set it with Environment="
    environment = {}
    try:
        for item in shlex.split(props.get("Environment", "")):
            key, sep, value = item.partition("=")
            if sep:
                environment[key] = value   # a variable set twice: the last one counts, as for systemd
    except ValueError:
        return None, f"cannot read the Environment of {SERVICE}"
    return environment, ""


def opensc_leaves_piv_cards(host):
    """A daemon that holds both a PKCS#11 module and YubiKey PIV devices is started with an OpenSC
    configuration that ignores the YubiKey's reader. Without it the daemon's own PKCS#11 module holds the
    card the PIV backend must open exclusively. The daemon refuses to start when it sees that with the
    card attached; this says so before it is started, and with the card unplugged."""
    config, path, why = daemon_config(host)
    if config is None:
        return False, why
    module, devices = config.get("pkcs11_module_path"), config.get("yubikey_devices")
    if not (isinstance(module, str) and module.strip()) or not (isinstance(devices, dict) and devices):
        return True, f"{path}: not both a PKCS#11 module and YubiKey PIV devices, nothing to keep apart"
    environment, why = unit_environment(host)
    if environment is None:
        return False, why
    conf = environment.get("OPENSC_CONF", "")
    if not conf.startswith("/"):
        return False, (f"{path} names a PKCS#11 module and YubiKey PIV devices, and {SERVICE} does not set "
                       "OPENSC_CONF in its Environment: OpenSC's defaults connect to the YubiKey and lock the PIV backend out")
    text = host.read(conf)
    if text is None:
        return False, f"cannot read the OpenSC configuration {conf} named by OPENSC_CONF"
    try:
        entries = ignored_readers(text)
    except ValueError as problem:
        return False, f"{conf} cannot be read as an OpenSC configuration: {problem}"
    # OpenSC ignores a reader whose name CONTAINS an entry. An entry counts when it is a piece of what
    # every YubiKey reader is called AND names the YubiKey: "Yubico", "YubiKey", "Yubico YubiKey". A piece
    # such as " " or "i" would ignore the YubiKey too, and the HSM's reader with it.
    matching = [entry for entry in entries if "Yubi" in entry and entry in YUBIKEY_READER]
    if not matching:
        return False, (f"{conf}: the block opensc-pkcs11.so reads (app opensc-pkcs11, else app default) has no "
                       f"ignored_readers entry that names a YubiKey's reader (a piece of {YUBIKEY_READER!r} containing \"Yubi\")")
    return True, f"{conf}: ignored_readers {matching[0]!r} keeps OpenSC off the YubiKey"


PCSCD_RULE_PATH = "/etc/polkit-1/rules.d/50-regalia-kms-pcscd.rules"
POLKIT_RULE_DIRECTORIES = ("/etc/polkit-1/rules.d", "/run/polkit-1/rules.d", "/usr/local/share/polkit-1/rules.d", "/usr/share/polkit-1/rules.d")
# sha256 of deploy/polkit/50-regalia-kms-pcscd.rules, and of the same file with ONLY_THE_KMS = false.
# tests/test_baremetal_os_probe.py holds these to the file. The file is compared byte for byte: what a
# JavaScript file does cannot be decided by reading it line by line.
PCSCD_RULE_SHA256 = "75d942b8a3d3c62be4082787eb1373504b09bee0fe0197541c910402a66eb55b"
PCSCD_RULE_BENCH_SHA256 = "4a052de6c145ea44ebce731bb968099b445e6eb89e80385747025bdbe9a3abbf"
PCSCD_ACTIONS = ("org.debian.pcsc-lite.access_pcsc", "org.debian.pcsc-lite.access_card")
# THE ONLY OTHER RULES FILES A KMS HOST MAY CARRY: the distribution's own, known by path and sha256
# (measured on Debian 13: polkitd 126-2, systemd 257.13, network-manager 1.52.1). Every rules file runs
# in one JavaScript context with the KMS rule and can grant before it or rewrite polkit's objects under
# it, and what a program does cannot be decided by reading it: a list of suspicious words was tried and
# an independent read found a dozen ways round it. So any other file fails the control, by name. A
# distribution update that changes one of these files fails it too, until the digest here is renewed.
KNOWN_RULES_FILES = {
    "/usr/share/polkit-1/rules.d/50-default.rules": "29f073ed9a8a6996b62f718e2bec962d5c84d311d23bb874830b4f9887eeabbf",
    "/usr/share/polkit-1/rules.d/org.freedesktop.NetworkManager.rules": "c9c419a58f716c4de1f469a362dbb00745c0d35ae3077857b03168bdd9b06ee0",
    "/usr/share/polkit-1/rules.d/systemd-networkd.rules": "f199e386a9297858331b00df07ed0b0ee5fcf4bea67f6c0bccc8a92b7e310bbd",
}


def rules_files(host, directory):
    """The *.rules file names in a polkit rules directory, or None when it exists and cannot be listed."""
    rc, _ = host.run(["test", "-d", directory])
    if rc != 0:
        return []
    # -H: a directory that is a symlink is followed, as polkitd's opendir follows it
    rc, out = host.run(["find", "-H", directory, "-mindepth", "1", "-maxdepth", "1", "-name", "*.rules", "-printf", "%f\\n"])
    if rc != 0:
        return None
    return sorted(line for line in out.splitlines() if line)


def pcscd_access_rule(host):
    """pcscd lets in the KMS user and root, and nobody else, by the shipped polkit rule; nothing on the host
    is seen to undo that; and polkit, asked about the running daemon, says yes.

    What it cannot measure: that a user with an active console session is refused. That follows from the
    rule and from no other file deciding first, which is checked here by reading the other files; a check
    by reading cannot be complete for a program, so the list of what it refuses is deliberately wide."""
    raw = host.read_bytes(PCSCD_RULE_PATH)
    if raw is None:
        return False, (f"{PCSCD_RULE_PATH} is missing or unreadable: pcscd admits only users with an active session, "
                       "so the KMS service user reaches no token (install deploy/polkit/50-regalia-kms-pcscd.rules)")
    digest = hashlib.sha256(raw).hexdigest()
    if digest == PCSCD_RULE_BENCH_SHA256:
        return False, f"{PCSCD_RULE_PATH} grants the KMS user and refuses nobody (ONLY_THE_KMS = false): a bench setting, not a KMS host's"
    if digest != PCSCD_RULE_SHA256:
        return False, f"{PCSCD_RULE_PATH} is not, byte for byte, the shipped rule (deploy/polkit/50-regalia-kms-pcscd.rules)"
    rc, out = host.run(["stat", "-c", "%u %a", PCSCD_RULE_PATH])
    fields = out.split()
    mode = int(fields[1], 8) if rc == 0 and len(fields) == 2 and re.fullmatch(r"[0-7]{3,4}", fields[1]) else None
    if mode is None or fields[0] != "0" or mode & 0o022:
        return False, f"{PCSCD_RULE_PATH} is not root's alone to change (owner and mode: {out.strip() or 'unreadable'})"
    if not mode & 0o004:
        return False, f"{PCSCD_RULE_PATH} is not readable by others (mode {fields[1]}): polkitd reads it as its own user and would not load it"
    for directory in POLKIT_RULE_DIRECTORIES:
        names = rules_files(host, directory)
        if names is None:
            return False, f"{directory} cannot be listed: what it grants is unknown"
        # Every directory polkitd reads, empty or not, and its parent: whoever can write either can add
        # a rules file, or rename one in, and polkitd loads it at once.
        rc, _ = host.run(["test", "-e", directory])
        for place in ((directory, os.path.dirname(directory)) if rc == 0 else ()):
            rc, out = host.run(["stat", "-L", "-c", "%u %a", place])
            fields = out.split()
            if rc != 0 or len(fields) != 2 or fields[0] != "0" or not re.fullmatch(r"[0-7]{3,4}", fields[1]) or int(fields[1], 8) & 0o022:
                return False, f"{place} is not root's alone to change (owner and mode: {out.strip() or 'unreadable'})"
        for name in names:
            path = f"{directory}/{name}"
            if path == PCSCD_RULE_PATH:
                continue
            if path not in KNOWN_RULES_FILES:
                return False, (f"{path} is a polkit rules file this host is not known to need: it runs beside the KMS rule and could "
                               "grant pcscd before it or rewrite polkit under it. A KMS host carries only the distribution's rules files and the KMS rule")
            other = host.read_bytes(path)
            if other is None:
                return False, f"{path} cannot be read: what it grants is unknown"
            if hashlib.sha256(other).hexdigest() != KNOWN_RULES_FILES[path]:
                return False, f"{path} is not the distribution's file as known (its digest differs): what it grants is unknown"
    # The effect, asked of polkit itself: the running daemon is admitted to both actions.
    rc, out = host.run(["systemctl", "show", SERVICE, "-p", "MainPID", "--value"])
    pid = out.strip()
    if rc != 0 or not pid.isdigit() or pid == "0":
        return False, f"{SERVICE} is not running: polkit cannot be asked whether it admits the daemon"
    for action in PCSCD_ACTIONS:
        rc, _ = host.run(["pkcheck", "--action-id", action, "--process", pid])
        if rc != 0:
            return False, f"polkit does not authorize the running KMS (pid {pid}) for {action}"
    return True, (f"{PCSCD_RULE_PATH}: the shipped rule; the only other rules files are the distribution's, known by digest; "
                  f"polkit authorizes the running KMS (pid {pid}) for pcscd")


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


def sysctl_paths(host, key):
    """[(name, /proc/sys path)] a baseline key covers. A "*" component is every entry of that directory as the kernel
    lists it now (net.ipv4.conf.*: all, default and each interface), named by the entry itself: an interface name may
    hold a dot, which a dotted key cannot say. A directory that does not list "all" and "default" is not the kernel's
    and gives one unreadable path, so the key fails."""
    parts = key.split(".")
    if "*" not in parts:
        return [(key, "/proc/sys/" + "/".join(parts))]
    at = parts.index("*")
    directory = "/proc/sys/" + "/".join(parts[:at])
    entries = sorted(host.listdir(directory))
    if not {"all", "default"} <= set(entries):
        return [(f"{key} (the entries of {directory})", None)]
    rest = "/".join(parts[at + 1:])
    return [(".".join(parts[:at]) + f".{entry}." + ".".join(parts[at + 1:]), f"{directory}/{entry}/{rest}") for entry in entries]


def sysctl_baseline(host):
    """Every SYSCTL_BASELINE setting has its value in /proc/sys, on every interface for a "*" key. All the
    differences are named, not only the first."""
    wrong = []
    for key, want in SYSCTL_BASELINE.items():
        for name, path in sysctl_paths(host, key):
            value = host.read(path) if path else None
            if value is None:
                wrong.append(f"{name} cannot be read (want {want})")
            elif " ".join(value.split()) != want:
                wrong.append(f"{name}={' '.join(value.split())!r} (want {want})")
    if wrong:
        return False, f"{len(wrong)} kernel setting(s) differ from the baseline {SYSCTL_FILE}: " + "; ".join(wrong)
    return True, f"all {len(SYSCTL_BASELINE)} settings of {SYSCTL_FILE} hold in /proc/sys"


def service_identity(host, service):
    """(user, uid, gid, process gids, "") for a running service whose kernel uids are its User='s, or
    (None, None, None, None, why)."""
    _, props = unit_properties(host, "User", "MainPID", "LoadState", service=service)
    if props.get("LoadState") != "loaded":
        return None, None, None, None, f"{service} is not loaded"
    user = props.get("User", "")
    if user in ("", "root", "0"):
        return None, None, None, None, f"{service} runs as {user or 'root (no User=)'}"
    rc, entry = host.run(["getent", "passwd", user])
    fields = entry.strip().split(":") if rc == 0 else []
    if len(fields) < 4 or not fields[2].isdigit() or not fields[3].isdigit():
        return None, None, None, None, f"{service}'s user {user!r} is not a user on this host"
    uid, gid = fields[2], fields[3]
    if uid == "0":
        return None, None, None, None, f"{service}'s user {user!r} has uid 0"
    pid = props.get("MainPID", "")
    if not pid.isdigit() or pid == "0":
        return None, None, None, None, f"{service} is not running, so the user the kernel gave it cannot be read (start it first)"
    status = host.read(f"/proc/{pid}/status") or ""
    uids = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.M)
    gids = re.search(r"^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.M)
    groups = re.search(r"^Groups:[ \t]*([\d \t]*)$", status, re.M)
    if not uids or not gids or not groups:
        return None, None, None, None, f"/proc/{pid}/status ({service}) has no Uid, Gid or Groups line"
    if set(uids.groups()) != {uid}:
        return None, None, None, None, (f"{service}'s running process (pid {pid}) has uids {' '.join(uids.groups())}, "
                                        f"not {user}'s {uid} throughout")
    # The running primary group is the user's own group, as the kernel reports it: a unit's Group= can give a process
    # another one, and two processes sharing it would share what that group may read
    if set(gids.groups()) != {gid}:
        return None, None, None, None, (f"{service}'s running process (pid {pid}) has gids {' '.join(gids.groups())}, "
                                        f"not {user}'s own group {gid} throughout")
    return user, uid, gid, {gid} | set(groups.group(1).split()), ""


def separate_users(host):
    """The KMS daemon and the bootstrap process run as two different unprivileged users, and neither process holds
    the other's primary group."""
    kms = service_identity(host, SERVICE)
    if kms[0] is None:
        return False, kms[4]
    boot = service_identity(host, BOOTSTRAP_SERVICE)
    if boot[0] is None:
        return False, boot[4]
    (k_user, k_uid, k_gid, k_groups, _), (b_user, b_uid, b_gid, b_groups, _) = kms, boot
    if k_user == b_user or k_uid == b_uid:
        return False, f"{SERVICE} and {BOOTSTRAP_SERVICE} run as the same user ({k_user}, uid {k_uid}, and {b_user}, uid {b_uid})"
    if k_gid == b_gid:
        return False, f"{k_user} and {b_user} share the primary group {k_gid}"
    if b_gid in k_groups:
        return False, f"the running KMS daemon holds {b_user}'s primary group {b_gid}"
    if k_gid in b_groups:
        return False, f"the running bootstrap process holds {k_user}'s primary group {k_gid}"
    return True, (f"{SERVICE} runs as {k_user} (uid {k_uid}, gid {k_gid}) and {BOOTSTRAP_SERVICE} as {b_user} "
                  f"(uid {b_uid}, gid {b_gid}); neither process holds the other's group")


# q-20: ABSENT, GA ruling under owner delegation 2026-11-25 (regalia-kms-r1s.12): no SSH server on a production KMS host.
# Where an SSH server's programs live on Debian 13 (OpenSSH 10 runs each session as sshd-session, and sshd-auth for
# authentication) and elsewhere, and Dropbear's. /sbin and /bin are links into /usr on a merged-/usr system.
SSHD_BINARIES = ("/usr/sbin/sshd", "/usr/bin/sshd", "/usr/local/sbin/sshd", "/usr/local/bin/sshd",
                 "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth", "/usr/libexec/openssh/sshd-session",
                 "/usr/sbin/dropbear")
# The unit files an SSH server comes with (systemctl list-unit-files globs): Debian's ssh.service, ssh.socket and
# ssh@.service; sshd.service and sshd@.service elsewhere; systemd-ssh-generator's sshd-vsock.socket and
# sshd-unix-local.socket (systemd 256+, made when an sshd is installed); the staging variant's
# regalia-staging-sshd.service; Dropbear's. The KMS unit is listed with them, so an empty answer cannot pass.
SSH_UNIT_PATTERNS = ("ssh.*", "ssh@*", "*sshd*", "dropbear*")
SSH_PORT = 22
PROC_TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")   # the listeners as the kernel holds them, beside ss's answer
STAGING_VARIANT = "/usr/lib/regalia-staging/VARIANT"   # build-rootfs.sh --variant staging writes it; imagevariant.py
                                                       # refuses a production image that holds it


def sshd_absent(host):
    """No SSH server on the host: no binary, no unit, nothing on TCP :22. Every problem is named, not the first only."""
    found = []
    # stat exits 1 for a missing path AND for most other errors: a stat that cannot stat "/" cannot say "absent" either
    rc, out = host.run(["stat", "-c", "%F", "/"])
    if rc != 0 or out.strip() != "directory":
        found.append(f"stat does not answer (stat / exit {rc}: {out.strip() or 'no output'}), so no path can be shown absent")
    for path in SSHD_BINARIES:
        # stat without -L: a link that points nowhere is still an SSH server's name, and is reported
        rc, out = host.run(["stat", "-c", "%F", path])
        if rc == 0:
            found.append(f"{path} is present ({out.strip() or 'a file'})")
        elif rc != 1:
            found.append(f"{path} cannot be checked (stat exit {rc})")
    on_path = host.which("sshd")
    if on_path and on_path not in SSHD_BINARIES:
        found.append(f"sshd is on PATH as {on_path}")
    rc, out = host.run(["systemctl", "list-unit-files", "--no-legend", "--no-pager", SERVICE, *SSH_UNIT_PATTERNS])
    units = [line.split() for line in out.splitlines() if line.split()]
    if SERVICE not in [unit[0] for unit in units]:
        found.append(f"the unit files cannot be listed (systemctl list-unit-files does not show {SERVICE})")
    else:
        found += [f"the unit {unit[0]} exists ({unit[1] if len(unit) > 1 else 'state unknown'})" for unit in units if unit[0] != SERVICE]
    rc, out = host.run(["ss", "-Hltn"])
    if rc != 0:
        found.append("the TCP listeners cannot be listed (ss failed)")
    else:
        # ss -Hltn: State Recv-Q Send-Q Local-Address:Port Peer-Address:Port. The port is after the last colon of the
        # local address (0.0.0.0:22, [::]:22, 0.0.0.0%eth0:22, *:22)
        found += [f"{fields[3]} is listening" for fields in (line.split() for line in out.splitlines())
                  if len(fields) >= 4 and fields[3].rpartition(":")[2] == str(SSH_PORT)]
    # the kernel's own tables, read independently of ss: an ss that exits 0 and prints nothing must not read as
    # "nothing on :22". Each row: sl local_address(hex IP:hex port) rem_address st(0A = LISTEN) ...
    for table in PROC_TCP_TABLES:
        text = host.read(table)
        if text is None:
            found.append(f"{table} cannot be read")
            continue
        found += [f"{table} shows a listener on :{SSH_PORT} ({fields[1]})" for fields in (line.split() for line in text.splitlines()[1:])
                  if len(fields) >= 4 and fields[3] == "0A" and fields[1].rpartition(":")[2].upper() == "%04X" % SSH_PORT]
    if found:
        why = "this host is not shown to be free of an SSH server (a production KMS host has none, q-20): " + "; ".join(found)
        if host.read(STAGING_VARIANT) is not None:
            why += (f". This is the STAGING image variant ({STAGING_VARIANT}): its operator sshd is staging-only, and "
                    "a staging host is never a production host")
        return False, why
    return True, f"no SSH server binary, no ssh or sshd unit file, nothing listening on TCP :{SSH_PORT} (q-20: absent)"


PROBES = {"core_dumps_disabled": core_dumps, "hibernation_disabled": hibernation,
          "swap_disabled_or_encrypted": swap, "kms_service_unprivileged": unprivileged,
          "kms_service_sandboxed": sandboxed, "kms_capabilities_minimal": capabilities,
          "kms_apparmor_enforced": apparmor, "kms_runtime_admission_required": runtime_admission,
          "kms_opensc_leaves_piv_cards": opensc_leaves_piv_cards, "kms_pcscd_access_rule": pcscd_access_rule,
          "kernel_sysctl_baseline": sysctl_baseline, "bootstrap_and_kms_users_separate": separate_users,
          "sshd_absent": sshd_absent}
