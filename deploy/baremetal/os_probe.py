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
  kms_apparmor_enforced       AppArmor is enabled and the running KMS process is confined by a
                              profile in enforce mode (read from /proc/<MainPID>/attr, not from the
                              unit: AppArmorProfile=-name starts unconfined when the profile is missing)

and that the daemon needs a runtime lease to serve (#74):

  kms_runtime_admission_required  the configuration the unit starts the daemon with (the file after
                              -config in ExecStart) states "runtime_admission": "required" with its
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
MEASURED = ("core_dumps_disabled", "hibernation_disabled", "swap_disabled_or_encrypted", "kms_service_unprivileged",
            "kms_service_sandboxed", "kms_capabilities_minimal", "kms_apparmor_enforced", "kms_runtime_admission_required",
            "kms_opensc_leaves_piv_cards", "kms_pcscd_access_rule")
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


PROBES = {"core_dumps_disabled": core_dumps, "hibernation_disabled": hibernation,
          "swap_disabled_or_encrypted": swap, "kms_service_unprivileged": unprivileged,
          "kms_service_sandboxed": sandboxed, "kms_capabilities_minimal": capabilities,
          "kms_apparmor_enforced": apparmor, "kms_runtime_admission_required": runtime_admission,
          "kms_opensc_leaves_piv_cards": opensc_leaves_piv_cards, "kms_pcscd_access_rule": pcscd_access_rule}
