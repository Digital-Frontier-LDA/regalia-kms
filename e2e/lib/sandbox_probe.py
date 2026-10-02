#!/usr/bin/env python3
"""A dummy service that TRIES what the KMS sandbox must refuse (#61, PoC 1.2), and what it must allow.

Run by e2e/kms-sandbox-negative.sh inside a transient systemd unit, once with the shipped hardening
and once with none. Every action runs in its own child process, because a system-call filter may
kill the process that tries (SIGSYS) instead of returning an error. Prints one JSON object:
action -> "allowed", "refused (<errno or signal>)", or "skipped (<why>)".

The paths of the marker files the test created outside the sandbox come in the environment:
MARKER_ROOT (under /root), MARKER_HOME (under /home), MARKER_TMP (in the host's /tmp).
Standard library only.
"""
import ctypes
import errno
import json
import os
import platform
import signal
import socket
import sys

STATE = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
PID = os.getpid()
libc = ctypes.CDLL(None, use_errno=True)


def create(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.unlink(path)


def write_tunable():
    with open("/proc/sys/kernel/printk", "r+") as f:      # written back unchanged
        value = f.read()
        f.seek(0)
        f.write(value)


def load_module():
    """init_module(2) with 64 bytes that are no module. A caller allowed to load modules gets the
    loader's verdict on the bytes (ENOEXEC and the like); one that is not gets EPERM or is killed."""
    if platform.machine() != "x86_64":
        raise RuntimeError("init_module's number is only known here for x86_64")
    junk = ctypes.create_string_buffer(b"\0" * 64, 64)
    if libc.syscall(175, junk, 64, b"") == 0:
        return
    err = ctypes.get_errno()
    if err in (errno.EPERM, errno.EACCES, errno.ENOSYS):
        raise OSError(err, os.strerror(err))
    # any other error came from the loader: the caller was let in


def make_setuid():
    path = os.path.join(STATE, "setuid-%d" % PID)
    with open(path, "w"):
        pass
    try:
        os.chmod(path, 0o4755)
    finally:
        os.unlink(path)


def chown_away():
    """Give a file to another user: only CAP_CHOWN can."""
    path = os.path.join(STATE, "chown-%d" % PID)
    with open(path, "w"):
        pass
    try:
        os.chown(path, 12345, 12345)
    finally:
        os.unlink(path)


def personality():
    if libc.personality(0x0008) == -1:                    # PER_LINUX32
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def new_namespace():
    if libc.unshare(0x00020000) == -1:                    # CLONE_NEWNS
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def open_socket(family, kind):
    return lambda: socket.socket(family, kind).close()


ACTIONS = {
    # the filesystem outside the state directory
    "write_etc": lambda: create("/etc/regalia-sandbox-probe.%d" % PID),
    "write_usr": lambda: create("/usr/local/regalia-sandbox-probe.%d" % PID),
    "write_var": lambda: create("/var/regalia-sandbox-probe.%d" % PID),
    "read_root_home": lambda: os.stat(os.environ["MARKER_ROOT"]),
    "read_home": lambda: os.stat(os.environ["MARKER_HOME"]),
    "see_host_tmp": lambda: os.stat(os.environ["MARKER_TMP"]),
    # the kernel
    "write_kernel_tunable": write_tunable,
    "list_kernel_modules": lambda: os.listdir("/usr/lib/modules"),
    "load_kernel_module": load_module,
    "read_kernel_log": lambda: os.close(os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)),
    # privilege
    "make_setuid_file": make_setuid,
    "use_cap_chown": chown_away,
    "change_personality": personality,
    "new_mount_namespace": new_namespace,
    # sockets
    "socket_netlink": open_socket(socket.AF_NETLINK, socket.SOCK_RAW),
    "socket_packet": open_socket(socket.AF_PACKET, socket.SOCK_RAW),
    # what the KMS needs, and must still have
    "write_state_directory": lambda: create(os.path.join(STATE, "probe-%d" % PID)),
    "socket_inet_stream": open_socket(socket.AF_INET, socket.SOCK_STREAM),
    "socket_inet6_stream": open_socket(socket.AF_INET6, socket.SOCK_STREAM),
    "socket_unix": open_socket(socket.AF_UNIX, socket.SOCK_STREAM),
}


def attempt(action):
    """Run one action in a child; the verdict travels back as its exit status or the signal that killed it."""
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            action()
        except OSError as error:
            code = 100 + min(error.errno or 0, 150)
        except RuntimeError:
            code = 99
        except BaseException:
            code = 98
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return "refused (killed by %s)" % signal.Signals(os.WTERMSIG(status)).name
    code = os.WEXITSTATUS(status)
    if code == 0:
        return "allowed"
    if code == 99:
        return "skipped (not supported on this machine)"
    if code == 98:
        return "skipped (the probe itself failed)"
    return "refused (%s)" % errno.errorcode.get(code - 100, "errno %d" % (code - 100))


def status_field(name):
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith(name + ":"):
                return line.split(":", 1)[1].strip()
    return ""


def main():
    report = {name: attempt(action) for name, action in ACTIONS.items()}
    # Not attempts but the process's own state, as the kernel reports it.
    report["state"] = {"uid": os.getuid(), "CapBnd": status_field("CapBnd"), "CapEff": status_field("CapEff"),
                       "NoNewPrivs": status_field("NoNewPrivs"), "Seccomp": status_field("Seccomp")}
    json.dump(report, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
