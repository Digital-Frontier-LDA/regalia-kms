#!/usr/bin/env python3
"""Run sc-hsm-tool with its PINs and DKEK password typed into its own prompts, never on argv.

sc-hsm-tool has no `env:` form (OpenSC 0.26.1), so `--so-pin X --pin Y --password Z` puts the
secrets in the process list for as long as the card takes, which is minutes for an initialise. Left
out, the tool prompts for each one; this answers those prompts over a pty from the environment:

    SCHSM_SO_PIN=… SCHSM_USER_PIN=… SCHSM_DKEK_PW=… e2e/lib/sc-hsm-pty.py sc-hsm-tool --reader 3 --initialize …

A secret is typed only once the prompt has turned echo OFF (input typed earlier can be flushed by the
prompt, and would be echoed back). The tool's output is passed through with every secret redacted.
The exit status is the tool's. A prompt whose secret is not in the environment is a hard stop, never
a guess, because a wrong guess at a PIN prompt spends a retry.
"""
import os
import pty
import re
import select
import sys
import termios
import time

PROMPTS = [
    (re.compile(r"Enter SO-PIN \(16 hexadecimal characters\) : ?$"), "SCHSM_SO_PIN"),
    (re.compile(r"Enter initial User-PIN \(6 - 16 characters\) : ?$"), "SCHSM_USER_PIN"),
    (re.compile(r"Enter User PIN : ?$"), "SCHSM_USER_PIN"),
    (re.compile(r"Enter password to (en|de)crypt DKEK share : ?$"), "SCHSM_DKEK_PW"),
    (re.compile(r"Please retype password to confirm : ?$"), "SCHSM_DKEK_PW"),
]
SECRETS = [v for v in (os.environ.get(k) for k in ("SCHSM_SO_PIN", "SCHSM_USER_PIN", "SCHSM_DKEK_PW")) if v]


def redact(text):
    for secret in SECRETS:
        text = text.replace(secret, "<redacted>")
    return text


def main(argv):
    if not argv:
        sys.exit("usage: sc-hsm-pty.py sc-hsm-tool ARGS…")
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    buffer, line = "", ""
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 1)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096).decode("utf-8", "replace")
        except OSError:
            break
        if not chunk:
            break
        buffer += chunk
        line += chunk
        sys.stdout.write(redact(chunk.replace("\r", "")))
        sys.stdout.flush()
        tail = line.rsplit("\n", 1)[-1]
        for pattern, variable in PROMPTS:
            if pattern.search(tail):
                value = os.environ.get(variable)
                if not value:
                    os.kill(pid, 9)
                    sys.exit(f"sc-hsm-pty: the tool asked for {variable}, which is not set: stopped, nothing typed")
                until = time.monotonic() + 5
                while termios.tcgetattr(fd)[3] & termios.ECHO and time.monotonic() < until:
                    time.sleep(0.02)
                if termios.tcgetattr(fd)[3] & termios.ECHO:
                    os.kill(pid, 9)
                    _, status = os.waitpid(pid, 0)
                    return os.waitstatus_to_exitcode(status)
                os.write(fd, (value + "\n").encode())
                line = ""
                break
    if time.monotonic() >= deadline:
        os.kill(pid, 9)
        _, status = os.waitpid(pid, 0)
        return os.waitstatus_to_exitcode(status)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
