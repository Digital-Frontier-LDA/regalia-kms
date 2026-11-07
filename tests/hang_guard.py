"""Run a shell snippet that may hang, and leave nothing running when it does (#682).

The snippet runs in a session of its own. On a hang, killing that session's leader group is not enough:
timeout(1) moves itself into a process group of its own, and the command it runs (and anything that command
forks) sits in that group, so a killpg of the leader's group misses all of it, and the leftovers keep the
pipes open. The cleanup kills EVERY process group with a member in the session instead, found from /proc,
so it needs no help from the processes it kills.
"""
import os
import signal
import subprocess
import time
import unittest
from pathlib import Path

HAVE_PROC = Path("/proc/self/stat").exists()

# A stand-in for a token tool stuck in a driver call: it ignores SIGTERM, and forks a child that ignores it
# too, so a cleanup that reaches only one process, or only one process group, leaves the other running.
DEAF_TO_TERM = ("import os, signal, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "os.fork()\n"
                "time.sleep(600)\n")


def session_members(sid):
    """[(pid, pgid)] of every live process in session SID (Linux /proc)."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # The command name may hold spaces or ")": the fields after the LAST ")" are state, ppid, pgrp, session.
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except (OSError, IndexError):
            continue
        if fields[0] != "Z" and int(fields[3]) == sid:
            found.append((int(entry.name), int(fields[2])))
    return found


def kill_session(sid):
    """SIGKILL every process group that has a member in session SID; repeat until none is left (at most 2 s).

    SID is always a session run_bounded made for the command alone (start_new_session), never the caller's: the test
    runner, and whatever runs it, are in another session, and this refuses outright to sweep the caller's own."""
    if sid == os.getsid(0):
        raise ValueError(f"refusing to sweep session {sid}: it is the caller's own, and would kill the test runner")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        groups = {pgid for _, pgid in session_members(sid)}
        if not groups:
            return
        for pgid in groups:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.05)


class Result:
    def __init__(self, stdout, seconds, hung, leftovers):
        self.stdout, self.seconds, self.hung, self.leftovers = stdout, seconds, hung, leftovers


def run_bounded(script, *args, limit=30, env=None):
    """Run `bash -c SCRIPT bash ARGS…` for at most LIMIT s. Whatever it left in its session afterwards, hung or
    not, is killed, and what was still alive just before that is reported in .leftovers (a test asserts it empty)."""
    if not HAVE_PROC:
        raise unittest.SkipTest("needs /proc to find a hung command's process groups")
    proc = subprocess.Popen(["bash", "-c", script, "bash", *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True, env=env)
    # The sweep below is scoped to this session: it must be the command's own, led by it, or nothing is found.
    if not os.getsid(proc.pid) == proc.pid != os.getsid(0):
        proc.kill(); proc.communicate()      # reaped before failing: a live leftover would print over the result line
        raise AssertionError("the command does not lead a session of its own")
    t0, hung = time.monotonic(), False
    try:
        stdout, _ = proc.communicate(timeout=limit)
    except subprocess.TimeoutExpired:
        hung = True
        kill_session(proc.pid)
        try:
            stdout, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout = ""          # something the cleanup missed still holds the pipe: reported below, not raised
    seconds = time.monotonic() - t0
    leftovers = session_members(proc.pid)
    kill_session(proc.pid)
    if proc.poll() is None:
        proc.kill()
    proc.stdout.close()
    proc.wait(timeout=10)
    return Result(stdout, seconds, hung, leftovers)
