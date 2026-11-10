"""bounded.py SECONDS GRACE COMMAND [ARG...]: run COMMAND for at most SECONDS, then end its whole process group (#684).

`timeout -k` is not enough. GNU coreutils' timeout signals the command's process group, but uutils' timeout (the
default `timeout` on ubuntu-26.04, measured on #684) signals only the command itself. A token tool's forked child,
or a TERM-deaf command that forks, then outlives the bound, and holds the pipe open so the caller hangs anyway.

So COMMAND runs as the leader of a process group of its own, inside the caller's session. On expiry:

1. SIGTERM goes to the whole group.
2. The helper waits until the GROUP is empty, not just until the leader has exited, or until GRACE seconds pass.
   A leader that exits on SIGTERM can leave a child that ignores it.
3. If anything is still in the group, SIGKILL goes to the whole group.

Exit status, the same contract as timeout(1):
  124   the bound expired and SIGTERM was enough;
  137   the bound expired and SIGKILL was needed;
  else  COMMAND's own exit status (128+N if a signal N ended it).
A COMMAND that exits 124 or 137 by itself cannot be told apart by status alone. On expiry the helper also writes
"bounded: <command> timed out after N s" to stderr. A caller must treat 124 and 137 as "the call hung":
an ERROR, never a negative answer. Say a hung listing reads as "no token": that turns a hang into a silent pass.

If the helper itself receives SIGTERM, SIGINT or SIGHUP (a cancelled CI job, a Ctrl-C), it ends the group the
same way (TERM, then the grace, then KILL if needed), then exits 128+signal, as GNU timeout does.

Known limit: a descendant that leaves the group (setsid, or setpgid to another group) is out of reach of the
group signals. #698 names it. Nothing here tries to follow it.
"""
import os
import signal
import subprocess
import sys
import time

POLL = 0.05


class Signalled(Exception):
    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


def group_alive(pgid):
    """Whether any process (a zombie included) is still in process group PGID."""
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:                       # a member we may not signal still exists
        return True


def end_group(proc, grace):
    """SIGTERM the group, wait up to GRACE s for it to empty, then SIGKILL it. True if SIGKILL was needed."""
    pgid = proc.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        proc.poll()                               # reap the leader, so a dead leader does not count as a member
        if not group_alive(pgid):
            return False
        time.sleep(POLL)
    proc.poll()
    if not group_alive(pgid):
        return False
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return False
    proc.wait()
    return True


def main(argv):
    if len(argv) < 4:
        sys.stderr.write("usage: bounded.py SECONDS GRACE COMMAND [ARG...]\n")
        return 125
    try:
        seconds, grace = float(argv[1]), float(argv[2])
    except ValueError:
        sys.stderr.write("bounded: SECONDS and GRACE must be numbers\n")
        return 125
    if seconds <= 0 or grace <= 0:
        sys.stderr.write("bounded: SECONDS and GRACE must be > 0 (a zero grace never sends SIGKILL)\n")
        return 125
    command = argv[3:]

    def on_signal(signum, _frame):
        raise Signalled(signum)

    try:
        proc = subprocess.Popen(command, process_group=0)
    except OSError as e:
        sys.stderr.write("bounded: cannot run %s: %s\n" % (command[0], e))
        return 127 if isinstance(e, FileNotFoundError) else 126
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, on_signal)
    try:
        try:
            rc = proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            killed = end_group(proc, grace)
            sys.stderr.write("bounded: %s timed out after %g s%s\n" % (command[0], seconds,
                                                                        ", and needed SIGKILL" if killed else ""))
            return 137 if killed else 124
    except Signalled as s:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)    # a second cancel must not cut the cleanup short
        end_group(proc, grace)
        return 128 + s.signum
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
