#!/usr/bin/env python3
"""The audit trails of a KMS node and of the revocation authority, and how each line is written (#278).

ONE REGISTRY. TRAILS names every trail: where it is (fixed, or from the node's or authority's
configuration), who writes it, and its stream name at the collector. The units, the shipper and the tests
read it; nothing else lists trail files.

HOW A LINE IS WRITTEN (append): one JSON object a line, in canonical form (sorted keys, no spaces, ASCII),
with two fields of its own:
  seq   1, 2, 3, ... in the order the lines were written;
  prev  the SHA-256, hex, of the previous line's exact bytes (its newline included), "" for the first.
An edited, deleted or reordered line breaks the chain, and anyone can check it with a few lines of code
(verify). The Go shipper checks it before it sends anything, and ships each line to the collector inside
an audit.Event whose own chain the collector already verifies (#278).

  * The file is opened without following a link, and must be a regular file owned by the writer: a trail
    is never a symlink to somewhere else, nor someone else's file.
  * Writers are serialized by flock on the file itself, across processes and threads.
  * The line is fsynced before append returns. If it cannot be written (a full disk, a permission, an
    fsync error) append RAISES, and the operation it records is refused by its caller: an operation is
    never done unrecorded (as Vault refuses a request it cannot write to its local audit device). A
    collector that cannot be reached is a different matter: lines wait in the file, and only an alert
    says so.
  * A line torn by a crash (no newline at the end of the file) is terminated and kept, and the chain goes
    on over its bytes: refusing to append after it would refuse every operation for ever. verify reports
    it as torn, apart from a break.
  * A line is written whole or not at all: a short write cuts the file back and raises (_write_whole).
  * A chain cannot see its tail cut off; verify(expected_head=...) checks it against a hash kept elsewhere.
  * Who may read it: a trail is 0640, its group the one its shipper reads through
    (regalia-audit-ship@<trail>, a member of that group and nothing else, no capability). The registry
    names the group; the operator tools' directory is root:regalia-audit 2750, so their trails take it.
  * Lines written before the chain existed (no seq) may only come first; the first chained line's prev
    covers the last of them.

Run by path, from anywhere (it imports nothing but the standard library):

    python3 -Es /usr/lib/regalia-kms/deploy/baremetal/trails.py append recovery-key < event.json
    python3 -Es /usr/lib/regalia-kms/deploy/baremetal/trails.py verify /var/log/regalia/recovery-key.jsonl [<expected head>]

append takes the event, a JSON object, on standard input (nothing on argv, so nothing in ps), for the
operator tools' trails only (their path is fixed); exit 0 written, 1 refused (nothing written).
"""
import fcntl
import grp
import hashlib
import json
import os
import stat
import sys
import time

MAX_LINE = 64 * 1024                       # the collector's own bound on an event
TOOL_DIR = "/var/log/regalia"
TOOL_DIR_OWNER = 0                         # root: the operator tools run as root
TOOL_GROUP = "regalia-audit"               # the group that reads the operator tools' trails
MODE = 0o640                               # every trail: its writer writes, its shipper's group reads
OWN = ("seq", "prev")

# name: (where, writer, stream at the collector, the group its shipper reads it through).
# "state_dir", "admission_dir": the configuration's. The service trails take their writer's own group
# (the file's group is the writer's); the operator tools' take TOOL_GROUP from their directory.
TRAILS = {
    "sync": ("state_dir/sync-audit.jsonl", "regalia-sync.service (user regalia-sync), node", "sync", "regalia-sync"),
    "admission": ("admission_dir/audit.jsonl", "regalia-admission.service, node", "admission", "regalia-admission"),
    "enrol": (TOOL_DIR + "/enrol.jsonl", "regalia-node enrol, root, by hand, node", "enrol", TOOL_GROUP),
    "authority": ("state_dir/audit.jsonl", "regalia-authority.service (user regalia-authority)", "authority", "regalia-authority"),
    "reanchor": (TOOL_DIR + "/reanchor.jsonl", "reanchor.py, root, by hand", "reanchor", TOOL_GROUP),
    "recount": (TOOL_DIR + "/recount.jsonl", "recount.py, root, by hand", "recount", TOOL_GROUP),
    "recovery-key": (TOOL_DIR + "/recovery-key.jsonl", "recovery-key.sh, root, by hand", "recovery-key", TOOL_GROUP),
    "recovery-reconcile": (TOOL_DIR + "/recovery-reconcile.jsonl", "recovery-reconcile.py, root, by hand", "recovery-reconcile", TOOL_GROUP),
}


class Refused(Exception):
    """Nothing was written."""


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def where(name, cfg=None):
    """The path of trail `name`; a configuration supplies state_dir and admission_dir."""
    if name not in TRAILS:
        raise Refused("no trail is called %r" % (name,))
    path = TRAILS[name][0]
    if path.startswith("/"):
        return path
    base, _, rest = path.partition("/")
    if not cfg or base not in cfg:
        raise Refused("the trail %s is under the configuration's %s: give the configuration" % (name, base))
    return os.path.join(cfg[base], rest)


def _last_line(fd):
    """The file's last line, newline included, or b"" for an empty file; and whether it ended with one."""
    size = os.fstat(fd).st_size
    if size == 0:
        return b"", True
    step, data = 4096, b""
    position = size
    while position > 0:
        take = min(step, position)
        position -= take
        data = os.pread(fd, take, position) + data
        body = data[:-1] if data.endswith(b"\n") else data
        cut = body.rfind(b"\n")
        if cut >= 0:
            return data[cut + 1:], data.endswith(b"\n")
        if len(data) > 2 * MAX_LINE:
            break
    return data, data.endswith(b"\n")


def _sequence_of(line):
    try:
        value = json.loads(line)
    except ValueError:
        return None
    seq = value.get("seq") if isinstance(value, dict) else None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 1 else None


def _tool_group():
    try:
        return grp.getgrnam(TOOL_GROUP).gr_gid
    except KeyError:
        return None                        # not installed (a development machine): the directory stays 0700


def _tool_dir(directory):
    """The operator tools' directory, root:regalia-audit 2750: made here when absent, brought to that
    from 0700, and otherwise required to be exactly a real directory of root's that only its owner
    writes and only TOOL_GROUP reads, so the rule lives in one place."""
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    gid = _tool_group()
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != TOOL_DIR_OWNER:
        raise Refused("%s must be a directory of root's" % directory)
    if gid is not None and (info.st_gid, stat.S_IMODE(info.st_mode)) != (gid, 0o2750) and stat.S_IMODE(info.st_mode) == 0o700:
        os.chown(directory, -1, gid, follow_symlinks=False)
        os.chmod(directory, 0o2750, follow_symlinks=False)
        info = os.lstat(directory)
    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o700 and not (gid is not None and info.st_gid == gid and mode == 0o2750):
        raise Refused("%s must be root's, 0700 or %s 2750: no group or other can write" % (directory, TOOL_GROUP))


def append(path, event, now=time.time):
    """Append `event` (a dict) to the trail at `path`, chained. Returns its seq. Raises if it cannot."""
    if not isinstance(event, dict):
        raise Refused("an event is a JSON object")
    if any(k in event for k in OWN):
        raise Refused("an event may not carry %s: the trail sets them" % " or ".join(OWN))
    if os.path.dirname(os.path.abspath(path)) == TOOL_DIR:
        _tool_dir(TOOL_DIR)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, MODE)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise Refused("%s is not a regular file of this user's: not written" % path)
        fcntl.flock(fd, fcntl.LOCK_EX)
        _readable_by_its_shipper(fd, info, path)
        last, ended = _last_line(fd)
        if last and not ended:                     # torn by a crash: terminated, kept, chained over
            _write_whole(fd, b"\n")
            last += b"\n"
        previous = _sequence_of(last) if last else None
        seq = (previous or chained_count(fd, last)) + 1 if last else 1
        line = canonical(dict(event, at=event.get("at", int(now())), seq=seq, prev=hashlib.sha256(last).hexdigest() if last else "")) + b"\n"
        if len(line) > MAX_LINE:
            raise Refused("the event is %d bytes, more than a trail line may be" % len(line))
        _write_whole(fd, line)
        os.fsync(fd)
        return seq
    finally:
        os.close(fd)


def _readable_by_its_shipper(fd, info, path):
    """MODE on every append (a file made under a umask, or one written before this rule, is brought to it),
    and, under the operator tools' directory, TOOL_GROUP: a trail its shipper cannot read is never shipped."""
    if stat.S_IMODE(info.st_mode) != MODE:
        os.fchmod(fd, MODE)
    if os.path.dirname(os.path.abspath(path)) == TOOL_DIR:
        gid = _tool_group()
        if gid is not None and info.st_gid != gid:
            os.fchown(fd, -1, gid)


def _write_whole(fd, line):
    """Write `line` at the end, all of it or none of it: a short write (a disk filling mid-line) or a failed
    one cuts the file back to where it was, under the caller's lock, and raises. A partial line left
    behind would be read as torn and chained over, recording an operation that was refused."""
    size = os.fstat(fd).st_size
    try:
        written = os.write(fd, line)
        if written != len(line):
            raise OSError("a short write: %d of %d bytes" % (written, len(line)))
    except BaseException:
        os.ftruncate(fd, size)
        raise


def chained_count(fd, last):
    """The seq to continue from when the last line carries none (legacy lines, or a torn one): the number
    of chained lines before it, found by reading the file (rare: once, after an upgrade or a crash)."""
    count = 0
    for line in os.pread(fd, os.fstat(fd).st_size, 0).splitlines():
        seq = _sequence_of(line)
        if seq is not None:
            count = seq
    return count


def verify(path, expected_head=None):
    """Check a trail's chain. Returns {"lines", "chained", "legacy", "torn", "head"}; raises Refused at the
    first break (a line whose prev is not the previous line's SHA-256, a seq out of order, a line not in
    canonical form, a legacy line after a chained one).

    A chain cannot see its own tail cut off: a file truncated after line n verifies as a good file of n
    lines. Only a record kept elsewhere can: `expected_head` is the SHA-256 of a line known to have been
    written (the shipper's last acknowledged line, the collector's), and verify refuses unless the chain
    passes through it. "head" is the last line's hash; a final torn line is that line, and counted torn."""
    with open(path, "rb") as f:
        data = f.read()
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    else:
        lines[-1:] = [lines[-1]] if lines else []
    report = {"lines": 0, "chained": 0, "legacy": 0, "torn": 0, "head": ""}
    previous, expected, chained = b"", 1, False
    reached = expected_head is None
    for number, body in enumerate(lines, 1):
        if previous and hashlib.sha256(previous).hexdigest() == expected_head:
            reached = True
        raw = body + b"\n"
        report["lines"] += 1
        try:
            value = json.loads(body)
        except ValueError:
            report["torn"] += 1                    # kept, and chained over by the next line
            previous = raw
            continue
        if not isinstance(value, dict) or "seq" not in value:
            if chained:
                raise Refused("line %d has no seq after the chain began" % number)
            report["legacy"] += 1
            previous = raw
            continue
        chained = True
        if canonical(value) != body:
            raise Refused("line %d is not in canonical form: edited" % number)
        if value["seq"] != expected:
            raise Refused("line %d carries seq %r where %d was expected: a line deleted or reordered" % (number, value["seq"], expected))
        if value["prev"] != (hashlib.sha256(previous).hexdigest() if previous else ""):
            raise Refused("line %d's prev is not the SHA-256 of the line before it: a line edited, deleted or reordered" % number)
        expected += 1
        report["chained"] += 1
        previous = raw
    report["head"] = hashlib.sha256(previous).hexdigest() if previous else ""
    if not reached and report["head"] != expected_head:
        raise Refused("the chain does not reach %s, a line known to have been written: the file was cut short or replaced" % expected_head)
    return report


def main(argv):
    if len(argv) == 2 and argv[0] == "append":
        name = argv[1]
        try:
            path = where(name)
            event = json.loads(sys.stdin.buffer.read(MAX_LINE + 1))
            print(append(path, event))
            return 0
        except (Refused, OSError, ValueError) as failure:
            print("REFUSED: %s" % failure, file=sys.stderr)
            return 1
    if len(argv) in (2, 3) and argv[0] == "verify":
        try:
            print(json.dumps(verify(*argv[1:]), sort_keys=True))
            return 0
        except (Refused, OSError) as failure:
            print("BROKEN: %s" % failure, file=sys.stderr)
            return 1
    print("usage: trails.py append <trail> < event.json | verify <path> [<expected head>]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
