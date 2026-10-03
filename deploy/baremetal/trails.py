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
import re
import stat
import sys
import time

MAX_LINE = 64 * 1024                       # the collector's own bound on an event
ROTATE_BYTES = 16 * 1024 * 1024            # a trail file this long is archived and a new one begun
ARCHIVE = re.compile(r"\.([0-9]{20})")     # <trail>.<last seq>: an archived file of the trail
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
    fd = _open_locked(path)
    try:
        last, ended = _last_line(fd)
        if last and not ended:                     # torn by a crash: terminated, kept, chained over
            _write_whole(fd, b"\n")
            last += b"\n"
        previous = _sequence_of(last) if last else None
        seq = (previous or chained_count(fd, last)) + 1 if last else 1
        line = canonical(dict(event, at=event.get("at", int(now())), seq=seq, prev=hashlib.sha256(last).hexdigest() if last else "")) + b"\n"
        if len(line) > MAX_LINE:
            raise Refused("the event is %d bytes, more than a trail line may be" % len(line))
        if os.fstat(fd).st_size >= ROTATE_BYTES:
            _rotate(path, fd, seq - 1, line)
            return seq
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


def _open_locked(path):
    """The trail, open and locked. A writer that waited on the lock while another rotated the file holds
    the archive's inode: it sees `path` is no longer that file, and opens the new one."""
    while True:
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, MODE)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise Refused("%s is not a regular file of this user's: not written" % path)
            fcntl.flock(fd, fcntl.LOCK_EX)
            now = os.stat(path, follow_symlinks=False)
            if (now.st_dev, now.st_ino) == (info.st_dev, info.st_ino):
                _readable_by_its_shipper(fd, info, path)
                return fd
        except BaseException:
            os.close(fd)
            raise
        os.close(fd)


def _rotate(path, fd, last_seq, line):
    """Start a new file whose first line is `line`, chained onto the last line of the full one, which stays
    as the archive <path>.<last seq, 20 digits>. Under the caller's lock. In this order, so a cut anywhere
    leaves one chain:
      1  link the full file to its archive name (a cut here: two names for one file; segments() skips an
         archive that is the current file, and the next append finds the link made and goes on);
      2  write the new line to <path>.next and fsync it (a cut here: a stale .next, read by nobody,
         replaced by the next rotation; the event was not recorded, and append had not returned);
      3  rename it over <path>, and fsync the directory."""
    directory = os.path.dirname(os.path.abspath(path))
    archive = "%s.%020d" % (path, last_seq)
    try:
        os.link(path, archive, follow_symlinks=False)
    except FileExistsError:
        held, full = os.lstat(archive), os.fstat(fd)
        if (held.st_dev, held.st_ino) != (full.st_dev, full.st_ino):
            raise Refused("%s exists and is not this trail's full file: not rotated" % archive)
    _sync_directory(directory)
    following = path + ".next"
    try:
        stale = os.lstat(following)
    except FileNotFoundError:
        stale = None
    if stale is not None:
        if not stat.S_ISREG(stale.st_mode) or stale.st_uid != os.geteuid():
            raise Refused("%s is not a file this writer left: not rotated" % following)
        os.unlink(following)
    new = os.open(following, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, MODE)
    try:
        _readable_by_its_shipper(new, os.fstat(new), path)
        _write_whole(new, line)
        os.fsync(new)
    finally:
        os.close(new)
    os.rename(following, path)
    _sync_directory(directory)


def _sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
    return _verify_data(data, None, expected_head)


def _verify_data(data, marker, expected_head):
    """verify's check over `data`, which continues after the pruned line `marker` names (None: from the start)."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    else:
        lines[-1:] = [lines[-1]] if lines else []
    report = {"lines": 0, "chained": 0, "legacy": 0, "torn": 0, "head": ""}
    previous, expected, chained = "", 1, False             # previous: the SHA-256 of the line before, hex
    if marker:
        previous, expected, chained = marker["line_sha256"], marker["seq"] + 1, marker["seq"] > 0
    reached = expected_head is None or previous == expected_head
    for number, body in enumerate(lines, 1):
        if previous and previous == expected_head:
            reached = True
        raw = body + b"\n"
        report["lines"] += 1
        try:
            value = json.loads(body)
        except ValueError:
            report["torn"] += 1                    # kept, and chained over by the next line
            previous = hashlib.sha256(raw).hexdigest()
            continue
        if not isinstance(value, dict) or "seq" not in value:
            if chained:
                raise Refused("line %d has no seq after the chain began" % number)
            report["legacy"] += 1
            previous = hashlib.sha256(raw).hexdigest()
            continue
        chained = True
        if canonical(value) != body:
            raise Refused("line %d is not in canonical form: edited" % number)
        if value["seq"] != expected:
            raise Refused("line %d carries seq %r where %d was expected: a line deleted or reordered" % (number, value["seq"], expected))
        if value["prev"] != previous:
            raise Refused("line %d's prev is not the SHA-256 of the line before it: a line edited, deleted or reordered" % number)
        expected += 1
        report["chained"] += 1
        previous = hashlib.sha256(raw).hexdigest()
    report["head"] = previous
    if not reached and report["head"] != expected_head:
        raise Refused("the chain does not reach %s, a line known to have been written: the file was cut short or replaced" % expected_head)
    return report


def unanswered(path, **match):
    """The last REQUESTED event in the trail at `path` whose fields include `match`, if no later event answers
    it (an event whose "request" is its seq), or None. For the operator tools' request/outcome pairs: a run
    killed after its request (SIGKILL, the OOM killer, a power cut) leaves one, which the next run closes
    before it writes its own, so every request has exactly one outcome. A missing trail has none."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)             # append holds LOCK_EX: never a line half written, never a writer blocked long
        data = os.pread(fd, os.fstat(fd).st_size, 0)
    finally:
        os.close(fd)
    found, answered = None, set()
    lines = data.split(b"\n")
    lines.pop()                                    # what follows the last newline: "" or a line still being written, skipped
    for body in lines:
        try:
            value = json.loads(body)
        except ValueError:
            continue                                   # a torn line answers nothing
        if not isinstance(value, dict):
            continue
        if isinstance(value.get("request"), int):
            answered.add(value["request"])
        if value.get("outcome") == "REQUESTED" and all(value.get(k) == v for k, v in match.items()):
            found = value
    return found if found is not None and found.get("seq") not in answered else None


def segments(path):
    """A trail's files, oldest first: (marker, [archives], path). marker is the pruned point (prune), or
    None. An archive that is the current file is skipped (a rotation cut after its link), and so is
    one the marker covers (a prune cut before it removed it)."""
    directory, base = os.path.split(os.path.abspath(path))
    marker = _marker(path + ".pruned")
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        current = None
    archives = []
    for name in os.listdir(directory):
        match = ARCHIVE.fullmatch(name[len(base):]) if name.startswith(base) else None
        if not match:
            continue
        full = os.path.join(directory, name)
        info = os.lstat(full)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("%s is not a regular file" % full)
        if current is not None and (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino):
            continue
        last = int(match.group(1))
        if marker is not None and last <= marker["seq"]:
            continue
        archives.append((last, full))
    return marker, [full for _, full in sorted(archives)], path


def _marker(path):
    try:
        with open(path, "rb") as f:
            marker = json.loads(f.read(4096))
    except FileNotFoundError:
        return None
    except ValueError:
        raise Refused("%s is not a prune marker" % path)
    fields = {"seq": int, "sequence": int, "event_hash": str, "line_sha256": str, "timestamp": int, "line_chain": str}
    if not isinstance(marker, dict) or set(marker) != set(fields) or \
            not all(type(marker[k]) is t and (t is not int or marker[k] >= 0) for k, t in fields.items()) or \
            not re.fullmatch(r"[0-9a-f]{64}", marker["line_sha256"]) or not re.fullmatch(r"[0-9a-f]{64}", marker["line_chain"]) or \
            not re.fullmatch(r"sha256:[0-9a-f]{64}", marker["event_hash"]):
        raise Refused("%s is not a prune marker" % path)
    return marker


def _read_whole(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused("%s is not a regular file" % path)
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def verify_trail(path, expected_head=None):
    """verify over the whole trail: its archives in order, then the current file, as one chain, from the
    prune marker when there is one. An archive that does not end with a newline is refused: rotation only
    archives a whole file."""
    marker, archives, current = segments(path)
    parts = []
    for archive in archives:
        data = _read_whole(archive)
        if data and not data.endswith(b"\n"):
            raise Refused("%s does not end with a whole line: not an archive rotation made" % archive)
        parts.append(data)
    try:
        parts.append(_read_whole(current))
    except FileNotFoundError:
        pass
    return _verify_data(b"".join(parts), marker, expected_head)


RECEIPT_DOMAIN = "regalia.collector.receipt/v1"         # internal/audit/collector.go ReceiptPreimage
LINE_CHAIN_START = "00" * 32                            # internal/audit/collector.go LineChainStart


def line_chain(previous, line):
    """The collector's running digest of a stream's lines (internal/audit/collector.go LineChain), extended
    by one line's exact bytes, newline included."""
    return hashlib.sha256(bytes.fromhex(previous) + hashlib.sha256(line).digest()).hexdigest()
STREAM = re.compile(r"[A-Za-z0-9._-]{1,64}")


def receipt_keys(path):
    """The pinned set of the collector's receipt keys: one Ed25519 public key a line, 64 hex, '#' for
    comments. A set, so the collector's key can rotate: pin the new one beside the old, then drop the old."""
    keys = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                if not re.fullmatch(r"[0-9a-f]{64}", line):
                    raise Refused("%s: %r is not an Ed25519 public key in hex" % (path, line))
                keys.append(line)
    if not keys:
        raise Refused("%s pins no receipt key" % path)
    return keys


def client_identity(certificate_path):
    """The collector keys a stream by the SHA-256 of the client certificate's DER: this host's identity."""
    import ssl
    with open(certificate_path) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def _receipt_signed(receipt, keys, identity, stream):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    preimage = ("%s\n%s\n%s\n%d\n%s\n%s\n%s" % (RECEIPT_DOMAIN, identity, stream, receipt["sequence"], receipt["event_hash"],
                                                receipt["line_sha256"], receipt["line_chain"])).encode()
    try:
        signature = bytes.fromhex(receipt["signature"])
    except (TypeError, ValueError):
        return False
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(signature, preimage)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def prune(path, head_path, trail, site, identity, keys):
    """Remove the archives the collector holds, oldest first, and only those (#288). The shipper's head
    file (cmd/regalia-audit-ship -head) names, for each archive, the collector's SIGNED RECEIPT for its
    last line; nothing else in it is trusted but the line's time. An archive is removed only if:
      * the trail is the registry's `trail`, and the receipt is for this host's stream (`identity`, the
        SHA-256 of its client certificate, and <site>.<trail>), so another stream's receipt is useless;
      * the receipt verifies under one of `keys` (receipt_keys);
      * its position is the one counted here, from the marker through the archives' lines on disk;
      * its line hash is that of the archive's last line on disk, and its LINE CHAIN (the collector's
        running digest of every line it holds up to that one) is the one recomputed here over every line
        on disk from the marker: a receipt for one real line after placeholder ones (withheld lines with
        made-up hashes) carries a chain no trail on disk reproduces (regalia-kms-51).
    The collector checks every trail event's content against the line hash it names, so a receipt is
    for the line itself. A missing receipt leaves the archive (and every later one) waiting; a receipt
    that does not hold is refused, since only a forged head file makes one. The marker is written (and
    synced) first, so a cut leaves files the marker covers, which segments() skips and the next prune
    removes. Returns how many were removed."""
    registered = TRAILS.get(trail)
    if registered is None or os.path.basename(path) != os.path.basename(registered[0]):
        raise Refused("%s is not the %r trail of the registry" % (path, trail))
    stream = "%s.%s" % (site, trail)
    if not STREAM.fullmatch(stream) or not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise Refused("the stream %r or the identity is not one the collector keys" % stream)
    with open(head_path, "rb") as f:
        head = json.loads(f.read(1 << 20))
    named = {entry.get("name"): entry for entry in head.get("archives", []) if isinstance(entry, dict)} if isinstance(head, dict) else {}
    marker, archives, _ = segments(path)
    left = _left_behind(path, marker)                     # covered by the marker, left by a prune that was cut
    position = marker["sequence"] if marker else 0
    chain = marker["line_chain"] if marker else LINE_CHAIN_START
    covered = []
    for archive in archives:
        data = _read_whole(archive)
        position += data.count(b"\n")
        for line in data.splitlines(keepends=True):
            chain = line_chain(chain, line)
        entry = named.get(os.path.basename(archive))
        receipt = entry.get("receipt") if isinstance(entry, dict) else None
        if not isinstance(receipt, dict):
            break                                         # not yet held at the collector, or not yet receipted
        last = data[data.rstrip(b"\n").rfind(b"\n") + 1:]
        fields = (receipt.get("sequence"), receipt.get("event_hash"), receipt.get("line_sha256"), receipt.get("signature"),
                  receipt.get("line_chain"))
        if not data.endswith(b"\n") or not isinstance(fields[0], int) or not all(isinstance(v, str) for v in fields[1:]) or \
                not isinstance(entry.get("timestamp"), int) or fields[0] != position or \
                fields[2] != hashlib.sha256(last).hexdigest() or fields[4] != chain or not re.fullmatch(r"sha256:[0-9a-f]{64}", fields[1]) or \
                not _receipt_signed(receipt, keys, identity, stream):
            raise Refused("%s: its receipt does not hold (position %d, its last line, the chain of every line before it, the "
                          "stream %s, or the collector's signature): not pruned" % (archive, position, stream))
        covered.append((archive, {"seq": int(ARCHIVE.fullmatch(archive[len(path):]).group(1)), "sequence": position,
                                  "event_hash": fields[1], "line_sha256": fields[2], "timestamp": entry["timestamp"], "line_chain": chain}))
    for archive in left:
        os.unlink(archive)
    if not covered:
        if left:
            _sync_directory(os.path.dirname(os.path.abspath(path)))
        return len(left)
    new = covered[-1][1]
    staged = path + ".pruned.next"
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        _write_whole(fd, canonical(new))
        os.fsync(fd)
    finally:
        os.close(fd)
    _marker(staged)                                       # refuse to install a marker this module would not read
    os.rename(staged, path + ".pruned")
    _sync_directory(os.path.dirname(os.path.abspath(path)))
    for archive, _ in covered:
        os.unlink(archive)
    _sync_directory(os.path.dirname(os.path.abspath(path)))
    return len(left) + len(covered)


def _left_behind(path, marker):
    """Archives the marker already covers: a prune removed them from the trail, and was cut before it
    unlinked them. segments() skips them; prune finishes removing them."""
    if marker is None:
        return []
    directory, base = os.path.split(os.path.abspath(path))
    found = []
    for name in os.listdir(directory):
        match = ARCHIVE.fullmatch(name[len(base):]) if name.startswith(base) else None
        if match and int(match.group(1)) <= marker["seq"]:
            found.append(os.path.join(directory, name))
    return sorted(found)


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
            print(json.dumps(verify_trail(*argv[1:]), sort_keys=True))
            return 0
        except (Refused, OSError) as failure:
            print("BROKEN: %s" % failure, file=sys.stderr)
            return 1
    if len(argv) >= 2 and argv[0] == "unanswered":
        # unanswered <trail> [key=value ...]: the open request, as JSON, or nothing
        try:
            match = dict(item.split("=", 1) for item in argv[2:])
            found = unanswered(where(argv[1]), **match)
            if found is not None:
                print(json.dumps(found, sort_keys=True))
            return 0
        except (Refused, OSError, ValueError) as failure:
            print("REFUSED: %s" % failure, file=sys.stderr)
            return 1
    if len(argv) == 11 and argv[0] == "prune" and argv[3::2] == ["--trail", "--site", "--client-cert", "--receipt-keys"]:
        try:
            print(prune(argv[1], argv[2], argv[4], argv[6], client_identity(argv[8]), receipt_keys(argv[10])))
            return 0
        except (Refused, OSError, ValueError) as failure:
            print("REFUSED: %s" % failure, file=sys.stderr)
            return 1
    print("usage: trails.py append <trail> < event.json | verify <path> [<expected head>] | unanswered <trail> [key=value ...]"
          " | prune <path> <shipper head file> --trail <name> --site <site> --client-cert <pem> --receipt-keys <file>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
