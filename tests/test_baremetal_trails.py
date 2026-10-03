"""deploy/baremetal/trails.py: the registry, and hash-chained trail lines (#278)."""
import hashlib
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import node, trails

HERE = os.path.dirname(os.path.abspath(trails.__file__))


def _writer(path, n, start):
    for i in range(n):
        trails.append(path, {"event": "concurrent", "i": start + i})


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.path = os.path.join(self.d, "audit.jsonl")

    def lines(self):
        with open(self.path, "rb") as f:
            return f.read().split(b"\n")[:-1]

    def rewrite(self, lines):
        with open(self.path, "wb") as f:
            f.write(b"".join(line + b"\n" for line in lines))

    def refused(self, reason, fn, *args):
        with self.assertRaises(trails.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Chain(Case):
    def test_lines_are_chained_by_the_previous_line_s_bytes(self):
        for i in range(3):
            self.assertEqual(trails.append(self.path, {"event": "e", "i": i}), i + 1)
        lines = self.lines()
        self.assertEqual([json.loads(line)["seq"] for line in lines], [1, 2, 3])
        self.assertEqual(json.loads(lines[0])["prev"], "")
        for before, after in zip(lines, lines[1:]):
            self.assertEqual(json.loads(after)["prev"], hashlib.sha256(before + b"\n").hexdigest())
        report = trails.verify(self.path)
        self.assertEqual((report["chained"], report["head"]), (3, hashlib.sha256(lines[-1] + b"\n").hexdigest()))
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)                  # its shipper's group reads it

    def test_an_edited_deleted_or_reordered_line_breaks_the_chain(self):
        for i in range(4):
            trails.append(self.path, {"event": "e", "i": i})
        good = self.lines()
        edited = json.loads(good[1])
        edited["i"] = 99
        for label, lines, reason in (("edited", [good[0], trails.canonical(edited), good[2], good[3]], "prev is not"),
                                     ("deleted", [good[0], good[2], good[3]], "where 2 was expected"),
                                     ("reordered", [good[0], good[2], good[1], good[3]], "where 2 was expected"),
                                     ("respaced", [good[0], good[1].replace(b",", b", ", 1), good[2], good[3]], "canonical form")):
            with self.subTest(label):
                self.rewrite(lines)
                self.refused(reason, trails.verify, self.path)
        self.rewrite(good)
        self.assertEqual(trails.verify(self.path)["chained"], 4)

    def test_a_torn_line_is_kept_and_chained_over(self):
        trails.append(self.path, {"event": "a"})
        with open(self.path, "ab") as f:
            f.write(b'{"event":"cut sh')                                    # a crash mid-write: no newline
        self.assertEqual(trails.append(self.path, {"event": "b"}), 2)
        report = trails.verify(self.path)
        self.assertEqual((report["chained"], report["torn"]), (2, 1))
        self.assertEqual(json.loads(self.lines()[-1])["prev"], hashlib.sha256(b'{"event":"cut sh\n').hexdigest())

    def test_a_cut_tail_is_seen_only_against_an_expected_head(self):
        """#278 (regalia-kms-24): a file cut after line n is a good chain of n lines; the head the shipper
        (or collector) last acknowledged is what tells. The chain must pass through it, or end on it."""
        for i in range(4):
            trails.append(self.path, {"event": "e", "i": i})
        good = self.lines()
        heads = [hashlib.sha256(line + b"\n").hexdigest() for line in good]
        for head in heads:
            self.assertEqual(trails.verify(self.path, expected_head=head)["chained"], 4)
        self.rewrite(good[:2])
        self.assertEqual(trails.verify(self.path)["chained"], 2)                        # unseen without one
        self.assertEqual(trails.verify(self.path, expected_head=heads[1])["head"], heads[1])
        self.refused("does not reach", trails.verify, self.path, heads[3])
        self.refused("does not reach", trails.verify, self.path, "0" * 64)
        with open(self.path, "ab") as f:
            f.write(b'{"event":"cut')                                                     # a final torn line
        report = trails.verify(self.path, expected_head=heads[1])
        self.assertEqual((report["torn"], report["head"]), (1, hashlib.sha256(b'{"event":"cut\n').hexdigest()))

    def test_legacy_lines_may_only_come_first(self):
        with open(self.path, "wb") as f:
            f.write(b'{"at":1,"event":"before the chain"}\n')
        trails.append(self.path, {"event": "first chained"})
        self.assertEqual((trails.verify(self.path)["legacy"], trails.verify(self.path)["chained"]), (1, 1))
        with open(self.path, "ab") as f:
            f.write(b'{"at":2,"event":"unchained after"}\n')
        self.refused("no seq after the chain began", trails.verify, self.path)


class Writer(Case):
    def test_a_link_or_another_user_s_file_is_never_written(self):
        target = os.path.join(self.d, "elsewhere")
        os.symlink(target, self.path)
        with self.assertRaises(OSError):
            trails.append(self.path, {"event": "e"})
        self.assertFalse(os.path.exists(target))
        os.unlink(self.path)
        open(self.path, "w").close()
        with unittest.mock.patch.object(trails.os, "geteuid", return_value=os.getuid() + 1):
            self.refused("not a regular file of this user's", trails.append, self.path, {"event": "e"})

    def test_the_trail_s_own_fields_and_size(self):
        self.refused("may not carry", trails.append, self.path, {"event": "e", "seq": 7})
        self.refused("may not carry", trails.append, self.path, {"event": "e", "prev": ""})
        self.refused("more than a trail line may be", trails.append, self.path, {"event": "x" * trails.MAX_LINE})
        self.refused("JSON object", trails.append, self.path, ["not", "an", "object"])

    def test_a_short_or_failed_write_leaves_the_file_as_it_was_and_raises(self):
        """#278 (regalia-kms-24): a disk filling mid-line must not leave half a line, which the next append
        would chain over as torn, recording an operation that was refused."""
        trails.append(self.path, {"event": "a"})
        with open(self.path, "rb") as f:
            before = f.read()
        real = os.write
        for label, fake in (("short", lambda fd, data: real(fd, data[:len(data) // 2])),
                            ("ENOSPC", unittest.mock.Mock(side_effect=OSError(28, "No space left on device")))):
            with self.subTest(label):
                with unittest.mock.patch.object(trails.os, "write", fake):
                    with self.assertRaises(OSError):
                        trails.append(self.path, {"event": "refused"})
                with open(self.path, "rb") as f:
                    self.assertEqual(f.read(), before)
        self.assertEqual(trails.append(self.path, {"event": "b"}), 2)
        self.assertEqual((trails.verify(self.path)["chained"], trails.verify(self.path)["torn"]), (2, 0))

    def test_concurrent_writers_never_share_a_seq(self):
        processes = [multiprocessing.Process(target=_writer, args=(self.path, 25, 100 * k)) for k in range(4)]
        for p in processes:
            p.start()
        for p in processes:
            p.join(60)
        report = trails.verify(self.path)
        self.assertEqual(report["chained"], 100)

    def test_a_failure_to_write_raises_and_the_node_trail_raises_with_it(self):
        """#278 (decided by regalia-kms-24): a trail that cannot be written refuses the operation it records."""
        os.mkdir(self.path)                                                   # a directory where the file goes
        with self.assertRaises(OSError):
            trails.append(self.path, {"event": "e"})
        with self.assertRaises(OSError):
            node.Trail(self.path)({"event": "sync-pull", "outcome": "ALLOW"})


class ToolDirectory(Case):
    def test_the_tools_directory_is_made_and_must_be_root_s_and_private(self):
        """#278 (regalia-kms-3e): append makes /var/log/regalia when absent, 0700, then requires a real
        directory of root's with no group or other write: the rule in one place, not in every tool."""
        tool_dir = os.path.join(self.d, "regalia")
        absent = unittest.mock.patch.object(trails, "TOOL_GROUP", "no-such-group-for-this-test")
        with unittest.mock.patch.object(trails, "TOOL_DIR", tool_dir), unittest.mock.patch.object(trails, "TOOL_DIR_OWNER", os.getuid()), absent:
            trails.append(os.path.join(tool_dir, "recount.jsonl"), {"event": "e"})
            self.assertEqual(os.stat(tool_dir).st_mode & 0o7777, 0o700)           # no regalia-audit group: private
            os.chmod(tool_dir, 0o770)
            self.refused("no group or other can write", trails.append, os.path.join(tool_dir, "recount.jsonl"), {"event": "e"})
            os.chmod(tool_dir, 0o700)
        with unittest.mock.patch.object(trails, "TOOL_DIR", tool_dir), absent:  # owned by this user, not root
            self.refused("a directory of root's", trails.append, os.path.join(tool_dir, "recount.jsonl"), {"event": "e"})
        link = os.path.join(self.d, "linked")
        os.symlink(tool_dir, link)
        with unittest.mock.patch.object(trails, "TOOL_DIR", link), unittest.mock.patch.object(trails, "TOOL_DIR_OWNER", os.getuid()), absent:
            self.refused("a directory of root's", trails.append, os.path.join(link, "recount.jsonl"), {"event": "e"})

    def test_with_the_audit_group_the_directory_is_2750_and_the_trails_take_the_group(self):
        """#283 (regalia-kms-24): the shipper reads the operator tools' trails through regalia-audit and no
        capability. A 0700 directory is brought to root:regalia-audit 2750, each trail to 0640 in that
        group; a group-writable one is still refused. (The test user's own group stands in for it.)"""
        import grp
        tool_dir = os.path.join(self.d, "regalia")
        os.mkdir(tool_dir, 0o700)
        group = grp.getgrgid(os.getgid()).gr_name
        trail = os.path.join(tool_dir, "recount.jsonl")
        with unittest.mock.patch.object(trails, "TOOL_DIR", tool_dir), unittest.mock.patch.object(trails, "TOOL_DIR_OWNER", os.getuid()), \
                unittest.mock.patch.object(trails, "TOOL_GROUP", group):
            trails.append(trail, {"event": "e"})
            info = os.stat(tool_dir)
            self.assertEqual((info.st_mode & 0o7777, info.st_gid), (0o2750, os.getgid()))
            self.assertEqual((os.stat(trail).st_mode & 0o777, os.stat(trail).st_gid), (0o640, os.getgid()))
            os.chmod(tool_dir, 0o2770)
            self.refused("no group or other can write", trails.append, trail, {"event": "e"})

    def test_a_trail_of_another_mode_is_brought_to_0640(self):
        with open(self.path, "w"):
            pass
        os.chmod(self.path, 0o600)                                                 # made under a umask, or before the rule
        trails.append(self.path, {"event": "e"})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)


class Registry(Case):
    def test_every_trail_is_named_once_with_where_it_is(self):
        self.assertEqual(trails.where("enrol"), "/var/log/regalia/enrol.jsonl")
        self.assertEqual(trails.where("sync", {"state_dir": "/var/lib/regalia-sync"}), "/var/lib/regalia-sync/sync-audit.jsonl")
        self.assertEqual(trails.where("admission", {"admission_dir": "/var/lib/regalia-admission"}), "/var/lib/regalia-admission/audit.jsonl")
        self.refused("give the configuration", trails.where, "sync")
        self.refused("no trail is called", trails.where, "nope")
        streams = [stream for _, _, stream, _ in trails.TRAILS.values()]
        self.assertEqual(len(streams), len(set(streams)))
        for name in ("enrol", "reanchor", "recount", "recovery-key", "recovery-reconcile"):
            self.assertEqual(trails.where(name), "/var/log/regalia/%s.jsonl" % name)

    def test_the_node_s_trails_are_where_the_services_write_them(self):
        import inspect
        source = inspect.getsource(node)
        self.assertIn('node.held("audit.jsonl")', source)                    # admission's, in admission_dir
        self.assertIn('node.path("sync-audit.jsonl")', source)               # sync's, in state_dir


class PinnedVector(Case):
    def test_the_pinned_trail_is_one_trails_py_accepts_line_for_line(self):
        """#283 (regalia-kms-24): tests/vectors/trail-events-v2.json pins a trail to the events the Go
        shipper maps it to (internal/audit/trail.go's TestTheTrailMappingIsPinned). Its lines are ones
        this writer makes and this verify accepts, with the line hashes the events carry."""
        with open(os.path.join(HERE, "..", "..", "tests", "vectors", "trail-events-v2.json")) as f:
            vector = json.load(f)
        self.assertEqual(vector["format"], "regalia.trail/v2")
        data = "".join(line + "\n" for line in vector["lines"]).encode()
        with open(self.path, "wb") as f:
            f.write(data)
        report = trails.verify(self.path)
        self.assertEqual((report["chained"], report["legacy"], report["torn"]), (5, 2, 1))
        self.assertEqual([hashlib.sha256(line.encode() + b"\n").hexdigest() for line in vector["lines"]], vector["line_sha256"])
        self.assertEqual(len(vector["event_hashes"]), len(vector["lines"]))


class ByPath(Case):
    def test_it_runs_by_path_from_anywhere_with_the_event_on_stdin(self):
        trails.append(self.path, {"event": "e"})
        script = os.path.join(HERE, "trails.py")
        done = subprocess.run([sys.executable, "-Es", script, "verify", self.path], cwd="/", capture_output=True, timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["chained"], 1)
        with unittest.mock.patch.dict(trails.TRAILS, {"recount": (self.path, "test", "recount", "regalia-audit")}), \
                unittest.mock.patch.object(trails.sys, "stdin", unittest.mock.Mock(buffer=unittest.mock.Mock(read=lambda n: b'{"event":"recount-requested"}'))), \
                unittest.mock.patch("sys.stdout"):
            self.assertEqual(trails.main(["append", "recount"]), 0)
        self.assertEqual(trails.verify(self.path)["chained"], 2)


if __name__ == "__main__":
    unittest.main()


class Unanswered(unittest.TestCase):
    """trails.unanswered (#281, d9): the open request a killed run left, for the next run to close."""

    def test_the_last_request_with_no_outcome_naming_it(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.jsonl")
            self.assertIsNone(trails.unanswered(path, device="/dev/a"))                       # no trail, none
            first = trails.append(path, {"outcome": "REQUESTED", "device": "/dev/a"})
            trails.append(path, {"outcome": "ALLOW", "device": "/dev/a", "request": first})
            self.assertIsNone(trails.unanswered(path, device="/dev/a"))                       # answered
            other = trails.append(path, {"outcome": "REQUESTED", "device": "/dev/b"})
            killed = trails.append(path, {"outcome": "REQUESTED", "device": "/dev/a"})
            self.assertEqual(trails.unanswered(path, device="/dev/a")["seq"], killed)
            self.assertEqual(trails.unanswered(path, device="/dev/b")["seq"], other)
            self.assertIsNone(trails.unanswered(path, device="/dev/c"))
            with open(path, "ab") as f:
                f.write(b'{"torn')                                                           # a torn line answers nothing
            self.assertEqual(trails.unanswered(path, device="/dev/a")["seq"], killed)
            # a final line with no newline is skipped even when it parses: it may still be being written
            with open(path, "rb") as f:
                kept = f.read()
            with open(path, "wb") as f:
                f.write(kept[:-len(b'{"torn')] + json.dumps({"outcome": "ALLOW", "device": "/dev/a", "request": killed}).encode())
            self.assertEqual(trails.unanswered(path, device="/dev/a")["seq"], killed)
            with open(path, "wb") as f:
                f.write(kept[:-len(b'{"torn')])
            trails.append(path, {"outcome": "INCOMPLETE", "device": "/dev/a", "request": killed})
            self.assertIsNone(trails.unanswered(path, device="/dev/a"))
            trails.verify(path)


def _killed_at(path, step, start):
    """Child: append until a rotation, and die (os._exit, no cleanup) at `step` inside it."""
    real = {"link": trails.os.link, "rename": trails.os.rename, "sync": trails._sync_directory}
    calls = {"sync": 0}

    def die():
        os._exit(9)
    if step == "before-link":
        trails.os.link = lambda *a, **k: die()
    elif step == "after-link":
        trails._sync_directory = lambda d: die()
    elif step == "before-rename":
        trails.os.rename = lambda *a, **k: die()
    elif step == "after-rename":
        def sync(directory):
            calls["sync"] += 1
            real["sync"](directory)
            if calls["sync"] == 2:
                die()
        trails._sync_directory = sync
    for i in range(1000):
        trails.append(path, {"event": "e", "i": start + i})
    os._exit(0)                                                             # never rotated: the test fails


def _rotating_writer(path, n, start):
    for i in range(n):
        trails.append(path, {"event": "concurrent", "i": start + i})


class Rotation(Case):
    def setUp(self):
        super().setUp()
        patcher = unittest.mock.patch.object(trails, "ROTATE_BYTES", 400)
        patcher.start()
        self.addCleanup(patcher.stop)

    def archives(self):
        return sorted(name for name in os.listdir(self.d) if trails.ARCHIVE.fullmatch(name[len("audit.jsonl"):] or "x"))

    def test_a_full_file_is_archived_and_the_chain_goes_on_in_the_new_one(self):
        for i in range(12):
            self.assertEqual(trails.append(self.path, {"event": "e", "i": i}), i + 1)
        archives = self.archives()
        self.assertGreaterEqual(len(archives), 2)
        report = trails.verify_trail(self.path)
        self.assertEqual((report["chained"], report["lines"]), (12, 12))
        for name in archives:
            full = os.path.join(self.d, name)
            last = json.loads(open(full, "rb").read().splitlines()[-1])
            self.assertEqual(last["seq"], int(name.rsplit(".", 1)[1]))           # named by its last seq
            self.assertEqual(os.stat(full).st_mode & 0o777, 0o640)
        first = json.loads(open(self.path, "rb").readline())
        self.assertEqual(first["seq"], int(archives[-1].rsplit(".", 1)[1]) + 1)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o640)
        with self.assertRaises(trails.Refused):                                     # the current file alone does not start the chain
            trails.verify(self.path)

    def test_a_process_killed_anywhere_in_a_rotation_leaves_one_chain(self):
        """#278 (regalia-kms-24): killed at each step of a rotation (no cleanup, as a power cut would leave
        it): the archive and the current file verify as one chain, and the next append finishes the
        rotation without losing or repeating a line."""
        for step in ("before-link", "after-link", "before-rename", "after-rename"):
            with self.subTest(step):
                for name in os.listdir(self.d):
                    os.unlink(os.path.join(self.d, name))
                child = multiprocessing.Process(target=_killed_at, args=(self.path, step, 0))
                child.start()
                child.join(60)
                self.assertEqual(child.exitcode, 9, "the child did not reach a rotation")
                before = trails.verify_trail(self.path)["chained"]
                seq = trails.append(self.path, {"event": "after the cut"})
                report = trails.verify_trail(self.path)
                self.assertEqual((seq, report["chained"]), (before + 1, before + 1))
                for i in range(6):
                    trails.append(self.path, {"event": "on", "i": i})
                self.assertEqual(trails.verify_trail(self.path)["chained"], before + 7)
                self.assertFalse(os.path.exists(self.path + ".next") and step != "before-rename")

    def test_writers_waiting_on_a_rotated_file_reopen_the_new_one(self):
        processes = [multiprocessing.Process(target=_rotating_writer, args=(self.path, 25, 100 * k)) for k in range(4)]
        for p in processes:
            p.start()
        for p in processes:
            p.join(120)
        report = trails.verify_trail(self.path)
        self.assertEqual(report["chained"], 100)
        self.assertGreater(len(self.archives()), 3)

    IDENTITY, SITE, TRAIL = "ab" * 32, "sitea", "authority"                         # authority's trail is audit.jsonl

    def keys(self, *names):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as _s
        if not hasattr(self, "_keys"):
            self._keys = {}
        for name in names:
            self._keys.setdefault(name, Ed25519PrivateKey.generate())
        return [self._keys[n].public_key().public_bytes(_s.Encoding.Raw, _s.PublicFormat.Raw).hex() for n in names]

    def chain_through(self, sequence):
        """The collector's running digest of this trail's lines, 1 to sequence, read from the files on disk
        as they were before any prune (the test holds them all)."""
        chain = trails.LINE_CHAIN_START
        lines = b"".join(open(os.path.join(self.d, n), "rb").read() for n in self.archives()).splitlines(keepends=True)
        for line in lines[:sequence]:
            chain = trails.line_chain(chain, line)
        return chain

    def receipt(self, sequence, line_sha256, key="old", stream=None, chain=None):
        """What the collector signs (internal/audit/collector.go ReceiptPreimage)."""
        self.keys(key)
        event_hash = "sha256:" + hashlib.sha256(b"event %d" % sequence).hexdigest()
        chain = chain or self.chain_through(sequence)
        preimage = "%s\n%s\n%s\n%d\n%s\n%s\n%s" % (trails.RECEIPT_DOMAIN, self.IDENTITY, stream or "%s.%s" % (self.SITE, self.TRAIL),
                                                    sequence, event_hash, line_sha256, chain)
        return {"sequence": sequence, "event_hash": event_hash, "line_sha256": line_sha256, "line_chain": chain,
                "signature": self._keys[key].sign(preimage.encode()).hex()}

    def head(self, committed, upto=None, key="old", bend=None):
        """The shipper's head file after a pass: each archive wholly behind the committed line, with the
        collector's receipt for its last line. `bend(i, receipt)` alters one, for the refusals."""
        entries, sequence = [], 0
        for i, name in enumerate(self.archives()):
            data = open(os.path.join(self.d, name), "rb").read()
            sequence += data.count(b"\n")
            if sequence > committed:
                break
            last = data.splitlines(keepends=True)[-1]
            receipt = self.receipt(sequence, hashlib.sha256(last).hexdigest(), key=key if isinstance(key, str) else key[i])
            if bend:
                receipt = bend(i, receipt)
            entries.append({"name": name, "seq": int(name.rsplit(".", 1)[1]), "timestamp": 1790000000 + sequence, "receipt": receipt,
                            "sequence": sequence})
        entries = entries[:upto]
        path = os.path.join(self.d, "head.json")
        with open(path, "w") as f:
            json.dump({"trail": self.TRAIL, "committed": committed, "archives": entries}, f)
        return path, entries

    def placeholder_chain(self, sequence, last_line_sha256):
        chain = trails.LINE_CHAIN_START
        for k in range(1, sequence):
            chain = hashlib.sha256(bytes.fromhex(chain) + hashlib.sha256(b"placeholder %d" % k).digest()).hexdigest()
        return hashlib.sha256(bytes.fromhex(chain) + bytes.fromhex(last_line_sha256)).hexdigest()

    def prune(self, head, keys=("old",)):
        return trails.prune(self.path, head, self.TRAIL, self.SITE, self.IDENTITY, self.keys(*keys))

    def test_prune_removes_only_what_the_collector_signed_for_and_the_chain_still_verifies(self):
        for i in range(20):
            trails.append(self.path, {"event": "e", "i": i})
        archives = self.archives()
        self.assertGreaterEqual(len(archives), 3)
        second = sum(open(os.path.join(self.d, n), "rb").read().count(b"\n") for n in archives[:2])
        head, entries = self.head(second)                                           # receipts for the first two archives
        self.assertEqual(self.prune(head), 2)
        self.assertEqual(self.archives(), archives[2:])
        marker = json.load(open(self.path + ".pruned"))
        self.assertEqual((marker["seq"], marker["sequence"], marker["event_hash"]), (entries[-1]["seq"], second, entries[-1]["receipt"]["event_hash"]))
        self.assertEqual(trails.verify_trail(self.path)["chained"], 20 - entries[-1]["seq"])
        self.assertEqual(self.prune(head), 0)                                       # nothing more is receipted
        os.unlink(head)

    def test_a_receipt_that_does_not_hold_prunes_nothing(self):
        """#288 (regalia-kms-51, decided by regalia-kms-24): a compromised shipper's head file cannot remove
        a line the collector does not hold. Each way a receipt can fail to hold refuses, and nothing goes."""
        for i in range(12):
            trails.append(self.path, {"event": "e", "i": i})
        before = self.archives()
        bends = {
            "another line": lambda i, r: dict(r, line_sha256="0" * 64),
            "another position": lambda i, r: self.receipt(r["sequence"] + 1, r["line_sha256"]),
            "another stream": lambda i, r: self.receipt(r["sequence"], r["line_sha256"], stream="sitea.sync"),
            "an unpinned key": lambda i, r: self.receipt(r["sequence"], r["line_sha256"], key="stranger"),
            "a forged signature": lambda i, r: dict(r, signature="00" * 64),
            "a claimed line count": lambda i, r: dict(self.receipt(r["sequence"] + 50, r["line_sha256"]), sequence=r["sequence"] + 50),
            # regalia-kms-51: placeholder (withheld) lines with made-up hashes, then the archive's real last
            # line. The collector holds the right last line at the right position, and signs, but its chain
            # runs over the placeholders: no line before it ever reached the collector.
            "placeholders before the real last line": lambda i, r: self.receipt(
                r["sequence"], r["line_sha256"], chain=self.placeholder_chain(r["sequence"], r["line_sha256"])),
        }
        for label, bend in bends.items():
            with self.subTest(label):
                head, _ = self.head(10 ** 6, bend=lambda i, r: bend(i, r) if i == 0 else r)
                self.refused("does not hold", self.prune, head)
                self.assertEqual(self.archives(), before)
                self.assertFalse(os.path.exists(self.path + ".pruned"))
        os.unlink(head)

    def test_the_receipt_key_can_rotate_with_an_overlap(self):
        """#288 (regalia-kms-24): the pinned keys are a set. With old and new pinned, receipts by either
        hold; once the old is dropped, a receipt it signed is refused."""
        for i in range(16):
            trails.append(self.path, {"event": "e", "i": i})
        archives = self.archives()
        lines = [open(os.path.join(self.d, n), "rb").read().count(b"\n") for n in archives]
        head, _ = self.head(lines[0] + lines[1], key=["old", "new", "new"])          # the collector switched keys between them
        self.refused("does not hold", self.prune, head, ("new",))                    # old dropped too early: refused
        self.assertEqual(self.prune(head, ("old", "new")), 2)                        # the overlap
        os.unlink(head)

    def test_prune_runs_from_the_command_line_with_a_real_certificate(self):
        """The unit's own command: the identity is the SHA-256 of the client certificate's DER."""
        import datetime
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization as _s
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.x509.oid import NameOID
        key = _ec.generate_private_key(_ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shipper")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1) \
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256())
        pem = certificate.public_bytes(_s.Encoding.PEM)
        with open(self.d + "/client.crt", "wb") as f:
            f.write(pem)
        self.IDENTITY = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode())).hexdigest()
        self.assertEqual(trails.client_identity(self.d + "/client.crt"), self.IDENTITY)
        with open(self.d + "/receipt.pub", "w") as f:
            f.write("# the collector's receipt keys\n%s\n" % self.keys("old")[0])
        for i in range(12):
            trails.append(self.path, {"event": "e", "i": i})
        first = open(os.path.join(self.d, self.archives()[0]), "rb").read().count(b"\n")
        head, _ = self.head(first)
        argv = ["prune", self.path, head, "--trail", self.TRAIL, "--site", self.SITE, "--client-cert", self.d + "/client.crt",
                "--receipt-keys", self.d + "/receipt.pub"]
        with unittest.mock.patch("sys.stdout") as out:
            self.assertEqual(trails.main(argv), 0)
        self.assertEqual(out.write.call_args_list[0][0][0], "1")
        self.assertEqual(trails.main(argv[:-1] + [self.d + "/empty.pub"]), 1)        # no pinned key file: refused
        os.unlink(head)

    def test_a_prune_cut_after_its_marker_leaves_a_trail_that_still_verifies(self):
        for i in range(16):
            trails.append(self.path, {"event": "e", "i": i})
        archives = self.archives()
        first = open(os.path.join(self.d, archives[0]), "rb").read().count(b"\n")
        head, entries = self.head(first)
        with unittest.mock.patch.object(trails.os, "unlink", side_effect=OSError("cut")):
            with self.assertRaises(OSError):
                self.prune(head)
        self.assertEqual(self.archives(), archives)                                # the marker is in, the archive too
        marker, remaining, _ = trails.segments(self.path)
        self.assertEqual((marker["seq"], [os.path.basename(r) for r in remaining]), (entries[0]["seq"], archives[1:]))
        self.assertEqual(trails.verify_trail(self.path)["chained"], 16 - entries[0]["seq"])
        self.assertEqual(self.prune(head), 1)                                      # the one the cut left is removed now
        self.assertEqual(self.archives(), archives[1:])
        self.assertEqual(trails.verify_trail(self.path)["chained"], 16 - entries[0]["seq"])
        os.unlink(head)
