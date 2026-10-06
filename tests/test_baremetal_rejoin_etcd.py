"""deploy/baremetal/rejoin.py against a real etcd (v3.6.15): a taken over alone (takeover.py), then b back as a learner,
promoted, a voting member holding the survivor's state epoch. systemctl and the daemon are played; etcdctl, etcdutl
and etcd are the real ones. On localhost, the members' peer URLs stand in for the mesh URLs (rejoin._url and
etcdconf.check's mesh rule are the scripted test's, tests/test_baremetal_rejoin.py).

Needs ETCD_BIN, ETCDCTL_BIN and ETCDUTL_BIN; skipped without them, failed without them under REGALIA_EXPECT_ETCD=1."""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.baremetal import etcdconf, opstate, rejoin as rj, takeover as tk
from tests.test_baremetal_rejoin import chain, config_for
from tests.test_baremetal_takeover import NOW, authorization, sign
from tests.test_baremetal_takeover_etcd import BINS, HAVE, RealEtcd


class Hosts(RealEtcd):
    """Each node's data directory where a host has it, under its own root/<node>/ (so the export's rename is real)."""

    def data_dir(self, n):
        return os.path.join(self.root, n, os.path.basename(etcdconf.DATA_DIR))


class NodeView:
    """Node `me`'s host: its etcd, its files, its data directory's parent; systemctl played on its own etcd."""

    def __init__(self, hosts, me, manifest):
        self.hosts, self.me = hosts, me
        self.files = {etcdconf.CONFIG_PATH: config_for(me, manifest)}
        self.daemon = True

    def path(self, p):
        return p.replace(os.path.dirname(etcdconf.DATA_DIR), os.path.join(self.hosts.root, self.me), 1)

    def read(self, p):
        return self.files[p]

    def write(self, p, text, owner=None, mode=0o644):
        if p.startswith(os.path.dirname(etcdconf.DATA_DIR)):
            with open(self.path(p), "w") as f:
                f.write(text)
        else:
            self.files[p] = text

    def exists(self, p):
        return os.path.lexists(self.path(p))

    def listdir(self, p):
        return os.listdir(self.path(p))

    def rename(self, src, dst):
        os.rename(self.path(src), self.path(dst))

    def sha256(self, p):
        import hashlib
        with open(self.path(p), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def sleep(self, seconds):
        import time
        time.sleep(min(seconds, 1))

    def run(self, argv, input=None):
        h, me = self.hosts, self.me
        if argv[0] == "systemctl" and argv[-1] == tk.DAEMON:
            if argv[1] != "is-active":
                self.daemon = argv[1] != "stop"
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0 if self.daemon else 3, "active\n" if self.daemon else "inactive\n", "")
        if argv[0] == "systemctl":
            if argv[1] == "stop":
                h.stop(me)
            elif argv[1] in ("start", "restart"):
                config = json.loads(self.files[etcdconf.CONFIG_PATH])
                h.stop(me)
                h.start(me, initial=config["initial-cluster"], state=config["initial-cluster-state"])
                h.wait(h.client[me], 90, write=False)
            elif argv[1] == "is-active":
                return subprocess.CompletedProcess(argv, 0 if me in h.procs else 3, "active\n" if me in h.procs else "inactive\n", "")
            elif argv[1] == "show":
                return subprocess.CompletedProcess(argv, 0, "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        real = {tk.ETCDCTL: BINS["ETCDCTL_BIN"], tk.ETCDUTL: BINS["ETCDUTL_BIN"]}[argv[0]]
        argv = [real] + [h.client[me] if a == tk.ENDPOINT else os.path.join(h.data_dir(me), "member", "snap", "db") if a == tk.BACKEND
                         else a for a in argv[1:]]
        return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(HAVE or os.environ.get("REGALIA_EXPECT_ETCD") == "1", "no etcd binaries (ETCD_BIN, ETCDCTL_BIN, ETCDUTL_BIN)")
class RejoinRealEtcd(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HAVE, "REGALIA_EXPECT_ETCD=1 and the etcd binaries are missing: %s" % BINS)
        self.root = tempfile.mkdtemp(prefix="rejoin-etcd-")       # TMPDIR: on the dev qube under ~/.cache, not the shared /tmp
        self.addCleanup(shutil.rmtree, self.root, True)
        self.hosts = Hosts(self.root)
        self.addCleanup(self.hosts.close)
        h = self.hosts
        for i in range(5):
            self.assertEqual(h.ctl(h.client["a"], "put", "/regalia/v1/k%d" % i, "v").returncode, 0)
        status = json.loads(h.ctl(h.client["a"], "endpoint", "status", "-w", "json").stdout)[0]["Status"]["header"]
        h.files[tk.APPLIED] = json.dumps({"boot_id": "x", "boottime_ns": 1, "cluster_id": "%016x" % status["cluster_id"],
                                          "revision": status["revision"], "state_epoch": 0})
        h.stop("b")
        h.stop("c")
        self.chain = chain()
        with contextlib.redirect_stdout(io.StringIO()):
            tk.run(h, authorization(self.chain[1]), self.chain[:2], "a", NOW, sign)    # a alone at state epoch 2
        self.assertEqual(h.ctl(h.client["b"], "endpoint", "status").returncode != 0, True)       # b is down

    def test_b_back_as_a_learner_then_a_voting_member_its_old_data_kept(self):
        h, a = self.hosts, self.hosts
        b = NodeView(h, "b", self.chain[-1])
        urls = {n: h.peer[n] for n in "abc"}
        with mock.patch.object(rj, "_url", lambda manifest, n: urls[n]), \
                mock.patch.object(rj.etcdconf, "check", json.loads), mock.patch.object(rj, "JOIN_PAUSE_S", 1), \
                contextlib.redirect_stdout(io.StringIO()) as said:
            line, member_id = rj.admit(a, self.chain, "a", "b")
            self.assertEqual(line, "a=%s,b=%s" % (urls["a"], urls["b"]))
            self.assertEqual(h.ctl(h.client["a"], "put", "/while-learner", "v").returncode, 0)   # quorum 1 still: a commits
            export = rj.join(b, self.chain, "b", line, member_id)
            rj.promote(a, self.chain, "a", "b")
            rj.finish(b, self.chain, "b")
        self.assertTrue(os.path.isdir(b.path(export)), said.getvalue())
        self.assertEqual(json.loads(open(b.path(rj.JOINED)).read()), {"epoch": 3, "member_id": member_id})
        record = json.loads(open(b.path(export) + ".json").read())
        self.assertEqual((record["node_id"], record["epoch"]), ("b", 3))
        members = json.loads(h.ctl(h.client["a"], "member", "list", "-w", "json").stdout)["members"]
        self.assertEqual(sorted((m["name"], bool(m.get("isLearner"))) for m in members), [("a", False), ("b", False)])
        got = json.loads(h.ctl(h.client["b"], "get", opstate.STATE_EPOCH_KEY, "--print-value-only").stdout)
        self.assertEqual(got["entry"]["state_epoch"], 2)
        self.assertEqual(h.ctl(h.client["b"], "get", "/while-learner", "--print-value-only").stdout.strip(), "v")
        self.assertTrue(b.daemon)
        self.assertEqual(h.ctl(h.client["a"], "put", "/both", "v").returncode, 0)


if __name__ == "__main__":
    unittest.main()
