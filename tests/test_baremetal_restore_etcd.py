"""deploy/baremetal/restore.py against a real etcd (v3.6.15, as CI installs it): a single-node member, a snapshot saved, the
history after it written, then the restore. Only systemctl and chown are played here (systemctl starts and stops the
member's etcd process, on the staging directory while the restore's drop-in is in place); etcdutl's snapshot restore,
etcdctl's endpoint status, member list, get and txn, and the directory exchange (renameat2) are the real ones.

Needs ETCD_BIN, ETCDCTL_BIN and ETCDUTL_BIN; skipped without them, failed without them under REGALIA_EXPECT_ETCD=1.
Test keys only (tests/test_baremetal_restore.py's)."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from deploy.baremetal import etcdconf, opstate, restore as rs
from tests.test_baremetal_restore import NOW, chain, config_text, sign, statement
from tests.test_baremetal_takeover_etcd import BINS, HAVE, ports

CONFIG_PEER = etcdconf.LOOPBACK_PEER_URL


class RealSingle(rs.Host):
    """One member on localhost; the host the restore sees, its paths mapped under `root` and its systemctl played."""

    def __init__(self, root, the_chain):
        self.root, self.procs, self.files = root, {}, {etcdconf.CONFIG_PATH: config_text(the_chain)}
        self.daemon = True
        self.peer = "http://127.0.0.1:%d" % ports(1)[0]
        self.token = json.loads(self.files[etcdconf.CONFIG_PATH])["initial-cluster-token"]
        self.data = os.path.join(root, "data")
        self.run_dir = os.path.join(root, "run")
        os.makedirs(self.run_dir)
        self.client = etcdconf.client_endpoint(self.run_dir)
        self.start()

    def path(self, p):
        for real, here in ((rs.STAGING, os.path.join(self.data, "restore")), (rs.MEMBER, os.path.join(self.data, "member")),
                           (etcdconf.DATA_DIR, self.data)):
            if p == real or p.startswith(real + "/"):
                return here + p[len(real):]
        return p

    def start(self):
        data = os.path.join(self.data, "restore") if rs.DROPIN in self.files else self.data
        argv = [BINS["ETCD_BIN"], "--name", "a", "--data-dir", data, "--listen-peer-urls", self.peer, "--initial-advertise-peer-urls", self.peer,
                "--listen-client-urls", etcdconf.CLIENT_URL, "--advertise-client-urls", etcdconf.CLIENT_URL, "--initial-cluster", "a=" + self.peer,
                "--initial-cluster-token", self.token, "--initial-cluster-state", "new"]
        with open(os.path.join(self.root, "etcd.log"), "ab") as log:
            self.procs["a"] = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=log, cwd=self.run_dir)
        for _ in range(300):
            if self.ctl("endpoint", "status").returncode == 0:
                return
            time.sleep(0.2)
        self.stop()                                        # never leave a child behind a failed start
        raise AssertionError("etcd never answered")

    def stop(self):
        proc = self.procs.pop("a", None)
        if proc:
            proc.terminate()
            try:
                proc.wait(30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(10)

    def ctl(self, *args, input=None):
        return subprocess.run([BINS["ETCDCTL_BIN"], "--endpoints", self.client, "--command-timeout=5s"] + list(args), input=input,
                              capture_output=True, text=True, timeout=30)

    def close(self):
        self.stop()

    # the host
    def read(self, path):
        return self.files[path]

    def write(self, path, text, owner=None, mode=0o644):
        self.files[path] = text

    def exists(self, path):
        if path in (rs.DROPIN, rs.RESTORE_CONFIG):           # played in memory, as systemctl is
            return path in self.files
        return super().exists(self.path(path))

    def remove(self, path):
        self.files.pop(path, None)
        if path == rs.VERIFIED_SNAPSHOT and os.path.lexists(self.path(path)):
            os.unlink(self.path(path))

    def copy_verified(self, source, copy):
        return super().copy_verified(source, self.path(copy))

    def exchange(self, staged, live):
        return super().exchange(self.path(staged), self.path(live))

    def run(self, argv, input=None):
        if argv[0] == "systemctl" and argv[-1] == rs.DAEMON:
            if argv[1] != "is-active":
                self.daemon = argv[1] != "stop"
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0 if self.daemon else 3, "active\n" if self.daemon else "inactive\n", "")
        if argv[0] == "systemctl":
            verb = argv[1]
            if verb == "stop":
                self.stop()
            elif verb in ("start", "restart"):
                self.stop()
                self.start()
            elif verb == "is-active":
                up = "a" in self.procs
                return subprocess.CompletedProcess(argv, 0 if up else 3, "active\n" if up else "inactive\n", "")
            elif verb == "show":
                return subprocess.CompletedProcess(argv, 0, (rs.DROPIN if rs.DROPIN in self.files else "") + "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[0] == "chown":
            return subprocess.CompletedProcess(argv, 0, "", "")      # one user here
        real = {rs.ETCDCTL: BINS["ETCDCTL_BIN"], rs.ETCDUTL: BINS["ETCDUTL_BIN"]}[argv[0]]
        argv = [real] + [self.client if a == etcdconf.client_endpoint() else self.path(a).replace(CONFIG_PEER, self.peer) for a in argv[1:]]
        return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(HAVE or os.environ.get("REGALIA_EXPECT_ETCD") == "1", "no etcd binaries (ETCD_BIN, ETCDCTL_BIN, ETCDUTL_BIN)")
class RestoreRealEtcd(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HAVE, "REGALIA_EXPECT_ETCD=1 and the etcd binaries are missing: %s" % BINS)
        self.root = tempfile.mkdtemp(prefix="restore-etcd-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.chain = chain()
        self.host = RealSingle(self.root, self.chain)
        self.addCleanup(self.host.close)
        for i in range(5):
            self.assertEqual(self.host.ctl("put", "/regalia/v1/k%d" % i, "before").returncode, 0)
        self.snapshot = os.path.join(self.root, "snap.db")

    def save(self):
        done = self.host.ctl("snapshot", "save", self.snapshot)
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(self.snapshot, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def after(self):
        """The history after the snapshot: what a lost disk took with it."""
        for i in range(5, 9):
            self.assertEqual(self.host.ctl("put", "/regalia/v1/k%d" % i, "after").returncode, 0)

    def restore(self, signed):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            epoch = rs.run(self.host, signed, self.chain, "a", self.snapshot, NOW, sign)
        return epoch, out.getvalue()

    def keys(self):
        done = self.host.ctl("get", "/regalia/v1/k", "--prefix", "--keys-only")
        return sorted(line for line in done.stdout.split() if line)

    def test_the_restored_history_is_live_at_the_raised_epoch_and_the_daemon_runs(self):
        sha = self.save()
        self.after()
        epoch, said = self.restore(statement(self.chain, epoch=1, floor=0, sha=sha))
        self.assertEqual(epoch, 1, said)
        self.assertTrue(self.host.daemon)
        self.assertEqual(self.keys(), ["/regalia/v1/k%d" % i for i in range(5)])       # the history after the snapshot is gone
        kv = json.loads(self.host.ctl("get", opstate.STATE_EPOCH_KEY, "-w", "json").stdout)["kvs"][0]
        status = json.loads(self.host.ctl("endpoint", "status", "-w", "json").stdout)[0]["Status"]["header"]
        got = json.loads(self.host.ctl("get", opstate.STATE_EPOCH_KEY, "--print-value-only").stdout)
        entry = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, got, self.chain, None, ("%016x" % status["cluster_id"], kv["mod_revision"]))
        self.assertEqual(entry["state_epoch"], 1)
        self.assertEqual(kv["mod_revision"], entry["revision_before"] + 1)            # the restored store's first write
        members = json.loads(self.host.ctl("member", "list", "-w", "json").stdout)["members"]
        self.assertEqual([m["name"] for m in members], ["a"])
        self.assertTrue(os.path.isdir(os.path.join(self.root, "data", "restore", "member")))   # the replaced store, kept
        self.assertNotIn(rs.DROPIN, self.host.files)

    def test_a_snapshot_that_already_holds_the_epoch_is_refused_and_the_daemon_stays_stopped(self):
        status = json.loads(self.host.ctl("endpoint", "status", "-w", "json").stdout)[0]["Status"]["header"]
        cluster = "%016x" % status["cluster_id"]
        entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": 3, "node_id": "a",
                 "authorization": statement(self.chain, epoch=3, floor=2, now=NOW - 86400, sha="77" * 32), "cluster_id": cluster,
                 "revision_before": status["revision"], "issued_at": rs.stamp(NOW - 86400 + 60)}
        value = {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}
        self.assertEqual(self.host.ctl("put", opstate.STATE_EPOCH_KEY, json.dumps(value, sort_keys=True, separators=(",", ":"))).returncode, 0)
        sha = self.save()
        self.after()
        self.host.stop()                  # the lost disk: etcd is down, so only the snapshot's own epoch can be read
        with self.assertRaises(rs.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            rs.run(self.host, statement(self.chain, epoch=3, floor=2, sha=sha), self.chain, "a", self.snapshot, NOW, sign)
        self.assertIn("the restored store holds state epoch 3, and the statement's 3 does not raise it: the daemon is not started",
                      str(caught.exception))
        self.assertFalse(self.host.daemon)
        # etcd is back on its live store, untouched: it holds the history after the snapshot; staging is kept
        self.assertNotIn(rs.DROPIN, self.host.files)
        self.assertEqual(self.keys(), ["/regalia/v1/k%d" % i for i in range(9)])
        self.assertTrue(os.path.isdir(os.path.join(self.root, "data", "restore", "member")))
        self.assertFalse(os.path.exists(os.path.join(self.root, "data", "restore.snapshot")))

    def test_a_live_store_that_already_holds_the_epoch_is_refused_before_anything_stops(self):
        sha = self.save()
        first, _ = self.restore(statement(self.chain, epoch=1, floor=0, sha=sha))
        self.assertEqual(first, 1)
        shutil.rmtree(os.path.join(self.root, "data", "restore"))       # the operator moved the old store away
        with self.assertRaises(rs.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            rs.run(self.host, statement(self.chain, epoch=1, floor=0, sha=sha), self.chain, "a", self.snapshot, NOW, sign)
        self.assertIn("the live store holds state epoch 1, and the statement's 1 does not raise it: nothing is stopped", str(caught.exception))
        self.assertTrue(self.host.daemon)


if __name__ == "__main__":
    unittest.main()
