"""deploy/baremetal/takeover.py against a real etcd (v3.6.15, as CI installs it): three members, b and c stopped, a
taken over. Only systemctl is played here (it starts and stops a's etcd process); etcdutl's offline status, etcdctl's
endpoint status, member list, get and txn are the real tools, so the take-over's parsing, the cluster ID and revision
it relies on, and the state-epoch entry's quoting through `etcdctl txn` are etcd's own answers.

Needs ETCD_BIN, ETCDCTL_BIN and ETCDUTL_BIN; skipped without them, failed without them under REGALIA_EXPECT_ETCD=1."""
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from deploy.baremetal import etcdconf, opstate, takeover as tk
from tests.test_baremetal_takeover import NOW, authorization, chain, config_text, sign

BINS = {k: os.environ.get(k) for k in ("ETCD_BIN", "ETCDCTL_BIN", "ETCDUTL_BIN")}
HAVE = all(BINS.values()) and all(os.access(v, os.X_OK) for v in BINS.values())


def ports(n):
    out = []
    for _ in range(n):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            out.append(s.getsockname()[1])
    return out


class RealEtcd:
    """Three members on localhost; the host the take-over sees (run/read/write/remove), its systemctl played on a."""

    def __init__(self, root):
        self.root, self.procs, self.files = root, {}, {etcdconf.CONFIG_PATH: config_text(), tk.BOOT_ID: "x\n"}
        self.daemon = True                                # regalia-kms.service: played, it writes nothing here
        p = ports(3)
        self.peer = {n: "http://127.0.0.1:%d" % p[i] for i, n in enumerate("abc")}
        # each member serves its clients as the unit does: etcdconf.CLIENT_URL in its working directory, dialled at
        # etcdconf.client_endpoint() of that directory, the derivation takeover.ENDPOINT is (05 on #513)
        self.client = {}
        for n in "abc":
            os.makedirs(self.run_dir(n), exist_ok=True)
            self.client[n] = etcdconf.client_endpoint(self.run_dir(n))
        try:
            for n in "abc":
                self.start(n)
            self.wait(self.client["a"], 90)
        except BaseException:
            self.close()                                 # never leave a member running behind a failed start
            raise

    def run_dir(self, n):
        """The member's working directory, as /run/regalia-etcd is the unit's: its client socket is made there."""
        return os.path.join(self.root, n + "-run")

    def start(self, n, force=False):
        argv = [BINS["ETCD_BIN"], "--name", n, "--data-dir", os.path.join(self.root, n), "--listen-peer-urls", self.peer[n],
                "--initial-advertise-peer-urls", self.peer[n], "--listen-client-urls", etcdconf.CLIENT_URL, "--advertise-client-urls",
                etcdconf.CLIENT_URL, "--initial-cluster", ",".join("%s=%s" % (m, self.peer[m]) for m in "abc"),
                "--initial-cluster-token", "takeover-test", "--initial-cluster-state", "new"] + (["--force-new-cluster"] if force else [])
        with open(os.path.join(self.root, n + ".log"), "ab") as log:     # the child keeps its own descriptor
            self.procs[n] = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=log, cwd=self.run_dir(n))

    def stop(self, n):
        proc = self.procs.pop(n, None)
        if proc:
            proc.terminate()
            try:
                proc.wait(30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(10)

    def wait(self, url, seconds=30, write=True):
        """Until etcd at `url` takes a write (a formed cluster), or only answers (write=False: alone without quorum)."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if write and self.ctl(url, "put", "/probe", "x").returncode == 0:
                return
            if not write and self.listening(url):
                return
            time.sleep(0.3)
        raise AssertionError("etcd at %s never answered" % url)

    @staticmethod
    def listening(url):
        """etcd's client socket takes a connection: a member alone without quorum answers no request, but it runs."""
        try:
            with socket.socket(socket.AF_UNIX) as s:
                s.settimeout(1)
                s.connect(url[len("unix://"):])
                return True
        except OSError:
            return False

    def ctl(self, url, *args, input=None):
        return subprocess.run([BINS["ETCDCTL_BIN"], "--endpoints", url, "--command-timeout=5s"] + list(args), input=input,
                              capture_output=True, text=True, timeout=30)

    def close(self):
        for n in list(self.procs):
            self.stop(n)

    # the host
    def read(self, path):
        return self.files[path]

    def write(self, path, text, owner=None, mode=0o644):
        self.files[path] = text

    def remove(self, path):
        self.files.pop(path, None)

    def run(self, argv, input=None):
        if argv[0] == "systemctl" and argv[-1] == tk.DAEMON:
            if argv[1] != "is-active":
                self.daemon = argv[1] != "stop"
                return subprocess.CompletedProcess(argv, 0, "", "")
            return subprocess.CompletedProcess(argv, 0 if self.daemon else 3, "active\n" if self.daemon else "inactive\n", "")
        if argv[0] == "systemctl":
            verb = argv[1]
            if verb == "stop":
                self.stop("a")
            elif verb in ("start", "restart"):
                self.stop("a")
                self.start("a", force=tk.DROPIN in self.files and json.loads(self.files[tk.TAKEOVER_CONFIG])["force-new-cluster"])
                self.wait(self.client["a"], 90, write=False)
            elif verb == "is-active":
                return subprocess.CompletedProcess(argv, 0 if "a" in self.procs else 3, "active\n" if "a" in self.procs else "inactive\n", "")
            elif verb == "show":
                return subprocess.CompletedProcess(argv, 0, (tk.DROPIN if tk.DROPIN in self.files else "") + "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        real = {tk.ETCDCTL: BINS["ETCDCTL_BIN"], tk.ETCDUTL: BINS["ETCDUTL_BIN"]}[argv[0]]
        # only the derived endpoint is mapped to this test's working directory: a take-over that dials anything else
        # (the ":0"-less literal 05 found on #513) dials a socket that does not exist, here as on a host
        argv = [real] + [self.client["a"] if a == etcdconf.client_endpoint() else os.path.join(self.root, "a", "member", "snap", "db")
                         if a == tk.BACKEND else a for a in argv[1:]]
        return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(HAVE or os.environ.get("REGALIA_EXPECT_ETCD") == "1", "no etcd binaries (ETCD_BIN, ETCDCTL_BIN, ETCDUTL_BIN)")
class TakeOverRealEtcd(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HAVE, "REGALIA_EXPECT_ETCD=1 and the etcd binaries are missing: %s" % BINS)
        self.root = tempfile.mkdtemp(prefix="takeover-etcd-")       # TMPDIR: on the dev qube under ~/.cache, not the shared /tmp
        self.addCleanup(shutil.rmtree, self.root, True)
        self.host = RealEtcd(self.root)
        self.addCleanup(self.host.close)
        for i in range(5):
            self.assertEqual(self.host.ctl(self.host.client["a"], "put", "/regalia/v1/k%d" % i, "v").returncode, 0)
        status = json.loads(self.host.ctl(self.host.client["a"], "endpoint", "status", "-w", "json").stdout)[0]["Status"]["header"]
        self.cluster, self.applied = "%016x" % status["cluster_id"], status["revision"]
        self.host.files[tk.APPLIED] = json.dumps({"boot_id": "x", "boottime_ns": 1, "cluster_id": self.cluster,
                                                  "revision": self.applied, "state_epoch": 0})
        self.host.stop("b")
        self.host.stop("c")                              # fenced: a has no quorum
        self.chain = chain()
        self.signed = authorization(self.chain[-1])

    def take_over(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            epoch = tk.run(self.host, self.signed, self.chain, "a", NOW, sign)
        return epoch, out.getvalue()

    def test_a_alone_with_the_state_epoch_its_first_write(self):
        self.assertNotEqual(self.host.ctl(self.host.client["a"], "put", "/x", "y").returncode, 0)   # no quorum before
        epoch, said = self.take_over()
        self.assertEqual(epoch, 2, said)
        got = json.loads(self.host.ctl(self.host.client["a"], "get", opstate.STATE_EPOCH_KEY, "--print-value-only").stdout)
        kv = json.loads(self.host.ctl(self.host.client["a"], "get", opstate.STATE_EPOCH_KEY, "-w", "json").stdout)["kvs"][0]
        entry = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, got, self.chain, None, (self.cluster, kv["mod_revision"]))
        self.assertEqual(kv["mod_revision"], entry["revision_before"] + 1)          # the first write: the daemon was stopped
        self.assertTrue(self.host.daemon)
        self.assertEqual((entry["cluster_id"], entry["state_epoch"]), (self.cluster, 2))
        self.assertGreaterEqual(entry["revision_before"], self.applied)
        members = json.loads(self.host.ctl(self.host.client["a"], "member", "list", "-w", "json").stdout)["members"]
        self.assertEqual([m["name"] for m in members], ["a"])
        self.assertEqual(self.host.ctl(self.host.client["a"], "put", "/x", "y").returncode, 0)      # it commits alone
        self.assertNotIn(tk.DROPIN, self.host.files)
        # a second run, as after a crash past the put: found, not written again
        before = json.loads(self.host.ctl(self.host.client["a"], "get", opstate.STATE_EPOCH_KEY, "-w", "json").stdout)["kvs"][0]
        _, said = self.take_over()
        self.assertIn("already taken over at epoch 2", said)
        after = json.loads(self.host.ctl(self.host.client["a"], "get", opstate.STATE_EPOCH_KEY, "-w", "json").stdout)["kvs"][0]
        self.assertEqual(before["mod_revision"], after["mod_revision"])

    def test_a_store_behind_what_was_applied_is_refused_and_both_started_again(self):
        self.host.files[tk.APPLIED] = json.dumps({"boot_id": "x", "boottime_ns": 1, "cluster_id": self.cluster,
                                                  "revision": self.applied + 100, "state_epoch": 0})
        with self.assertRaises(tk.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            tk.run(self.host, self.signed, self.chain, "a", NOW, sign)
        self.assertIn("below the %d this node applied" % (self.applied + 100), str(caught.exception))
        self.assertIn("a", self.host.procs)               # nothing forced: etcd and the daemon back as they were
        self.assertTrue(self.host.daemon)
        self.assertNotIn(tk.DROPIN, self.host.files)


if __name__ == "__main__":
    unittest.main()
