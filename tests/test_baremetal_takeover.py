"""deploy/baremetal/takeover.py (#432, the owner's one-server decision): the lone survivor's etcd take-over, step by
step on a scripted host. Each refusal is shown with its own message; the argv of every command is the one checked."""
import base64
import contextlib
import io
import json
import subprocess
import unittest

from deploy.baremetal import etcdconf, membership as m, opstate, survivor as sv, takeover as tk
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, manifest4, nodes4, p256_sig, pub

T0 = 1791201600                                              # 2026-10-05T12:00:00Z, the authorization's not_before
NOW = T0 + sv.REQUEST_LIFE_S + sv.SKEW_S + 100               # inside the full scope of a power-readback fence
CLUSTER = 0x62ff5b5c1a2e3d4f


def chain():
    m1 = manifest4(1, "", nodes4())
    return [m1, manifest4(2, m.digest(m1), nodes4(b="QUARANTINED", c="QUARANTINED"), issued_at="2026-10-05T11:00:00Z")]


def authorization(tip, scope="full", method="redfish"):
    auth = {"schema": sv.AUTH_SCHEMA, "node_id": "a", "quarantine_epoch": tip["epoch"], "quarantine_digest": m.digest(tip),
            "not_before": "2026-10-05T12:00:00Z", "expires_at": "2026-10-06T12:00:00Z", "fenced": "b, c: off at the iLO", "scope": scope,
            "fence": {"method": method, "nodes": {o: {"power_state": "Off" if method == "redfish" else "unreachable",
                                                      "read_at": "2026-10-05T11:59:00Z"} for o in ("b", "c")}}}
    return {"authorization": auth, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                                 "sig": OWNER_KEYS[0].sign(sv.authorization_message(auth)).hex()}}


def config_text():
    nodes = {n["node_id"]: n for n in chain()[-1]["nodes"]}
    peer = etcdconf.peer_url(nodes["a"])
    config = {"name": "a", "data-dir": etcdconf.DATA_DIR, "listen-peer-urls": peer, "initial-advertise-peer-urls": peer,
              "listen-client-urls": etcdconf.CLIENT_URL, "advertise-client-urls": etcdconf.CLIENT_URL,
              "initial-cluster": "a=%s,b=%s,c=%s" % tuple(etcdconf.peer_url(nodes[n]) for n in "abc"), "initial-cluster-state": "new",
              "initial-cluster-token": "regalia-" + "0" * 32, "heartbeat-interval": 100, "election-timeout": 1000,
              "strict-reconfig-check": True, "enable-pprof": False, "tls-min-version": "TLS1.3",
              "peer-transport-security": {"cert-file": etcdconf.CERT_DIR + "/peer.crt", "key-file": etcdconf.CREDENTIALS + "/etcd-peer.key",
                                          "client-cert-auth": True, "trusted-ca-file": etcdconf.CERT_DIR + "/peers.pem", "auto-tls": False},
              "auto-compaction-mode": "periodic", "auto-compaction-retention": etcdconf.COMPACTION_RETENTION,
              "quota-backend-bytes": etcdconf.QUOTA_BYTES, "feature-gates": etcdconf.CORRUPTION_GATES, "logger": "zap", "log-outputs": ["stderr"]}
    return json.dumps(config)


class FakeHost:
    """systemctl, etcdctl and etcdutl as the take-over sees them; etcd's state-epoch key held here."""

    def __init__(self):
        self.files = {tk.APPLIED: json.dumps({"boot_id": "x", "boottime_ns": 1, "cluster_id": "%016x" % CLUSTER, "revision": 4700,
                                              "state_epoch": 0}), etcdconf.CONFIG_PATH: config_text()}
        self.owners, self.calls = {}, []
        self.is_active = (3, "inactive")
        self.backend_revision, self.revision, self.cluster = 4711, 4711, CLUSTER
        self.members = ["a", "b", "c"]
        self.kv = None                                   # (version, value text)
        self.keep_dropin = False
        self.race = False

    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path, text, owner=None, mode=0o644):
        self.files[path], self.owners[path] = text, (owner, mode)

    def remove(self, path):
        if not (path == tk.DROPIN and self.keep_dropin):
            self.files.pop(path, None)

    def done(self, rc=0, out=""):
        return subprocess.CompletedProcess([], rc, out, "")

    def run(self, argv, input=None):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "is-active"]:
            return self.done(*self.is_active)
        if argv[:2] == ["systemctl", "show"]:
            return self.done(0, tk.DROPIN + "\n" if tk.DROPIN in self.files else "\n")
        if argv[0] == "systemctl":
            if argv[1] in ("start", "restart") and tk.DROPIN in self.files:
                self.members = ["a"]                     # force-new-cluster
            return self.done()
        if argv[0] == tk.ETCDUTL:
            return self.done(0, json.dumps({"hash": 1, "revision": self.backend_revision, "totalKey": 5, "totalSize": 20480}))
        what = argv[3:]
        if what[:2] == ["endpoint", "status"]:
            return self.done(0, json.dumps([{"Endpoint": "x", "Status": {"header": {"cluster_id": self.cluster, "revision": self.revision}}}]))
        if what[:2] == ["member", "list"]:
            return self.done(0, json.dumps({"members": [{"name": n} for n in self.members]}))
        if what[0] == "get":
            kvs = [{"version": self.kv[0], "value": base64.b64encode(self.kv[1].encode()).decode()}] if self.kv else []
            return self.done(0, json.dumps({"kvs": kvs} if kvs else {}))
        if what[0] == "txn":
            self.input = input
            want = int(input.split('"')[3])
            have = self.kv[0] if self.kv else 0
            if self.race or want != have:
                return self.done(0, json.dumps({"header": {}}))
            value = json.loads(input.split("\n")[2].split(" ", 2)[2])
            self.kv, self.revision = (have + 1, value), self.revision + 1
            return self.done(0, json.dumps({"succeeded": True}))
        raise AssertionError(argv)


def sign(raw):
    return p256_sig(NODE_KEYS["a"], raw)


class TakeOver(unittest.TestCase):
    def setUp(self):
        self.chain, self.host = chain(), FakeHost()
        self.signed = authorization(self.chain[-1])

    def go(self, signed=None, now=NOW):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            epoch = tk.run(self.host, signed or self.signed, self.chain, "a", now, sign)
        return epoch, out.getvalue()

    def refused(self, reason, **kw):
        with self.assertRaises(m.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            tk.run(self.host, kw.pop("signed", None) or self.signed, self.chain, "a", kw.pop("now", NOW), sign)
        self.assertIn(reason, str(caught.exception))

    def test_the_take_over_in_order(self):
        epoch, said = self.go()
        self.assertEqual(epoch, 2)
        ctl = [tk.ETCDCTL, "--endpoints", tk.ENDPOINT]
        self.assertEqual(self.host.calls, [
            ["systemctl", "stop", tk.UNIT], ["systemctl", "is-active", tk.UNIT],
            [tk.ETCDUTL, "snapshot", "status", etcdconf.DATA_DIR + "/member/snap/db", "-w", "json"],
            ["systemctl", "daemon-reload"], ["systemctl", "start", tk.UNIT],
            ctl + ["endpoint", "status", "-w", "json"], ctl + ["member", "list", "-w", "json"],
            ctl + ["get", opstate.STATE_EPOCH_KEY, "-w", "json"], ctl + ["txn", "-w", "json"],
            ["systemctl", "daemon-reload"], ["systemctl", "restart", tk.UNIT],
            ["systemctl", "show", "--property=DropInPaths", "--value", tk.UNIT],
            ctl + ["endpoint", "status", "-w", "json"], ctl + ["member", "list", "-w", "json"]])
        self.assertIn("state epoch 2", said)
        self.assertNotIn(tk.DROPIN, self.host.files)
        self.assertNotIn(tk.TAKEOVER_CONFIG, self.host.files)
        # the entry etcd holds verifies on its own: what a wiped, rejoined node reads
        entry = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, json.loads(self.host.kv[1]), self.chain)
        self.assertEqual((entry["state_epoch"], entry["revision_before"], entry["cluster_id"]), (2, 4711, "%016x" % CLUSTER))

    def test_the_forced_configuration_is_etcd_s_own_file_and_the_drop_in_points_at_it(self):
        writes = []
        real = self.host.write
        self.host.write = lambda path, text, owner=None, mode=0o644: (writes.append((path, owner, mode, text)), real(path, text, owner, mode))
        self.go()
        (conf, owner, mode, text), (dropin, _, _, unit) = writes
        self.assertEqual((conf, owner, mode), (tk.TAKEOVER_CONFIG, "regalia-etcd", 0o600))     # d9: never the setgid dir's group
        self.assertIs(json.loads(text)["force-new-cluster"], True)
        self.assertEqual(dropin, tk.DROPIN)
        self.assertEqual(unit, "[Service]\nExecStart=\nExecStart=/usr/bin/etcd --config-file %s\n" % tk.TAKEOVER_CONFIG)
        with self.assertRaises(m.Refused):
            etcdconf.check(text)                         # the normal configuration can never carry the force

    def test_only_in_full_scope(self):
        self.refused("a take-over needs \"full\"", signed=authorization(self.chain[-1], scope="stateless"))
        self.refused("the full scope begins at 2026-10-05T12:16:00Z", now=T0 + 100)
        self.refused("the full scope begins at 2026-10-05T12:26:00Z", signed=authorization(self.chain[-1], method="attested"))
        self.assertEqual(self.host.calls, [])            # nothing touched

    def test_a_unit_that_does_not_stop_or_does_not_exist(self):
        self.host.is_active = (0, "active")
        self.refused("is not stopped (is-active: 0, 'active')")
        self.host.is_active = (4, "inactive")            # measured: a unit that does not exist says "inactive", exit 4
        self.refused("is not stopped (is-active: 4, 'inactive')")
        self.host.is_active = (3, "deactivating")        # a stop still in progress: not stopped
        self.refused("is not stopped (is-active: 3, 'deactivating')")

    def test_a_backend_below_what_this_node_applied_is_not_its_store(self):
        self.host.backend_revision = 4699
        self.refused("the backend on disk is at revision 4699, below the 4700 this node applied")
        self.assertNotIn(tk.DROPIN, self.host.files)

    def test_etcd_must_answer_alone_as_the_same_cluster_at_no_lower_revision(self):
        start = self.host.run

        def half_forced(argv, input=None):
            done = start(argv, input)
            if argv[1:2] == ["start"]:
                self.host.members = ["a", "b"]           # a force that left a member behind
            return done
        self.host.run = half_forced
        self.refused("etcd's members are ['a', 'b'], not a alone")
        self.setUp()
        self.host.cluster = CLUSTER + 1
        self.refused("etcd answers as cluster 62ff5b5c1a2e3d50; this node applied cluster 62ff5b5c1a2e3d4f")
        self.setUp()
        self.host.revision = 4710
        self.refused("etcd answers at revision 4710, below the 4711 its backend held")

    def test_the_drop_in_must_be_read_back_gone(self):
        """d9: a drop-in left in place forces a new cluster again at the next restart; the take-over does not finish."""
        self.host.keep_dropin = True
        self.refused("still carries the take-over drop-in after its removal")
        self.assertTrue(tk.forcing(self.host))

    def test_a_lost_race_on_the_key_and_a_second_run(self):
        self.host.race = True
        self.refused("the state-epoch key changed while this ran")
        self.setUp()
        self.go()
        kv = self.host.kv
        self.host.calls = []
        _, said = self.go()                              # a crash after the put: the next run finds it
        self.assertIn("already taken over at epoch 2", said)
        self.assertEqual(self.host.kv, kv)
        self.assertNotIn([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "txn", "-w", "json"], self.host.calls)

    def test_the_entry_is_verified_before_it_is_put(self):
        """A signer that is not this node's manifest key (a wrong TPM, a wrong PCR key): refused, nothing written."""
        with self.assertRaises(m.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            tk.run(self.host, self.signed, self.chain, "a", NOW, lambda raw: p256_sig(NODE_KEYS["b"], raw))
        self.assertIn("a's state-epoch entry signature does not verify", str(caught.exception))
        self.assertIsNone(self.host.kv)
        self.assertNotIn([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "txn", "-w", "json"], self.host.calls)

    def test_applied_json_is_read_exactly(self):
        self.host.files[tk.APPLIED] = json.dumps({"cluster_id": "%016x" % CLUSTER, "revision": 1})
        self.refused("applied.json fields mismatch")


class Main(unittest.TestCase):
    def test_config_comes_first_and_a_refusal_is_said(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            got = tk.main(["--config", "/nonexistent/node.json", "run", "--authorization", "/nonexistent/auth.json"])
        self.assertEqual(got, 1)
        self.assertIn("TAKEOVER: REFUSED:", out.getvalue())
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            tk.main(["run", "--authorization", "x"])


if __name__ == "__main__":
    unittest.main()
