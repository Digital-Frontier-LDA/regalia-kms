"""deploy/baremetal/restore.py (regalia-kms-dx7.6, docs/design/single-node.md 4.8): a single-node host's etcd restore from a
snapshot, step by step on a scripted host. The daemon starts only once the live store holds the raised state epoch the owner's
statement names; every refusal leaves it stopped from the moment the restored store could be served. Test keys only."""
import base64
import calendar
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from deploy.baremetal import etcdconf, membership as m, opstate, restore as rs, takeover as tk
from tests.test_baremetal_etcdconf import GENESIS, bound
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, nodes4, p256_sig, pub
from tests.test_baremetal_membership_v5 import manifest5, one, single5

NOW = calendar.timegm(time.strptime("2026-10-06T12:00:00Z", "%Y-%m-%dT%H:%M:%SZ"))
SNAPSHOT = "/var/backups/regalia-etcd.snapshot"
SNAPSHOT_SHA = "5a" * 32
CLUSTER = 0x62ff5b5c1a2e3d4f


def chain():
    return [single5(1, "", issued_at="2026-10-04T09:00:00Z")]


def sign(raw):
    return p256_sig(NODE_KEYS["a"], raw)


class OwnerKey:
    """The owner's card as p11sign shows it: an Ed25519 key (a test key)."""

    def __init__(self, key=None):
        self.key = key or OWNER_KEYS[0]

    def public(self):
        return pub(self.key)

    def sign(self, raw):
        return self.key.sign(raw)


def statement(the_chain, epoch=3, floor=2, now=NOW, sha=SNAPSHOT_SHA, life_s=6 * 3600):
    body = rs.statement_body(the_chain, "a", sha, epoch, floor, now, life_s)
    return {"restore": body, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                           "sig": OWNER_KEYS[0].sign(opstate.restore_message(body)).hex()}}


def config_text(the_chain):
    certs = etcdconf.choose(the_chain[-1], {"a": [bound("a")]})
    return etcdconf.render(the_chain[-1], "a", GENESIS, certs, None)[0]


class Store:
    """One etcd data directory: its revision and its state-epoch key, (version, value text, mod_revision) or None."""

    def __init__(self, revision, kv=None):
        self.revision, self.kv = revision, kv


class FakeHost:
    """systemctl, etcdctl, etcdutl, chown and mv as the restore sees them. Two data directories: the live one and STAGING;
    systemctl starts etcd on STAGING while the restore's drop-in is in place, on the live one otherwise."""

    def __init__(self, the_chain, snapshot_kv=None):
        self.files = {etcdconf.CONFIG_PATH: config_text(the_chain)}
        self.owners, self.calls = {}, []
        self.daemon, self.etcd = True, True
        self.live, self.staging = Store(5000), None
        self.snapshot = Store(4711, snapshot_kv)          # what the snapshot holds
        self.serving = self.live
        self.members, self.cluster = ["a"], CLUSTER
        self.sha = SNAPSHOT_SHA
        self.restore_fails = self.txn_lies = self.exchange_lies = self.exchange_fails = False
        self.staging_exists = False

    # the host's files
    def read(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    def write(self, path, text, owner=None, mode=0o644):
        self.files[path], self.owners[path] = text, (owner, mode)

    def remove(self, path):
        self.files.pop(path, None)

    def exists(self, path):
        if path == rs.STAGING:
            return self.staging is not None or self.staging_exists
        if path == rs.MEMBER:
            return self.live is not None
        raise AssertionError(path)

    def sha256(self, path):
        assert path == SNAPSHOT, path
        return self.sha

    def exchange(self, staged, live):
        assert (staged, live) == (rs.STAGING + "/member", rs.MEMBER), (staged, live)
        self.calls.append(["exchange", staged, live])
        if self.exchange_fails:
            raise OSError(22, "Invalid argument", live)
        if not self.exchange_lies:
            self.live, self.staging = self.staging, self.live

    def done(self, rc=0, out=""):
        return subprocess.CompletedProcess([], rc, out, "")

    def run(self, argv, input=None):
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "is-active"]:
            up = self.daemon if argv[2] == rs.DAEMON else self.etcd
            return self.done(0 if up else 3, "active" if up else "inactive")
        if argv[:2] == ["systemctl", "show"]:
            return self.done(0, rs.DROPIN + "\n" if rs.DROPIN in self.files else "\n")
        if argv[0] == "systemctl":
            verb, unit = argv[1], argv[-1]
            if verb == "daemon-reload":
                return self.done()
            if unit == rs.DAEMON:
                self.daemon = verb != "stop"
            else:
                self.etcd = verb != "stop"
                self.serving = (self.staging if rs.DROPIN in self.files else self.live) if self.etcd else None
            return self.done()
        if argv[0] == rs.ETCDUTL:
            assert argv[1:4] == ["snapshot", "restore", SNAPSHOT] and argv[argv.index("--data-dir") + 1] == rs.STAGING, argv
            if self.restore_fails:
                return self.done(1, "snapshot file has wrong CRC")
            self.staging = Store(self.snapshot.revision, self.snapshot.kv)
            return self.done()
        if argv[0] == "chown":
            return self.done()
        store = self.serving
        assert store is not None, "etcdctl with etcd stopped: %s" % argv
        what = argv[3:]
        if what[:2] == ["endpoint", "status"]:
            return self.done(0, json.dumps([{"Endpoint": "x", "Status": {"header": {"cluster_id": self.cluster, "revision": store.revision}}}]))
        if what[:2] == ["member", "list"]:
            return self.done(0, json.dumps({"members": [{"name": n} for n in self.members]}))
        if what[0] == "get":
            kv = store.kv
            kvs = [{"version": kv[0], "mod_revision": kv[2], "value": base64.b64encode(kv[1].encode()).decode()}] if kv else []
            return self.done(0, json.dumps({"kvs": kvs} if kvs else {}))
        if what[0] == "txn":
            want = int(input.split('"')[3])
            have = store.kv[0] if store.kv else 0
            if want != have:
                return self.done(0, json.dumps({"header": {}}))
            if not self.txn_lies:
                value = json.loads(input.split("\n")[2].split(" ", 2)[2])
                store.revision += 1
                store.kv = (have + 1, value, store.revision)
            return self.done(0, json.dumps({"succeeded": True}))
        raise AssertionError(argv)


def held(the_chain, epoch, revision_before=4700, mod_revision=4701):
    """A verified restore entry at `epoch` as a store holds it: (version, value text, mod_revision)."""
    entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": epoch, "node_id": "a",
             "authorization": statement(the_chain, epoch=epoch, floor=epoch - 1, now=NOW - 86400, sha="77" * 32),
             "cluster_id": "%016x" % CLUSTER, "revision_before": revision_before, "issued_at": rs.stamp(NOW - 86400 + 60)}
    value = {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}
    return (1, json.dumps(value, sort_keys=True, separators=(",", ":")), mod_revision)


class Restore(unittest.TestCase):
    def setUp(self):
        self.chain = chain()
        self.host = FakeHost(self.chain)
        self.signed = statement(self.chain)

    def go(self, signed=None, now=NOW, host=None):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            epoch = rs.run(host or self.host, signed or self.signed, self.chain, "a", SNAPSHOT, now, sign)
        return epoch, out.getvalue()

    def refused(self, reason, signed=None, now=NOW, the_chain=None):
        with self.assertRaises(m.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            rs.run(self.host, signed or self.signed, the_chain or self.chain, "a", SNAPSHOT, now, sign)
        self.assertIn(reason, str(caught.exception))

    def daemon_started_after_its_stop(self):
        calls = self.host.calls
        stop = calls.index(["systemctl", "stop", rs.DAEMON])
        return ["systemctl", "start", rs.DAEMON] in calls[stop + 1:]

    def test_the_restore_in_order_and_the_daemon_only_on_the_raised_epoch(self):
        epoch, said = self.go()
        self.assertEqual(epoch, 3)
        ctl = [rs.ETCDCTL, "--endpoints", rs.ENDPOINT]
        config = json.loads(self.host.files[etcdconf.CONFIG_PATH])
        self.assertEqual(self.host.calls, [
            ["systemctl", "stop", rs.DAEMON], ["systemctl", "is-active", rs.DAEMON],
            ["systemctl", "stop", rs.UNIT], ["systemctl", "is-active", rs.UNIT],
            [rs.ETCDUTL, "snapshot", "restore", SNAPSHOT, "--data-dir", rs.STAGING, "--name", "a", "--initial-cluster", "a=https://127.0.0.1:2380",
             "--initial-cluster-token", config["initial-cluster-token"], "--initial-advertise-peer-urls", "https://127.0.0.1:2380"],
            ["chown", "-R", "--no-dereference", "regalia-etcd:regalia-etcd", rs.STAGING],
            ["systemctl", "daemon-reload"], ["systemctl", "start", rs.UNIT],
            ctl + ["endpoint", "status", "-w", "json"], ctl + ["member", "list", "-w", "json"],
            ctl + ["get", opstate.STATE_EPOCH_KEY, "-w", "json"], ctl + ["txn", "-w", "json"], ctl + ["get", opstate.STATE_EPOCH_KEY, "-w", "json"],
            ["systemctl", "stop", rs.UNIT], ["systemctl", "is-active", rs.UNIT],
            ["exchange", rs.STAGING + "/member", rs.MEMBER],
            ["systemctl", "daemon-reload"], ["systemctl", "restart", rs.UNIT],
            ["systemctl", "show", "--property=DropInPaths", "--value", rs.UNIT], ["systemctl", "show", "--property=DropInPaths", "--value", rs.UNIT],
            ctl + ["endpoint", "status", "-w", "json"], ctl + ["member", "list", "-w", "json"], ctl + ["get", opstate.STATE_EPOCH_KEY, "-w", "json"],
            ["systemctl", "daemon-reload"], ["systemctl", "start", rs.DAEMON]])
        self.assertTrue(self.host.daemon)
        live = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, json.loads(self.host.live.kv[1]), self.chain, None,
                                          ("%016x" % CLUSTER, self.host.live.kv[2]))
        self.assertEqual((live["state_epoch"], live["revision_before"]), (3, 4711))       # the snapshot's revision, then the raise
        self.assertEqual(self.host.staging.revision, 5000)                                 # the store it replaced, kept
        self.assertNotIn(rs.DROPIN, self.host.files)
        self.assertNotIn(rs.RESTORE_CONFIG, self.host.files)
        self.assertIn("state epoch 3 written over 0", said)

    def test_the_staged_configuration_is_the_checked_one_with_its_data_dir_moved(self):
        staged = json.loads(rs.staged_config(self.host.files[etcdconf.CONFIG_PATH]))
        normal = json.loads(self.host.files[etcdconf.CONFIG_PATH])
        self.assertEqual(staged, dict(normal, **{"data-dir": rs.STAGING}))
        self.assertEqual(rs.dropin(), "[Service]\nExecStart=\nExecStart=/usr/bin/etcd --config-file /run/regalia-etcd/restore.conf.yml\n")

    def test_a_restore_over_a_snapshot_that_holds_an_older_epoch(self):
        self.host = FakeHost(self.chain, snapshot_kv=held(self.chain, 2))
        epoch, said = self.go()
        self.assertEqual(epoch, 3)
        self.assertIn("state epoch 3 written over 2", said)
        self.assertTrue(self.host.daemon)

    def test_restore_refuses_without_a_raised_state_epoch(self):
        """The snapshot already holds the statement's epoch (a statement used twice, or issued below what the store saw): the
        daemon is not started, and the live store is not replaced."""
        for held_epoch in (3, 7):
            with self.subTest(held_epoch):
                self.host = FakeHost(self.chain, snapshot_kv=held(self.chain, held_epoch))
                live = self.host.live
                self.refused("REFUSED: the restored store holds state epoch %d, and the statement's 3 does not raise it: the daemon is not "
                             "started" % held_epoch)
                self.assertFalse(self.host.daemon)
                self.assertFalse(self.daemon_started_after_its_stop())
                self.assertIs(self.host.live, live)
                self.assertFalse(any(c[0] == "exchange" for c in self.host.calls))
                self.assertFalse(any(c[0] == rs.ETCDCTL and "txn" in c for c in self.host.calls))

    def test_a_write_that_did_not_land_leaves_the_daemon_stopped(self):
        self.host.txn_lies = True
        self.refused("the staging store does not hold state epoch 3 after its write: the daemon is not started")
        self.assertFalse(self.daemon_started_after_its_stop())
        self.assertFalse(any(c[0] == "exchange" for c in self.host.calls))

    def test_an_exchange_that_did_not_happen_leaves_the_daemon_stopped(self):
        self.host.exchange_lies = True
        self.refused("the live store holds state epoch none, not 3: the daemon is not started")
        self.assertFalse(self.daemon_started_after_its_stop())

    def test_a_failed_exchange_leaves_the_live_store_and_the_daemon_stopped(self):
        self.host.exchange_fails = True
        live = self.host.live
        self.refused("the exchange of %s/member and %s failed" % (rs.STAGING, rs.MEMBER))
        self.assertIs(self.host.live, live)
        self.assertFalse(self.daemon_started_after_its_stop())


    def test_a_multi_node_cluster_is_refused_before_anything_stops(self):
        multi = [manifest5(1, "", nodes4())]
        self.refused("an etcd restore is refused under the multi-node profile (epoch 1): a multi-node cluster's etcd comes back by a "
                     "take-over and a rejoin", the_chain=multi)
        self.assertEqual(self.host.calls, [])
        self.assertTrue(self.host.daemon)

    def test_refusals_before_the_store_is_touched_start_nothing_and_stop_nothing(self):
        later = self.chain + [single5(2, m.digest(self.chain[0]), issued_at="2026-10-06T00:00:00Z")]
        cases = [("the restore statement is for epoch 1; this node's manifest is epoch 2: a new epoch ends it", {"the_chain": later}),
                 ("the restore statement is valid from 2026-10-06T12:00:00Z to 2026-10-06T18:00:00Z, not now", {"now": NOW + 6 * 3600}),
                 ("the restore statement is valid from", {"now": NOW - rs.SKEW_S - 1}),
                 ("the restore statement is not the owner's", {"signed": dict(self.signed, signature={
                     "party": "a", "key": pub(NODE_KEYS["a"]), "sig": sign(opstate.restore_message(self.signed["restore"]))})})]
        for reason, kw in cases:
            with self.subTest(reason):
                self.host = FakeHost(self.chain)
                self.refused(reason, **kw)
                self.assertEqual(self.host.calls, [])
        self.host = FakeHost(self.chain)
        self.host.sha = "66" * 32
        self.refused("the snapshot %s is not the one the statement names" % SNAPSHOT)
        self.host = FakeHost(self.chain)
        self.host.staging_exists = True
        self.refused("%s exists, left by an earlier restore" % rs.STAGING)
        self.assertEqual(self.host.calls, [])

    def test_a_multi_node_configuration_on_disk_is_refused(self):
        three = [manifest5(1, "", nodes4())]
        offered = {n: [bound(n)] for n in "abc"}
        self.host.files[etcdconf.CONFIG_PATH] = etcdconf.render(three[0], "a", GENESIS, etcdconf.choose(three[0], offered), 20)[0]
        self.refused("a single-node etcd's initial-cluster is a alone")
        self.assertEqual(self.host.calls, [])

    def test_a_failed_restore_starts_both_again_and_touches_nothing(self):
        self.host.restore_fails = True
        self.refused("etcdutl snapshot restore failed (1): snapshot file has wrong CRC")
        self.assertTrue(self.host.daemon and self.host.etcd)
        self.assertNotIn(rs.DROPIN, self.host.files)


class RealExchange(unittest.TestCase):
    """restore.Host.exchange on this machine's file system: renameat2 RENAME_EXCHANGE (Linux), or a rename into place."""

    @unittest.skipUnless(os.uname().sysname == "Linux", "renameat2 is Linux's")
    def test_the_two_directories_are_exchanged_and_a_missing_live_one_is_renamed_into_place(self):
        root = tempfile.mkdtemp(prefix="restore-exchange-")
        self.addCleanup(shutil.rmtree, root, True)
        staged, live = os.path.join(root, "restore", "member"), os.path.join(root, "member")
        for path, mark in ((staged, "restored"), (live, "old")):
            os.makedirs(path)
            with open(os.path.join(path, "which"), "w") as f:
                f.write(mark)
        rs.Host().exchange(staged, live)
        for path, mark in ((live, "restored"), (staged, "old")):
            with open(os.path.join(path, "which")) as f:
                self.assertEqual(f.read(), mark)
        shutil.rmtree(live)
        rs.Host().exchange(staged, live)
        with open(os.path.join(live, "which")) as f:
            self.assertEqual(f.read(), "old")
        self.assertFalse(os.path.exists(staged))


class Owner(unittest.TestCase):
    """The owner's side: the epoch from the ledger above the collector's, issued once, recorded before the touch."""

    def setUp(self):
        self.chain = chain()
        self.dir = tempfile.mkdtemp(prefix="restore-ledger-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.ledger = rs.Ledger(os.path.join(self.dir, "ledger.json"))

    def make(self, collector=0, typed=None, key=None):
        def confirm(text):
            self.shown = text
            _, digest = rs.shown(self.pending(text))
            return typed if typed is not None else "%d %s" % (self.epoch_in(text), digest[:8])
        with contextlib.redirect_stdout(io.StringIO()):
            return rs.make_statement(self.chain, "a", SNAPSHOT_SHA, collector, self.ledger, NOW, confirm, lambda: OwnerKey(key), say=lambda _: None)

    @staticmethod
    def epoch_in(text):
        return int(text.split("state epoch")[1].split(",")[0])

    def pending(self, text):
        epoch = self.epoch_in(text)
        floor = int(text.split("above the floor")[1].split("\n")[0])
        return rs.statement_body(self.chain, "a", SNAPSHOT_SHA, epoch, floor, NOW)

    def test_each_epoch_is_issued_once_above_the_collector_and_the_ledger(self):
        first = self.make(collector=4)
        self.assertEqual((first["restore"]["state_epoch"], first["restore"]["floor"]), (5, 4))
        second = self.make(collector=4)                      # the same snapshot again: another epoch
        self.assertEqual((second["restore"]["state_epoch"], second["restore"]["floor"]), (6, 5))
        third = self.make(collector=9)                       # the collector saw more than this ledger issued
        self.assertEqual((third["restore"]["state_epoch"], third["restore"]["floor"]), (10, 9))
        opstate.verify_restore(third, self.chain, "a")
        self.assertEqual(self.ledger.read()["clusters"][m.digest(self.chain[0])], [5, 6, 10])

    def test_a_mistyped_confirmation_signs_nothing_and_burns_its_epoch(self):
        with self.assertRaises(m.Refused) as caught:
            self.make(typed="1 00000000")
        self.assertIn("nothing is signed (epoch 1 stays issued)", str(caught.exception))
        self.assertEqual(self.make()["restore"]["state_epoch"], 2)

    def test_a_key_that_is_not_the_owner_s_spends_no_epoch(self):
        from tests.test_baremetal_membership_v4 import ed25519
        with self.assertRaises(m.Refused) as caught:
            self.make(key=ed25519(99))
        self.assertIn("is not one of the manifest's owner_keys: nothing is signed", str(caught.exception))
        self.assertEqual(self.ledger.read()["clusters"], {})

    def test_the_owner_tool_refuses_a_multi_node_chain(self):
        self.chain = [manifest5(1, "", nodes4())]
        with self.assertRaises(m.Refused) as caught:
            self.make()
        self.assertIn("an etcd restore is the single-node profile's", str(caught.exception))
        self.assertEqual(self.ledger.read()["clusters"], {})

    def test_a_ledger_that_is_not_one_is_refused(self):
        with open(self.ledger.path, "w") as f:
            json.dump({"schema": rs.LEDGER_SCHEMA, "clusters": {m.digest(self.chain[0]): [3, 2]}}, f)
        with self.assertRaises(m.Refused) as caught:
            self.make()
        self.assertIn("are not a rising list of epochs", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
