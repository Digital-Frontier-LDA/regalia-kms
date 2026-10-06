"""deploy/baremetal/rejoin.py (#432, G5): a fenced server's return to the survivor's etcd as a learner, on a scripted
host. Each refusal by its own message; the argv of every etcd command is the one checked."""
import base64
import contextlib
import io
import json
import subprocess
import unittest

from deploy.baremetal import etcdconf, membership as m, opstate, rejoin as rj, survivor as sv, takeover as tk
from tests.test_baremetal_membership_v4 import NODE_KEYS, manifest4, nodes4, p256_sig
from tests.test_baremetal_takeover import CLUSTER, NOW, authorization, chain as takeover_chain, config_text, sign


def chain():
    """The take-over's chain (epoch 2: b, c quarantined), then the root's lift (epoch 3: all three counting)."""
    c = takeover_chain()
    return c + [manifest4(3, m.digest(c[-1]), nodes4(), issued_at="2026-10-06T00:00:00Z")]


def url(manifest, node_id):
    return etcdconf.peer_url(etcdconf.members(manifest)[node_id])


def config_for(node_id, manifest):
    config = json.loads(config_text())
    config["name"] = node_id
    config["listen-peer-urls"] = config["initial-advertise-peer-urls"] = url(manifest, node_id)
    return json.dumps(config)


def state_epoch_value():
    c = takeover_chain()
    entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": 2, "node_id": "a", "authorization": authorization(c[-1]),
             "cluster_id": "%016x" % CLUSTER, "revision_before": 4711, "issued_at": sv._stamp(NOW)}
    return {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}


class FakeEtcd:
    """One node's view: systemctl, etcdctl and etcdutl, the files, the data directory; the cluster shared."""

    def __init__(self, me, cluster, manifest):
        self.me, self.cluster, self.calls = me, cluster, []
        self.files = {etcdconf.CONFIG_PATH: config_for(me, manifest)}
        self.dirs = {etcdconf.DATA_DIR}
        self.running = {tk.UNIT: True, tk.DAEMON: True}
        self.sleeps = []
        self.learner = False                             # how this node's etcd answers its own endpoint status
        self.holds_epoch = True                          # whether its etcd has the state-epoch entry yet
        self.cluster_id = CLUSTER                        # the cluster its etcd answers as
        self.member_id = 0                               # the member its etcd answers as

    def done(self, rc=0, out="", err=""):
        return subprocess.CompletedProcess([], rc, out, err)

    def read(self, path):
        return self.files[path]

    def write(self, path, text, owner=None, mode=0o644):
        self.files[path] = text
        self.owner = getattr(self, "owner", {})
        self.owner[path] = (owner, mode)

    def remove(self, path):
        self.files.pop(path, None)

    def exists(self, path):
        return path in self.dirs or path in self.files

    def listdir(self, path):
        return sorted(d.rsplit("/", 1)[1] for d in list(self.dirs) + list(self.files) if d.rsplit("/", 1)[0] == path)

    def rename(self, src, dst):
        self.dirs.remove(src)
        self.dirs.add(dst)

    def sha256(self, path):
        return "ab" * 32

    def sleep(self, seconds):
        self.sleeps.append(seconds)

    def run(self, argv, input=None):
        self.calls.append(argv)
        c = self.cluster
        if argv[0] == "systemctl":
            if argv[1] == "is-active":
                return self.done(0 if self.running[argv[2]] else 3, "active\n" if self.running[argv[2]] else "inactive\n")
            if argv[1] == "show":
                return self.done(0, (tk.DROPIN + "\n") if c.forcing else "\n")
            if argv[1] in ("stop", "start", "restart"):
                self.running[argv[2]] = argv[1] != "stop"
            return self.done()
        if argv[0] == tk.ETCDUTL:
            return self.done(0, json.dumps({"hash": 1, "revision": 4689, "totalKey": 5, "totalSize": 20480}))
        what = argv[3:]
        if what[:2] == ["member", "list"]:
            return self.done(0, json.dumps({"members": c.members}))
        if what[:2] == ["member", "add"]:
            c.next_id += 1
            added = {"ID": c.next_id, "peerURLs": [what[4].split("=", 1)[1]], "isLearner": True}
            c.members.append(added)
            return self.done(0, json.dumps({"member": added, "members": c.members}))
        if what[:2] == ["member", "promote"]:
            if c.sync_after > 0:
                c.sync_after -= 1
                return self.done(1, "", "Error: etcdserver: " + rj.NOT_IN_SYNC)
            for member in c.members:
                if "%x" % member["ID"] == what[2]:
                    member.pop("isLearner", None)
            return self.done(0, "Member promoted")
        if what[:2] == ["member", "remove"]:
            c.members = [x for x in c.members if "%x" % x["ID"] != what[2]]
            return self.done(0, "removed")
        if what[:2] == ["endpoint", "status"]:
            status = {"header": {"cluster_id": self.cluster_id, "member_id": self.member_id, "revision": 4800}}
            if self.learner:
                status["isLearner"] = True
            return self.done(0, json.dumps([{"Endpoint": "x", "Status": status}]))
        if what[0] == "get":
            kvs = [{"version": 1, "mod_revision": 4712, "value": base64.b64encode(json.dumps(c.value).encode()).decode()}] if self.holds_epoch else []
            return self.done(0, json.dumps({"kvs": kvs} if kvs else {}))
        raise AssertionError(argv)


class Cluster:
    def __init__(self, manifest):
        self.members = [{"ID": 0x6965d0c8a2e3b4d, "name": "a", "peerURLs": [url(manifest, "a")], "clientURLs": ["unix://x"]}]
        self.forcing, self.sync_after, self.value = False, 0, state_epoch_value()
        self.next_id = 0x3d4f5dd237552cf0


class Case(unittest.TestCase):
    def setUp(self):
        self.chain = chain()
        self.cluster = Cluster(self.chain[-1])
        self.a = FakeEtcd("a", self.cluster, self.chain[-1])
        self.b = FakeEtcd("b", self.cluster, self.chain[-1])

    def quiet(self, fn, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            got = fn(*args)
        return got, out.getvalue()

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught, contextlib.redirect_stdout(io.StringIO()):
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Admit(Case):
    def test_b_admitted_as_a_learner_with_the_members_now(self):
        (line, member_id), said = self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.assertEqual(member_id, "3d4f5dd237552cf1")
        self.assertIn("MEMBER-ID: 3d4f5dd237552cf1", said)
        b_url = url(self.chain[-1], "b")
        self.assertIn([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "member", "add", "b", "--learner", "--peer-urls=" + b_url, "-w", "json"],
                      self.a.calls)
        self.assertEqual(line, "a=%s,b=%s" % (url(self.chain[-1], "a"), b_url))   # a and b: never the manifest's three
        self.assertIn("INITIAL-CLUSTER: " + line, said)
        again, said = self.quiet(rj.admit, self.a, self.chain, "a", "b")            # run again: the same, nothing added
        self.assertEqual(again, (line, member_id))
        self.assertEqual(len(self.cluster.members), 2)
        self.assertIn("already admitted as a learner", said)

    def test_never_while_the_take_over_drop_in_is_in_force(self):
        self.cluster.forcing = True
        self.refused("still carries the take-over drop-in", rj.admit, self.a, self.chain, "a", "b")

    def test_both_returners_learn_at_once_and_never_a_third(self):
        """etcdconf's max-learners 2 (#519): c is admitted while b is still a learner, unstarted or started, so both catch
        up together; a third learner is refused, and so is any learner beside a voting member that has not started."""
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.quiet(rj.admit, self.a, self.chain, "a", "c")                          # b unstarted, still a learner: c too
        self.assertEqual([m.get("isLearner") for m in self.cluster.members[1:]], [True, True])
        self.cluster.members[1]["name"] = "b"
        self.quiet(rj.admit, self.a, self.chain, "a", "c")                          # run again: the same, nothing added
        self.assertEqual(len(self.cluster.members), 3)
        self.cluster.members.pop()                                                  # c's learner gone: a third stands in
        self.cluster.members.append({"ID": 99, "name": "z", "peerURLs": ["https://[fd72:6567:6c61::99]:2380"], "isLearner": True})
        self.refused("b, z are still joining: at most 2 learners at once", rj.admit, self.a, self.chain, "a", "c")
        self.cluster.members[2] = {"ID": 99, "peerURLs": ["https://[fd72:6567:6c61::99]:2380"]}     # an unstarted VOTER
        self.refused("a voting member that has not started is still joining", rj.admit, self.a, self.chain, "a", "c")

    def test_only_a_node_the_manifest_counts_and_never_a_voting_one(self):
        self.refused("b is not an etcd member under epoch 2", rj.admit, self.a, self.chain[:-1], "a", "b")   # before the lift
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.cluster.members[1].pop("isLearner")
        self.refused("b is already a voting member", rj.admit, self.a, self.chain, "a", "b")
        self.refused("a node does not admit itself", rj.admit, self.a, self.chain, "a", "a")


class Join(Case):
    def admitted(self):
        (line, member_id), _ = self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.b.learner, self.b.member_id, self.member_id = True, int(member_id, 16), member_id
        return line

    def test_the_old_data_kept_the_config_existing_and_a_learner_with_the_state_epoch(self):
        line = self.admitted()
        export, said = self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertEqual(export, etcdconf.DATA_DIR + ".divergent-e3-r4689")
        self.assertIn(export, self.b.dirs)
        self.assertNotIn(etcdconf.DATA_DIR, self.b.dirs)                            # the divergent tail moved aside, kept
        record = json.loads(self.b.files[export + ".json"])
        self.assertEqual(record, {"node_id": "b", "epoch": 3, "revision": 4689, "db_sha256": "ab" * 32, "kept_at": export})
        self.assertIn("EXPORTED", said)
        config = etcdconf.check(self.b.files[etcdconf.CONFIG_PATH])
        self.assertEqual((config["initial-cluster"], config["initial-cluster-state"]), (line, "existing"))
        self.assertEqual(self.b.owner[etcdconf.CONFIG_PATH], (None, 0o644))         # root's, as rendered
        self.assertEqual(self.b.calls[:4], [["systemctl", "stop", tk.DAEMON], ["systemctl", "is-active", tk.DAEMON],
                                            ["systemctl", "stop", tk.UNIT], ["systemctl", "is-active", tk.UNIT]])
        self.assertTrue(self.b.running[tk.UNIT])
        self.assertFalse(self.b.running[tk.DAEMON])                                 # not before it is promoted

    def test_run_again_exports_nothing_twice(self):
        line = self.admitted()
        self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertEqual(json.loads(self.b.files[rj.JOINED]), {"epoch": 3, "member_id": self.member_id})
        self.b.dirs.add(etcdconf.DATA_DIR)                                          # the joined store's directory
        self.b.calls = []
        export, said = self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertIsNone(export)
        self.assertIn("is learner %s's, joined at epoch 3: kept" % self.member_id, said)
        self.assertFalse(any(c[0] == tk.ETCDUTL for c in self.b.calls))
        self.assertIn(etcdconf.DATA_DIR, self.b.dirs)

    def test_abandoned_then_admitted_again_the_old_learner_s_directory_is_set_aside(self):
        """05: a removed learner's directory is never started as the new one; it is kept aside, and the export stays."""
        line = self.admitted()
        self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.b.dirs.add(etcdconf.DATA_DIR)
        first = self.member_id
        self.quiet(rj.abandon, self.a, self.chain, "a", "b")
        line = self.admitted()
        self.assertNotEqual(self.member_id, first)
        self.b.calls = []
        export, said = self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertIsNone(export)
        aside = etcdconf.DATA_DIR + ".abandoned-e3-1"
        self.assertIn(aside, self.b.dirs)
        self.assertNotIn(etcdconf.DATA_DIR, self.b.dirs)
        self.assertIn(etcdconf.DATA_DIR + ".divergent-e3-r4689", self.b.dirs)        # the divergent tail, untouched
        self.assertFalse(any(c[0] == tk.ETCDUTL for c in self.b.calls))
        self.assertEqual(json.loads(self.b.files[rj.JOINED])["member_id"], self.member_id)
        self.assertIn("set aside at %s (kept)" % aside, said)

    def test_a_crash_before_the_marker_sets_the_directory_aside_too(self):
        line = self.admitted()
        self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.b.dirs.add(etcdconf.DATA_DIR)
        del self.b.files[rj.JOINED]
        _, said = self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertIn(etcdconf.DATA_DIR + ".abandoned-e3-1", self.b.dirs)

    def test_the_record_comes_first_and_a_crash_before_the_rename_completes_it(self):
        """05: the digest is never lost: the record is written before the rename, and a record alone finishes it."""
        line = self.admitted()
        order = []
        write, rename = self.b.write, self.b.rename
        self.b.write = lambda path, text, owner=None, mode=0o644: (order.append(("write", path)), write(path, text, owner, mode))
        self.b.rename = lambda src, dst: (order.append(("rename", dst)), rename(src, dst))
        self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        export = etcdconf.DATA_DIR + ".divergent-e3-r4689"
        self.assertLess(order.index(("write", export + ".json")), order.index(("rename", export)))
        self.setUp()
        line = self.admitted()
        record = {"node_id": "b", "epoch": 3, "revision": 4689, "db_sha256": "cd" * 32, "kept_at": export}
        self.b.files[export + ".json"] = json.dumps(record)                          # written, then the crash: no rename
        self.b.calls = []
        got, said = self.quiet(rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertEqual(got, export)
        self.assertIn(export, self.b.dirs)
        self.assertEqual(json.loads(self.b.files[export + ".json"])["db_sha256"], "cd" * 32)     # the first digest, kept
        self.assertFalse(any(c[0] == tk.ETCDUTL for c in self.b.calls))

    def test_a_wrong_configuration_refuses_before_anything_is_stopped_or_moved(self):
        """CodeRabbit on #515: judged first, so a wrong configuration leaves the node serving and its data where it was."""
        line = self.admitted()
        self.b.files[etcdconf.CONFIG_PATH] = config_for("c", self.chain[-1])
        self.refused("etcd's configuration is c's, not b's", rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertEqual(self.b.calls, [])
        self.assertEqual(self.b.dirs, {etcdconf.DATA_DIR})
        self.assertTrue(self.b.running[tk.UNIT] and self.b.running[tk.DAEMON])

    def test_it_must_answer_as_the_learner_admit_made(self):
        line = self.admitted()
        self.b.member_id = 0x1234
        self.refused("answers as member 1234, not the learner %s admit made" % self.member_id, rj.join, self.b, self.chain, "b", line,
                     self.member_id)
        self.assertNotIn(rj.JOINED, self.b.files)

    def test_the_initial_cluster_is_the_manifest_s_members_at_their_mesh_urls(self):
        line = self.admitted()
        a_url, b_url = url(self.chain[-1], "a"), url(self.chain[-1], "b")
        self.refused("initial-cluster gives a at https://[fd72:6567:6c61::9]:2380", rj.join, self.b, self.chain, "b",
                     "a=https://[fd72:6567:6c61::9]:2380,b=" + b_url, self.member_id)
        self.refused("this node included", rj.join, self.b, self.chain, "b", "a=" + a_url, self.member_id)
        self.refused("z is not an etcd member", rj.join, self.b, self.chain, "b", line + ",z=" + b_url, self.member_id)
        self.refused("the member ID is the hex admit said", rj.join, self.b, self.chain, "b", line, "3D4F")
        self.assertEqual(self.b.calls, [])                                          # nothing stopped, nothing moved

    def test_it_must_answer_as_a_learner_holding_the_survivor_s_state_epoch(self):
        line = self.admitted()
        self.b.learner = False
        self.refused("answers as a voting member before any promotion", rj.join, self.b, self.chain, "b", line, self.member_id)
        self.setUp()
        line = self.admitted()
        self.b.holds_epoch = False
        self.refused("holds no state-epoch entry", rj.join, self.b, self.chain, "b", line, self.member_id)
        self.assertEqual(len(self.b.sleeps), rj.JOIN_TRIES - 1)                     # waited, bounded, then refused
        self.setUp()
        line = self.admitted()
        forged = self.cluster.value                                                  # a well-formed signature by b's key
        self.cluster.value = dict(forged, signature=p256_sig(NODE_KEYS["b"], opstate.state_epoch_message(forged["entry"])))
        self.refused("state-epoch entry signature does not verify", rj.join, self.b, self.chain, "b", line, self.member_id)
        self.setUp()
        line = self.admitted()
        self.b.cluster_id = CLUSTER + 1                                              # joined some other store
        self.refused("names cluster %016x; it is stored in cluster %016x" % (CLUSTER, CLUSTER + 1), rj.join, self.b, self.chain, "b", line, self.member_id)


class Promote(Case):
    def test_promoted_once_in_sync_retrying_while_etcd_says_it_is_not(self):
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.cluster.sync_after = 3
        _, said = self.quiet(rj.promote, self.a, self.chain, "a", "b")
        self.assertEqual(self.a.sleeps, [rj.PROMOTE_PAUSE_S] * 3)
        self.assertIn([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "member", "promote", "3d4f5dd237552cf1"], self.a.calls)
        self.assertNotIn("isLearner", self.cluster.members[1])
        self.assertIn("b promoted", said)

    def test_bounded_and_any_other_error_refused_at_once(self):
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.cluster.sync_after = rj.PROMOTE_TRIES
        self.refused("still not in sync after 300 s: run promote again, or abandon it", rj.promote, self.a, self.chain, "a", "b")
        self.a.run = lambda argv, input=None: (subprocess.CompletedProcess([], 1, "", "Error: permission denied")
                                               if "promote" in argv else FakeEtcd.run(self.a, argv, input))
        self.refused("failed: Error: permission denied", rj.promote, self.a, self.chain, "a", "b")
        self.refused("c is not a member: admit it first", rj.promote, self.a, self.chain, "a", "c")

    def test_a_promote_that_said_yes_is_read_back(self):
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.a.run = lambda argv, input=None: (subprocess.CompletedProcess([], 0, "Member promoted", "")
                                               if "promote" in argv else FakeEtcd.run(self.a, argv, input))
        self.refused("b is not a voting member after its promotion", rj.promote, self.a, self.chain, "a", "b")


class Finish(Case):
    def test_the_daemon_starts_only_on_a_voting_member(self):
        self.b.learner = True
        self.b.running[tk.DAEMON] = False
        self.refused("still a learner: promote it on the survivor first", rj.finish, self.b, self.chain, "b")
        self.assertFalse(self.b.running[tk.DAEMON])
        self.b.learner = False
        _, said = self.quiet(rj.finish, self.b, self.chain, "b")
        self.assertTrue(self.b.running[tk.DAEMON])
        self.assertIn("voting member of cluster %016x at state epoch 2" % CLUSTER, said)


class Abandon(Case):
    def test_only_a_learner_is_removed(self):
        self.quiet(rj.admit, self.a, self.chain, "a", "b")
        self.quiet(rj.abandon, self.a, self.chain, "a", "b")
        self.assertEqual([x.get("name") for x in self.cluster.members], ["a"])
        self.refused("a is a voting member: abandon removes only a learner", rj.abandon, self.a, self.chain, "a", "a")


class Main(unittest.TestCase):
    def test_config_first_and_a_refusal_is_said(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(rj.main(["--config", "/nonexistent/node.json", "admit", "--node", "b"]), 1)
        self.assertIn("TAKEOVER: REFUSED:", out.getvalue())
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            rj.main(["join"])


if __name__ == "__main__":
    unittest.main()
