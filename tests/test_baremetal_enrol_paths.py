"""regalia-node enrol paths (#190, design steps 6 and 7): the AKs both ways as regalia-sync, then this node's LUKS
path from every peer that may authorize, each journalled; local.bin is removed only after EVERY path is, as the
last journal step. The peer exchange itself is tests/test_baremetal_enrolpeer.py; here it is stood in for."""
import hashlib
import io
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import enrol, enrolpeer, node as node_module
from deploy.baremetal import membership as m


class FakeNode:
    node_id, tcti, runtime, cfg = "a", None, "/run/regalia", {"pcrs": [7, 11]}

    def __init__(self, cfg, run):
        pass

    def manifest(self):
        return {"epoch": 1}


class Paths(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.dir, self.esp = self.d + "/enrol", self.d + "/esp"
        enrol._safe_directory(self.dir)
        with open(self.dir + "/bundle.json", "w") as f:
            f.write('{"schema": "%s", "node_id": "a", "ek_name": "e", "ak_name": "k", "wg_service_pub": "s", "wg_boot_pub": "b"}'
                    % enrol.SCHEMA_BUNDLE)
        self.journal = enrol.Journal(self.dir, "a")
        enrol.local_contribution(self.journal, self.dir)
        os.makedirs(self.esp + "/loader/credentials")
        sealed = b"c2VhbGVk\nbG9jYWw=\n"
        with open(self.esp + "/loader/credentials/regalia.unlock-local.cred", "wb") as f:
            f.write(sealed)
        self.journal.done("seal", files={"regalia.unlock-local.cred": {"sha256": hashlib.sha256(sealed).hexdigest(), "size": len(sealed)}})
        self.asked, self.keys = [], 0
        self.refuse = set()
        for target, value in ((node_module, "Node"), ):
            patcher = unittest.mock.patch.object(target, value, FakeNode)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, value in (("load", lambda path: {}), ("boot_session", lambda run_dir: ("5e" * 32, b"session key"))):
            patcher = unittest.mock.patch.object(node_module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(enrol, "peers_to_enrol", lambda manifest, node_id: ["b", "c"])
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(enrol, "_ask_for", lambda node, manifest, peer: peer)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.records = []

        def write_record(journal, directory, node, manifest, peers, run=None):        # step 8: test_baremetal_enrol_record.py
            self.records.append(list(peers))
            journal.done("record", sha256="ab" * 32)
        patcher = unittest.mock.patch.object(enrol, "write_record", write_record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def request_path(self, manifest, node_id, peer, ask, session, quote, local, sealed_local, device, recovery, run):
        self.asked.append((peer, session, local, sealed_local, device, recovery))
        if peer in self.refuse:
            raise m.Refused("%s did not answer" % peer)
        return {"path_epoch": 1, "keyslot": 2 + len(self.asked)}

    def recovery(self):
        self.keys += 1
        return b"recovery key"

    def paths(self, aks=None):
        with unittest.mock.patch.object(enrolpeer, "request_path", self.request_path):
            return enrol.enrol_paths(self.dir, self.esp, self.recovery, aks=aks or (lambda config: {"b": "ok", "c": "ok"}),
                                     out=io.StringIO(), config_path="/etc/regalia/node.json")

    def state(self, step):
        return enrol.Journal(self.dir, "a").state(step)          # as the run left it on disk

    def local(self):
        return os.path.join(self.dir, enrol.LOCAL_FILE)

    def test_a_path_from_every_peer_then_local_bin_goes_last(self):
        with open(self.local(), "rb") as f:
            local = f.read()
        self.assertEqual(self.paths(), [])
        self.assertEqual([a[0] for a in self.asked], ["b", "c"])
        for peer, session, given, sealed_local, device, key in self.asked:
            self.assertEqual((session, given, sealed_local, device, key),
                             (("5e" * 32, b"session key"), local, "c2VhbGVkbG9jYWw=", enrol.ROOT_DEVICE, b"recovery key"))
        self.assertEqual(self.keys, 1, "the recovery key is asked for once")
        self.assertFalse(os.path.exists(self.local()))
        steps = enrol.Journal(self.dir, "a").doc["steps"]
        self.assertEqual([steps["path:b"]["keyslot"], steps["path:c"]["keyslot"]], [3, 4])
        self.assertEqual((steps["paths"]["state"], steps["record"]["state"], steps["local_removed"]["state"]), ("done", "done", "done"))
        self.assertEqual(self.records, [["b", "c"]], "the record is written once, with every peer, before local.bin goes")
        self.assertEqual(self.paths(), [])                      # again: nothing more to do
        self.assertEqual(len(self.asked), 2)

    def test_a_peer_that_does_not_answer_keeps_local_bin_and_a_rerun_finishes(self):
        self.refuse = {"c"}
        missing = self.paths()
        self.assertEqual(len(missing), 1)
        self.assertIn("c (c did not answer)", missing[0])
        self.assertTrue(os.path.exists(self.local()), "local.bin stays while a peer has no path")
        self.assertIsNone(self.state("paths"))
        self.refuse = set()
        self.assertEqual(self.paths(), [])
        self.assertEqual([a[0] for a in self.asked], ["b", "c", "c"], "b's journalled path is not asked for again")
        self.assertFalse(os.path.exists(self.local()))

    def test_a_peer_whose_ak_step_failed_is_named_and_not_asked_for_a_path(self):
        missing = self.paths(aks=lambda config: {"b": "ok", "c": "the source refused: no live heartbeat"})
        self.assertIn("c (AK step: the source refused: no live heartbeat)", missing[0])
        self.assertEqual([a[0] for a in self.asked], ["b"])
        self.assertTrue(os.path.exists(self.local()))

    def test_a_crash_between_paths_done_and_the_unlink_is_finished_by_the_rerun(self):
        with unittest.mock.patch.object(enrol, "_remove_local", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.paths()
        self.assertEqual(self.state("paths"), "done")
        self.assertTrue(os.path.exists(self.local()))
        self.assertEqual(self.paths(), [])
        self.assertFalse(os.path.exists(self.local()))
        self.assertEqual(self.state("local_removed"), "done")

    def test_a_sealed_credential_this_enrolment_did_not_seal_is_refused(self):
        with open(self.esp + "/loader/credentials/regalia.unlock-local.cred", "ab") as f:
            f.write(b"x")
        with self.assertRaisesRegex(enrol.Refused, "is not the credential this enrolment sealed"):
            self.paths()
        self.assertEqual(self.asked, [])

    def test_nothing_before_the_seal(self):
        self.journal.doc["steps"].pop("seal")
        enrol._atomic_json(self.journal.path, self.journal.doc)
        with self.assertRaisesRegex(enrol.Refused, "not sealed yet"):
            self.paths()

    def test_local_bin_is_never_removed_before_every_path_and_the_record_are_journalled(self):
        with self.assertRaisesRegex(enrol.Refused, "only once every peer's path is journalled"):
            enrol._remove_local(self.journal, self.dir)
        self.journal.done("paths", peers=["b", "c"])
        with self.assertRaisesRegex(enrol.Refused, "only once the enrolment record is written"):
            enrol._remove_local(self.journal, self.dir)
        self.assertTrue(os.path.exists(self.local()))


class Peers(unittest.TestCase):
    def test_every_other_node_that_may_authorize(self):
        manifest = {"nodes": [{"node_id": n} for n in "abcd"]}
        with unittest.mock.patch.object(m, "may", lambda manifest, node, what: node != "d"):
            self.assertEqual(enrol.peers_to_enrol(manifest, "a"), ["b", "c"])


if __name__ == "__main__":
    unittest.main()
