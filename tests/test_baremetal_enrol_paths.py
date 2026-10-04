"""regalia-node enrol paths (#190, design steps 6 and 7): the AKs both ways as regalia-sync, then this node's LUKS
path from every peer that may authorize, each journalled; local.bin is removed only after EVERY path is, as the
last journal step. The peer exchange itself is tests/test_baremetal_enrolpeer.py; here it is stood in for."""
import base64
import copy
import hashlib
import io
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import enrol, enrolpeer, node as node_module, unlock
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
        # a sealed local half as systemd-creds writes it (a TPM-only header), wrapped over lines as on the ESP
        blob = base64.b64encode(bytes.fromhex(next(iter(unlock.LOCAL_KEY_TYPES))) + b"local half").decode()
        self.sealed_local = blob
        sealed = (blob[:20] + "\n" + blob[20:] + "\n").encode()
        with open(self.esp + "/loader/credentials/regalia.unlock-local.cred", "wb") as f:
            f.write(sealed)
        self.journal.done("seal", files={"regalia.unlock-local.cred": {"sha256": hashlib.sha256(sealed).hexdigest(), "size": len(sealed)}})
        self.asked, self.keys, self.given = [], 0, []
        self.refuse = set()
        self.header = {"keyslots": {"0": {}}, "tokens": {}}         # keyslot 0: the recovery key
        patcher = unittest.mock.patch.object(unlock, "luks_meta", lambda device, run=None: copy.deepcopy(self.header))
        patcher.start()
        self.addCleanup(patcher.stop)
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

    def request_path(self, manifest, node_id, peer, ask, session, quote, local, sealed_local, device, recovery, run):
        self.asked.append((peer, session, local, sealed_local, device, bytes(recovery)))
        self.given.append(recovery)
        if peer in self.refuse:
            raise m.Refused("%s did not answer" % peer)
        slot = 2 + len(self.asked)
        self.path(peer, slot, sealed_local)
        return {"path_epoch": 1, "keyslot": slot}

    def path(self, peer, slot, sealed_local=None):
        """A path token from `peer` in the header, as unlock.enrol_path writes it."""
        self.header["keyslots"][str(slot)] = {}
        self.header["tokens"][str(len(self.header["tokens"]))] = {
            "type": unlock.TOKEN_TYPE, "keyslots": [str(slot)], "version": unlock.VERSION, "target": "a", "peer": peer,
            "path_epoch": 1, "local": sealed_local or self.sealed_local}

    def drop(self, peer):
        """`peer`'s token and keyslot gone from the header (a reseal, a luksKillSlot)."""
        for i, token in list(self.header["tokens"].items()):
            if token["peer"] == peer:
                del self.header["tokens"][i]
                del self.header["keyslots"][token["keyslots"][0]]

    def recovery(self):
        self.keys += 1
        return bytearray(b"recovery key")

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
                             (("5e" * 32, b"session key"), local, self.sealed_local, enrol.ROOT_DEVICE, b"recovery key"))
        self.assertEqual(self.keys, 1, "the recovery key is asked for once")
        self.assertEqual(self.given[0], bytearray(len(b"recovery key")), "and zeroed once used")
        self.assertFalse(os.path.exists(self.local()))
        steps = enrol.Journal(self.dir, "a").doc["steps"]
        self.assertEqual([steps["path:b"]["keyslot"], steps["path:c"]["keyslot"]], [3, 4])
        self.assertEqual((steps["paths"]["state"], steps["local_removed"]["state"]), ("done", "done"))
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

    def test_local_bin_is_never_removed_before_every_path_is_journalled(self):
        with self.assertRaisesRegex(enrol.Refused, "only once every peer's path is journalled"):
            enrol._remove_local(self.journal, self.dir, lambda peers: [])
        self.assertTrue(os.path.exists(self.local()))

    def test_a_journalled_path_the_header_lost_keeps_local_bin_and_is_asked_for_again(self):
        """regalia-kms-1e on #274: local.bin goes on the header's word, read again, never the journal's alone."""
        with open(self.local(), "rb") as f:
            local = f.read()
        self.assertEqual(self.paths(), [])
        self.journal = enrol.Journal(self.dir, "a")
        steps = self.journal.doc["steps"]
        steps.pop("local_removed")                      # as if the unlink had not happened yet: put local.bin back
        enrol._atomic_json(self.journal.path, self.journal.doc)
        with open(self.local(), "wb") as f:
            f.write(local)
        self.drop("c")
        self.refuse = {"c"}
        missing = self.paths()
        self.assertEqual(len(missing), 1)
        self.assertIn("c (c did not answer)", missing[0])
        self.assertTrue(os.path.exists(self.local()), "the journal says done, the header lacks c: local.bin stays")
        self.assertEqual([a[0] for a in self.asked], ["b", "c", "c"], "c is asked for again, b is not")
        self.refuse = set()
        self.assertEqual(self.paths(), [])
        self.assertFalse(os.path.exists(self.local()))

    def test_the_last_step_itself_reads_the_header(self):
        self.journal.done("paths", peers=["b", "c"])
        with self.assertRaisesRegex(enrol.Refused, "local.bin stays: the header has no path from c"):
            enrol._remove_local(self.journal, self.dir, lambda peers: ["c"])
        self.assertTrue(os.path.exists(self.local()))

    def test_a_token_over_another_local_half_is_no_path(self):
        self.path("b", 7, sealed_local=base64.b64encode(bytes.fromhex(next(iter(unlock.LOCAL_KEY_TYPES))) + b"another").decode())
        self.assertEqual(enrol._without_path(self.header, "a", ["b"], self.sealed_local), ["b"])
        self.path("b", 8)
        self.assertEqual(enrol._without_path(self.header, "a", ["b"], self.sealed_local), [])

    def test_local_bin_is_overwritten_before_it_is_unlinked(self):
        written = []
        real = os.pwrite
        with unittest.mock.patch.object(enrol.os, "pwrite", lambda fd, data, offset: (written.append(bytes(data)), real(fd, data, offset))[1]):
            self.assertEqual(self.paths(), [])
        self.assertEqual(written, [bytes(32)])
        self.assertFalse(os.path.exists(self.local()))


class ConsoleKey(unittest.TestCase):
    """regalia-kms-1e on #274: the recovery key is read from the controlling terminal only; getpass would fall
    back to standard input (a pipe, a here-string, a script) when /dev/tty cannot be opened."""

    def test_standard_input_not_a_terminal_is_refused(self):
        with unittest.mock.patch.object(enrol.sys, "stdin", io.StringIO("piped-key\n")):
            with self.assertRaisesRegex(enrol.Refused, "standard input is not a terminal"):
                enrol.console_key("key: ")

    def test_no_controlling_terminal_is_refused(self):
        stdin = unittest.mock.Mock(isatty=lambda: True)
        with unittest.mock.patch.object(enrol.sys, "stdin", stdin):
            with self.assertRaisesRegex(enrol.Refused, "no controlling terminal"):
                enrol.console_key("key: ", tty="/nonexistent/tty")

    def test_a_key_typed_at_a_terminal_comes_back_as_a_bytearray(self):
        import pty
        controller, terminal = pty.openpty()
        self.addCleanup(os.close, controller)
        self.addCleanup(os.close, terminal)
        import threading

        def type_it():                                  # after the prompt: echo is off then, and typeahead was flushed
            prompt = b""
            while not prompt.endswith(b"key: "):
                prompt += os.read(controller, 64)
            os.write(controller, b"typed key\n")
        typist = threading.Thread(target=type_it, daemon=True)
        typist.start()
        stdin = unittest.mock.Mock(isatty=lambda: True)
        with unittest.mock.patch.object(enrol.sys, "stdin", stdin):
            typed = enrol.console_key("key: ", tty=os.ttyname(terminal))
        self.assertEqual((type(typed), typed), (bytearray, bytearray(b"typed key")))

    def test_the_paths_command_never_reads_a_pipe(self):
        """End to end, as 1e measured getpass: no controlling terminal and the key on a pipe is refused."""
        import subprocess
        import sys
        done = subprocess.run(["setsid", sys.executable, "-c", "from deploy.baremetal import enrol\nenrol.console_key('key: ')"],
                              input="piped-key\n", capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("standard input is not a terminal", done.stderr)
        self.assertNotIn("piped-key", done.stdout)


class Peers(unittest.TestCase):
    def test_every_other_node_that_may_authorize(self):
        manifest = {"nodes": [{"node_id": n} for n in "abcd"]}
        with unittest.mock.patch.object(m, "may", lambda manifest, node, what: node != "d"):
            self.assertEqual(enrol.peers_to_enrol(manifest, "a"), ["b", "c"])


if __name__ == "__main__":
    unittest.main()
