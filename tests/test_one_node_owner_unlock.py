"""Exercise the owner-off verdict and the actual fail-closed shell launcher."""
import ast
from contextlib import contextmanager
import os
import socket
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from tests.test_one_node_revocation import one_node, threenode
from tests.test_baremetal_membership_v5 import single5


class OwnerOff(unittest.TestCase):
    def test_only_an_exhausted_owner_connection_attempt_without_a_key_passes(self):
        result = dict(rc=1, peer=None, marker=False, key_delivered=False,
                      stderr="regalia-unlock: attempt 1: owner (path epoch 1): hello: the transport failed (no connection); "
                             "asking again in 2s\nregalia-unlock: no peer helped in 1 attempts\n")
        before, after = (0, 0, 0), (100, 120, 88)
        self.assertTrue(one_node.owner_connection_refused(result, before, after))
        for change in (dict(rc="timeout"), dict(rc=2), dict(rc=-11), dict(rc=0), dict(key_delivered=True),
                       dict(peer="owner"), dict(marker=True), dict(stderr="invalid config"),
                       dict(stderr="regalia-unlock: no peer helped in 1 attempts"),
                       dict(stderr=result["stderr"].replace("owner (", "other ("))):
            with self.subTest(change=change):
                self.assertFalse(one_node.owner_connection_refused(dict(result, **change), before, after))

    def test_missing_or_one_way_peer_traffic_cannot_pass_owner_off(self):
        result = dict(rc=1, peer=None, marker=False, key_delivered=False,
                      stderr="regalia-unlock: attempt 1: owner (path epoch 1): hello: the transport failed (no connection); "
                             "asking again in 2s\nregalia-unlock: no peer helped in 1 attempts\n")
        for before, after in ((None, (100, 120, 88)), ((0, 0, 0), None),
                              ((100, 120, 88), (100, 120, 88)), ((0, 0, 0), (0, 10, 10)),
                              ((0, 0, 0), (100, 0, 11)), ((0, 0, 0), (100, 11, 0)),
                              ((101, 1, 1), (100, 2, 2)), ((100, 20, 20), (101, 10, 30))):
            with self.subTest(before=before, after=after):
                self.assertFalse(one_node.owner_connection_refused(result, before, after))

    def test_wireguard_stats_match_the_manifest_peer_in_both_commands(self):
        cluster = threenode.Cluster.__new__(threenode.Cluster)
        cluster.manifest = single5(1, "")
        peer = threenode.wgsvc.wg_key(cluster.manifest["nodes"][0]["wg_boot_pub"])
        outputs = {"latest-handshakes": f"other 300\n{peer} 100\n", "transfer": f"other 999 999\n{peer} 120 88\n"}
        cluster.owner = SimpleNamespace(in_ns=lambda *argv: SimpleNamespace(stdout=outputs[argv[-1]]))
        self.assertEqual(cluster.owner_boot_traffic("a"), (100, 120, 88))
        for missing in ("other 999 999\n", f"{peer} 1\n", f"{peer} -1 88\n", f"{peer} 120 88\n{peer} 10 20\n"):
            with self.subTest(transfer=missing):
                outputs["transfer"] = missing
                self.assertIsNone(cluster.owner_boot_traffic("a"))

    def test_scenario_keeps_the_tunnel_and_client_limits_when_enabling_the_responder(self):
        tree = ast.parse(Path(one_node.__file__).read_text())
        scenario = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "scenario")
        attempt = next(n for n in scenario.body if isinstance(n, ast.With) and
                       ast.unparse(n.items[0].context_expr) == "cluster.owner_tunnel('a')")
        calls = []
        active = set()

        @contextmanager
        def state(name):
            active.add(name)
            try:
                yield ["SENT: signed response"]
            finally:
                active.remove(name)

        def unlock(name, **limits):
            calls.append((name, limits, frozenset(active)))
            return dict(rc=0, peer="owner", marker=True)

        traffic_order = []

        def traffic(name):
            traffic_order.append((name, frozenset(active), len(calls)))
            return (100, 120, 88) if calls else (0, 0, 0)

        cluster = SimpleNamespace(owner_boot_traffic=traffic, owner_tunnel=lambda _: state("tunnel"), owner_answering=lambda _: state("responder"),
                                  unlock=unlock, stop=lambda _: None)
        exec(compile(ast.Module(body=[attempt], type_ignores=[]), one_node.__file__, "exec"),
             dict(cluster=cluster, ok=lambda *_: None, owner_connection_refused=lambda *_: False,
                  unlock=one_node.unlock, until=threenode.until))
        limits = dict(timeout=90, rounds=1)
        self.assertEqual(calls, [("a", limits, {"tunnel"}), ("a", limits, {"tunnel", "responder"})])
        self.assertEqual(traffic_order, [("a", {"tunnel"}, 0), ("a", {"tunnel"}, 1)])

    def test_failed_mount_prevents_launch_but_success_runs_the_client(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            mount = work / "mount"
            marker = work / "launched"
            script = threenode.blind_mount_script([work / "owner space", work / "second"])
            argv = ["bash", "-c", script, "bash", "touch", str(marker)]
            env = dict(os.environ, PATH=directory + os.pathsep + os.environ["PATH"])
            mount.write_text('#!/bin/sh\ncase "$*" in *second) exit 17;; esac\n')
            mount.chmod(0o755)
            self.assertEqual(subprocess.run(argv, env=env).returncode, 17)
            self.assertFalse(marker.exists())
            mount.write_text("#!/bin/sh\nexit 0\n")
            subprocess.run(argv, env=env, check=True)
            self.assertTrue(marker.exists())

class UnlockReplies(unittest.TestCase):
    def launch(self, tx, *frames):
        program = "import os,sys; [os.write(int(sys.argv[1]), frame.encode()) for frame in sys.argv[2:]]"
        client = subprocess.Popen([sys.executable, "-c", program, str(tx.fileno()), *frames], pass_fds=(tx.fileno(),),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(client.__exit__, None, None, None)
        return client

    def test_wait_drains_a_key_from_a_client_that_already_exited(self):
        rx, tx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with rx, tx:
            client = self.launch(tx, "-", "+fixture")
            self.assertEqual(client.wait(timeout=5), 0)
            self.assertTrue(threenode.wait_unlock_reply(rx, client, time.monotonic() + 1),
                            "queued positive datagram was missed after client exit")

    def test_communicate_completion_drains_a_reply_that_arrived_after_polling(self):
        rx, tx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with rx, tx:
            self.assertFalse(threenode.drain_unlock_reply(rx))
            client = self.launch(tx, "+fixture")
            rc, _, key = threenode.finish_unlock_client(client, rx, b"", 5)
            self.assertEqual(rc, 0)
            self.assertTrue(key, "queued positive datagram was missed after communicate")

    def test_exited_client_and_empty_queue_return_no_key(self):
        rx, tx = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with rx, tx:
            client = self.launch(tx, "-")
            self.assertEqual(client.wait(timeout=5), 0)
            self.assertFalse(threenode.wait_unlock_reply(rx, client, time.monotonic() + 1))
            rc, _, key = threenode.finish_unlock_client(client, rx, b"", 5)
            self.assertEqual(rc, 0)
            self.assertFalse(key)
