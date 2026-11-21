"""Exercise the owner-off verdict and the actual fail-closed shell launcher."""
import ast
from contextlib import contextmanager
import errno
import os
import socket
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from tests.test_one_node_revocation import one_node, threenode
from tests.test_baremetal_membership_v5 import single5


class OwnerOff(unittest.TestCase):
    def test_only_an_exhausted_owner_connection_attempt_without_a_key_passes(self):
        result = dict(owner_tcp_errno=errno.ECONNREFUSED, rc=1, peer=None, marker=False, key_delivered=False,
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

    def test_only_inner_tcp_refusal_qualifies_with_valid_client_and_peer_evidence(self):
        result = dict(rc=1, peer=None, marker=False, key_delivered=False,
                      stderr="regalia-unlock: attempt 1: owner (path epoch 1): hello: the transport failed (no connection); "
                             "asking again in 2s\nregalia-unlock: no peer helped in 1 attempts\n")
        before, after = (0, 0, 0), (100, 120, 88)
        for code in (None, 0, errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENODEV, errno.EACCES):
            with self.subTest(code=code):
                self.assertFalse(one_node.owner_connection_refused(dict(result, owner_tcp_errno=code), before, after))
        self.assertFalse(one_node.owner_connection_refused(result, before, after))
        self.assertTrue(one_node.owner_connection_refused(dict(result, owner_tcp_errno=errno.ECONNREFUSED), before, after))

    def test_missing_or_one_way_peer_traffic_cannot_pass_owner_off(self):
        result = dict(owner_tcp_errno=errno.ECONNREFUSED, rc=1, peer=None, marker=False, key_delivered=False,
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
        self.assertEqual(calls, [("a", dict(limits, probe_owner_off=True), {"tunnel"}), ("a", limits, {"tunnel", "responder"})])
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


class OwnerTcpProbe(unittest.TestCase):
    def boot(self):
        manifest = single5(1, "")
        site = {"boot_mesh": {"node_id": "a", "address": "10.89.0.4",
                             "owner": {"address": "10.89.0.19"}, "peers": [], "unlock_port": 7444}}
        endpoints = threenode.bootnet.unlock_endpoints(site, manifest)
        return one_node.unlock.boot_config(manifest, "a", "/dev/loop0", [7, 11], endpoints)

    def test_socket_uses_exact_node_namespace_interface_source_and_config_endpoint(self):
        boot = self.boot()
        for code in (0, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ENETUNREACH,
                     errno.EHOSTUNREACH, errno.ENODEV, errno.EACCES, None):
            with self.subTest(code=code):
                probe = MagicMock()
                probe.__enter__.return_value = probe
                probe.connect.side_effect = (TimeoutError("deadline") if code is None else OSError(code, "connect")) if code != 0 else None
                ns = Mock(side_effect=lambda _, connect: connect())
                with patch.object(threenode, "in_netns", ns), patch.object(threenode.socket, "socket", return_value=probe) as factory:
                    self.assertEqual(threenode.owner_tcp_probe("fixture-a", "10.89.0.4", boot), code)
                ns.assert_called_once()
                self.assertEqual(ns.call_args.args[0], "fixture-a")
                factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
                self.assertEqual(probe.method_calls, [
                    unittest.mock.call.settimeout(3),
                    unittest.mock.call.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"wg-boot\0"),
                    unittest.mock.call.bind(("10.89.0.4", 0)),
                    unittest.mock.call.connect(("10.89.0.19", 7444)),
                ])

    def test_namespace_or_socket_setup_refusal_does_not_prove_tcp_refusal(self):
        boot = self.boot()
        failure = OSError(errno.ECONNREFUSED, "setup")
        with patch.object(threenode, "in_netns", side_effect=failure):
            self.assertIsNone(threenode.owner_tcp_probe("fixture-a", "10.89.0.4", boot))
        for stage in ("setsockopt", "bind"):
            with self.subTest(stage=stage):
                probe = MagicMock()
                probe.__enter__.return_value = probe
                getattr(probe, stage).side_effect = failure
                with patch.object(threenode, "in_netns", side_effect=lambda _, connect: connect()), \
                        patch.object(threenode.socket, "socket", return_value=probe):
                    self.assertIsNone(threenode.owner_tcp_probe("fixture-a", "10.89.0.4", boot))
                probe.connect.assert_not_called()

    def test_probe_runs_only_on_negative_boot_after_client_completion_before_teardown(self):
        tree = ast.parse(Path(threenode.__file__).read_text())
        cluster = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Cluster")
        unlock_method = next(node for node in cluster.body if isinstance(node, ast.FunctionDef) and node.name == "unlock")
        start = next(i for i, node in enumerate(unlock_method.body) if isinstance(node, ast.Try)
                     and "finish_unlock_client" in ast.unparse(node))
        end = next(i for i, node in enumerate(unlock_method.body[start:], start)
                   if ast.unparse(node).startswith("self.abrmd_answers"))
        body = ast.unparse(ast.Module(body=unlock_method.body[start:end], type_ignores=[]))
        code = compile("def attempt():\n    mounted = False\n" + textwrap.indent(body, "    "), threenode.__file__, "exec")
        boot = self.boot()
        for requested in (True, False):
            with self.subTest(requested=requested):
                events = []

                def finish(*args):
                    events.append("client finished")
                    return 1, "", b""

                def observe(ns, source, config):
                    events.append("probe")
                    self.assertEqual((ns, source), ("fixture-a", "10.89.0.4"))
                    self.assertIs(config, boot)
                    return errno.ECONNREFUSED

                n = SimpleNamespace(ns="fixture-a", boot_address="10.89.0.4", tpm_sock="/unused", run="/unused",
                                    in_ns=lambda *args, **kwargs: events.append(("teardown", args)))
                env = dict(n=n, self=SimpleNamespace(client="client"), source="10.89.0.4", boot=boot, probe_owner_off=requested,
                           os=SimpleNamespace(environ={}, path=SimpleNamespace(exists=lambda _: False)),
                           config="/fixture.json", creds="/creds", asks="/asks", request="request", volume="/volume",
                           rounds=1, timeout=90, script="mount guard", time=SimpleNamespace(monotonic=lambda: 0),
                           subprocess=SimpleNamespace(Popen=lambda *args, **kwargs: SimpleNamespace(poll=lambda: 1),
                                                      PIPE=None, DEVNULL=None),
                           wait_unlock_reply=lambda *_: b"", finish_unlock_client=finish, owner_tcp_probe=observe,
                           reply=SimpleNamespace(close=lambda: None), result={}, mounted=False,
                           shutil=SimpleNamespace(rmtree=lambda *_: None))
                exec(code, env)
                env["attempt"]()
                self.assertEqual(events, ["client finished"] + (["probe"] if requested else []) +
                                 [("teardown", ("ip", "link", "del", "wg-boot"))])
                self.assertEqual(env["result"].get("owner_tcp_errno"), errno.ECONNREFUSED if requested else None)


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
