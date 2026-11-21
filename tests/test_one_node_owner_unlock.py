"""Exercise the owner-off verdict and the actual fail-closed shell launcher."""
import ast
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from tests.test_one_node_revocation import one_node, threenode


class OwnerOff(unittest.TestCase):
    def test_only_an_exhausted_owner_connection_attempt_without_a_key_passes(self):
        result = dict(rc=1, peer=None, marker=False, key_delivered=False,
                      stderr="regalia-unlock: attempt 1: owner (path epoch 1): hello: the transport failed (no connection); "
                             "asking again in 2s\nregalia-unlock: no peer helped in 1 attempts\n")
        self.assertTrue(one_node.owner_connection_refused(result))
        for change in (dict(rc="timeout"), dict(rc=2), dict(rc=-11), dict(rc=0), dict(key_delivered=True),
                       dict(peer="owner"), dict(marker=True), dict(stderr="invalid config"),
                       dict(stderr="regalia-unlock: no peer helped in 1 attempts"),
                       dict(stderr=result["stderr"].replace("owner (", "other ("))):
            with self.subTest(change=change):
                self.assertFalse(one_node.owner_connection_refused(dict(result, **change)))

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

        cluster = SimpleNamespace(owner_tunnel=lambda _: state("tunnel"), owner_answering=lambda _: state("responder"),
                                  unlock=unlock, stop=lambda _: None)
        exec(compile(ast.Module(body=[attempt], type_ignores=[]), one_node.__file__, "exec"),
             dict(cluster=cluster, ok=lambda *_: None, owner_connection_refused=lambda _: False,
                  unlock=one_node.unlock, until=threenode.until))
        limits = dict(timeout=90, rounds=1)
        self.assertEqual(calls, [("a", limits, {"tunnel"}), ("a", limits, {"tunnel", "responder"})])

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
