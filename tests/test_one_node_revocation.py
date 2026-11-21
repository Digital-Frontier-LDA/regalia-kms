"""Exercise one-node's actual final revocation assertion without starting its Linux fixture.

Compile just the assertion's three statements from scenario(): the expected reason, the poll,
and its verdict. This keeps the inline predicate under test without adding a production helper
or importing code that manages namespaces, software TPMs, or services.
"""
import ast
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

from deploy.baremetal import admission, membership
from tests.test_baremetal_membership_v5 import single5
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "e2e" / "one-node.py"
spec = importlib.util.spec_from_file_location("one_node_revocation_fixture", SOURCE)
one_node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(one_node)
threenode = one_node.threenode

NO_LEASE = "the source refused: a may not serve under epoch 2: no lease"


def denial():
    return dict(event="admission-renew", outcome="DENY", peer="a", epoch=2, reason=NO_LEASE)


class RevocationDenial(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tree = ast.parse(SOURCE.read_text(), str(SOURCE))
        scenario = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "scenario")
        start = next(i for i, node in enumerate(scenario.body) if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "first_refusal" for target in node.targets))
        cls.assertion = compile(ast.Module(body=scenario.body[start:start + 3], type_ignores=[]), str(SOURCE), "exec")

    def accepted(self, events, *, collected=True, read_error=False):
        verdicts = []
        now = 0

        def sleep(seconds):
            nonlocal now
            now += seconds

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            lines = [json.dumps(dict(e, at=10)).encode() + b"\n" for e in events]
            path.write_bytes(b"".join(lines))
            cluster = threenode.Cluster.__new__(threenode.Cluster)
            cluster.nodes = {"a": SimpleNamespace(admission_log=path.parent)}
            stream = [{"detail": {"line_sha256": hashlib.sha256(line).hexdigest()}} for line in lines] if collected else []
            cluster.audit_stream = lambda *_: stream
            cluster._trail_path = lambda *_: path
            if read_error:
                cluster.audit_stream = lambda *_: (_ for _ in ()).throw(OSError("collector unavailable"))

            def trail(*args):
                if read_error and now < 60:
                    raise OSError("poll failed, diagnostic reread succeeds")
                return events

            with patch.object(threenode, "time", SimpleNamespace(monotonic=lambda: now, sleep=sleep)):
                exec(self.assertion, {"cluster": cluster, "admission_trail": trail, "committed_at": 10,
                                      "until": threenode.until, "ok": lambda condition, *_: verdicts.append(condition)})
        self.assertEqual(len(verdicts), 1)
        return verdicts[0]

    def test_polling_error_cannot_pass_even_if_diagnostic_reread_succeeds(self):
        self.assertFalse(self.accepted([], read_error=True))

    def test_local_denial_without_collector_record_cannot_pass(self):
        self.assertFalse(self.accepted([denial()], collected=False))

    def test_sync_s_peer_a_epoch_two_no_lease_denial_satisfies_the_assertion(self):
        self.assertTrue(self.accepted([denial()]), "the actual sync refusal must satisfy step 5")

    def test_another_peer_or_the_aggregate_denial_cannot_satisfy_the_assertion(self):
        for peer in ("b", ""):
            with self.subTest(peer=peer):
                event = denial()
                event["peer"] = peer
                self.assertFalse(self.accepted([event]), "another peer's refusal must not prove a's revocation")

    def test_a_denial_from_another_epoch_cannot_satisfy_the_assertion(self):
        for epoch in (1, 3):
            with self.subTest(epoch=epoch):
                event = denial()
                event["epoch"] = epoch
                self.assertFalse(self.accepted([event]), "only the committed revocation epoch may satisfy step 5")

    def test_a_different_reason_cannot_satisfy_the_assertion(self):
        for reason in ("the manifest leaves no node this peer could attest", "no lease",
                       "the source refused: b may not serve under epoch 2: no lease", NO_LEASE + " (unrelated)"):
            with self.subTest(reason=reason):
                event = denial()
                event["reason"] = reason
                self.assertFalse(self.accepted([event]), "step 5 needs the exact sync no-lease refusal")

    def test_a_different_event_or_outcome_cannot_satisfy_the_assertion(self):
        for field, value in (("event", "admission-serving"), ("outcome", "ALLOW")):
            with self.subTest(field=field):
                event = denial()
                event[field] = value
                self.assertFalse(self.accepted([event]))

    def test_an_empty_trail_or_missing_fields_cannot_satisfy_the_assertion(self):
        self.assertFalse(self.accepted([]))
        for field in denial():
            with self.subTest(field=field):
                event = denial()
                del event[field]
                self.assertFalse(self.accepted([event]))

    def test_the_expected_denial_is_found_among_unrelated_events(self):
        other = denial()
        other["peer"] = "b"
        self.assertTrue(self.accepted([{}, other, denial()]))


class Shutdown(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.parent = self.directory / "run" / "admission"
        self.parent.mkdir(parents=True)
        self.path = self.parent / "admission.json"
        self.owner_uid = os.getuid()
        identity = Mock(side_effect=lambda name: SimpleNamespace(pw_uid=self.owner_uid))
        identity_patch = patch.object(one_node, "pwd", SimpleNamespace(getpwnam=identity), create=True)
        identity_patch.start()
        self.addCleanup(identity_patch.stop)
        self.identity = identity
        self.journal = self.path.with_name("audit.jsonl")
        first = single5(1, "")
        self.tip = single5(2, membership.digest(first))
        self.previous = {"session_id": "ab" * 32, "boot_id": "2462ce77-2a3f-4774-b553-47399e233251"}
        self.document = dict(schema=admission.SCHEMA, node_id="a", **self.previous, epoch=2,
                             manifest_digest=membership.digest(self.tip),
                             hsm_serials=" ".join(self.tip["nodes"][0]["hsm_serials"]), lease_issued_at=admission.NEVER,
                             requested_boottime_ms=0, **admission.NO_STATE, serve_until_boottime_ms=0, mode="lease",
                             reason="revoked")
        self.now = 0
        self.kms = SimpleNamespace(state=self.path.parent, sign=Mock(side_effect=self.sign))
        self.kms.denied_not_admitted = lambda request_id: one_node.Daemon.denied_not_admitted(self.kms, request_id)
        self.outcome = "not-admitted"
        clock = SimpleNamespace(monotonic=lambda: self.now, sleep=self.advance)
        for module in (one_node, threenode):
            patcher = patch.object(module, "time", clock)
            patcher.start()
            self.addCleanup(patcher.stop)

    def advance(self, seconds):
        self.now += seconds

    def sign(self, message, *, request_id, timeout):
        self.record(request_id, self.outcome)
        return 503, {"request_id": request_id}, None

    def record(self, request_id, outcome):
        with self.journal.open("a") as audit:
            audit.write(json.dumps(dict(request_id=request_id, decision="deny", operation="sign", outcome=outcome)) + "\n")

    def read(self):
        return one_node.non_serving_admission(self.path, self.tip, self.previous)

    def observe(self, read=None):
        return one_node.observe_shutdown(self.kms, read or self.read, 0, 3)

    def test_reason_accepts_the_printable_ascii_length_boundary(self):
        document = dict(self.document, reason=" ~" + "x" * (admission.ADMISSION_REASON_LIMIT - 2))
        self.path.write_text(json.dumps(document))
        self.assertEqual(self.read(), document)

    def test_reason_rejects_printable_unicode_and_ascii_controls(self):
        for reason in ("révocation", "revoked\x7f", "revoked\n"):
            with self.subTest(reason=reason):
                self.path.write_text(json.dumps(dict(self.document, reason=reason)))
                self.assertIsNone(self.read())

    def test_reason_rejects_one_byte_over_the_limit(self):
        reason = "x" * (admission.ADMISSION_REASON_LIMIT + 1)
        self.path.write_text(json.dumps(dict(self.document, reason=reason)))
        self.assertIsNone(self.read())

    def test_valid_admission_uses_configured_owner(self):
        self.path.write_text(json.dumps(self.document))
        self.assertEqual(self.read(), self.document)
        self.identity.assert_called_once_with("regalia-admission")

    def test_symlinks_at_file_parent_or_higher_ancestor_are_refused(self):
        self.path.write_text(json.dumps(self.document))
        target = self.parent / "real.json"
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaisesRegex((OSError, membership.Refused), ".*"):
            self.read()
        self.path.unlink()
        target.rename(self.path)
        for real in (self.parent, self.parent.parent):
            with self.subTest(real=real):
                moved = real.with_name(real.name + "-real")
                real.rename(moved)
                real.symlink_to(moved, target_is_directory=True)
                try:
                    with self.assertRaisesRegex(membership.Refused, "directory"):
                        self.read()
                finally:
                    real.unlink()
                    moved.rename(real)

    def test_writable_file_and_immediate_parent_are_refused(self):
        self.path.write_text(json.dumps(self.document))
        for path in (self.path, self.parent):
            with self.subTest(path=path):
                mode = path.stat().st_mode & 0o777
                path.chmod(mode | 0o020)
                try:
                    with self.assertRaisesRegex(membership.Refused, "owner or root"):
                        self.read()
                finally:
                    path.chmod(mode)

    @unittest.skipIf(os.getuid() == 0, "requires a nonroot-owned fixture")
    def test_untrusted_owner_is_refused(self):
        self.path.write_text(json.dumps(self.document))
        self.owner_uid += 1
        with self.assertRaisesRegex(membership.Refused, "owner or root"):
            self.read()

    def test_sticky_ancestor_is_allowed_but_writable_nonsticky_ancestor_is_refused(self):
        self.path.write_text(json.dumps(self.document))
        self.parent.parent.chmod(0o1777)
        self.assertEqual(self.read(), self.document)
        self.parent.parent.chmod(0o777)
        with self.assertRaisesRegex(membership.Refused, "replace"):
            self.read()

    def test_oversized_file_is_refused(self):
        self.path.write_bytes(json.dumps(self.document).encode().ljust(4097, b" "))
        with self.assertRaises(membership.Refused):
            self.read()

    def test_fifo_returns_a_regular_file_refusal_without_waiting_for_a_writer(self):
        os.mkfifo(self.path)
        script = """
import sys
import unittest
from pathlib import Path
from tests.test_one_node_revocation import Shutdown
case = Shutdown()
case.setUp()
case.path = Path(sys.argv[1])
with unittest.TestCase().assertRaisesRegex(Exception, "not a regular file"):
    case.read()
print("FIFO rejected as nonregular")
"""
        try:
            result = subprocess.run([sys.executable, "-c", script, str(self.path)], capture_output=True,
                                    text=True, timeout=6)
        except subprocess.TimeoutExpired:
            self.fail("FIFO blocked instead of returning a nonregular-file refusal")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "FIFO rejected as nonregular"), result.stderr)

    def test_early_audited_503_cannot_combine_with_later_zero_and_200(self):
        self.path.write_text(json.dumps(self.document))

        def later_zero():
            return self.read() if self.now >= 1 else None

        def sign_at_time(*args, **kwargs):
            if self.now < 1:
                return self.sign(*args, **kwargs)
            return 200, {}, None

        self.kms.sign.side_effect = sign_at_time
        self.assertEqual(self.observe(later_zero), (None, 1))
        self.kms.sign.assert_called()

    def test_delayed_post_zero_audit_retains_the_response_observation_time(self):
        self.path.write_text(json.dumps(self.document))
        audit = self.kms.denied_not_admitted
        self.kms.denied_not_admitted = lambda request_id: self.now >= 5 and audit(request_id)
        self.assertEqual(self.observe(lambda: self.read() if self.now >= 1 else None), (1, 1))
        self.assertEqual(self.now, 5)
        self.assertEqual(self.kms.sign.call_count, 2)

    def test_correlated_gate_denial_and_current_zero_admission_pass(self):
        self.path.write_text(json.dumps(self.document))
        self.assertEqual(self.observe(), (0, 0))

    def test_unrelated_503_and_unrelated_audit_do_not_pass(self):
        self.path.write_text(json.dumps(self.document))
        self.record("different-request", "not-admitted")
        self.outcome = "backend-unavailable"
        self.assertEqual(self.observe(), (None, 0))

    def test_missing_malformed_stale_or_expired_file_cannot_prove_a_stop(self):
        for raw in (None, "{", "[]", json.dumps(dict(self.document, epoch=1)),
                    json.dumps(dict(self.document, session_id="12" * 32)),
                    json.dumps(dict(self.document, serve_until_boottime_ms=1)),
                    json.dumps(dict(self.document, serve_until_boottime_ms=False))):
            with self.subTest(raw=raw):
                self.now = 0
                if raw is not None:
                    self.path.write_text(raw)
                self.assertEqual(self.observe(), (None, None))

    def test_exceptions_are_not_observations(self):
        self.kms.sign.side_effect = OSError("broken socket")
        self.assertEqual(self.observe(Mock(side_effect=OSError("broken admission read"))), (None, None))

    def test_a_read_completing_after_the_shared_deadline_does_not_pass(self):
        self.path.write_text(json.dumps(self.document))

        def late_read():
            self.advance(4)
            return self.read()

        self.assertEqual(self.observe(late_read), (None, None))
        self.kms.sign.assert_not_called()

    def test_a_response_after_the_shared_deadline_does_not_pass(self):
        self.path.write_text(json.dumps(self.document))

        def late_sign(*args, **kw):
            self.advance(4)
            return self.sign(*args, **kw)

        self.kms.sign.side_effect = late_sign
        self.assertEqual(self.observe(), (None, 0))

    def test_delayed_audit_confirms_only_the_original_in_budget_response(self):
        self.path.write_text(json.dumps(self.document))
        audit = self.kms.denied_not_admitted
        self.kms.denied_not_admitted = lambda request_id: self.now >= 5 and audit(request_id)
        self.assertEqual(self.observe(), (0, 0))
        self.assertEqual(self.now, 5)
        self.assertEqual(self.kms.sign.call_count, 3)


if __name__ == "__main__":
    unittest.main()
