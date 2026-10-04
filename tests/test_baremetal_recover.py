"""deploy/baremetal/recover.py and owner.sign_recovery (#387): the owner as the second source when one peer is left.
The statement is domain-separated and bound to this node, this operation and this tip, for minutes; the node checks
it against the tip's owner_keys and that the chain extends what it last knew; the owner's tool judges the tip
against its own signing record, the node's counter and the audit collector's signed witness."""
import hashlib
import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat, membership as m, owner, recover, trails
from tests.test_baremetal_membership import ROOT, ROOT_PUB, sign
from tests.test_baremetal_membership_v4 import OWNER_KEYS, manifest4, nodes4, pub

T0 = 1790000000
STRANGER = Ed25519PrivateKey.generate()          # an Ed25519 key in no manifest's owner_keys


class Key:
    def __init__(self, key):
        self.key, self.signed = key, []

    def public(self):
        return pub(self.key)

    def sign(self, message):
        self.signed.append(message)
        return self.key.sign(message)


class Case(unittest.TestCase):
    def setUp(self):
        self.m1 = manifest4(1, "", nodes4())
        self.m2 = manifest4(2, m.digest(self.m1), nodes4(c="QUARANTINED"), issued_at="2026-10-04T10:00:00Z")
        self.m3 = manifest4(3, m.digest(self.m2), nodes4(c="QUARANTINED"), issued_at="2026-10-04T11:00:00Z", policy_version="p2")
        self.chain = [sign(self.m1, ROOT), sign(self.m2, ROOT), sign(self.m3, ROOT)]
        self.session = "00ff" * 8 + ":boot-1"
        self.key = Key(OWNER_KEYS[0])

    def signed(self, purpose="recover", node="b", session=None, tip=None, expires=None, key=None):
        tip = tip or self.m3
        st = recover.statement(purpose, node, tip, session or self.session, expires if expires is not None else T0 + 300)
        signer = key or OWNER_KEYS[0]
        return {"statement": st, "key": pub(signer), "sig": signer.sign(recover.message(st)).hex()}

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Statement(Case):
    def test_its_own_domain_for_each_purpose_and_never_a_membership_or_heartbeat_input(self):
        st = recover.statement("recover", "b", self.m3, self.session, T0)
        raw = recover.message(st)
        self.assertTrue(raw.startswith(b"regalia-recover/v1\0"))
        self.assertTrue(recover.message(dict(st, purpose="reanchor")).startswith(b"regalia-reanchor/v1\0"))
        for prefix in (m.DOMAIN, heartbeat.DOMAIN):
            self.assertFalse(raw.startswith(prefix))
        self.refused("the purpose is one of", recover.message, dict(st, purpose="other"))

    def test_the_node_takes_only_this_tip_this_node_this_operation_for_minutes(self):
        ok = recover.verify_owner(self.m3, self.signed(), "recover", "b", self.session, T0)
        self.assertEqual(ok["epoch"], 3)
        cases = [("is for node a", self.signed(node="a")),
                 ("is for another operation", self.signed(session="11ee" * 8 + ":boot-1")),
                 ("is for reanchor, not recover", self.signed(purpose="reanchor")),
                 ("not the peer's tip", self.signed(tip=self.m2)),
                 ("has expired", self.signed(expires=T0)),
                 ("has expired, or expires further ahead", self.signed(expires=T0 + recover.SESSION_TTL + 1)),
                 ("not one of the tip manifest's owner_keys", self.signed(key=STRANGER))]
        for reason, statement in cases:
            with self.subTest(reason):
                self.refused(reason, recover.verify_owner, self.m3, statement, "recover", "b", self.session, T0)
        forged = dict(self.signed(), sig=self.signed(node="a")["sig"])
        self.refused("does not verify", recover.verify_owner, self.m3, forged, "recover", "b", self.session, T0)
        # either owner key of the tip will do (ADR-0002 D30)
        recover.verify_owner(self.m3, self.signed(key=OWNER_KEYS[1]), "recover", "b", self.session, T0)

    def test_the_chain_extends_what_the_node_last_knew_and_owner_keys_may_rotate(self):
        self.assertEqual(recover.verify_chain(self.chain, ROOT_PUB, self.m2)["epoch"], 3)
        fork2 = manifest4(2, m.digest(self.m1), nodes4(b="QUARANTINED"), issued_at="2026-10-04T10:00:00Z")
        self.refused("does not extend this node's last known manifest", recover.verify_chain, self.chain, ROOT_PUB, fork2)
        rotated = manifest4(4, m.digest(self.m3), nodes4(c="QUARANTINED"), owner_keys=[{"alg": "ed25519", "key": pub(OWNER_KEYS[2])}])
        self.assertEqual(recover.verify_chain(self.chain + [sign(rotated, ROOT)], ROOT_PUB, self.m2)["owner_keys"][0]["key"], pub(OWNER_KEYS[2]))


class Witness(Case):
    """The audit collector's signed record of a node's sync stream: its highest epoch, checked against its receipt."""

    def export(self, epochs):
        out, chain = [], trails.LINE_CHAIN_START
        for i, epoch in enumerate(epochs):
            line = json.dumps({"event": "sync-apply", "outcome": "ALLOW", "epoch": epoch, "at": T0 + i}, sort_keys=True)
            raw = line.encode() + b"\n"
            out.append({"sequence": i + 1, "detail": {"line": line, "line_sha256": hashlib.sha256(raw).hexdigest()}})
            chain = trails.line_chain(chain, raw)
        return out, chain, hashlib.sha256(raw).hexdigest()

    def receipt(self, export, chain, last, key, identity="id" * 32, stream="site-b.sync"):
        preimage = ("%s\n%s\n%s\n%d\n%s\n%s\n%s" % (trails.RECEIPT_DOMAIN, identity, stream, len(export), "e" * 64, last, chain)).encode()
        return {"sequence": len(export), "event_hash": "e" * 64, "line_sha256": last, "line_chain": chain, "signature": key.sign(preimage).hex()}

    def test_the_highest_epoch_the_collector_holds_under_a_receipt_that_verifies(self):
        collector = Ed25519PrivateKey.generate()
        keys = [pub(collector)]
        export, chain, last = self.export([1, 2, 3, 2])
        self.assertEqual(recover.witness_epoch(export, self.receipt(export, chain, last, collector), keys, "id" * 32, "site-b.sync"), 3)
        tampered = [dict(e) for e in export]
        tampered[1] = dict(tampered[1], detail=dict(tampered[1]["detail"], line=tampered[1]["detail"]["line"].replace('"epoch": 2', '"epoch": 9')))
        self.refused("does not hold the line it names", recover.witness_epoch, tampered, self.receipt(export, chain, last, collector), keys, "id" * 32, "site-b.sync")
        self.refused("not for this export", recover.witness_epoch, export[:-1], self.receipt(export, chain, last, collector), keys, "id" * 32, "site-b.sync")
        self.refused("does not verify under the pinned", recover.witness_epoch, export, self.receipt(export, chain, last, Ed25519PrivateKey.generate()),
                     keys, "id" * 32, "site-b.sync")


class OwnerSide(Witness):
    def record(self, epoch, manifest):
        return [{"epoch": 1, "digest": m.digest(self.m1), "verified": True},
                {"epoch": epoch, "digest": m.digest(manifest), "verified": True},
                {"epoch": 9, "digest": "00" * 32, "verified": False}]          # a signature that did not verify: no floor

    def sign_recovery(self, typed, **kw):
        args = dict(peer_chain=self.chain, root_key=ROOT_PUB, record_lines=self.record(2, self.m2), purpose="recover", node_id="b",
                    session=self.session, open_signer=lambda: self.key, confirm=lambda text: (self.shown.append(text), typed)[1], now=T0)
        args.update(kw)
        return owner.sign_recovery(say=lambda text: None, **args)

    def setUp(self):
        super().setUp()
        self.shown = []

    def test_judged_against_this_machine_s_record_and_signed_for_this_operation(self):
        st = self.sign_recovery("recover b 3 %s no collector" % m.digest(self.m3)[:8])
        self.assertEqual(recover.verify_owner(self.m3, st, "recover", "b", self.session, T0)["epoch"], 3)
        text = self.shown[0]
        self.assertIn("a LOWER BOUND", text)
        self.assertIn("NOT CONSULTED", text)
        self.assertIn('policy_version: "p1" -> "p2"', text)
        self.assertIn("any later revocation", text)

    def test_nothing_is_signed_below_the_record_or_the_counter_or_off_its_chain_or_mistyped(self):
        line = "recover b 3 %s no collector" % m.digest(self.m3)[:8]
        self.refused("below what this machine signed (epoch 3)", self.sign_recovery, line, record_lines=self.record(3, self.m3), peer_chain=self.chain[:2])
        other = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED"), issued_at="2026-10-04T10:00:00Z")
        self.refused("does not hold, at epoch 2, the manifest this machine signed", self.sign_recovery, line, record_lines=self.record(2, other))
        self.refused("below the node's counter (4)", self.sign_recovery, line, counter_epoch=4)
        self.refused("is not this recover's: nothing is signed", self.sign_recovery, "recover b 3 %s" % m.digest(self.m3)[:8])
        self.refused("no verified signature", self.sign_recovery, line, record_lines=[{"epoch": 3, "digest": "00", "verified": False}])
        self.refused("not one of the tip manifest's owner_keys", self.sign_recovery, line, open_signer=lambda: Key(STRANGER))
        self.assertEqual(self.key.signed, [])

    def test_the_collector_s_witness_refuses_a_withheld_revocation(self):
        collector = Ed25519PrivateKey.generate()
        export, chain, last = self.export([1, 2, 3, 4])                     # some node took epoch 4: the peer's tip is 3
        witness = (export, self.receipt(export, chain, last, collector), [pub(collector)], "id" * 32, "site-b.sync")
        self.refused("the audit collector saw epoch 4, above the peer's tip (epoch 3): a revocation withheld", self.sign_recovery,
                     "recover b 3 %s" % m.digest(self.m3)[:8], witnesses=[witness])
        export, chain, last = self.export([1, 2, 3])
        witness = (export, self.receipt(export, chain, last, collector), [pub(collector)], "id" * 32, "site-b.sync")
        st = self.sign_recovery("recover b 3 %s" % m.digest(self.m3)[:8], witnesses=[witness])     # consulted: no acknowledgement needed
        self.assertIn("saw at most epoch 3", self.shown[-1])
        self.assertEqual(st["statement"]["epoch"], 3)


class Node(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_the_last_known_manifest_is_what_the_store_wrote_or_nothing(self):
        case = Case("setUp")
        case.setUp()
        path = os.path.join(self.d, "membership.json")
        with open(path, "wb") as f:
            f.write(m.canonical(case.chain[:2]))                # as membership.Store._write leaves it
        self.assertEqual(m.digest(recover.last_known(path, ROOT_PUB)), m.digest(case.m2))
        with open(path, "wb") as f:
            f.write(b"not json")
        self.assertIsNone(recover.last_known(path, ROOT_PUB))
        self.assertIsNone(recover.last_known(os.path.join(self.d, "gone.json"), ROOT_PUB))

    def test_the_owner_check_wants_this_boot_s_session_and_nobody_else_answering(self):
        import unittest.mock
        case = Case("setUp")
        case.setUp()
        node = unittest.mock.Mock(node_id="b", cfg={"run_dir": self.d})
        made = recover.new_session(os.path.join(self.d, recover.SESSION_FILE), "boot-1", now=lambda: T0)
        case.session = recover.session_id(made)
        signed = case.signed()
        check = recover.owner_check(node, signed, "recover", "a", now=lambda: T0 + 10, boot_id="boot-1")
        with unittest.mock.patch.object(recover, "second_node_answers", return_value=[]):
            self.assertEqual(check(case.m3)["epoch"], 3)
        with unittest.mock.patch.object(recover, "second_node_answers", return_value=["c"]):
            with self.assertRaisesRegex(m.Refused, "c answers over the service tunnel: recover from two nodes"):
                check(case.m3)
        with self.assertRaisesRegex(m.Refused, "from another boot"):
            recover.owner_check(node, signed, "recover", "a", now=lambda: T0 + 10, boot_id="boot-2")(case.m3)
        recover.new_session(os.path.join(self.d, recover.SESSION_FILE), "boot-1", now=lambda: T0)       # a new session: the old statement is void
        with self.assertRaisesRegex(m.Refused, "for another operation"):
            check(case.m3)

    def test_the_restore_half_never_runs_as_root(self):
        import pwd
        import unittest.mock
        with unittest.mock.patch.object(recover.os, "geteuid", return_value=0), \
                unittest.mock.patch.object(pwd, "getpwnam", return_value=unittest.mock.Mock(pw_uid=990)), \
                unittest.mock.patch("sys.stderr") as err:
            self.assertEqual(recover.main(["_restore", "--config", "/nonexistent/node.json"]), 1)
        self.assertIn("runs as regalia-sync only", "".join(str(c) for c in err.write.call_args_list))

    def test_apply_and_session_need_root(self):
        import unittest.mock
        with unittest.mock.patch.object(recover.os, "geteuid", return_value=1000), unittest.mock.patch("sys.stderr"):
            self.assertEqual(recover.main(["session", "--config", "/nonexistent/node.json"]), 2)
            self.assertEqual(recover.main(["apply", "--config", "/nonexistent/node.json", "--peer", "a=x.json"]), 2)


class Session(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.path = os.path.join(self.d, recover.SESSION_FILE)

    def test_one_operation_in_one_boot_for_minutes(self):
        made = recover.new_session(self.path, "boot-1", rand=lambda n: b"\x01" * n, now=lambda: T0)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        self.assertEqual(recover.session_id(made), "01" * 16 + ":boot-1")
        self.assertEqual(recover.held_session(self.path, "boot-1", now=lambda: T0 + 60), made)
        with self.assertRaisesRegex(m.Refused, "from another boot"):
            recover.held_session(self.path, "boot-2", now=lambda: T0)
        with self.assertRaisesRegex(m.Refused, "older than"):
            recover.held_session(self.path, "boot-1", now=lambda: T0 + recover.SESSION_TTL + 1)
        os.unlink(self.path)
        with self.assertRaisesRegex(m.Refused, "run `recover session` first"):
            recover.held_session(self.path, "boot-1")


if __name__ == "__main__":
    unittest.main()
