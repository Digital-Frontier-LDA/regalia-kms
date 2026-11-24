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
        # owner_keys rotate only with a later card ceremony's record (#405, #361 B): its sequence and digest move with them
        rotated = manifest4(4, m.digest(self.m3), nodes4(c="QUARANTINED"), owner_keys=[{"alg": "ed25519", "key": pub(OWNER_KEYS[2])}],
                            card_record={"sequence": 2, "digest": "cb" * 32})
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

    def beat_export(self, sequences, epochs=None):
        """The collector's export of the node's beat-propose events (beat.py:225 writes the sequence to the trail
        line), with the same line/receipt mechanics as `export`."""
        out, chain = [], trails.LINE_CHAIN_START
        for i, sequence in enumerate(sequences):
            line = json.dumps({"event": "beat-propose", "outcome": "ALLOW", "sequence": sequence,
                               "epoch": (epochs[i] if epochs else sequence), "at": T0 + i}, sort_keys=True)
            raw = line.encode() + b"\n"
            out.append({"sequence": i + 1, "detail": {"line": line, "line_sha256": hashlib.sha256(raw).hexdigest()}})
            chain = trails.line_chain(chain, raw)
        return out, chain, hashlib.sha256(raw).hexdigest()

    def test_witness_sequence_is_the_highest_beat_propose_allow(self):
        """witness_sequence: the highest beat-propose ALLOW sequence in the witnessed stream; a stream with no
        beat-propose ALLOW returns 0 (review defcc750, finding 2: it had no test)."""
        collector = Ed25519PrivateKey.generate()
        keys = [pub(collector)]
        export, chain, last = self.beat_export([3, 1, 7])
        self.assertEqual(recover.witness_sequence(export, self.receipt(export, chain, last, collector), keys, "id" * 32, "site-b.sync"), 7)
        # no beat-propose ALLOW event at all (the sync-apply export): 0
        sync_export, sync_chain, sync_last = self.export([1, 2])
        self.assertEqual(recover.witness_sequence(sync_export, self.receipt(sync_export, sync_chain, sync_last, collector), keys, "id" * 32, "site-b.sync"), 0)
        # a DENIED beat-propose does not count: rebuild the export with the tampered line and its correct receipt
        denied_line = json.dumps({"event": "beat-propose", "outcome": "DENY", "sequence": 9,
                                  "epoch": 9, "at": T0}, sort_keys=True)
        denied_raw = denied_line.encode() + b"\n"
        denied_export = [{"sequence": 1, "detail": {"line": denied_line,
                                                    "line_sha256": hashlib.sha256(denied_raw).hexdigest()}}]
        denied_chain = trails.line_chain(trails.LINE_CHAIN_START, denied_raw)
        denied_last = hashlib.sha256(denied_raw).hexdigest()
        self.assertEqual(recover.witness_sequence(denied_export, self.receipt(denied_export, denied_chain, denied_last, collector), keys, "id" * 32, "site-b.sync"), 0)

    def test_witness_sequence_refuses_an_export_its_receipt_does_not_hold_for(self):
        """A receipt that does not hold for the export (a different last line, a wrong key) is refused: the
        sequence is witnessed, never free."""
        collector = Ed25519PrivateKey.generate()
        keys = [pub(collector)]
        export, chain, last = self.beat_export([3, 5])
        # the receipt signs a different export (its last line is not the export's)
        other, _, other_last = self.beat_export([9])
        self.refused("not for this export", recover.witness_sequence, export,
                     self.receipt(other, other, other_last, collector), keys, "id" * 32, "site-b.sync")
        # the receipt does not verify under the pinned keys
        self.refused("does not verify under the pinned", recover.witness_sequence, export,
                     self.receipt(export, chain, last, Ed25519PrivateKey.generate()), keys, "id" * 32, "site-b.sync")
        # a tampered line breaks the named hash
        tampered = [dict(e) for e in export]
        tampered[1] = dict(tampered[1], detail=dict(tampered[1]["detail"], line=tampered[1]["detail"]["line"].replace('"sequence": 5', '"sequence": 99')))
        self.refused("does not hold the line it names", recover.witness_sequence, tampered,
                     self.receipt(export, chain, last, collector), keys, "id" * 32, "site-b.sync")


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
        self.assertIn("a revocation two nodes signed after epoch 2 is invisible here", text)
        late = self.sign_recovery("recover b 3 %s no collector" % m.digest(self.m3)[:8], now=T0 + 7200, issued=T0)
        self.assertEqual(late["statement"]["expires"], T0 + recover.SESSION_TTL - 60)     # the node's time, not the laptop's

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


import subprocess                                                                  # noqa: E402
import types                                                                       # noqa: E402
import unittest.mock                                                               # noqa: E402

from deploy.baremetal import convergence                                          # noqa: E402
import tests.test_baremetal_convergence as ct                                      # noqa: E402
import tests.test_baremetal_replacement as rt                                      # noqa: E402


class Recovers(ct.Case):
    """#387's acceptance: the COMMAND recovers, through apply() and its hand-over to regalia-sync, for each state
    MEMBERSHIP-RECOVERY.md sends to it, and every decision (the root half's refusals too) is a line in the sync trail.
    The hand-over is runuser in production; here `run` calls _restore's half in this process."""

    def setUp(self):
        super().setUp()
        self.trail, self.handed = [], []
        self.stores["a"] = self.store("a")
        self.stores["a"].commit(self.e1)
        e2 = rt.sign(self.chain(self.m1, [self.entry("a"), self.entry("b"), self.entry("c", "MAINTENANCE")]))
        e3 = rt.sign(self.chain(e2["manifest"], [self.entry("a"), self.entry("b"), self.entry("c")]))
        self.e2, self.e3 = e2, e3
        for name in ("a", "b", "c"):
            convergence.catch_up(self.stores[name], [e2, e3])

    def node(self, store):
        d = self.d
        return types.SimpleNamespace(node_id="c", cfg={"root_key": ct.ROOT, "run_dir": d}, store=lambda: store,
                                     path=lambda name: store.path if name == "membership.json" else os.path.join(d, name))

    def runner(self, store):
        def run(cmd, cwd=None, capture_output=None, text=None, input=None):
            self.assertEqual(cmd[:5], ["runuser", "-u", recover.SYNC_USER, "-g", recover.SYNC_USER])
            self.assertIn("_restore", cmd)
            given = json.loads(input)
            self.handed.append(given)
            try:
                out = recover.handed(self.node(store), given, self.trail.append)
            except m.Refused as refusal:
                return subprocess.CompletedProcess(cmd, 1, "", "REFUSED: %s" % refusal)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out) + "\n", "")
        return run

    def apply(self, store, peers, one_source=None, phrase=None, answers=()):
        """recover apply on c, typing `phrase` (default: exactly the one asked for)."""
        asked = []

        def typed(prompt):
            asked.append(prompt.split("Type exactly: ", 1)[1].split("\n", 1)[0])
            return asked[-1] if phrase is None else phrase
        node = self.node(store)
        with unittest.mock.patch("deploy.baremetal.node.Node", return_value=node), \
                unittest.mock.patch("deploy.baremetal.node.load", return_value={}), \
                unittest.mock.patch("deploy.baremetal.node.publish"), \
                unittest.mock.patch.object(recover, "owner_check", side_effect=self.owner_check(answers)):
            try:
                return recover.apply("/etc/regalia/node.json", peers, one_source, typed=typed, run=self.runner(store))
            finally:
                self.asked = asked

    def owner_check(self, answers):
        # the owner check's own tests are above (OwnerCheck); here it is the gate it is in apply(): a second node answering refuses
        def check(node, signed, purpose, peer, now=None, boot_id=None):
            def on(tip):
                others = [n for n in answers if n != peer]
                if others:
                    raise m.Refused("%s answers over the service tunnel: %s from two nodes, not with the owner" % (", ".join(others), purpose))
                return signed["statement"]
            return on
        return check

    def statement(self):
        st = recover.statement("recover", "c", self.e3["manifest"], "00ff" * 8 + ":boot-1", T0 + 300)
        return {"statement": st, "key": "11" * 32, "sig": "22" * 64}

    def outcomes(self):
        return [(e["event"], e["outcome"]) for e in self.trail]

    # ---- the recoveries ----

    def test_rollback_from_one_peer(self):
        c = self.stores["c"]
        with open(c.path, "wb") as f:
            f.write(m.canonical([self.e1]))                                     # a restored disk: epoch 1 under a counter at 3
        self.refused("ROLLBACK", c.load)
        self.assertEqual(self.apply(c, {"b": self.stores["b"].envelopes()}), 3)
        self.assertEqual(c.load()["epoch"], 3)
        self.assertEqual(self.asked, ["recover c to epoch 3 %s from b" % m.digest(self.e3["manifest"])[:8]])
        self.assertEqual(self.outcomes(), [("recover", "ALLOW")])
        self.assertEqual((self.trail[0]["sources"], self.trail[0]["minimum"], self.trail[0]["epoch"]), (["b"], None, 3))
        self.assertNotIn("one_source", self.trail[0])

    def test_conflict_from_one_peer_and_a_forked_source_refused_and_recorded(self):
        c = self.stores["c"]
        rival2 = rt.sign(self.chain(self.m1, [self.entry("a"), self.entry("b"), self.entry("c", "DRAINING")]))
        rival3 = rt.sign(self.chain(rival2["manifest"], [self.entry("a"), self.entry("b"), self.entry("c")]))
        fork = [self.e1, rival2, rival3]
        with open(c.path, "wb") as f:
            f.write(m.canonical(fork))                                           # a substituted disk: another validly signed chain
        self.refused("CONFLICT", c.load)
        os.unlink(c.path)                                                        # the procedure: keep it as evidence, remove it, recover
        self.refused("CONFLICT: the manifest at epoch 3 is not the one this node's TPM recorded", self.apply, c, {"b": fork})
        self.assertEqual(self.outcomes(), [("recover", "DENY")])
        self.assertIn("CONFLICT", self.trail[0]["reason"])
        self.assertEqual(self.apply(c, {"b": self.stores["b"].envelopes()}), 3)
        self.assertEqual(self.outcomes(), [("recover", "DENY"), ("recover", "ALLOW")])

    def crash_window(self):
        fresh = self.store("c2")                                                 # c, crashed between counter and record at epoch 3
        convergence.catch_up(fresh, [self.e1, self.e2])
        fresh.hw.advance(3)
        os.unlink(fresh.path)
        self.assertFalse(fresh.pinned())
        return fresh

    def test_the_crash_window_from_two_peers_and_one_peer_refused_and_recorded(self):
        c = self.crash_window()
        self.refused("recovery needs whole chains from 2 different sources that agree (1 given)", self.apply, c, {"b": self.stores["b"].envelopes()})
        self.assertEqual(self.outcomes(), [("recover", "DENY")])
        self.assertEqual(self.apply(c, {"a": self.stores["a"].envelopes(), "b": self.stores["b"].envelopes()}), 3)
        self.assertEqual(self.asked[-1], "recover c to epoch 3 %s from a+b" % m.digest(self.e3["manifest"])[:8])
        self.assertEqual(self.outcomes(), [("recover", "DENY"), ("recover", "ALLOW")])
        self.assertEqual(self.trail[-1]["sources"], ["a", "b"])
        self.assertTrue(c.pinned())

    def test_the_crash_window_from_one_peer_and_the_owner(self):
        c = self.crash_window()
        signed = self.statement()
        self.assertEqual(self.apply(c, {"b": self.stores["b"].envelopes()}, one_source=signed), 3)
        self.assertEqual(self.asked, ["recover c to epoch 3 %s from b and the owner" % m.digest(self.e3["manifest"])[:8]])
        self.assertEqual(self.outcomes(), [("recover", "ALLOW")])
        self.assertEqual(self.trail[0]["minimum"], 1)
        self.assertEqual(self.trail[0]["one_source"], {"owner_key": signed["key"],
                                                       "statement": hashlib.sha256(m.canonical(signed["statement"])).hexdigest()})

    # ---- the root half's refusals are recorded too ----

    def test_a_second_node_answering_refuses_one_source_and_is_recorded(self):
        c = self.crash_window()
        self.refused("a answers over the service tunnel", self.apply, c, {"b": self.stores["b"].envelopes()}, one_source=self.statement(), answers=("a",))
        self.assertEqual(self.outcomes(), [("recover", "DENY")])
        self.assertIn("answers over the service tunnel", self.trail[0]["reason"])
        self.assertEqual(self.trail[0]["sources"], ["b"])
        self.assertIn("one_source", self.trail[0])
        self.assertFalse(c.pinned())                                             # nothing was changed

    def test_a_mistyped_phrase_changes_nothing_and_is_recorded(self):
        c = self.crash_window()
        self.refused("the phrase typed is not this recovery's", self.apply, c,
                     {"a": self.stores["a"].envelopes(), "b": self.stores["b"].envelopes()}, phrase="recover c to epoch 3")
        self.assertEqual(self.outcomes(), [("recover", "DENY")])
        self.assertEqual([g.get("refused", "")[:10] for g in self.handed], ["the phrase"])
        self.assertFalse(c.pinned())

    def test_one_source_takes_exactly_one_peer_recorded(self):
        c = self.crash_window()
        self.refused("--one-source takes exactly one --peer", self.apply, c,
                     {"a": self.stores["a"].envelopes(), "b": self.stores["b"].envelopes()}, one_source=self.statement())
        self.assertEqual(self.outcomes(), [("recover", "DENY")])

    def test_a_refusal_that_cannot_be_recorded_says_so(self):
        c = self.crash_window()

        def broken(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 1, "", "REFUSED: cannot write the trail")
        with unittest.mock.patch.object(self, "runner", return_value=broken):
            with self.assertRaises(m.Refused) as caught:
                self.apply(c, {"b": self.stores["b"].envelopes()}, phrase="wrong")
        said = str(caught.exception)
        self.assertTrue(said.startswith("the phrase typed is not this recovery's: nothing was changed; "), said)   # the reason first, kept whole
        self.assertIn("and the refusal could not be recorded in the sync trail: REFUSED: cannot write the trail", said)
        self.assertEqual(self.trail, [])
        self.assertFalse(c.pinned())                                             # nothing was restored
        self.assertFalse(os.path.exists(c.path))


class SingleNodeStatement(Witness):
    """The v2 owner statement under single-node (docs/design/single-node.md 4.7): the collector's witnessed
    epoch is bound into the statement, and a collector above the tip is a refusal."""

    def setUp(self):
        super().setUp()
        self.collector = Ed25519PrivateKey.generate()
        self.collector_pub = pub(self.collector)

    def witness(self, epoch):
        export, chain, last = self.export([1, epoch])
        return (export, self.receipt(export, chain, last, self.collector), [self.collector_pub], "id" * 32, "site-a.sync")

    def v2_statement(self, collector_epoch, purpose="recover", node="a", tip=None, session=None):
        st = recover.statement(purpose, node, tip or self.m3, session or self.session, T0 + 300,
                               collector_epoch=collector_epoch)
        return {"statement": st, "key": pub(OWNER_KEYS[0]), "sig": OWNER_KEYS[0].sign(recover.message(st)).hex()}

    def test_v2_statement_has_collector_epoch_in_its_message(self):
        """A v2 statement's message includes collector_epoch and uses the v2 prefix."""
        st = recover.statement("recover", "a", self.m3, self.session, T0 + 300, collector_epoch=3)
        self.assertIn("collector_epoch", st)
        raw = recover.message(st)
        self.assertTrue(raw.startswith(b"regalia-recover/v2\0"))
        # the v1 prefix is not used
        self.assertFalse(raw.startswith(b"regalia-recover/v1\0"))

    def test_v2_statement_for_recount_has_collector_sequence(self):
        """A recount statement requires both collector_epoch and collector_sequence."""
        st = recover.statement("recount", "a", self.m3, self.session, T0 + 300,
                               collector_epoch=3, collector_sequence=41)
        self.assertIn("collector_epoch", st)
        self.assertIn("collector_sequence", st)
        self.assertEqual(st["collector_sequence"], 41)
        raw = recover.message(st)
        self.assertTrue(raw.startswith(b"regalia-recount/v2\0"))
        # without collector_sequence, the recount statement is refused
        self.refused("a recount statement needs collector_sequence", recover.statement,
                     "recount", "a", self.m3, self.session, T0 + 300, collector_epoch=3)

    def test_verify_owner_under_single_node_requires_v2(self):
        """Under single_node=True, verify_owner requires collector_epoch in the statement."""
        single_tip = self.m3  # m3 is a v4 manifest, but we pass single_node=True to simulate
        # a v1 statement (no collector_epoch) is refused
        v1 = self.signed()
        self.refused("under single-node the statement must be v2",
                     recover.verify_owner, single_tip, v1, "recover", "b", self.session, T0, single_node=True)
        # a v2 statement with collector_epoch <= tip epoch is accepted
        v2 = self.v2_statement(3, node="b")
        self.assertEqual(recover.verify_owner(single_tip, v2, "recover", "b", self.session, T0,
                                              single_node=True)["collector_epoch"], 3)

    def test_verify_owner_under_single_node_refuses_collector_above_tip(self):
        """A collector_epoch above the tip's epoch is a refusal: a revocation was withheld."""
        v2 = self.v2_statement(99, node="b")
        self.refused("the collector's witnessed epoch 99 is above the tip's epoch 3",
                     recover.verify_owner, self.m3, v2, "recover", "b", self.session, T0, single_node=True)

    def test_verify_owner_under_multi_node_accepts_v1(self):
        """Under single_node=False (multi-node), v1 statements are accepted as before."""
        v1 = self.signed()
        self.assertEqual(recover.verify_owner(self.m3, v1, "recover", "b", self.session, T0,
                                              single_node=False)["epoch"], 3)


class SingleNodeCommand(Recovers):
    """The single-node owner-chain path at the COMMAND (docs/design/single-node.md 4.7):
    `recover apply --owner-chain CHAIN.json --owner-statement ST.json`, no --peer: main() loads the statement
    and hands the owner chain over, apply() verifies the chain and the v2 statement over the tip, and the restore
    runs as regalia-sync. The owner chain is refused under a multi-node tip."""

    def single_tip(self):
        import tests.test_baremetal_membership_v5 as v5
        from tests.test_baremetal_membership_v4 import OWNER_KEYS as O, pub as p
        man = v5.single5(1, "", nodes=[v5.one("a", "ACTIVE", i=0)])
        man["owner_keys"] = [{"alg": "ed25519", "key": p(O[0])}]
        return rt.sign(man)

    def single_v2(self, tip, node="a", collector_epoch=1, session=None):
        st = recover.statement("recover", node, tip["manifest"], session or "aa" * 8 + ":boot-x", T0 + 300,
                               collector_epoch=collector_epoch)
        return {"statement": st, "key": "11" * 32, "sig": "22" * 64}

    def single_runner(self, store):
        def run(cmd, cwd=None, capture_output=None, text=None, input=None):
            self.assertEqual(cmd[:5], ["runuser", "-u", recover.SYNC_USER, "-g", recover.SYNC_USER])
            self.assertIn("_restore", cmd)
            given = json.loads(input)
            self.handed.append(given)
            try:
                out = recover.handed(self.node(store), given, self.trail.append)
            except m.Refused as refusal:
                return subprocess.CompletedProcess(cmd, 1, "", "REFUSED: %s" % refusal)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out) + "\n", "")
        return run

    def single_apply(self, store, owner_chain=None, one_source=None, phrase=None, peers=None):
        asked = []

        def typed(prompt):
            asked.append(prompt.split("Type exactly: ", 1)[1].split("\n", 1)[0])
            return asked[-1] if phrase is None else phrase
        node = self.node(store)
        with unittest.mock.patch("deploy.baremetal.node.Node", return_value=node), \
                unittest.mock.patch("deploy.baremetal.node.load", return_value={}), \
                unittest.mock.patch("deploy.baremetal.node.publish"), \
                unittest.mock.patch.object(recover, "owner_check",
                                           side_effect=lambda n, s, p, peer, now=None, boot_id=None:
                                           (lambda tip, single_node=None: s["statement"])):
            try:
                return recover.apply("/etc/regalia/node.json", peers or {}, one_source, typed=typed,
                                     run=self.single_runner(store), owner_chain=owner_chain)
            finally:
                self.asked = asked

    def test_main_loads_the_owner_statement_with_owner_chain_no_peer(self):
        """--owner-chain takes its --owner-statement without --one-source: the documented command
        `recover apply --owner-chain CHAIN --owner-statement ST` must load both and hand them to apply()."""
        tip = self.single_tip()
        signed = self.single_v2(tip)
        with open(self.d + "/owner-chain.json", "w") as f:
            json.dump([tip], f)
        with open(self.d + "/statement.json", "w") as f:
            json.dump(signed, f)
        cfg = {"schema": "regalia.node/v1", "node_id": "a", "root_key": "aa" * 32, "run_dir": self.d,
               "state_dir": self.d, "site": "/nonexistent"}
        with open(self.d + "/node.json", "w") as f:
            json.dump(cfg, f)
        with unittest.mock.patch("deploy.baremetal.node.load", return_value=cfg), \
                unittest.mock.patch("deploy.baremetal.node.Node") as node_mock, \
                unittest.mock.patch("deploy.baremetal.recover.apply") as apply_mock, \
                unittest.mock.patch.object(recover.os, "geteuid", return_value=0):
            node_mock.return_value = types.SimpleNamespace(node_id="a", cfg=cfg, path=lambda n: os.path.join(self.d, n))
            self.assertEqual(recover.main(["apply", "--config", self.d + "/node.json",
                                           "--owner-chain", self.d + "/owner-chain.json",
                                           "--owner-statement", self.d + "/statement.json"]), 0)
            self.assertEqual(apply_mock.call_count, 1)
            args, kw = apply_mock.call_args
            self.assertEqual(args[0], os.path.join(self.d, "node.json"))
            self.assertEqual(args[1], {})                                          # no peer
            self.assertEqual(args[2]["statement"], signed["statement"])             # the statement, loaded
            self.assertEqual(kw["owner_chain"], [tip])                              # and the owner chain

    def test_apply_owner_chain_recovers_a_gone_disk(self):
        """apply() under the owner chain: the chain verifies from the root, the v2 statement is checked over the
        tip (v2, collector_epoch <= tip), minimum 1 (while the record pins), and the store is restored from the
        owner's chain alone."""
        fresh = self.store("a2")
        # the chain is v5: a store committing it would set the anchor's schema to v5 (a QUORUM schema) and refuse
        # the owner-written anchor, as the convergence and reanchor owner-chain fixtures do
        fresh._judge_by = lambda manifests: None
        fresh.commit(self.single_tip())
        os.unlink(fresh.path)                                                       # the disk: gone
        self.assertTrue(fresh.pinned())
        tip = self.single_tip()
        self.assertEqual(self.single_apply(fresh, owner_chain=[tip], one_source=self.single_v2(tip)), 1)
        self.assertEqual(fresh.load()["epoch"], 1)
        self.assertEqual(self.asked, ["recover c to epoch 1 %s from owner-chain collector at epoch 1"
                                      % m.digest(tip["manifest"])[:8]])
        self.assertEqual(self.outcomes(), [("recover", "ALLOW")])
        self.assertEqual(self.trail[0]["sources"], ["owner-chain"])
        self.assertEqual(self.trail[0]["minimum"], 1)
        self.assertTrue(fresh.pinned())

    def test_apply_owner_chain_refused_under_multi_node_tip(self):
        """The owner chain is refused under a multi-node tip: the path is single-node's alone."""
        c = self.crash_window()
        tip = self.single_tip()
        self.refused("owner_chain is refused under a multi-node tip", self.single_apply, c,
                     owner_chain=self.stores["b"].envelopes(), one_source=self.single_v2(tip, node="c"))
        self.assertEqual(self.outcomes(), [("recover", "DENY")])

    def test_apply_owner_chain_refused_under_multi_node_tip_with_a_v1_statement(self):
        """Under a multi-node tip the owner chain is refused BEFORE the statement is read: with a v1 statement
        (no collector_epoch) the old code read one_source['statement']['collector_epoch'] for the phrase and
        raised a KeyError outside the Refused handler, so the refusal was never recorded (review defcc750,
        finding 3; the review's PROBE3 showed the KeyError and an empty trail). Now it is a Refused, in the trail."""
        c = self.crash_window()
        # a v1 statement (no collector_epoch), as the owner's tool signs it under a multi-node tip
        st = recover.statement("recover", "c", self.e3["manifest"], "bb" * 8 + ":boot-x", T0 + 300)
        v1 = {"statement": st, "key": "11" * 32, "sig": "22" * 64}
        # the refusal is a Refused: apply() raises it and the runner records it
        self.refused("owner_chain is refused under a multi-node tip", self.single_apply, c,
                     owner_chain=self.stores["b"].envelopes(), one_source=v1)
        self.assertEqual(self.outcomes(), [("recover", "DENY")])
        # the denial says why, and names the owner chain, not a KeyError
        self.assertIn("owner_chain is refused", self.trail[-1]["reason"])
