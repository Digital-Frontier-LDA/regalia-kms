"""deploy/baremetal/reanchor.py and membership.Store.reanchor (#68): a new TPM anchor for a node whose anchor
is unusable. Every fence around it has a test: the authority and a peer, a usable anchor never reset, no way
back below a counter that still reads, verified before the TPM is touched, typed, recorded."""
import ast
import contextlib
import copy
import glob
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from deploy.baremetal import convergence, reanchor
from deploy.baremetal import membership as m
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import REVOKE, ROOT, ROOT_PUB, _Swtpm, manifest, sign, three

AUTHORITY = convergence.AUTHORITY
GARBAGE = b"\x5a" * 48


def chain(upto, **last):
    """Epochs 1..upto, root-signed; `last` sets node states in the newest manifest."""
    envs, cur = [], None
    for e in range(1, upto + 1):
        states = last if e == upto else {}
        env = sign(manifest(e, m.digest(cur) if cur else "", three(**dict({"a": "DRAINING" if e % 2 else "ACTIVE"}, **states))), ROOT)
        cur = m.accept(cur, env, ROOT_PUB)
        envs.append(env)
    return envs


class Case(unittest.TestCase):
    """Node b at epoch 3 on a FakeTpm. `lose_record()` leaves neither record slot valid."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm)
        self.hw.define()
        self.path = self.d + "/membership.json"
        self.envs = chain(5)
        self.store = m.Store(self.path, ROOT_PUB, self.hw)
        for env in self.envs[:3]:
            self.store.commit(env)
        self.events = []

    def lose_record(self):
        for index in self.hw.record_indices:
            self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=GARBAGE)

    def state(self):
        """Everything a refusal must leave alone: the TPM's NV indices and the membership file."""
        with open(self.path, "rb") as f:
            return copy.deepcopy(self.tpm.nv), self.tpm.highest, f.read()

    def digest(self, epoch):
        return m.digest(self.envs[epoch - 1]["manifest"])

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def unchanged(self, before, reason, fn, *args, **kw):
        self.refused(reason, fn, *args, **kw)
        self.assertEqual(self.state(), before)


class StoreReanchor(Case):
    def test_a_node_with_no_record_gets_a_new_anchor_on_the_chain(self):
        self.lose_record()
        self.refused("NO RECORD", self.store.load)
        self.refused("NO RECORD", self.store.restore, self.envs[:3])                 # no chain from a peer helps
        old_counter = self.tpm.nv["0x1500016"][1]
        self.assertEqual(self.store.reanchor(self.envs[:3])["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.pinned(), self.hw.unusable()), (3, (3, self.digest(3)), True, None))
        new_base = int.from_bytes(self.tpm.nv["0x1500017"][1], "big")
        self.assertGreater(new_base, old_counter)                                    # a new counter, above every value the old one held
        self.assertEqual(self.tpm.nv["0x1500016"][1], new_base + 3)
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 3)
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).commit(self.envs[3])["epoch"], 4)     # and it goes on from there

    def test_a_longer_chain_brings_the_newer_epochs(self):
        self.lose_record()
        self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)
        self.assertEqual((self.hw.value(), self.hw.record()), (5, (5, self.digest(5))))

    def test_a_usable_anchor_is_never_reset(self):
        before = self.state()
        self.unchanged(before, "the TPM anchor is usable: it is not reset", self.store.reanchor, self.envs[:3])
        self.unchanged(before, "the TPM anchor is usable: it is not reset", self.store.reanchor, self.envs)
        # nor in the crash window, which load() repairs by itself
        self.store._write(self.envs[:4])
        self.hw.advance(4)
        before = self.state()
        self.assertEqual((self.hw.pinned(), self.hw.unusable()), (False, None))
        self.unchanged(before, "the TPM anchor is usable: it is not reset", self.store.reanchor, self.envs[:4])
        # nor with ONE slot lost: the other is the record
        self.tpm(["tpm2_nvwrite", "0x150001a", "-C", "o", "-i", "-"], input=GARBAGE)
        self.tpm(["tpm2_nvwrite", "0x150001b", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(3, self.digest(3)))
        before = self.state()
        self.unchanged(before, "the TPM anchor is usable: it is not reset", self.store.reanchor, self.envs[:4])

    def test_it_is_not_a_way_back_below_a_counter_that_still_reads(self):
        self.lose_record()
        before = self.state()
        self.unchanged(before, "the fetched chain ends at epoch 2, below the TPM high-water 3, which still reads: re-anchoring does not go back",
                       self.store.reanchor, self.envs[:2])
        # a counter moved outside Store: the record is two behind, the anchor inconsistent, and the chain must still reach the counter
        fresh = Case()
        fresh.setUp()
        self.addCleanup(fresh.doCleanups)
        fresh.hw.advance(5)
        self.assertIn("the TPM record is for epoch 3 but the TPM high-water is 5", fresh.hw.unusable())
        before = fresh.state()
        fresh.unchanged(before, "below the TPM high-water 5, which still reads", fresh.store.reanchor, fresh.envs[:4])
        self.assertEqual(fresh.store.reanchor(fresh.envs)["epoch"], 5)

    def test_a_counter_that_is_gone_puts_no_floor_and_is_replaced(self):
        self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])
        self.refused("fail closed", self.hw.value)
        self.assertIn("fail closed", self.hw.unusable())
        self.assertEqual(self.store.reanchor(self.envs[:3])["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (3, (3, self.digest(3)), None))

    def test_the_chain_is_verified_from_the_root_and_against_the_disk_before_anything_changes(self):
        self.lose_record()
        before = self.state()
        forged = self.envs[:2] + [dict(self.envs[2], signature=dict(self.envs[2]["signature"], sig="00" * 64))]
        fork3 = sign(manifest(3, self.digest(2), three(c="QUARANTINED")), ROOT)
        for reason, envelopes in (("a chain to re-anchor on is a non-empty list of envelopes", []),
                                  ("a chain to re-anchor on is a non-empty list of envelopes", {"manifest": 1}),
                                  ("the manifest signature does not verify", forged),
                                  ("the fetched chain repeats epoch 2", self.envs[:2] + [self.envs[1], self.envs[2]]),
                                  ("the first manifest must be the root-signed epoch 1", self.envs[1:3]),
                                  ("CONFLICT: the fetched chain differs from the stored one at epoch 3", self.envs[:2] + [fork3])):
            with self.subTest(reason=reason):
                self.unchanged(before, reason, self.store.reanchor, envelopes)
        with mock.patch.object(m, "MAX_CHAIN_BYTES", 100):
            self.unchanged(before, "the chain to re-anchor on is oversized", self.store.reanchor, self.envs[:3])

    def test_a_crash_after_the_disk_write_leaves_the_old_anchor_and_is_run_again(self):
        self.lose_record()
        nv = copy.deepcopy(self.tpm.nv)
        with mock.patch.object(self.hw, "redefine", side_effect=RuntimeError("power lost")), self.assertRaises(RuntimeError):
            self.store.reanchor(self.envs)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), m.canonical(self.envs))                       # the verified chain is on disk
        self.assertEqual(self.tpm.nv, nv)                                            # the TPM as it was: still no record
        self.refused("NO RECORD", m.Store(self.path, ROOT_PUB, self.hw).load)
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).reanchor(self.envs)["epoch"], 5)

    def test_a_crash_after_the_new_anchor_is_defined_is_completed_by_load(self):
        self.lose_record()
        with mock.patch.object(self.hw, "anchor", side_effect=RuntimeError("power lost")), self.assertRaises(RuntimeError):
            self.store.reanchor(self.envs)
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (0, (0, "00" * 32), None))   # a new, empty anchor
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 5)   # and the chain on disk is the one that was verified
        self.assertEqual((self.hw.value(), self.hw.record()), (5, (5, self.digest(5))))

    def test_a_chain_longer_than_one_jump_is_anchored_in_steps(self):
        self.lose_record()
        with mock.patch.object(m.HighWater, "MAX_JUMP", 2):
            self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)
        self.assertEqual((self.hw.value(), self.hw.record()), (5, (5, self.digest(5))))


class Command(Case):
    """reanchor.reanchor() and the program: who must agree, what the operator types, what is recorded."""

    def sources(self, upto=3, **more):
        return dict({AUTHORITY: self.envs[:upto], "c": self.envs[:upto]}, **more)

    def run_reanchor(self, sources, typed=None, node_id="b"):
        return reanchor.reanchor(self.store, sources, node_id, typed or (lambda planned: reanchor.phrase(node_id, planned)), self.events.append)

    def test_the_authority_and_a_peer_that_agree_re_anchor_the_node_and_it_is_recorded(self):
        self.lose_record()
        seen = []
        typed = lambda planned: seen.append(planned) or "re-anchor b at epoch 3 %s" % self.digest(3)[:8]
        self.assertEqual(self.run_reanchor(self.sources(), typed), {"epoch": 3, "manifest_digest": self.digest(3)})
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (3, (3, self.digest(3)), None))
        self.assertEqual((seen[0]["epoch"], seen[0]["old_epoch"], seen[0]["sources"], seen[0]["chain"]), (3, 3, [AUTHORITY, "c"], self.envs[:3]))
        self.assertIn("NO RECORD", seen[0]["reason"])
        self.assertEqual(len(self.events), 1)
        event = self.events[0]
        self.assertEqual({k: event[k] for k in ("event", "outcome", "reason", "subject", "peer", "epoch", "manifest_digest", "sources")},
                         {"event": "reanchor", "outcome": "ALLOW", "reason": "", "subject": "b", "peer": "operator", "epoch": 3,
                          "manifest_digest": self.digest(3), "sources": [AUTHORITY, "c"]})
        self.assertIn("NO RECORD", event["anchor_was"])

    def test_the_longest_of_the_agreeing_chains_is_anchored(self):
        self.lose_record()
        self.assertEqual(self.run_reanchor({AUTHORITY: self.envs, "c": self.envs[:3]})["epoch"], 5)

    def denied(self, reason, sources, typed=None, node_id="b"):
        before, events = self.state(), len(self.events)
        self.unchanged(before, reason, self.run_reanchor, sources, typed, node_id)
        self.assertEqual(len(self.events), events + 1)
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertIn(reason[:60], self.events[-1]["reason"])

    def test_two_peers_alone_cannot_re_anchor_a_node(self):
        self.lose_record()
        self.denied("re-anchoring needs the revocation authority's chain: peers alone cannot re-anchor a node", {"a": self.envs[:3], "c": self.envs[:3]})
        self.denied("re-anchoring needs the revocation authority's chain", {"c": self.envs[:3]})
        self.denied("re-anchoring needs the revocation authority's chain", {})
        self.denied("sources must map each source to the chain it gave", [self.envs[:3], self.envs[:3]])

    def test_the_authority_alone_cannot_either(self):
        self.lose_record()
        self.denied("re-anchoring needs the authority's chain and at least one peer's (1 source given)", {AUTHORITY: self.envs[:3]})

    def test_the_sources_must_agree_and_be_trusted_by_the_chain(self):
        self.lose_record()
        fork3 = sign(manifest(3, self.digest(2), three(c="QUARANTINED")), ROOT)
        fork = self.envs[:2] + [fork3]
        self.denied("CONFLICT: the sources' chains differ at epoch 3", {AUTHORITY: self.envs[:3], "c": fork})
        self.denied("CONFLICT: the sources' chains differ at epoch 3", {AUTHORITY: fork, "c": self.envs[:3]})
        self.denied("'z' is not a source this chain trusts", {AUTHORITY: self.envs[:3], "z": self.envs[:3]})
        retired = chain(3, c="RETIRED")
        os.unlink(self.path)                                                         # (the disk would refuse this other chain first)
        with open(self.path, "wb") as f:
            f.write(m.canonical(retired[:2]))
        self.denied("'c' is not a source this chain trusts", {AUTHORITY: retired, "c": retired})   # a node that chain has retired vouches for nothing
        self.denied("a fetched chain ends at epoch 2, below the TPM high-water 3", {AUTHORITY: self.envs[:3], "c": self.envs[:2]})
        self.denied("the manifest signature does not verify",
                    {AUTHORITY: self.envs[:3], "c": self.envs[:2] + [dict(self.envs[2], signature=dict(self.envs[2]["signature"], sig="00" * 64))]})

    def test_a_fork_two_sources_agree_on_is_still_refused_by_the_disk(self):
        self.lose_record()
        fork = self.envs[:2] + [sign(manifest(3, self.digest(2), three(a="MAINTENANCE")), ROOT)]
        self.denied("CONFLICT: the fetched chain differs from the stored one at epoch 3", {AUTHORITY: fork, "c": fork})

    def test_a_usable_anchor_is_refused_before_any_chain_is_looked_at(self):
        self.denied("the TPM anchor is usable: it is not reset", self.sources())
        self.denied("the TPM anchor is usable: it is not reset", {AUTHORITY: "not even a chain", "c": None})

    def test_the_operator_must_type_the_node_the_epoch_and_the_digest(self):
        self.lose_record()
        right = "re-anchor b at epoch 3 %s" % self.digest(3)[:8]
        for wrong in ("", "yes", right.upper(), right + " ", right.replace("epoch 3", "epoch 4"), right[:-1] + ("0" if right[-1] != "0" else "1"),
                      right.replace("re-anchor b", "re-anchor c"), None):
            with self.subTest(typed=wrong):
                self.denied("not confirmed: the phrase typed is not %r" % right, self.sources(), lambda planned: wrong)
        self.assertEqual(self.run_reanchor(self.sources(), lambda planned: right)["epoch"], 3)

    def test_nothing_is_asked_when_the_plan_is_refused(self):
        asked = []
        self.denied("the TPM anchor is usable", self.sources(), lambda planned: asked.append(planned) or "x")
        self.lose_record()
        self.denied("re-anchoring needs the revocation authority's chain", {"c": self.envs[:3]}, lambda planned: asked.append(planned) or "x")
        self.assertEqual(asked, [])

    def test_the_node_must_be_one_of_the_chain(self):
        self.lose_record()
        self.denied("z9 is not a node of the chain being anchored", self.sources(), None, "z9")
        before = self.state()
        for bad in ("", "B", "b c", None, "@authority"):
            with self.subTest(node_id=bad):
                self.unchanged(before, "node_id must be a node ID", self.run_reanchor, self.sources(), None, bad)

    def program(self, *extra, typed=None, peers=("c",), upto=3, log="audit.jsonl"):
        for name in (AUTHORITY,) + tuple(peers):
            with open("%s/%s.json" % (self.d, name.strip("@")), "wb") as f:
                f.write(m.canonical(self.envs[:upto]))
        argv = ["--membership", self.path, "--root-key", ROOT_PUB, "--tpm-index", "0x1500016", "--node-id", "b",
                "--authority", self.d + "/authority.json", "--audit-log", "%s/%s" % (self.d, log)]
        for name in peers:
            argv += ["--peer", "%s=%s/%s.json" % (name, self.d, name)]
        asked = []

        def ask(prompt):
            asked.append(prompt)
            return typed if typed is not None else prompt.split("Type exactly: ")[1].split("\n")[0]
        self.said = io.StringIO()
        with contextlib.redirect_stderr(self.said), contextlib.redirect_stdout(io.StringIO()):
            rc = reanchor.main(argv + list(extra), ask=ask, highwater=lambda index: m.HighWater(index, lock_path=self.d + "/hw.lock", run=self.tpm))
        return rc, asked

    def audit(self, log="audit.jsonl"):
        with open("%s/%s" % (self.d, log)) as f:
            return [json.loads(line) for line in f]

    def test_the_program_re_anchors_and_writes_the_request_and_the_outcome_to_the_audit_log(self):
        self.lose_record()
        rc, asked = self.program()
        self.assertEqual((rc, len(asked)), (0, 1))
        self.assertIn("Type exactly: re-anchor b at epoch 3 %s" % self.digest(3)[:8], asked[0])
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (3, (3, self.digest(3)), None))
        log = self.audit()
        self.assertEqual([(e["event"], e.get("outcome")) for e in log], [("reanchor-requested", None), ("reanchor", "ALLOW")])
        self.assertEqual((log[1]["epoch"], log[1]["manifest_digest"], log[1]["sources"], log[1]["subject"]), (3, self.digest(3), [AUTHORITY, "c"], "b"))
        self.assertRegex(log[1]["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(os.stat(self.d + "/audit.jsonl").st_mode & 0o777, 0o600)

    def test_the_program_refuses_and_records_the_refusal(self):
        self.lose_record()
        before = self.state()
        for label, kw, extra, lines, said in (
                ("the wrong phrase", {"typed": "yes"}, (), 2, "NOT DONE: not confirmed: the phrase typed is not"),
                ("no peer", {"peers": ()}, (), 2, "NOT DONE: re-anchoring needs the authority's chain and at least one peer's (1 source given)"),
                ("a chain that is behind", {"upto": 2}, (), 2, "NOT DONE: a fetched chain ends at epoch 2, below the TPM high-water 3"),
                ("a peer named twice", {}, ("--peer", "c=%s/c.json" % self.d), 0, "NOT DONE: --peer names c twice"),
                ("a peer without a file", {}, ("--peer", "a"), 0, "NOT DONE: --peer takes NODE=CHAIN.json, not 'a'"),
                ("a peer without a name", {}, ("--peer", "=%s/c.json" % self.d), 0, "NOT DONE: --peer takes NODE=CHAIN.json, not"),
                ("a peer file that is absent", {}, ("--peer", "a=%s/absent.json" % self.d), 0, "No such file or directory")):
            with self.subTest(label):
                log = "audit-%d.jsonl" % len(label)
                self.assertEqual(self.program(*extra, log=log, **kw)[0], 1)
                self.assertIn(said, self.said.getvalue())
                self.assertEqual(self.state(), before)
                entries = self.audit(log) if os.path.exists("%s/%s" % (self.d, log)) else []
                self.assertEqual(len(entries), lines)
                if lines:
                    self.assertEqual((entries[0]["event"], entries[1]["outcome"]), ("reanchor-requested", "DENY"))

    def test_without_a_writable_audit_log_nothing_is_done(self):
        self.lose_record()
        before = self.state()
        rc, asked = self.program(log="no-such-directory/audit.jsonl")
        self.assertEqual((rc, asked, self.state()), (1, [], before))

    def test_a_malformed_tpm_index_or_root_key_is_refused(self):
        self.lose_record()
        before = self.state()
        for extra, said in ((("--tpm-index", "zz"), "--tpm-index must be 0x and up to 8 hex digits"),
                            (("--tpm-index", "1500016"), "--tpm-index must be 0x and up to 8 hex digits"),
                            (("--tpm-index", "0x1500016; rm"), "--tpm-index must be 0x and up to 8 hex digits"),
                            (("--root-key", "AB" * 32), "--root-key must be 64 lowercase hex")):
            with self.subTest(extra=extra):
                self.assertEqual(self.program(*extra)[0], 1)
                self.assertIn(said, self.said.getvalue())
                self.assertEqual(self.state(), before)


class OnlyAnOperator(unittest.TestCase):
    """Re-anchoring resets rollback protection. Nothing a service runs, and nothing that handles what a peer
    sent, may reach it."""

    def test_only_the_command_calls_it(self):
        here = os.path.dirname(os.path.abspath(__file__))
        found = {}
        for path in sorted(glob.glob(os.path.join(here, "..", "deploy", "**", "*.py"), recursive=True)):
            with open(path) as f:
                tree = ast.parse(f.read())
            name = os.path.basename(path)
            for item in ast.walk(tree):
                if isinstance(item, ast.Call) and isinstance(item.func, (ast.Attribute, ast.Name)):
                    called = item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
                    if called in ("reanchor", "redefine"):
                        found.setdefault(called, set()).add(name)
                if isinstance(item, (ast.Import, ast.ImportFrom)) and any(alias.name.split(".")[-1] == "reanchor" for alias in item.names):
                    found.setdefault("import", set()).add(name)
        # Store.reanchor is called by the command, HighWater.redefine by Store.reanchor, and nobody imports the command
        self.assertEqual(found, {"reanchor": {"reanchor.py"}, "redefine": {"membership.py"}})
        self.assertFalse(hasattr(convergence, "reanchor"))


class OnSwtpm(_Swtpm):
    """The same on a real (software) TPM: the record lost in both slots, then re-anchored by the program."""

    def test_a_node_whose_record_is_lost_is_re_anchored_on_a_real_tpm(self):
        path = self.d + "/membership.json"
        envs = chain(4)
        store = m.Store(path, ROOT_PUB, self.hw)
        for env in envs[:3]:
            store.commit(env)
        old_counter = subprocess.run(["tpm2_nvread", "0x1500016", "-C", "o", "-s", "8"], env=self.env, capture_output=True, check=True).stdout
        for index in self.hw.record_indices:
            subprocess.run(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=GARBAGE, env=self.env, check=True, capture_output=True)
        with self.assertRaisesRegex(m.Refused, "NO RECORD"):
            m.Store(path, ROOT_PUB, self.hw).load()
        for name in ("authority", "c"):
            with open("%s/%s.json" % (self.d, name), "wb") as f:
                f.write(m.canonical(envs))
        argv = ["--membership", path, "--root-key", ROOT_PUB, "--tpm-index", "0x1500016", "--node-id", "b", "--authority", self.d + "/authority.json",
                "--peer", "c=%s/c.json" % self.d, "--audit-log", self.d + "/audit.jsonl"]
        make = lambda index: m.HighWater(index, tcti=self.tcti, lock_path=self.d + "/hw.lock")
        self.assertEqual(reanchor.main(argv, ask=lambda prompt: "no", highwater=make), 1)
        self.assertEqual(self.hw.slots(), [None, None])                              # refused: the TPM as it was
        self.assertEqual(reanchor.main(argv, ask=lambda prompt: prompt.split("Type exactly: ")[1].split("\n")[0], highwater=make), 0)
        digest4 = m.digest(envs[3]["manifest"])
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.pinned(), self.hw.unusable()), (4, (4, digest4), True, None))
        new_base = subprocess.run(["tpm2_nvread", "0x1500017", "-C", "o", "-s", "8"], env=self.env, capture_output=True, check=True).stdout
        self.assertGreater(int.from_bytes(new_base, "big"), int.from_bytes(old_counter, "big"))
        self.assertEqual(m.Store(path, ROOT_PUB, self.hw).load()["epoch"], 4)
        with open(self.d + "/audit.jsonl") as f:
            self.assertEqual([json.loads(line).get("outcome") for line in f], [None, "DENY", None, "ALLOW"])


if __name__ == "__main__":
    unittest.main()
