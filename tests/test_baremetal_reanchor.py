"""deploy/baremetal/reanchor.py and membership.Store.reanchor (#68): a new TPM anchor for a node whose anchor
is unusable. Every fence around it has a test: two other nodes that agree, a usable anchor never reset, a silent
TPM never re-anchored, nothing the TPM still holds forgotten, never an empty anchor on the way, verified
before anything changes, typed at a terminal, recorded (and INCOMPLETE said when it is)."""
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

from deploy.baremetal import convergence, reanchor, trails
from deploy.baremetal import membership as m
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_membership import ROOT, ROOT_PUB, _Swtpm, manifest, sign, three

OTHER = "a"                      # the other node beside c whose chain vouches (#199: there is no authority any more)
GARBAGE = b"\x5a" * 48


def chain(upto, **last):
    """Epochs 1..upto, root-signed; `last` sets node states in the newest manifest."""
    envs, cur = [], None
    for e in range(1, upto + 1):
        states = last if e == upto else {}
        # b, the node re-anchored (never a source), alternates so that every epoch's manifest differs; a and c, the two
        # sources (#199), stay ACTIVE: they may authorize, so they may vouch
        env = sign(manifest(e, m.digest(cur) if cur else "", three(**dict({"b": "DRAINING" if e % 2 else "ACTIVE"}, **states))), ROOT)
        cur = m.accept(cur, env, ROOT_PUB)
        envs.append(env)
    return envs


class PowerLost(Exception):
    pass


class Case(unittest.TestCase):
    """Node b at epoch 3 on a FakeTpm. `lose_record()` leaves neither record slot valid. `self.fail_from`
    makes every TPM call from that one on raise PowerLost; `self.silent` makes the TPM answer nothing;
    `self.refuse` picks single calls that fail."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.calls, self.fail_from, self.silent, self.refuse = 0, None, False, lambda argv: False
        self.hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.run_tpm)
        self.hw.define()
        self.path = self.d + "/membership.json"
        self.envs = chain(5)
        self.store = m.Store(self.path, ROOT_PUB, self.hw)
        for env in self.envs[:3]:
            self.store.commit(env)
        self.events = []

    def run_tpm(self, argv, **kw):
        self.calls += 1
        if self.fail_from is not None and self.calls >= self.fail_from:
            raise PowerLost("at TPM call %d: %s" % (self.calls, " ".join(argv[:2])))
        if self.silent or self.refuse(argv):
            return subprocess.CompletedProcess(argv, 1, b"", b"no answer")
        return self.tpm(argv, **kw)

    def lose_record(self):
        for index in self.hw.record_indices:
            self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=GARBAGE)

    def state(self):
        """Everything a refusal must leave alone: the TPM's NV indices and the membership file."""
        content = None
        if os.path.exists(self.path):
            with open(self.path, "rb") as f:
                content = f.read()
        return copy.deepcopy(self.tpm.nv), self.tpm.highest, content

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
    def test_a_node_with_no_record_gets_a_new_anchor_at_the_chains_epoch(self):
        self.lose_record()
        self.refused("NO RECORD", self.store.load)
        self.refused("NO RECORD", self.store.restore, self.envs[:3])                 # no chain from a peer helps
        old_counter = self.tpm.nv["0x1500016"][1]
        self.assertEqual(self.store.reanchor(self.envs[:3])["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.slots(), self.hw.pinned(), self.hw.unusable()),
                         (3, [(3, self.digest(3))] * 2, True, None))                 # AT epoch 3, both slots, from the first moment
        self.assertGreater(self.tpm.nv["0x1500016"][1], old_counter)                 # a new counter, above every value the old one held
        self.assertEqual(int.from_bytes(self.tpm.nv["0x1500017"][1], "big"), self.tpm.nv["0x1500016"][1] - 3)
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 3)
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).commit(self.envs[3])["epoch"], 4)     # and it goes on from there

    def test_a_longer_chain_brings_the_newer_epochs_whatever_the_jump_bound(self):
        self.lose_record()
        with mock.patch.object(m.HighWater, "MAX_JUMP", 1):                          # no stepping: the anchor is defined at the epoch
            self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)
        self.assertEqual((self.hw.value(), self.hw.record()), (5, (5, self.digest(5))))

    def test_on_a_tpm_that_never_held_a_counter_that_high_the_counter_is_raised_first(self):
        self.tpm.nv.clear()
        self.tpm.highest = 0                                                         # a new TPM: the first increment lands at 1
        self.assertIn("the index is not defined", self.hw.unusable())
        self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)
        self.assertEqual((self.hw.value(), self.tpm.nv["0x1500016"][1], int.from_bytes(self.tpm.nv["0x1500017"][1], "big")), (5, 5, 0))

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

    def test_a_tpm_that_does_not_answer_is_not_re_anchored(self):
        """51's finding 2: any failure used to read as "unusable", and a failing counter removed the floor."""
        os.unlink(self.path)
        before = self.state()
        self.silent = True
        self.refused("the TPM does not answer", self.hw.unusable)                    # neither usable nor unusable: unknown
        self.unchanged(before, "the TPM does not answer", self.store.reanchor, self.envs[:1])
        self.silent = False
        # the TPM answers and lists the counter, and one read of it fails: still not "the index is missing"
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvreadpublic", "0x1500016"]
        self.refused("cannot read NV index 0x1500016: the high-water anchor is unavailable (fail closed): the TPM lists it and did not give it", self.hw.unusable)
        self.unchanged(before, "the TPM lists it and did not give it", self.store.reanchor, self.envs[:1])
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvread", "0x150001a"]          # a record slot that is as it should be and does not read
        self.unchanged(before, "cannot read 48 bytes from the record index 0x150001a", self.store.reanchor, self.envs[:1])
        self.refuse = lambda argv: argv[0] == "tpm2_getcap"                          # an index really missing, and the TPM cannot be asked what it holds
        self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])
        before = self.state()
        self.unchanged(before, "the TPM does not answer (tpm2_getcap handles-nv-index failed)", self.store.reanchor, self.envs[:3])
        self.refuse = lambda argv: False
        self.assertIn("the index is not defined", self.hw.unusable())                # now the TPM says so: that is an unusable anchor
        self.assertEqual(self.store.reanchor(self.envs[:3])["epoch"], 3)

    def test_it_is_not_a_way_back_below_a_counter_that_still_reads(self):
        self.lose_record()
        before = self.state()
        self.unchanged(before, "the fetched chain ends at epoch 2, below epoch 3, which this node's TPM still holds (its counter): re-anchoring does not go back",
                       self.store.reanchor, self.envs[:2])
        # a counter moved outside Store: the record is two behind, the anchor inconsistent, and the chain must still reach the counter
        self.tpm(["tpm2_nvwrite", "0x150001a", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(3, self.digest(3)))
        self.hw.advance(5)
        self.assertIn("the TPM record is for epoch 3 but the TPM high-water is 5", self.hw.unusable())
        before = self.state()
        self.unchanged(before, "below epoch 5, which this node's TPM still holds (its counter)", self.store.reanchor, self.envs[:4])
        self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)

    def test_a_record_slot_that_still_reads_is_not_forgotten(self):
        """51's finding 1: with the counter gone the only floor was gone too, and a slot that still validated
        was never compared with the chain. The node went from epoch 3 to epoch 1, or onto a fork at epoch 3."""
        fork = self.envs[:2] + [sign(manifest(3, self.digest(2), three(c="QUARANTINED")), ROOT)]
        for label, damage in (("the counter is gone, both slots read", lambda: self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])),
                              ("the counter is gone and one slot is garbage", lambda: self.tpm(["tpm2_nvwrite", "0x150001b", "-C", "o", "-i", "-"], input=GARBAGE)),
                              ("the base is gone too", lambda: self.tpm(["tpm2_nvundefine", "0x1500017", "-C", "o"]))):
            with self.subTest(label):
                damage()
                if os.path.exists(self.path):
                    os.unlink(self.path)                                             # the disk says nothing either
                self.assertIsNotNone(self.hw.unusable())
                self.assertIn((3, self.digest(3)), self.hw.remains()[1])
                before = self.state()
                self.unchanged(before, "the fetched chain ends at epoch 1, below epoch 3, which this node's TPM still holds (a record slot)",
                               self.store.reanchor, self.envs[:1])
                self.unchanged(before, "CONFLICT: a record slot that still reads names another manifest at epoch 3 than the fetched chain",
                               self.store.reanchor, fork)
                self.unchanged(before, "CONFLICT: a record slot that still reads names another manifest at epoch 3",
                               self.store.reanchor, fork + [sign(manifest(4, m.digest(fork[2]["manifest"]), three()), ROOT)])
        self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)                  # the chain it was on, however much newer
        self.assertEqual(self.hw.slots(), [(5, self.digest(5))] * 2)

    def test_a_slot_of_another_size_is_not_a_record_slot(self):
        """51's finding 9: a 64-byte index holding a valid 48-byte record was accepted. And main's old single
        40-byte record is not read as one: such a node is re-anchored, its counter still the floor."""
        for size in (40, 64):
            with self.subTest(size=size):
                self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
                self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", str(size), "-a", "ownerread|ownerwrite|authread|authwrite"])
                self.tpm(["tpm2_nvwrite", "0x150001b", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(3, self.digest(3))[:size])
                self.assertEqual(self.hw.unusable(), "record index 0x150001b is %d bytes, not 48" % size)
                self.refused("record index 0x150001b is %d bytes, not 48" % size, self.store.load)
        before = self.state()
        self.unchanged(before, "below epoch 3, which this node's TPM still holds (its counter)", self.store.reanchor, self.envs[:2])
        self.assertEqual(self.store.reanchor(self.envs[:3])["epoch"], 3)
        self.assertEqual(self.hw.slots(), [(3, self.digest(3))] * 2)

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
                self.assertFalse(self.store.reanchor_began)
        with mock.patch.object(m, "MAX_CHAIN_BYTES", 100):
            self.unchanged(before, "the chain to re-anchor on is oversized", self.store.reanchor, self.envs[:3])

    def interrupted_at_every_call(self, max_jump, damage="lose_record"):
        """Re-anchor onto epochs 1-5 with the power lost at the k-th TPM call of the redefinition, for every k.
        What is left is never an anchor that would take another chain (51's findings 3 and 4), and never one
        that has forgotten a valid record (51's second-round finding A)."""
        outcomes = set()
        for k in range(1, 200):
            case = Case()
            case.setUp()
            try:
                if damage == "lose_record":
                    case.lose_record()
                else:                                                # the counter is gone; both slots still hold valid records (3, then 2)
                    case.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])
                    os.unlink(case.path)
                with mock.patch.object(m.HighWater, "MAX_JUMP", max_jump):
                    real = case.hw.redefine

                    def redefine(*args, **kw):
                        case.fail_from = case.calls + k                  # the k-th TPM call of the redefinition and all after it
                        return real(*args, **kw)
                    try:
                        with mock.patch.object(case.hw, "redefine", redefine):
                            case.store.reanchor(case.envs)
                        outcomes.add("finished")
                        self.assertGreater(k, 10)
                        break
                    except PowerLost:
                        pass
                    case.fail_from = None
                    self.assertTrue(case.store.reanchor_began)
                    counter, records = case.hw.remains()
                    floor = max([counter or 0] + [epoch for epoch, _ in records])
                    self.assertGreaterEqual(floor, 3, "after TPM call %d the TPM holds less than the epoch 3 it held" % k)
                    for epoch, held_digest in records:               # and every record it holds is the chain's
                        self.assertEqual(held_digest, case.digest(epoch), "after TPM call %d" % k)
                    with open(case.path, "rb") as f:
                        self.assertEqual(f.read(), m.canonical(case.envs))           # the verified chain is on disk
                    why = case.hw.unusable()
                    if why is None:                                                  # usable: then it is the finished anchor, nothing less
                        outcomes.add("usable at the chain's epoch")
                        self.assertEqual((case.hw.value(), case.hw.record()), (5, (5, case.digest(5))), "after TPM call %d" % k)
                    else:
                        outcomes.add("unusable")
                    # the disk swapped for an older chain, or a fork, in that state: never accepted
                    fork = case.envs[:4] + [sign(manifest(5, case.digest(4), three(c="QUARANTINED")), ROOT)]
                    for swapped in (case.envs[:1], case.envs[:4], fork):
                        with open(case.path, "wb") as f:
                            f.write(m.canonical(swapped))
                        with self.assertRaises(m.Refused, msg="after TPM call %d the node loaded %d envelopes" % (k, len(swapped))):
                            m.Store(case.path, ROOT_PUB, case.hw).load()
                    with open(case.path, "wb") as f:
                        f.write(m.canonical(case.envs))
                    # and the way forward exists: run it again if the anchor is unusable, load if it is finished
                    again = m.Store(case.path, ROOT_PUB, case.hw)
                    done = again.load() if why is None else again.reanchor(case.envs)
                    self.assertEqual((done["epoch"], case.hw.value(), case.hw.record(), case.hw.unusable()), (5, 5, (5, case.digest(5)), None),
                                     "after TPM call %d" % k)
                    self.assertEqual(m.Store(case.path, ROOT_PUB, case.hw).load()["epoch"], 5)
            finally:
                case.doCleanups()
        self.assertEqual(outcomes, {"finished", "unusable", "usable at the chain's epoch"})

    def test_power_lost_at_any_point_of_the_redefinition_never_leaves_an_anchor_for_another_chain(self):
        self.interrupted_at_every_call(m.HighWater.MAX_JUMP)

    def test_and_a_chain_longer_than_one_jump_is_not_stranded_by_it(self):
        self.interrupted_at_every_call(2)

    def test_power_lost_while_valid_records_remain_never_lowers_what_the_tpm_holds(self):
        """51's second-round finding A: the slots were deleted in index order, so a cut after the first delete
        left only the older record (floor 2), after both nothing; with the file gone or garbage, a re-anchor
        to epoch 2, or onto a fork at 3, then succeeded. The slots are no longer deleted."""
        self.interrupted_at_every_call(m.HighWater.MAX_JUMP, damage="counter gone, valid slots")

    def test_after_a_cut_with_the_file_gone_a_lower_chain_or_a_fork_is_still_refused(self):
        self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])
        os.unlink(self.path)
        real = self.hw.redefine

        def redefine(*args, **kw):
            self.fail_from = self.calls + 12                         # past the first record write and the counter's delete
            return real(*args, **kw)
        with mock.patch.object(self.hw, "redefine", redefine), self.assertRaises(PowerLost):
            self.store.reanchor(self.envs)
        self.fail_from = None
        os.unlink(self.path)                                         # the disk is no guard
        self.assertIn((5, self.digest(5)), self.hw.remains()[1])                     # the new record went in before the counter was touched
        fork = self.envs[:4] + [sign(manifest(5, self.digest(4), three(c="QUARANTINED")), ROOT)]
        before = self.state()
        self.unchanged(before, "below epoch 5, which this node's TPM still holds (a record slot)", self.store.reanchor, self.envs[:2])
        self.unchanged(before, "below epoch 5, which this node's TPM still holds (a record slot)", self.store.reanchor, self.envs[:3])
        self.unchanged(before, "CONFLICT: a record slot that still reads names another manifest at epoch 5", self.store.reanchor, fork)
        self.assertEqual(self.store.reanchor(self.envs)["epoch"], 5)

    def test_a_crash_after_the_disk_write_leaves_the_old_remains_and_is_run_again(self):
        self.lose_record()
        nv = copy.deepcopy(self.tpm.nv)
        with mock.patch.object(self.hw, "redefine", side_effect=PowerLost("before the TPM was touched")), self.assertRaises(PowerLost):
            self.store.reanchor(self.envs)
        self.assertTrue(self.store.reanchor_began)
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), m.canonical(self.envs))                       # the verified chain is on disk
        self.assertEqual(self.tpm.nv, nv)                                            # the TPM as it was: still no record
        self.refused("NO RECORD", m.Store(self.path, ROOT_PUB, self.hw).load)
        # and the file now on disk binds the next attempt: a shorter chain is refused by it
        self.refused("the fetched chain is shorter than the stored one", m.Store(self.path, ROOT_PUB, self.hw).reanchor, self.envs[:3])
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).reanchor(self.envs)["epoch"], 5)

    def test_an_index_that_cannot_be_deleted_stops_it_and_is_run_again(self):
        self.lose_record()
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvundefine", "0x1500017"]
        self.refused("cannot delete NV index 0x1500017", self.store.reanchor, self.envs)
        self.assertTrue(self.store.reanchor_began)
        self.assertIn("the index is not defined", self.hw.unusable())                # the counter is gone; the new record is in a slot
        self.assertIn((5, self.digest(5)), self.hw.remains()[1])
        self.refuse = lambda argv: False
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).reanchor(self.envs)["epoch"], 5)


class Command(Case):
    """reanchor.reanchor() and the program: who must agree, what the operator types, what is recorded."""

    def sources(self, upto=3, **more):
        return dict({OTHER: self.envs[:upto], "c": self.envs[:upto]}, **more)

    def run_reanchor(self, sources, typed=None, node_id="b"):
        return reanchor.reanchor(self.store, sources, node_id, typed or (lambda planned: reanchor.phrase(node_id, planned)), self.events.append)

    def outcomes(self):
        return [(e["event"], e.get("outcome")) for e in self.events]

    def test_two_other_nodes_that_agree_re_anchor_the_node_and_it_is_recorded(self):
        self.lose_record()
        seen = []
        typed = lambda planned: seen.append(planned) or "re-anchor b at epoch 3 %s" % self.digest(3)[:8]
        self.assertEqual(self.run_reanchor(self.sources(), typed), {"epoch": 3, "manifest_digest": self.digest(3)})
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (3, (3, self.digest(3)), None))
        self.assertEqual((seen[0]["epoch"], seen[0]["counter"], seen[0]["records"], seen[0]["sources"], seen[0]["chain"]), (3, 3, [], [OTHER, "c"], self.envs[:3]))
        self.assertIn("NO RECORD", seen[0]["reason"])
        self.assertEqual(self.outcomes(), [("reanchor-requested", None), ("reanchor", "ALLOW")])
        for event in self.events:                                # the request names what is about to be anchored, before it is
            self.assertEqual({k: event[k] for k in ("subject", "peer", "epoch", "manifest_digest", "sources")},
                             {"subject": "b", "peer": "operator", "epoch": 3, "manifest_digest": self.digest(3), "sources": [OTHER, "c"]})
            self.assertIn("NO RECORD", event["anchor_was"])

    def test_the_request_is_recorded_before_anything_is_asked_or_changed(self):
        self.lose_record()
        before = self.state()
        seen = []

        def typed(planned):
            seen.append((self.outcomes(), self.state() == before))
            return reanchor.phrase("b", planned)
        self.run_reanchor(self.sources(), typed)
        self.assertEqual(seen, [([("reanchor-requested", None)], True)])
        # and if the request cannot be recorded, nothing is asked and nothing is done
        self.lose_record()
        before = self.state()
        with self.assertRaises(OSError):
            reanchor.reanchor(self.store, self.sources(), "b", lambda planned: self.fail("asked"), mock.Mock(side_effect=OSError("disk full")))
        self.assertEqual(self.state(), before)

    def denied(self, reason, sources, typed=None, node_id="b", requested=False):
        before, events = self.state(), len(self.events)
        self.unchanged(before, reason, self.run_reanchor, sources, typed, node_id)
        self.assertEqual([e.get("outcome") for e in self.events[events:]], ([None] if requested else []) + ["DENY"])
        self.assertIn(reason[:60], self.events[-1]["reason"])

    def test_one_node_alone_cannot_re_anchor_a_node(self):
        """#199: two other nodes are the quorum (there is no authority any more): one node's chain is not enough."""
        self.lose_record()
        self.denied("re-anchoring needs whole chains from at least two other nodes (1 source given)", {"c": self.envs[:3]})
        self.denied("re-anchoring needs whole chains from at least two other nodes (1 source given)", {OTHER: self.envs[:3]})
        self.denied("re-anchoring needs whole chains from at least two other nodes (0 source given)", {})
        self.denied("sources must map each source to the chain it gave", [self.envs[:3], self.envs[:3]])

    def test_the_node_is_not_a_source_for_its_own_re_anchor(self):
        """51's finding 6: {a source, b} re-anchored node b: the "peer" was the node itself."""
        self.lose_record()
        self.denied("b cannot be a source for its own re-anchor", {OTHER: self.envs[:3], "b": self.envs[:3]})
        self.denied("b cannot be a source for its own re-anchor", {OTHER: self.envs[:3], "b": self.envs[:3], "c": self.envs[:3]})

    def test_every_source_gives_the_same_whole_chain(self):
        """51's finding 6: the longest chain won, so one node at 1..3 with another at 1..5 anchored epoch 5 on the
        second's word alone. #199: no source is privileged any more, so a chain ahead of another, either way round,
        is refused; the same whole chain from both is anchored."""
        self.lose_record()
        for chains in ({OTHER: self.envs[:3], "c": self.envs}, {OTHER: self.envs, "c": self.envs[:3]}):
            with self.subTest(sorted((k, len(v)) for k, v in chains.items())):
                self.denied("the nodes' chains end at different epochs", chains)
        self.assertEqual(self.run_reanchor({OTHER: self.envs, "c": self.envs})["epoch"], 5)
        self.assertEqual(self.events[-2]["epoch"], 5)

    def test_the_sources_must_agree_and_be_trusted_by_the_chain(self):
        self.lose_record()
        fork3 = sign(manifest(3, self.digest(2), three(c="QUARANTINED")), ROOT)
        fork = self.envs[:2] + [fork3]
        self.denied("CONFLICT: the sources' chains differ at epoch 3", {OTHER: self.envs[:3], "c": fork})
        self.denied("CONFLICT: the sources' chains differ at epoch 3", {OTHER: fork, "c": self.envs[:3]})
        self.denied("'z' is not a source this chain trusts", {OTHER: self.envs[:3], "z": self.envs[:3]})
        retired = chain(3, c="RETIRED")
        with open(self.path, "wb") as f:                                             # (the disk would refuse this other chain first)
            f.write(m.canonical(retired[:2]))
        self.denied("'c' is not a source this chain trusts", {OTHER: retired, "c": retired})   # a node that chain has retired vouches for nothing
        self.denied("a fetched chain ends at epoch 2, below the TPM high-water 3", {OTHER: self.envs[:3], "c": self.envs[:2]})
        self.denied("the manifest signature does not verify",
                    {OTHER: self.envs[:3], "c": self.envs[:2] + [dict(self.envs[2], signature=dict(self.envs[2]["signature"], sig="00" * 64))]})

    def test_the_floor_the_sources_must_reach_includes_a_record_slot_that_still_reads(self):
        self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])                        # the counter is gone; the slots hold epoch 3
        os.unlink(self.path)
        self.denied("a fetched chain ends at epoch 1, below the TPM high-water 3", {OTHER: self.envs[:1], "c": self.envs[:1]})
        fork = self.envs[:2] + [sign(manifest(3, self.digest(2), three(b="MAINTENANCE")), ROOT)]
        self.denied("CONFLICT: a record slot that still reads names another manifest at epoch 3", {OTHER: fork, "c": fork}, requested=True)
        seen = []
        self.assertEqual(self.run_reanchor(self.sources(), lambda planned: seen.append(planned) or reanchor.phrase("b", planned))["epoch"], 3)
        self.assertEqual((seen[0]["counter"], sorted(seen[0]["records"])), (None, [(2, self.digest(2)), (3, self.digest(3))]))    # both slots bind the chain

    def test_a_fork_two_sources_agree_on_is_still_refused_by_the_disk(self):
        self.lose_record()
        fork = self.envs[:2] + [sign(manifest(3, self.digest(2), three(b="MAINTENANCE")), ROOT)]
        self.denied("CONFLICT: the fetched chain differs from the stored one at epoch 3", {OTHER: fork, "c": fork}, requested=True)

    def test_a_usable_anchor_or_a_silent_tpm_is_refused_before_any_chain_is_looked_at(self):
        self.denied("the TPM anchor is usable: it is not reset", self.sources())
        self.denied("the TPM anchor is usable: it is not reset", {OTHER: "not even a chain", "c": None})
        self.silent = True
        self.denied("the TPM does not answer", self.sources())

    def test_the_operator_must_type_the_node_the_epoch_and_the_digest(self):
        self.lose_record()
        right = "re-anchor b at epoch 3 %s" % self.digest(3)[:8]
        for wrong in ("", "yes", right.upper(), right + " ", right.replace("epoch 3", "epoch 4"), right[:-1] + ("0" if right[-1] != "0" else "1"),
                      right.replace("re-anchor b", "re-anchor c"), None):
            with self.subTest(typed=wrong):
                self.denied("not confirmed: the phrase typed is not %r" % right, self.sources(), lambda planned: wrong, requested=True)
        self.assertEqual(self.run_reanchor(self.sources(), lambda planned: right)["epoch"], 3)

    def test_nothing_is_asked_when_the_plan_is_refused(self):
        asked = []
        self.denied("the TPM anchor is usable", self.sources(), lambda planned: asked.append(planned) or "x")
        self.lose_record()
        self.denied("re-anchoring needs whole chains from at least two other nodes", {"c": self.envs[:3]}, lambda planned: asked.append(planned) or "x")
        self.assertEqual(asked, [])

    def test_the_node_must_be_one_of_the_chain(self):
        self.lose_record()
        self.denied("z9 is not a node of the chain being anchored", self.sources(), None, "z9")
        for bad in ("", "B", "b c", None, "@b"):
            with self.subTest(node_id=bad):
                self.denied("node_id must be a node ID", self.sources(), None, bad)

    def test_a_failure_after_the_anchor_was_touched_is_incomplete_not_denied(self):
        """51's finding 5: it was reported as DENY, "not done", with the TPM changed."""
        self.lose_record()
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvdefine", "0x1500017"]        # the redefinition fails part-way
        with self.assertRaisesRegex(reanchor.Incomplete, "cannot define the base index 0x1500017"):
            self.run_reanchor(self.sources())
        self.assertEqual(self.outcomes(), [("reanchor-requested", None), ("reanchor", "INCOMPLETE")])
        self.assertIn("cannot define the base index", self.events[-1]["reason"])
        self.assertIn("the index is not defined", self.hw.unusable())                # the new counter has no base yet: not usable for anything
        self.assertIn((3, self.digest(3)), self.hw.remains()[1])                     # and the new record is already in
        self.refuse = lambda argv: False
        self.assertEqual(self.run_reanchor(self.sources())["epoch"], 3)              # run again: it completes
        self.assertEqual(self.outcomes()[-1], ("reanchor", "ALLOW"))

    def program(self, *extra, typed=None, peers=(OTHER, "c"), upto=3, log="audit.jsonl", ask="given", tty=None, owner_check=reanchor._owner_check):
        for name in peers:
            with open("%s/%s.json" % (self.d, name), "wb") as f:
                f.write(m.canonical(self.envs[:upto]))
        argv = ["--membership", self.path, "--root-key", ROOT_PUB, "--tpm-index", "0x1500016", "--node-id", "b",
                "--audit-log", "%s/%s" % (self.d, log)]
        for name in peers:
            argv += ["--peer", "%s=%s/%s.json" % (name, self.d, name)]
        asked = []

        def answer(prompt):
            asked.append(prompt)
            if isinstance(typed, BaseException):
                raise typed
            if callable(typed):
                return typed(prompt)
            return typed if typed is not None else prompt.split("Type exactly: ")[1].split("\n")[0]
        self.said = io.StringIO()
        with contextlib.redirect_stderr(self.said), contextlib.redirect_stdout(self.said):
            rc = reanchor.main(argv + list(extra), ask=answer if ask == "given" else None, tty=tty, owner_check=owner_check,
                               highwater=lambda index, tcti, policy=None, define_policy=None: m.HighWater(index, lock_path=self.d + "/hw.lock", run=self.run_tpm, policy=policy, define_policy=define_policy))
        return rc, asked

    def one_source(self, verdict, peers=(OTHER,), extra=()):
        """--one-source with the owner's check stood in for (recover.py's own tests check the statement): `verdict`
        is what it does with the tip, and what it was given is kept."""
        self.checked = []

        def owner_check(config, node_id, statement, peer):
            self.checked.append((config, node_id, statement, peer))
            return lambda tip: verdict(tip)
        # the node configuration is only named here: the indices are laid down owner-written, as without one (#242's
        # define policy has its own tests)
        with mock.patch.object(reanchor, "node_define_policy", lambda path, node_id: (lambda: None)):
            return self.program("--one-source", "--owner-statement", self.d + "/st.json", "--node-config", self.d + "/node.json", *extra,
                                peers=peers, owner_check=owner_check)

    def test_one_other_node_and_the_owner_re_anchor_and_the_owner_is_named_as_a_source(self):
        self.lose_record()
        seen = []
        rc, asked = self.one_source(seen.append)
        self.assertEqual((rc, len(asked)), (0, 1), self.said.getvalue())
        self.assertEqual((seen[0]["epoch"], self.checked[0][1:]), (3, ("b", self.d + "/st.json", OTHER)))
        self.assertEqual((self.hw.value(), self.hw.record()), (3, (3, self.digest(3))))
        self.assertEqual(self.audit()[-1]["sources"], [OTHER, "owner"])

    def test_one_source_takes_exactly_one_node_the_owner_s_word_and_the_disk_s_manifest(self):
        self.lose_record()
        before = self.state()
        for peers in ((OTHER, "c"), ()):
            with self.subTest(peers=peers):
                self.assertEqual(self.one_source(lambda tip: None, peers=peers)[0], 1)
                self.assertIn("--one-source takes exactly one", self.said.getvalue())
        self.assertEqual(self.program("--one-source", peers=(OTHER,))[0], 1)
        self.assertIn("needs --owner-statement and --node-config", self.said.getvalue())

        def refuse(tip):
            raise m.Refused("the statement has expired")
        rc, asked = self.one_source(refuse)
        self.assertEqual((rc, asked), (1, []))                                    # refused before anything is asked
        self.assertIn("the statement has expired", self.said.getvalue())
        self.assertEqual(self.audit()[-1]["outcome"], "DENY")
        # the disk still holds epochs 1..3 of ANOTHER chain: the peer's is a fork of it, refused whatever the owner says
        fork = chain(3, c="DRAINING")
        with open("%s/fork.json" % self.d, "wb") as f:
            f.write(m.canonical(fork))
        rc, asked = self.one_source(lambda tip: None, peers=(), extra=("--peer", "%s=%s/fork.json" % (OTHER, self.d)))
        self.assertEqual((rc, asked), (1, []))
        self.assertIn("does not extend this node's last known manifest", self.said.getvalue())
        self.assertEqual(self.state(), before)

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
        for entry in log:
            self.assertEqual((entry["epoch"], entry["manifest_digest"], entry["sources"], entry["subject"]), (3, self.digest(3), [OTHER, "c"], "b"))
            self.assertRegex(entry["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(os.stat(self.d + "/audit.jsonl").st_mode & 0o777, 0o640)           # #283: its shipper reads it through the group
        self.assertEqual(trails.verify(self.d + "/audit.jsonl")["chained"], 2)            # #278: a hash-chained trail
        self.assertEqual(trails.where("reanchor"), "/var/log/regalia/reanchor.jsonl")     # --audit-log's default

    def test_the_program_refuses_and_records_the_refusal(self):
        self.lose_record()
        before = self.state()
        for label, kw, extra, outcomes, said in (
                ("the wrong phrase", {"typed": "yes"}, (), [None, "DENY"], "NOT DONE, nothing was changed: not confirmed: the phrase typed is not"),
                ("nothing typed: end of input", {"typed": EOFError()}, (), [None, "DENY"], "NOT DONE, nothing was changed: not confirmed"),
                ("one node only", {"peers": ("c",)}, (), ["DENY"], "NOT DONE, nothing was changed: re-anchoring needs whole chains from at least two other nodes (1 source given)"),
                ("the node as its own peer", {"peers": (OTHER, "b")}, (), ["DENY"], "b cannot be a source for its own re-anchor"),
                ("a chain that is behind", {"upto": 2}, (), ["DENY"], "a fetched chain ends at epoch 2, below the TPM high-water 3"),
                ("a peer named twice", {}, ("--peer", "c=%s/c.json" % self.d), [], "--peer names c twice"),
                ("a peer without a file", {}, ("--peer", "a"), [], "--peer takes NODE=CHAIN.json, not 'a'"),
                ("a peer without a name", {}, ("--peer", "=%s/c.json" % self.d), [], "--peer takes NODE=CHAIN.json, not"),
                ("a peer file that is absent", {}, ("--peer", "d=%s/absent.json" % self.d), [], "No such file or directory")):
            with self.subTest(label):
                log = "audit-%d.jsonl" % len(label)
                self.assertEqual(self.program(*extra, log=log, **kw)[0], 1)
                self.assertIn(said, self.said.getvalue())
                self.assertEqual(self.state(), before)
                entries = self.audit(log) if os.path.exists("%s/%s" % (self.d, log)) else []
                self.assertEqual([e.get("outcome") for e in entries], outcomes)

    def test_the_phrase_is_typed_at_a_terminal(self):
        """51's finding 7: a pipe carrying the phrase was enough."""
        self.lose_record()
        before = self.state()
        with mock.patch("builtins.input", side_effect=AssertionError("asked without a terminal")):     # fail, never block, if the check is gone
            rc, asked = self.program(ask=None, tty=lambda: False)
        self.assertEqual((rc, asked, self.state()), (1, [], before))
        self.assertIn("the phrase must be typed at a terminal: standard input is not one", self.said.getvalue())
        self.assertFalse(os.path.exists(self.d + "/audit.jsonl"))
        with mock.patch("builtins.input", side_effect=lambda prompt: prompt.split("Type exactly: ")[1].split("\n")[0]):
            self.assertEqual(self.program(ask=None, tty=lambda: True)[0], 0)         # at a terminal: asked with input()

    def test_without_a_writable_audit_log_nothing_is_done(self):
        self.lose_record()
        before = self.state()
        rc, asked = self.program(log="no-such-directory/audit.jsonl")
        self.assertEqual((rc, asked, self.state()), (1, [], before))
        self.assertIn("NOT DONE, nothing was changed", self.said.getvalue())

    def test_an_interrupted_re_anchor_exits_3_and_says_to_run_it_again(self):
        self.lose_record()
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvdefine", "0x1500017"]
        self.assertEqual(self.program()[0], 3)
        self.assertIn("INCOMPLETE: the anchor was being replaced and it did not finish: cannot define the base index 0x1500017", self.said.getvalue())
        self.assertIn("Run this command again", self.said.getvalue())
        self.assertNotIn("nothing was changed", self.said.getvalue())
        self.assertEqual([e.get("outcome") for e in self.audit()], [None, "INCOMPLETE"])
        self.refuse = lambda argv: False
        self.assertEqual(self.program()[0], 0)
        self.assertEqual([e.get("outcome") for e in self.audit()], [None, "INCOMPLETE", None, "ALLOW"])

    def test_an_incomplete_re_anchor_that_cannot_be_logged_is_still_incomplete(self):
        """51's B and CodeRabbit on #182: the OSError from the log replaced Incomplete, and the operator was
        told "nothing was changed" with a new counter on the TPM."""
        self.lose_record()
        self.refuse = lambda argv: argv[:2] == ["tpm2_nvdefine", "0x1500017"]          # the redefinition fails after the counter
        real, appends = os.open, []

        def opener(name, flags, *mode, **kw):
            if name == self.d + "/audit.jsonl" and flags & os.O_APPEND:
                appends.append(name)
                if len(appends) > 1:
                    raise OSError(28, "No space left on device", name)
            return real(name, flags, *mode, **kw)
        with mock.patch("os.open", side_effect=opener):
            rc, _ = self.program()
        self.assertEqual(rc, 3)
        said = self.said.getvalue()
        self.assertIn("INCOMPLETE: the anchor was being replaced and it did not finish: cannot define the base index", said)
        self.assertIn("and this could not be written to the audit log", said)
        self.assertNotIn("nothing was changed", said)
        self.assertEqual([e.get("outcome") for e in self.audit()], [None])
        with self.assertRaises(reanchor.Incomplete):                 # and at the function level
            reanchor.reanchor(self.store, self.sources(), "b", lambda planned: reanchor.phrase("b", planned),
                              mock.Mock(side_effect=[None, OSError(28, "No space left on device")]))

    def test_the_tpm_is_named_on_the_command_line_never_taken_from_the_environment(self):
        """51's C: a TPM2TOOLS_TCTI left in the shell would re-anchor another TPM, which truthfully says the
        indices are missing, and the log would record an ALLOW that did nothing to this host."""
        self.lose_record()
        before = self.state()
        with mock.patch.dict(os.environ, {"TPM2TOOLS_TCTI": "swtpm:path=/elsewhere"}):
            rc, asked = self.program()
        self.assertEqual((rc, asked, self.state()), (1, [], before))
        self.assertIn("TPM2TOOLS_TCTI is set in the environment: name the TPM with --tcti instead", self.said.getvalue())
        given = []
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TPM2TOOLS_TCTI", None)
            with mock.patch.object(reanchor, "main", reanchor.main):
                rc, asked = self.program("--tcti", "device:/dev/tpmrm0")
        self.assertEqual(rc, 0)
        self.assertIn("TPM: device:/dev/tpmrm0, NV index 0x1500016.", self.said.getvalue() + "".join(asked) or "")
        self.assertEqual({e["tpm"] for e in self.audit()}, {"device:/dev/tpmrm0"})

    def test_a_re_anchor_whose_outcome_cannot_be_recorded_says_it_is_done(self):
        """51's finding 5: with the log made unwritable while the operator was typing, the TPM was re-anchored
        and the program said NOT DONE."""
        self.lose_record()
        real, appends = os.open, []

        def opener(name, flags, *mode, **kw):
            if name == self.d + "/audit.jsonl" and flags & os.O_APPEND:
                appends.append(name)
                if len(appends) > 1:                                                 # the request went in; the outcome does not
                    raise PermissionError(13, "Permission denied", name)
            return real(name, flags, *mode, **kw)
        with mock.patch("os.open", side_effect=opener):
            rc, _ = self.program()
        self.assertEqual(rc, 4)
        self.assertIn("DONE, but the outcome could not be written to the audit log", self.said.getvalue())
        self.assertIn("b now holds epoch 3, manifest %s" % self.digest(3), self.said.getvalue())
        self.assertEqual((self.hw.value(), self.hw.record()), (3, (3, self.digest(3))))
        self.assertEqual([e.get("outcome") for e in self.audit()], [None])

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
        self.assertEqual(self.hw.remains(), (3, []))
        for name in (OTHER, "c"):
            with open("%s/%s.json" % (self.d, name), "wb") as f:
                f.write(m.canonical(envs))
        argv = ["--membership", path, "--root-key", ROOT_PUB, "--tpm-index", "0x1500016", "--node-id", "b",
                "--peer", "a=%s/a.json" % self.d, "--peer", "c=%s/c.json" % self.d, "--audit-log", self.d + "/audit.jsonl", "--tcti", self.tcti]
        os.environ.pop("TPM2TOOLS_TCTI", None)
        make = lambda index, tcti, policy=None, define_policy=None: m.HighWater(index, tcti=tcti, lock_path=self.d + "/hw.lock", policy=policy, define_policy=define_policy)
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(reanchor.main(argv, ask=lambda prompt: "no", highwater=make), 1)
            self.assertEqual(self.hw.slots(), [None, None])                          # refused: the TPM as it was
            self.assertEqual(reanchor.main(argv, ask=lambda prompt: prompt.split("Type exactly: ")[1].split("\n")[0], highwater=make), 0)
        digest4 = m.digest(envs[3]["manifest"])
        self.assertEqual((self.hw.value(), self.hw.slots(), self.hw.pinned(), self.hw.unusable()), (4, [(4, digest4)] * 2, True, None))
        new_base = subprocess.run(["tpm2_nvread", "0x1500017", "-C", "o", "-s", "8"], env=self.env, capture_output=True, check=True).stdout
        new_counter = subprocess.run(["tpm2_nvread", "0x1500016", "-C", "o", "-s", "8"], env=self.env, capture_output=True, check=True).stdout
        self.assertGreater(int.from_bytes(new_counter, "big"), int.from_bytes(old_counter, "big"))
        self.assertEqual(int.from_bytes(new_counter, "big") - int.from_bytes(new_base, "big"), 4)
        self.assertEqual(m.Store(path, ROOT_PUB, self.hw).load()["epoch"], 4)
        with open(self.d + "/audit.jsonl") as f:
            self.assertEqual([json.loads(line).get("outcome") for line in f], [None, "DENY", None, "ALLOW"])

    def test_the_tpm_says_which_indices_it_holds_and_a_silent_one_is_not_an_unusable_anchor(self):
        self.assertTrue(self.hw._defined() >= {0x1500016, 0x1500017, 0x150001a, 0x150001b})
        subprocess.run(["tpm2_nvundefine", "0x150001b", "-C", "o"], env=self.env, check=True, capture_output=True)
        self.assertNotIn(0x150001b, self.hw._defined())
        self.assertEqual(self.hw.unusable(), "cannot read NV index 0x150001b: the high-water anchor is unavailable (fail closed): the index is not defined")
        gone = m.HighWater("0x1500016", tcti="swtpm:path=%s/absent.sock" % self.d, lock_path=self.d + "/x.lock")
        with self.assertRaisesRegex(m.Refused, "the TPM does not answer"):
            gone.unusable()


if __name__ == "__main__":
    unittest.main()
