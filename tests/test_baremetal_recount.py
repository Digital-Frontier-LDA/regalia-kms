"""deploy/baremetal/recount.py: a new definition for an unusable heartbeat sequence counter (#244)."""
import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat as hb, membership as m, recount
import tests.test_baremetal_heartbeat as hbt

T0 = hbt.T0


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = hbt.FakeTpm()
        self.counter = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=self.tpm)
        self.counter.define()
        self.m1 = hbt.manifest()
        self.fresh = hb.Freshness(self.counter, lambda: (T0 + 60, True), lambda: 5000, self.d + "/freshness.json")
        self.fresh.accept(hbt.beat(self.m1, 40, issued=T0), self.m1)
        self.events = []
        self.floor = self.d + "/recount-floor.json"

    def state(self):
        with open(self.d + "/freshness.json") as f:
            return json.load(f)

    def break_counter(self):
        """The counter's index gone (what #182 refuses as Unusable): every heartbeat is then refused."""
        self.tpm.nv.pop(self.counter.index)

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Recount(Case):
    def test_an_unusable_counter_is_redefined_at_the_held_heartbeat_and_the_next_is_accepted(self):
        self.break_counter()
        self.refused("", self.fresh.check, self.m1)                               # stranded
        value = recount.recount(self.counter, self.m1, [self.state()], lambda planned: recount.phrase(self.counter.index, planned), self.events.append, self.floor)
        self.assertEqual((value, self.counter.value()), (40, 40))
        self.refused("REPLAY", self.fresh.accept, hbt.beat(self.m1, 40, issued=T0 + 30), self.m1)
        self.fresh.accept(hbt.beat(self.m1, 41, issued=T0 + 30), self.m1)
        self.assertEqual([(e["event"], e.get("outcome")) for e in self.events], [("recount-requested", None), ("recount", "ALLOW")])

    def test_a_usable_counter_is_never_reset(self):
        self.refused("the counter is usable", recount.recount, self.counter, self.m1, [self.state()], lambda p: "", self.events.append, self.floor)
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertEqual(self.counter.value(), 40)

    def test_the_floor_is_the_highest_verified_heartbeat_and_a_stranger_s_raises_nothing(self):
        self.break_counter()
        stranger = Ed25519PrivateKey.generate()
        forged = hbt.beat(self.m1, 10 ** 6, issued=T0, key=stranger)              # signed by nobody the manifest names
        authority = hbt.beat(self.m1, 55, issued=T0 + 10)                         # the authority's latest
        planned = recount.plan(self.counter, self.m1, [self.state(), forged, authority])
        self.assertEqual((planned["floor"], planned["held"]), (55, [(40, 1), (55, 1)]))

    def test_without_a_verified_heartbeat_nothing_is_done(self):
        self.break_counter()
        stranger = Ed25519PrivateKey.generate()
        self.refused("no heartbeat given verifies", recount.recount, self.counter, self.m1,
                     [hbt.beat(self.m1, 99, key=stranger)], lambda p: "", self.events.append, self.floor)
        self.assertEqual(self.events[-1]["outcome"], "DENY")

    def test_the_old_counter_still_read_is_a_floor_too(self):
        # a counter whose base was redefined with other attributes: unusable, but the counter still reads
        planned_before = None
        self.tpm.nv[self.counter.base_index][0] &= ~self.tpm.LOCKED          # the base no longer write-locked: unusable
        planned_before = recount.plan(self.counter, self.m1, [hbt.beat(self.m1, 3, issued=T0)])
        self.assertEqual(planned_before["floor"], max(3, planned_before["old"] or 0))
        self.assertEqual(planned_before["old"], 40)

    def test_a_tpm_that_does_not_answer_is_not_recounted(self):
        self.tpm.broken = True
        with self.assertRaises(m.Refused) as caught:
            recount.recount(self.counter, self.m1, [self.state()], lambda p: "", self.events.append, self.floor)
        self.assertNotIsInstance(caught.exception, m.Unusable)
        self.assertEqual(self.events[-1]["outcome"], "DENY")

    def test_a_wrong_phrase_changes_nothing(self):
        self.break_counter()
        with self.assertRaises(m.Refused):
            recount.recount(self.counter, self.m1, [self.state()], lambda p: "yes", self.events.append, self.floor)
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertNotIn(self.counter.index, self.tpm.nv)                        # untouched

    def test_an_interruption_is_incomplete_and_a_rerun_finishes(self):
        self.break_counter()
        real = self.tpm.__call__
        calls = {"n": 0}

        def flaky(argv, input=None, **kw):
            if argv[0] == "tpm2_nvdefine" and calls["n"] == 0:
                calls["n"] += 1
                raise OSError("power cut")
            return real(argv, input=input, **kw)
        self.counter.run = flaky
        with self.assertRaises(recount.Incomplete):
            recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append, self.floor)
        self.assertEqual(self.events[-1]["outcome"], "INCOMPLETE")
        self.counter.run = real
        self.assertEqual(recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append, self.floor), 40)


class AcrossACut(Case):
    def test_a_cut_after_any_tpm_call_never_lowers_the_floor(self):
        """#261 (regalia-kms-3e, decided by regalia-kms-24): the old counter reads 1000 with wrong attributes,
        the held heartbeat is 990. Cut after each TPM call in turn: every rerun defines at 1000 or more."""
        for cut in range(1, 12):
            with self.subTest(cut=cut):
                tpm = hbt.FakeTpm()
                counter = hb.Counter("0x1500018", lock_path=self.d + "/c.lock", run=tpm)
                counter.define()
                counter.advance(1000)
                tpm.nv[counter.base_index][0] &= ~tpm.LOCKED                     # wrong attributes: unusable, still reads
                floor = self.d + "/floor-%d.json" % cut
                calls = {"n": 0}

                def cutting(argv, input=None, **kw):
                    if argv[0] in ("tpm2_nvundefine", "tpm2_nvdefine", "tpm2_nvincrement", "tpm2_nvwrite", "tpm2_nvwritelock"):
                        calls["n"] += 1
                        if calls["n"] == cut:
                            raise OSError("power cut at TPM call %d" % cut)
                    return tpm(argv, input=input, **kw)
                counter.run = cutting
                held = [hbt.beat(self.m1, 990, issued=T0)]
                try:
                    recount.recount(counter, self.m1, held, lambda p: recount.phrase(counter.index, p), self.events.append, floor)
                except recount.Incomplete:
                    pass
                counter.run = tpm
                value = recount.recount(counter, self.m1, held, lambda p: recount.phrase(counter.index, p), self.events.append, floor) \
                    if counter_unusable(counter) else counter.value()
                self.assertGreaterEqual(value, 1000)
                os.unlink(floor)

    def test_an_unreadable_carried_floor_is_a_refusal(self):
        self.break_counter()
        with open(self.floor, "w") as f:
            f.write("{")
        self.refused("not valid JSON", recount.recount, self.counter, self.m1, [self.state()], lambda p: "", self.events.append, self.floor)


def counter_unusable(counter):
    try:
        counter.value()
    except m.Unusable:
        return True
    return False


class TheHostsTpmAndChain(Case):
    def anchored(self):
        anchor = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.tpm)
        anchor.define()
        store = m.Store(self.d + "/membership.json", hbt.pub(hbt.ROOT), anchor)
        store.commit(signed(self.m1))
        return anchor

    def test_the_chain_must_be_the_one_this_tpm_anchored(self):
        anchor = self.anchored()
        self.assertEqual(recount.current([signed(self.m1)], hbt.pub(hbt.ROOT), anchor), self.m1)
        fork = dict(self.m1, issued_at="2026-09-30T00:00:00Z")
        self.refused("CONFLICT", recount.current, [signed(fork)], hbt.pub(hbt.ROOT), anchor)

    def test_a_tpm_without_the_host_s_anchor_is_refused(self):
        other = m.HighWater("0x1500016", lock_path=self.d + "/other.lock", run=hbt.FakeTpm())   # another TPM: no anchor at all
        with self.assertRaises(m.Refused):
            recount.current([signed(self.m1)], hbt.pub(hbt.ROOT), other)


def signed(man):
    return {"manifest": man, "signature": {"signer": "root", "key": hbt.pub(hbt.ROOT), "sig": hbt.ROOT.sign(m.DOMAIN + m.canonical(man)).hex()}}


class ConcurrentService(Case):
    def test_an_advance_by_the_service_waits_for_the_recount(self):
        """#261 (regalia-kms-3e, decided by regalia-kms-24): recount holds the counter's own lock, the one the
        service's Counter takes, so a concurrent advance blocks until the new counter is in place."""
        import threading
        self.break_counter()
        service = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=self.tpm)    # the service's construction
        real = self.counter._define_counter
        seen = {}

        def define(floor):
            thread = threading.Thread(target=lambda: seen.setdefault("value", service.advance(floor + 1)))
            thread.start()
            thread.join(0.3)
            seen["blocked"] = thread.is_alive()
            seen["thread"] = thread
            return real(floor)
        self.counter._define_counter = define
        recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append, self.floor)
        seen["thread"].join(5)
        self.assertTrue(seen["blocked"])                                       # it waited for the recount
        self.assertEqual((seen["value"], service.value()), (41, 41))           # then advanced on the new counter


class CommandLine(TheHostsTpmAndChain):
    def node_setup(self, sync="inactive"):
        tpm = hbt.FakeTpm()                                   # the indices as node.json spells them
        anchor = m.HighWater("0x01500016", lock_path=self.d + "/hw.lock", run=tpm)
        anchor.define()
        m.Store(self.d + "/membership.json", hbt.pub(hbt.ROOT), anchor).commit(signed(self.m1))
        counter = hb.Counter("0x01500018", lock_path=self.d + "/heartbeat-counter.lock", run=tpm)
        counter.define()
        hb.Freshness(counter, lambda: (T0 + 60, True), lambda: 5000, self.d + "/freshness.json").accept(hbt.beat(self.m1, 41, issued=T0), self.m1)
        tpm.nv.pop("0x01500018")                              # the counter's index gone: unusable
        with open(os.path.join(os.path.dirname(recount.__file__), "node.example.json")) as f:
            cfg = json.load(f)
        cfg.update(root_key=hbt.pub(hbt.ROOT), tcti=None, state_dir=self.d, nv_epoch="0x01500016", nv_heartbeat="0x01500018")
        with open(self.d + "/node.json", "w") as f:
            json.dump(cfg, f)
        import subprocess

        def run(argv, **kw):
            if argv[0] == "systemctl":
                return subprocess.CompletedProcess(argv, 0 if sync == "active" else 3, (sync + "\n").encode(), b"")
            return tpm(argv, **kw)
        return counter, run

    def test_end_to_end_from_the_node_s_configuration(self):
        counter, run = self.node_setup()
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "recount 0x01500018 at 41", run=run), 0)
        self.assertEqual(counter.value(), 41)
        with open(self.d + "/audit.jsonl") as f:
            self.assertEqual([json.loads(line)["event"] for line in f], ["recount-requested", "recount"])
        self.assertEqual(recount.main(argv, ask=lambda prompt: "", run=run), 1)             # usable now: refused

    def test_refused_while_regalia_sync_runs(self):
        counter, run = self.node_setup(sync="active")
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "recount 0x01500018 at 41", run=run), 1)
        self.assertFalse(os.path.exists(self.d + "/audit.jsonl"))                           # nothing asked, nothing done

    def test_an_explicit_heartbeat_that_does_not_exist_is_refused(self):
        counter, run = self.node_setup()
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl", "--heartbeat", self.d + "/nope.json"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "recount 0x01500018 at 41", run=run), 1)

    def test_on_the_authority_refused_while_it_runs(self):
        import tests.test_baremetal_authority as at
        from deploy.baremetal import authority
        with open(self.d + "/authority.json", "w") as f:
            json.dump(at.config(self.d), f)
        held = authority.one_writer(self.d)                   # what regalia-authority holds while it serves
        self.addCleanup(os.close, held)
        argv = ["--config", self.d + "/authority.json", "--audit-log", self.d + "/audit.jsonl"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "", run=self.tpm), 1)


if __name__ == "__main__":
    unittest.main()
