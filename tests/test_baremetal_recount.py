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
        value = recount.recount(self.counter, self.m1, [self.state()], lambda planned: recount.phrase(self.counter.index, planned), self.events.append)
        self.assertEqual((value, self.counter.value()), (40, 40))
        self.refused("REPLAY", self.fresh.accept, hbt.beat(self.m1, 40, issued=T0 + 30), self.m1)
        self.fresh.accept(hbt.beat(self.m1, 41, issued=T0 + 30), self.m1)
        self.assertEqual([(e["event"], e.get("outcome")) for e in self.events], [("recount-requested", None), ("recount", "ALLOW")])

    def test_a_usable_counter_is_never_reset(self):
        self.refused("the counter is usable", recount.recount, self.counter, self.m1, [self.state()], lambda p: "", self.events.append)
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
                     [hbt.beat(self.m1, 99, key=stranger)], lambda p: "", self.events.append)
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
            recount.recount(self.counter, self.m1, [self.state()], lambda p: "", self.events.append)
        self.assertNotIsInstance(caught.exception, m.Unusable)
        self.assertEqual(self.events[-1]["outcome"], "DENY")

    def test_a_wrong_phrase_changes_nothing(self):
        self.break_counter()
        with self.assertRaises(m.Refused):
            recount.recount(self.counter, self.m1, [self.state()], lambda p: "yes", self.events.append)
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
            recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append)
        self.assertEqual(self.events[-1]["outcome"], "INCOMPLETE")
        self.counter.run = real
        self.assertEqual(recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append), 40)


class CommandLine(Case):
    def test_end_to_end(self):
        self.break_counter()
        with open(self.d + "/membership.json", "wb") as f:
            f.write(m.canonical([hbt.sign(self.m1) if hasattr(hbt, "sign") else {"manifest": self.m1, "signature": {
                "signer": "root", "key": hbt.pub(hbt.ROOT), "sig": hbt.ROOT.sign(m.DOMAIN + m.canonical(self.m1)).hex()}}]))
        argv = ["--membership", self.d + "/membership.json", "--root-key", hbt.pub(hbt.ROOT), "--tpm-index", "0x1500018",
                "--heartbeat", self.d + "/freshness.json", "--audit-log", self.d + "/audit.jsonl"]
        code = recount.main(argv, ask=lambda prompt: "recount 0x1500018 at 40", counter_for=lambda index, tcti: self.counter)
        self.assertEqual((code, self.counter.value()), (0, 40))
        with open(self.d + "/audit.jsonl") as f:
            self.assertEqual([json.loads(line)["event"] for line in f], ["recount-requested", "recount"])
        self.assertEqual(recount.main(argv, ask=lambda prompt: "", counter_for=lambda index, tcti: self.counter), 1)   # usable now: refused


if __name__ == "__main__":
    unittest.main()
