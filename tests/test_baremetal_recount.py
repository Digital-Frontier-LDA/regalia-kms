"""deploy/baremetal/recount.py: a new definition for an unusable heartbeat sequence counter (#244)."""
import json
import os
import shutil
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat as hb, membership as m, recount, trails
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

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def signed(self, man, key=hbt.ROOT, signer="root"):
        from tests.test_baremetal_membership import sign
        return sign(man, key, signer)


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
        latest = hbt.beat(self.m1, 55, issued=T0 + 10)                            # the nodes' latest
        planned = recount.plan(self.counter, self.m1, [self.state(), forged, latest])
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


class SingleNodeRecount(Case):
    """Under a single-node manifest (docs/design/single-node.md 4.7): the owner's v2 recount statement is a
    floor source beside the heartbeats, and the floor must not go below the node's beat signing counter."""

    def single_manifest(self):
        """A single-node v5 manifest: node a alone, owner revokes."""
        import tests.test_baremetal_membership_v5 as v5
        from tests.test_baremetal_membership_v4 import OWNER_KEYS, pub
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        root = Ed25519PrivateKey.generate()
        owner = Ed25519PrivateKey.generate()
        man = v5.single5(1, "", nodes=[v5.one("a", "ACTIVE", i=0)])
        man["owner_keys"] = [{"alg": "ed25519", "key": pub(owner)}]
        return man

    def single_node_beat(self, man, sequence, issued=T0):
        """A heartbeat signed by the node's own key (the single-node signer), for a single-node manifest.
        The manifest's heartbeat_signers names node "a"; the beat is signed by an Ed25519 key (the fixture's
        signer), and the manifest's signing rules are not checked by plan() (it calls heartbeat.signed, which
        verifies the signature against the manifest's parties)."""
        # use the REVOKE key (Ed25519) as the node's signing key: the single-node manifest's heartbeat_signers
        # names "a" as a party, but heartbeat.signed verifies the signature, not the party rule, in plan()'s context
        return hbt.beat(man, sequence, issued=issued, key=hbt.REVOKE, domain=hb.DOMAIN)

    def v2_recount_statement(self, collector_sequence, collector_epoch=1, node="a", manifest=None):
        from deploy.baremetal import recover
        from tests.test_baremetal_membership_v4 import OWNER_KEYS, pub
        st = recover.statement("recount", node, manifest or self.single_manifest(), "00ff" * 8 + ":boot-1", T0 + 300,
                               collector_epoch=collector_epoch, collector_sequence=collector_sequence)
        return {"statement": st, "key": pub(OWNER_KEYS[0]), "sig": OWNER_KEYS[0].sign(recover.message(st)).hex()}

    def test_owner_statement_is_a_floor_source_under_single_node(self):
        """Under a single-node manifest, the owner's v2 recount statement raises the floor to its
        collector_sequence, even with no verified heartbeat."""
        self.break_counter()
        man = self.single_manifest()
        st = self.v2_recount_statement(collector_sequence=55)
        planned = recount.plan(self.counter, man, [], owner_statement=st, signer=lambda: 10)
        self.assertEqual(planned["floor"], 55)
        self.assertEqual(planned["held"], [])

    def test_owner_statement_is_refused_under_multi_node(self):
        """An owner statement of purpose recount is refused under a multi-node manifest: the owner is not a
        floor source for a multi-node recount."""
        self.break_counter()
        st = self.v2_recount_statement(collector_sequence=55)
        self.refused("refused under a multi-node manifest", recount.plan, self.counter, self.m1, [],
                     owner_statement=st, signer=lambda: 0)

    def test_liveness_floor_must_not_go_below_signing_counter(self):
        """The floor is the max of everything named above AND the signing counter's current value: a floor
        below what the node has already signed would make the next heartbeat a replay. No margin."""
        self.break_counter()
        man = self.single_manifest()
        # the signing counter reads 60: the floor must be at least 60, even with a lower heartbeat
        held = [self.single_node_beat(man, 30)]
        st = self.v2_recount_statement(collector_sequence=40)
        planned = recount.plan(self.counter, man, [self.state(), held[0]], owner_statement=st, signer=lambda: 60)
        self.assertGreaterEqual(planned["floor"], 60)
        # no margin: the floor is exactly max(40, 60, 30) = 60, not 61 or more
        self.assertEqual(planned["floor"], 60)

    def test_without_heartbeat_or_statement_still_refused(self):
        """With neither a verified heartbeat nor the statement, the recount is refused even under single-node."""
        self.break_counter()
        man = self.single_manifest()
        self.refused("no heartbeat given verifies", recount.plan, self.counter, man, [],
                     owner_statement=None, signer=lambda: 0)

    def test_floor_is_max_of_all_sources(self):
        """The floor is the max of: old counter, prior, held heartbeats, collector_sequence, and signing counter."""
        self.break_counter()
        man = self.single_manifest()
        held = [self.single_node_beat(man, 30)]
        st = self.v2_recount_statement(collector_sequence=50)
        planned = recount.plan(self.counter, man, [self.state(), held[0]], owner_statement=st, signer=lambda: 45, prior=5)
        # max(old=40 (from setUp), prior=5, held=30, collector=50, signing=45) = 50
        self.assertEqual(planned["floor"], 50)


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
        self.assertEqual(self.events[-1]["outcome"], "DENY")

    def test_a_floor_file_that_cannot_be_read_is_recorded_as_a_refusal(self):
        """#261 (CodeRabbit): an OSError on the floor file is recorded as DENY before it propagates."""
        self.break_counter()
        os.mkdir(self.floor)                                                      # a directory where the floor goes
        with self.assertRaises(OSError):
            recount.recount(self.counter, self.m1, [self.state()], lambda p: "", self.events.append, self.floor)
        self.assertEqual([(e["event"], e["outcome"]) for e in self.events], [("recount", "DENY")])
        self.assertNotIn(self.counter.index, self.tpm.nv)                        # untouched


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
    def test_an_advance_after_lock_release_does_not_invalidate_the_recount(self):
        """#244 (carried from draft #373): the rebuilt counter is verified BEFORE its lock goes to a waiting service; read
        after, a legitimate advance made a recovery that worked read as INCOMPLETE (repository CI saw it)."""
        from contextlib import contextmanager
        from unittest.mock import patch
        self.break_counter()
        service = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=self.tpm)
        exclusive = m._exclusive
        define = self.counter._define_at
        rebuilt = []
        advanced = []

        def define_at(floor):
            define(floor)
            rebuilt.append(True)

        @contextmanager
        def handoff(path):
            with exclusive(path):
                yield
            if path == self.counter.lock_path and rebuilt and not advanced:
                advanced.append(True)
                # Deterministically model a waiting service acquiring the lock
                # immediately after recount releases it, before its next line.
                self.assertEqual(service.advance(41), 41)

        with patch.object(m, "_exclusive", handoff), patch.object(self.counter, "_define_at", define_at):
            value = recount.recount(self.counter, self.m1, [self.state()],
                                    lambda p: recount.phrase(self.counter.index, p),
                                    self.events.append, self.floor)
        self.assertEqual(value, 40)
        self.assertEqual(service.value(), 41)
        self.assertEqual(len(advanced), 1)
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")

    def test_an_advance_by_the_service_waits_for_the_recount(self):
        """#261 (regalia-kms-3e, decided by regalia-kms-24): recount holds the counter's own lock, the one the
        service's Counter takes, so a concurrent advance blocks until the new counter is in place."""
        import threading
        self.break_counter()
        service = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=self.tpm)    # the service's construction
        real = self.counter._define_at
        seen = {}

        def define(floor):
            thread = threading.Thread(target=lambda: seen.setdefault("value", service.advance(floor + 1)))
            thread.start()
            thread.join(0.3)
            seen["blocked"] = thread.is_alive()
            seen["thread"] = thread
            return real(floor)
        self.counter._define_at = define
        recount.recount(self.counter, self.m1, [self.state()], lambda p: recount.phrase(self.counter.index, p), self.events.append, self.floor)
        seen["thread"].join(5)
        self.assertTrue(seen["blocked"])                                       # it waited for the recount
        self.assertEqual((seen["value"], service.value()), (41, 41))           # then advanced on the new counter


class CommandLine(TheHostsTpmAndChain):
    def node_setup(self, sync="inactive"):
        # a node holds the measurements its manifest commits to (#332): the recount defines its counter under the
        # policy they name (#242), owner-written here, as these images are not signed UKIs
        from deploy.baremetal import measurements
        document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {
            n["node_id"]: {"accepted": [{"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32, "11": "a1" * 32}}]}
            for n in self.m1["nodes"]}}
        self.m1 = dict(self.m1, policy_version=measurements.version(document))
        measurements.Documents(os.path.join(self.d, measurements.STORE_DIR)).put(document)
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
        cfg.update(root_key=hbt.pub(hbt.ROOT), tcti="device:/dev/tpmrm0", state_dir=self.d, nv_epoch="0x01500016", nv_heartbeat="0x01500018",
                   node_id=self.m1["nodes"][0]["node_id"])         # a node the manifest lists
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
        self.assertEqual(trails.verify(self.d + "/audit.jsonl")["chained"], 3)            # #278: a hash-chained trail

    def test_refused_unless_regalia_sync_is_stopped(self):
        for state in ("active", "activating", "deactivating", "reloading", ""):
            with self.subTest(state=state or "(no answer)"):
                self.d = tempfile.mkdtemp()                       # a host of its own for each state
                self.addCleanup(shutil.rmtree, self.d, True)
                counter, run = self.node_setup(sync=state)
                argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl"]
                self.assertEqual(recount.main(argv, ask=lambda prompt: "recount 0x01500018 at 41", run=run), 1)
                self.assertFalse(os.path.exists(self.d + "/audit.jsonl"))                   # nothing asked, nothing done

    def test_an_explicit_heartbeat_that_does_not_exist_is_refused(self):
        counter, run = self.node_setup()
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl", "--heartbeat", self.d + "/nope.json"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "recount 0x01500018 at 41", run=run), 1)

    def test_a_configuration_that_is_not_a_node_s_is_refused(self):
        """#199 retired the authority host: recount runs on a node, from node.json, and nothing else."""
        with open(self.d + "/other.json", "w") as f:
            json.dump({"schema": "regalia.authority/v1", "run_dir": "/run/regalia"}, f)
        argv = ["--config", self.d + "/other.json", "--audit-log", self.d + "/audit.jsonl"]
        self.assertEqual(recount.main(argv, ask=lambda prompt: "", run=self.tpm), 1)
        self.assertFalse(os.path.exists(self.d + "/audit.jsonl"))

    def owner_statement_host(self, collector_sequence=60):
        """A single-node host (docs/design/single-node.md 4.7) whose heartbeat counter is unusable and whose
        freshness state is gone: recount's only floor source is the owner's v2 recount statement. The chain is
        a's single-node v5 tip (a, ACTIVE) over the fixture root, the counter broken, the signing counter the
        node's own beat counter at 30. The anchor is judged by the tip's own schema, like node.store() (#242 B3)."""
        import tests.test_baremetal_membership_v5 as v5
        from tests.test_baremetal_membership_v4 import OWNER_KEYS, pub
        from deploy.baremetal import node as node_module
        from tests.test_baremetal_single_node_network import single_site
        man = v5.single5(1, "", nodes=[v5.one("a", "ACTIVE", i=0)])
        man["owner_keys"] = [{"alg": "ed25519", "key": pub(OWNER_KEYS[0])}]   # the statement's owner key
        chain = [self.signed(man)]
        tpm = hbt.FakeTpm()
        for index in ("0x01500018", "0x0150001c"):
            hb.Counter(index, lock_path=self.d + "/%s.lock" % index, run=tpm).define()
        hb.Counter("0x0150001c", lock_path=self.d + "/0x0150001c.lock", run=tpm).advance(30)
        anchor = m.HighWater("0x01500016", lock_path=self.d + "/hw.lock", run=tpm)
        anchor.define()
        store = m.Store(self.d + "/membership.json", hbt.pub(hbt.ROOT), anchor)
        # the chain is v5: a store committing it would set the anchor's schema to v5 (a QUORUM schema) and refuse
        # the owner-written anchor, as the convergence and reanchor owner-chain fixtures do
        store._judge_by = lambda manifests: None
        store.commit(chain[0])
        tpm.nv.pop("0x01500018")                                   # the heartbeat counter's index gone: unusable
        import builtins
        real_open = builtins.open
        with real_open(os.path.join(self.d, "site.json"), "w") as f:
            json.dump(single_site(), f)
        with real_open(os.path.join(os.path.dirname(recount.__file__), "node.example.json")) as f:
            cfg = json.load(f)
        cfg.update(root_key=hbt.pub(hbt.ROOT), tcti="device:/dev/tpmrm0", state_dir=self.d, node_id="a",
                   site=os.path.join(self.d, "site.json"),
                   nv_epoch="0x01500016", nv_heartbeat="0x01500018", nv_signing="0x0150001c")
        with open(self.d + "/node.json", "w") as f:
            json.dump(cfg, f)
        # a single-node host whose approved images are unsigned: its anchor and counters are owner-written (no
        # approved-image write policy), so the policy resolvers answer None, never the real PCR key or store
        for name in ("image_policy", "image_key", "define_policy", "_tip_schema"):
            patcher = unittest.mock.patch.object(node_module, name, return_value=None)
            self.addCleanup(patcher.stop)
            patcher.start()

        def run(argv, **kw):
            if argv[0] == "systemctl":
                import subprocess
                return subprocess.CompletedProcess(argv, 3, b"inactive\n", b"")
            if argv[0] == "tpm2_readclock":
                import subprocess
                return subprocess.CompletedProcess(argv, 0, b"  clock: 5000\n", b"")
            return tpm(argv, **kw)
        with real_open(os.path.join(self.d, "recovery-session.json"), "w") as f:
            json.dump({"nonce": "aa" * 8, "boot_id": "00ff00ff-0000-4000-8000-000000000000",
                       "issued": T0 - 60}, f)
        with real_open(os.path.join(self.d, "boot_id"), "w") as f:
            f.write("00ff00ff-0000-4000-8000-000000000000\n")
        from deploy.baremetal import recover
        # the session file the node's run_dir would hold (/run/regalia, not writable on this host): point the
        # module constant at this directory, which holds it
        session_patcher = unittest.mock.patch.object(recover, "SESSION_FILE", os.path.join(self.d, "recovery-session.json"))
        self.addCleanup(session_patcher.stop)
        session_patcher.start()
        tip = chain[0]["manifest"]
        st = recover.statement("recount", "a", tip, "aa" * 8 + ":00ff00ff-0000-4000-8000-000000000000",
                               T0 + 600, collector_epoch=1, collector_sequence=collector_sequence)
        with real_open(self.d + "/statement.json", "w") as f:
            json.dump({"statement": st, "key": pub(OWNER_KEYS[0]),
                       "sig": OWNER_KEYS[0].sign(recover.message(st)).hex()}, f)

        def ask(prompt):
            return "recount 0x01500018 at %d" % max(collector_sequence, 30)
        # the kernel's boot ID, on a host without /proc: the statement's session names this boot
        def stub(*args, **kw):
            if args and args[0] == "/proc/sys/kernel/random/boot_id":
                return real_open(os.path.join(self.d, "boot_id"), *args[1:], **kw)
            return real_open(*args, **kw)
        open_patcher = unittest.mock.patch("builtins.open", side_effect=stub)
        self.addCleanup(open_patcher.stop)
        open_patcher.start()
        # authenticated time: the host's clock reads inside the statement's validity window. The statement
        # expires at T0+600; verify_owner needs `now < expires <= now + SESSION_TTL`, and the session (issued
        # T0-60) needs `now - issued <= SESSION_TTL`. With now = T0+300: 0 < 600 <= 900 and 360 <= 900, so both
        # verify. Patched (not a chrony status file: root-owned files and a boot clock are not this host's).
        auth_patcher = unittest.mock.patch("deploy.baremetal.heartbeat.authenticated_now",
                                           side_effect=lambda clock, tpm_clock, floor: (T0 + 300, floor))
        self.addCleanup(auth_patcher.stop)
        auth_patcher.start()
        return run, ask

    def test_owner_statement_at_the_command(self):
        """--owner-statement is the single-node floor source at the command (docs/design/single-node.md 4.7):
        the node's own beat signing counter (nv_signing) is read for the liveness floor, the statement's
        collector_sequence raises the floor, and the new counter reads the max."""
        run, ask = self.owner_statement_host()
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl",
                "--owner-statement", self.d + "/statement.json"]
        self.assertEqual(recount.main(argv, ask=ask, run=run), 0)
        counter = hb.Counter("0x01500018", lock_path=self.d + "/0x01500018.lock", run=run)
        self.assertEqual(counter.value(), 60)
        with open(self.d + "/audit.jsonl") as f:
            self.assertEqual([json.loads(line)["event"] for line in f], ["recount-requested", "recount"])
        self.assertEqual(json.loads(open(self.d + "/recount-floor-0x01500018.json").read())["floor"], 60)

    def test_owner_statement_refused_under_a_multi_node_tip(self):
        """A v2 recount statement given against a multi-node manifest is refused by the command, before
        anything is changed: the owner is not a floor source for a multi-node recount."""
        run, ask = self.owner_statement_host()
        argv = ["--config", self.d + "/node.json", "--audit-log", self.d + "/audit.jsonl",
                "--owner-statement", self.d + "/statement.json"]
        # swap the host's chain for the multi-node fixture's: the statement names the single-node tip, so the
        # node's manifest (multi-node) and the statement disagree, and the statement is refused
        with open(self.d + "/membership.json", "wb") as f:
            f.write(m.canonical([signed(self.m1)]))
        self.assertEqual(recount.main(argv, ask=ask, run=run), 1)
        self.assertFalse(os.path.exists(self.d + "/audit.jsonl"))


if __name__ == "__main__":
    unittest.main()
