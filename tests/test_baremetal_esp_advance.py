"""node.esp_advance (#66 B3): the root oneshot that writes the published chain to the ESP, THEN moves the TPM anchor,
so that no reboot finds an ESP chain below its anchor (the initrd refuses that as a ROLLBACK). Sync never anchors
(tests/test_baremetal_store_anchors.py). The TPM is hbt.FakeTpm; the boots themselves are in
tests/test_baremetal_unlock_boot.py (QEMU)."""
import hashlib
import os
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, enrol
from deploy.baremetal import membership as m
from deploy.baremetal import node
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_replacement as rt
from tests.test_baremetal_node import ROOT, Case


class EspCase(Case):
    def setUp(self):
        super().setUp()
        self.esp = os.path.join(self.d, "esp")
        os.mkdir(self.esp, 0o755)
        self.lock = os.path.join(self.d, "run", "esp-advance.lock")
        self.n = self.node()
        anchoring = self.n.anchor()
        anchoring.define()
        m.Store(self.n.path("membership.json"), ROOT, anchoring).commit(self.e1)      # as enrolment leaves it: anchored at 1
        self.sync = m.Store(self.n.path("membership.json"), ROOT, self.n.anchor(), anchors=False)
        self.m2 = dict(hbt.manifest(2, m.digest(self.m1)), policy_version="p2")
        self.e2 = rt.sign(self.m2)

    def on_esp(self):
        with open(os.path.join(self.esp, bootcreds.CHAIN_ON_ESP), "rb") as f:
            return m.load(f.read())

    def advance(self):
        return node.esp_advance(self.n, self.esp, lock_path=self.lock)


class EspAdvance(EspCase):

    def test_the_esp_is_written_before_the_anchor_moves(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.assertEqual(self.n.anchor().value(), 1, "sync moved the anchor")
        self.assertEqual(self.n.manifest()["epoch"], 2)                       # the root services read the chain ahead of the anchor
        order = []
        write, anchor = enrol._replace_esp, m.HighWater.anchor
        with unittest.mock.patch.object(enrol, "_replace_esp", lambda *a: (order.append("esp"), write(*a))[1]), \
                unittest.mock.patch.object(m.HighWater, "anchor", lambda hw, *a: (order.append("anchor"), anchor(hw, *a))[1]):
            epoch, sha, rewritten, unrenderable = self.advance()
        self.assertEqual(order, ["esp", "anchor"])
        self.assertEqual((epoch, rewritten, unrenderable), (2, True, None))
        self.assertEqual(self.on_esp(), [self.e1, self.e2])
        self.assertEqual(sha, hashlib.sha256(m.canonical([self.e1, self.e2])).hexdigest())
        self.assertEqual(self.n.anchor().value(), 2)
        self.assertEqual(self.advance()[1:], (sha, False, None))                    # again: nothing to write, the anchor already there

    def test_the_request_is_recorded_before_anything_changes_and_the_outcome_after(self):
        """#278 for the ESP advance (regalia-kms-3e's read): a REQUEST line before the ESP or the anchor changes, the ALLOW
        after the anchor is checked; a crash in between leaves a request with no outcome, never a false ALLOW."""
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        order, lines = [], []
        write, anchor = enrol._replace_esp, m.HighWater.anchor
        with unittest.mock.patch.object(enrol, "_replace_esp", lambda *a: (order.append("esp"), write(*a))[1]), \
                unittest.mock.patch.object(m.HighWater, "anchor", lambda hw, *a: (order.append("anchor"), anchor(hw, *a))[1]):
            node.esp_advance(self.n, self.esp, lock_path=self.lock, record=lambda event: (order.append(event["event"]), lines.append(event)))
        self.assertEqual(order, ["esp-advance-requested", "esp", "anchor", "esp-advance"])
        facts = {"epoch": 2, "manifest_digest": m.digest(self.m2), "chain_sha256": hashlib.sha256(m.canonical([self.e1, self.e2])).hexdigest(),
                 "esp_rewritten": True, "boot_renderable": True}
        self.assertEqual(lines, [dict(facts, event="esp-advance-requested"), dict(facts, event="esp-advance", outcome="ALLOW")])

    def test_a_trail_that_cannot_be_written_changes_nothing(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))

        def full(event):
            raise OSError("No space left on device")
        with self.assertRaises(OSError):
            node.esp_advance(self.n, self.esp, lock_path=self.lock, record=full)
        self.assertFalse(os.path.exists(os.path.join(self.esp, bootcreds.CHAIN_ON_ESP)))     # the ESP untouched
        self.assertEqual(self.n.anchor().value(), 1)

    def test_an_anchor_that_fails_leaves_a_request_and_no_allow(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        lines = []
        with unittest.mock.patch.object(m.HighWater, "anchor", side_effect=OSError("power cut")), self.assertRaises(OSError):
            node.esp_advance(self.n, self.esp, lock_path=self.lock, record=lines.append)
        self.assertEqual([e["event"] for e in lines], ["esp-advance-requested"])

    def test_main_records_a_successful_run_in_the_trail(self):
        """The unit's own entry point records the run: request, then ALLOW for the epoch it anchored (#449). Without it
        only the systemd e2e (node-units step 7) would notice a caller that stopped passing its trail."""
        import json
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        path = os.path.join(self.d, "esp-advance-ok.jsonl")
        with unittest.mock.patch.object(node.trails, "where", lambda name, cfg=None: path), \
                unittest.mock.patch.object(node.metrics, "publish", lambda *a, **k: True), \
                unittest.mock.patch.object(node, "load", lambda p: self.cfg), \
                unittest.mock.patch.object(node, "Node", lambda cfg: self.n):    # the fixture's software anchor, not a TPM
            import contextlib, io
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = node.main(["--config", "x", "--esp", self.esp, "--esp-lock", self.lock, "esp-advance"])
            self.assertEqual(rc, 0, err.getvalue())
        with open(path) as f:
            lines = [json.loads(l) for l in f.read().splitlines()]
        self.assertEqual([e["event"] for e in lines], ["esp-advance-requested", "esp-advance"])
        self.assertEqual((lines[-1]["outcome"], lines[-1]["epoch"]), ("ALLOW", 2))

    def test_an_allow_line_that_cannot_be_written_is_a_gap_not_a_refusal(self):
        """df-grafana-b9's read of #449: the ALLOW is written AFTER the anchor moved. If it fails, the advance still
        happened: esp_advance says so (TrailIncomplete, with its result), and main() writes no DENY for it, exits 3 and
        says it advanced. A DENY there would record as refused the one move that took place."""
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        lines = []

        def record(event):
            if event.get("outcome") == "ALLOW":
                raise OSError("No space left on device")
            lines.append(event)
        with self.assertRaises(node.TrailIncomplete) as gap:
            node.esp_advance(self.n, self.esp, lock_path=self.lock, record=record)
        self.assertEqual(self.n.anchor().value(), 2)                      # it moved
        self.assertEqual(self.on_esp()[-1], self.e2)
        self.assertEqual(gap.exception.result[0], 2)
        self.assertIn("advanced to epoch 2", str(gap.exception))
        self.assertEqual([e["event"] for e in lines], ["esp-advance-requested"])

    def test_main_writes_no_deny_for_an_advance_whose_allow_failed(self):
        import contextlib, io, json
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        path = os.path.join(self.d, "esp-advance-gap.jsonl")
        real = node.Trail.__call__

        def call(trail, event):
            if event.get("outcome") == "ALLOW":
                raise OSError("No space left on device")
            return real(trail, event)
        published, err = [], io.StringIO()
        with unittest.mock.patch.object(node.trails, "where", lambda name, cfg=None: path), \
                unittest.mock.patch.object(node.metrics, "publish", lambda writer, samples, target=None: published.append(samples)), \
                unittest.mock.patch.object(node, "load", lambda p: self.cfg), \
                unittest.mock.patch.object(node, "Node", lambda cfg: self.n), \
                unittest.mock.patch.object(node.Trail, "__call__", call), contextlib.redirect_stderr(err):
            rc = node.main(["--config", "x", "--esp", self.esp, "--esp-lock", self.lock, "esp-advance"])
        self.assertEqual(rc, 3, err.getvalue())
        self.assertIn("INCOMPLETE: advanced to epoch 2", err.getvalue())
        with open(path) as f:
            events = [json.loads(l) for l in f.read().splitlines()]
        self.assertEqual([(e["event"], e.get("outcome")) for e in events], [("esp-advance-requested", None)])   # no DENY
        self.assertEqual(self.n.anchor().value(), 2)
        self.assertEqual({n: v for n, _, v in published[-1]}.get("regalia_esp_advance_ok"), 1)

    def test_main_records_a_refusal_in_the_trail(self):
        import json
        path = os.path.join(self.d, "esp-advance.jsonl")
        with unittest.mock.patch.object(node.trails, "where", lambda name, cfg=None: path), \
                unittest.mock.patch.object(node.metrics, "publish", lambda *a, **k: True), \
                unittest.mock.patch.object(node, "load", lambda p: self.cfg), \
                unittest.mock.patch.object(node, "esp_advance", side_effect=m.Refused("ROLLBACK: below the anchor")):
            # the run lock in the test's directory: main() takes it before the advance (esp_advance_settled, #471),
            # and the unit's default under /run is root's: a non-root run would be refused there, not by ROLLBACK
            self.assertEqual(node.main(["--config", "x", "--esp-lock", self.lock, "esp-advance"]), 2)
        with open(path) as f:
            line = json.loads(f.read().splitlines()[-1])
        self.assertEqual((line["event"], line["outcome"]), ("esp-advance", "DENY"))
        self.assertIn("ROLLBACK: below the anchor", line["reason"])

    def test_a_v4_chain_over_an_owner_written_anchor_is_refused_before_the_esp(self):
        """#242 B3 (regalia-kms-ed): the anchor is judged by the published chain esp_advance anchors, not by sync's store:
        a v4 tip over an owner-written anchor is Unusable, refused with the ESP unwritten and the anchor where it was."""
        import tests.test_baremetal_membership_v4 as v4
        with open(self.n.path(node.PUBLISHED), "wb") as f:
            f.write(m.canonical([self.e1, rt.sign(v4.manifest4(2, m.digest(self.m1), v4.nodes4()))]))
        with self.assertRaisesRegex(m.Unusable, "is owner-written: under regalia.membership/v4"):
            self.advance()
        self.assertFalse(os.path.exists(os.path.join(self.esp, bootcreds.CHAIN_ON_ESP)))
        self.assertEqual(self.n.anchor().value(), 1)

    def test_a_settled_advance_records_every_run_it_makes(self):
        """#449 over main's esp_advance_settled (#471): the settle loop may run the advance twice when the published chain
        changes during the first run. Each run is recorded, request before its ESP and anchor, outcome after: two pairs."""
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        lines, runs = [], []

        def advance(n, esp, lock_path, record=None):
            runs.append(1)
            if len(runs) == 1:  # the chain is republished while the first run is under way
                with open(n.path(node.PUBLISHED), "ab") as f:
                    f.write(b"")
                os.utime(n.path(node.PUBLISHED))
            return node.esp_advance(n, esp, lock_path=lock_path, record=record)
        node.esp_advance_settled(self.n, self.esp, lock_path=self.lock, advance=advance, record=lines.append)
        pairs = [e["event"] for e in lines]
        self.assertEqual(pairs.count("esp-advance-requested"), len(runs))
        self.assertEqual(pairs.count("esp-advance"), len(runs))
        self.assertTrue(all(e.get("outcome") == "ALLOW" for e in lines if e["event"] == "esp-advance"))

    def test_settling_without_a_trail_calls_the_advance_as_before(self):
        """A stand-in advance that takes no `record` (main's settle tests) is called exactly as before #449."""
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        seen = []
        node.esp_advance_settled(self.n, self.esp, lock_path=self.lock,
                                 advance=lambda n, esp, lock_path: seen.append(lock_path) or node.esp_advance(n, esp, lock_path=lock_path))
        self.assertEqual(seen, [self.lock + ".anchor"])

    def test_a_crash_between_the_write_and_the_anchor_is_completed_by_the_next_run(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        with unittest.mock.patch.object(m.HighWater, "anchor", side_effect=OSError("power cut")), self.assertRaises(OSError):
            self.advance()
        self.assertEqual(self.on_esp(), [self.e1, self.e2])                   # the ESP ahead: what the initrd accepts
        self.assertEqual(self.n.anchor().value(), 1)
        self.assertEqual(bootcreds.anchored(self.on_esp(), ROOT, self.n.anchor())["epoch"], 2)
        self.assertEqual(self.advance()[0], 2)
        self.assertEqual(self.n.anchor().value(), 2)

    def test_a_refused_chain_writes_nothing_and_leaves_the_anchor(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.advance()
        published = self.n.path(node.PUBLISHED)
        for label, chain, reason in (
                ("a rollback", [self.e1], "ROLLBACK"),
                ("a fork at the anchored epoch", [self.e1, rt.sign(dict(self.m2, policy_version="forked"))], "CONFLICT"),
                ("a chain the root did not sign", [self.e1, rt.sign(self.m2, key=hbt.REVOKE)], "")):
            with self.subTest(label):
                with open(published, "wb") as f:
                    f.write(m.canonical(chain))
                with self.assertRaises(m.Refused) as caught:
                    self.advance()
                self.assertIn(reason, str(caught.exception))
                self.assertEqual(self.on_esp(), [self.e1, self.e2])
                self.assertEqual(self.n.anchor().value(), 2)

    def test_a_chain_the_initrd_could_not_render_is_still_anchored_with_a_warning(self):
        """b and c revoked: no peer is left to unlock a. The next boot must go to the recovery prompt, and the anchor must
        not freeze at epoch 1 (rollback protection with it): written, anchored, and said."""
        m2 = dict(hbt.manifest(2, m.digest(self.m1), b="REVOKED_STOLEN", c="REVOKED_STOLEN"))
        self.sync.commit(rt.sign(m2))
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        epoch, _, rewritten, unrenderable = self.advance()
        self.assertEqual((epoch, rewritten, self.n.anchor().value()), (2, True, 2))
        self.assertIn("the manifest leaves a no peer", unrenderable)

    def test_only_the_chain_is_written(self):
        """The measured site credential is enrolment's; the ESP advance never touches loader/credentials."""
        credentials = os.path.join(self.esp, "loader", "credentials")
        os.makedirs(credentials)
        for path in (os.path.join(self.esp, "loader"), credentials):
            os.chmod(path, 0o755)                                             # whatever the umask: a trusted path
        with open(os.path.join(credentials, "regalia.site.cred"), "wb") as f:
            f.write(b"as enrolment wrote it")
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.advance()
        self.assertEqual(sorted(os.listdir(credentials)), ["regalia.site.cred"])
        with open(os.path.join(credentials, "regalia.site.cred"), "rb") as f:
            self.assertEqual(f.read(), b"as enrolment wrote it")
        self.assertEqual(sorted(os.listdir(os.path.join(self.esp, "EFI", "regalia"))), ["membership.json"])

    def test_a_link_on_the_esp_is_not_followed(self):
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        os.makedirs(os.path.join(self.esp, "EFI", "regalia"))
        for path in (os.path.join(self.esp, "EFI"), os.path.join(self.esp, "EFI", "regalia")):
            os.chmod(path, 0o755)
        os.symlink(os.path.join(self.d, "elsewhere"), os.path.join(self.esp, bootcreds.CHAIN_ON_ESP))
        self.refused("", self.advance)
        self.assertFalse(os.path.exists(os.path.join(self.d, "elsewhere")))
        self.assertEqual(self.n.anchor().value(), 1)


class AnchorLag(EspCase):
    """regalia-kms-48's read: an ESP advance that keeps failing leaves the anchor behind, silently; sync says so in
    membership.prom (RegaliaMembershipAnchorBehind), and `node check` shows both."""

    def test_sync_publishes_the_held_epoch_and_the_anchor_s(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        written = []
        with unittest.mock.patch.object(node.metrics, "publish", lambda writer, samples, target=None: written.append((writer, samples, target))):
            s = node.Sync.__new__(node.Sync)
            s.node, s.store = self.n, self.sync
            s.membership_metrics()
            self.advance()
            s.membership_metrics()
        self.assertEqual([(w, dict((name, v) for name, _, v in samples)) for w, samples, _ in written],
                         [("sync", {"regalia_membership_epoch": 2, "regalia_membership_anchor_epoch": 1}),
                          ("sync", {"regalia_membership_epoch": 2, "regalia_membership_anchor_epoch": 2})])
        self.assertEqual(written[0][2], node.metrics.path("sync", "membership.prom"))
        self.assertIn("regalia_membership_anchor_epoch 1", node.metrics.render("sync", written[0][1]))
        with unittest.mock.patch.object(node.metrics, "publish", side_effect=OSError("full")):
            s.membership_metrics()                                            # never raises: metrics do not stop sync

    def test_the_esp_advance_publishes_its_own_reading_success_or_not(self):
        """regalia-kms-48: root's own file (sync's could lie), at every run: ok, the anchor as it reads it, and whether the
        next boot renders. main() writes it on a refusal too."""
        written = []
        node.esp_metrics(self.n, ok=True, renderable=False, publish=written.append)
        got = {name: value for name, _, value in written[0]}
        self.assertEqual((got["regalia_esp_advance_ok"], got["regalia_esp_boot_renderable"], got["regalia_esp_anchor_epoch"]), (1, 0, 1))
        self.assertIn("regalia_esp_advance_ok 1", node.metrics.render("esp-advance", written[0]))
        node.esp_metrics(self.n, ok=True, publish=lambda samples: (_ for _ in ()).throw(OSError("full")))   # never raises
        published = []
        with unittest.mock.patch.object(node.metrics, "publish", lambda writer, samples, target=None: published.append((writer, samples))), \
                unittest.mock.patch.object(node, "load", lambda path: self.cfg), \
                unittest.mock.patch.object(node, "esp_advance", side_effect=m.Refused("ROLLBACK: below the anchor")):
            self.assertEqual(node.main(["--config", "x", "esp-advance"]), 2)
        self.assertEqual(published[0][0], "esp-advance")
        self.assertEqual({name: value for name, _, value in published[0][1]}.get("regalia_esp_advance_ok"), 0)


class Settled(EspCase):
    """regalia-kms-24 and 3e on main's three-node-recovery: a publication landing DURING a run is folded into it by the
    path unit, which starts nothing afterwards. esp_advance_settled runs again while the published chain changed under
    the run, so the ESP and the anchor reach what is published."""

    def test_a_chain_published_during_the_run_is_followed_by_another_run(self):
        node.publish(self.sync, self.n.path(node.PUBLISHED))                  # epoch 1 published
        runs = []

        def advance(n, esp, lock_path):
            result = node.esp_advance(n, esp, lock_path=lock_path)
            runs.append(result[0])
            if len(runs) == 1:                                                # sync publishes epoch 2 while run 1 is active
                self.sync.commit(self.e2)
                node.publish(self.sync, self.n.path(node.PUBLISHED))
            return result
        epoch = node.esp_advance_settled(self.n, self.esp, lock_path=self.lock, advance=advance)[0]
        self.assertEqual((runs, epoch, self.n.anchor().value()), ([1, 2], 2, 2))
        self.assertEqual(self.on_esp(), [self.e1, self.e2])

    def test_one_run_when_nothing_changed_and_a_refusal_when_it_never_settles(self):
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        calls = []
        node.esp_advance_settled(self.n, self.esp, lock_path=self.lock,
                                 advance=lambda n, esp, lock_path: calls.append(1) or node.esp_advance(n, esp, lock_path=lock_path))
        self.assertEqual(len(calls), 1)
        published = self.n.path(node.PUBLISHED)

        def churn(n, esp, lock_path):                                         # a file that changes under every run
            with open(published, "ab") as f:
                f.write(b" ")
            return (1, "", False, None)
        with self.assertRaises(m.Refused) as caught:
            node.esp_advance_settled(self.n, self.esp, lock_path=self.lock, advance=churn)
        self.assertIn("changed during each of %d runs" % node.ESP_SETTLE_RUNS, str(caught.exception))

    def test_a_second_run_is_refused_while_one_holds_the_run(self):
        """regalia-kms-95: two runs interleaved could write an OLDER chain to the ESP after the other anchored a newer one
        (an ESP below its anchor: a ROLLBACK at the next boot). One run at a time, on node.ESP_LOCK's file; the second is
        refused, never interleaved."""
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        inner, ran = [], []

        def first(n, esp, lock_path):
            inner.append(lock_path)
            with self.assertRaises(m.Refused) as caught:                       # a second run while the first is inside
                node.esp_advance_settled(self.n, self.esp, lock_path=self.lock,
                                         advance=lambda *a, **k: ran.append(1))
            self.assertIn("another regalia-esp-advance run, or a re-anchor, holds", str(caught.exception))
            return node.esp_advance(n, esp, lock_path=lock_path)
        self.assertEqual(node.esp_advance_settled(self.n, self.esp, lock_path=self.lock, advance=first)[0], 1)
        self.assertEqual(ran, [])                                              # the second never touched the ESP or anchor
        self.assertEqual(inner, [self.lock + ".anchor"])                       # the anchor's own lock is another file

    def test_esp_advance_and_reanchor_serialize_on_one_lock(self):
        """regalia-kms-24: reanchor (#391) holds node.ESP_LOCK for its whole re-anchor. The ESP advance takes the same file
        for its whole run: either one, held, refuses the other."""
        from deploy.baremetal import reanchor
        self.assertEqual(reanchor.ESP_LOCK, node.ESP_LOCK)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        with reanchor.esp_lock_held(self.lock) as held:                         # a re-anchor is running
            self.assertTrue(held)
            with self.assertRaises(m.Refused):
                node.esp_advance_settled(self.n, self.esp, lock_path=self.lock)
        self.assertEqual(self.n.anchor().value(), 1)

        def during(n, esp, lock_path):                                         # an ESP advance is running
            with self.assertRaises(m.Refused) as caught, reanchor.esp_lock_held(self.lock):
                pass
            self.assertIn("regalia-esp-advance holds the anchor's lock", str(caught.exception))
            return node.esp_advance(n, esp, lock_path=lock_path)
        node.esp_advance_settled(self.n, self.esp, lock_path=self.lock, advance=during)

if __name__ == "__main__":
    unittest.main()
