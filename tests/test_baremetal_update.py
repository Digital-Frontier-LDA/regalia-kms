"""deploy/baremetal/update.py: the acting half of a rolling image update (#75, Phase 15). The decisions are the
real ones (rollout.may_reboot on leases signed by the OpenSSL TPM fixtures, bootnext on PE images built as
ukify lays them out); the host's TPM, sync client and firmware are fakes."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from deploy.baremetal import bootnext, measurements, rollout, update
from deploy.baremetal import membership as m
import tests.test_baremetal_lease as lt
import tests.test_baremetal_rollout as rt
from tests.test_baremetal_bootnext import ESP_GUID, FakeEfibootmgr, accepted, image

ONE, TWO = image(b"one"), image(b"two")
SET1, SET2 = accepted("image-1", ONE), accepted("image-2", TWO)
BOTH = rt.document("v2", **{n: [dict(SET1), dict(SET2)] for n in "abc"})
NEXT = rt.document("v3", **{n: [dict(SET2)] for n in "abc"})


class FakeHost:
    def __init__(self, case, manifest, document):
        self.case, self.node_id, self._manifest, self._document = case, "a", manifest, document
        self.running, self.refusing, self.asked, self.rebooted, self.reboot_fails, self.later = SET1, {}, [], 0, None, 0
        self.private_root = case.private
        self.firmware = FakeEfibootmgr()
        self.firmware.add("0002", "regalia-kms image-2", r"\EFI\Linux\image-2.efi")
        self.where = {"mount": lambda path: (0x0801, "vfat"), "partition_device": lambda guid: 0x0801, "loader_partition": lambda: ESP_GUID}

    def run(self, argv, **kw):
        if argv[:1] == [bootnext.EFIBOOTMGR]:
            return self.firmware(argv, **kw)
        return subprocess.run(argv, **kw)          # OpenSSL, for the leases' signatures

    def manifest(self):
        return self._manifest

    def anchored(self):
        return self._anchored if hasattr(self, "_anchored") else self._manifest["epoch"]

    def unrenderable(self, manifest):
        return getattr(self, "_unrenderable", None)

    def document(self, manifest):
        """As update.Host's (#332): the document of the manifest asked about, which here is the one held."""
        assert manifest == self._manifest, "a document is asked for another manifest than the one held"
        return self._document

    def pcrs(self, selection):
        values = dict(self.running["pcrs"], **self.running.get("phases", {}).get("system", {}))
        return {str(i): values[str(i)] for i in selection}

    def session(self):
        return lt.SESSION

    def own_state(self):
        return {"schema": rt.attest.STATE_SCHEMA, "nodes": {}, "nonces": {}}

    def now(self):
        return self.case.now + self.later

    def lease_from(self, peer, manifest, session, state_path):
        # a root-only directory of apply's own, under the private root, not the admission service's
        self.asked.append((peer, os.path.dirname(state_path)))
        assert os.path.dirname(os.path.dirname(state_path)) == self.private_root, state_path
        assert oct(os.stat(os.path.dirname(state_path)).st_mode & 0o777) == "0o700"
        if peer in self.refusing:
            refusal = self.refusing[peer]
            raise refusal if isinstance(refusal, Exception) else m.Refused(refusal)
        body = dict(self.case.body(manifest), node_id="a", ak_name=self.case.keys["a"].ak_name, issuer=peer, session_id=session)
        return lt.sign(body, self.case.keys[peer] if peer in self.case.keys else self.case.keys["a"])

    def quote(self, nonce, manifest):
        """A stand-in for Host.quote: this node's system-phase quote over `nonce`, in the shape node.quote gives
        (ephemeral_public, nonce, quote, signature). The FakeHost's boot session is fixed (lt.SESSION / SESSION_KEY)."""
        assert re.fullmatch(r"[0-9a-f]{64}", nonce), nonce
        return {"ephemeral_public": lt.SESSION_KEY, "nonce": nonce, "quote": "aa" * 64, "signature": "bb" * 64}

    def boot(self):
        return bootnext.state(self.run)

    def reboot(self):
        if self.reboot_fails:
            raise m.Refused(self.reboot_fails)
        self.rebooted += 1
        self.firmware.reboot()


class Case(rt.Case):
    def setUp(self):
        super().setUp()
        self.private = tempfile.mkdtemp()
        self.esp = tempfile.mkdtemp()
        for d in (self.private, self.esp):
            self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(self.esp, "EFI", "Linux"))
        for name, data in (("image-1.efi", ONE), ("image-2.efi", TWO), ("image-3.efi", image(b"three"))):
            with open(os.path.join(self.esp, "EFI", "Linux", name), "wb") as f:
                f.write(data)
        self.m1 = self.under(rt.document("v1", **{n: [dict(SET1)] for n in "abc"}))
        self.m2 = self.under(BOTH, epoch=2, prev=m.digest(self.m1))
        self.host = FakeHost(self, self.m2, BOTH)
        self.trail, self.prompts = [], []

    def record(self, event):
        self.trail.append(event)
        return len(self.trail)                    # the seq trails.append would return

    def typed(self, answer):
        def ask(prompt):
            self.prompts.append(prompt)
            return answer
        return ask

    def apply(self, answer="reboot a into image-2", entry="0002"):
        return update.apply(self.host, entry, self.esp, self.typed(answer), self.record, say=lambda line: None)

    def bootnexts(self):
        return [call for call in self.host.firmware.calls if "--bootnext" in call]


class Apply(Case):
    def test_apply_sets_bootnext_on_next_after_live_leases_and_reboots_and_records_who_vouched(self):
        done = self.apply()
        self.assertEqual(done["state"]["next"], "0002")
        self.assertEqual((self.host.rebooted, self.host.firmware.current), (1, "0002"))
        self.assertEqual([p for p, _ in self.host.asked], ["b", "c", "b", "c"])  # each peer asked once before the phrase, once after
        self.assertEqual(os.listdir(self.private), [])                          # the leases went with their directory
        self.assertEqual([(e["outcome"], e.get("request")) for e in self.trail], [("REQUESTED", None), ("ALLOW", 1)])
        self.assertEqual((self.trail[0]["lease_issuers"], self.trail[0]["authorizers"], self.trail[0]["from"], self.trail[0]["to"]),
                         (["b", "c"], ["b", "c"], "image-1", "image-2"))
        self.assertEqual(self.trail[1]["measured"], bootnext.measured(TWO))
        # after the trial boot, any reset is CURRENT again
        self.host.firmware.reboot()
        self.assertEqual(self.host.firmware.current, "0001")

    def test_an_epoch_the_esp_advance_has_not_anchored_is_refused(self):
        """#66 B3: the published chain ahead of the TPM anchor: the ESP may not hold it yet, so no reboot."""
        self.host._anchored = self.host.manifest()["epoch"] - 1
        self.refused("the TPM anchor is at epoch %d, the published chain at %d: regalia-esp-advance has not written"
                     % (self.host._anchored, self.host._anchored + 1), self.apply)
        self.assertEqual((self.bootnexts(), self.prompts, self.host.asked, [e["outcome"] for e in self.trail]), ([], [], [], ["DENY"]))

    def test_a_manifest_that_fails_to_verify_leaves_a_deny_on_the_trail(self):
        """regalia-kms-dx7.8 review, finding 3 (regression): the module text promises 'every exit is on the
        update trail'. A chain that does not verify is the case an auditor most needs on the trail; reading the
        topology for the event used to call host.manifest() before the try that records the DENY, so the
        refusal escaped the trail. The topology is read inside the try, from the manifest already read there:
        the DENY is back, and the chain is read once, not twice."""
        import unittest.mock as mock
        with mock.patch.object(type(self.host), "manifest", side_effect=m.Refused("the chain does not verify from the root key")):
            self.refused("the chain does not verify from the root key", self.apply)
        self.assertEqual([e["outcome"] for e in self.trail], ["DENY"])
        self.assertEqual(self.trail[0]["reason"], "the chain does not verify from the root key")

    def test_a_next_boot_that_needs_the_recovery_key_is_refused(self):
        """regalia-kms-48: a manifest that leaves the initrd nothing to render turns a reboot into a recovery-key ceremony."""
        self.host._unrenderable = "the manifest leaves a no peer with an address"
        self.refused("the initrd cannot render a boot configuration under epoch %d (the manifest leaves a no peer" % self.host.manifest()["epoch"],
                     self.apply)
        self.assertEqual((self.bootnexts(), self.prompts, self.host.asked, [e["outcome"] for e in self.trail]), ([], [], [], ["DENY"]))

    def test_nothing_changes_without_the_phrase(self):
        self.refused("not confirmed: nothing was changed", self.apply, "yes")
        self.assertEqual((self.bootnexts(), self.host.rebooted), ([], 0))
        self.assertEqual([(e["outcome"], e.get("aborted")) for e in self.trail], [("DENY", True)])

    def test_a_peer_that_gives_no_lease_stops_it_and_is_named(self):
        self.host.refusing = {"c": "c did not answer (TimeoutError)"}
        why = self.refused("c gave no lease: c did not answer (TimeoutError)", self.apply)
        self.assertTrue(why.startswith("WAIT: no valid lease from c (none presented)"), why)     # may_reboot's own reason first
        self.assertEqual([p for p, _ in self.host.asked], ["b", "c"])            # asked once, not again
        self.assertEqual((self.bootnexts(), self.host.rebooted, self.prompts), ([], 0, []))
        self.assertEqual([(e["outcome"], e["no_lease"]) for e in self.trail], [("DENY", {"c": "c did not answer (TimeoutError)"})])
        self.assertIn("c gave no lease", self.trail[0]["reason"])

    def test_an_entry_whose_image_is_not_next_is_refused_before_anything_is_asked_of_the_operator(self):
        self.host.firmware.add("0003", "wrong", r"\EFI\Linux\image-3.efi")
        self.refused("it is not that image", self.apply, entry="0003")
        self.assertEqual((self.bootnexts(), self.prompts), ([], []))
        self.assertEqual([e["outcome"] for e in self.trail], ["DENY"])

    def test_bootorder_must_start_with_the_running_image_or_there_is_no_fallback(self):
        """`efibootmgr --create` puts the new entry first: left so, a reset after the trial boot would boot it again."""
        self.host.firmware.order = ["0002", "0001", "0000"]
        self.refused("BootOrder starts with 0002, not with Boot0001, the image this host runs", self.apply)
        self.assertEqual((self.bootnexts(), self.prompts, [e["outcome"] for e in self.trail]), ([], [], ["DENY"]))

    def test_what_the_host_runs_is_read_from_its_tpm(self):
        self.host.running = SET2
        self.refused("a already runs its target image-2", self.apply)
        self.host.running = accepted("image-3", image(b"three"))
        self.refused("match none of the sets the manifest approves for a", self.apply)
        self.assertEqual((self.bootnexts(), [e["outcome"] for e in self.trail]), ([], ["DENY", "DENY"]))

    def test_a_trail_that_cannot_be_written_stops_it_before_bootnext(self):
        def broken(event):
            raise OSError("the update trail is not writable")
        with self.assertRaises(OSError):
            update.apply(self.host, "0002", self.esp, self.typed("reboot a into image-2"), broken, say=lambda line: None)
        self.assertEqual((self.bootnexts(), self.host.rebooted), ([], 0))

    def test_an_armed_bootnext_never_outlives_an_apply_that_did_not_reboot(self):
        """d9 on #326: the trail write after BootNext, or the reboot itself, fails. BootNext is cleared and read
        back, and that is recorded; a later reset is CURRENT, not an unwatched trial boot."""
        self.host.reboot_fails = "systemctl reboot failed (exit 1): Failed to connect to bus"
        self.refused("the reboot did not happen (systemctl reboot failed (exit 1)", self.apply)
        self.assertIsNone(self.host.firmware.next)
        self.assertEqual([(e["outcome"], e.get("request")) for e in self.trail], [("REQUESTED", None), ("ALLOW", 1), ("BOOTNEXT-CLEARED", 1)])
        self.host.firmware.reboot()
        self.assertEqual(self.host.firmware.current, "0001")
        # the trail itself fails right after BootNext is set
        self.host.reboot_fails, self.trail[:] = None, []
        calls = []

        def breaks_after_the_request(event):
            calls.append(event["outcome"])
            if event["outcome"] == "ALLOW":
                raise OSError("the update trail is not writable")
            return self.record(event)
        self.refused("the reboot did not happen (the update trail is not writable); BootNext is cleared", update.apply, self.host, "0002",
                     self.esp, self.typed("reboot a into image-2"), breaks_after_the_request, say=lambda line: None)
        self.assertEqual((self.host.firmware.next, self.host.rebooted), (None, 0))
        self.assertEqual(calls, ["REQUESTED", "ALLOW", "BOOTNEXT-CLEARED"])

    def test_a_run_cut_after_its_request_is_closed_and_its_bootnext_cleared(self):
        trail = os.path.join(self.private, "update.jsonl")
        record = lambda event: update.trails.append(trail, event)
        seq = record({"event": "update-apply", "node_id": "a", "entry": "0002", "outcome": "REQUESTED"})
        self.host.firmware.next = "0002"                        # armed, then the process was killed
        closed = update.close_cut(self.host, trail, record, say=lambda line: None)
        self.assertEqual((closed["outcome"], closed["request"], closed["bootnext_cleared"]), ("INCOMPLETE", seq, "0002"))
        self.assertIsNone(self.host.firmware.next)
        self.assertIsNone(update.close_cut(self.host, trail, record, say=lambda line: None))      # answered now

    def test_leases_that_run_out_while_the_phrase_waits_stop_it(self):
        """d9 on #326: the operator types the phrase ten minutes after the plan. The leases have run out."""
        def slow(prompt):
            self.host.later = 600
            return "reboot a into image-2"
        self.refused("the peers' leases no longer allow it after the confirmation", update.apply, self.host, "0002", self.esp, slow, self.record,
                     say=lambda line: None)
        self.assertEqual((self.bootnexts(), self.host.rebooted), ([], 0))
        self.assertEqual([(e["outcome"], e.get("expired")) for e in self.trail], [("DENY", True)])
        self.assertEqual([p for p, _ in self.host.asked], ["b", "c", "b", "c"])      # asked again after the phrase, once each

    def failing_firmware(self, bootnext_rc=0):
        """efibootmgr whose --delete-bootnext fails (EFI variables gone read-only), and optionally --bootnext too."""
        fw, plain = self.host.firmware, FakeEfibootmgr.__call__

        def call(argv, **kw):
            if "--bootnext" in argv and bootnext_rc:
                fw.next = argv[-1]                        # written, but reported as failed
                return subprocess.CompletedProcess(argv, bootnext_rc, "", "write error")
            if "--delete-bootnext" in argv:
                return subprocess.CompletedProcess(argv, 5, "", "EFI variables are read-only")
            return plain(fw, argv, **kw)
        self.host.run = lambda argv, **kw: call(argv, **kw) if argv[:1] == [bootnext.EFIBOOTMGR] else subprocess.run(argv, **kw)

    def test_a_bootnext_that_cannot_be_cleared_is_critical_and_says_what_to_do(self):
        """24 on #326: BootNext armed, no reboot, and clearing it failed: recorded CRITICAL, raised, with the command."""
        self.failing_firmware(bootnext_rc=5)
        self.refused("CRITICAL: setting BootNext failed (efibootmgr --bootnext 0002 failed (exit 5): write error) AND BootNext could "
                     "not be cleared", self.apply)
        self.assertEqual([e["outcome"] for e in self.trail], ["REQUESTED", "CRITICAL", "FAILED"])
        self.assertIn("efibootmgr --delete-bootnext", self.trail[1]["reason"])
        self.trail.clear()
        self.failing_firmware()
        self.host.reboot_fails = "systemctl reboot failed (exit 1)"
        self.refused("CRITICAL: the reboot did not happen (systemctl reboot failed (exit 1)) AND BootNext could not be cleared", self.apply)
        self.assertEqual([e["outcome"] for e in self.trail], ["REQUESTED", "ALLOW", "CRITICAL"])

    def test_the_deadline_is_bounded(self):
        for minutes in (0, 4, 121):
            with self.subTest(minutes=minutes):
                self.refused("the deadline is 5 to 120 minutes", update.apply, self.host, "0002", self.esp, self.typed(""), self.record, minutes)
        self.assertEqual({e["outcome"] for e in self.trail}, {"DENY"})


class Promote(Case):
    def promote(self, answer="make 0002 the default on a"):
        return update.promote(self.host, self.esp, self.typed(answer), self.record, say=lambda line: None)

    def test_only_the_target_image_the_host_came_up_on_once_a_peer_has_vouched_for_this_boot(self):
        self.refused("a runs image-1, not its target image-2", self.promote)
        self.apply()                                       # BootNext, and the trial boot: the fake firmware is on 0002
        self.trail.clear()
        self.host.running = SET2
        self.host.refusing = {"b": "refused", "c": "refused"}
        self.refused("no peer gave this boot a lease", self.promote)
        self.host.refusing = {"c": OSError("No route to host")}       # d9: a peer that is down does not stop the others
        after = self.promote()
        self.assertEqual(self.trail[-1]["no_lease"], {"c": "unreachable (OSError: No route to host)"})
        self.assertEqual(after["order"][:2], ["0002", "0001"])
        self.assertEqual([(e["outcome"], e["lease_issuers"]) for e in self.trail], [("DENY", []), ("REQUESTED", ["b"]), ("ALLOW", ["b"])])

    def test_the_booted_image_must_be_the_target(self):
        """Running image-2's PCRs while BootCurrent's file is image-1 would mean the file changed under it."""
        self.host.running = SET2
        self.refused("it is not that image", self.promote)


class SingleNode(Case):
    """regalia-kms-dx7.8 (docs/design/single-node.md 4.6): the single-node profile's update is a planned outage.
    apply takes --planned-outage, asks nobody, and records the decision on the trail; promote asks for a lease of its
    OWN for the boot it promotes (the self-issued one); and the flag under another profile is a refusal."""

    def setUp(self):
        super().setUp()
        # the single-node host's accepted images are its own UKI-measured sets: per-phase PCR 11, as the image on the ESP
        self.sc1 = rt.document("s-current", a=[dict(SET1)])
        self.scboth = rt.document("s-both", a=[dict(SET1), dict(SET2)])
        self.s1 = dict(self.single(1, ""), policy_version=measurements.version(self.sc1))
        self.s2 = dict(self.single(2, m.digest(self.s1)), policy_version=measurements.version(self.scboth))
        self.host._manifest, self.host._document = self.s2, self.scboth
        self.host.running = self.scboth["nodes"]["a"]["accepted"][0]
        # the self-issued lease this host holds for this boot: a's AK signs for a, as _issue allows under the profile
        self.self_lease = lt.sign(dict(self.body(self.s2), node_id="a", issuer="a"), self.keys["a"])

    def apply(self, answer="reboot a into image-2", entry="0002", planned_outage=False):
        return update.apply(self.host, entry, self.esp, self.typed(answer), self.record,
                            planned_outage=planned_outage, say=lambda line: None)

    def test_apply_under_the_single_node_profile_is_a_planned_outage_and_asks_no_body(self):
        done = self.apply(planned_outage=True)
        self.assertEqual(done["state"]["next"], "0002")
        self.assertEqual((self.host.rebooted, self.host.firmware.current), (1, "0002"))
        self.assertEqual(self.host.asked, [], "no peer exists: nobody is asked for a lease")
        self.assertEqual([e["outcome"] for e in self.trail], ["REQUESTED", "ALLOW"])
        for event in self.trail:
            self.assertEqual(event.get("planned_outage"), True)
            self.assertEqual(event.get("topology"), "single-node")
            self.assertEqual(event.get("lease_issuers"), [])
            self.assertEqual(event.get("authorizers"), [])
        # and the denial says the same on the trail
        self.refused("a single-node host's reboot is a planned outage: give --planned-outage", self.apply)
        self.assertEqual(self.trail[-1]["planned_outage"], False)
        self.assertEqual(self.trail[-1]["topology"], "single-node")
        self.assertEqual(self.host.rebooted, 1)                     # only the one that was planned went down

    def test_apply_refuses_the_planned_outage_flag_under_another_profile(self):
        self.host._manifest, self.host._document, self.host.running = self.m2, BOTH, self.host.running
        self.refused("--planned-outage is a single-node decision", self.apply, planned_outage=True)
        self.assertEqual(self.host.rebooted, 0)
        self.assertEqual(self.trail[-1]["planned_outage"], True)
        self.assertEqual(self.trail[-1]["topology"], "multi-node")

    def test_promote_under_the_single_node_profile_needs_the_node_s_own_lease_for_this_boot(self):
        """promote on three nodes needs a peer's lease for the boot it promotes; with one node it needs its own:
        the self-issued lease is the record that it booted, in this session, under this epoch."""
        self.apply(planned_outage=True)
        self.trail.clear()
        self.host.running = self.scboth["nodes"]["a"]["accepted"][-1]
        after = update.promote(self.host, self.esp, self.typed("make 0002 the default on a"), self.record,
                               say=lambda line: None, planned_outage=True)
        self.assertEqual(after["order"][:2], ["0002", "0001"])
        self.assertEqual(self.trail[-1]["lease_issuers"], ["a"])
        self.assertEqual(self.trail[-1]["planned_outage"], True)
        # and without the self-lease, refused: no evidence that this boot came up
        self.host.firmware.order = ["0001", "0002"]
        self.host.refusing = {"a": "no lease was issued for this boot"}
        self.refused("no peer gave this boot a lease", update.promote, self.host, self.esp,
                     self.typed("make 0002 the default on a"), self.record, say=lambda line: None,
                     planned_outage=True)

    def test_promote_under_the_single_node_profile_records_the_planned_outage_from_the_profile(self):
        """regalia-kms-dx7.8 review, finding 5: the runbook's promote step names no --planned-outage (there is no
        such flag; the operator's decision was the apply's). The promote's trail still records planned_outage
        true, from the PROFILE: under single-node the update is a planned outage, and the trail says so on every
        event, as the runbook's row promises. Called without the flag, as main() does, a single-node promote says
        true; a multi-node promote (no flag) still says false."""
        self.apply(planned_outage=True)
        self.trail.clear()
        self.host.running = self.scboth["nodes"]["a"]["accepted"][-1]
        after = update.promote(self.host, self.esp, self.typed("make 0002 the default on a"), self.record,
                               say=lambda line: None)
        self.assertEqual(after["order"][:2], ["0002", "0001"])
        self.assertEqual(self.trail[-1]["planned_outage"], True, "single-node promote records it from the profile")
        self.assertEqual(self.trail[-1]["topology"], "single-node")
        # the same call under another profile (no flag, no outage) records false: the profile is what decides
        self.host._manifest, self.host._document, self.host.running = self.m2, BOTH, BOTH["nodes"]["a"]["accepted"][-1]
        self.host.firmware.order = ["0001", "0002"]
        self.trail.clear()
        update.promote(self.host, self.esp, self.typed("make 0002 the default on a"), self.record, say=lambda line: None)
        self.assertEqual(self.trail[-1]["planned_outage"], False, "multi-node promote with no flag records false")
        self.assertEqual(self.trail[-1]["topology"], "multi-node")

    def test_quote_for_owner_prints_the_system_phase_quote_over_the_owner_s_nonce(self):
        """regalia-kms-dx7.8: after the planned-outage reboot the serving path is up (a self-lease for this boot),
        and quote-for-owner prints the node's system-phase quote over the owner's nonce -- the evidence owner.py
        attest-booted verifies, carried back to the owner by hand. Read-only: it records nothing on success (like
        status), and a DENY on the trail only when the serving path is not up, the host is not single-node, or the
        nonce is malformed."""
        nonce = "11" * 32
        out = []
        self.trail.clear()
        evidence = update.quote_for_owner(self.host, nonce, self.record, say=out.append)
        self.assertEqual(evidence, {"ephemeral_public": lt.SESSION_KEY, "nonce": nonce, "quote": "aa" * 64,
                                    "signature": "bb" * 64, "phase": "system"})
        self.assertEqual(self.trail, [], "read-only: no change, nothing on the trail")
        self.assertIn(json.dumps(evidence, sort_keys=True), out)
        # the serving path not up (no self-lease) is a refusal: the quote would be of a boot that never came up
        self.host.refusing = {"a": "no lease was issued for this boot"}
        self.refused("the serving path has not come up", update.quote_for_owner, self.host, nonce, self.record,
                     say=lambda line: None)
        self.assertEqual((self.trail[-1]["event"], self.trail[-1]["outcome"]), ("update-quote-for-owner", "DENY"))
        # under another profile it is refused: a peer, not the owner, is the source of the lease and the quote
        self.host.refusing = {}
        self.host._manifest, self.host._document, self.host.running = self.m2, BOTH, SET2
        self.refused("quote-for-owner is the single-node profile's", update.quote_for_owner, self.host, nonce,
                     self.record, say=lambda line: None)
        # a nonce that is not the owner's (64 hex) is refused before anything is asked
        self.host._manifest, self.host._document, self.host.running = self.s2, self.scboth, self.scboth["nodes"]["a"]["accepted"][0]
        self.refused("the owner's nonce is 64 lowercase hex", update.quote_for_owner, self.host, "zz", self.record,
                     say=lambda line: None)


class Forget(Case):
    def test_only_an_image_the_manifest_no_longer_approves(self):
        self.apply()
        self.host.running = SET2
        update.promote(self.host, self.esp, self.typed("make 0002 the default on a"), self.record, say=lambda line: None)
        forget = lambda: update.forget(self.host, "0001", self.esp, self.typed("remove 0001 from a"), self.record, say=lambda line: None)
        self.refused("Boot0001's image is image-1, which the manifest still approves for a", forget)
        self.host._manifest, self.host._document = self.under(NEXT, epoch=3, prev=m.digest(self.m2)), NEXT     # the retire
        after = forget()
        self.assertNotIn("0001", after["entries"])
        self.assertEqual([e["outcome"] for e in self.trail[-3:]], ["DENY", "REQUESTED", "ALLOW"])


class Status(Case):
    def test_status_says_whether_a_reset_boots_the_target(self):
        found = update.status(self.host, self.esp)
        self.assertEqual((found["running"], found["target"], found["entries"], found["promoted"]),
                         ("image-1", "image-2", {"0001": "image-1", "0002": "image-2"}, False))
        self.apply()
        self.assertFalse(update.status(self.host, self.esp)["promoted"])
        self.host.running = SET2
        update.promote(self.host, self.esp, self.typed("make 0002 the default on a"), self.record, say=lambda line: None)
        found = update.status(self.host, self.esp)
        self.assertEqual((found["running"], found["order"][0], found["promoted"]), ("image-2", "0002", True))
        self.host.firmware.next = "0001"                        # armed: a reset would not boot the target
        self.assertFalse(update.status(self.host, self.esp)["promoted"])
        self.assertNotIn("--bootorder", sum(self.host.firmware.calls[-3:], []))


class Running(unittest.TestCase):
    def test_exactly_one_set_must_match(self):
        self.assertEqual(update.running_set(BOTH, "a", lambda sel: {"7": "00" * 32, "11": SET2["phases"]["system"]["11"]})["label"], "image-2")
        with self.assertRaises(m.Refused):
            update.running_set(BOTH, "a", lambda sel: {"7": "00" * 32})          # not the PCRs asked for
        with self.assertRaises(m.Refused):
            update.running_set(BOTH, "a", lambda sel: {"7": "00" * 32, "11": SET2["phases"]["initrd"]["11"]})   # still in its initrd



class TheRealHost(unittest.TestCase):
    def test_pcrs_are_read_from_the_tpm_named_by_the_configuration(self):
        host = update.Host.__new__(update.Host)
        host.node = type("N", (), {"tcti": "device:/dev/tpmrm0"})()
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(bytes([7]) * 32 + bytes([11]) * 32)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        host.run = run
        self.assertEqual(host.pcrs([11, 7]), {"7": "07" * 32, "11": "0b" * 32})
        self.assertEqual(calls[0][:5], ["tpm2_pcrread", "-T", "device:/dev/tpmrm0", "sha256:11,7", "-o"])

    def test_it_runs_only_as_root(self):
        if os.geteuid() == 0:
            self.skipTest("run as root")
        rc = update.main(["promote", "--config", "/nonexistent/node.json"], typed=lambda prompt: "")
        self.assertEqual(rc, 1)

    def test_lease_from_under_single_node_uses_the_node_s_own_sync(self):
        """regalia-kms-dx7.8 review (CodeRabbit on #779): under the single-node profile the lease source is this
        node's OWN regalia-sync (self_source), not sources() -- a single-node host has no service tunnel, and
        sources() excludes the node itself, so asking its own node ID refused with 'not a peer this node can
        reach'. The admission renew path (node.py) makes the same choice; lease_from now mirrors it. The flow is
        stopped right after the source selection (node.quote raises a sentinel), so the test asserts which source
        method was called and that the require passes, not the rest of the lease exchange."""
        from tests.test_baremetal_membership_v5 import single5, manifest5, one
        from tests.test_baremetal_membership_v4 import nodes4
        class Sentinel(Exception):
            pass
        single = single5(1, "", [dict(one("a"), ek_name="00" * 32, ak_name="00" * 32)], policy_version="x")
        multi = manifest5(1, "", nodes4())
        for label, manifest, peer, want in (("single-node", single, "a", "self_source"),
                                            ("multi-node", multi, "b", "sources")):
            with self.subTest(label):
                calls = []
                def self_source(self, timeout=None):
                    calls.append("self_source")
                    return {"a": "local-transport"}
                def sources(self, m, timeout=None):
                    calls.append("sources")
                    return {"a": "tunnel", "b": "tunnel"}
                def quote(self, session_id, public):
                    raise Sentinel("stopped after source selection")
                node = type("N", (), {"node_id": "a", "clock": staticmethod(lambda: 0), "tpm_clock": staticmethod(lambda: 0),
                                      "self_source": self_source, "sources": sources, "quote": quote})()
                host = update.Host.__new__(update.Host)
                host.node, host.node_id, host.run, host._session = node, "a", lambda *a, **k: None, ("ab" * 32, "cd" * 32)
                d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
                with self.assertRaises(Sentinel):
                    host.lease_from(peer, manifest, "ab" * 32, os.path.join(d, "lease.json"))
                self.assertEqual(calls, [want], "profile %s must pick %s()" % (label, want))


if __name__ == "__main__":
    unittest.main()
