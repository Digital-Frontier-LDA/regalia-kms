"""deploy/baremetal/update.py: the acting half of a rolling image update (#75, Phase 15). The decisions are the
real ones (rollout.may_reboot on leases signed by the OpenSSL TPM fixtures, bootnext on PE images built as
ukify lays them out); the host's TPM, sync client and firmware are fakes."""
import os
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

    def document(self, manifest):
        """As update.Host's (#332): the document of the manifest asked about, which here is the one held."""
        assert manifest == self._manifest, "a document is asked for another manifest than the one held"
        return self._document

    def pcrs(self, selection):
        values = dict(self.running["pcrs"], **self.running["phases"]["system"])
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
        return lt.sign(body, self.case.keys[peer])

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

if __name__ == "__main__":
    unittest.main()
