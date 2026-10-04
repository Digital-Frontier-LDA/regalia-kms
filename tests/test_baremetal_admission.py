"""deploy/baremetal/admission.py (#74): the root service that keeps the node's runtime lease and writes the
one file the Go daemon reads. Refused means serve_until 0 in the same step; a failed renewal leaves what
the lease still gives; the file runs out by itself if the service stops."""
import json
import os
import subprocess
import unittest
import unittest.mock
from unittest import mock

from deploy.baremetal import admission, lease
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt

BOOT = "0f3a9c1e-1111-4222-8333-444455556666"


class Case(lt.Case):
    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.d, "admission.json")
        self.manifest_now = self.m1
        self.peer_up = True
        self.service = self.new_service()

    def new_service(self):
        return admission.Service(self.holder, lambda: self.manifest_now, self.renew, self.path,
                                 boottime=lambda: self.ticks, boot=lambda: BOOT)

    def renew(self, request):
        """The transport's stand-in: peer b answers, under whatever manifest it holds."""
        if not self.peer_up:
            raise ConnectionError("peer b is unreachable")
        return self.issue("b", manifest=self.manifest_now, request=request)

    def on_disk(self):
        with open(self.path) as f:
            return json.load(f)


class Metrics(Case):
    """#305: after every round, serving and the lease left, through deploy/baremetal/metrics.py's registry."""

    def test_serving_and_the_lease_left_are_published_and_registered(self):
        from deploy.baremetal import metrics
        published = []
        service = admission.Service(self.holder, lambda: self.manifest_now, self.renew, self.path,
                                    boottime=lambda: self.ticks, boot=lambda: BOOT, metrics=published.append)
        service.step()
        self.assertEqual(published[-1], [("regalia_admission_serving", {}, 1), ("regalia_admission_lease_seconds_left", {}, lease.MAX_LIFETIME)])
        self.manifest_now = None                                          # no manifest: not admitted
        service.step()
        self.assertEqual(published[-1], [("regalia_admission_serving", {}, 0), ("regalia_admission_lease_seconds_left", {}, 0)])
        for samples in published:
            metrics.render("admission", samples)


class Backoff(Case):
    """48 on #347: while renewals fail they back off, 5 s doubling to 60 s, and a success ends it."""

    def test_a_cut_off_node_asks_less_and_less_then_once_a_minute(self):
        asked = []
        real = self.renew

        def renew(request):
            asked.append(self.ticks // 1000)
            return real(request)
        self.renew = renew
        service = self.new_service()
        service.step()                                                     # leased
        self.peer_up = False
        self.later(lease.MAX_LIFETIME)                                     # its lease has run out: due() on every step
        start, asked[:] = self.ticks // 1000, []
        for _ in range(10 * 60 // 5):                                      # ten minutes of the 5 s step
            service.step()
            self.later(5)
        gaps = [b - a for a, b in zip(asked, asked[1:])]
        self.assertEqual(gaps[:5], [5, 10, 20, 40, 60])
        self.assertTrue(all(g == 60 for g in gaps[4:]), gaps)
        self.assertLessEqual(len(asked), 15)                               # not 120
        self.peer_up = True
        self.later(admission.RETRY_MAX)
        self.assertGreater(service.step()["serve_until_boottime_ms"], 0)
        self.assertEqual((service.retry_at, service.retry_wait), (0, 0))   # a success ends the back-off


class Recorded(Case):
    """#340: each change between serving and not serving is on the node's admission trail, once, with its reason; TO
    serving only once recorded, TO not serving at once (recorded after; a failed record is loud and tried again)."""

    def recording(self, fail=lambda event: False):
        self.trail, self.warned = [], []

        def record(event):
            if fail(event):
                raise OSError("the trail is not writable")
            self.trail.append(event)
        return admission.Service(self.holder, lambda: self.manifest_now, self.renew, self.path, boottime=lambda: self.ticks,
                                 boot=lambda: BOOT, record=record, warn=self.warned.append)

    def test_each_change_is_recorded_once_with_its_reason(self):
        service = self.recording()
        service.step()
        service.step()                                                      # no change: nothing more
        self.assertEqual([(e["event"], e["outcome"], e["peer"], e["subject"], e["epoch"]) for e in self.trail],
                         [("admission-serving", "ALLOW", "b", "a", 1)])
        self.peer_up = False
        self.later(lease.MAX_LIFETIME - admission.MARGIN)                   # into the margin: it stops
        self.assertEqual(service.step()["serve_until_boottime_ms"], 0)
        service.step()
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW", "DENY"])
        self.assertIn("renewal failed: peer b is unreachable", self.trail[-1]["reason"])
        self.peer_up = True
        self.later(admission.RETRY_MAX)                                     # the next attempt its back-off allows
        self.assertGreater(service.step()["serve_until_boottime_ms"], 0)    # back: recorded again
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW", "DENY", "ALLOW"])

    def test_it_serves_only_once_the_change_is_recorded(self):
        """24's rule on #340: going TO serving requires the record."""
        broken = [True]
        service = self.recording(fail=lambda event: broken[0])
        document = service.step()
        self.assertEqual(document["serve_until_boottime_ms"], 0)
        self.assertIn("the change to serving could not be recorded on the admission trail: the trail is not writable", document["reason"])
        self.assertEqual(self.on_disk(), document)
        broken[0] = False
        self.assertGreater(service.step()["serve_until_boottime_ms"], 0)
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW"])

    def test_it_stops_serving_even_when_that_cannot_be_recorded_and_says_so(self):
        """And going TO not serving never waits on the trail: it stops, then records; a failed record is loud and tried
        again at the next round, never a reason to keep serving."""
        broken = [False]
        service = self.recording(fail=lambda event: broken[0] and event["outcome"] == "DENY")
        service.step()
        self.peer_up, broken[0] = False, True
        self.later(lease.MAX_LIFETIME - admission.MARGIN)
        document = service.step()
        self.assertEqual((document["serve_until_boottime_ms"], self.on_disk()["serve_until_boottime_ms"]), (0, 0))
        self.assertEqual(len(self.warned), 1)
        self.assertIn("AUDIT: this node stopped serving", self.warned[0])
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW"])     # not taken yet
        service.step()
        self.assertEqual(len(self.warned), 2)                               # tried again, loud again
        broken[0] = False
        service.step()
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW", "DENY"])
        service.step()
        self.assertEqual([e["outcome"] for e in self.trail], ["ALLOW", "DENY"])     # recorded once


class Admission(Case):
    def test_a_node_with_a_lease_is_admitted_until_its_expiry_less_the_margin(self):
        asked_at = self.ticks
        document = self.service.step()
        self.assertEqual(document, self.on_disk())
        self.assertEqual(list(document), list(admission.FIELDS))
        self.assertEqual(document, {
            "schema": "regalia.admission/v1", "node_id": "a", "session_id": lt.SESSION, "boot_id": BOOT, "epoch": 1,
            "manifest_digest": m.digest(self.m1), "lease_issued_at": hbt.stamp(self.now), "requested_boottime_ms": asked_at,
            "serve_until_boottime_ms": self.ticks + (lease.MAX_LIFETIME - admission.MARGIN) * 1000, "reason": ""})
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o644)       # the daemon, another user, reads it
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".admission-")], [])

    def test_the_bound_is_in_boottime_and_does_not_move_between_renewals(self):
        first = self.service.step()["serve_until_boottime_ms"]
        self.later(50)
        self.assertEqual(self.service.step()["serve_until_boottime_ms"], first)          # same lease, 50 s later: the same instant
        self.later(50)                                                                    # a third of the lifetime used: renewed
        renewed = self.service.step()
        self.assertEqual(renewed["serve_until_boottime_ms"], self.ticks + (lease.MAX_LIFETIME - admission.MARGIN) * 1000)
        self.assertEqual(renewed["requested_boottime_ms"], self.ticks)
        self.assertGreater(renewed["serve_until_boottime_ms"], first)

    def test_a_failed_renewal_keeps_what_the_lease_still_gives_and_no_more(self):
        first = self.service.step()
        self.peer_up = False
        self.later(150)
        kept = self.service.step()
        self.assertEqual(kept["serve_until_boottime_ms"], first["serve_until_boottime_ms"])
        self.assertEqual(kept["requested_boottime_ms"], first["requested_boottime_ms"])   # still the lease it holds, not the failed request
        self.assertEqual(kept["reason"], "")
        self.later(lease.MAX_LIFETIME - 150 - admission.MARGIN)                           # into the margin
        inside = self.service.step()
        self.assertEqual(inside["serve_until_boottime_ms"], 0)
        self.assertIn("renewal failed: peer b is unreachable", inside["reason"])
        self.assertIn("the lease has 10 s left, inside the 10 s margin", inside["reason"])
        self.later(admission.MARGIN)
        gone = self.service.step()
        self.assertEqual((gone["serve_until_boottime_ms"], gone["lease_issued_at"], gone["requested_boottime_ms"]), (0, admission.NEVER, 0))
        self.assertIn("EXPIRED: the runtime lease expired", gone["reason"])
        self.peer_up = True                                                               # the peer is back: admitted again,
        self.later(admission.RETRY_MAX)                                                   # at the next attempt its back-off allows
        self.assertGreater(self.service.step()["serve_until_boottime_ms"], self.ticks)

    def test_a_revoked_node_is_written_as_zero_in_the_step_that_learns_it(self):
        self.assertGreater(self.service.step()["serve_until_boottime_ms"], 0)
        for state in ("QUARANTINED", "RETIRED", "REVOKED_STOLEN", "MAINTENANCE"):
            with self.subTest(state=state):
                self.manifest_now = self.manifest(2, m.digest(self.m1), a=state)          # the revoking manifest arrives
                document = self.service.step()
                self.assertEqual((document["serve_until_boottime_ms"], document["epoch"]), (0, 2))
                self.assertIn("a may not serve under epoch 2 (%s)" % state, document["reason"])
                self.assertEqual(document, self.on_disk())

    def test_every_refusal_of_the_check_is_zero_with_its_reason(self):
        self.service.step()
        for label, reason, break_it, mend_it in (
                ("unauthenticated time", "time is not authenticated", lambda: setattr(self, "authenticated", False), lambda: setattr(self, "authenticated", True)),
                ("the clock set back", "the clock went backwards", lambda: setattr(self, "now", self.now - 3600), lambda: setattr(self, "now", self.now + 3600)),
                ("no manifest", "this node holds no manifest", lambda: setattr(self, "manifest_now", None), lambda: setattr(self, "manifest_now", self.m1))):
            with self.subTest(label):
                break_it()
                document = self.service.step()
                self.assertEqual(document["serve_until_boottime_ms"], 0)
                self.assertIn(reason, document["reason"])
                mend_it()
                self.assertGreater(self.service.step()["serve_until_boottime_ms"], 0)

        def rolled_back():
            raise m.Refused("ROLLBACK: the membership on disk is epoch 1 but the TPM high-water is 2")
        self.service.manifest = rolled_back
        document = self.service.step()
        self.assertEqual((document["serve_until_boottime_ms"], document["epoch"], document["manifest_digest"]), (0, 0, "00" * 32))
        self.assertIn("ROLLBACK", document["reason"])

    def test_a_reason_is_printable_and_bounded(self):
        self.manifest_now = None
        self.service.manifest = lambda: (_ for _ in ()).throw(m.Refused("bad\x00\n\x1b[31m" + "x" * 500))
        reason = self.service.step()["reason"]
        self.assertEqual(reason, "bad???[31m" + "x" * 500)

    def test_the_longest_document_fits_what_the_daemon_reads(self):
        """internal/admission refuses a file above maxFileBytes (4096) as oversized, which would hide the reason:
        the reason is cut at ADMISSION_REASON_LIMIT, and the document with every field at its largest fits."""
        self.manifest_now = None
        self.service.manifest = lambda: (_ for _ in ()).throw(m.Refused("y" * 10000))
        self.assertEqual(len(self.service.step()["reason"]), admission.ADMISSION_REASON_LIMIT)
        widest = {"schema": admission.SCHEMA, "node_id": "n" * 32, "session_id": "f" * 64, "boot_id": "b" * 36,
                  "epoch": 2 ** 63 - 1, "manifest_digest": "d" * 64, "lease_issued_at": "9999-12-31T23:59:59Z",
                  "requested_boottime_ms": 2 ** 63 - 1, "serve_until_boottime_ms": 2 ** 63 - 1,
                  "reason": "\\" * admission.ADMISSION_REASON_LIMIT}            # every character escaped: the worst case
        self.assertEqual(set(widest), set(self.service.step()))                     # the same fields the service writes
        self.assertLessEqual(len(json.dumps(widest).encode()) + 1, 4096)

    def test_if_the_service_stops_the_file_runs_out_by_itself(self):
        document = self.service.step()
        self.later(lease.MAX_LIFETIME)                    # nobody writes again
        self.assertEqual(self.on_disk(), document)
        self.assertLess(self.on_disk()["serve_until_boottime_ms"], self.ticks)            # the daemon's own clock is past it
        self.assertEqual(self.ticks - self.on_disk()["serve_until_boottime_ms"], admission.MARGIN * 1000)

    def test_a_restarted_service_still_knows_when_the_held_lease_was_asked_for(self):
        first = self.service.step()
        self.later(20)
        again = self.new_service().step()
        self.assertEqual(again["requested_boottime_ms"], first["requested_boottime_ms"])
        for _ in range(admission.MAX_REQUESTS + 5):       # the record of requests is bounded: the newest are kept
            self.service._remember(os.urandom(32).hex(), self.ticks)
            self.later(1)
        with open(self.path + ".requests") as f:
            kept = json.load(f)
        self.assertEqual(len(kept), admission.MAX_REQUESTS)
        self.assertEqual(max(kept.values()), self.ticks - 1000)
        os.unlink(self.path + ".requests")                # lost: it says so with 0, and does not invent a time
        self.assertEqual(self.new_service().step()["requested_boottime_ms"], 0)
        with open(self.path + ".requests", "w") as f:
            f.write("[")
        self.assertEqual(self.new_service().step()["requested_boottime_ms"], 0)

    def test_run_writes_zero_before_it_passes_on_an_error_that_is_not_a_refusal(self):
        self.service.step()
        rounds = []

        def stop():
            rounds.append(1)
            return len(rounds) > 2
        with unittest.mock.patch.object(admission.time, "sleep"):
            self.service.run(stop)
        self.assertGreater(self.on_disk()["serve_until_boottime_ms"], 0)
        with unittest.mock.patch.object(self.service, "step", side_effect=OSError("the TPM is gone")):
            with self.assertRaises(OSError):
                self.service.run(lambda: False)
        self.assertEqual(self.on_disk()["serve_until_boottime_ms"], 0)
        self.assertIn("the lease service failed: the TPM is gone", self.on_disk()["reason"])

    def test_the_write_is_whole_or_not_at_all(self):
        document = self.service.step()
        with unittest.mock.patch.object(admission.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                admission.write(self.path, dict(document, serve_until_boottime_ms=0))
        self.assertEqual(self.on_disk(), document)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".admission-")], [])
        self.refused("an admission document has exactly its fields, in order", admission.write, self.path, {"schema": admission.SCHEMA})

    def test_the_kernel_boot_id_and_the_command_line(self):
        self.assertRegex(admission.boot_id(), r"^[0-9a-f-]{36}$")
        bad = os.path.join(self.d, "boot_id")
        with open(bad, "w") as f:
            f.write("not-a-uuid\n")
        self.refused("the kernel boot ID is not a UUID", admission.boot_id, bad)
        self.assertGreater(admission.boottime_ms(), 0)
        self.service.step()
        with unittest.mock.patch.object(admission, "boottime_ms", return_value=self.ticks), unittest.mock.patch("builtins.print") as shown:
            self.assertEqual(admission.main([self.path]), 0)
            self.assertIn("admitted for 290 more seconds", shown.call_args[0][0])
        with unittest.mock.patch.object(admission, "boottime_ms", return_value=self.ticks + 10 ** 9), unittest.mock.patch("builtins.print") as shown:
            self.assertEqual(admission.main([self.path]), 1)
            self.assertIn("NOT ADMITTED: the lease ran out", shown.call_args[0][0])
        with unittest.mock.patch("builtins.print"):
            self.assertEqual(admission.main([os.path.join(self.d, "absent.json")]), 1)

    def test_held_returns_a_copy_of_the_lease(self):
        self.assertIsNone(self.holder.held())
        self.service.step()
        held = self.holder.held()
        self.assertEqual(held["lease"]["node_id"], "a")
        held["lease"]["node_id"] = "z"
        self.assertEqual(self.holder.held()["lease"]["node_id"], "a")


class DaemonStart(Case):
    """The daemon serves only under a lease asked for after its own process started (#72). The service
    sees that start and asks at once, not at the next scheduled renewal."""

    def setUp(self):
        super().setUp()
        self.started = None
        self.service = admission.Service(self.holder, lambda: self.manifest_now, self.renew, self.path,
                                         boottime=lambda: self.ticks, boot=lambda: BOOT, daemon_started=lambda: self.started)

    def test_a_daemon_that_started_after_the_lease_was_asked_for_gets_a_new_one_at_once(self):
        first = self.service.step()
        self.later(5)                                   # far from a third of the lease
        self.assertEqual(self.service.step()["requested_boottime_ms"], first["requested_boottime_ms"])   # no daemon known: the schedule
        self.started = first["requested_boottime_ms"] - 1
        self.assertEqual(self.service.step()["requested_boottime_ms"], first["requested_boottime_ms"])   # it started before: the lease serves it
        self.started = self.ticks - 2000                # the daemon restarted two seconds ago
        renewed = self.service.step()
        self.assertEqual(renewed["requested_boottime_ms"], self.ticks)
        self.assertGreater(renewed["requested_boottime_ms"], self.started)
        self.assertGreater(renewed["serve_until_boottime_ms"], first["serve_until_boottime_ms"])
        self.later(5)
        self.assertEqual(self.service.step()["requested_boottime_ms"], renewed["requested_boottime_ms"])  # once, not at every step

    def test_a_renewal_in_the_same_second_as_the_held_lease_still_takes_effect(self):
        """Both leases then expire together. The one just asked for must win the tie, or the daemon would go
        on waiting with the service believing it had answered."""
        first = self.service.step()
        self.ticks += 700                               # the boot clock moved; authenticated time, in seconds, did not
        self.started = self.ticks - 100
        renewed = self.service.step()
        self.assertEqual(renewed["requested_boottime_ms"], self.ticks)
        self.assertEqual(renewed["serve_until_boottime_ms"] - first["serve_until_boottime_ms"], 700)   # the same expiry, read 700 ms later
        self.ticks += 5000
        self.assertEqual(self.service.step()["requested_boottime_ms"], renewed["requested_boottime_ms"])

    def test_a_renewal_for_the_daemon_is_held_even_if_it_has_less_life_than_the_lease_held(self):
        """Found by an independent read. The issuer dates a lease by ITS clock and cuts it at ITS heartbeat's
        expiry, so the lease asked for after the daemon started can end before the one held. Keeping the
        longer one left the daemon refusing every token, and the service asking again every round."""
        first = self.service.step()

        def shorter(request):
            body = dict(self.issue("c", manifest=self.manifest_now, request=request)["lease"], expires_at=hbt.stamp(self.now + lease.MAX_LIFETIME - 5))
            return lt.sign(body, self.keys["c"])
        self.service.renew = shorter
        self.later(1)
        self.started = self.ticks - 500
        renewed = self.service.step()
        self.assertEqual(renewed["requested_boottime_ms"], self.ticks)                        # the new lease is the one held
        self.assertEqual(renewed["serve_until_boottime_ms"] - first["serve_until_boottime_ms"], -5000 + 1000)   # 5 s shorter, read 1 s later
        self.assertEqual(self.holder.held()["lease"]["issuer"], "c")
        self.later(5)
        self.assertEqual(self.service.step()["requested_boottime_ms"], renewed["requested_boottime_ms"])   # and it is not asked for again
        # on the schedule, with no daemon waiting, the longer lease is still the one kept
        self.later(lease.MAX_LIFETIME // 3 + 5)

        def much_shorter(request):
            body = dict(self.issue("b", manifest=self.manifest_now, request=request)["lease"], expires_at=hbt.stamp(self.now + 20))
            return lt.sign(body, self.keys["b"])
        self.service.renew = much_shorter
        kept = self.service.step()
        self.assertEqual((kept["requested_boottime_ms"], self.holder.held()["lease"]["issuer"]), (renewed["requested_boottime_ms"], "c"))

    def test_a_preferred_lease_inside_the_margin_costs_one_round_and_heals_at_the_next(self):
        first = self.service.step()

        def nearly_over(request):
            body = dict(self.issue("c", manifest=self.manifest_now, request=request)["lease"], expires_at=hbt.stamp(self.now + admission.MARGIN))
            return lt.sign(body, self.keys["c"])
        good, self.service.renew = self.service.renew, nearly_over
        self.later(1)
        self.started = self.ticks - 500
        inside = self.service.step()
        self.assertEqual(inside["serve_until_boottime_ms"], 0)
        self.assertIn("inside the 10 s margin", inside["reason"])
        self.service.renew = good
        self.later(5)
        healed = self.service.step()                                    # the schedule asks again: the held lease is nearly over
        self.assertGreater(healed["serve_until_boottime_ms"], first["serve_until_boottime_ms"])
        self.assertGreater(healed["requested_boottime_ms"], self.started)

    def test_a_lease_asked_for_at_the_very_tick_the_daemon_started_is_not_after_it(self):
        first = self.service.step()
        self.started = first["requested_boottime_ms"]
        self.later(1)
        self.assertEqual(self.service.step()["requested_boottime_ms"], self.ticks)

    def test_while_the_peer_is_down_it_keeps_asking_and_keeps_what_it_holds(self):
        first = self.service.step()
        self.later(5)
        self.started, self.peer_up = self.ticks - 1000, False
        kept = self.service.step()
        self.assertEqual((kept["requested_boottime_ms"], kept["serve_until_boottime_ms"]),
                         (first["requested_boottime_ms"], first["serve_until_boottime_ms"]))
        self.later(5)
        self.peer_up = True
        self.assertEqual(self.service.step()["requested_boottime_ms"], self.ticks)

    def test_a_lost_request_record_counts_as_asked_before(self):
        self.service.step()
        os.unlink(self.path + ".requests")
        self.later(5)
        self.started = 1                                # long ago, yet nothing shows the lease was asked for since
        self.assertEqual(self.service.step()["requested_boottime_ms"], self.ticks)

    def test_the_start_of_a_systemd_unit_is_read_from_the_kernel(self):
        proc = os.path.join(self.d, "proc")
        os.makedirs(os.path.join(proc, "4242"))
        tail = " S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 123456 20 21\n"
        calls = []

        def systemctl(pid=b"4242\n", code=0):
            def run(argv, **kw):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, code, pid, b"")
            return run
        for name in ("(regalia-kms)", "(a b)", "(evil) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 20)"):
            with open(os.path.join(proc, "4242", "stat"), "w") as f:
                f.write("4242 " + name + tail)
            self.assertEqual(admission.unit_started(run=systemctl(), proc=proc)(), 1234570)
        self.assertEqual(calls[0], ["systemctl", "show", "--property=MainPID", "--value", "regalia-kms.service"])
        self.assertEqual(admission.process_started_ms(4242, proc), 1234570)
        # nothing to read is "unknown", never an error that stops the lease service and never a time
        for label, run in (("the unit has no main process", systemctl(b"0\n")), ("systemctl failed", systemctl(code=1)),
                           ("not a PID", systemctl(b"4242; rm\n")), ("the process is gone", systemctl(b"4243\n"))):
            with self.subTest(label):
                self.assertIsNone(admission.unit_started(run=run, proc=proc)())

        def missing(argv, **kw):
            raise FileNotFoundError("systemctl")

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 10)
        self.assertIsNone(admission.unit_started(run=missing, proc=proc)())
        self.assertIsNone(admission.unit_started(run=slow, proc=proc)())
        for label, stat in (("no command name", "4242 regalia-kms S 1 2"), ("too short", "4242 (x) S 1 2 3"),
                            ("not a number", "4242 (x)" + tail.replace("123456", "soon")), ("zero", "4242 (x)" + tail.replace("123456", "0")),
                            ("negative", "4242 (x)" + tail.replace("123456", "-5")), ("empty", "")):
            with self.subTest(label):
                with open(os.path.join(proc, "4242", "stat"), "w") as f:
                    f.write(stat)
                self.refused("the process start time cannot be read", admission.process_started_ms, 4242, proc)
                self.assertIsNone(admission.unit_started(run=systemctl(), proc=proc)())

    def test_this_process_s_start_is_on_the_boot_clock_and_matches_what_the_daemon_would_read(self):
        started = admission.process_started_ms(os.getpid())
        self.assertTrue(0 < started <= admission.boottime_ms())
        self.assertEqual(started % 10, 0)
        self.assertEqual(admission.process_started_ms(os.getpid()), started)

    def test_another_clock_tick_is_refused_rather_than_disagreed_with(self):
        with mock.patch.object(os, "sysconf", lambda name: 250):
            self.refused("the kernel clock tick is not 100 Hz", admission.process_started_ms, os.getpid())
            self.assertIsNone(admission.unit_started(run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"%d\n" % os.getpid(), b""))())


if __name__ == "__main__":
    unittest.main()


class Renewals(unittest.TestCase):
    """#340: node.admission_service records each renewal attempt on the node's own trail: ALLOW names the issuing peer,
    DENY carries its refusal, and a last DENY when no peer gave a lease. A lease whose record fails is not used."""

    def service(self, answers, broken=False):
        from deploy.baremetal import node, sync
        self.trail = []

        class Trail:
            def __init__(inner, path, trail):
                pass

            def __call__(inner, event):
                if broken and event.get("outcome") == "ALLOW":
                    raise OSError("the trail is not writable")
                self.trail.append(event)

        class Client:
            def __init__(inner, node_id, manifest, freshness, sources, sink):
                pass

            def renewer(inner, name, quote):
                def renew(request):
                    if isinstance(answers[name], Exception):
                        raise answers[name]
                    return answers[name]
                return renew
        manifest = {"epoch": 3, "nodes": []}
        fake = unittest.mock.Mock(node_id="a", runtime="/run/regalia", run=None)
        fake.manifest.return_value = manifest
        fake.sources.return_value = {"b": None, "c": None}
        for patcher in (mock.patch.object(node, "boot_session", return_value=("ab" * 32, b"pub")), mock.patch.object(node, "Trail", Trail),
                        mock.patch.object(sync, "Client", Client), mock.patch.object(node.membership, "digest", return_value="d" * 64),
                        mock.patch.object(node.lease, "Holder")):
            patcher.start()                           # for the test's whole length: renew() runs after the service is built
            self.addCleanup(patcher.stop)
        return node.admission_service(fake, daemon_started=lambda: None)

    def test_a_refusal_then_an_answer(self):
        service = self.service({"b": m.Refused("b: a is REVOKED_STOLEN under epoch 3"), "c": {"lease": "envelope"}})
        self.assertEqual(service.renew({"nonce": "n"}), {"lease": "envelope"})
        self.assertEqual([(e["event"], e["peer"], e["outcome"]) for e in self.trail], [("admission-renew", "b", "DENY"), ("admission-renew", "c", "ALLOW")])
        self.assertIn("REVOKED_STOLEN", self.trail[0]["reason"])
        self.assertEqual((self.trail[1]["subject"], self.trail[1]["epoch"]), ("a", 3))

    def test_no_peer_gave_a_lease(self):
        service = self.service({"b": m.Refused("b refused"), "c": m.Refused("c did not answer")})
        with self.assertRaises(m.Refused):
            service.renew({"nonce": "n"})
        self.assertEqual([(e["peer"], e["outcome"]) for e in self.trail], [("b", "DENY"), ("c", "DENY"), ("", "DENY")])
        self.assertIn("no peer gave a lease (2 asked: b: b refused; c: c did not answer)", self.trail[-1]["reason"])

    def test_a_cut_off_node_writes_tens_of_lines_not_hundreds_and_says_how_often(self):
        """48 on #347: ten minutes cut off at the 5 s step, with the service's back-off: the first refusal of each kind
        whole, then one count line at most a minute; a peer back writes what is still counted, then its ALLOW."""
        from deploy.baremetal import node
        clock = [0.0]
        service = self.service({"b": m.Refused("b did not answer (TimeoutError)"), "c": m.Refused("c did not answer (TimeoutError)")})
        quiet = [c.cell_contents for c in service.renew.__closure__ if isinstance(c.cell_contents, node.QuietRefusals)][0]
        quiet.clock = lambda: clock[0]
        attempts, wait, at = 0, 0, 0.0
        while clock[0] < 600:                                  # the service's cadence: 5 s, doubling to 60 s while failing
            if clock[0] >= at:
                attempts += 1
                with self.assertRaises(m.Refused):
                    service.renew({"nonce": "n"})
                wait = min(max(wait * 2, admission.RETRY_FIRST), admission.RETRY_MAX)
                at = clock[0] + wait
            clock[0] += 5
        self.assertLessEqual(len(self.trail), 15)              # not 3 a step: about 360 lines
        firsts = [e for e in self.trail if "repeated" not in e]
        counts = [e for e in self.trail if "repeated" in e]
        self.assertEqual([(e["peer"], e["outcome"]) for e in firsts], [("b", "DENY"), ("c", "DENY"), ("", "DENY")])
        self.assertTrue(counts and all(e["outcome"] == "DENY" for e in counts))
        # every refusal is on the trail, whole or counted: 3 lines an attempt, less what is still counted (at most 3 * 1 attempt)
        self.assertGreaterEqual(sum(e["repeated"] for e in counts) + 3, 3 * attempts - 3)
        self.assertLessEqual(sum(e["repeated"] for e in counts) + 3, 3 * attempts)
        self.assertIn("b x", counts[0]["reason"])
        self.assertIn("no peer gave a lease x", counts[0]["reason"])

    def test_a_success_writes_what_is_still_counted_then_itself(self):
        from deploy.baremetal import node
        answers = {"b": m.Refused("b refused: epoch 4 is not current"), "c": m.Refused("c refused: epoch 5 is not current")}
        service = self.service(answers)
        quiet = [c.cell_contents for c in service.renew.__closure__ if isinstance(c.cell_contents, node.QuietRefusals)][0]
        quiet.clock = lambda: 0.0                                # never a minute: only the success flushes
        for _ in range(3):
            with self.assertRaises(m.Refused):
                service.renew({"nonce": "n"})
        self.assertEqual(len(self.trail), 3)                     # epochs differ only in their numbers: one kind per peer
        answers["c"] = {"lease": "envelope"}
        service.renew({"nonce": "n"})
        self.assertEqual([(e["peer"], e["outcome"], e.get("repeated")) for e in self.trail[3:]], [("", "DENY", 6), ("c", "ALLOW", None)])   # rounds 2 and 3: 3 each; round 4 asks c first (the rotation)
        answers["c"] = m.Refused("c refused: epoch 6 is not current")
        with self.assertRaises(m.Refused):
            service.renew({"nonce": "n"})
        self.assertEqual(self.trail[-1]["peer"], "")             # news again after the success: written whole
        self.assertNotIn("repeated", self.trail[-1])

    def test_a_lease_whose_record_fails_is_not_used(self):
        service = self.service({"b": {"lease": "envelope"}, "c": {"lease": "envelope"}}, broken=True)
        with self.assertRaises(OSError):
            service.renew({"nonce": "n"})

