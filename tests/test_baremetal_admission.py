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
        self.peer_up = True                                                               # the peer is back: admitted again
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
        self.assertEqual(reason, "bad???[31m" + "x" * 230)

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
