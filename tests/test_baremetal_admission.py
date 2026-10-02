"""deploy/baremetal/admission.py (#74): the root service that keeps the node's runtime lease and writes the
one file the Go daemon reads. Refused means serve_until 0 in the same step; a failed renewal leaves what
the lease still gives; the file runs out by itself if the service stops."""
import json
import os
import unittest
import unittest.mock

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


if __name__ == "__main__":
    unittest.main()
