"""deploy/baremetal/heartbeat_watch.py and the manifest's heartbeat bound (#69): a v2 manifest sets how
long a heartbeat may live; the watch says how much is left and warns while it runs out."""
import json
import os
import stat
import unittest

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import heartbeat_watch as watch
from deploy.baremetal import membership as m
from tests import test_baremetal_heartbeat as hbt

T0, beat, stamp = hbt.T0, hbt.beat, hbt.stamp
HOUR, DAY = 3600, 24 * 3600


def manifest2(life, epoch=1, prev="", **states):
    """hbt.manifest under schema v2: each node with an SSH host key, and the heartbeat bound `life`."""
    v1 = hbt.manifest(epoch, prev, **states)
    nodes = [dict(entry, ssh_host_pub=("%02x" % (0xd0 + i)) * 32) for i, entry in enumerate(v1["nodes"])]
    return dict(v1, schema=m.SCHEMA_V2, heartbeat_max_lifetime_s=life, nodes=nodes)


class Bound(hbt.Case):
    def test_a_v1_manifest_keeps_24_hours_and_a_v2_manifest_states_its_own(self):
        self.assertEqual(hb.max_lifetime(self.m1), DAY)
        for life in (m.HEARTBEAT_MIN_S, 12 * HOUR, DAY, 3 * DAY, m.HEARTBEAT_HARD_MAX_S):
            self.assertEqual(hb.max_lifetime(manifest2(life)), life)
        # the constant here holds even against a manifest that membership would not have let through
        self.assertEqual(hb.max_lifetime(dict(manifest2(DAY), heartbeat_max_lifetime_s=30 * DAY)), 7 * DAY)
        self.assertEqual(hb.HARD_MAX_LIFETIME, 7 * DAY)

    def test_a_heartbeat_longer_than_the_manifest_allows_is_refused_whoever_signed_it(self):
        for life in (HOUR, 12 * HOUR, 3 * DAY):
            with self.subTest(life=life):
                man = manifest2(life)
                self.refused("at most %d s under the current manifest (this one: %d s)" % (life, life + 1),
                             self.f.accept, beat(man, 1, lifetime=life + 1), man)
                self.assertEqual(self.counter.value(), 0)
        man = manifest2(7 * DAY)
        self.refused("at most 604800 s under any manifest", self.f.accept, beat(man, 1, lifetime=7 * DAY + 1), man)
        # under v1 the bound is the old one, with or without a longer heartbeat on offer
        self.refused("at most 86400 s under the current manifest (this one: 86401 s)", self.f.accept, beat(self.m1, 1, lifetime=DAY + 1), self.m1)
        self.refused("at most 86400 s under the current manifest", self.f.accept, beat(self.m1, 1, lifetime=3 * DAY), self.m1)

    def test_a_heartbeat_at_the_bound_is_accepted_and_lives_that_long(self):
        for life in (HOUR, 3 * DAY, 7 * DAY):
            with self.subTest(life=life):
                self.setUp()
                man = manifest2(life)
                self.assertEqual(self.f.accept(beat(man, 1, lifetime=life), man), life - 60)
                self.later(life - 61)
                self.assertEqual(hb.authorize(man, "b", "a", self.f), 1)
                self.later(1)
                self.refused("EXPIRED", hb.authorize, man, "b", "a", self.f)

    def test_a_shorter_heartbeat_than_the_bound_is_fine(self):
        man = manifest2(3 * DAY)
        self.assertEqual(self.f.accept(beat(man, 1, lifetime=HOUR), man), HOUR - 60)

    def test_a_heartbeat_held_from_before_does_not_outlive_a_manifest_that_shortens_the_bound(self):
        """The bound is the CURRENT manifest's. A new manifest is a new epoch and digest, so the old
        heartbeat is void anyway; and one for the new manifest is held to the new bound."""
        long = manifest2(3 * DAY)
        self.f.accept(beat(long, 1, lifetime=3 * DAY), long)
        short = manifest2(HOUR, 2, m.digest(long))
        self.refused("the heartbeat is for epoch 1, the current manifest is epoch 2", self.f.check, short)
        self.refused("at most 3600 s under the current manifest", self.f.accept, beat(short, 2, lifetime=3 * DAY), short)
        self.assertEqual(self.f.accept(beat(short, 2, issued=self.now, lifetime=HOUR), short), HOUR)

    def test_a_planted_long_heartbeat_on_disk_is_refused_at_check_too(self):
        man = manifest2(HOUR)
        with open(self.state, "w") as f:
            json.dump({"envelope": beat(man, 1, lifetime=2 * HOUR), "floor": None}, f)
        self.refused("at most 3600 s under the current manifest", self.f.check, man)
        self.assertEqual(self.counter.value(), 0)

    def test_window_gives_what_a_monitor_needs(self):
        man = manifest2(3 * DAY)
        self.f.accept(beat(man, 4, issued=T0, lifetime=2 * DAY), man)
        self.later(500)
        self.assertEqual(self.f.window(man), (self.now, T0, T0 + 2 * DAY, 4))
        self.assertEqual(self.f.live_until(man), (self.now, T0 + 2 * DAY))
        self.authenticated = False
        self.refused("time is not authenticated", self.f.window, man)


class Watching(hbt.Case):
    def setUp(self):
        super().setUp()
        self.man = manifest2(DAY)
        self.events, self.held = [], self.man
        self.prom, self.wstate = os.path.join(self.d, "regalia_heartbeat.prom"), os.path.join(self.d, "watch.json")
        self.w = self.watch()
        self.f.accept(beat(self.man, 1, issued=self.now, lifetime=DAY), self.man)

    def watch(self, **kw):
        return watch.Watch(self.f, lambda: self.held, self.events.append, self.prom, self.wstate, clock=lambda: self.now, **kw)

    def left(self, seconds, lifetime=DAY):
        """Move to the moment the heartbeat issued at the start has `seconds` left."""
        self.later(lifetime - seconds - (self.now - self.issued))

    issued = T0 + 60

    def kinds(self):
        seen = [(e["severity"], e["kind"], e["threshold_percent"]) for e in self.events]
        del self.events[:]
        return seen

    def gauges(self):
        with open(self.prom) as f:
            lines = [line.split() for line in f if not line.startswith("#")]
        return {name: int(value) for name, value in lines}

    def test_the_metrics_say_what_is_left(self):
        self.later(HOUR)
        got = self.w.step()
        self.assertEqual((got["live"], got["seconds_left"], got["lifetime"], got["max_lifetime"], got["sequence"], got["epoch"]),
                         (True, 23 * HOUR, DAY, DAY, 1, 1))
        self.assertEqual(self.gauges(), {"regalia_heartbeat_seconds_left": 23 * HOUR, "regalia_heartbeat_live": 1,
                                         "regalia_heartbeat_lifetime_seconds": DAY, "regalia_heartbeat_max_lifetime_seconds": DAY,
                                         "regalia_heartbeat_checked_timestamp_seconds": self.now})
        with open(self.prom) as f:
            text = f.read()
        self.assertIn("# TYPE regalia_heartbeat_seconds_left gauge\nregalia_heartbeat_seconds_left 82800\n", text)
        self.assertEqual(text.count("# HELP "), 5)
        self.assertEqual(stat.S_IMODE(os.stat(self.prom).st_mode), 0o640)       # node_exporter reads it through its directory's group (#305)
        self.assertEqual(stat.S_IMODE(os.stat(self.wstate).st_mode), 0o600)
        self.assertEqual(sorted(os.listdir(self.d)), sorted(set(os.listdir(self.d)) - {n for n in os.listdir(self.d) if n.startswith(".heartbeat-watch-")}))
        self.assertEqual(self.kinds(), [])

    def test_it_warns_once_at_50_25_and_10_percent_then_every_hour(self):
        self.w.step()
        self.left(12 * HOUR + 1)
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # just above half
        self.left(12 * HOUR)
        self.w.step()
        event = self.events[0]
        self.assertEqual((event["event"], event["epoch"], event["manifest_digest"], event["sequence"], event["seconds_left"],
                          event["lifetime_s"], event["max_lifetime_s"], event["reason"]),
                         ("heartbeat-freshness", 1, m.digest(self.man), 1, 12 * HOUR, DAY, DAY, ""))
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])
        for _ in range(3):                                                       # hours pass: 50 % is said once
            self.later(HOUR)
            self.w.step()
        self.assertEqual(self.kinds(), [])
        self.left(6 * HOUR)
        self.w.step()
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 25)])
        self.later(2 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # 25 % is said once too
        self.left(8640)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 10)])
        self.later(HOUR - 1)
        self.w.step()
        self.assertEqual(self.kinds(), [])
        self.later(1)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 10)])           # hourly from 10 %
        self.later(HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 10)])

    def test_expiry_is_an_error_at_once_and_every_hour_and_renewal_is_said(self):
        self.left(8640)
        self.w.step()
        self.kinds()
        self.left(0)
        got = self.w.step()
        self.assertEqual((got["live"], got["seconds_left"]), (False, 0))
        self.assertIn("EXPIRED", self.events[0]["reason"])
        self.assertEqual(self.kinds(), [("ERROR", "EXPIRED", 0)])               # at once, not an hour after the last warning
        self.assertEqual((self.gauges()["regalia_heartbeat_seconds_left"], self.gauges()["regalia_heartbeat_live"],
                          self.gauges()["regalia_heartbeat_max_lifetime_seconds"]), (0, 0, DAY))
        self.later(HOUR - 1)
        self.w.step()
        self.assertEqual(self.kinds(), [])
        self.later(1)
        self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "EXPIRED", 0)])
        self.f.accept(beat(self.man, 2, issued=self.now, lifetime=DAY), self.man)
        self.w.step()
        self.w.step()
        self.assertEqual(self.kinds(), [("INFO", "RENEWED", 0)])
        self.assertEqual(self.gauges()["regalia_heartbeat_live"], 1)

    def test_a_newer_heartbeat_starts_the_thresholds_again(self):
        self.left(6 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 25)])           # first seen below two thresholds: the lower, once
        self.f.accept(beat(self.man, 2, issued=self.now, lifetime=DAY), self.man)
        self.w.step()
        self.assertEqual(self.kinds(), [("INFO", "RENEWED", 0)])
        self.later(12 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])           # of the new one
        # a renewal that arrives already half used is a warning, not a "renewed"
        self.f.accept(beat(self.man, 3, issued=self.now - 13 * HOUR, lifetime=DAY), self.man)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])

    def test_a_healthy_peer_says_nothing(self):
        for sequence in range(2, 6):
            self.later(HOUR)
            self.f.accept(beat(self.man, sequence, issued=self.now, lifetime=DAY), self.man)
            self.w.step()
        self.assertEqual(self.kinds(), [])

    def test_an_authority_that_renews_at_one_third_used_never_warns(self):
        """The condition the thresholds assume: a renewal before half of a heartbeat is used. Across restarts
        of the watcher too."""
        for sequence in range(2, 12):
            self.later(8 * HOUR - 1)
            self.watch().step()                                                  # just before the renewal: two thirds left
            self.later(1)
            self.f.accept(beat(self.man, sequence, issued=self.now, lifetime=DAY), self.man)
            self.watch().step()
        self.assertEqual(self.kinds(), [])
        # and one that renews only after half is used warns in every cycle: the setting to change is the authority's
        self.later(12 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])

    def test_the_hourly_repeat_survives_a_restart_of_the_watcher(self):
        """Every step here is a new process: neither quiet for an hour after a restart, nor a warning at each."""
        self.left(8640)
        self.watch().step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 10)])
        for _ in range(5):
            self.later(600)
            self.watch().step()
        self.assertEqual(self.kinds(), [])                                       # 50 minutes: nothing
        self.later(600)
        self.watch().step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 10)])           # the hour
        self.left(0)
        self.watch().step()
        self.assertEqual(self.kinds(), [("ERROR", "EXPIRED", 0)])
        for _ in range(5):
            self.later(600)
            self.watch().step()
        self.assertEqual(self.kinds(), [])
        self.later(600)
        self.watch().step()
        self.assertEqual(self.kinds(), [("ERROR", "EXPIRED", 0)])
        with open(self.wstate) as f:
            state = json.load(f)
        self.assertEqual({k: state[k] for k in ("sequence", "level", "down", "announced", "errors")},
                         {"sequence": 1, "level": 10, "down": True, "announced": True, "errors": {"EXPIRED": self.now}})
        self.assertEqual(sorted(state), sorted(watch.STATE_KEYS))

    def test_the_fraction_is_of_the_heartbeat_s_own_lifetime(self):
        """12-hour heartbeats under a 24-hour bound are not at "50 % left" on arrival."""
        self.f.accept(beat(self.man, 2, issued=self.now, lifetime=12 * HOUR), self.man)
        self.w.step()
        self.assertEqual(self.kinds(), [])
        self.assertEqual((self.gauges()["regalia_heartbeat_lifetime_seconds"], self.gauges()["regalia_heartbeat_max_lifetime_seconds"]),
                         (12 * HOUR, DAY))
        self.later(6 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])

    def test_anything_that_stops_the_peer_authorizing_is_an_error_with_its_reason(self):
        self.w.step()
        self.authenticated = False
        self.w.step()
        self.assertIn("time is not authenticated", self.events[0]["reason"])
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])
        self.assertEqual(self.gauges()["regalia_heartbeat_live"], 0)
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # not at every step
        self.authenticated = True
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # usable again for one step: not said yet
        self.w.step()
        self.assertEqual(self.kinds(), [("INFO", "RECOVERED", 0)])                # for two: said. The same heartbeat: nothing was renewed
        # the manifest moved on and no heartbeat for it has arrived
        self.held = manifest2(DAY, 2, m.digest(self.man), a="REVOKED_STOLEN")
        self.later(HOUR)
        self.w.step()
        self.assertIn("the heartbeat is for epoch 1", self.events[0]["reason"])
        self.assertEqual((self.events[0]["epoch"], self.events[0]["manifest_digest"]), (2, m.digest(self.held)))
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])
        # no manifest at all, and a store that refuses
        self.held = None
        self.later(HOUR)
        self.w.step()
        self.assertEqual((self.events[0]["reason"], self.events[0]["epoch"]), ("no manifest is held", 0))
        self.assertEqual(self.gauges()["regalia_heartbeat_max_lifetime_seconds"], 0)
        self.kinds()

        def broken():
            raise m.Refused("the chain does not verify")
        refusing = watch.Watch(self.f, broken, self.events.append, self.prom, self.wstate, clock=lambda: self.now)
        self.later(HOUR)
        self.assertEqual(refusing.step()["reason"], "no manifest is held")
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])

    def test_a_peer_that_never_had_a_heartbeat_is_an_error_from_the_first_step(self):
        os.unlink(self.state)
        self.w.step()
        self.assertIn("no heartbeat is held", self.events[0]["reason"])
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])

    def test_what_was_warned_survives_a_restart_and_a_damaged_state_costs_one_repeat(self):
        self.left(12 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])
        good = {"sequence": 1, "level": 50, "last": self.now, "down": False, "announced": False, "recovering": False, "errors": {}}
        with open(self.wstate) as f:
            self.assertEqual(json.load(f), good)
        self.watch().step()                                                      # a new process
        self.assertEqual(self.kinds(), [])

        def state(**change):
            return json.dumps(dict(good, **change)).encode()
        for damage in (b"", b"{", b" " * (watch.MAX_BYTES + 1), b'{"key": 1, "level": 50, "last": 1}',      # the previous format
                       json.dumps({k: v for k, v in good.items() if k != "errors"}).encode(), state(more=1),
                       state(sequence=-1), state(sequence=True), state(sequence="1"), state(level=49), state(level=True), state(last=1.5),
                       state(last=True), state(down=1), state(announced="no"), state(recovering=0), state(recovering=None), state(errors=[]), state(errors={"OTHER": 1}),
                       state(errors={"EXPIRED": None}), state(errors={"EXPIRED": True}), state(errors={"UNUSABLE": "soon"})):
            with self.subTest(damage=damage[:40]):
                with open(self.wstate, "wb") as f:
                    f.write(damage)
                self.watch().step()
                self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])
                self.watch().step()
                self.assertEqual(self.kinds(), [])

    def test_a_warning_the_sink_could_not_take_is_due_again(self):
        def failing(event):
            raise OSError("the journal is full")
        self.left(12 * HOUR)
        broken = watch.Watch(self.f, lambda: self.held, failing, self.prom, self.wstate, clock=lambda: self.now)
        with self.assertRaises(OSError):
            broken.step()
        self.assertEqual(self.gauges()["regalia_heartbeat_seconds_left"], 12 * HOUR)   # the metric was written first
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])

    def test_a_clock_set_back_repeats_rather_than_going_quiet(self):
        live = {"live": True, "sequence": 1, "seconds_left": 8000, "lifetime": DAY, "max_lifetime": DAY, "epoch": 1,
                "manifest_digest": "", "reason": ""}
        ahead = self.now + 10 ** 6
        state = watch.decide(live, {"sequence": 1, "level": 10, "last": ahead}, self.now)
        self.assertEqual((state[0]["kind"], state[1]["last"]), ("RUNNING_OUT", self.now))
        down = dict(live, live=False, seconds_left=0, reason="EXPIRED: long ago")
        state = watch.decide(down, {"sequence": 1, "errors": {"EXPIRED": ahead}}, self.now)
        self.assertEqual((state[0]["kind"], state[1]["errors"]), ("EXPIRED", {"EXPIRED": self.now}))

    def test_a_reading_that_flaps_costs_one_error_an_hour_and_is_never_called_recovered(self):
        """Found by an independent read of #153: live, down, live, down at every step sent one event a step
        to the log and the audit trail. And by the read of the fix: a RECOVERED said at the first live
        step would be the trail's last word while the reading was down again."""
        self.w.step()
        for minute in range(59):                                                 # an hour of flapping, one step a minute
            self.authenticated = minute % 2 == 1
            self.later(60)
            self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])               # one, and the trail still says down: it is
        self.authenticated = False
        self.later(120)
        self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])               # the hour passed: said again
        self.authenticated = True
        self.w.step()
        self.assertEqual(self.kinds(), [])
        self.w.step()
        self.assertEqual(self.kinds(), [("INFO", "RECOVERED", 0)])               # two live steps in a row: that outage's end
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # said once

    def test_what_was_said_about_a_heartbeat_is_not_said_again_after_a_blip(self):
        self.left(12 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])
        self.authenticated = False
        self.w.step()
        self.authenticated = True
        self.w.step()
        self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0), ("INFO", "RECOVERED", 0)])   # not a second "50 % left"
        self.left(6 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 25)])            # the next threshold, once

    def test_a_remembered_sequence_that_is_not_the_heartbeat_s_does_not_silence_its_warnings(self):
        """A state file from elsewhere, naming a higher sequence at the lowest threshold: the real heartbeat's
        50 % and 25 % must still be said. And a lower sequence arriving is not a renewal."""
        with open(self.wstate, "w") as f:
            json.dump({"sequence": 9, "level": 10, "last": self.now, "down": False, "announced": False, "recovering": False, "errors": {}}, f)
        self.left(12 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 50)])
        self.left(6 * HOUR)
        self.w.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 25)])
        with open(self.wstate, "w") as f:
            json.dump({"sequence": 9, "level": 10, "last": self.now, "down": False, "announced": False, "recovering": False, "errors": {}}, f)
        self.f.accept(beat(self.man, 2, issued=self.now, lifetime=DAY), self.man)
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # sequence 2 after a remembered 9: no "RENEWED"

    def test_renewed_means_a_newer_heartbeat_and_recovered_means_the_same_one(self):
        self.authenticated = False
        self.w.step()
        self.kinds()
        self.authenticated = True
        self.f.accept(beat(self.man, 2, issued=self.now, lifetime=DAY), self.man)
        self.w.step()
        self.assertEqual((self.events[0]["kind"], self.events[0]["sequence"]), ("RENEWED", 2))
        self.kinds()
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # said once
        # an outage that was never announced (its ERROR fell inside the hour) ends without a word
        self.authenticated = False
        self.w.step()
        self.authenticated = True
        self.w.step()
        self.assertEqual(self.kinds(), [])

    def test_each_kind_of_outage_has_its_own_hour(self):
        self.left(300)
        self.authenticated = False
        self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "UNUSABLE", 0)])
        self.authenticated = True
        self.later(300)                                                          # five minutes of unusable, and now it has expired
        self.w.step()
        self.assertEqual(self.kinds(), [("ERROR", "EXPIRED", 0)])                # a different fact: said at once
        self.later(600)
        self.authenticated = False
        self.w.step()
        self.assertEqual(self.kinds(), [])                                       # unusable again, inside its hour: held

    def test_the_thresholds_and_the_repeat_are_a_local_setting_and_are_checked(self):
        self.left(20 * HOUR)
        early = self.watch(thresholds=(90, 5), repeat=60)
        early.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 90)])
        self.left(HOUR)
        early.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 5)])
        self.later(60)
        early.step()
        self.assertEqual(self.kinds(), [("WARN", "RUNNING_OUT", 5)])
        for bad, reason in (((), "at least one"), (None, "at least one"), ((0,), "whole percent"), ((100,), "whole percent"),
                            ((0.5,), "whole percent"), ((True,), "whole percent"), ((10, 50), "highest down"), ((50, 50), "highest down")):
            with self.subTest(bad=bad):
                self.refused(reason, lambda: self.watch(thresholds=bad))
        for bad in (59, 0, 3600.0, True):
            with self.subTest(repeat=bad):
                self.refused("at least 60 seconds", lambda: self.watch(repeat=bad))

    def test_a_failed_write_leaves_no_temporary_file(self):
        os.mkdir(self.prom)                                                      # the metrics path cannot be replaced
        with self.assertRaises(OSError):
            self.w.step()
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".heartbeat-watch-")], [])


if __name__ == "__main__":
    unittest.main()
