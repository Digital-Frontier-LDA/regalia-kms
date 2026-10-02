"""deploy/baremetal/authtime.py (#69, #80): the clock is authenticated only when chrony is synchronised to
NTS sources, at least two of which agree. chronyc's reports here are those a real chronyd printed (recorded
with a private NTS server and client on the loopback, chrony 4.6.1); e2e/authtime-chrony-nts.py runs the
same code against live daemons."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import authtime
from deploy.baremetal import membership as m

NOW = 1790973000
# two NTS sources that agree; a third that is combined
TRACKING = "7F000001,127.0.0.1,9,1790972976.511162019,-0.000005244,0.000000519,0.000002347,-0.099,0.013,0.643,0.000013843,0.000003165,1.0,Normal\n"
SOURCES = ("^,*,127.0.0.1,8,0,377,1,0.000010777,0.000011296,0.000017674\n"
           "^,+,127.0.0.2,8,0,377,1,0.000003299,0.000003299,0.000005795\n")
AUTHDATA = ("127.0.0.1,NTS,1,30,128,13,0,0,8,64\n"
            "127.0.0.2,NTS,1,30,128,13,0,0,8,64\n")
# recorded: nothing synchronised
UNSYNCED = "00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,1.000000000,1.000000000,0.0,Not synchronised\n"
BOOT = "0b1e7c2a-5d3f-4a6b-8c9d-0e1f2a3b4c5d"


def reading(tracking=TRACKING, sources=SOURCES, authdata=AUTHDATA):
    return authtime.parse(tracking, sources, authdata)


class Case(unittest.TestCase):
    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Judging(Case):
    def test_two_nts_sources_that_agree_authenticate_the_clock(self):
        authtime.judge(reading(), NOW)
        self.assertEqual(reading()["sources"][0], {"name": "127.0.0.1", "state": "*", "reaching": True, "mode": "NTS", "keyed": True, "nak": "0"})
        for leap in ("Insert second", "Delete second"):                 # a leap second pending is still a synchronised clock
            authtime.judge(reading(TRACKING.replace("Normal", leap)), NOW)

    def test_each_way_the_clock_is_not_authenticated(self):
        one = lambda old, new: SOURCES.replace(old, new)                 # noqa: E731
        for label, reason, got in (
                ("not synchronised (recorded)", "the clock is not synchronised (Not synchronised)",
                 reading(UNSYNCED, "^,?,127.0.0.2,0,6,0,4294967295,0.000000000,0.000000000,0.000000000\n", "127.0.0.2,NTS,0,0,0,4294967295,1,0,0,0\n")),
                ("an unknown leap status", "the clock is not synchronised (Maybe)", reading(TRACKING.replace("Normal", "Maybe"))),
                ("a plain NTP source that chrony does not even use (recorded)", "a time source without NTS is configured: 127.0.0.9",
                 reading(sources=SOURCES + "^,-,127.0.0.9,8,0,377,1,0.000003299,0.000003299,0.000005795\n", authdata=AUTHDATA + "127.0.0.9,-,0,0,0,4294967295,0,0,0,0\n")),
                ("a symmetric-key source", "a time source without NTS is configured: 127.0.0.2", reading(authdata=AUTHDATA.replace("127.0.0.2,NTS", "127.0.0.2,SK"))),
                ("nothing selected", "no time source is selected", reading(sources=one("^,*,", "^,+,"))),
                ("two selected", "no time source is selected", reading(sources=one("^,+,", "^,*,"))),
                ("one source only", "only 1 NTS source(s) agree; 2 are needed", reading(sources=one("^,+,", "^,-,"))),
                ("the second is a falseticker", "only 1 NTS source(s) agree", reading(sources=one("^,+,", "^,x,"))),
                ("the second is unreachable", "only 1 NTS source(s) agree", reading(sources=one("^,+,127.0.0.2,8,0,377", "^,?,127.0.0.2,8,0,0"))),
                ("a combined source that stopped answering", "the time source 127.0.0.2 has stopped answering", reading(sources=one("^,+,127.0.0.2,8,0,377", "^,+,127.0.0.2,8,0,0"))),
                ("the selected source has no keys yet", "the time source 127.0.0.1 holds no NTS keys", reading(authdata=AUTHDATA.replace("127.0.0.1,NTS,1,30,128,13,0,0,8,64", "127.0.0.1,NTS,0,0,0,4294967295,1,0,0,0"))),
                ("a combined source with no cookies", "the time source 127.0.0.2 holds no NTS keys", reading(authdata=AUTHDATA.replace("127.0.0.2,NTS,1,30,128,13,0,0,8,64", "127.0.0.2,NTS,1,30,128,13,0,0,0,64"))),
                ("a correction is pending", "the system clock is 2.500 s from chrony's time", reading(TRACKING.replace("-0.000005244", "2.5"))),
                ("a correction is pending, the other way", "the system clock is -1.001 s from chrony's time", reading(TRACKING.replace("-0.000005244", "-1.001")))):
            with self.subTest(label):
                self.refused(reason, authtime.judge, got, NOW)

    def test_synchronised_must_not_be_a_memory(self):
        authtime.judge(reading(), 1790972976 + authtime.MAX_AGE)
        self.refused("the clock was last updated 3600.5 s ago (at most 3600)", authtime.judge, reading(), 1790972977 + authtime.MAX_AGE)
        self.refused("the clock was last updated", authtime.judge, reading(), 1790972976 - 2)       # an update dated in the future
        authtime.judge(reading(), 1790972976 + 30, max_age=30)
        self.refused("at most 30", authtime.judge, reading(), 1790972976 + 32, max_age=30)

    def test_two_is_the_least_and_more_can_be_asked(self):
        for bad in (1, 0, True, None, 2.0):
            self.refused("at least two NTS sources must agree", authtime.judge, reading(), NOW, minimum=bad)
        self.refused("only 2 NTS source(s) agree; 3 are needed", authtime.judge, reading(), NOW, minimum=3)
        three = reading(sources=SOURCES + "^,+,127.0.0.3,8,0,377,1,0.000003299,0.000003299,0.000005795\n", authdata=AUTHDATA + "127.0.0.3,NTS,1,30,128,13,0,0,8,64\n")
        authtime.judge(three, NOW, minimum=3)

    def test_what_is_not_understood_is_refused_not_guessed(self):
        for label, reason, args in (
                ("a short tracking line", "chronyc tracking is not understood", ("7F000001,127.0.0.1,9\n", SOURCES, AUTHDATA)),
                ("two tracking lines", "chronyc tracking is not understood", (TRACKING * 2, SOURCES, AUTHDATA)),
                ("no tracking line", "chronyc tracking is not understood", ("", SOURCES, AUTHDATA)),
                ("a reference time that is no number", "chronyc tracking is not understood", (TRACKING.replace("1790972976.511162019", "yesterday"), SOURCES, AUTHDATA)),
                ("an error instead of a report", "chronyc tracking is not understood", ("506 Cannot talk to daemon\n", SOURCES, AUTHDATA)),
                ("a short sources line", "chronyc sources is not understood", (TRACKING, "^,*,127.0.0.1\n", AUTHDATA)),
                ("a reach that is no octal", "chronyc sources is not understood", (TRACKING, SOURCES.replace(",377,", ",399,", 1), AUTHDATA)),
                ("a short authdata line", "chronyc authdata is not understood", (TRACKING, SOURCES, "127.0.0.1,NTS\n")),
                ("authdata refused", "chronyc authdata is not understood", (TRACKING, SOURCES, "501 Not authorised\n")),
                ("a source authdata does not cover", "chronyc authdata does not cover the source 127.0.0.2", (TRACKING, SOURCES, AUTHDATA.splitlines()[0] + "\n")),
                ("a source named twice", "chronyc authdata names a source twice", (TRACKING, SOURCES, AUTHDATA + AUTHDATA.splitlines()[0] + "\n")),
                ("authdata for a source that is not listed", "do not list the same sources", (TRACKING, SOURCES.splitlines()[0] + "\n", AUTHDATA))):
            with self.subTest(label):
                self.refused(reason, authtime.parse, *args)
        keyed = authtime.parse(TRACKING, SOURCES, AUTHDATA.replace("127.0.0.2,NTS,1,30,128", "127.0.0.2,NTS,x,30,128"))
        self.assertFalse(keyed["sources"][1]["keyed"])                   # a key ID that is no number is "no keys", not a crash


class Asking(Case):
    def chrony(self, reports=None, code=0):
        reports = {"tracking": TRACKING, "sources": SOURCES, "authdata": AUTHDATA} if reports is None else reports
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, code, reports[argv[-1]].encode(), b"")
        return run, calls

    def test_chrony_is_asked_three_things_numerically_over_its_socket(self):
        run, calls = self.chrony()
        authtime.judge(authtime.ask(run), NOW)
        self.assertEqual(calls, [["chronyc", "-n", "-c", report] for report in ("tracking", "sources", "authdata")])
        run, calls = self.chrony()
        authtime.ask(run, chronyc="/usr/bin/chronyc", socket_path="/run/chrony/chronyd.sock")
        self.assertEqual(calls[2], ["/usr/bin/chronyc", "-h", "/run/chrony/chronyd.sock", "-n", "-c", "authdata"])

    def test_a_chrony_that_cannot_be_asked_is_a_refusal(self):
        self.refused("chrony could not be asked for tracking", authtime.ask, self.chrony(code=1)[0])

        def missing(argv, **kw):
            raise FileNotFoundError("chronyc")

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 10)
        self.refused("chrony could not be asked (FileNotFoundError)", authtime.ask, missing)
        self.refused("chrony could not be asked (TimeoutExpired)", authtime.ask, slow)


class Configuring(Case):
    def test_every_server_with_nts_nothing_selectable_without_it_and_two_at_least(self):
        self.assertEqual(authtime.conf(["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"]),
                         "server nts.netnod.se nts iburst\nserver ptbtime1.ptb.de nts iburst\nserver time.cloudflare.com nts iburst\n"
                         "authselectmode require\nminsources 2\n")
        for bad, reason in ((["nts.netnod.se"], "at least 2 NTS servers"), ([], "at least 2 NTS servers"), (None, "at least 2 NTS servers"),
                            (["nts.netnod.se", "nts.netnod.se"], "listed twice"),
                            (["nts.netnod.se", "192.0.2.1 nts\nserver evil.example"], "is not a host name"),
                            (["nts.netnod.se", "Time.Cloudflare.com"], "is not a host name"), (["nts.netnod.se", "localhost"], "is not a host name"),
                            (["nts.netnod.se", 7], "is not a host name"), (["nts.netnod.se", "a." + "b" * 300 + ".se"], "is not a host name")):
            with self.subTest(bad=bad):
                self.refused(reason, authtime.conf, bad)


class Publishing(Case):
    """The root service writes one fact; an unprivileged service believes it only while it is fresh."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.path, self.ticks, self.now, self.answer = os.path.join(self.d, "authtime.json"), 100_000, NOW, reading()
        self.me = os.getuid()

    def service(self):
        def answer():
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
        return authtime.Service(self.path, answer, wall=lambda: self.now, boottime=lambda: self.ticks, boot=lambda: BOOT)

    def clock(self, **how):
        return authtime.clock(self.path, wall=lambda: self.now, boottime=lambda: self.ticks, boot=lambda: BOOT, owner=self.me, **how)

    def test_authenticated_time_is_published_and_believed_while_fresh(self):
        document = self.service().step()
        self.assertEqual(document, {"schema": "regalia.authtime/v1", "boot_id": BOOT, "checked_boottime_ms": 100_000, "authenticated": True, "reason": ""})
        with open(self.path) as f:
            self.assertEqual(json.load(f), document)
        self.assertEqual(list(document), list(authtime.FIELDS))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o644)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".authtime-")], [])
        self.assertEqual(self.clock()(), (NOW, True))
        self.ticks += authtime.MAX_STALE * 1000
        self.assertEqual(self.clock()(), (NOW, True))
        self.ticks += 1                                                  # the root service has stopped: a minute later, no
        self.assertEqual(self.clock()(), (NOW, False))
        self.refused("is 60001 ms old (at most 60 s): the check has stopped", authtime.status, self.path, lambda: self.ticks, lambda: BOOT, self.me)

    def test_a_clock_that_is_not_authenticated_is_published_with_its_reason(self):
        self.answer = reading(UNSYNCED, "", "")
        document = self.service().step()
        self.assertEqual((document["authenticated"], document["reason"]), (False, "the clock is not synchronised (Not synchronised)"))
        self.assertEqual(self.clock()(), (NOW, False))
        self.refused("time is not authenticated: the clock is not synchronised", authtime.status, self.path, lambda: self.ticks, lambda: BOOT, self.me)
        for failure, reason in ((m.Refused("chrony could not be asked for tracking"), "chrony could not be asked for tracking"),
                                (RuntimeError("boom"), "the check failed (RuntimeError)")):
            self.answer = failure
            self.assertEqual((self.service().step()["authenticated"], self.service().step()["reason"]), (False, reason))
        self.answer = reading()
        self.ticks += 15_000
        self.service().step()
        self.assertEqual(self.clock()(), (NOW, True))                    # and back, at the next check

    def test_a_status_that_is_not_this_boot_s_root_s_or_well_formed_is_not_believed(self):
        self.service().step()
        self.assertEqual(self.clock()(), (NOW, True))
        other = authtime.clock(self.path, wall=lambda: self.now, boottime=lambda: self.ticks, boot=lambda: "another-boot", owner=self.me)
        self.assertEqual(other()[1], False)
        self.assertEqual(authtime.clock(self.path, wall=lambda: self.now, boottime=lambda: self.ticks, boot=lambda: BOOT, owner=self.me + 1)()[1], False)
        self.ticks -= 1                                                  # a check dated in the future of the boot clock
        self.assertEqual(self.clock()()[1], False)
        self.ticks += 1
        good = authtime.read(self.path, self.me)
        for label, document in (("another schema", dict(good, schema="regalia.authtime/v2")), ("true as text", dict(good, authenticated="true")),
                                ("true as 1", dict(good, authenticated=1)), ("a reason that is no text", dict(good, reason=None)),
                                ("a time that is no integer", dict(good, checked_boottime_ms="100000")), ("a negative time", dict(good, checked_boottime_ms=-1)),
                                ("a time as true", dict(good, checked_boottime_ms=True)), ("more", dict(good, more=1)),
                                ("less", {k: v for k, v in good.items() if k != "reason"})):
            with self.subTest(label):
                with open(self.path, "w") as f:
                    json.dump(document, f)
                self.assertEqual(self.clock()(), (NOW, False))
        for label, raw in (("not JSON", b"yes"), ("empty", b""), ("too long", b" " * 5000)):
            with self.subTest(label):
                with open(self.path, "wb") as f:
                    f.write(raw)
                self.assertEqual(self.clock()()[1], False)
        self.service().step()
        self.assertEqual(self.clock()()[1], True)

    def test_a_file_or_directory_others_can_write_is_not_believed(self):
        self.service().step()
        os.chmod(self.path, 0o664)
        self.refused("not a file only its writer can change", authtime.read, self.path, self.me)
        os.chmod(self.path, 0o646)
        self.assertEqual(self.clock()()[1], False)
        os.chmod(self.path, 0o644)
        os.chmod(self.d, 0o777)
        self.refused("is writable by others", authtime.read, self.path, self.me)
        os.chmod(self.d, 0o775)
        self.assertEqual(self.clock()()[1], False)
        os.chmod(self.d, 0o755)
        self.assertEqual(self.clock()()[1], True)
        os.unlink(self.path)
        os.symlink("/etc/hostname", self.path)                           # not followed
        self.refused("cannot be read", authtime.read, self.path, self.me)
        os.unlink(self.path)
        os.mkdir(self.path)
        self.assertEqual(self.clock()()[1], False)
        os.rmdir(self.path)
        self.refused("cannot be read (FileNotFoundError)", authtime.read, self.path, self.me)
        self.assertEqual(self.clock()(), (NOW, False))                   # no file at all: the service never ran

    def test_a_failed_write_leaves_no_temporary_file_and_the_last_status_goes_stale(self):
        self.service().step()
        self.refused("exactly its fields, in order", authtime.write, self.path, {"authenticated": True})
        os.chmod(self.d, 0o555)
        try:
            if os.getuid() != 0:
                with self.assertRaises(OSError):
                    self.service().step()
        finally:
            os.chmod(self.d, 0o755)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".authtime-")], [])
        # the temporary file exists and the rename fails: it is removed, and the status on disk is the old one
        before = open(self.path).read()
        self.answer = reading(UNSYNCED, "", "")
        with unittest.mock.patch.object(authtime.os, "replace", side_effect=OSError("no rename")):
            with self.assertRaises(OSError):
                self.service().step()
        self.assertEqual(([n for n in os.listdir(self.d) if n.startswith(".authtime-")], open(self.path).read()), ([], before))


if __name__ == "__main__":
    unittest.main()
