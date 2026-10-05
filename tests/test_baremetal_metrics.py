"""deploy/baremetal/metrics.py (#305): the node's textfile metrics for node_exporter, from one registry."""
import os
import re
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from deploy.baremetal import authtime, heartbeat_watch, metrics as m
from deploy.baremetal import membership

ROOT = Path(__file__).resolve().parents[1]


class Registry(unittest.TestCase):
    def test_every_name_is_regalia_and_every_writer_known(self):
        for name, (kind, text, labels, writer) in m.METRICS.items():
            with self.subTest(name):
                self.assertRegex(name, m.NAME.pattern)
                self.assertIn(kind, ("gauge", "counter"))
                self.assertIn(writer, m.WRITERS)
                self.assertTrue(text and "\n" not in text)
                if kind == "counter":
                    self.assertTrue(name.endswith("_total"))

    def test_the_go_shipper_writes_exactly_the_registry_s_audit_ship_names(self):
        """cmd/regalia-audit-ship (regalia-kms-48) writes its own textfile: its names are held to the registry."""
        source = (ROOT / "cmd" / "regalia-audit-ship" / "main.go").read_text()
        written = set(re.findall(r"# TYPE (regalia_\w+) ", source))
        registered = {name for name, entry in m.METRICS.items() if entry[3] == "audit-ship"}
        self.assertEqual(written, registered)

    def test_the_heartbeat_watch_writes_registered_names_only(self):
        text = heartbeat_watch.metrics({"seconds_left": 1, "live": True, "lifetime": 2, "max_lifetime": 3}, 4)
        names = set(re.findall(r"^(regalia_\w+) ", text, re.M))
        self.assertEqual(names, {name for name, entry in m.METRICS.items() if entry[3] == "sync"} - {"regalia_unlock_refused_total", "regalia_membership_epoch", "regalia_membership_anchor_epoch"})   # unlock.prom, membership.prom
        for name in names:
            self.assertIn("# HELP %s %s\n" % (name, m.METRICS[name][1]), text)      # one help text, the registry's

    def test_no_label_takes_free_text(self):
        """regalia-kms-24: enums and numbers only. A label with no list of values is a trail name, from trails.py."""
        for name, (_, _, labels, _) in m.METRICS.items():
            for label, allowed in labels.items():
                with self.subTest(name=name, label=label):
                    self.assertTrue(allowed is not None or label == "trail")


class Rendering(unittest.TestCase):
    def refused(self, reason, *args):
        with self.assertRaises(m.Refused) as caught:
            m.render(*args)
        self.assertIn(reason, str(caught.exception))

    def test_a_deterministic_textfile(self):
        samples = [("regalia_chrony_latch_set", {}, 0), ("regalia_time_authenticated", {"cause": "ok"}, 1)]
        text = m.render("authtime", samples)
        self.assertEqual(text, m.render("authtime", list(reversed(samples))))
        self.assertEqual(text.splitlines()[1], "# TYPE regalia_chrony_latch_set gauge")
        self.assertIn('regalia_time_authenticated{cause="ok"} 1\n', text)

    def test_what_the_registry_does_not_allow_is_refused(self):
        self.refused("not a registered metric", "authtime", [("regalia_secret_key", {}, 1)])
        self.refused("written by sync, not authtime", "authtime", [("regalia_heartbeat_live", {}, 1)])
        self.refused("takes the labels", "authtime", [("regalia_time_authenticated", {}, 1)])
        self.refused("not an allowed value", "authtime", [("regalia_time_authenticated", {"cause": "the peer said: hi"}, 1)])
        self.refused("not an allowed value", "authtime", [("regalia_time_authenticated", {"cause": "rate"}, 1)])
        self.refused("not an allowed value", "audit-ship", [("regalia_audit_trail_lines", {"trail": "Sync Trail"}, 1)])
        self.refused("has no number", "admission", [("regalia_admission_serving", {}, True)])
        self.refused("has no number", "admission", [("regalia_admission_serving", {}, float("nan"))])
        self.refused("cannot be negative", "sync", [("regalia_unlock_refused_total", {"cause": "rate"}, -1)])
        self.refused("no metrics writer", "kms", [])


class Writing(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_a_whole_file_0640_and_no_temporary_left(self):
        target = os.path.join(self.d, "authtime.prom")
        self.assertTrue(m.publish("authtime", [("regalia_chrony_latch_set", {}, 1)], target))
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o640)
        self.assertEqual(os.listdir(self.d), ["authtime.prom"])
        self.assertIn("regalia_chrony_latch_set 1\n", open(target).read())

    def test_a_file_that_cannot_be_written_does_not_stop_the_service(self):
        self.assertFalse(m.publish("authtime", [("regalia_chrony_latch_set", {}, 1)], os.path.join(self.d, "missing", "a.prom")))
        with self.assertRaises(m.Refused):                     # but a sample the registry refuses still raises
            m.publish("authtime", [("regalia_nope", {}, 1)], os.path.join(self.d, "a.prom"))

    def test_each_writer_has_its_directory_under_one_root(self):
        self.assertEqual(m.path("authtime"), "/run/regalia-metrics/authtime/authtime.prom")
        self.assertEqual(m.path("sync", "unlock.prom"), "/run/regalia-metrics/sync/unlock.prom")
        with self.assertRaises(m.Refused):
            m.path("sync")                                             # two files: one must be named
        with self.assertRaises(m.Refused):
            m.path("sync", "other.prom")
        self.assertEqual(m.path("audit-ship", "sync.prom"), "/run/regalia-metrics/audit-ship/sync.prom")
        self.assertEqual(len({directory for directory, _ in m.WRITERS.values()}), len(m.WRITERS))

    def test_node_exporter_listens_on_the_host_address_only_behind_its_tls_config(self):
        args = m.node_exporter_args({"host_ipv4": "192.0.2.10"})
        self.assertIn("--web.listen-address=192.0.2.10:9100", args)
        self.assertIn("--web.config.file=/etc/regalia/node-exporter/web.yml", args)
        self.assertIn("--collector.textfile.directory=/run/regalia-metrics/*", args)


class NodeExporter(unittest.TestCase):
    def test_its_web_config_requires_a_client_certificate(self):
        import yaml
        config = yaml.safe_load((ROOT / "deploy" / "baremetal" / "node-exporter" / "web.yml").read_text())
        tls = config["tls_server_config"]
        self.assertEqual((tls["client_auth_type"], tls["min_version"]), ("RequireAndVerifyClientCert", "TLS13"))
        self.assertTrue(all(tls[k].startswith("/etc/regalia/node-exporter/") for k in ("cert_file", "key_file", "client_ca_file")))
        self.assertEqual(set(config), {"tls_server_config"})       # no basic auth, no HTTP server options beside it

    def test_the_args_line_is_rendered_from_the_site(self):
        import io
        import unittest.mock
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            self.assertEqual(m.main(["node-exporter-args", str(ROOT / "deploy" / "baremetal" / "site.example.json")]), 0)
        self.assertEqual(out.getvalue(), 'ARGS="--web.listen-address=192.0.2.10:9100 --web.config.file=/etc/regalia/node-exporter/web.yml '
                                         '--collector.textfile.directory=/run/regalia-metrics/*"\n')


class Counting(unittest.TestCase):
    """#317: the unlock listener's refusals, by cause, published whole on every change; never raising."""

    def test_each_cause_counts_and_publishes_registered_samples(self):
        published = []
        counter = m.Counter("sync", "regalia_unlock_refused_total", "unlock.prom", m.UNLOCK_CAUSES, publish=published.append)
        counter.flush()
        counter("rate")
        counter("rate")
        counter("connections")
        counter("something else")                                      # not a cause: ignored, not raised
        counter.flush()
        self.assertEqual(published, [[("regalia_unlock_refused_total", {"cause": "connections"}, 0),
                                      ("regalia_unlock_refused_total", {"cause": "rate"}, 0)],
                                     [("regalia_unlock_refused_total", {"cause": "connections"}, 1),
                                      ("regalia_unlock_refused_total", {"cause": "rate"}, 2)]])
        for samples in published:
            m.render("sync", samples)

    def test_a_refusal_flood_writes_nothing_until_the_round(self):
        """regalia-kms-48: counting is an increment; the refusing thread (the accept loop) never writes."""
        published = []
        counter = m.Counter("sync", "regalia_unlock_refused_total", "unlock.prom", m.UNLOCK_CAUSES, publish=published.append)
        for _ in range(1000):
            counter("connections")
        self.assertEqual(published, [])
        counter.flush()
        self.assertEqual(len(published), 1)
        self.assertIn(("regalia_unlock_refused_total", {"cause": "connections"}, 1000), published[0])

    def test_two_flushes_never_publish_out_of_order(self):
        """One lock spans the snapshot and the write: a slower flush cannot publish an older count after a newer."""
        import threading
        published, started = [], threading.Event()
        counter = m.Counter("sync", "regalia_unlock_refused_total", "unlock.prom", m.UNLOCK_CAUSES)

        def slow(samples):
            started.set()
            threading.Event().wait(0.2)                                 # the first write is slow
            published.append(dict((labels["cause"], value) for _, labels, value in samples)["rate"])
        counter.publish = slow
        counter("rate")
        first = threading.Thread(target=counter.flush)
        first.start()
        started.wait(5)
        counter("rate")
        counter.flush()                                                 # waits for the first write, then publishes 2
        first.join()
        self.assertEqual(published, sorted(published))

    def test_a_publish_that_fails_never_stops_what_counts(self):
        def broken(samples):
            raise OSError(28, "No space left on device")
        counter = m.Counter("sync", "regalia_unlock_refused_total", "unlock.prom", m.UNLOCK_CAUSES, publish=broken)
        counter("rate")                                                # no exception
        self.assertEqual(counter.counts["rate"], 1)


class Causes(unittest.TestCase):
    def test_authtime_s_reasons_map_to_the_enum(self):
        for reason, cause in (("", "ok"), ("chrony could not be asked for tracking", "chrony_unreachable"),
                              ("/usr/share/zoneinfo/right/UTC is missing: chronyd has no leap-second data (install tzdata-legacy)", "no_leap_zone"),
                              ("the transition could not be recorded in the time trail (OSError)", "unrecorded"),
                              ("the clock is not synchronised (Not synchronised)", "not_synchronised"),
                              ("a time source nobody declared is configured: 192.0.2.9", "undeclared_source"),
                              ("only 1 NTS source(s) agree", "too_few_sources"), ("something new", "other")):
            with self.subTest(reason=reason):
                self.assertEqual(m.time_cause(reason), cause)
                self.assertIn(cause, m.TIME_CAUSE_VALUES)


class Publishers(unittest.TestCase):
    """authtime and admission publish after every check, through the registry."""

    def test_authtime_publishes_its_verdict_s_cause_and_the_latch(self):
        from tests.test_baremetal_authtime import BOOT, DECLARED, NOW, reading
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        published, latch = [], os.path.join(d, "chrony-latch")
        service = authtime.Service(os.path.join(d, "authtime.json"), DECLARED, reading, wall=lambda: NOW, boottime=lambda: 1,
                                   boot=lambda: BOOT, leap=lambda: __file__, metrics=published.append, latch=latch)
        service.step()
        open(latch, "w").close()
        service.reading = lambda: (_ for _ in ()).throw(membership.Refused("chrony could not be asked for tracking"))
        service.step()
        self.assertEqual(published, [[("regalia_time_authenticated", {"cause": "ok"}, 1), ("regalia_chrony_latch_set", {}, 0)],
                                     [("regalia_time_authenticated", {"cause": "chrony_unreachable"}, 0), ("regalia_chrony_latch_set", {}, 1)]])
        for samples in published:
            m.render("authtime", samples)                       # the registry takes them


if __name__ == "__main__":
    unittest.main()
