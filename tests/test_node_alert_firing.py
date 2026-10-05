"""deploy/monitoring/regalia-node.rules.yml (#305): every rule names registered series only, every registered
series is either alerted on or a stated context gauge, and every rule fires on its fault and stays silent when
healthy, under promtool's own evaluation (as tests/test_alert_firing.py does for the KMS daemon's rules)."""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from deploy.baremetal import metrics
from tests.test_alert_firing import REQUIRE_PROMTOOL, render, series

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "deploy" / "monitoring" / "regalia-node.rules.yml"
# series a node writes for context, with no alert of their own (each says why)
CONTEXT = {
    "regalia_heartbeat_max_lifetime_seconds": "what the manifest allows",
    "regalia_heartbeat_checked_timestamp_seconds": "staleness is node_textfile_mtime_seconds",
    "regalia_admission_lease_seconds_left": "RegaliaNotServing watches the outcome",
    "regalia_audit_trail_lines": "read beside backlog",
    "regalia_esp_anchor_epoch": "root's reading of the anchor, beside sync's (RegaliaMembershipAnchorBehind)",
    "regalia_esp_advance_run_timestamp_seconds": "when it last ran: a oneshot, run on each new chain",
    "regalia_audit_trail_committed": "read beside backlog",
}
AUTHTIME = "/run/regalia-metrics/authtime/authtime.prom"
HEARTBEAT = "/run/regalia-metrics/sync/heartbeat.prom"
LEASE = "/run/regalia-metrics/admission/lease.prom"
MEMBERSHIP = "/run/regalia-metrics/sync/membership.prom"
ESP_ADVANCE = "/run/regalia-metrics/esp-advance/esp-advance.prom"
SHIP = "/run/regalia-metrics/audit-ship/sync.prom"
NODE_A, NODE_B = {"instance": "a:9100", "job": "regalia-node"}, {"instance": "b:9100", "job": "regalia-node"}

# Cases a single fault/healthy pair cannot show, each with exactly the alerts expected (labels beyond the rule's).
EXTRA = [
    # two nodes with trails of the same name: each node's backlog is judged by ITS last success, never another's
    ("RegaliaAuditTrailBehind", "two nodes: only the one behind", 1200,
     [("regalia_audit_trail_backlog", dict(NODE_A, trail="sync"), "3+0x20"),
      ("regalia_audit_trail_last_success_seconds", dict(NODE_A, trail="sync"), "0+0x20"),
      ("regalia_audit_trail_backlog", dict(NODE_B, trail="sync"), "3+0x20"),
      ("regalia_audit_trail_last_success_seconds", dict(NODE_B, trail="sync"), "600+60x20")],
     [dict(NODE_A, trail="sync")]),
    ("RegaliaAuditTrailNeverShipped", "two nodes: one has never shipped, the other's success does not hide it", 1200,
     [("regalia_audit_trail_backlog", dict(NODE_A, trail="sync"), "3+0x20"),
      ("regalia_audit_trail_backlog", dict(NODE_B, trail="sync"), "3+0x20"),
      ("regalia_audit_trail_last_success_seconds", dict(NODE_B, trail="sync"), "600+60x20")],
     [dict(NODE_A, trail="sync")]),
    # a one-hour heartbeat (a manifest may set it): healthy at 50 minutes left, no warning and no page
    ("RegaliaHeartbeatRunningOut", "a one-hour lifetime, 50 minutes left", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "3000+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "3600+0x5")], []),
    ("RegaliaHeartbeatAboutToExpire", "a one-hour lifetime, 50 minutes left", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "3000+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "3600+0x5")], []),
    # the held heartbeat's age, whatever its lifetime: a one-hour heartbeat is never two hours old; a 24-hour one, 2 h 10 min
    # after it was issued, is (and is nowhere near half its life: the age alert is the earlier one there)
    # the boundary at the production lifetime (6 h): over two hours, strictly (regalia-kms-d9 on #329)
    ("RegaliaHeartbeatNotRenewed", "6 h lifetime, exactly 2 h old", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "14400+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "21600+0x5")], []),
    ("RegaliaHeartbeatNotRenewed", "6 h lifetime, one second under 2 h old", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "14401+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "21600+0x5")], []),
    ("RegaliaHeartbeatNotRenewed", "6 h lifetime, one second over 2 h old", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "14399+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "21600+0x5")], [{}]),
    ("RegaliaHeartbeatNotRenewed", "a one-hour lifetime, 10 minutes left", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "600+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "3600+0x5")], []),
    ("RegaliaHeartbeatNotRenewed", "a 24-hour lifetime, issued 2 h 10 min ago", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "78600+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")], [{}]),
    ("RegaliaHeartbeatRunningOut", "a 24-hour lifetime, issued 2 h 10 min ago: the age alert's case, not this one", 120,
     [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "78600+0x5"),
      ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")], []),
    # the ESP advance runs seconds after a publication: ten minutes behind, then caught up, is not an alert (#66 B3)
    ("RegaliaMembershipAnchorBehind", "ten minutes behind, then caught up", 1200,
     [("regalia_membership_epoch", {}, "5+0x30"), ("regalia_membership_anchor_epoch", {}, "4+0x9 5+0x20")], []),
    # the authtime file missing on one node only: that node alone
    ("RegaliaAuthtimeMetricsMissing", "two nodes: only the one without the file", 420,
     [("up", NODE_A, "1+0x10"), ("up", NODE_B, "1+0x10"),
      ("node_textfile_mtime_seconds", dict(NODE_B, file=AUTHTIME), "0+60x10")],
     [NODE_A]),
]

SCENARIOS = {
    "RegaliaTimeNotAuthenticated": {
        "fault": [("regalia_time_authenticated", {"cause": "chrony_unreachable"}, "0+0x10")],
        "healthy": [("regalia_time_authenticated", {"cause": "ok"}, "1+0x10")], "at": 180},
    "RegaliaChronyLatched": {
        "fault": [("regalia_chrony_latch_set", {}, "1+0x5")], "healthy": [("regalia_chrony_latch_set", {}, "0+0x5")], "at": 120},
    "RegaliaHeartbeatRunningOut": {         # thresholds relative to the heartbeat's lifetime (24 h here)
        "fault": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "40000+0x5"),
                  ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")],
        "healthy": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "50000+0x5"),
                    ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")], "at": 120},
    "RegaliaHeartbeatNotRenewed": {          # the production lifetime (6 h, #69): over 2 h since it was issued
        "fault": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "14000+0x5"),
                  ("regalia_heartbeat_lifetime_seconds", {}, "21600+0x5")],
        "healthy": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "20700+0x5"),
                    ("regalia_heartbeat_lifetime_seconds", {}, "21600+0x5")], "at": 120},
    "RegaliaHeartbeatAboutToExpire": {
        "fault": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "20000+0x5"),
                  ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")],
        # running out, not about to expire: the warning's case, not this page's
        "healthy": [("regalia_heartbeat_live", {}, "1+0x5"), ("regalia_heartbeat_seconds_left", {}, "40000+0x5"),
                    ("regalia_heartbeat_lifetime_seconds", {}, "86400+0x5")], "at": 120},
    "RegaliaHeartbeatNotLive": {
        "fault": [("regalia_heartbeat_live", {}, "0+0x10")], "healthy": [("regalia_heartbeat_live", {}, "1+0x10")], "at": 420},
    "RegaliaNotServing": {
        "fault": [("regalia_admission_serving", {}, "0+0x10")], "healthy": [("regalia_admission_serving", {}, "1+0x10")], "at": 420},
    "RegaliaAuditTrailBehind": {
        "fault": [("regalia_audit_trail_backlog", {"trail": "sync"}, "3+0x20"),
                  ("regalia_audit_trail_last_success_seconds", {"trail": "sync"}, "0+0x20")],
        # lines waiting, and passes committing: shipping, not behind
        "healthy": [("regalia_audit_trail_backlog", {"trail": "sync"}, "3+0x20"),
                    ("regalia_audit_trail_last_success_seconds", {"trail": "sync"}, "600+60x20")], "at": 1200},
    "RegaliaAuditTrailNeverShipped": {
        "fault": [("regalia_audit_trail_backlog", {"trail": "sync"}, "3+0x20")],
        "healthy": [("regalia_audit_trail_backlog", {"trail": "sync"}, "3+0x20"),
                    ("regalia_audit_trail_last_success_seconds", {"trail": "sync"}, "600+60x20")], "at": 1200},
    "RegaliaAuditTrailTampered": {
        "fault": [("regalia_audit_trail_tampered", {"trail": "sync"}, "1+0x5")],
        "healthy": [("regalia_audit_trail_tampered", {"trail": "sync"}, "0+0x5")], "at": 120},
    "RegaliaUnlockRefused": {
        "fault": [("regalia_unlock_refused_total", {"cause": "rate"}, "0+1x20")],
        "healthy": [("regalia_unlock_refused_total", {"cause": "rate"}, "5+0x20")], "at": 900},
    "RegaliaMembershipAnchorBehind": {      # published at 5, anchored at 4 for twenty minutes; healthy: caught up
        "fault": [("regalia_membership_epoch", {}, "5+0x30"), ("regalia_membership_anchor_epoch", {}, "4+0x30")],
        "healthy": [("regalia_membership_epoch", {}, "5+0x30"), ("regalia_membership_anchor_epoch", {}, "5+0x30")], "at": 1200},
    "RegaliaEspAdvanceFailing": {
        "fault": [("regalia_esp_advance_ok", {}, "0+0x30")], "healthy": [("regalia_esp_advance_ok", {}, "1+0x30")], "at": 1200},
    "RegaliaNextBootNeedsRecoveryKey": {
        "fault": [("regalia_esp_boot_renderable", {}, "0+0x5")], "healthy": [("regalia_esp_boot_renderable", {}, "1+0x5")], "at": 120},
    "RegaliaEspAdvanceMetricsMissing": {
        "fault": [("up", NODE_A, "1+0x10")],
        "healthy": [("up", NODE_A, "1+0x10"), ("node_textfile_mtime_seconds", dict(NODE_A, file=ESP_ADVANCE), "0+0x10")], "at": 420},
    "RegaliaMembershipMetricsMissing": {
        "fault": [("up", NODE_A, "1+0x10")],
        "healthy": [("up", NODE_A, "1+0x10"), ("node_textfile_mtime_seconds", dict(NODE_A, file=MEMBERSHIP), "0+60x10")], "at": 420},
    "RegaliaNodeMetricsStale": {
        "fault": [("node_textfile_mtime_seconds", {"file": AUTHTIME}, "0+0x10")],
        "healthy": [("node_textfile_mtime_seconds", {"file": AUTHTIME}, "0+60x10")], "at": 600},
    "RegaliaAuditShipMetricsStale": {
        "fault": [("node_textfile_mtime_seconds", {"file": SHIP}, "0+0x10")],
        "healthy": [("node_textfile_mtime_seconds", {"file": SHIP}, "0+30x10")], "at": 600},
    # an absent file alerts: the node is scraped, and its file's mtime is not there at all (regalia-kms-d9)
    "RegaliaAuthtimeMetricsMissing": {
        "fault": [("up", NODE_A, "1+0x10")],
        "healthy": [("up", NODE_A, "1+0x10"), ("node_textfile_mtime_seconds", dict(NODE_A, file=AUTHTIME), "0+60x10")], "at": 420},
    "RegaliaHeartbeatMetricsMissing": {
        "fault": [("up", NODE_A, "1+0x10")],
        "healthy": [("up", NODE_A, "1+0x10"), ("node_textfile_mtime_seconds", dict(NODE_A, file=HEARTBEAT), "0+60x10")], "at": 420},
    "RegaliaLeaseMetricsMissing": {
        "fault": [("up", NODE_A, "1+0x10")],
        "healthy": [("up", NODE_A, "1+0x10"), ("node_textfile_mtime_seconds", dict(NODE_A, file=LEASE), "0+60x10")], "at": 420},
    "RegaliaNodeTextfileUnreadable": {        # a malformed file: node_exporter drops its series and says so
        "fault": [("node_textfile_scrape_error", NODE_A, "1+0x5")],
        "healthy": [("node_textfile_scrape_error", NODE_A, "0+0x5")], "at": 120},
    "RegaliaNodeExporterDown": {
        "fault": [("up", {"job": "regalia-node"}, "0+0x10")], "healthy": [("up", {"job": "regalia-node"}, "1+0x10")], "at": 300},
}


def rules():
    document = yaml.safe_load(RULES_PATH.read_text())
    return {rule["alert"]: rule for group in document["groups"] for rule in group["rules"]}


class Structure(unittest.TestCase):
    def test_every_series_a_rule_names_is_registered(self):
        for name, rule in rules().items():
            for series_name in re.findall(r"regalia_[a-z0-9_]+", rule["expr"]):
                with self.subTest(alert=name, series=series_name):
                    self.assertIn(series_name, metrics.METRICS)

    def test_every_registered_series_is_alerted_on_or_stated_context(self):
        named = {s for rule in rules().values() for s in re.findall(r"regalia_[a-z0-9_]+", rule["expr"])}
        self.assertEqual(set(metrics.METRICS) - named, set(CONTEXT))

    def test_every_alert_has_a_severity_a_summary_and_a_fault_scenario(self):
        found = rules()
        self.assertEqual(set(found), set(SCENARIOS))
        for name, rule in found.items():
            self.assertIn(rule["labels"]["severity"], ("critical", "warning"))
            self.assertTrue(rule["annotations"]["summary"])


class Firing(unittest.TestCase):
    def setUp(self):
        self.promtool = shutil.which("promtool")
        if self.promtool is None:
            if REQUIRE_PROMTOOL:
                self.fail("promtool is required in this job and was not found on PATH")
            self.skipTest("promtool not installed; set ALERT_RULES_JOB=1 to require it")

    def test_every_alert_fires_on_its_fault_and_stays_silent_when_healthy(self):
        found, cases = rules(), []
        for name, scenario in sorted(SCENARIOS.items()):
            rule, labels = found[name], {}
            for _, series_labels, _ in scenario["fault"]:
                labels.update(series_labels)
            for state, alerts in (("fault", [{"exp_labels": {"alertname": name, **rule.get("labels", {}), **labels},
                                              "exp_annotations": {k: render(v, labels) for k, v in rule.get("annotations", {}).items()}}]),
                                  ("healthy", [])):
                cases.append({"name": "%s on the %s state" % (name, state), "interval": "1m",
                              "input_series": [{"series": series(metric, series_labels), "values": values}
                                               for metric, series_labels, values in scenario[state]],
                              "alert_rule_test": [{"eval_time": "%ds" % scenario["at"], "alertname": name, "exp_alerts": alerts}]})
        for alertname, title, at, inputs, expected in EXTRA:
            rule = found[alertname]
            cases.append({"name": "%s: %s" % (alertname, title), "interval": "1m",
                          "input_series": [{"series": series(metric, labels), "values": values} for metric, labels, values in inputs],
                          "alert_rule_test": [{"eval_time": "%ds" % at, "alertname": alertname, "exp_alerts": [
                              {"exp_labels": {"alertname": alertname, **rule.get("labels", {}), **labels},
                               "exp_annotations": {k: render(v, labels) for k, v in rule.get("annotations", {}).items()}}
                              for labels in expected]}]})
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy(RULES_PATH, workspace / RULES_PATH.name)
            (workspace / "generated.test.yml").write_text(yaml.safe_dump(
                {"rule_files": [RULES_PATH.name], "evaluation_interval": "1m", "tests": cases}, sort_keys=False))
            done = subprocess.run([self.promtool, "test", "rules", "generated.test.yml"], cwd=workspace, capture_output=True, text=True)
        output = done.stdout + done.stderr
        self.assertNotIn("no file match pattern", output)
        self.assertEqual(0, done.returncode, output)


if __name__ == "__main__":
    unittest.main()
