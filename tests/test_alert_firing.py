"""Drive a fault at every alert rule and require the alert to fire.

test_alert_rules.py proves the rules and OBSERVABILITY.md name the same series. That is a
STRUCTURAL check, and structure is not behaviour: a rule can name every series correctly and
still be unable to fire, or fire on a state that is normal.

Both have happened here, and neither was caught by a test:

  * RegaliaFencingLeaseLost (now RegaliaNoActiveSite, across the sites) would have paged on EVERY daemon restart, because `lease_held 0`
    before the first evaluation is byte-identical to a lease just lost. A rule that pages on
    every restart is a rule somebody silences.
  * Fixing that by making the gauge absent until first evaluation left
    RegaliaFencingEvaluationStale unable to fire at all -- `time()` minus an absent series
    matches nothing -- so a site whose fencing never evaluated was watched by NO rule while
    appearing to be watched by two.

Both were found by reading. This file is the fault injection that finds the next one: each
alert gets a series pattern that must make it fire, and a healthy pattern that must not. Those
two specific regressions are pinned as their own cases below.

Evaluation is done by `promtool test rules`, the Prometheus unit-test runner, so the semantics
under test are Prometheus's own rather than a re-implementation of them here.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "deploy" / "monitoring" / "regalia-kms.rules.yml"

# A promtool that is missing locally is a skip; in the job that owns this check it is a failure.
# A silently skipped behavioural test is exactly the "appears to be watched" state above.
REQUIRE_PROMTOOL = os.environ.get("ALERT_RULES_JOB") == "1"

LABEL_TEMPLATE = re.compile(r"\{\{ *\$labels\.([a-zA-Z_][a-zA-Z0-9_]*) *\}\}")


def series(name: str, labels: dict[str, str] | None = None) -> str:
    if not labels:
        return name
    inner = ",".join(f'{key}="{value}"' for key, value in sorted(labels.items()))
    return f"{name}{{{inner}}}"


# Each scenario: the fault that must fire the alert, and the healthy state that must not.
#
# `labels` are the series labels the alert inherits; they are also what the summary template
# renders from, so they are declared once here rather than duplicated into an expected string.
# `at` is the evaluation time in seconds -- for a rule with `for:`, it must exceed the hold.
SCENARIOS: dict[str, dict] = {
    "RegaliaAuditBacklogGrowing": {
        "fault": [("regalia_audit_backlog_events", {}, "5+0x10")],
        "healthy": [("regalia_audit_backlog_events", {}, "0+0x10")],
        "at": 400,
    },
    "RegaliaAuditBacklogOverLimit": {
        "fault": [("regalia_audit_backlog_events", {}, "5000+0x10")],
        "healthy": [("regalia_audit_backlog_events", {}, "4096+0x10")],
        "at": 200,
    },
    "RegaliaAuditOldestUnshippedStale": {
        "fault": [("regalia_audit_oldest_unshipped_age_seconds", {}, "400+0x10")],
        "healthy": [("regalia_audit_oldest_unshipped_age_seconds", {}, "10+0x10")],
        "at": 200,
    },
    "RegaliaAuditShipperStuck": {
        # Backlog present and the acknowledged head frozen: behind AND not moving.
        "fault": [
            ("regalia_audit_backlog_events", {}, "5+0x20"),
            ("regalia_audit_shipped_sequence", {}, "100+0x20"),
        ],
        # Behind but draining is not stuck -- this is the case a naive `backlog > 0` would
        # page on, and the reason the rule carries the rate() term at all.
        "healthy": [
            ("regalia_audit_backlog_events", {}, "5+0x20"),
            ("regalia_audit_shipped_sequence", {}, "100+10x20"),
        ],
        "at": 700,
    },
    "RegaliaAuditChainBroken": {
        "fault": [("regalia_audit_verify_outcome", {"outcome": "chain-broken"}, "1+0x5")],
        "healthy": [("regalia_audit_verify_outcome", {"outcome": "chain-broken"}, "0+0x5")],
        "at": 120,
    },
    "RegaliaAuditVerifyUnreadable": {
        "fault": [("regalia_audit_verify_outcome", {"outcome": "unreadable"}, "1+0x10")],
        "healthy": [("regalia_audit_verify_outcome", {"outcome": "unreadable"}, "0+0x10")],
        "at": 300,
    },
    "RegaliaAuditVerifyUnknownOutcome": {
        "fault": [("regalia_audit_verify_outcome", {"outcome": "unknown"}, "1+0x5")],
        "healthy": [("regalia_audit_verify_outcome", {"outcome": "unknown"}, "0+0x5")],
        "at": 120,
    },
    "RegaliaAuditVerifyStale": {
        "fault": [("regalia_audit_verify_last_run_seconds", {}, "0+0x10")],
        "healthy": [("regalia_audit_verify_last_run_seconds", {}, "580+0x10")],
        "at": 600,
    },
    # across the sites of one job (#432): no site holding, or two; `labels` because the rules aggregate the instance away
    "RegaliaNoActiveSite": {
        "fault": [("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "a"}, "0+0x25"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "a"}, "0+60x25"),
                  ("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "b"}, "0+0x25"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "b"}, "0+60x25")],
        "healthy": [("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "a"}, "1+0x25"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "a"}, "0+60x25"),
                    ("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "b"}, "0+0x25"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "b"}, "0+60x25")],
        "labels": {"job": "regalia-kms"},
        "at": 1380,
    },
    "RegaliaTwoActiveSites": {
        "fault": [("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "a"}, "1+0x5"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "a"}, "0+60x5"),
                  ("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "b"}, "1+0x5"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "b"}, "0+60x5")],
        "healthy": [("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "a"}, "1+0x5"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "a"}, "0+60x5"),
                    ("regalia_fencing_lease_held", {"job": "regalia-kms", "instance": "b"}, "0+0x5"), ("regalia_fencing_last_check_seconds", {"job": "regalia-kms", "instance": "b"}, "0+60x5")],
        "labels": {"job": "regalia-kms"},
        "at": 120,
    },
    "RegaliaFencingNeverEvaluated": {
        "fault": [("regalia_fencing_evaluated", {}, "0+0x10")],
        "healthy": [("regalia_fencing_evaluated", {}, "1+0x10")],
        "at": 400,
    },
    "RegaliaFencingEvaluationStale": {
        "fault": [("regalia_fencing_last_check_seconds", {}, "0+0x10")],
        "healthy": [("regalia_fencing_last_check_seconds", {}, "580+0x10")],
        "at": 600,
    },
    "RegaliaFencingEpochChanged": {
        "fault": [("regalia_fencing_lease_epoch", {}, "1 1 1 2 2 2")],
        "healthy": [("regalia_fencing_lease_epoch", {}, "1+0x10")],
        "at": 360,
    },
    "RegaliaBackendQuarantined": {
        "fault": [("regalia_backend_quarantined",
                   {"device": "pico-01", "reason": "pin-lockout"}, "1+0x5")],
        "healthy": [("regalia_backend_quarantined",
                     {"device": "pico-01", "reason": "pin-lockout"}, "0+0x5")],
        "at": 120,
    },
    "RegaliaPINRetriesLow": {
        "fault": [("regalia_token_pin_retries_remaining", {"device": "pico-01"}, "2+0x5")],
        "healthy": [("regalia_token_pin_retries_remaining", {"device": "pico-01"}, "3+0x5")],
        "at": 120,
    },
    "RegaliaPINReadingStale": {
        "fault": [("regalia_token_pin_retries_updated_at_seconds",
                   {"device": "pico-01"}, "0+0x30")],
        "healthy": [("regalia_token_pin_retries_updated_at_seconds",
                     {"device": "pico-01"}, "1500+0x30")],
        "at": 1500,
    },
    "RegaliaQuotaRejectionsSustained": {
        "fault": [("regalia_policy_quota_rejections_total", {}, "0+1x20")],
        "healthy": [("regalia_policy_quota_rejections_total", {}, "0+0x20")],
        "at": 900,
    },
    "RegaliaNotReady": {
        "fault": [("regalia_ready", {}, "0+0x10")],
        "healthy": [("regalia_ready", {}, "1+0x10")],
        "at": 300,
    },
    "RegaliaReadinessFlapping": {
        "fault": [("regalia_readiness_transitions_total", {}, "0+2x20")],
        "healthy": [("regalia_readiness_transitions_total", {}, "0+0x20")],
        "at": 900,
    },
    "RegaliaReadinessCheckStale": {
        "fault": [("regalia_readiness_last_check_seconds", {}, "0+0x10")],
        "healthy": [("regalia_readiness_last_check_seconds", {}, "580+0x10")],
        "at": 600,
    },
    "RegaliaRouterRejections": {
        "fault": [("regalia_http_router_decisions_total", {"decision": "rejected"}, "0+1x20")],
        "healthy": [("regalia_http_router_decisions_total", {"decision": "rejected"}, "0+0x20")],
        "at": 900,
    },
    "RegaliaOperationErrors": {
        "fault": [("regalia_http_requests_total",
                   {"outcome": "5xx", "route": "/v1/operations/sign"}, "0+1x20")],
        "healthy": [("regalia_http_requests_total",
                     {"outcome": "5xx", "route": "/v1/operations/sign"}, "0+0x20")],
        "at": 900,
    },
    "RegaliaUnauthenticatedProbing": {
        "fault": [("regalia_http_unauthenticated_total", {}, "0+1x40")],
        "healthy": [("regalia_http_unauthenticated_total", {}, "0+0x40")],
        "at": 1500,
    },
}


def alert_rules() -> dict[str, dict]:
    document = yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))
    found = {}
    for group in document["groups"]:
        for rule in group["rules"]:
            if "alert" in rule:
                found[rule["alert"]] = rule
    return found


def render(summary: str, labels: dict[str, str]) -> str:
    """Render the only templating the summaries use: {{ $labels.name }}."""
    return LABEL_TEMPLATE.sub(lambda match: labels.get(match.group(1), ""), summary)


def build_cases(rules: dict[str, dict]) -> list[dict]:
    cases = []
    for name, scenario in sorted(SCENARIOS.items()):
        rule = rules[name]
        labels = {}
        for _, series_labels, _ in scenario["fault"]:
            labels.update(series_labels)
        labels = scenario.get("labels", labels)      # a rule that aggregates labels away states the ones it keeps
        expected_labels = {"alertname": name, **rule.get("labels", {}), **labels}
        expected_annotations = {
            key: render(value, labels)
            for key, value in rule.get("annotations", {}).items()
        }
        cases.append({
            "name": f"{name} fires on the injected fault",
            "interval": "1m",
            "input_series": [
                {"series": series(metric, series_labels), "values": values}
                for metric, series_labels, values in scenario["fault"]
            ],
            "alert_rule_test": [{
                "eval_time": f"{scenario['at']}s",
                "alertname": name,
                "exp_alerts": [{
                    "exp_labels": expected_labels,
                    "exp_annotations": expected_annotations,
                }],
            }],
        })
        cases.append({
            "name": f"{name} stays silent on the healthy state",
            "interval": "1m",
            "input_series": [
                {"series": series(metric, series_labels), "values": values}
                for metric, series_labels, values in scenario["healthy"]
            ],
            "alert_rule_test": [{
                "eval_time": f"{scenario['at']}s",
                "alertname": name,
                "exp_alerts": [],
            }],
        })
    return cases


class AlertFiringTests(unittest.TestCase):
    def setUp(self):
        self.promtool = shutil.which("promtool")
        if self.promtool is None:
            if REQUIRE_PROMTOOL:
                self.fail("promtool is required in this job and was not found on PATH")
            self.skipTest("promtool not installed; set ALERT_RULES_JOB=1 to require it")
        self.rules = alert_rules()

    def test_every_alert_has_a_fault_scenario(self):
        """A new alert must arrive with the fault that proves it can fire."""
        missing = sorted(set(self.rules) - set(SCENARIOS))
        self.assertEqual([], missing,
                         "these alerts have no fault injection, so nothing proves they fire")
        unknown = sorted(set(SCENARIOS) - set(self.rules))
        self.assertEqual([], unknown,
                         "these scenarios name alerts that no longer exist")

    def test_every_alert_fires_on_its_fault_and_stays_silent_when_healthy(self):
        cases = build_cases(self.rules)
        self.assertEqual(len(cases), 2 * len(self.rules))

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            # promtool resolves rule_files RELATIVE TO THE TEST FILE, and a path that matches
            # nothing is only a WARNING -- the run still exits 0 on a suite of silence-only
            # expectations. Copying the rules in beside the generated suite keeps the path
            # trivially correct, and the warning is treated as failure below regardless.
            shutil.copy(RULES_PATH, workspace / RULES_PATH.name)
            suite = {
                "rule_files": [RULES_PATH.name],
                "evaluation_interval": "1m",
                "tests": cases,
            }
            suite_path = workspace / "generated.test.yml"
            suite_path.write_text(yaml.safe_dump(suite, sort_keys=False), encoding="utf-8")

            completed = subprocess.run(
                [self.promtool, "test", "rules", suite_path.name],
                cwd=workspace, capture_output=True, text=True, check=False,
            )

        output = completed.stdout + completed.stderr
        self.assertNotIn("no file match pattern", output,
                         "the rules file was not loaded, so every silence expectation was vacuous")
        self.assertEqual(0, completed.returncode, output)

    def test_a_site_that_never_evaluated_fencing_is_seen_by_exactly_one_rule(self):
        """The restart state, pinned: both regressions this file exists for live here.

        Before the first evaluation, lease_held and last_check_seconds are ABSENT by design --
        a zero there cannot be told apart from a lease just lost, so LeaseLost would page on
        every restart. Absence buys that, and costs the other direction: `time()` minus a
        series that does not exist matches nothing, so EvaluationStale cannot fire either.

        That leaves a site whose fencing never evaluated invisible to both rules while
        appearing to be watched by two, which is why regalia_fencing_evaluated is emitted at 0
        instead of the series simply being dropped. Exactly one rule must see this state.
        """
        rules = alert_rules()
        never_evaluated = {
            "name": "fencing configured but never evaluated",
            "interval": "1m",
            # evaluated is emitted at 0; the other two gauges do not exist yet.
            "input_series": [
                {"series": "regalia_fencing_evaluated", "values": "0+0x10"},
            ],
            "alert_rule_test": [
                {
                    "eval_time": "400s",
                    "alertname": "RegaliaFencingNeverEvaluated",
                    "exp_alerts": [{
                        "exp_labels": {
                            "alertname": "RegaliaFencingNeverEvaluated",
                            **rules["RegaliaFencingNeverEvaluated"].get("labels", {}),
                        },
                        "exp_annotations": rules["RegaliaFencingNeverEvaluated"]["annotations"],
                    }],
                },
                # A restart must not page. This is the regression that would have woken
                # somebody on every deploy.
                {"eval_time": "400s", "alertname": "RegaliaNoActiveSite", "exp_alerts": []},
                # And the stale rule genuinely cannot see this state, which is why the one
                # above has to.
                {"eval_time": "400s", "alertname": "RegaliaFencingEvaluationStale",
                 "exp_alerts": []},
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy(RULES_PATH, workspace / RULES_PATH.name)
            suite_path = workspace / "fencing.test.yml"
            suite_path.write_text(yaml.safe_dump({
                "rule_files": [RULES_PATH.name],
                "evaluation_interval": "1m",
                "tests": [never_evaluated],
            }, sort_keys=False), encoding="utf-8")
            completed = subprocess.run(
                [self.promtool, "test", "rules", suite_path.name],
                cwd=workspace, capture_output=True, text=True, check=False,
            )

        output = completed.stdout + completed.stderr
        self.assertNotIn("no file match pattern", output, "the rules file was not loaded")
        self.assertEqual(0, completed.returncode, output)



class FencingAcrossSites(unittest.TestCase):
    """RegaliaNoActiveSite and RegaliaTwoActiveSites judge the sites of one job together (#432), counting a site as holding
    only while its verdict is fresh (evaluated in the last 60 s): a planned switchover does not page, an idle old site that
    still exports held=1 after its lease expired is not a second active site (48's read), and one cluster's sites are never
    judged with another's."""

    def setUp(self):
        self.promtool = shutil.which("promtool")
        if self.promtool is None:
            if REQUIRE_PROMTOOL:
                self.fail("promtool is required in this job and was not found on PATH")
            self.skipTest("promtool not installed; set ALERT_RULES_JOB=1 to require it")

    def run_suite(self, tests):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy(RULES_PATH, workspace / RULES_PATH.name)
            (workspace / "sites.test.yml").write_text(yaml.safe_dump(
                {"rule_files": [RULES_PATH.name], "evaluation_interval": "1m", "tests": tests}, sort_keys=False), encoding="utf-8")
            completed = subprocess.run([self.promtool, "test", "rules", "sites.test.yml"], cwd=workspace,
                                       capture_output=True, text=True, check=False)
        output = completed.stdout + completed.stderr
        self.assertNotIn("no file match pattern", output)
        self.assertEqual(0, completed.returncode, output)

    @staticmethod
    def site(labels, held, checked):
        """A site's two series: held, and when it last evaluated ("0+60xN" follows promtool's time(): fresh)."""
        return [{"series": series("regalia_fencing_lease_held", labels), "values": held},
                {"series": series("regalia_fencing_last_check_seconds", labels), "values": checked}]

    def expected(self, name, job):
        rule = alert_rules()[name]
        return [{"exp_labels": {"alertname": name, **rule["labels"], "job": job},
                 "exp_annotations": {k: render(v, {"job": job}) for k, v in rule["annotations"].items()}}]

    def test_a_planned_switchover_does_not_page_and_clusters_are_judged_apart(self):
        a, b, c = ({"job": "regalia-kms", "instance": i} for i in ("a", "b", "c"))
        other = {"job": "regalia-kms-other", "instance": "x"}
        fresh = "0+60x40"
        self.run_suite([
            {"name": "a switchover: a holds, no site for 12 minutes, then b", "interval": "1m",
             "input_series": self.site(a, "1+0x5 0+0x35", fresh) + self.site(b, "0+0x17 1+0x23", fresh),
             "alert_rule_test": [{"eval_time": "25m", "alertname": "RegaliaNoActiveSite", "exp_alerts": []},
                                 {"eval_time": "25m", "alertname": "RegaliaTwoActiveSites", "exp_alerts": []}]},
            {"name": "two clusters: only the one where no site holds", "interval": "1m",
             "input_series": self.site(a, "1+0x30", fresh) + self.site(c, "0+0x30", fresh) + self.site(other, "0+0x30", fresh),
             "alert_rule_test": [{"eval_time": "23m", "alertname": "RegaliaNoActiveSite",
                                  "exp_alerts": self.expected("RegaliaNoActiveSite", "regalia-kms-other")}]},
            {"name": "two clusters, each with one holder: never two active", "interval": "1m",
             "input_series": self.site(a, "1+0x5", fresh) + self.site(other, "1+0x5", fresh),
             "alert_rule_test": [{"eval_time": "3m", "alertname": "RegaliaTwoActiveSites", "exp_alerts": []}]},
        ])

    def test_an_idle_old_site_still_exporting_held_is_not_a_second_site(self):
        """48's read: the daemon evaluates on Ready(), not on a timer. The old site, idle since its lease expired at minute
        5, still exports held=1 with its last evaluation at minute 5; the new site is promoted at minute 7 (expiry plus the
        60 s skew, plus the promote). No "two sites"; and no "no site" either while the new one holds. But with NO fresh
        holder at all (the old site idle and stale, nobody promoted) "no site" pages: a stale held=1 does not hide it."""
        a, b = ({"job": "regalia-kms", "instance": i} for i in ("a", "b"))
        stale_after_5 = "0+60x5 300+0x30"           # evaluated until minute 5, then nobody asks it
        self.run_suite([
            {"name": "old site idle after expiry, new site promoted", "interval": "1m",
             "input_series": self.site(a, "1+0x35", stale_after_5) + self.site(b, "0+0x6 1+0x29", "0+60x35"),
             "alert_rule_test": [{"eval_time": "10m", "alertname": "RegaliaTwoActiveSites", "exp_alerts": []},
                                 {"eval_time": "30m", "alertname": "RegaliaNoActiveSite", "exp_alerts": []}]},
            {"name": "old site idle and stale, nobody promoted: no site", "interval": "1m",
             "input_series": self.site(a, "1+0x35", stale_after_5) + self.site(b, "0+0x35", "0+60x35"),
             "alert_rule_test": [{"eval_time": "30m", "alertname": "RegaliaNoActiveSite",
                                  "exp_alerts": self.expected("RegaliaNoActiveSite", "regalia-kms")}]},
        ])

if __name__ == "__main__":
    unittest.main()
