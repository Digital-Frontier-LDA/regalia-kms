"""The alert rules and the observability contract must agree about every series.

A rule naming a series nothing emits pages nobody about nothing — it is wrong about
what it watches. A documented series with no rule is decoration: the metric exists,
and nobody will ever be woken by it. Both directions are checked, and both were
verified by deleting a rule (documented series unruled) and adding a phantom rule
(undocumented series referenced) and watching this file fail each time.
"""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "deploy" / "monitoring" / "regalia-kms.rules.yml"
CONTRACT_PATH = ROOT / "OBSERVABILITY.md"

METRIC_REFERENCE = re.compile(r"regalia_[a-z_]+")


def documented_series():
    """Every series in the OBSERVABILITY.md table, with whether it is alert-exempt."""
    rows = {}
    in_table = False
    for line in CONTRACT_PATH.read_text(encoding="utf-8").splitlines():
        if line.startswith("| Series"):
            in_table = True
            continue
        if in_table:
            if not line.startswith("|"):
                break
            if line.startswith("| ---") or line.startswith("| Series"):
                continue
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            name = cells[0].strip("`")
            # A series whose stated condition is "none" is a context gauge and
            # carries no alert by design.
            rows[name] = "none" not in cells[3].lower()
    return rows


def load_rules():
    return yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))


class AlertRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = load_rules()

    def rules(self):
        rules = []
        for group in self.document["groups"]:
            rules.extend(group["rules"])
        return rules

    def test_rules_file_is_structurally_valid(self):
        rules = self.rules()
        self.assertTrue(rules, "no rules were parsed: this test would pass while checking nothing")
        for rule in rules:
            self.assertIn("alert", rule)
            self.assertIn("expr", rule)
            self.assertIn(rule.get("labels", {}).get("severity"), {"warning", "critical"},
                          f"{rule['alert']}: severity must be warning or critical — the pager cannot route anything else")

    def test_every_rule_references_only_documented_series(self):
        for rule in self.rules():
            for name in METRIC_REFERENCE.findall(rule["expr"]):
                self.assertIn(name, documented_series(),
                              f"{rule['alert']} references {name}, which OBSERVABILITY.md does not document: "
                              "a rule about a series nothing emits pages nobody")

    def test_every_documented_series_has_a_rule(self):
        referenced = set()
        for rule in self.rules():
            referenced.update(METRIC_REFERENCE.findall(rule["expr"]))
        for name, needs_alert in documented_series().items():
            if not needs_alert:
                continue
            self.assertIn(name, referenced,
                          f"{name} is documented in OBSERVABILITY.md but no rule alerts on it: "
                          "a metric nobody can alert on is decoration")

    def test_every_documented_alert_condition_names_a_threshold_consistently(self):
        # The doc's staleness pairs: a *_seconds freshness gauge must appear in a
        # rule that subtracts it from time(), or the staleness claim is aspirational.
        for name, needs_alert in documented_series().items():
            if not needs_alert or not name.endswith("_seconds"):
                continue
            matched = any(
                re.search(rf"time\(\)\s*-\s*{re.escape(name)}", rule["expr"]) or name in rule["expr"]
                for rule in self.rules()
            )
            self.assertTrue(matched, f"{name} is a freshness gauge no rule consumes")

    def test_every_fencing_state_has_a_rule_that_can_actually_fire(self):
        """Fencing has three distinguishable bad states and each needs its own rule.

        This is the gap that shipped once. regalia_fencing_lease_held is ABSENT until the
        lease has been evaluated, deliberately: a zero there is byte-identical to a lease
        that was just lost, so a rule on it would page on every restart, and a rule that
        pages on every restart gets silenced. But absence also means the staleness rule
        cannot fire -- time() minus a series that does not exist matches nothing -- so a
        site whose fencing never evaluates at all was watched by no rule while appearing
        to be watched by two.

        Checking that each series is merely referenced somewhere is what missed it. The
        states are what must be covered, so the states are what this asserts.
        """
        expressions = " ".join(rule["expr"] for rule in self.rules())
        for state, series, why in (
            ("never evaluated", "regalia_fencing_evaluated",
             "a site whose lease is never evaluated has an unknown role, not a passive one"),
            ("evaluated and lost", "regalia_fencing_lease_held",
             "the actual lease-loss signal"),
            ("evaluation stopped", "regalia_fencing_last_check_seconds",
             "a held/lost reading that is no longer being refreshed is a stale claim"),
        ):
            self.assertIn(series, expressions,
                          f"no rule watches the {state!r} fencing state ({series}): {why}")

if __name__ == "__main__":
    unittest.main()
