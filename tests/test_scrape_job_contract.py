"""The scrape job the rules select and the one MONITORING.md tells the monitoring service to configure are one name.

A missing or mismatched job on an up selector makes alerts go blind or refer to unrelated targets.
The composite file may explicitly select the daemon as well as the exporter. Each composite alert
has its own expected set of up jobs.

Also: the image enables exactly the registry's trails (image/units-enabled.txt, [per-host], regalia-kms-r1s.8: on a
verity host an operator's `systemctl enable` is gone at the next boot), and README's `systemctl start` command, which
starts them without a reboot, names exactly the same, one instance per line and no brace expansion (sh would pass the
braces through), so every trail is shipped (one left out raises RegaliaAuditShipMetricsMissing for ever).
"""

import pathlib
import re
import unittest

import yaml

from deploy.baremetal import trails

ROOT = pathlib.Path(__file__).resolve().parents[1]

MONITORING = ROOT / "deploy" / "baremetal" / "MONITORING.md"
README = ROOT / "deploy" / "baremetal" / "README.md"
RULE_FILES = sorted((ROOT / "deploy" / "monitoring").glob("*.rules.yml"))

DOCUMENTED_NODE = re.compile(r"\*\*The scrape job is `([^`]+)`\.\*\*")
DOCUMENTED_KMS = re.compile(r"\*\*The daemon scrape job is `([^`]+)`\.\*\*")
DOCUMENTED_COLLECTOR = re.compile(r"\*\*The collector scrape job is `([^`]+)`\.\*\*")
COMPOSITE = "regalia-single-node.rules.yml"
# Every composite (single-node) alert's up selectors, by job. The behind-collector rules compare
# against the collector's witness and select no up (their applicability is the node's own series,
# not a scrape's liveness); the collector's blind-state and the pending-file rules select the node
# exporter (the scraped target whose series or file is absent). regalia-kms-dx7.9.
UP_JOBS = {
    "RegaliaSingleNodeDown": {"regalia-node", "regalia-kms"},
    "RegaliaTopologyProfileInvalid": {"regalia-node", "regalia-kms"},
    "RegaliaTopologyMetricMissing": {"regalia-node"},
    "RegaliaTopologyProfileMismatch": {"regalia-node"},
    "RegaliaMembershipBehindCollector": set(),
    "RegaliaAnchorBehindCollector": set(),
    "RegaliaCollectorEpochMissing": {"regalia-node"},
    "RegaliaCollectorAnchorEpochMissing": {"regalia-node"},
    "RegaliaCollectorWitnessUnreadable": {"regalia-node"},
    "RegaliaNextBootCannotRender": set(),
    "RegaliaNextBootNeedsOwner": set(),
    "RegaliaRestorePending": set(),
    "RegaliaRestoreMetricsMissing": {"regalia-node"},
}
UP_SELECTOR = re.compile(r"(?<![\w:])up(?![\w:])\s*(\{[^}]*\})?")
# any matcher on the job label: =, !=, =~, !~, quoted either way
JOB_MATCHER = re.compile(r"""\bjob\s*(=~|!~|!=|=)\s*(["'])(.*?)\2""")
START = re.compile(r"systemctl start \\\n((?:    regalia-audit-ship@[a-z-]+(?: \\)?\n)+)")
UNITS_ENABLED = ROOT / "deploy" / "baremetal" / "image" / "units-enabled.txt"


def rule_expressions():
    for path in RULE_FILES:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for rule in group["rules"]:
                yield path.name, rule.get("alert") or rule.get("record"), str(rule["expr"])


class ScrapeJobContract(unittest.TestCase):
    def test_the_rules_select_the_documented_job(self):
        doc = MONITORING.read_text(encoding="utf-8")
        self.assertEqual(DOCUMENTED_NODE.findall(doc), ["regalia-node"])
        self.assertEqual(DOCUMENTED_KMS.findall(doc), ["regalia-kms"])
        # The single-node behind rules (regalia-kms-dx7.9, D1=A) compare a node against the audit
        # collector's own witness, scraped on the owner's monitoring service under its own job.
        self.assertEqual(DOCUMENTED_COLLECTOR.findall(doc), ["regalia-collector"])
        matchers = [(file, alert, op, value)
                    for file, alert, expr in rule_expressions()
                    for op, _, value in JOB_MATCHER.findall(expr)]
        self.assertTrue(matchers, "no rule selects a job: the pattern no longer matches the rules")
        wrong = [m for m in matchers if m[2] != "="
                 or (m[3] != "regalia-node"
                     and (m[0], m[3]) != (COMPOSITE, "regalia-kms")
                     and (m[0], m[3]) != (COMPOSITE, "regalia-collector"))]
        self.assertEqual(wrong, [], "job matchers must use exact documented job identities")

    def test_every_up_selector_names_the_job(self):
        composite = {}
        for file, alert, expr in rule_expressions():
            jobs = set()
            for selector in UP_SELECTOR.findall(expr):
                terms = JOB_MATCHER.findall(selector)
                self.assertEqual(len(terms), 1, f"{file}/{alert}: up must name one explicit job")
                operator, _, job = terms[0]
                self.assertEqual(operator, "=", f"{file}/{alert}: up must have an exact job")
                jobs.add(job)
            if file == COMPOSITE:
                composite[alert] = jobs
            elif jobs:
                self.assertEqual(jobs, {"regalia-node"}, f"{file}/{alert}: up must select the exporter job")
        self.assertEqual(composite, UP_JOBS, "composite up selectors must address each alert's exact jobs")


class ShipperEnableList(unittest.TestCase):
    def test_the_readme_starts_every_trail(self):
        lines = START.findall(README.read_text(encoding="utf-8"))
        self.assertEqual(len(lines), 1, "README must give the start line exactly once")
        self.assertEqual(sorted(re.findall(r"regalia-audit-ship@([a-z-]+)", lines[0])), sorted(trails.TRAILS))
    def test_the_image_enables_every_trail(self):
        section, enabled = None, []
        for line in UNITS_ENABLED.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if re.fullmatch(r"\[[a-z-]+\]", line):
                section = line[1:-1]
            elif section == "per-host" and line and not line.startswith("#"):
                enabled.append(line.split(" | ")[1])
        self.assertEqual(sorted(re.findall(r"^regalia-audit-ship@([a-z-]+)\.service$", "\n".join(enabled), re.M)), sorted(trails.TRAILS))


if __name__ == "__main__":
    unittest.main()
