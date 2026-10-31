"""The scrape job the rules select and the one MONITORING.md tells the monitoring service to configure are one name.

Every `Regalia…Missing` rule and RegaliaNodeExporterDown select `up{job="regalia-node"}`. If the documented job and
the rules' matcher differ, those rules never fire and nothing reports that they cannot: the service scrapes, the
series arrive, and the alerts that tell a missing writer from a node that is down are silently gone. So the name is
read from the documentation and every `job` matcher in the rule files is held to it.

Also: README's `systemctl enable --now` command names exactly the registry's trails, one instance per line and no
brace expansion (sh would pass the braces through), so a node set up by the README ships every trail (one left out
raises RegaliaAuditShipMetricsMissing for ever).
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

DOCUMENTED = re.compile(r"\*\*The scrape job is `([^`]+)`\.\*\*")
# any matcher on the job label: =, !=, =~, !~, quoted either way
JOB_MATCHER = re.compile(r"""\bjob\s*(=~|!~|!=|=)\s*(["'])(.*?)\2""")
ENABLE = re.compile(r"systemctl enable --now \\\n((?:    regalia-audit-ship@[a-z-]+(?: \\)?\n)+)")


def documented_job():
    names = DOCUMENTED.findall(MONITORING.read_text(encoding="utf-8"))
    if len(names) != 1:
        raise AssertionError("MONITORING.md must state the scrape job exactly once as **The scrape job is `NAME`.**, "
                             "found %d" % len(names))
    return names[0]


def job_matchers():
    """(file, alert, operator, value) for every job matcher in every rule expression."""
    out = []
    for path in RULE_FILES:
        for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
            for rule in group["rules"]:
                for op, _, value in JOB_MATCHER.findall(str(rule["expr"])):
                    out.append((path.name, rule.get("alert") or rule.get("record"), op, value))
    return out


class ScrapeJobContract(unittest.TestCase):
    def test_the_rules_select_the_documented_job(self):
        job = documented_job()
        matchers = job_matchers()
        self.assertTrue(matchers, "no rule selects a job: the pattern no longer matches the rules")
        wrong = [m for m in matchers if m[2] != "=" or m[3] != job]
        self.assertEqual(wrong, [], "every job matcher must be job=\"%s\" (MONITORING.md)" % job)

    def test_every_up_selector_names_the_job(self):
        # an unscoped up{} would count every job the service scrapes, so a node's Missing rule could be satisfied
        # (or fired) by another target on the same instance address
        bare = []
        for path in RULE_FILES:
            for group in yaml.safe_load(path.read_text(encoding="utf-8"))["groups"]:
                for rule in group["rules"]:
                    for sel in re.findall(r"\bup\b(\{[^}]*\})?", str(rule["expr"])):
                        if "job" not in sel:
                            bare.append((path.name, rule.get("alert")))
        self.assertEqual(bare, [])


class ShipperEnableList(unittest.TestCase):
    def test_the_readme_enables_every_trail(self):
        lines = ENABLE.findall(README.read_text(encoding="utf-8"))
        self.assertEqual(len(lines), 1, "README must give the enable line exactly once")
        self.assertEqual(sorted(re.findall(r"regalia-audit-ship@([a-z-]+)", lines[0])), sorted(trails.TRAILS))


if __name__ == "__main__":
    unittest.main()
