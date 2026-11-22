"""Evaluate the external single-node monitoring contract with Prometheus itself."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.test_alert_firing import REQUIRE_PROMTOOL, render, series

RULE_DIR = Path(__file__).resolve().parents[1] / "deploy" / "monitoring"
DOWN = "RegaliaSingleNodeDown"
PROFILE = "RegaliaTopologyProfileInvalid"
MISSING = "RegaliaTopologyMetricMissing"
MISMATCH = "RegaliaTopologyProfileMismatch"
OWNER = "RegaliaOwnerAssistedReboot"
NODE = {"job": "regalia-node", "instance": "a:9100", "topology_profile": "single-node"}
KMS = {"job": "regalia-kms", "instance": "a:8443", "topology_profile": "single-node"}
LEASE = "/run/regalia-metrics/admission/lease.prom"
ALERTS = {DOWN: "critical", PROFILE: "warning", MISSING: "warning", MISMATCH: "warning", OWNER: "info"}


def health(labels, *, up="1+0x40", value="1+0x40", stamp="0+60x40", path=LEASE):
    node = labels["job"] == "regalia-node"
    status = "regalia_admission_serving" if node else "regalia_ready"
    freshness = "node_textfile_mtime_seconds" if node else "regalia_readiness_last_check_seconds"
    timestamp_labels = dict(labels, file=path) if node else labels
    return [("up", labels, up)] + ([(status, labels, value)] if value else []) + (
        [(freshness, timestamp_labels, stamp)] if stamp else [])


def case(title, inputs, alert, expected=(), at="6m"):
    return title, inputs, alert, expected, at


def cases():
    # No samples from either endpoint are required to page, including after
    # Prometheus's normal five-minute instant-vector lookback has elapsed.
    for endpoint, other in ((NODE, KMS), (KMS, NODE)):
        failed = [("up", endpoint, "0+0x40")] + health(other)
        yield case(f"{endpoint['job']} never scraped successfully", failed, DOWN, [endpoint], "0m")
        yield case(f"{endpoint['job']} prolonged outage", failed, DOWN, [endpoint], "30m")
        yield case(f"{endpoint['job']} outage after last good series expire",
                   health(endpoint, up="1 0+0x39", value="1 stale", stamp="0 stale") + health(other),
                   DOWN, [endpoint], "30m")
        for label, settings in (
            ("missing state", {"value": None}), ("false state", {"value": "0+0x40"}),
            ("missing timestamp", {"stamp": None}), ("stale timestamp", {"stamp": "60+0x40"}),
            ("future timestamp", {"stamp": "600+60x40"}),
        ):
            yield case(f"{endpoint['job']} {label}", health(endpoint, **settings) + health(other), DOWN, [endpoint])
        boundary_samples = health(endpoint, stamp="240+0x40") + health(other)
        yield case(f"{endpoint['job']} exactly 120 seconds is fresh", boundary_samples, DOWN)
        yield case(f"{endpoint['job']} at 121 seconds pages",
                   health(endpoint, stamp="239+0x40") + health(other), DOWN, [endpoint])
        for wrong in (dict(endpoint, job="unrelated"), dict(endpoint, instance="other:1234")):
            # Inject the right metric names with the wrong match keys.
            foreign = [(name, {**labels, **wrong}, samples)
                       for name, labels, samples in health(endpoint)[1:]]
            for broken in ("value", "stamp"):
                yield case(f"{endpoint['job']} {broken} cannot match {wrong['job']}/{wrong['instance']}",
                           health(endpoint, **{broken: None}) + health(other) + foreign, DOWN, [endpoint])

    yield case("simultaneous down endpoints stay distinct",
               [("up", labels, "0+0x40") for labels in (NODE, KMS)], DOWN, [NODE, KMS])
    for lease_path in (LEASE, "lease.prom", "admission/lease.prom"):
        yield case(f"healthy single: {lease_path}", health(NODE, path=lease_path) + health(KMS)
                   + [("regalia_topology_nodes", NODE, "1+0x40")], DOWN)
    yield case("other textfile cannot mask a missing lease mtime",
               health(NODE, path="admission/unrelated.prom") + health(KMS), DOWN, [NODE])
    for profile in ("multi-node", None):
        labels = {k: v for k, v in NODE.items() if k != "topology_profile"}
        if profile is not None:
            labels["topology_profile"] = profile
        yield case(f"healthy {profile or 'legacy'} target", health(labels), DOWN)
        yield case(f"{profile or 'legacy'} target keeps its delayed outage coverage",
                   [("up", labels, "0+0x40")], "RegaliaNodeExporterDown", [labels])

    for endpoint in (NODE, KMS):
        legacy = {k: v for k, v in endpoint.items() if k != "topology_profile"}
        invalid = dict(endpoint, topology_profile="typo")
        for label, target in (("missing", legacy), ("invalid", invalid)):
            samples = [("up", target, "0+0x40")]
            yield case(f"{endpoint['job']} {label} metadata waits five minutes", samples, PROFILE, at="4m")
            yield case(f"{endpoint['job']} {label} metadata warns even when down", samples, PROFILE, [target], "5m")
        yield case(f"{endpoint['job']} valid metadata is quiet", [("up", endpoint, "1+0x40")], PROFILE)

    multi = dict(NODE, topology_profile="multi-node")
    for target, wrong, correct in ((NODE, 3, 1), (multi, 1, 3)):
        name = target["topology_profile"]
        no_metric = [("up", target, "1+0x40")]
        conflicting = no_metric + [("regalia_topology_nodes", target, f"{wrong}+0x40")]
        yield case(f"{name} missing topology waits", no_metric, MISSING, at="4m")
        yield case(f"{name} missing topology warns", no_metric, MISSING, [target], "5m")
        yield case(f"{name} down target has no live topology expectation", [("up", target, "0+0x40")], MISSING)
        yield case(f"{name} mismatching topology waits", conflicting, MISMATCH, at="4m")
        yield case(f"{name} mismatching topology warns", conflicting, MISMATCH, [target], "5m")
        yield case(f"{name} matching topology is quiet", no_metric
                   + [("regalia_topology_nodes", target, f"{correct}+0x40")], MISMATCH)
    yield case("missing topology is not a conflicting value",
               [("up", NODE, "1+0x40")], MISMATCH)

    legacy = {"job": "regalia-node", "instance": "legacy:9100"}
    mislabeled = dict(NODE, topology_profile="multi-node")
    unknown = {k: v for k, v in NODE.items() if k != "topology_profile"}
    for metric, alert in (("regalia_membership_epoch", "RegaliaMembershipBehindFleet"),
                          ("regalia_esp_anchor_epoch", "RegaliaAnchorBehindFleet")):
        for target, topology in ((mislabeled, 1), (unknown, 1), (NODE, None)):
            for value, other, side in ((1, 3, "left"), (3, 1, "max")):
                inputs = [(metric, target, f"{value}+0x40"), (metric, legacy, f"{other}+0x40")]
                if topology is not None:
                    inputs.append(("regalia_topology_nodes", target, "1+0x40"))
                yield case(f"{alert} excludes {target.get('topology_profile')} topology {topology} from {side}",
                           inputs, alert, at="32m")

    for specific, signal, value in (("RegaliaSurvivorRecoveryActive", "regalia_admission_recovery", 1),
                                    ("RegaliaNextBootNeedsRecoveryKey", "regalia_esp_boot_renderable", 0)):
        yield case(f"{specific} suppressed on verified single despite wrong metadata",
                   [(signal, mislabeled, f"{value}+0x40"), ("regalia_topology_nodes", mislabeled, "1+0x40")], specific)
        yield case(f"{specific} keeps wrong-static-single verified multi coverage",
                   [(signal, NODE, f"{value}+0x40"), ("regalia_topology_nodes", NODE, "3+0x40")], specific, [NODE])
    yield case("owner info requires live verified size one",
               [("regalia_topology_nodes", mislabeled, "1+0x40"),
                ("regalia_topology_nodes", dict(NODE, instance="multi:9100"), "3+0x40"),
                ("up", dict(NODE, instance="unverified:9100"), "1+0x40")], OWNER, [mislabeled])
    for name, signal, labels in (("RegaliaNodeExporterDown", "up", NODE),
                                 ("RegaliaNotServing", "regalia_admission_serving", NODE),
                                 ("RegaliaNotReady", "regalia_ready", KMS)):
        legacy = {k: v for k, v in labels.items() if k != "topology_profile"}
        yield case(f"{name} delays only the legacy copy of the page",
                   [(signal, labels, "0+0x40"), (signal, legacy, "0+0x40")], name, [legacy])
    for alert, left, expected in (("RegaliaHeartbeatRunningOut", 1499, True),
                                  ("RegaliaHeartbeatRunningOut", 1500, False),
                                  ("RegaliaHeartbeatAboutToExpire", 749, True),
                                  ("RegaliaHeartbeatAboutToExpire", 750, False)):
        yield case(f"{alert} on 3000s self-renewed life with {left}s left",
                   [("regalia_heartbeat_live", NODE, "1+0x40"),
                    ("regalia_heartbeat_lifetime_seconds", NODE, "3000+0x40"),
                    ("regalia_heartbeat_seconds_left", NODE, f"{left}+0x40")], alert, [NODE] if expected else [])


class SingleNodeAlertFiring(unittest.TestCase):
    def test_profiles_and_health_at_real_promtool_evaluation(self):
        promtool = shutil.which("promtool")
        if promtool is None:
            if REQUIRE_PROMTOOL:
                self.fail("promtool is required in this job")
            self.skipTest("promtool is required for PromQL evaluation")
        names = ["regalia-node.rules.yml", "regalia-kms.rules.yml", "regalia-single-node.rules.yml"]
        paths = [RULE_DIR / name for name in names if (RULE_DIR / name).is_file()]
        rules = {rule["alert"]: rule for path in paths for group in yaml.safe_load(path.read_text())["groups"]
                 for rule in group["rules"] if "alert" in rule}
        scenarios = []
        for title, inputs, alert, expected, at in cases():
            rule = rules.get(alert, {})
            severity = ALERTS.get(alert) or rule["labels"]["severity"]
            annotations = rule.get("annotations", {})
            scenarios.append({
                "name": title, "interval": "1m",
                "input_series": [{"series": series(metric, labels), "values": value} for metric, labels, value in inputs],
                "alert_rule_test": [{"eval_time": at, "alertname": alert, "exp_alerts": [
                    {"exp_labels": {**labels, "alertname": alert, "severity": severity},
                     "exp_annotations": {k: render(v, labels) for k, v in annotations.items()}}
                    for labels in expected]}],
            })
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            for path in paths:
                shutil.copy(path, workspace / path.name)
            (workspace / "cases.yml").write_text(yaml.safe_dump({
                "rule_files": [p.name for p in paths], "evaluation_interval": "1m", "tests": scenarios}))
            done = subprocess.run([promtool, "test", "rules", "cases.yml"], cwd=workspace, capture_output=True, text=True)
        output = done.stdout + done.stderr
        self.assertNotIn("no file match pattern", output)
        self.assertEqual(done.returncode, 0, output)
