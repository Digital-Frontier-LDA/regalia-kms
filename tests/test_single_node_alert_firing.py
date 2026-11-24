"""Evaluate the external single-node monitoring contract with Prometheus itself (regalia-kms-dx7.9).

Every rule in regalia-single-node.rules.yml gets a fault that must fire it and a healthy state that
must not. In addition, the CROSS-PROFILE MATRIX holds the two rule files to each other: every rule
in regalia-node.rules.yml and regalia-kms.rules.yml is fed a healthy-but-single-node fixture (one
node, topology_profile="single-node") and the multi-node-only rules must stay silent even when
faulted, and every rule in regalia-single-node.rules.yml is faulted on a multi-node fixture and must
stay silent. A rule that matches across profiles would page a healthy one-node installation, or
blind a multi-node cluster; the matrix is the pin.
"""
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
BEHIND_M = "RegaliaMembershipBehindCollector"
BEHIND_A = "RegaliaAnchorBehindCollector"
EPOCH_MISSING = "RegaliaCollectorEpochMissing"
CANNOT_RENDER = "RegaliaNextBootCannotRender"
OWNER = "RegaliaNextBootNeedsOwner"
RESTORE = "RegaliaRestorePending"
RESTORE_MISSING = "RegaliaRestoreMetricsMissing"
NODE = {"job": "regalia-node", "instance": "a:9100", "topology_profile": "single-node"}
KMS = {"job": "regalia-kms", "instance": "a:8443", "topology_profile": "single-node"}
# The collector endpoint labels the reference by the node's own site; the scrape job adds its own
# job and relabels site to instance, so the reference series carries the node's instance under the
# collector's job. The comparisons in regalia-single-node.rules.yml match on that instance,
# ignoring job.
COLLECTOR = {"job": "regalia-collector", "instance": "a:9100"}
MULTI = {"job": "regalia-node", "instance": "b:9100", "topology_profile": "multi-node"}
LEASE = "/run/regalia-metrics/admission/lease.prom"
ALERTS = {DOWN: "critical", PROFILE: "warning", MISSING: "warning", MISMATCH: "warning",
          BEHIND_M: "warning", BEHIND_A: "warning", EPOCH_MISSING: "warning", CANNOT_RENDER: "warning",
          OWNER: "info", RESTORE: "critical", RESTORE_MISSING: "warning"}


def health(labels, *, up="1+0x40", value="1+0x40", stamp="0+60x40", path=LEASE):
    node = labels["job"] == "regalia-node"
    status = "regalia_admission_serving" if node else "regalia_ready"
    freshness = "node_textfile_mtime_seconds" if node else "regalia_readiness_last_check_seconds"
    timestamp_labels = dict(labels, file=path) if node else labels
    return [("up", labels, up)] + ([(status, labels, value)] if value else []) + (
        [(freshness, timestamp_labels, stamp)] if stamp else [])


def case(title, inputs, alert, expected=(), at="6m"):
    return title, inputs, alert, expected, at


def witness(healthy=True):
    """The collector's two reference series for the single-node target, at the same epoch (caught up)."""
    epoch = "5+0x40"
    return [("regalia_collector_witnessed_membership_epoch", COLLECTOR, epoch),
            ("regalia_collector_witnessed_anchor_epoch", COLLECTOR, epoch)]


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
                # Applicability is external inventory, not a sync-written value.
                # With multi/legacy metadata, sync cannot hide a lagging node or
                # remove the maximum that makes another node's lag observable.
                expected = [] if target.get("topology_profile") == "single-node" else [target if value < other else legacy]
                yield case(f"{alert} uses inventory for {target.get('topology_profile')} topology {topology} on {side}",
                           inputs, alert, expected, at="32m")
                if topology is not None:
                    pulse_inputs = inputs[:-1] + [("regalia_topology_nodes", target, "3+0x9 1 3+0x30")]
                    yield case(f"{alert} sync topology cannot reset pending {side} for {target.get('topology_profile')}",
                               pulse_inputs, alert, expected, at="32m")

    for specific, signal, value in (("RegaliaSurvivorRecoveryActive", "regalia_admission_recovery", 1),
                                    ("RegaliaNextBootNeedsRecoveryKey", "regalia_esp_boot_renderable", 0)):
        for target in (mislabeled, unknown):
            yield case(f"{specific} sync topology cannot suppress {target.get('topology_profile', 'legacy')} inventory",
                       [(signal, target, f"{value}+0x40"), ("regalia_topology_nodes", target, "1+0x40")], specific, [target])
        yield case(f"{specific} uses single inventory despite contradictory sync telemetry",
                   [(signal, NODE, f"{value}+0x40"), ("regalia_topology_nodes", NODE, "3+0x40")], specific)

    # The owner-presence info rule, moved here from regalia-node.rules.yml as RegaliaNextBootNeedsOwner
    # (regalia-kms-dx7.9), keyed on the external inventory. The multi-node target is labeled
    # multi-node, so the rule's single-node matcher is the whole test: it must not match it.
    yield case("owner info requires single inventory and live verified size one",
               [("regalia_topology_nodes", mislabeled, "1+0x40"),
                ("regalia_topology_nodes", NODE, "1+0x40"),
                ("up", dict(NODE, instance="unverified:9100"), "1+0x40")], OWNER, [NODE])
    yield case("owner info is silent on a multi-node target of size one",
               [("regalia_topology_nodes", MULTI, "1+0x40")], OWNER)

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

    # BEHIND THE COLLECTOR (regalia-kms-dx7.9, D1=A): the node's own chain against the collector's
    # witness. The reference is the off-host job regalia-collector's, never the node's own telemetry.
    # The comparison is written with the collector's witness on the left, so the alert's labels
    # are the reference's: the node's instance, under the collector's job (not the node's job,
    # and no topology_profile). The summary renders from exactly that label set.
    for metric, alert in (("regalia_membership_epoch", BEHIND_M), ("regalia_esp_anchor_epoch", BEHIND_A)):
        behind_labels = {"instance": NODE["instance"]}
        # the fault: the node holds an older epoch than the witness committed, and stays there
        yield case(f"{alert}: the node lags the witness",
                   [(metric, NODE, "4+0x40"), ("regalia_collector_witnessed_"
                     + ("membership" if metric == "regalia_membership_epoch" else "anchor") + "_epoch", COLLECTOR, "5+0x40")],
                   alert, [behind_labels], at="32m")
        # the boundary: equal is caught up, whatever the hold (the <= mutant fires here)
        yield case(f"{alert}: equal to the witness is caught up",
                   [(metric, NODE, "5+0x40"), ("regalia_collector_witnessed_"
                     + ("membership" if metric == "regalia_membership_epoch" else "anchor") + "_epoch", COLLECTOR, "5+0x40")],
                   alert, at="32m")
        # a new epoch reaches the node first: the node is AHEAD of what it has shipped so far,
        # and the reference catches up with the trail; no alert
        yield case(f"{alert}: ahead of the witness is quiet",
                   [(metric, NODE, "6+0x40"), ("regalia_collector_witnessed_"
                     + ("membership" if metric == "regalia_membership_epoch" else "anchor") + "_epoch", COLLECTOR, "5+0x40")],
                   alert, at="32m")
        # the reference is per instance: a second, higher reference for another node does not
        # implicate this one (the match is one-to-one on instance, ignoring job)
        yield case(f"{alert}: another site's reference cannot implicate this node",
                   [(metric, NODE, "5+0x40"),
                    ("regalia_collector_witnessed_"
                     + ("membership" if metric == "regalia_membership_epoch" else "anchor") + "_epoch", COLLECTOR, "5+0x40"),
                    ("regalia_collector_witnessed_"
                     + ("membership" if metric == "regalia_membership_epoch" else "anchor") + "_epoch",
                     dict(COLLECTOR, instance="b:9100"), "9+0x40")], alert)

    # THE BLIND STATE: the scraped target has no collector reference at all.
    yield case("collector reference absent waits fifteen minutes",
               [("up", NODE, "1+0x40")], EPOCH_MISSING, at="14m")
    yield case("collector reference absent warns after fifteen",
               [("up", NODE, "1+0x40")], EPOCH_MISSING, [NODE], "16m")
    yield case("a witnessed reference suppresses the blind-state warning",
               [("up", NODE, "1+0x40")] + witness(), EPOCH_MISSING)
    yield case("a multi-node target has no blind-state expectation",
               [("up", MULTI, "1+0x40")], EPOCH_MISSING)

    # THE UNRENDERABLE ESP: regalia-esp-advance writes it on every run, success or not.
    yield case("an unrenderable ESP under single-node warns at once",
               [("regalia_esp_boot_renderable", NODE, "0+0x40")], CANNOT_RENDER, [NODE], "1m")
    yield case("a renderable ESP under single-node is quiet",
               [("regalia_esp_boot_renderable", NODE, "1+0x40")], CANNOT_RENDER)
    yield case("a multi-node target's unrenderable ESP is not this rule's",
               [("regalia_esp_boot_renderable", MULTI, "0+0x40")], CANNOT_RENDER)

    # THE RESTORE-PENDING BOOT GUARD: the marker holds etcd and the daemon SKIPPED; the page names the cause.
    yield case("restore pending pages the held host",
               [("regalia_restore_pending", NODE, "1+0x40")], RESTORE, [NODE], "1m")
    yield case("no marker is quiet",
               [("regalia_restore_pending", NODE, "0+0x40")], RESTORE)
    yield case("a multi-node target's marker is not this rule's",
               [("regalia_restore_pending", MULTI, "1+0x40")], RESTORE)
    # A FILE THAT IS NOT THERE MUST ALERT TOO: a scraped single-node target with no pending.prom.
    yield case("pending metrics file absent waits five minutes",
               [("up", NODE, "1+0x40")], RESTORE_MISSING, at="4m")
    yield case("pending metrics file absent warns after five",
               [("up", NODE, "1+0x40")], RESTORE_MISSING, [NODE], "6m")
    yield case("pending metrics file present is quiet",
               [("up", NODE, "1+0x40"),
                ("node_textfile_mtime_seconds", dict(NODE, file="/run/regalia-metrics/restore/pending.prom"), "0+60x10")],
               RESTORE_MISSING)
    yield case("a multi-node target has no pending file expectation",
               [("up", MULTI, "1+0x40")], RESTORE_MISSING)


def cross_profile_matrix():
    """Every rule in the three files, faulted or healthy on the OPPOSITE profile's fixture.

    A multi-node-only rule must stay silent on a single-node fixture even when its fault is
    present (the exclusion is the inventory label, not the telemetry), and every single-node rule
    must stay silent on a multi-node fixture. The fixtures are the rules' own faults from the
    firing files above, relabeled with the other profile's inventory.
    """
    scenarios = []
    # multi-node-only rules, faulted on a single-node fixture: must stay silent
    for alert, fault in (
        ("RegaliaMembershipBehindFleet", [("regalia_membership_epoch", NODE, "4+0x40"),
                                          ("regalia_membership_epoch", {"job": "regalia-node", "instance": "z:9100",
                                                                       "topology_profile": "single-node"}, "5+0x40")]),
        ("RegaliaAnchorBehindFleet", [("regalia_esp_anchor_epoch", NODE, "4+0x40"),
                                      ("regalia_esp_anchor_epoch", {"job": "regalia-node", "instance": "z:9100",
                                                                   "topology_profile": "single-node"}, "5+0x40")]),
        ("RegaliaSurvivorRecoveryActive", [("regalia_admission_recovery", NODE, "1+0x40")]),
        ("RegaliaNextBootNeedsRecoveryKey", [("regalia_esp_boot_renderable", NODE, "0+0x40")]),
        ("RegaliaNotServing", [("regalia_admission_serving", NODE, "0+0x40")]),
        ("RegaliaNodeExporterDown", [("up", NODE, "0+0x40")]),
        ("RegaliaNotReady", [("regalia_ready", KMS, "0+0x40")]),
    ):
        scenarios.append(("matrix: " + alert + " stays silent on a single-node fixture", fault, alert, [],
                          "32m" if alert in ("RegaliaMembershipBehindFleet", "RegaliaAnchorBehindFleet", "RegaliaNodeExporterDown",
                                            "RegaliaNotServing", "RegaliaNotReady") else "6m"))
    # single-node rules, faulted on a multi-node fixture: must stay silent
    for alert, fault in (
        (BEHIND_M, [("regalia_membership_epoch", MULTI, "4+0x40"),
                    ("regalia_collector_witnessed_membership_epoch", COLLECTOR, "5+0x40")]),
        (BEHIND_A, [("regalia_esp_anchor_epoch", MULTI, "4+0x40"),
                    ("regalia_collector_witnessed_anchor_epoch", COLLECTOR, "5+0x40")]),
        (EPOCH_MISSING, [("up", MULTI, "1+0x40")]),
        (CANNOT_RENDER, [("regalia_esp_boot_renderable", MULTI, "0+0x40")]),
        (OWNER, [("regalia_topology_nodes", MULTI, "1+0x40")]),
        (RESTORE, [("regalia_restore_pending", MULTI, "1+0x40")]),
        (RESTORE_MISSING, [("up", MULTI, "1+0x40")]),
    ):
        scenarios.append(("matrix: " + alert + " stays silent on a multi-node fixture", fault, alert, [],
                          "32m" if alert in (BEHIND_M, BEHIND_A, EPOCH_MISSING, RESTORE_MISSING) else "6m"))
    return scenarios


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
        for title, inputs, alert, expected, at in list(cases()) + list(cross_profile_matrix()):
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


if __name__ == "__main__":
    unittest.main()
