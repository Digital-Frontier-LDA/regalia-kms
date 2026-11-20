"""Named 1ym mutant controls; run through heavy --host heavy-pool-h4i on a disposable checkout.

Only an assertion failure in the named test counts as a kill. Errors, skips and build failures do not.
"""
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests import test_baremetal_boot_render as checks


def unit_control(name, before, after, test, reason):
    original = checks.UNIT.read_text()
    assert original.count(before) == 1, name + ": mutation target drifted"
    with tempfile.TemporaryDirectory() as directory:
        unit = Path(directory) / "render.service"
        unit.write_text(original.replace(before, after))
        output = io.StringIO()
        with patch.object(checks, "UNIT", unit):
            result = unittest.TextTestRunner(stream=output).run(checks.SitePresence(test))
        failure = any(case.id().split(" (", 1)[0].endswith("." + test) and reason in trace
                      for case, trace in result.failures)
        killed = failure and not result.errors and not result.skipped
        print(name + ": " + ("KILLED by " + test if killed else "INVALID OR SURVIVED"), flush=True)
        print(output.getvalue(), flush=True)
        if not killed:
            raise SystemExit(1)


def go_control(name, before, after, subtest):
    source = checks.ROOT / "cmd/regalia-unlock/render.go"
    original = source.read_text()
    assert original.count(before) == 1, name + ": mutation target drifted"
    test = "TestPresentSiteCredentialFailsClosed/" + subtest
    try:
        source.write_text(original.replace(before, after))
        done = subprocess.run(["go", "test", "-json", "-count=1", "./cmd/regalia-unlock",
                               "-run", "^TestPresentSiteCredentialFailsClosed$/^" + subtest + "$"],
                              cwd=checks.ROOT, capture_output=True, text=True)
    finally:
        source.write_text(original)
    events = []
    for line in done.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    diagnostic = "".join(e.get("Output", "") for e in events if e.get("Test") == test)
    killed = (done.returncode != 0 and
              any(e.get("Test") == test and e.get("Action") == "fail" for e in events) and
              "present bad site was accepted instead of failing closed" in diagnostic and
              not any(e.get("Action") == "skip" for e in events))
    print(name + ": " + ("KILLED by " + test if killed else "INVALID OR SURVIVED"), flush=True)
    print(diagnostic + done.stderr, flush=True)
    if not killed:
        raise SystemExit(1)


if __name__ == "__main__":
    gate = "ConditionPathExistsGlob=" + checks.SOURCE + "\n"
    unit_control("missing-presence-gate", gate, "",
                 "test_absent_site_is_an_expected_pre_genesis_condition_skip", "missing site must skip")
    unit_control("content-gate-hides-bad-site", gate, gate.replace("ConditionPathExistsGlob", "ConditionFileNotEmpty"),
                 "test_present_bad_site_reaches_the_existing_hard_failure", "present bad site must not be condition-skipped")
    unit_control("following-links-hides-dangling-site", gate, gate.replace("ConditionPathExistsGlob", "ConditionPathExists"),
                 "test_dangling_site_link_reaches_the_existing_hard_failure", "dangling site link must not masquerade")
    unit_control("missing-pre-genesis-log-explanation", "no site credential: expected pre-genesis skip", "boot configuration",
                 "test_absent_site_is_an_expected_pre_genesis_condition_skip", "must explain pre-genesis")
    unit_control("stale-unit-inventory-pin", "# Before enrolment/genesis", "# Before genesis/enrolment",
                 "test_the_inventory_pins_the_changed_unit", "unit inventory digest must match")
    go_control("invalid-site-accepted", "site, err := bootcfg.ReadSite(siteRaw)\n\tif err != nil {\n\t\treturn \"\", err",
               "site, err := bootcfg.ReadSite(siteRaw)\n\tif err != nil {\n\t\treturn \"\", nil", "invalid")
    go_control("unreadable-site-accepted", 'return "", fmt.Errorf("the site document %s is missing: %v", siteCredential, err)',
               'return "", nil', "unreadable")
    print("1ym: all seven named mutants killed; no skips", flush=True)
