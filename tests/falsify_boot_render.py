"""1ym named controls; run through heavy --host heavy-pool-h4i on a disposable checkout.

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


def go_control(name, path, before, after, test, reason):
    source = checks.ROOT / path
    original = source.read_text()
    assert original.count(before) == 1, name + ": mutation target drifted"
    selector = "/".join("^" + part + "$" for part in test.split("/"))
    try:
        source.write_text(original.replace(before, after))
        done = subprocess.run(["go", "test", "-json", "-count=1", "./cmd/regalia-unlock", "-run", selector],
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
              reason in diagnostic and not any(e.get("Action") == "skip" for e in events))
    print(name + ": " + ("KILLED by " + test if killed else "INVALID OR SURVIVED"), flush=True)
    print(diagnostic + done.stderr, flush=True)
    if not killed:
        raise SystemExit(1)


if __name__ == "__main__":
    pre = "cmd/regalia-unlock/pregenesis.go"
    render = "cmd/regalia-unlock/render.go"
    anchor = "cmd/regalia-unlock/membership/highwater.go"
    controls = [
        ("pre-genesis-not-skipped", pre, "return true, nil", "return false, nil", "pre_genesis", "condition exit = 0, want 1"),
        ("stub-evidence-ignored", pre, "if stubState {", "if false && stubState {", "enrolled_stub_site_deleted", "condition exit = 1, want 255"),
        ("esp-chain-evidence-ignored", pre, "if chain {", "if false && chain {", "enrolled_chain_site_deleted", "condition exit = 1, want 255"),
        ("esp-loader-evidence-ignored", pre, "if credentials {", "if false && credentials {", "enrolled_loader_site_deleted", "condition exit = 1, want 255"),
        ("tpm-open-error-skipped", pre,
         'return false, errors.New("missing site credential: TPM cannot be opened; pre-genesis is unproven")',
         "return true, nil", "tpm_open_error", "condition exit = 1, want 255"),
        ("tpm-inventory-error-skipped", pre,
         'return false, errors.New("missing site credential: TPM NV inventory cannot be read; pre-genesis is unproven")',
         "return true, nil", "tpm_inventory_error", "condition exit = 1, want 255"),
        ("error-exit-is-nonfailing", pre, 'fmt.Fprintf(diagnostics, "regalia-unlock: %v; boot render refused\\n", err)\n\t\treturn 255',
         'fmt.Fprintf(diagnostics, "regalia-unlock: %v; boot render refused\\n", err)\n\t\treturn 1', "tpm_inventory_error", "condition exit = 1, want 255"),
        ("nil-inventory-treated-as-absence", anchor, "if defined == nil {", "if false && defined == nil {", "tpm_nil_inventory", "condition exit = 1, want 255"),
        ("directory-read-error-ignored", pre, "return len(entries) != 0, err", "return len(entries) != 0, nil", "stub_read_error", "condition exit = 1, want 255"),
        ("esp-unmount-error-ignored", render, "if unmountErr := env.unmount(dir); unmountErr != nil {",
         "if unmountErr := env.unmount(dir); false && unmountErr != nil {", "esp_unmount_error", "condition exit = 1, want 255"),
        ("skip-log-explanation-removed", pre, "no site credential: expected pre-genesis skip", "skip", "pre_genesis", "condition must log exactly one reason"),
        ("enrolled-log-explanation-removed", pre, "missing site credential on an enrolled node: ESP membership state is present",
         "missing site", "enrolled_chain_site_deleted", "condition must log exactly one reason"),
    ]
    layout = "[]uint32{h.index, h.base, h.slots[0], h.slots[1]}"
    indices = ["h.index", "h.base", "h.slots[0]", "h.slots[1]"]
    for index, subtest in zip(indices, ["nv_counter_without_esp", "nv_base_without_esp", "nv_slot_0_without_esp", "nv_slot_1_without_esp"]):
        replacement = "[]uint32{" + ", ".join(i for i in indices if i != index) + "}"
        controls.append(("anchor-omitted-" + subtest, anchor, layout, replacement, subtest, "condition exit = 1, want 255"))
    for name, path, before, after, subtest, reason in controls:
        go_control(name, path, before, after, "TestRenderCondition/" + subtest, reason)
    go_control("main-condition-dispatch-removed", "cmd/regalia-unlock/main.go",
               '\tif len(os.Args) > 1 && os.Args[1] == "-render-check" {\n\t\tos.Exit(runRenderCheck(os.Args[1:], os.Stderr))\n\t}\n',
               "", "TestRenderCheckMainExitStatus", "main must exit 255, not a non-failing skip")
    for name, before, after, subtest in [
        ("invalid-site-accepted", "site, err := bootcfg.ReadSite(siteRaw)\n\tif err != nil {\n\t\treturn \"\", err",
         "site, err := bootcfg.ReadSite(siteRaw)\n\tif err != nil {\n\t\treturn \"\", nil", "invalid"),
        ("unreadable-site-accepted", 'return "", fmt.Errorf("the site document %s is missing: %v", siteCredential, err)',
         'return "", nil', "unreadable"),
    ]:
        go_control(name, render, before, after, "TestPresentSiteCredentialFailsClosed/" + subtest,
                   "present bad site was accepted instead of failing closed")
    unit_test = "test_the_code_checks_enrolment_before_credential_setup"
    unit_control("helper-runs-after-credential-setup", "ExecCondition=", "ExecStartPre=", unit_test, "helper must run as ExecCondition")
    unit_control("file-only-condition-bypasses-code", "DefaultDependencies=no\n",
                 "DefaultDependencies=no\nConditionPathExistsGlob=" + checks.SOURCE + "\n", unit_test, "must not bypass the enrolment/TPM decision")
    unit_control("stale-unit-inventory-pin", "Description=Render", "Description=Verify",
                 "test_the_inventory_pins_the_changed_unit", "unit inventory digest must match")
    print("1ym: all 22 named mutants killed; no skips", flush=True)
