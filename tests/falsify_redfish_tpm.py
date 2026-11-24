#!/usr/bin/env python3
"""regalia-kms-dx7.40 named controls: each guard of the TPM-clear request builder is broken on purpose and a named
test must FAIL for it (an assertion; an error or a skip does not count). Each named test is first run on the tree
as it is and must pass. Run from the checkout's root: python3 -Es tests/falsify_redfish_tpm.py

The file is mutated in place and restored in a finally; run it on a clean checkout. The mutations target the
request builder (the attribute name, the Clear value, the settings URI, the serial guard, the registry-lacks-value
refusal, the consumed readback) so that a wrong request would be SENT, not refused.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RED = ROOT / "deploy/baremetal/redfish.py"
# the tests as a namespace package, whatever else on this Python is called "tests"
BOOT = ("import os, sys, types, unittest; sys.path.insert(0, os.getcwd()); m = types.ModuleType('tests'); "
        "m.__path__ = [os.path.join(os.getcwd(), 'tests')]; sys.modules['tests'] = m; "
        "unittest.main(module=None, argv=['falsify'] + sys.argv[1:])")
TPM = "tests.test_baremetal_redfish.Tpm."
REF = "tests.test_baremetal_redfish.TpmRefusals."


def run(test):
    done = subprocess.run([sys.executable, "-Es", "-c", BOOT, "-v", test], cwd=ROOT, capture_output=True, text=True)
    return done.returncode, re.sub(r"\x1b\[[0-9;]*m", "", done.stdout + done.stderr)       # no colour: the lines are read


def skipped(output):
    return re.search(r"skipped=|\.\.\. skipped", output) is not None


def replaced(before, after):
    def apply():
        text = RED.read_text()
        assert text.count(before) == 1, "mutation anchor drifted: %r" % before[:60]
        RED.write_text(text.replace(before, after))
    return apply


def control(name, mutate, tests, original):
    try:
        mutate()
        for test in tests:
            code, output = run(test)
            short = test.rsplit(".", 1)[1]
            killed = (code != 0 and ("FAIL: %s " % short) in output and ("ERROR: %s " % short) not in output
                      and not skipped(output))
            print("%s: %s %s" % (name, "KILLED by" if killed else "INVALID OR SURVIVED", test), flush=True)
            if not killed:
                print(output, flush=True)
                raise SystemExit(1)
    finally:
        RED.write_text(original)


CONTROLS = [
    # (m1) the attribute name swapped: the PATCH would set Tpm2Operation when the registry lists TpmOperation
    ("m1 the attribute name swapped",
     replaced('plan = {"uri": state["settings_uri"], "body": {"Attributes": {state["attribute"]: state["clear"]}}}',
              'plan = {"uri": state["settings_uri"], "body": {"Attributes": {"Tpm2Operation": state["clear"]}}}'),
     [TPM + "test_apply_patches_the_pending_and_waits_until_consumed"]),
    # (m2) the Clear value replaced by the current (no-action) value: the PATCH would set NoAction, not Clear
    ("m2 the Clear value replaced by the current value",
     replaced('plan = {"uri": state["settings_uri"], "body": {"Attributes": {state["attribute"]: state["clear"]}}}',
              'plan = {"uri": state["settings_uri"], "body": {"Attributes": {state["attribute"]: state["current"]}}}'),
     [TPM + "test_apply_patches_the_pending_and_waits_until_consumed"]),
    # (m3) the settings URI replaced by the live Bios/ URI: the PATCH would hit the live resource, not the pending
    ("m3 the settings URI pointed at the live Bios/",
     replaced('status, _ = self.transport.request("PATCH", plan["uri"], plan["body"])',
              'status, _ = self.transport.request("PATCH", BIOS, plan["body"])'),
     [TPM + "test_apply_patches_the_pending_and_waits_until_consumed"]),
    # (m4) the serial guard removed in bios_discover: the client would PATCH a server that is not the one named
    # (the guard is in discover(); bios_discover skips it by reading the system directly)
    ("m4 the serial guard removed in bios_discover",
     replaced('found = self.discover()\n        bios = self._get(BIOS)',
              'system = self._get(SYSTEM)\n        found = {"serial": str(system.get("SerialNumber") or "").strip(), "uuid": "", "model": "", "manufacturer": "", "power": system.get("PowerState"), "firmware": "2.82", "reset_target": "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/", "reset_types": []}\n        bios = self._get(BIOS)'),
     [REF + "test_another_server_is_never_read_for_the_bios"]),
    # (m5) the registry-lacks-value refusal removed: the client would PATCH even when the registry lists no Clear
    ("m5 the registry-lacks-value refusal removed",
     replaced('require(clear is not None, "the iLO at %s lists no Clear value for %s (it offers %s): nothing is assumed"',
              'require(True, "the iLO at %s lists no Clear value for %s (it offers %s): nothing is assumed"'),
     [REF + "test_a_registry_without_a_clear_value_is_refused"]),
    # (m6) the consumed readback skipped: the client would report consumed without reading the live attribute back
    ("m6 the consumed readback skipped",
     replaced('if live == state["no_action"]:\n                live_readbacks[-1]["consumed_before"] = restart["outcome"]',
              'if True:\n                live_readbacks[-1]["consumed_before"] = restart["outcome"]'),
     [TPM + "test_a_pending_that_is_not_consumed_times_out_as_a_refusal_with_its_readbacks"]),
]


if __name__ == "__main__":
    os.chdir(ROOT)
    original = RED.read_text()
    named = sorted({t for _, _, tests in CONTROLS for t in tests})
    for test in named:                               # the controls' own control: each passes on the tree as it is
        code, output = run(test)
        if code != 0 or skipped(output):
            print("NOT GREEN BEFORE ANY MUTATION: %s\n%s" % (test, output), flush=True)
            raise SystemExit(1)
    print("%d named tests green on the tree as it is" % len(named), flush=True)
    for name, mutate, tests in CONTROLS:
        control(name, mutate, tests, original)
    print("all %d named mutants killed; source restored" % len(CONTROLS), flush=True)
    assert RED.read_text() == original, "a mutation was left in the tree"
