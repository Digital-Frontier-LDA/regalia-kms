#!/usr/bin/env python3
"""Named dx7.35 controls. Run on a disposable checkout through heavy --host heavy-pool-h4i.

Each mutant must build/import and fail a named assertion; a broken build/import is
INVALID, never a caught defect. Every edit is restored in finally, and the clean
baseline runs before and after. Python gets a fresh bytecode cache for each run.
No refused fixture is reconstructed or transferred by this harness.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = "cmd/regalia-unlock/bootcfg/bootcfg.go"
PY = "deploy/baremetal/bootcreds.py"
PARITY = ["go", "test", "-json", "-count=1", "./cmd/regalia-unlock/bootcfg"]
CLIENT = ["go", "test", "-json", "-count=1", "./cmd/regalia-unlock", "-run",
          "^TestSingleNodeVerifiedRenderUnlocksOnlyWithCurrentOwner$"]
PYTHON = [sys.executable, "-Es", "-m", "unittest", "-v", "tests.test_baremetal_bootcreds.Render",
          "tests.test_baremetal_bootcreds.EspFiles.test_single_node_esp_chain_and_site_render_owner_credentials"]
with (ROOT / "tests/vectors/bootcreds-v1.json").open() as fixture:
    prior_keys = json.load(fixture)["manifests"]["single-node"]["owner_keys"]
OLD_OWNER_KEYS = "[]any{" + ",".join('map[string]any{"alg":"%s","key":"%s"}' % (k["alg"], k["public"])
                                   for k in prior_keys) + "}"

# name, file, unique source anchor, replacement, test command
MUTANTS = [
    ("go-single-node-refusal", GO,
     'func Render(manifest map[string]any, site Site) (map[string][]byte, error) {',
     'func Render(manifest map[string]any, site Site) (map[string][]byte, error) {\n'
     '\tif p, _ := membership.Profile(manifest); p == membership.ProfileSingleNode { return nil, refuse("pending", "single-node pending") }', PARITY),
    ("python-single-node-refusal", PY,
     '    endpoints = bootnet.unlock_endpoints(site, manifest)',
     '    require(membership.profile(manifest) != membership.SINGLE_NODE, "single-node pending")\n'
     '    endpoints = bootnet.unlock_endpoints(site, manifest)', PYTHON),
    ("go-single-profile-mismatch", GO,
     'if profile == membership.ProfileSingleNode {',
     'if profile == membership.ProfileSingleNode && site.Owner != nil {', PARITY),
    ("go-multi-profile-mismatch", GO,
     'if site.Owner != nil {', 'if false && site.Owner != nil {', PARITY),
    ("go-no-ed25519-owner-guard", GO,
     'if len(ownerKeys) == 0 {', 'if false && len(ownerKeys) == 0 {', PARITY),
    ("go-ed25519-owner-filter", GO,
     'if key["alg"] == "ed25519" {', 'if true {', PARITY),
    ("go-owner-key-substitution", GO,
     '"key": key["key"]', '"key": manifest["owner_keys"].([]any)[0].(map[string]any)["key"]', PARITY),
    ("go-owner-key-order", GO,
     'for _, entry := range manifest["owner_keys"].([]any) {',
     'for i := len(manifest["owner_keys"].([]any))-1; i >= 0; i-- { entry := manifest["owner_keys"].([]any)[i]', PARITY),
    ("go-owner-wireguard-pin", GO,
     '"wg_service_pub": manifest["owner_wg_pub"]',
     '"wg_service_pub": nodes[site.NodeID]["wg_boot_pub"]', PARITY),
    ("go-owner-tunnel-endpoint", GO,
     'endpoints[membership.OwnerParty]}}',
     'fmt.Sprintf("%s:%d", site.Owner.Underlay, site.UnlockPort)}}', PARITY),
    ("go-owner-schema", GO,
     '= bootSingleSchema, membership.ProfileSingleNode, ownerKeys',
     '= bootSchema, membership.ProfileSingleNode, ownerKeys', PARITY),
    ("go-owner-topology", GO,
     '= bootSingleSchema, membership.ProfileSingleNode, ownerKeys',
     '= bootSingleSchema, membership.ProfileMultiNode, ownerKeys', PARITY),
    ("go-owner-no-tpm-names", GO,
     'pins = []any{map[string]any{"node_id": membership.OwnerParty, "endpoint": endpoints[membership.OwnerParty]}}',
     'pins = []any{map[string]any{"node_id": membership.OwnerParty, "endpoint": endpoints[membership.OwnerParty], "ek_name": "", "ak_name": ""}}', PARITY),
    ("go-multi-no-peer-refusal", GO,
     'if len(pins) == 0 {', 'if false && len(pins) == 0 {', PARITY),
    ("go-owner-ruleset", GO,
     'set(underlays), site.ListenPort', 'set([]string{site.HostIPv4}), site.ListenPort', PARITY),
    ("go-owner-boot-env", GO,
     'site.NICMAC, site.HostIPv4, site.Prefix', 'site.NICMAC, site.Address, site.Prefix', PARITY),
    ("python-esp-preflight", PY,
     '    render(manifest, site, device)                    # what the initrd will render must render: refused here, not at boot',
     '    # mutant: no render preflight',
     [sys.executable, "-Es", "-m", "unittest", "-v",
      "tests.test_baremetal_bootcreds.EspFiles.test_a_chain_that_leaves_the_host_no_peer_writes_nothing"]),
    ("go-old-owner-accepted", "cmd/regalia-unlock/attest.go",
     'if !known {', 'if false && !known {', CLIENT),
    ("go-stale-owner-keys", GO,
     '= bootSingleSchema, membership.ProfileSingleNode, ownerKeys',
     '= bootSingleSchema, membership.ProfileSingleNode, ' + OLD_OWNER_KEYS, CLIENT),
]


# Every control names its intended assertion and its diagnostic. Matching unrelated
# FAIL/ERROR text elsewhere in the run is never evidence that this control fired.
PARITY_TEST = "TestEveryRenderIsTheSameBytes/"
SINGLE_CASE = PARITY_TEST + "a,_single-node_/_single-node"
ESP_TEST = "tests.test_baremetal_bootcreds.EspFiles."
CLIENT_TEST = "TestSingleNodeVerifiedRenderUnlocksOnlyWithCurrentOwner"
EXPECTED = {
    "go-single-node-refusal": (SINGLE_CASE, "Python rendered, Go: single-node pending"),
    "python-single-node-refusal": (
        ESP_TEST + "test_single_node_esp_chain_and_site_render_owner_credentials",
        "AssertionError: single-node ESP rendering refused: single-node pending"),
    "go-single-profile-mismatch": (
        PARITY_TEST + "a_/_single-node", r'Python refused, for profile .*Go: .*Class:"no-peer"'),
    "go-multi-profile-mismatch": (
        PARITY_TEST + "a,_single-node_/_all_active", r'Python refused, for profile .*Go: .*Class:"no-address"'),
    "go-no-ed25519-owner-guard": (
        SINGLE_CASE + "_no_ed25519_owner", r"Python refused, for owner-key .*Go: <nil>"),
    "go-ed25519-owner-filter": (SINGLE_CASE + "_mixed_owner_keys", "regalia.unlock-config differs:"),
    "go-owner-key-substitution": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-owner-key-order": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-owner-wireguard-pin": (SINGLE_CASE, "regalia.wg-boot-conf differs:"),
    "go-owner-tunnel-endpoint": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-owner-schema": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-owner-topology": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-owner-no-tpm-names": (SINGLE_CASE, "regalia.unlock-config differs:"),
    "go-multi-no-peer-refusal": (
        PARITY_TEST + "a_/_b_and_c_quarantined", r"Python refused, for no-peer .*Go: <nil>"),
    "go-owner-ruleset": (PARITY_TEST + "a_/_all_active", "regalia.boot-nft differs:"),
    "go-owner-boot-env": (PARITY_TEST + "a_/_all_active", "regalia.boot-env differs:"),
    "python-esp-preflight": (
        ESP_TEST + "test_a_chain_that_leaves_the_host_no_peer_writes_nothing", "AssertionError: Refused not raised"),
    "go-old-owner-accepted": (CLIENT_TEST, "the previous owner was not refused by the rendered key pin: <nil>"),
    "go-stale-owner-keys": (CLIENT_TEST, "rendered current owner did not unlock:.*not signed by one of the owner_keys"),
}


def run(command):
    with tempfile.TemporaryDirectory(prefix="bootcreds-pyc-") as cache:
        if command[0] == sys.executable:
            command = [command[0], "-X", "pycache_prefix=" + cache, *command[1:]]
        return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def go_events(output):
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            yield event


def classify(command, result, expected):
    """Only the expected assertion's diagnostic can kill; every unittest ERROR is invalid."""
    if result.returncode == 0:
        return "SURVIVED"
    output = result.stdout
    if any(s in output for s in ("[build failed]", "[setup failed]", "declared and not used", "undefined:",
                                 "SyntaxError", "ImportError", "ModuleNotFoundError", "panic:")):
        return "INVALID"
    if re.search(r"^ERROR: ", output, re.MULTILINE):
        return "INVALID"
    test, reason = expected
    if command[0] == "go":
        events = list(go_events(output))
        failed = any(e.get("Action") == "fail" and e.get("Test") == test for e in events)
        diagnostic = "".join(e.get("Output", "") for e in events if e.get("Test") == test)
        return "KILLED" if failed and re.search(reason, diagnostic) else "INVALID"
    # Associate the reason with its FAIL block, not a traceback for another test.
    blocks = re.finditer(r"^FAIL: [^\n]+ \(([^)]+)\)\n-+\n(.*?)(?=^={10,}\n|\Z)",
                         output, re.MULTILINE | re.DOTALL)
    return "KILLED" if any(m[1] == test and re.search(reason, m[2]) for m in blocks) else "INVALID"


def verify_classifier():
    """Adversarial output controls: a setup error must not masquerade as a kill."""
    test, reason = EXPECTED["python-single-node-refusal"]
    failure = "FAIL: test_single_node_esp_chain_and_site_render_owner_credentials (%s)\n%s\n%s\n" % (test, "-" * 70, reason)
    setup_error = failure.replace("FAIL:", "ERROR:").replace(reason, "PermissionError: fixture setup failed")
    cases = [
        ("python-expected-assertion", PYTHON, failure, EXPECTED["python-single-node-refusal"], "KILLED"),
        ("python-setup-error", PYTHON, setup_error, EXPECTED["python-single-node-refusal"], "INVALID"),
        ("python-error-with-expected-text", PYTHON, failure.replace("FAIL:", "ERROR:"), EXPECTED["python-single-node-refusal"], "INVALID"),
        ("python-wrong-test", PYTHON, failure.replace(test, "other.test"), EXPECTED["python-single-node-refusal"], "INVALID"),
        ("python-wrong-reason", PYTHON, failure.replace(reason, "AssertionError: unrelated"), EXPECTED["python-single-node-refusal"], "INVALID"),
    ]
    test, reason = EXPECTED["go-single-node-refusal"]
    output = "\n".join(json.dumps(e) for e in (
        {"Action": "output", "Test": test, "Output": reason}, {"Action": "fail", "Test": test}))
    cases.extend([
        ("go-expected-assertion", PARITY, output, (test, reason), "KILLED"),
        ("go-wrong-test", PARITY, output, ("otherTest", reason), "INVALID"),
        ("go-wrong-reason", PARITY, output, (test, "unrelated"), "INVALID"),
        ("go-build-error", PARITY, "FAIL [build failed]", (test, reason), "INVALID"),
    ])
    for name, command, output, expected, want in cases:
        got = classify(command, subprocess.CompletedProcess(command, 1, stdout=output), expected)
        if got != want:
            raise SystemExit("classifier control %s: %s, expected %s" % (name, got, want))
        print("classifier %s: %s" % (name, got), flush=True)


def baseline(label):
    for command in (PARITY, PYTHON, CLIENT):
        result = run(command)
        skipped = any(e.get("Action") == "skip" for e in go_events(result.stdout)) if command[0] == "go" else "skipped" in result.stdout
        if result.returncode or skipped:
            print(result.stdout, flush=True)
            raise SystemExit(label + " baseline failed or skipped")
    print(label + " baseline PASS (zero skips)", flush=True)


def main():
    if {m[0] for m in MUTANTS} != set(EXPECTED):
        raise SystemExit("every mutant must have exactly one expected failure")
    verify_classifier()
    baseline("before")
    failed = []
    for name, relative, anchor, replacement, command in MUTANTS:
        path = ROOT / relative
        original = path.read_text()
        if original.count(anchor) != 1:
            raise SystemExit(name + ": source anchor is not unique")
        try:
            path.write_text(original.replace(anchor, replacement))
            result = run(command)
        finally:
            path.write_text(original)
        verdict = classify(command, result, EXPECTED[name])
        if verdict == "KILLED":
            print("%s: KILLED by %s: %s" % (name, *EXPECTED[name]), flush=True)
        else:
            failed.append(name)
            print(name + ": " + verdict, flush=True)
            print(result.stdout, flush=True)
    baseline("after")
    if failed:
        raise SystemExit("unproven mutants: " + ", ".join(failed))
    print("all %d named mutants KILLED; sources restored" % len(MUTANTS), flush=True)


if __name__ == "__main__":
    main()
