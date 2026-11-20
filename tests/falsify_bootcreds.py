#!/usr/bin/env python3
"""Named dx7.35 controls. Run on a disposable checkout through heavy --host heavy-pool-h4i.

Each mutant must build/import and fail a named assertion; a broken build/import is
INVALID, never a caught defect. Every edit is restored in finally, and the clean
baseline runs before and after. Python gets a fresh bytecode cache for each run.
No refused fixture is reconstructed or transferred by this harness.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
GO = "cmd/regalia-unlock/bootcfg/bootcfg.go"
PY = "deploy/baremetal/bootcreds.py"
PARITY = ["go", "test", "-count=1", "./cmd/regalia-unlock/bootcfg"]
PYTHON = [sys.executable, "-Es", "-m", "unittest", "-v", "tests.test_baremetal_bootcreds.Render",
          "tests.test_baremetal_bootcreds.EspFiles.test_single_node_esp_chain_and_site_render_owner_credentials"]

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
    ("go-owner-key-rotation", GO,
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
]


def run(command):
    with tempfile.TemporaryDirectory(prefix="bootcreds-pyc-") as cache:
        if command[0] == sys.executable:
            command = [command[0], "-X", "pycache_prefix=" + cache, *command[1:]]
        return subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def baseline(label):
    for command in (PARITY, PYTHON):
        result = run(command)
        if result.returncode:
            print(result.stdout, flush=True)
            raise SystemExit(label + " baseline failed")
    print(label + " baseline PASS", flush=True)


def main():
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
        output = result.stdout
        invalid = any(s in output for s in ("[build failed]", "declared and not used", "undefined:",
                                            "SyntaxError", "ImportError", "ModuleNotFoundError", "panic:"))
        named = re.findall(r"--- FAIL: ([^\n]+)|^(FAIL|ERROR): ([^\n]+)", output, re.MULTILINE)
        if result.returncode and named and not invalid:
            first = next(s for s in named[0] if s)
            print(name + ": KILLED by " + first, flush=True)
        else:
            failed.append(name)
            print(name + (": INVALID" if invalid else ": SURVIVED"), flush=True)
            print(output, flush=True)
    baseline("after")
    if failed:
        raise SystemExit("unproven mutants: " + ", ".join(failed))
    print("all %d named mutants KILLED; sources restored" % len(MUTANTS), flush=True)


if __name__ == "__main__":
    main()
