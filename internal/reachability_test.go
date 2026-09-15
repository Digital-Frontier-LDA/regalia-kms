package internal_test

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// testOnlyPackages are the packages that legitimately have no path from the daemon binary.
//
// Adding a name here is a claim that the package is not a runtime control, and it should be
// justified. Everything else must be reachable from cmd/regalia-kms.
var testOnlyPackages = map[string]string{
	"internal":             "this package: cross-package boundary tests only",
	"internal/integration": "end-to-end HTTP tests over the assembled service",
	"internal/sweeptext":   "restores mutation-neutralised source for the ledger drift guards in internal/policy and internal/audit; nothing in the daemon reads source text",
}

// unwiredControls are implemented, tested, and NOT reachable from the daemon. This is debt, not an
// exemption, and each entry names the issue that closes it.
//
// Keeping them in a separate map from testOnlyPackages matters: calling an unwired control
// "test-only" would be false, and the next person would read the allowlist as a statement that
// nothing is missing. The test reports these every run so they stay visible rather than becoming
// background.
//
// The exposure is contained rather than ignored: bindBackendToRegistry refuses to start a daemon
// whose key registry routes to a backend no provider serves, so a manifest binding an object to
// yubikey-piv fails loudly at startup instead of at the first signature.
var unwiredControls = map[string]string{
	"internal/backend/yubikey": "issue #16 — the daemon constructs this provider only under -tags piv " +
		"(cmd/regalia-kms/yubikey_backend_piv.go, #421); the default build, which is the one this test's go list sees, " +
		"links yubikey_backend_stub.go instead. No build in this repository records -tags piv for the shipped artifact, " +
		"which hsm-host-role takes as an externally built binary pinned by SHA-256. PIN custody is not the blocker: the " +
		"daemon's pin.LockedFileSource satisfies yubikey.PINSource (TestTheDaemonsPINSourceFitsTheYubiKeyProvider). " +
		"Whether the adapter is otherwise complete is not something this test can see",
	"internal/backend/openpgp":        "issue #21 — the admission layer is complete; the driver's protocol half now exists (openpgp/driver), and what is missing is the PC/SC transport binding and the daemon wiring",
	"internal/backend/openpgp/driver": "issue #21 — the OpenPGP card protocol layer, wire-tested against scripted transports; deliberately unreachable until ADR-0001 §4's physical qualification is complete. Through openpgp/pcsc (-tags piv) it has passed positive operations, negative controls, exclusive access and PW1-block recovery on YubiKey 5C NFC 25923902; removal is not recorded",
}

// EVERY CONTROL MUST HAVE A PATH FROM THE DAEMON.
//
// This exists because the same defect happened three times in one day. internal/fencing was
// complete, well tested, and had no non-test importer at all, so ADR-0001 §8 — never two
// simultaneous signers — was enforced by nothing at runtime while every test in the package passed.
// A Fencing readiness probe was added to Dependencies, populated in main, and never read by
// NewRequired, so a passive site still reported ready. And internal/backend/yubikey is a complete
// PIV adapter that the daemon never constructs, while the registry advertises yubikey-piv as a
// valid binding.
//
// The pattern is always the same: the package compiles, its own tests pass, and nothing in
// production calls it. Package tests cannot see this — only the import graph can. So the graph is
// the assertion.
//
// This catches an unreachable PACKAGE. It does not catch an unread struct field, which is how the
// readiness probe slipped through, so it is a floor rather than a guarantee.
func TestEveryInternalPackageIsReachableFromTheDaemon(t *testing.T) {
	reachable := listPackages(t, "go", "list", "-deps", "../cmd/regalia-kms")
	all := listPackages(t, "go", "list", "../internal/...")
	if len(all) == 0 || len(reachable) == 0 {
		t.Fatal("could not enumerate packages: this test would silently pass while checking nothing")
	}

	inGraph := make(map[string]struct{}, len(reachable))
	for _, name := range reachable {
		inGraph[name] = struct{}{}
	}

	var orphans []string
	for _, name := range all {
		if _, ok := inGraph[name]; ok {
			continue
		}
		if _, allowed := testOnlyPackages[name]; allowed {
			continue
		}
		if reason, known := unwiredControls[name]; known {
			t.Logf("UNWIRED CONTROL: %s — %s", name, reason)
			continue
		}
		orphans = append(orphans, name)
	}
	// AN ALLOWLIST ENTRY THAT STOPPED BEING TRUE IS A CLAIM NOTHING CHECKS.
	//
	// The loop above skips a reachable package before it ever consults unwiredControls, so wiring
	// one of these into the daemon removed the orphan failure and left the entry behind, still
	// logging "UNWIRED CONTROL" every run for something the daemon now reaches. That is worse than
	// no entry: the log line is the only place a reader learns what is unwired, and it would be
	// stating the opposite of the truth.
	//
	// It is a floor, not a guarantee — being in the import graph is necessary for the daemon to
	// construct something, not sufficient. internal/backend/openpgp relies on it to hold "the
	// daemon serves no OpenPGP backend", so that claim cannot quietly stop being true.
	for name := range unwiredControls {
		if _, reachable := inGraph[name]; reachable {
			t.Errorf("%s is listed as an unwired control, and the daemon now reaches it. "+
				"Remove the entry: while it is there, every run logs that this package is unreachable, which is false.", name)
		}
	}

	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Fatalf("these packages have no path from cmd/regalia-kms, so nothing in production calls them: %s\n"+
			"A control the daemon never reaches is enforced by nothing, however well its own tests pass. "+
			"Either wire it into the daemon, or add it to testOnlyPackages with a reason.",
			strings.Join(orphans, ", "))
	}
}

func listPackages(t *testing.T, name string, args ...string) []string {
	t.Helper()
	// Trim THIS module's own path so the check survives a module rename (a fork should not
	// silently turn this test into one that checks nothing) without ever capturing a
	// dependency's internal/ packages (e.g. google.golang.org/grpc/internal/...).
	modOut, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	modulePrefix := strings.TrimSpace(string(modOut)) + "/"
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	var packages []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if suffix, ok := strings.CutPrefix(line, modulePrefix); ok && strings.HasPrefix(suffix, "internal") {
			packages = append(packages, suffix)
		}
	}
	return packages
}
