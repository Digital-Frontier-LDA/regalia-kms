package main

// Round two of #237 on cmd/regalia-kms, second pass: preflight().
//
// preflight is called by 13 tests and 35 of its 46 operands still survive. Running BOTH
// directions before writing anything — the convention the previous pass established — splits
// them in a way a refusal-only reading cannot see:
//
//	15 both-direction   nothing drives either arm
//	 7 TRUE-only        the refusal IS tested; the guard firing UNCONDITIONALLY is not
//	13 FALSE-only
//
// Seven TRUE-only survivors in one function is what a validation routine attracts: fixtures
// accumulate around what it must REFUSE, and nothing asserts what it must leave alone. That is
// the same gap that left provider.go:150[1] and :197[0] open in #386, found here by running the
// check first instead of discovering it in falsification.
//
// This file closes the report-content half of it. preflight's report is not decoration: the
// Checked list is what an operator is told held, and the Unchecked list is what preflight
// refuses to claim. A note that appears when its check did not run is a false assurance, and
// an Unchecked item that disappears is a limit the operator is no longer told about.
//
// TWO OF THE NINE ARE NOT FULLY CLOSED, and both are recorded rather than glossed:
//
//	:108 `settings.PolicyStatePath != ""` — the TRUE direction cannot be detected. The guard is
//	     nested inside `if settings.PolicyPath != ""` at :95, and config.go:369 refuses any
//	     configuration where exactly one of the two paths is set ("policy_path and
//	     policy_state_path must be configured together"). So whenever :108 is REACHED the
//	     operand is already true, and forcing it true changes nothing. Masked by that coupling.
//	     The pair experiment is confounded — config.go:369 alone is killed by
//	     TestDecodeRejectsUnsafeValues and the pair adds no failure — so this rests on the
//	     structural argument above, which is checkable from the two line numbers.
//
//	:230 `settings.PKCS11ModulePath != ""` — the FALSE direction needs a configuration where a
//	     module IS set, and config couples that to three more paths, one of which preflight
//	     then LOADS (secure-channel evidence at :143). No fixture in this package builds valid
//	     evidence. Reachable, untested, and left in the ledger rather than half-covered.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

func noted(report *preflightReport, fragment string) bool {
	for _, line := range report.Checked {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

func unchecked(report *preflightReport, fragment string) bool {
	for _, line := range report.Unchecked {
		if strings.Contains(line, fragment) {
			return true
		}
	}
	return false
}

// TestPreflightClaimsOnlyTheChecksItRan covers preflight.go:108 (`PolicyStatePath != ""`),
// :230 (`PKCS11ModulePath != ""`), :235 (`TLSCertificatePath == ""`) and :244
// (`ApproverKeysPath != ""`), all in the direction where the guard fires unconditionally.
//
// Each of these gates a line in the report rather than a refusal, so deleting the operand is
// invisible to every existing test — none of the 13 reads the report at all. Forced TRUE, each
// adds a claim about a check that did not run, or an Unchecked limit that does not apply.
//
// The absent rows are the ones that matter. Asserting a note APPEARS when configured pins the
// FALSE direction, which was already covered; asserting it is ABSENT when unconfigured is what
// pins TRUE.
//
// Falsifier: `(true || (settings.PolicyStatePath != ""))` and the equivalent for each row.
func TestPreflightClaimsOnlyTheChecksItRan(t *testing.T) {
	t.Run("no policy state journal configured means no journal note", func(t *testing.T) {
		settings := completeSettings(t)
		// Both, because config couples them: "policy_path and policy_state_path must be
		// configured together". Unsetting only the journal is refused before preflight runs.
		settings.PolicyStatePath, settings.PolicyPath = "", ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "policy state journal") {
			t.Fatalf("preflight reported on a policy state journal that was never configured: %v",
				report.Checked)
		}
	})

	t.Run("no PKCS#11 module configured means no token caveat", func(t *testing.T) {
		settings := completeSettings(t)
		settings.PKCS11ModulePath = ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if unchecked(report, "PKCS#11 module is not loaded") {
			t.Fatalf("preflight disclaimed a token check on a host with no module configured — "+
				"an Unchecked item that does not apply reads as a gap where there is none: %v",
				report.Unchecked)
		}
	})

	// THE CONFIGURED-MODULE ARM IS NOT HERE, and that is a limit rather than an oversight.
	// Asserting the caveat APPEARS when a module IS configured would pin :230 in the other
	// direction, but config couples the module to three more paths — "pkcs11_module_path,
	// pin_paths, secure_channel_evidence_path and audit_journal_path must be configured
	// together" — and preflight then LOADS the secure-channel evidence at :143. No fixture in
	// this package builds valid evidence, so the row would need a new fixture family for one
	// operand direction. :230's FALSE direction stays open in the ledger.

	t.Run("configured mutual TLS removes the no-TLS caveat", func(t *testing.T) {
		dir := tlsSettings(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		settings := completeSettings(t)
		settings.TLSCertificatePath = filepath.Join(dir, "server.crt")
		settings.TLSPrivateKeyPath = filepath.Join(dir, "server.key")
		settings.TLSClientCAPath = filepath.Join(dir, "server.crt")
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if unchecked(report, "no mutual TLS is configured") {
			t.Fatalf("preflight told the operator no transport identity was checked on a host "+
				"where it had just loaded and validated the keypair: %v", report.Unchecked)
		}
	})

	t.Run("a configured approver key set is reported", func(t *testing.T) {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "approvers.json")
		document := `{"approvers":{"spiffe://regalia/approver/alice":"` +
			base64.StdEncoding.EncodeToString(public) + `"}}`
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		settings := completeSettings(t)
		settings.ApproverKeysPath = path
		_, _, _, _, report, preflightErr := preflight(settings)
		if preflightErr != nil {
			t.Fatalf("preflight: %v", preflightErr)
		}
		if !noted(report, "approver key set loads") {
			t.Fatalf("a configured approver key set was loaded but not reported — the operator "+
				"is not told which approvers the daemon will honour: %v", report.Checked)
		}
	})

	t.Run("no approver key set configured means no approver note", func(t *testing.T) {
		settings := completeSettings(t)
		settings.ApproverKeysPath = ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "approver key set loads") {
			t.Fatalf("preflight reported an approver key set on a host that configured none: %v",
				report.Checked)
		}
	})
}

// TestPreflightRunsTheCrossChecksOnlyWhenBothSidesLoaded covers preflight.go:129 operands 0
// and 1 (`keyRegistry != nil && policyEngine != nil`) and :135 operands 0 and 1
// (`keyRegistry != nil && rbacPolicy != nil`), in the direction where the operand is deleted
// from the conjunction.
//
// Both guards protect a cross-check between two artefacts. With one side absent there is
// nothing to cross-check, and the note claiming it was done would be a claim about a
// comparison that never happened.
//
// Falsifier: `(true || (policyEngine != nil))` makes the conjunction depend on the registry
// alone, so requireDeclaredPoliciesAreEnforced runs against a nil engine.
func TestPreflightRunsTheCrossChecksOnlyWhenBothSidesLoaded(t *testing.T) {
	t.Run("no purpose policy means no declared-policy cross-check", func(t *testing.T) {
		settings := completeSettings(t)
		settings.PolicyPath = ""
		settings.PolicyStatePath = ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "declared policy_id") {
			t.Fatalf("preflight claimed every object's declared policy_id was checked against a "+
				"policy engine it never built: %v", report.Checked)
		}
	})

	t.Run("no RBAC policy means no grant cross-check", func(t *testing.T) {
		settings := completeSettings(t)
		settings.RBACPolicyPath = ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "RBAC grant names an object") {
			t.Fatalf("preflight claimed every RBAC grant was checked against the registry with "+
				"no RBAC policy loaded: %v", report.Checked)
		}
	})

	t.Run("no registry means neither cross-check", func(t *testing.T) {
		// Site goes with it: config couples registry_path and site, so unsetting only the
		// registry is refused before preflight runs. This is the fixture that reaches the
		// keyRegistry operand of BOTH conjunctions — the rows above vary the other side.
		settings := completeSettings(t)
		settings.RegistryPath, settings.Site = "", ""
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "declared policy_id") || noted(report, "RBAC grant names an object") {
			t.Fatalf("preflight claimed a cross-check against a registry it never loaded: %v",
				report.Checked)
		}
	})

	t.Run("both sides present does run them", func(t *testing.T) {
		settings := completeSettings(t)
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !noted(report, "declared policy_id") || !noted(report, "RBAC grant names an object") {
			t.Fatalf("preflight skipped a cross-check with both sides loaded — without this row "+
				"the two above would pass with the checks deleted entirely: %v", report.Checked)
		}
	})
}

// TestACorruptPolicyStateJournalIsRefusedNotNotedAsAbsent covers preflight.go:112
// (`errors.Is(stateErr, os.ErrNotExist)`) in the TRUE direction.
//
// This is the sharpest of the seven. Forced true, the ErrNotExist arm of the switch matches
// EVERY failure, so the default arm — the one that returns the error — becomes unreachable. A
// journal that exists and is damaged is then reported as "does not exist yet", which the
// surrounding comment explicitly treats as benign on a commissioned site, and preflight
// returns nil.
//
// That is the #220 inversion this file was written about, one arm over: a refusal downgraded
// to a note, on a host with state it cannot account for.
//
// Falsifier: `(true || (errors.Is(stateErr, os.ErrNotExist)))`. preflight then accepts the
// corrupt journal and the daemon starts on it.
func TestACorruptPolicyStateJournalIsRefusedNotNotedAsAbsent(t *testing.T) {
	settings := completeSettings(t)
	if err := os.WriteFile(settings.PolicyStatePath, []byte("{not a journal at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, report, err := preflight(settings)
	if err == nil {
		t.Fatalf("a damaged policy state journal was accepted; the report says %v — an existing "+
			"file that cannot be read is not an absent one, and the daemon would start on it",
			report.Checked)
	}
	if !strings.Contains(err.Error(), "policy state journal") {
		t.Fatalf("preflight refused, but not on the journal: %v", err)
	}
	if noted(report, "does not exist yet") {
		t.Fatal("a damaged journal was reported as one that does not exist yet")
	}
}

var _ = config.Config{}
