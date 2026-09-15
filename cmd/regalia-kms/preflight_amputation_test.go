package main

// Round two of #237, third pass on cmd/regalia-kms: the amputation rule in preflight().
//
// #220's rule is that a journal may be absent only if nothing remembers history it should
// have, and the commissioning record is what remembers. preflight applies that rule four
// times — fencing epochs, the revocation list, the audit journal and the policy state journal
// — and #382's ledger recorded that "every existing test uses the audit half".
//
// Measured on 4a59dbd, seven of those operands still survived in BOTH directions:
//
//	:158[0] :158[1]   the fencing-epoch caveat
//	:163[0] :163[1]   the revocation-list caveat
//	:169[0] :171[0] :172[0]   the audit journal's absent-versus-damaged split
//
// What they gate is what the operator is TOLD, not whether the daemon starts, which is why
// nothing caught them: the report is the output nothing asserted on until this round.
//
// :158 sits inside `if settings.FencingLeasePath != ""`, so reaching it needs a lease path AND
// a loadable fencing public key. That containment is why the pair looked unreachable from the
// fixtures that existed — every one of them stopped at the outer guard.

import (
	"os"
	"path/filepath"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"strings"
	"testing"
)

// commissioned builds a settings whose state paths are configured, with the authority key
// published, and either with or without a signed commissioning record. Without one, the
// absence of history is unaccountable and preflight must say so; with one, the same absence is
// a commissioned site that has not been used yet.
//
// AuditJournalPath is cleared here. config couples it to three more paths — "pkcs11_module_path,
// pin_paths, secure_channel_evidence_path and audit_journal_path must be configured together" —
// and preflight refuses at settings.Validate() before reaching anything below. The existing
// provenance tests never hit that because they call checkProvenance directly rather than
// preflight. withToken below is the fixture that satisfies the coupling.
func commissioned(t *testing.T, withRecord bool) (config.Config, string) {
	t.Helper()
	settings, dir := provenanceSettings(t)
	key := authorityKeyFor(t, &settings)
	settings.FencingLeasePath = filepath.Join(dir, "lease.json")
	settings.AuditJournalPath = ""
	if withRecord {
		writeRecord(t, settings.CommissioningRecordPath, recordBody, key)
	} else {
		settings.CommissioningRecordPath = ""
	}
	return settings, dir
}

// withToken satisfies config's four-way hardware coupling so the audit-journal branch is
// reachable at all. The secure-channel evidence is real — preflight LOADS it at :143 — and is
// plain JSON with no signature, which is why this fixture is cheap and why the audit half of
// the amputation rule was reachable all along.
func withToken(t *testing.T, settings *config.Config, dir string) {
	t.Helper()
	evidence := filepath.Join(dir, "evidence.json")
	document := `{"schema_version":1,"devices":[{"device_serial":"serial-1",` +
		`"verified_by":"ceremony-2026-09-01","verified_at":"2026-09-01T10:00:00Z",` +
		`"expires_at":"2030-01-01T00:00:00Z","firmware":"4.2","secure_messaging_established":true}]}`
	if err := os.WriteFile(evidence, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(dir, "pin")
	if err := os.WriteFile(pin, []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings.SecureChannelEvidence = evidence
	settings.PINPaths = map[string]string{"hsm-sitea": pin}
	settings.PKCS11ModulePath = "/opt/nitrokey/libsc-hsm-pkcs11.so"
	settings.AuditJournalPath = filepath.Join(dir, "audit.jsonl")
}

// TestTheAmputationCaveatsTrackTheCommissioningRecord covers preflight.go:158 operands 0 and 1
// and :163 operands 0 and 1, in both directions.
//
// Each caveat says the same thing about a different journal: preflight does not read it, so a
// truncated or emptied one is indistinguishable from one that was never written. That is only
// true WITHOUT provenance. With a commissioning record the absence is accounted for, and
// printing the caveat anyway tells an operator they have a blind spot they do not have.
//
// Falsifier: `(true || (settings.CommissioningRecordPath == ""))` keeps the caveat on a
// commissioned host; `(false && (settings.FencingStatePath != ""))` drops it from a host that
// genuinely has one.
func TestTheAmputationCaveatsTrackTheCommissioningRecord(t *testing.T) {
	for _, row := range []struct {
		name     string
		fragment string
	}{
		{"the fencing epoch journal", "fencing epoch journal is not read"},
		{"the revocation list", "revocation list is not read"},
	} {
		t.Run(row.name+" is caveated on an unaccountable host", func(t *testing.T) {
			settings, _ := commissioned(t, false)
			_, _, _, _, report, err := preflight(settings)
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			if !unchecked(report, row.fragment) {
				t.Fatalf("no caveat for %s on a host with the path configured and NO commissioning "+
					"record — the operator is not told that absence and loss look the same here: %v",
					row.name, report.Unchecked)
			}
		})
		t.Run(row.name+" is not caveated on a commissioned host", func(t *testing.T) {
			settings, _ := commissioned(t, true)
			_, _, _, _, report, err := preflight(settings)
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			if unchecked(report, row.fragment) {
				t.Fatalf("%s was caveated on a host whose commissioning record accounts for its "+
					"history — a blind spot reported where there is none: %v", row.name, report.Unchecked)
			}
		})
	}
}

// TestTheAuditJournalIsReadThroughTheCommissioningRecord covers preflight.go:169, :171 and
// :172, in both directions, plus :179.
//
// The three states are distinct and preflight distinguishes them: not configured (say
// nothing), configured and absent (say what the absence MEANS, which depends on the record),
// and configured and present (read it, and refuse if it does not verify).
//
// Falsifier: `(true || (settings.AuditJournalPath != ""))` reports on a journal nobody
// configured; `(true || (errors.Is(statErr, os.ErrNotExist)))` reports a DAMAGED journal as
// one that does not exist yet, which is the #220 inversion one arm over; and
// `(true || (settings.CommissioningRecordPath != ""))` tells an unaccountable host its absence
// is benign.
func TestTheAuditJournalIsReadThroughTheCommissioningRecord(t *testing.T) {
	t.Run("not configured means nothing is said about it", func(t *testing.T) {
		settings, _ := commissioned(t, true)
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if noted(report, "audit journal") {
			t.Fatalf("preflight reported on an audit journal that was never configured: %v",
				report.Checked)
		}
	})

	t.Run("absent on a commissioned host is not a loss", func(t *testing.T) {
		settings, dir := commissioned(t, true)
		withToken(t, &settings, dir)
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !noted(report, "commissioned site with no events") {
			t.Fatalf("an absent journal on a commissioned host was not read through the record: %v",
				report.Checked)
		}
	})

	t.Run("absent on an unaccountable host is indistinguishable from loss", func(t *testing.T) {
		settings, dir := commissioned(t, false)
		withToken(t, &settings, dir)
		_, _, _, _, report, err := preflight(settings)
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if !noted(report, "indistinguishable from losing it") {
			t.Fatalf("an absent journal with no commissioning record was reported as benign — "+
				"that is the difference #220 exists to keep visible: %v", report.Checked)
		}
	})

	t.Run("present and damaged is refused, not read as absent", func(t *testing.T) {
		settings, dir := commissioned(t, true)
		withToken(t, &settings, dir)
		if err := os.WriteFile(settings.AuditJournalPath, []byte("{not a journal\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, _, _, report, err := preflight(settings)
		if err == nil {
			t.Fatalf("a damaged audit journal was accepted; the report says %v", report.Checked)
		}
		if !strings.Contains(err.Error(), "audit journal") {
			t.Fatalf("preflight refused, but not on the journal: %v", err)
		}
		// "audit journal", not "does not exist yet": the POLICY STATE journal is absent in this
		// fixture and carries the same phrase, so the looser fragment matched its note and the
		// row failed for the wrong reason. A report assertion has to name which line it means.
		if noted(report, "audit journal does not exist yet") {
			t.Fatal("a journal that exists and is damaged was reported as one that does not exist")
		}
	})
}

// TestAnAuditSinkThatTheSinkWouldRejectIsRefused covers preflight.go:186.
//
// The sink URL is validated here so -check-config refuses a malformed one without starting the
// daemon. Nothing drove either arm.
//
// Falsifier: `(false && (err != nil))` accepts a URL the sink will reject at runtime, which
// moves the failure from a preflight refusal to a daemon that starts and cannot ship audit.
func TestAnAuditSinkThatTheSinkWouldRejectIsRefused(t *testing.T) {
	settings, _ := commissioned(t, true)
	settings.AuditSinkURL = "http://audit.internal/ingest"
	_, _, _, _, _, err := preflight(settings)
	if err == nil {
		t.Fatal("a plaintext http audit sink was accepted; the sink requires an https origin")
	}
	if !strings.Contains(err.Error(), "audit sink") {
		t.Fatalf("preflight refused, but not on the sink: %v", err)
	}
}

// TestPreflightReportsTheTokenSideItCanCheckAndCaveatsTheRest covers preflight.go:142 and :143
// (the secure-channel evidence load) and :230 (the token caveat), in the direction where the
// operand is deleted and the check silently stops happening.
//
// :230 is the row #387 could not build: reaching it needs a configuration with a PKCS#11
// module set, which config couples to three more paths, one of which preflight LOADS. The
// evidence document turned out to be plain JSON with no signature, so the fixture is cheap —
// the operand was reachable all along and the ledger entry saying otherwise was a fixture gap,
// not a property of the code.
//
// Falsifier: `(false && (settings.SecureChannelEvidence != ""))` skips the load entirely and
// the note disappears; `(false && (settings.PKCS11ModulePath != ""))` drops the caveat and the
// operator is told nothing was left unchecked on a host whose token was never contacted.
func TestPreflightReportsTheTokenSideItCanCheckAndCaveatsTheRest(t *testing.T) {
	settings, dir := commissioned(t, true)
	withToken(t, &settings, dir)
	_, _, _, _, report, err := preflight(settings)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if !noted(report, "secure-channel evidence is well-formed") {
		t.Fatalf("configured secure-channel evidence was not loaded or not reported: %v", report.Checked)
	}
	if !unchecked(report, "PKCS#11 module is not loaded") {
		t.Fatalf("preflight claimed nothing was left unchecked on a host with a module configured; "+
			"the token was NOT contacted and the report must say so: %v", report.Unchecked)
	}
}

// TestAnUnreadableFencingKeyIsRefused covers preflight.go:149.
//
// The fencing public key is what a lease is verified against. Deleting the error check lets
// preflight pass on a host whose key cannot be parsed, and the daemon then starts and fails to
// verify any lease at all.
//
// Falsifier: `(false && (err != nil))`.
func TestAnUnreadableFencingKeyIsRefused(t *testing.T) {
	settings, _ := commissioned(t, true)
	if err := os.WriteFile(settings.FencingPublicKeyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, err := preflight(settings)
	if err == nil {
		t.Fatal("a fencing public key that does not parse was accepted")
	}
}

// TestACaveatIsNotPrintedForARevocationListNobodyConfigured covers preflight.go:163 operand 0
// in the TRUE direction — the guard firing unconditionally.
//
// The caveat names a specific journal. Printed for a path that is not configured, it tells an
// operator they have a blind spot on a file the deployment does not have.
//
// :158's matching operand is NOT pinned here and cannot be. It sits inside
// `if settings.FencingLeasePath != ""`, and config refuses any configuration setting only some
// of "fencing_lease_path, fencing_state_path and fencing_public_key_path" — so whenever :158 is
// reached, FencingStatePath is already non-empty and forcing the operand true is a no-op. Same
// shape as :108 and the policy-path coupling; recorded as masked, with the control arm in the
// PR rather than a claim that the pair proved it.
//
// Falsifier: `(true || (settings.RevokedSerialsPath != ""))`.
func TestACaveatIsNotPrintedForARevocationListNobodyConfigured(t *testing.T) {
	settings, _ := commissioned(t, false)
	settings.RevokedSerialsPath = ""
	_, _, _, _, report, err := preflight(settings)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if unchecked(report, "revocation list is not read") {
		t.Fatalf("preflight caveated a revocation list on a host that configures none: %v",
			report.Unchecked)
	}
}

// TestMalformedSecureChannelEvidenceIsRefused covers preflight.go:143 in the FALSE direction.
//
// The row above proves the evidence is LOADED and reported when it is valid, which pins the
// TRUE direction. It cannot pin FALSE: with the error check deleted, valid evidence still
// produces the note and that test still passes. Only evidence that fails to load separates
// them — the same success-arm/refusal-arm pairing that :150 and :197 needed in #386, in the
// other order.
//
// Falsifier: `(false && (err != nil))`. preflight then notes that the evidence is "well-formed
// and unexpired" over a file it could not parse.
func TestMalformedSecureChannelEvidenceIsRefused(t *testing.T) {
	settings, dir := commissioned(t, true)
	withToken(t, &settings, dir)
	if err := os.WriteFile(settings.SecureChannelEvidence, []byte(`{"schema_version":1,"devices":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, report, err := preflight(settings)
	if err == nil {
		t.Fatalf("evidence naming no device was accepted; the report says %v", report.Checked)
	}
	if !strings.Contains(err.Error(), "secure-channel evidence") {
		t.Fatalf("preflight refused, but not on the evidence: %v", err)
	}
	if noted(report, "secure-channel evidence is well-formed") {
		t.Fatal("preflight vouched for evidence it could not load")
	}
}
