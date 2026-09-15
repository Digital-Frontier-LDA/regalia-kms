package main

// GUARD COVERAGE, ROUND 2 (#237). The first pass over this package mutated 103 whole `if`
// CONDITIONS to `if false && (<original>)`. This pass re-derived the population from
// tools/guardenum and swept per LEAF OPERAND: 152 sites / 165 operands, one
// operand-direction each, plus 10 operands in a shape guardenum does not enumerate at all.
//
// THE SHAPE THE ENUMERATOR CANNOT SEE. guardenum's header states that an `if` condition and a
// boolean `return` "are the only places these operands occur" and that there is "no sixth to
// discover later". Go has one more: a case clause of a switch with NO tag expression is a
// boolean branch with neither keyword. This package uses that form for exactly the decisions a
// sweep most wants — what the ABSENCE of a state file means (#220), and whether the server
// certificate is inside its validity window — and three of the four survivors in that shape are
// pinned below. They were invisible to the tool, not merely unswept by it.
//
// Each test here is the SOLE failure when its operand is neutralised, and each was falsified
// that way before being committed. The survivors this file does NOT pin are recorded in the PR
// ledger with a reachability argument apiece; the largest group is run()'s startup wiring past
// the missing-manifest refusal, which no fixture executes at all.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

// A PROVENANCE REFUSAL MUST REACH THE OPERATOR, NOT BECOME A NOTE ABOUT ITS OWN ABSENCE.
//
// Every #220 refusal is asserted against checkProvenance directly — history without provenance,
// an uncommissioned host, a forged or unsigned record, a record for another site. preflight is
// the only thing that CALLS checkProvenance, and it is driven in the existing suite only with
// the record path unset (the unconfigured rows) or with a record that verifies. So the branch
// that turns a provenance verdict into a preflight verdict was never exercised in the refusing
// direction.
//
// Measured with `case provenanceErr != nil:` neutralised: record is nil on error, so the switch
// falls past `case record != nil` to the default arm, which appends "no commissioning record is
// configured" to Unchecked and returns a NIL error. Every #220 refusal is silently downgraded to
// a note saying the host has no record — on a host that has one configured and state it cannot
// account for. run() then starts the daemon, because main's `if preflightErr != nil` at main.go:178
// receives nil.
//
// NOT via `-check-config`, which this comment claimed until 2026-09-10 and which is the one path
// that is NOT exposed: main.go:175 prints "preflight passed" and main.go:176 returns nil
// immediately, so the daemon never starts on that path. The exposure is the ORDINARY startup path,
// where the downgraded error reaches :178, passes the nil check, and execution continues to :181.
// Naming the wrong path makes the hazard look like a diagnostic-flag problem rather than the
// default one.
//
// That is the inversion the issue was filed over, arriving one layer above where it was fixed:
// the check is correct, the wiring that acts on it is not, and nothing anywhere reports a
// difference.
func TestPreflightReturnsTheProvenanceRefusalRatherThanNotingItsAbsence(t *testing.T) {
	settings, _ := provenanceSettings(t)
	// The hardware and fencing quartets are all-or-nothing in Validate, and preflight runs
	// Validate first — so the paths this test does not need are cleared rather than
	// half-configured, or the refusal would come from the wrong detector.
	settings.AuditJournalPath = ""
	settings.FencingStatePath = ""
	settings.FencingPublicKeyPath = ""

	// State exists and the commissioning record does not: "history without provenance", the row
	// checkProvenance refuses and preflight must pass on. The revocation list is the state used
	// because it belongs to no all-or-nothing group in Validate.
	if err := os.WriteFile(settings.RevokedSerialsPath, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _, _, _, report, err := preflight(settings)
	if err == nil {
		t.Fatalf("preflight accepted a host with state and no commissioning record — the refusal became a note (%q) and -check-config would print \"preflight passed\" over an unaccountable host",
			strings.Join(report.Unchecked, " | "))
	}
	if !strings.Contains(err.Error(), "history without provenance") {
		t.Fatalf("preflight refused, but not with the provenance verdict: %v — a refusal from any other check would leave the provenance wiring unproven", err)
	}
}

// A COMMISSIONED HOST MUST NOT BE REPORTED AS ONE WITH NO RECORD.
//
// The `case record != nil:` arm is what turns a verified record into the line an operator reads
// before deploying. Measured with it neutralised: the switch falls to its default arm, so a host
// whose record VERIFIED is told "no commissioning record is configured, so a missing journal
// cannot be distinguished from a lost one" — the exact ambiguity the record exists to remove,
// reported at a host that has removed it.
//
// The existing #220 row that drives preflight with a valid record asserts on the POLICY STATE
// note ("the commissioning record makes that a commissioned site"), which is emitted by a
// different guard reading the same setting, so it stays green through this one.
func TestPreflightNamesTheCommissionedSiteRatherThanReportingItUnaccountable(t *testing.T) {
	settings, _ := provenanceSettings(t)
	key := authorityKeyFor(t, &settings)
	settings.AuditJournalPath = ""
	// fencing_lease_path completes the trio provenanceSettings leaves at two, so Validate passes.
	settings.FencingLeasePath = filepath.Join(filepath.Dir(settings.CommissioningRecordPath), "lease.json")
	writeRecord(t, settings.CommissioningRecordPath, recordBody, key)

	_, _, _, _, report, err := preflight(settings)
	if err != nil {
		t.Fatalf("a commissioned host failed preflight: %v", err)
	}
	if unchecked := strings.Join(report.Unchecked, "\n"); strings.Contains(unchecked, "no commissioning record is configured") {
		t.Fatalf("preflight told a commissioned host it has no commissioning record:\n%s\n— the record verified, and the one line saying so is what an operator rebuilding under pressure reads", unchecked)
	}
	if checked := strings.Join(report.Checked, "\n"); !strings.Contains(checked, "site commissioned at") {
		t.Fatalf("preflight verified the record and never said so:\n%s\n— a verdict nobody can read is not a report", checked)
	}
}

// A CERTIFICATE THAT IS NOT VALID YET FAILS THE SAME WAY AN EXPIRED ONE DOES.
//
// preflight refuses an expired server certificate and reports remaining life for a valid one,
// and both arms are tested. The third arm — `case now.Before(leaf.NotBefore):` — had no fixture,
// and its fixture was already sitting in the helper's signature: writeKeypair takes notBefore as
// a parameter and every caller passed a time in the past.
//
// A future NotBefore is not a hypothetical. It is what a provisioning host with a skewed clock
// issues, and what a certificate cut ahead of a scheduled rotation looks like until the window
// opens. The consequence is identical to the expired case the suite does test: the listener
// refuses every connection. Measured with the arm neutralised, preflight takes the default arm
// and reports "server certificate is valid until <date> (N days remaining)" — a green line, with
// a remaining-life figure, for a certificate that is not usable yet.
func TestPreflightRefusesAServerCertificateThatIsNotValidYet(t *testing.T) {
	now := time.Now()
	settings := completeSettings(t)
	dir := tlsSettings(t, now.Add(48*time.Hour), now.Add(90*24*time.Hour))
	settings.ListenAddress = "0.0.0.0:8443"
	settings.TLSCertificatePath = filepath.Join(dir, "server.crt")
	settings.TLSPrivateKeyPath = filepath.Join(dir, "server.key")
	settings.TLSClientCAPath = filepath.Join(dir, "clients.pem")

	_, _, _, _, report, err := preflight(settings)
	if err == nil {
		t.Fatalf("preflight accepted a certificate that is not valid for another 48 hours, reporting %q — the listener would refuse every connection and preflight said the configuration was fine",
			strings.Join(report.Checked, " | "))
	}
	if !strings.Contains(err.Error(), "not valid until") {
		t.Fatalf("preflight refused, but not because the certificate has not started: %v — an operator whose clock is skewed needs to be told which end of the window is wrong", err)
	}
}

// AN EXISTING BUT EMPTY AUDIT JOURNAL IS A VERDICT, NOT AN INDEX OUT OF RANGE.
//
// verifyPolicyStateJournal has TestVerifyPolicyStateDistinguishesEmptyFromPopulated. Its twin,
// verifyAuditJournal, has tests for an intact journal, a truncated one and a missing one — and
// none for the empty one. The bound was named on one side only, and the unnamed side is the one
// that crashes: with `len(events) == 0` neutralised, `events[len(events)-1]` indexes -1 and the
// command dies with a runtime panic.
//
// The state is ordinary rather than exotic. audit.Open creates the journal on first start, so
// every commissioned site has exactly this file between commissioning and its first key use —
// which is precisely when an operator runs -verify-audit to confirm the trail is sound before
// putting the site into service.
//
// The panic is recovered here rather than left to kill the test binary: a panicking mutation
// aborts the process and truncates the failing set, so a test that dies with it cannot be shown
// to be the sole detector of anything.
func TestVerifyAuditDistinguishesAnEmptyJournalFromAPopulatedOne(t *testing.T) {
	path := writeJournal(t, 0)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the fixture did not create the journal, so this test cannot tell empty from missing: %v", err)
	}

	var out bytes.Buffer
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("verifying an existing but empty audit journal panicked: %v — a commissioned site has exactly this file until its first key use, and -verify-audit is what an operator runs on it",
				recovered)
		}
	}()

	if err := verifyAuditJournal(path, &out); err != nil {
		t.Fatalf("an empty journal failed verification: %v — the daemon creates the file on first start, so this is a state every site passes through", err)
	}
	// "intact and empty", not merely "intact": a report that does not say the journal holds no
	// events reads the same as one summarising events it never printed.
	if report := out.String(); !strings.Contains(report, "intact and empty") {
		t.Fatalf("the report does not say the journal is empty: %q — an operator comparing two copies needs the event count, and an absent one reads as unreported rather than zero", report)
	}
}

// THE AUDIT SINK IS OPTIONAL, AND THE GUARD THAT MAKES IT OPTIONAL IS THE ONE TO ASSERT AGAINST.
//
// TestAnAuditSinkIsOptionalAndItsAbsenceIsNotAFailure names this property and does not gate it:
// it calls openAudit(settings, nil), handing in the nil sink itself rather than asking
// auditSinkFor for one. Every case that DOES call auditSinkFor sets audit_sink_url. So the early
// return that makes shipping optional had no test on either side of it.
//
// Measured with `settings.AuditSinkURL == ""` neutralised: a journal-only deployment falls into
// the mTLS block and startup fails with "audit_sink_url requires mutual TLS material" — a host
// that ships nothing refused for lacking the material to ship it. This is a refusal-direction
// defect, which a mutation sweep is structurally worst at finding: every negative test stays
// green because the daemon still refuses, just for the wrong reason and at the wrong host.
//
// No known-good arm is added here. The complement is already the whole of
// TestTheAuditSinkRefusesEveryWayItCouldShipUnauthenticated, so a mutant that returned (nil,
// nil) unconditionally is caught there rather than needing a second assertion in this test that
// could halt before the one above it.
func TestAnUnconfiguredAuditSinkIsNoSinkRatherThanARefusal(t *testing.T) {
	settings := config.Config{AuditJournalPath: filepath.Join(t.TempDir(), "audit.jsonl")}

	sink, err := auditSinkFor(settings)
	if err != nil {
		t.Fatalf("auditSinkFor refused a deployment that ships nothing: %v — the local journal is the primary record, and a host with no collector must still start", err)
	}
	// The ANSWER, not merely the absence of an error: a non-nil sink built from no URL would
	// satisfy err == nil and then ship the audit trail somewhere nobody configured.
	if sink != nil {
		t.Fatalf("auditSinkFor built a sink %T from an empty audit_sink_url — reconciliation and the recorder would both ship to a destination the configuration does not name", sink)
	}
}
