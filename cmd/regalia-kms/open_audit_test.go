package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

// TestTheAuditSinkRefusesEveryWayItCouldShipUnauthenticated.
//
// openAudit is where AUDIT.md's "the trail ships over mutual TLS, to a pinned host, without a
// proxy" is actually enforced, and it was covered by nothing. The trail is the record of every key
// use: a sink reachable over an unauthenticated client is not a degraded audit, it is an audit
// stream delivered to whoever answers.
//
// Each case removes exactly one piece of what makes the sink trustworthy and asserts the daemon
// refuses to start rather than shipping anyway. They are subtests so that one refusal failing
// cannot mask the rest — a Fatalf in a shared loop body stops the cases after it.
func TestTheAuditSinkRefusesEveryWayItCouldShipUnauthenticated(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	journal := filepath.Join(dir, "audit.jsonl")

	emptyPEM := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(emptyPEM, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	garbageKey := filepath.Join(dir, "garbage.key")
	if err := os.WriteFile(garbageKey, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		settings config.Config
		wants    string
	}{
		"no client certificate at all": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "https://collector.test"},
			wants:    "mutual TLS",
		},
		"a keypair that does not load": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "https://collector.test",
				TLSCertificatePath: certPath, TLSPrivateKeyPath: garbageKey, TLSClientCAPath: certPath},
			wants: "load audit client keypair",
		},
		"trust roots that cannot be read": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "https://collector.test",
				TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath, TLSClientCAPath: filepath.Join(dir, "absent.pem")},
			wants: "read audit trust roots",
		},
		"trust roots holding no usable certificate": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "https://collector.test",
				TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath, TLSClientCAPath: emptyPEM},
			wants: "no usable certificate",
		},
		// Not https: the pinned server name comes from the URL, and over plaintext there is
		// nothing to pin it to. sinkServerName owns the refusal; this asserts openAudit routes
		// through it rather than building a client that would never verify anything.
		"a sink URL that is not https": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "http://collector.test",
				TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath, TLSClientCAPath: certPath},
			wants: "must be https",
		},
		// AUDIT.md requires an ORIGIN, not an endpoint: the sink appends its own path, so a
		// configured path would silently produce a different URL than the operator wrote. Refused
		// by ValidateSinkURL, which openAudit reaches only after every check above has passed —
		// so this case also proves the earlier refusals are not swallowing it.
		"a sink URL carrying a path rather than an origin": {
			settings: config.Config{AuditJournalPath: journal, AuditSinkURL: "https://collector.test/v1/audit",
				TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath, TLSClientCAPath: certPath},
			wants: "invalid audit collector configuration",
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The refusals live in auditSinkFor since collector reconciliation split
			// sink construction from recorder open (startup reconciles against the sink
			// BEFORE opening the journal, so a bad sink can never get that far).
			_, err := auditSinkFor(test.settings)
			if err == nil {
				t.Fatalf("auditSinkFor accepted a sink with %s: the audit trail would ship over a client that proves nothing", name)
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("auditSinkFor() error = %q, want it to mention %q — a refusal for a different reason would leave this one unproven",
					err, test.wants)
			}
			// NOT "Stat returned an error". Any error would satisfy that -- a permission or I/O
			// failure would read as "absent" and the assertion would pass without the journal
			// having been checked at all. Only ErrNotExist proves the file is not there.
			if _, statErr := os.Stat(journal); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("journal at %s: stat = %v, want ErrNotExist — a daemon that fails to start must not leave state behind, and any other error means this was not established",
					journal, statErr)
			}
		})
	}
}

// TestAnAuditSinkIsOptionalAndItsAbsenceIsNotAFailure. The local journal is the primary record and
// the sink is the off-host copy; a deployment that has not configured shipping must still start,
// or the refusals above would be indistinguishable from "shipping is mandatory".
func TestAnAuditSinkIsOptionalAndItsAbsenceIsNotAFailure(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "audit.jsonl")

	recorder, err := openAudit(config.Config{AuditJournalPath: journal}, nil)
	if err != nil {
		t.Fatalf("openAudit() with no sink error = %v", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("no journal at %s after opening the recorder: %v", journal, err)
	}
}

// TestFullyConfiguredMutualTLSIsAccepted, so the refusals above are shown to be about the missing
// piece and not about openAudit rejecting every sink it is given.
func TestFullyConfiguredMutualTLSIsAccepted(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeypair(t, dir, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	journal := filepath.Join(dir, "audit.jsonl")

	recorder, err := openAudit(config.Config{
		AuditJournalPath: journal, AuditSinkURL: "https://collector.test",
		TLSCertificatePath: certPath, TLSPrivateKeyPath: keyPath, TLSClientCAPath: certPath,
	}, nil)
	if err != nil {
		t.Fatalf("openAudit() with complete mTLS material error = %v: the refusal cases prove nothing if this path also fails", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
}

// TestPreflightOutputCannotBeMisreadAsAllClear.
//
// -check-config prints two kinds of line and an operator decides whether to deploy by scanning
// them. An unchecked item is not a passing one — it is a thing preflight could not answer, like a
// missing approver key set that will deny every approval-requiring request at runtime — so the two
// must not be confusable at a glance.
//
// The assertion is on the DISTINCTION rather than on the exact strings: pinning "  ok      " would
// fail on a harmless realignment while still passing if both prefixes became the same word.
func TestPreflightOutputCannotBeMisreadAsAllClear(t *testing.T) {
	var out strings.Builder
	writePreflight(&preflightReport{
		Checked:   []string{"registry loads, 3 objects"},
		Unchecked: []string{"no approver key set is configured"},
	}, &out)

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("writePreflight emitted %d lines for one checked and one unchecked item:\n%s", len(lines), out.String())
	}
	var checked, unchecked string
	for _, line := range lines {
		if strings.Contains(line, "registry loads") {
			checked = line
		}
		if strings.Contains(line, "approver key set") {
			unchecked = line
		}
	}
	if checked == "" || unchecked == "" {
		t.Fatalf("an item did not reach the output at all:\n%s", out.String())
	}
	// strings.Fields, not Split on a literal space: the point of this test is that alignment may
	// change freely, and a split on " " would return the whole line as element zero the moment the
	// formatting used a tab. The two whole lines differ, so the comparison below would pass while
	// measuring nothing.
	checkedMarker := firstField(t, checked)
	uncheckedMarker := firstField(t, unchecked)
	if checkedMarker == uncheckedMarker {
		t.Fatalf("both lines lead with %q, so an unanswered check reads as a passing one:\n%s", checkedMarker, out.String())
	}
	// Case matters more than the word: an operator skimming a long report sees shape before text,
	// and the unchecked marker is the one that must interrupt them.
	if uncheckedMarker != strings.ToUpper(uncheckedMarker) || checkedMarker == strings.ToUpper(checkedMarker) {
		t.Fatalf("the unchecked marker %q does not stand out against the checked marker %q", uncheckedMarker, checkedMarker)
	}
}

func firstField(t *testing.T, line string) string {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) == 0 {
		t.Fatalf("no marker on line %q", line)
	}
	return fields[0]
}
