package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

func writeJournal(t *testing.T, events int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := audit.Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < events; i++ {
		draft := audit.Draft{
			Timestamp: time.Now().UTC(), RequestID: fmt.Sprintf("11111111-1111-4111-8111-%012d", i),
			Principal: "spiffe://regalia/workload/release", Decision: "allow", ObjectID: "release-signing-key",
			Purpose: "release-artifact", Operation: "sign", DeviceID: "hsm-sitea", Outcome: "ok",
			RegistryDigest: "sha256:aa", PolicyDigest: "sha256:bb", RBACDigest: "sha256:cc",
		}
		if err := recorder.Record(t.Context(), draft, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// AN AUDIT TRAIL NOBODY CAN CHECK IS TAMPER-EVIDENT ONLY IN PRINCIPLE.
//
// audit.VerifyIntegrity had no caller outside its own package tests, and internal/ packages cannot
// be imported from outside the module — so the KMS wrote a hash-chained, truncation-detecting
// journal that an operator had no way to verify. The evidence was unreachable by the people the
// evidence is for.
func TestVerifyAuditReportsAnIntactJournal(t *testing.T) {
	var out bytes.Buffer
	if err := verifyAuditJournal(writeJournal(t, 3), &out); err != nil {
		t.Fatalf("an intact journal failed verification: %v", err)
	}
	report := out.String()
	for _, want := range []string{"3 events", "head sequence 3", "head hash sha256:"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not state %q, so two copies of a journal cannot be compared from it:\n%s", want, report)
		}
	}
}

// TRUNCATION IS THE ATTACK THE CHAIN ALONE CANNOT SEE. Any valid prefix of a valid chain is itself
// a valid chain, so deleting the most recent events leaves something that walks clean from genesis.
// The high-water mark is what closes that, and it was applied only inside Open until now.
func TestVerifyAuditDetectsTruncation(t *testing.T) {
	path := writeJournal(t, 4)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(contents, []byte("\n"))
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 journal lines, got %d", len(lines))
	}
	if err := os.WriteFile(path, bytes.Join(lines[:2], nil), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = verifyAuditJournal(path, &out)
	if err == nil {
		t.Fatalf("a truncated journal verified clean: the events that were removed left no trace\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("the failure does not say the journal was truncated, so an operator cannot tell tampering from corruption: %v", err)
	}
}

// A MISSING JOURNAL IS A VERIFICATION FAILURE, even though it is fine for Open, which creates one.
// Verification is the opposite situation: the operator is asking about a trail that should exist, so
// answering "intact and empty" is a green result for a deleted journal or a typo in the path.
func TestVerifyAuditRefusesAMissingJournal(t *testing.T) {
	var out bytes.Buffer
	if err := verifyAuditJournal(filepath.Join(t.TempDir(), "absent.jsonl"), &out); err == nil {
		t.Fatalf("verifying a journal that does not exist succeeded: %s", out.String())
	}
}
