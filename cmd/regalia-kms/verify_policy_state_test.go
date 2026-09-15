package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

func journalWith(t *testing.T, reservations int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := policy.OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= reservations; index++ {
		nonce := fmt.Sprintf("nonce_%012d", index)
		if err := state.Reserve(context.Background(), policy.Reservation{
			PolicyID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer",
			Principal: "spiffe://regalia/workload/tx-signer", Nonce: nonce, UTCDate: "2026-09-05",
			Amounts:   map[string]uint64{"uatom": 100},
			DailyCaps: map[string]uint64{"uatom": 1_000_000},
		}); err != nil {
			t.Fatalf("reserving %d: %v", index, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// THE OPERATOR COMMAND THE QUOTA ALERT SENDS PEOPLE TO, AT 0%.
//
// RUNBOOK-KMS-OPERATOR.md's RegaliaQuotaRejectionsSustained row tells a responder to run
// `-verify-policy-state`, and quotes the output it should see. This pins that the command
// produces what the runbook says it produces -- a runbook whose quoted transcript has drifted
// from the binary is worse than one with no transcript, because the reader compares their output
// against it and concludes the wrong thing.
func TestVerifyPolicyStateReportsWhatTheRunbookQuotes(t *testing.T) {
	var out bytes.Buffer
	path := journalWith(t, 1)
	if err := verifyPolicyStateJournal(path, &out); err != nil {
		t.Fatalf("an intact journal was reported as a failure: %v", err)
	}
	// The whole line, not fragments. "1 reservations" is a substring of "10 reservations" and
	// "head sequence 1" of "head sequence 10", so a fragment check passes on a journal with ten
	// times the entries -- which is precisely the number an operator is reading the line for.
	printed := out.String()
	expected := fmt.Sprintf("policy state journal %s is intact: 1 reservations, head sequence 1, head hash sha256:", path)
	if !strings.HasPrefix(printed, expected) {
		t.Errorf("the command no longer prints what the runbook quotes:\n got %q\nwant prefix %q", printed, expected)
	}
	// And the hash is a hash: the line ends with sha256: followed by 64 hex digits and nothing
	// else. Without this the prefix check passes on a line whose hash is empty or truncated,
	// which is what an operator would be comparing against their own output.
	if !regexp.MustCompile(`head hash sha256:[0-9a-f]{64}\n$`).MatchString(printed) {
		t.Errorf("the line does not end in a full sha256 digest: %q", printed)
	}
}

// An empty journal says so, rather than reporting a head of nothing.
func TestVerifyPolicyStateDistinguishesEmptyFromPopulated(t *testing.T) {
	var out bytes.Buffer
	if err := verifyPolicyStateJournal(journalWith(t, 0), &out); err != nil {
		t.Fatalf("an empty journal was reported as a failure: %v", err)
	}
	if printed := out.String(); !strings.Contains(printed, "intact and empty") {
		t.Errorf("an empty journal did not say so: %q", printed)
	}
	if printed := out.String(); strings.Contains(printed, "head sequence") {
		t.Errorf("an empty journal reported a head: %q", printed)
	}
}

// THE ASYMMETRY THE RUNBOOK CALLS OUT, PINNED.
//
// "at preflight a *missing* policy journal is fine (the daemon creates it), but
// `-verify-policy-state` on a missing file fails — the preflight asks 'may I start', the verifier
// asks 'is the trail there', and they are different questions."
//
// Answering "empty and intact" for a deleted journal or a mistyped path would be a green result
// for the two cases an operator most needs told apart from a clean one.
func TestVerifyPolicyStateFailsOnAMissingJournalEvenThoughTheDaemonWouldCreateOne(t *testing.T) {
	directory := t.TempDir()
	absent := filepath.Join(directory, "policy-state.jsonl")

	var out bytes.Buffer
	err := verifyPolicyStateJournal(absent, &out)
	if err == nil {
		t.Fatalf("a missing journal verified successfully, printing %q", out.String())
	}
	if !strings.Contains(err.Error(), "cannot verify") {
		t.Errorf("the failure does not say the journal could not be verified: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a failed verification still printed a report: %q", out.String())
	}

	// The other half of the asymmetry: the daemon's own open of that same path creates it.
	// Without this the test above is just "missing file errors", which is not the claim.
	state, openErr := policy.OpenFileState(absent)
	if openErr != nil {
		t.Fatalf("the daemon could not create the journal the verifier refused: %v", openErr)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(absent); statErr != nil {
		t.Fatalf("the journal was not created: %v", statErr)
	}
}

// A shortened journal is what makes a spent quota available again, so it must never verify.
func TestVerifyPolicyStateRefusesATruncatedJournal(t *testing.T) {
	path := journalWith(t, 2)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(contents), "\n")
	if len(lines) < 2 {
		t.Fatalf("the fixture has %d lines: a truncation cannot be tested", len(lines))
	}
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = verifyPolicyStateJournal(path, &out)
	if err == nil {
		t.Fatalf("a truncated journal verified successfully, printing %q", out.String())
	}
	// SPECIFICALLY truncation. A malformed line, a JSON error or an unreadable file would all
	// satisfy "some error came back" while saying something quite different to an operator --
	// and truncation is the one that means spent quota and consumed nonces are available again.
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("the journal was refused for another reason, so truncation is not what caught it: %v", err)
	}
}
