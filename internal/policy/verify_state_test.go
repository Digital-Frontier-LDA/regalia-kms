package policy

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func journalWith(t *testing.T, reservations int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reservations; i++ {
		item := reservation(fmt.Sprintf("nonce_%012d", i), "2026-09-04", 10, 1_000)
		if err := state.Reserve(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// THE JOURNAL THAT HOLDS SPENT QUOTA COULD NOT BE CHECKED BY ANYONE.
//
// This journal records every reservation and every consumed nonce, so shortening it restores spent
// quota and permits replay — which is exactly why the high-water mark exists. Yet the package
// exported OpenFileState and nothing else, and OpenFileState takes an EXCLUSIVE flock for the
// process lifetime, so verifying it meant stopping the daemon.
func TestVerifyStateReportsAnIntactJournal(t *testing.T) {
	summary, err := VerifyState(journalWith(t, 3))
	if err != nil {
		t.Fatalf("an intact journal failed verification: %v", err)
	}
	if summary.Reservations != 3 || summary.HeadSequence != 3 || !strings.HasPrefix(summary.HeadHash, "sha256:") {
		t.Fatalf("summary does not describe the journal: %+v", summary)
	}
}

// VERIFICATION MUST NOT NEED THE LOCK. OpenFileState holds an exclusive flock for the process
// lifetime, so if verification took one too, an operator could only check a journal by stopping the
// service that writes it — and the moment you most want to verify is the moment you least want to
// stop it.
func TestVerifyStateWorksWhileTheDaemonHoldsTheJournal(t *testing.T) {
	path := journalWith(t, 2)
	holder, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	summary, err := VerifyState(path)
	if err != nil {
		t.Fatalf("verification failed while the journal was open by a writer: %v", err)
	}
	if summary.Reservations != 2 {
		t.Fatalf("expected 2 reservations, got %+v", summary)
	}
}

// Truncation is what the high-water mark exists to catch: a shortened journal is a valid chain, and
// the quota it recorded as spent becomes available again.
func TestVerifyStateDetectsTruncation(t *testing.T) {
	path := journalWith(t, 4)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(contents, []byte("\n"))
	if len(lines) < 4 {
		t.Fatalf("expected at least 4 lines, got %d", len(lines))
	}
	if err := os.WriteFile(path, bytes.Join(lines[:2], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyState(path)
	if err == nil {
		t.Fatal("a truncated policy state journal verified clean: the spent quota it recorded is available again and nothing said so")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("the failure does not say the journal was truncated: %v", err)
	}
}

// A missing journal is a verification failure even though OpenFileState creates one.
func TestVerifyStateRefusesAMissingJournal(t *testing.T) {
	if _, err := VerifyState(filepath.Join(t.TempDir(), "absent.jsonl")); err == nil {
		t.Fatal("verifying a policy state journal that does not exist succeeded")
	}
}
