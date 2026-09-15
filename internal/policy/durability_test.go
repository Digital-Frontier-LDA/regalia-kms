package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TRUNCATING THE JOURNAL MUST NOT RESTORE SPENT NONCES OR QUOTA.
//
// The journal is a hash chain validated from genesis, which proves nobody EDITED it and says
// nothing about TRUNCATION: any valid prefix is itself a valid chain. Deleting the tail therefore
// reopened cleanly with the replay record and the daily cap restored — a replay and an overspend
// obtained with `truncate`, by anyone who can write the file the service already trusts.
func TestTruncatedJournalIsDetectedRatherThanResettingQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.jsonl")

	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, nonce := range []string{"nonce_000000000001", "nonce_000000000002", "nonce_000000000003"} {
		if err := state.Reserve(context.Background(), reservation(nonce, "2026-09-04", 30, 100)); err != nil {
			t.Fatalf("reserve %s: %v", nonce, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	// Roll the journal back to a single event: a valid chain, and a shorter history.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(contents), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 journal lines, got %d", len(lines))
	}
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileState(path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("a truncated journal reopened; spent nonces and quota would be reusable")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// A REWRITTEN JOURNAL OF THE SAME LENGTH IS ALSO A ROLLBACK. Swapping the history for a different
// one that happens to be as long must not pass either.
func TestRewrittenJournalOfEqualLengthIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	// Build a different single-event journal from genesis: internally consistent, wrong history.
	fresh := filepath.Join(t.TempDir(), "other.jsonl")
	other, err := OpenFileState(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Reserve(context.Background(), reservation("nonce_000000000009", "2026-09-04", 10, 100)); err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	swapped, err := os.ReadFile(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, swapped, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileState(path)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("a journal swapped for a different history of the same length reopened")
	}
}

// TWO PROCESSES MUST NOT SHARE ONE JOURNAL.
//
// Replay and quota are enforced from maps loaded at open, so a second process keeps its own copy:
// both grant the same nonce and both spend the full daily cap. That is a double-spend obtained by
// starting the service twice — a deployment mistake, not an attack — so it must fail at startup.
func TestASecondProcessCannotOpenTheSameJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.jsonl")
	first, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := OpenFileState(path)
	if err == nil {
		_ = second.Close()
		t.Fatal("two instances opened one policy journal; both would grant the same nonce and spend the full cap")
	}
	if !strings.Contains(err.Error(), "already open") {
		t.Fatalf("error does not name the cause: %v", err)
	}

	// Closing the first must release the lock, or a restart could never take over.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("the journal stayed locked after the holder closed it: %v", err)
	}
	_ = third.Close()
}

// The ordinary path must still work: reopening an intact journal keeps its history.
func TestIntactJournalReopensAndKeepsItsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 60, 100)); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("an intact journal was refused: %v", err)
	}
	defer reopened.Close()
	if err := reopened.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err != ErrReplay {
		t.Fatalf("replay across restart = %v, want ErrReplay", err)
	}
	if err := reopened.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-04", 50, 100)); err != ErrLimit {
		t.Fatalf("quota across restart = %v, want ErrLimit (60 of 100 already spent)", err)
	}
}
