package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func record(t *testing.T, recorder *Recorder, requestID string) {
	t.Helper()
	if err := recorder.Record(context.Background(), draft(requestID, "allow"), false); err != nil {
		t.Fatalf("record %s: %v", requestID, err)
	}
}

// DROPPING THE MOST RECENT AUDIT EVENTS MUST NOT VERIFY CLEAN.
//
// The chain proves nobody edited the journal and says nothing about truncation: any valid prefix is
// itself a valid chain. For an audit trail that is precisely the interesting attack — the events
// worth removing are always the most recent ones — and it previously left no trace, with Verify
// returning no error and Open resuming from the shortened history.
func TestTruncatedAuditJournalIsDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"018f0000-0000-7000-8000-00000000000a", "018f0000-0000-7000-8000-00000000000b", "018f0000-0000-7000-8000-00000000000c"} {
		record(t, recorder, id)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(contents), "\n")
	// Keep only the first event: a shorter, internally valid chain.
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, nil)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("a truncated audit journal reopened; the removed events left no trace")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

// An intact journal must still reopen and continue its chain, or the guard would cost more than the
// attack it prevents.
func TestIntactAuditJournalReopensAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, nil)
	if err != nil {
		t.Fatalf("an intact audit journal was refused: %v", err)
	}
	record(t, reopened, "018f0000-0000-7000-8000-00000000000b")
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := Verify(path)
	if err != nil {
		t.Fatalf("verify after restart: %v", err)
	}
	if len(events) != 2 || events[1].Sequence != 2 {
		t.Fatalf("chain did not continue across restart: %d events", len(events))
	}
}
