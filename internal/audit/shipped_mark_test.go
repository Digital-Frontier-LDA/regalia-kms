package audit

// A corrupt .shipped mark is a crash artifact — tmp-and-rename makes a half-written mark
// unlikely, but a truncated file is exactly what an interrupted filesystem leaves, and it is
// also what tampering looks like. The .shipped mark is the SECOND, independent record of how
// far the trail reached (its own comment: an attacker who knows the scheme deletes the
// sidecar along with the events); a corrupt one that silently reads as "nothing shipped"
// empties that memory, and the guards that refuse it — readMark's unmarshal, and the
// readShippedMark propagation in VerifyIntegrity and Open — had no detector anywhere in the
// module (#237 verification, measured: guards defeated, a 3-event journal with a truncated
// .shipped verified clean).
//
// CLASSIFIED RATHER THAN TESTED, two shapes (recorded so the next sweep does not re-derive):
//   .high-water corruption — with the unmarshal guard defeated it is caught downstream by the
//     genesis-downgrade rule, so a row there is red by the wrong detector.
//   Open's OWN readShippedMark error check (the third survivor of the #237 claim) — Open runs
//     VerifyIntegrity first, and A1+B refuse the same file before Open's re-read executes, so
//     that instance is unreachable as a sole detector through the public path (measured: its
//     single defeat leaves this row green). Defense-in-depth re-read, not an independent gate.
// This row tests the shape where nothing else stands behind the guard. The assertion
// matches readMark's FULL phrase, not the word "malformed": the word appears in exactly
// one message in this package today, which makes a word-match safe by accident — a second
// malformed-bearing message added anywhere on these paths would silently satisfy it. The
// phrase-match is measured to distinguish (see the PR thread measurement).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// journalWithSink writes real events through a real sink, so both sidecars exist and the
// collector has genuinely acknowledged the shipped position.
func journalWithSink(t *testing.T, events int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < events; i++ {
		if err := recorder.Record(context.Background(), draft(uniqueRequestID(i), "allow"), true); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func uniqueRequestID(i int) string {
	return fmt.Sprintf("018f0000-0000-7000-8000-%012d", i+1)
}

func TestACorruptShippedMarkIsRefusedNotIgnored(t *testing.T) {
	path := journalWithSink(t, 3)
	// Half-written JSON: the shape an interrupted rename leaves behind.
	if err := os.WriteFile(path+shippedSuffix, []byte(`{"sequence":2,"hash":"sha256:`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrity(path); err == nil || !strings.Contains(err.Error(), "audit mark is malformed") {
		t.Fatalf("a corrupt .shipped mark verified clean (err=%v) — the collector's acknowledged position is the journal's second truncation memory, and a corrupt one must not read as nothing shipped", err)
	}
	if recorder, err := Open(path, &memorySink{ready: true}); err == nil || !strings.Contains(err.Error(), "audit mark is malformed") {
		if recorder != nil {
			recorder.Close()
		}
		t.Fatalf("Open accepted a journal with a corrupt .shipped mark (err=%v) — the daemon would start and serve with its shipped-memory silently empty", err)
	} else if recorder != nil {
		recorder.Close()
	}
}
