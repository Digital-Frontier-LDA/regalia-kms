package audit

// #237 tail: the last uncovered guard in that issue's enumerable findings.
//
//	if reached == mark.Sequence && mark.Hash != genesisHash && reachedHash != mark.Hash
//
// It catches the one substitution the other two checks cannot see. The chain walk cannot,
// because — as the comment above VerifyIntegrity says — any valid PREFIX of a valid chain is
// itself a valid chain. The sequence comparison cannot, because the sequence is UNCHANGED: the
// journal still ends where the mark says it does. What differs is the CONTENT at that
// sequence, and only the recorded hash notices.
//
// THE FIXTURE MUST NOT USE AN ALL-ZERO HASH, which is the obvious thing to reach for and would
// have made this row pass for the wrong reason: genesisHash is
// "sha256:" + 64 zeros, so a zero-filled mark makes `mark.Hash != genesisHash` FALSE and the
// guard never evaluates its third operand. Same shape as an odd-length signature built from
// zero bytes tripping a zero-check before the length check.

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAJournalThatDisagreesWithItsMarkAtTheSameSequenceIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")
	record(t, recorder, "018f0000-0000-7000-8000-00000000000b")
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	// The journal is intact and ends at sequence 2. Rewrite only the MARK, keeping the sequence
	// it already records and changing the hash — the state an attacker leaves behind after
	// re-chaining the tail: the count still matches, the content does not.
	//
	// Non-zero hex, deliberately: a zero-filled hash equals genesisHash and would be excluded by
	// the guard's second operand before the third one is reached.
	substituted := "sha256:" + strings.Repeat("ab", 32)
	if substituted == genesisHash {
		t.Fatal("the fixture hash equals genesisHash, so the guard's second operand would exclude it and this row would prove nothing")
	}
	if err := writeAuditHighWater(path, highWaterMark{Sequence: 2, Hash: substituted}); err != nil {
		t.Fatal(err)
	}

	_, err = VerifyIntegrity(path)
	if err == nil {
		t.Fatal("a journal whose recorded history names a different hash at the same sequence verified clean — the tail can be rewritten in place and the mark still agrees on how far it reached")
	}
	if !strings.Contains(err.Error(), "does not match its recorded history") {
		t.Fatalf("refused, but by a different guard: %v — this row exists to prove the hash comparison fires, and any other refusal means the sequence or shipped-mark checks caught it first", err)
	}

	// KNOWN-GOOD (§18): the same journal with a mark that agrees verifies clean, so the row is
	// not passing against a check that refuses every mark.
	events, readErr := Verify(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	last := events[len(events)-1]
	if err := writeAuditHighWater(path, highWaterMark{Sequence: last.Sequence, Hash: last.Hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrity(path); err != nil {
		t.Fatalf("the journal was refused with a mark that matches it (%v) — the refusal above would prove nothing", err)
	}
}
