package fencing

// Falsification test for the #261 fix: verifyEpochJournal at gate.go:222 must
// refuse a record carrying a field the hash cannot see, since epochHash at
// gate.go:253 marshals the PARSED struct.
//
// The chain's integrity check (record.Hash == epochHash(record)) operates on
// the struct the decoder returned, so a field present in the file but absent
// from epochRecord is dropped at Decode and never contributes to the hash.
// Without DisallowUnknownFields() on gate.go:222's decoder, the journal still
// verifies and the injected content rides along invisibly in the artifact
// that decides which site may sign — the same shape authority.go:217 carries,
// and one the readLease verifier at gate.go:153 already refuses.
//
// Falsifier (verified RED 2026-09-06): replace the `decoder.DisallowUnknown
// Fields()` call with `if false { decoder.DisallowUnknownFields() }`. With
// the guard removed, the decoder silently drops the injected field, the chain
// hash still matches the parsed struct, and VerifyEpochs returns
// (maxEpoch, headHash, nil) instead of an integrity-failure error.
//
// Gate.go has TWO decoders — readLease at L152 (already protected) and
// verifyEpochJournal at L222 (the fix). Unlike authority.go's pair, neither
// is §17: gate.go has only ONE reader of the epoch journal (VerifyEpochs at
// L243 is a thin wrapper around verifyEpochJournal), so there is no summary
// loop whose guard is masked by ordering. The fix is load-bearing from day
// one.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifyEpochJournalRefusesAFieldItsHashCannotSee(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "epochs.jsonl")
	leasePath := filepath.Join(directory, "lease.json")

	public, private, _ := ed25519.GenerateKey(rand.Reader)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	now := time.Now().UTC()

	// Use Open + Ready so the journal is created by the gate's own appendEpoch
	// path (gate.go:189) — the test then exercises the exact writer the
	// production code uses, and the injected file mirrors what an attacker
	// with file access would actually see on disk.
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !gate.Ready(context.Background()) {
		t.Fatalf("first-ever lease was not accepted; the gate's own writer left a journal it cannot verify, so the injection below would be testing the wrong thing")
	}

	// ANCHOR FIRST: the untouched journal must verify. Without this control,
	// the refusal below would prove only that this test wrote a file the
	// verifier dislikes for some other reason — a control case that catches
	// fixture drift rather than the named defect.
	if maxEpoch, head, err := VerifyEpochs(statePath); err != nil {
		t.Fatalf("the unmodified journal did not verify (maxEpoch=%d head=%q err=%v); the refusal below would prove nothing", maxEpoch, head, err)
	}

	raw, err := os.ReadFile(statePath)
	if err != nil || len(raw) < 2 {
		t.Fatalf("read %d bytes (err=%v) — the fixture did not write a journal; the injection below has nothing to mutate", len(raw), err)
	}
	// Inject a field the struct does not have, spliced into the recorded JSON
	// without touching any hashed field. The Hash of the record was computed
	// BEFORE the injection by the gate's appendEpoch path, so it still
	// matches epochHash(parsedStruct) — the chain is intact, the content
	// rides invisibly: exactly what the fix refuses.
	injected := bytes.Replace(raw, []byte(`{"`), []byte(`{"injected":"rider","`), 1)
	if bytes.Equal(injected, raw) {
		t.Fatalf("the injection did not change the record — the fixture's shape changed and this test rewrites nothing. raw = %q", raw)
	}
	if err := os.WriteFile(statePath, injected, 0o600); err != nil {
		t.Fatal(err)
	}

	maxEpoch, head, err := VerifyEpochs(statePath)
	if err == nil {
		t.Fatalf("a journal record carrying an unknown field verified cleanly (maxEpoch=%d, head=%q); "+
			"epochHash hashes the parsed struct, so the field never reached the chain and the gate's "+
			"high-water mark is extendable by anyone who can write the file. verifyEpochJournal "+
			"DisallowUnknownFields at gate.go:222 is the only refusal that sees it", maxEpoch, head)
	}
}
