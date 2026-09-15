package fencing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheEpochChainBindsTheRecordContent pins the epoch journal's hash chain to the record
// CONTENT — and exists because nothing else did. Found on 2026-09-06 while mutating the
// authority journal in #29's AC2 work: replacing epochHash with a constant (computed then
// ignored, so it compiles) passed the fencing suite and the ENTIRE kms tree. A constant hash
// yields a chain that is perfectly self-consistent and secures nothing; every existing tamper
// test wrote structural garbage ("tampered\n"), which the JSON parser refuses long before any
// hash comparison runs. The parser was the detector; the hash was never the sole detector for
// anything.
//
// This test is the one tamper shape whose sole detector is the hash: a meaningful field is
// rewritten in place with every recorded hash left byte-identical.
func TestTheEpochChainBindsTheRecordContent(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "epochs.jsonl")

	// A valid two-record chain, built exactly as the gate appends it. previous starts at
	// genesisHash itself: if the constant ever changes, this chain is built from the old
	// value and the precondition check below fails LOUDLY — self-reporting duplication,
	// not silent drift (a re-encoded literal here would be DRY-er but no safer).
	previous := genesisHash
	var journal strings.Builder
	for epoch := uint64(1); epoch <= 2; epoch++ {
		record := epochRecord{Epoch: epoch, PreviousHash: previous}
		record.Hash = epochHash(record)
		// The marshal error is ignored because epochRecord cannot fail to marshal: every
		// field is a uint64 or a string, and no field carries a channel, func or cycle.
		encoded, _ := json.Marshal(record)
		journal.Write(encoded)
		journal.WriteByte('\n')
		previous = record.Hash
	}
	if err := os.WriteFile(statePath, []byte(journal.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEpochJournal(statePath); err != nil {
		t.Fatalf("the fixture chain does not verify: %v", err)
	}

	// The surgical rewrite: epoch 2 becomes epoch 9 — a forged history that inflates the
	// high-water mark — with both hash fields exactly as recorded. The parser is happy; only
	// the hash can refuse it.
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(data), `"epoch":2`, `"epoch":9`, 1)
	if rewritten == string(data) {
		t.Fatal("fixture failed to rewrite the epoch — the test asserts nothing")
	}
	if err := os.WriteFile(statePath, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEpochJournal(statePath); err == nil {
		t.Fatal("a forged epoch verified — the chain binds no content, and the high-water mark that stops an old active resuming is rewritable by anyone who can re-serialize JSON")
	}
}
