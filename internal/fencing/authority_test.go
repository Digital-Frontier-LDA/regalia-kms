package fencing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTheAuthorityJournalRecordsGrantsAndRefusals(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	base := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	if err := journal.Append(GrantRecord{
		Kind: RecordGranted, Site: "sitea", Epoch: 1, Operator: "on-call",
		NotBefore: base, ExpiresAt: base.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("append grant: %v", err)
	}
	// THE REFUSAL IS A DECISION WORTH RECORDING: this is the split-brain attempt, the record
	// an auditor holding every lease ever issued still cannot otherwise see.
	if err := journal.Append(GrantRecord{
		Kind: RecordRefused, Site: "siteb", Epoch: 2, Operator: "on-call",
		NotBefore: base, ExpiresAt: base.Add(10 * time.Minute),
		Reason: "fencing: siteb would be active while sitea holds the lease, so both sites would sign",
	}); err != nil {
		t.Fatalf("append refusal: %v", err)
	}
	if journal.Head() != 2 {
		t.Fatalf("head after two decisions is %d, want 2", journal.Head())
	}
	summary, err := VerifyAuthorityJournal(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary.Records != 2 || summary.Grants != 1 || summary.Refusals != 1 || summary.HeadSequence != 2 {
		t.Fatalf("summary disagrees with what was appended: %+v", summary)
	}
	// A second handle picks up the head where the first left it.
	reopened, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := reopened.Append(GrantRecord{
		Kind: RecordGranted, Site: "siteb", Epoch: 3, Operator: "on-call",
		NotBefore: base.Add(10 * time.Minute), ExpiresAt: base.Add(20 * time.Minute),
	}); err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	summary, err = VerifyAuthorityJournal(path)
	if err != nil || summary.HeadSequence != 3 {
		t.Fatalf("chain did not continue across handles: %+v err=%v", summary, err)
	}
}

func TestTheAuthorityJournalRefusesTamperingAndBadModes(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(GrantRecord{Kind: RecordGranted, Site: "sitea", Epoch: 1, Operator: "on-call"}); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(GrantRecord{Kind: RecordGranted, Site: "sitea", Epoch: 2, Operator: "on-call"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if len(data) < 10 {
		t.Fatalf("read %d bytes from %s, too few to truncate — the fixture did not write a journal", len(data), path)
	}
	if err := os.WriteFile(path, append(data[:len(data)-10], []byte("tampered\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAuthorityJournal(path); err == nil {
		t.Fatal("a tampered journal reopened cleanly — the authority's decisions are rewriteable")
	}
	if _, err := VerifyAuthorityJournal(path); err == nil {
		t.Fatal("a tampered journal verified cleanly")
	}

	// The mode discipline: a group-writable journal (or one in a writable directory) is a
	// journal anyone with local access can rewrite and re-sign.
	lax := filepath.Join(dir, "lax.jsonl")
	if err := os.WriteFile(lax, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	// CHMOD, BECAUSE os.WriteFile's MODE IS MASKED BY THE UMASK. Requesting 0660 under a umask of
	// 0077 produces 0600, the mode guard never fires, and this test failed with "a group-writable
	// journal was accepted" — the fixture, not the guard. Measured on a pristine tree: green under
	// umask 0022, red under 0077. Chmod is not masked. Found sweeping the class after review on
	// #321 flagged the same omission in a fixture of mine.
	if err := os.Chmod(lax, 0o660); err != nil {
		t.Fatal(err)
	}
	// And assert the fixture built the state it claims, so a future masking change fails HERE
	// rather than as an accusation against the guard.
	if info, err := os.Stat(lax); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm()&0o077 == 0 {
		t.Fatalf("fixture did not produce a group-writable journal: mode is %04o", info.Mode().Perm())
	}
	if _, err := OpenAuthorityJournal(lax); err == nil {
		t.Fatal("a group-writable journal was accepted")
	}
	// Unattributed decisions do not append.
	journal2, err := OpenAuthorityJournal(filepath.Join(dir, "second.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal2.Append(GrantRecord{Kind: RecordGranted, Site: "sitea", Epoch: 1, Operator: ""}); err == nil {
		t.Fatal("an unattributed decision was recorded — who decided is the point of the journal")
	}
	if err := journal2.Append(GrantRecord{Kind: "mystery", Site: "sitea", Epoch: 1, Operator: "on-call"}); err == nil {
		t.Fatal("an unknown kind was recorded")
	}
}

func TestTheChainBindsTheRecordContent(t *testing.T) {
	// The chain's hash must bind the record's CONTENT, not merely be self-consistent. A
	// neutered hash function (constant output) yields a chain that verifies perfectly while
	// binding nothing — found by mutation: hash-computed-but-ignored survived every existing
	// test, because the byte-mangling tamper above is caught by structure, not cryptography.
	// This test rewrites a decision's ATTRIBUTION in place, keeping every hash field exactly
	// as recorded: the real hash refuses it; a content-blind hash accepts it.
	dir := privateTempDir(t)
	path := filepath.Join(dir, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	if err := journal.Append(GrantRecord{
		Kind: RecordGranted, Site: "sitea", Epoch: 1, Operator: "on-call",
		NotBefore: base, ExpiresAt: base.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(data), "on-call", "someone-else", 1)
	if rewritten == string(data) {
		t.Fatal("fixture failed to rewrite the attribution — the test asserts nothing")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAuthorityJournal(path); err == nil {
		t.Fatal("a rewritten attribution verified — the chain hashes do not bind the record content, so the journal's decisions are rewriteable by anyone who can re-serialize JSON")
	}
}

// TestAJournalRecordCarryingAnUnknownFieldIsRefused closes the gap the chain cannot see.
// grantRecordHash marshals the PARSED record, so a field present in the file but absent from
// GrantRecord is dropped at Decode and never contributes to the hash: the chain still verifies
// and the injected content rides along in the one artifact that exists to make a decision
// auditable. gate.go's lease verifier has refused unknown fields since it was written.
func TestAJournalRecordCarryingAnUnknownFieldIsRefused(t *testing.T) {
	dir := privateTempDir(t)
	path := filepath.Join(dir, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := journal.Append(GrantRecord{
		Kind: RecordGranted, Site: "sitea", Epoch: 1, Operator: "jbo",
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil || len(data) < 2 {
		t.Fatalf("read %d bytes (err=%v) — the fixture did not write a journal", len(data), err)
	}
	// ANCHOR FIRST: the untouched journal must verify, or the refusal below proves only that
	// this test can write a file the verifier dislikes for some other reason.
	if _, err := VerifyAuthorityJournal(path); err != nil {
		t.Fatalf("the unmodified journal did not verify (%v) — the refusal below would prove nothing", err)
	}

	// A field the struct does not have, spliced into the record without touching any hashed
	// field. This is what an attacker who can edit the file gets for free when the decoder is
	// permissive: the chain is intact and the content is invisible.
	injected := strings.Replace(string(data), `{"`, `{"attacker":"rider","`, 1)
	if injected == string(data) {
		t.Fatal("the injection did not change the record — the fixture's shape changed and this test rewrites nothing")
	}
	if err := os.WriteFile(path, []byte(injected), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyAuthorityJournal(path); err == nil {
		t.Fatal("a journal record carrying an unknown field verified cleanly — grantRecordHash " +
			"hashes the parsed struct, so the field never reached the chain and the decision " +
			"record can be extended by anyone who can write the file")
	}
	if _, err := OpenAuthorityJournal(path); err == nil {
		t.Fatal("the tampered journal reopened cleanly, so the appending path accepts it too")
	}
}
