package audit

// #237 operand sweep, two survivors on the high-water mark path. They fail in opposite
// directions, which is why they sit together: one lets a failure be misreported, the other
// refuses a journal that is fine.
//
// AN UNREADABLE MARK IS NOT AN ABSENT ONE, AND NOT A MALFORMED ONE EITHER. readMark classifies
// three states off a single read — absent (genesis, the fresh-site case), unreadable (permission
// or I/O), malformed (the bytes are not a mark). Only the first and third had a detector. With
// the middle operand replaced by a constant the read error is discarded and the nil contents fall
// through into json.Unmarshal, which fails: the journal is still refused, so every `err != nil`
// assertion in the package stays green, and the operator is told the mark is MALFORMED and sent
// to inspect bytes that were never read. Distinguishing those is the entire purpose of that
// operand, so this asserts the sentinel rather than the presence of an error.
//
// AND A MARK THAT LAGS IS NOT A MARK THAT DISAGREES. The other survivor is a refusal-direction
// defect, the kind a suite of negative tests is structurally worst at: every test on this path
// asks whether a tampered journal is refused, and none asks whether an untampered one is
// accepted.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnUnreadableHighWaterMarkIsNotReportedAsMalformed(t *testing.T) {
	// Root ignores mode bits, so this row can only be built as an ordinary user; CI's test step
	// runs unprivileged and the one root step runs a single named test in another package.
	if os.Geteuid() == 0 {
		t.Log("running as root: skipping, since root reads a 0000 file and the fixture cannot build the state it needs")
		return
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 2)
	mark := path + highWaterSuffix

	if err := os.Chmod(mark, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mark, 0o600) })

	// PROVE THE FIXTURE. If the mark is still readable, the row below exercises the ordinary
	// success path and would fail blaming the guard rather than the fixture.
	if _, err := os.ReadFile(mark); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the 0000 high-water mark is still readable (%v), so this row asserts nothing about an unreadable one", err)
	}

	_, err := VerifyIntegrity(path)
	if err == nil {
		t.Fatal("a journal whose high-water mark could not be read verified clean: the mark is the record of how far the trail reached, and 'I could not read it' was answered as 'nothing is wrong'")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("an unreadable high-water mark was refused as %q, which does not carry os.ErrPermission — the mark's bytes were never read, yet the operator is told they are malformed and sent to inspect a file whose content is not the problem; the two failures are fixed by different people",
			err)
	}
}

// A JOURNAL WHOSE MARK LAGS IS THE CRASH WINDOW, NOT AN ATTACK.
//
// Record advances only after Write and Sync both succeed, and writes the sidecar AFTER that — so
// a crash between the two leaves a durable event the mark does not name. That is a documented,
// reachable state: TestDurableIsTrueWhenOnlyTheHighWaterMarkFailed pins it from the writing side,
// and ErrDurable exists precisely because the event survives it.
//
// The operand that keeps VerifyIntegrity from refusing that state is the sequence comparison in
// front of the hash comparison. Replace it with a constant and the hash check applies to a
// journal whose head is simply AHEAD of its mark: the hashes differ because they are different
// events, and the daemon refuses to start after an ordinary crash, telling the operator its
// journal disagrees with its history when nothing has touched it.
func TestAJournalWhoseMarkLagsTheCrashWindowStillVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")

	// The mark as it stands after the first event: the value a crash during the SECOND event's
	// sidecar write leaves behind.
	markAfterFirst, err := os.ReadFile(path + highWaterSuffix)
	if err != nil {
		t.Fatal(err)
	}

	// Block the sidecar write with a directory, which fails for any uid — chmod would not,
	// because root ignores mode bits and CI containers run as root.
	if err := os.RemoveAll(path + highWaterSuffix); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+highWaterSuffix, 0o755); err != nil {
		t.Fatal(err)
	}

	secondErr := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-00000000000b", "allow"), false)
	if secondErr == nil || !Durable(secondErr) {
		t.Fatalf("fixture: the second Record returned %v, and this row needs the state where the event IS durable and only the sidecar write failed", secondErr)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}

	// The directory is this test's obstruction, not part of the state under test. What the crash
	// leaves on disk is the OLD mark beside the NEW journal, so restore exactly that.
	if err := os.RemoveAll(path + highWaterSuffix); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+highWaterSuffix, markAfterFirst, 0o600); err != nil {
		t.Fatal(err)
	}

	// PROVE THE FIXTURE: two durable events, and a mark naming only the first.
	mark, err := readAuditHighWater(path)
	if err != nil {
		t.Fatal(err)
	}
	if mark.Sequence != 1 {
		t.Fatalf("fixture: the restored mark names sequence %d, and this row needs it one behind the journal", mark.Sequence)
	}

	events, err := VerifyIntegrity(path)
	if err != nil {
		t.Fatalf("a journal holding 2 durable events beside a mark naming only the first was refused (%v): that is what a crash between the append and the sidecar write leaves, so this refusal takes the daemon down at the next start over a journal nothing has tampered with",
			err)
	}
	if len(events) != 2 {
		t.Fatalf("VerifyIntegrity returned %d events, want the 2 that were durably appended", len(events))
	}
}
