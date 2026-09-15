package audit

// #237 operand sweep of internal/audit. The chain scan refuses on three operands and only one
// of them had a detector:
//
//	if event.Sequence != uint64(len(events)+1) || event.PreviousHash != previous || event.Hash != eventHash(event)
//	   (1) sequence contiguity                    (2) the back-link                 (3) the self-hash
//
// (3) is covered. (1) and (2) each survived being replaced with a constant.
//
// The existing fixtures cannot reach them. TestVerifyDetectsAlteredAndMissingEvents flips a byte
// WITHOUT recomputing, so (3) fires; and its "missing" row deletes a whole line, which trips (1)
// and (2) TOGETHER, so neither is ever the sole refuser. What is left unpinned is exactly what an
// attacker who knows the scheme does: recompute whatever you rewrite. Against that, (3) has
// nothing to say — the entry agrees with its own hash — and (1) and (2) are the whole defence.
//
// A FIXTURE PINNING A CONSTANT HASH WOULD BIND NOTHING. Every journal below is rebuilt with
// eventHash over the content it has just rewritten, so what Verify receives is internally
// consistent. That is the only version of this test that means anything: the question is not
// whether an inconsistent entry is caught, it is whether rewriting the record of what happened
// is caught once the rewriter has done its arithmetic.
//
// The same sweep found the periodic verifier's head comparison unpinned as a whole — both its
// operands survived separately AND composed — so the live-journal rows are here too. Between
// startup and shutdown that comparison is the only thing watching, and a valid prefix of a valid
// chain is itself a valid chain, so the chain scan it runs first cannot notice.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeJournal replaces the journal with exactly these events, one JSON object per line, in the
// order given. It does NOT recompute anything: each caller has already decided what its fixture
// claims, and a helper that silently re-chained would repair the very defect under test.
func writeJournal(t *testing.T, path string, events []Event) {
	t.Helper()
	var buffer bytes.Buffer
	for _, event := range events {
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		buffer.Write(line)
		buffer.WriteByte('\n')
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// THE SEQUENCE RULE IS WHAT REPORTS A GAP. Delete an event from the middle, relink the survivor
// over the hole, and the back-link and the self-hash are both satisfied — the chain reads as a
// clean two-event history whose sequence numbers are 1 and 3.
//
// Tolerating that is not only a lost record. verifyEvents' contiguity is a stated guarantee that
// callers INDEX on: reconcilePositions takes events[head-1] and VerifyIntegrity takes
// events[shipped.Sequence-1], both with a comment naming this rule as what makes the index safe.
// A journal with a gap makes those read the wrong event or run off the end of the slice.
func TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 3)

	events, err := Verify(path)
	if err != nil || len(events) != 3 {
		t.Fatalf("control: the untampered journal verified as %d events (%v), want 3 — the assertions below would be about a broken fixture rather than about the chain", len(events), err)
	}

	// Event 2 is removed and event 3 is relinked over the hole: its back-link now names event 1
	// and its hash is recomputed over that content. Its SEQUENCE is left at 3, which is what
	// removing a record from the middle leaves behind.
	relinked := events[2]
	relinked.PreviousHash = events[0].Hash
	relinked.Hash = eventHash(relinked)
	writeJournal(t, path, []Event{events[0], relinked})

	// PROVE THE FIXTURE REACHES THE SEQUENCE OPERAND AND NOTHING ELSE. If either of the other
	// two operands is also unsatisfied, this row is red by the wrong detector and says nothing
	// about the rule it is named for.
	if relinked.PreviousHash != events[0].Hash {
		t.Fatalf("fixture: the relinked event does not chain to its new predecessor, so the back-link operand would refuse it first")
	}
	if relinked.Hash != eventHash(relinked) {
		t.Fatalf("fixture: the relinked event's hash does not match its own content, so the self-hash operand would refuse it first")
	}

	if surviving, err := Verify(path); err == nil {
		t.Fatalf("a journal with its second event deleted and its third relinked over the hole verified clean as %d events: the sequences read 1 and 3 and nothing reported the gap, so a removed audit record leaves a trail that still looks whole — and every caller that indexes the result by sequence (reconcilePositions' events[head-1], VerifyIntegrity's events[shipped.Sequence-1]) now reads the wrong event or runs off the end",
			len(surviving))
	}
}

// THE BACK-LINK IS WHAT SURVIVES A REWRITE. Change what an entry says happened, recompute its
// hash, and the entry is internally consistent — the self-hash operand is satisfied by
// construction. Only its successor still remembers the original, and only because it committed
// the predecessor's hash into its own bytes.
func TestRewritingAnEntryAndRecomputingItsHashStillBreaksTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 3)

	events, err := Verify(path)
	if err != nil || len(events) != 3 {
		t.Fatalf("control: the untampered journal verified as %d events (%v), want 3", len(events), err)
	}

	// The rewrite an audit trail exists to make impossible: the first event is turned from an
	// allow into a deny after the fact, and its hash is recomputed so it agrees with itself.
	rewritten := events[0]
	if rewritten.Decision != "allow" || rewritten.Outcome != "ok" {
		t.Fatalf("fixture: the recorded event is %q/%q, not the allow this row means to rewrite", rewritten.Decision, rewritten.Outcome)
	}
	rewritten.Decision, rewritten.Outcome = "deny", "refused"
	rewritten.Hash = eventHash(rewritten)

	// PROVE THE FIXTURE. The rewrite must actually change the entry's hash, or the journal
	// written below is the original one and every assertion passes for no reason. And the
	// rewritten entry must agree with its own hash, or the self-hash operand refuses it and the
	// back-link stays unpinned.
	if rewritten.Hash == events[0].Hash {
		t.Fatal("fixture: rewriting the decision did not change the entry's hash, so this journal is the original and the row proves nothing")
	}
	if rewritten.Hash != eventHash(rewritten) {
		t.Fatal("fixture: the rewritten entry does not agree with its own hash, so the self-hash operand would refuse it first")
	}

	// Events 2 and 3 are left exactly as the recorder wrote them, so the ONLY thing wrong with
	// this journal is that event 2's back-link names the entry event 1 used to be.
	writeJournal(t, path, []Event{rewritten, events[1], events[2]})

	if surviving, err := Verify(path); err == nil {
		t.Fatalf("an audit entry was rewritten from allow to deny, its hash recomputed to match, and the journal verified clean as %d events — the record now says the opposite of what the KMS did and the chain agreed with it",
			len(surviving))
	}
}

// THE LIVE JOURNAL: TRUNCATED UNDER A RUNNING RECORDER.
//
// What survives a truncation is a valid chain, because a prefix of a valid chain always is. The
// verifier's chain scan therefore reads it without complaint, and the only thing that knows more
// events were written is the recorder's own in-memory head.
//
// Both operands of that comparison survived this sweep separately AND composed: the whole guard
// could be deleted and the suite stayed green, because the one test that reaches VerifyNow with a
// damaged journal alters a byte in place, which the chain scan catches on its own.
func TestATruncationUnderARunningRecorderIsReportedAsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	for _, id := range []string{
		"018f0000-0000-7000-8000-00000000000a",
		"018f0000-0000-7000-8000-00000000000b",
		"018f0000-0000-7000-8000-00000000000c",
	} {
		record(t, recorder, id)
	}

	// Control, so the refusal below is attributable to the truncation rather than to a verifier
	// that reports everything broken.
	if state := recorder.VerifyNow(context.Background()); state.Outcome != VerifyIntact || state.Events != 3 {
		t.Fatalf("control: the untouched live journal verified as %+v, want intact over 3 events", state)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(contents), "\n")
	if len(lines) < 3 {
		t.Fatalf("fixture: the journal holds %d lines, so there is nothing to truncate", len(lines))
	}
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}

	// PROVE THE FIXTURE. The truncated file must itself be a clean one-event chain, or this row
	// is red by the chain scan and says nothing about the head comparison that follows it.
	if prefix, err := Verify(path); err != nil || len(prefix) != 1 {
		t.Fatalf("fixture: the truncated journal is not a clean 1-event chain (%d events, %v), so the chain scan would refuse it before the head comparison ran", len(prefix), err)
	}

	if state := recorder.VerifyNow(context.Background()); state.Outcome != VerifyChainBroken {
		t.Fatalf("the journal was cut from 3 events to 1 under a running recorder and the periodic verifier reported %q: what is left verifies as a chain, so nothing but the comparison against the recorder's own head can notice, and the deletion an audit trail exists to record pages nobody",
			state.Outcome)
	}
}

// THE LIVE JOURNAL: REPLACED WITH A DIFFERENT CHAIN OF THE SAME LENGTH.
//
// This row is the one that makes the head-HASH operand the sole refuser. Truncation moves the
// head sequence and the head hash together, so the sequence operand can stand in for the hash
// one there; here the replacement holds the same number of events, so the sequences agree and
// only the hash disagrees. Distinct events have distinct hashes, which is why the reverse
// isolation does not exist: a differing head sequence always brings a differing head hash.
func TestAReplacementChainOfTheSameLengthIsReportedAsBroken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	for _, id := range []string{
		"018f0000-0000-7000-8000-00000000000a",
		"018f0000-0000-7000-8000-00000000000b",
		"018f0000-0000-7000-8000-00000000000c",
	} {
		record(t, recorder, id)
	}
	if state := recorder.VerifyNow(context.Background()); state.Outcome != VerifyIntact {
		t.Fatalf("control: the untouched live journal verified as %+v, want intact", state)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := Verify(path)
	if err != nil || len(events) != 3 {
		t.Fatalf("control: %d events, %v", len(events), err)
	}

	// Rewrite the first event's outcome to a value of the SAME WIDTH and re-chain the two after
	// it, recomputing every hash. The result is a genuine three-event chain occupying exactly as
	// many bytes as the one it replaced, so the verifier's durable-prefix bound reads all of it
	// and the chain scan finds nothing wrong.
	replacement := append([]Event(nil), events...)
	if replacement[0].Outcome != "allowed" {
		t.Fatalf("fixture: the recorded outcome is %q, and this row needs a value it can replace with one of equal width", replacement[0].Outcome)
	}
	replacement[0].Outcome = "blocked"
	replacement[0].Hash = eventHash(replacement[0])
	for index := 1; index < len(replacement); index++ {
		replacement[index].PreviousHash = replacement[index-1].Hash
		replacement[index].Hash = eventHash(replacement[index])
	}
	writeJournal(t, path, replacement)

	// PROVE THE FIXTURE, three ways, because each one is a different way this row could be red
	// for a reason that is not the head hash.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("fixture: the replacement is %d bytes against the original's %d — the verifier reads only the recorder's durable prefix, so a different length would either cut the last line or leave part of the old one, and the chain scan would refuse it before the head comparison",
			len(after), len(before))
	}
	replaced, err := Verify(path)
	if err != nil || len(replaced) != 3 {
		t.Fatalf("fixture: the replacement is not itself a clean 3-event chain (%d events, %v), so this row would be red by the chain scan", len(replaced), err)
	}
	if replaced[len(replaced)-1].Sequence != events[len(events)-1].Sequence {
		t.Fatalf("fixture: the replacement's head sequence is %d against the original's %d — this row exists because they AGREE, leaving the head hash as the only difference",
			replaced[len(replaced)-1].Sequence, events[len(events)-1].Sequence)
	}
	if replaced[len(replaced)-1].Hash == events[len(events)-1].Hash {
		t.Fatal("fixture: the replacement's head hash equals the original's, so there is nothing for the comparison to notice")
	}

	if state := recorder.VerifyNow(context.Background()); state.Outcome != VerifyChainBroken {
		t.Fatalf("the journal was replaced under a running recorder with a different history of the same length and the periodic verifier reported %q: the substitute is a valid chain of the same depth, so the chain scan passes it, and only its disagreement with the head this process actually wrote gives it away",
			state.Outcome)
	}
}
