package audit

// #237. When this file was written, a WHOLE-GUARD sweep measured 34 of 57 refusal guards leaving
// the suite green when replaced with a constant — the highest survival rate of any package swept
// at that point. Four targeted PRs (#223, #227, #234, #248) had each pinned the guard in front of
// them; the package around those guards was never examined.
//
// THAT NUMBER IS A DATED MEASUREMENT, NOT THE PACKAGE'S CURRENT STATE, and it is in a different
// unit from the one the sweep now uses. Re-derived on the commit that added chain_rewrite_test.go,
// per LEAF OPERAND rather than per guard: 107 sites / 155 operands, 84 detected and 71 survivors,
// of which 33 were closed there. Neither figure implies the other — a guard dies when any one of
// its operands is covered — so quote the unit with the count or the next reader inherits a number
// that was never about what they are measuring.
//
// This closes the integrity-path and reconciliation guards: the ones that decide whether a
// journal is trustworthy, and the ones that decide whether the collector's answer about it is.
//
// Every case asserts the specific message. On a path with this many sequential refusals `err !=
// nil` is satisfied by almost any bad input for almost any reason — that assertion is what let
// two guards in internal/certs rot earlier today.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validDraft is the draft the other suites use, factored out so a test that means to break ONE
// field is visibly breaking one field.
func validDraft(second int) Draft {
	return Draft{
		Timestamp: time.Date(2026, 9, 6, 12, 0, second, 0, time.UTC),
		RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
		Principal: "test-principal", Decision: "allow", ObjectID: "object-1",
		Purpose: "test-purpose", Operation: "release-secret", DeviceID: "device-1",
		Outcome:        "ok",
		RegistryDigest: "aa" + strings.Repeat("bb", 31),
		PolicyDigest:   "cc" + strings.Repeat("dd", 31),
		RBACDigest:     "ee" + strings.Repeat("ff", 31),
	}
}

// THE JOURNAL IS ONE EVENT PER LINE, AND NOTHING AFTER EACH ONE.
//
// Every line is decoded, and then decoded AGAIN to prove the line held exactly one document. That
// second Decode is the same guard #243 found missing in controlplane.Open and
// approval.KeySet.Verify — here it exists, and nothing detected it. Without it a line carrying an
// event plus anything appended verifies clean, so two byte-different journals produce the same
// verified history and a digest over the file names neither of them.
func TestVerifyIntegrityRefusesALineWithATrailingDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 2)

	// ANCHOR, first and unconditional: the untouched journal verifies, so a refusal below is
	// about the appended bytes and not about the fixture.
	clean, err := VerifyIntegrity(path)
	if err != nil || len(clean) != 2 {
		t.Fatalf("anchor: the untouched journal must verify with 2 events, got %d, %v", len(clean), err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("fixture: want 2 lines, got %d", len(lines))
	}
	// Append a second document to the FIRST line only. The chain, the hashes and the mark are all
	// untouched, so the trailing-data check is the only thing that can refuse this.
	lines[0] += ` {"attacker":"rider"}`
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := VerifyIntegrity(path)
	if err == nil {
		t.Fatalf("a journal line carrying a second document verified, returning %d events: two "+
			"byte-different journals now produce the same history", len(events))
	}
	if !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
}

// A JOURNAL THAT IS NOT A REGULAR FILE.
//
// os.DevNull is the isolating fixture, and a directory is not: opening a directory fails at the
// open, so a directory fixture is refused one guard earlier and proves nothing about this one.
// os.DevNull opens, Stat reports a character device, and the read succeeds returning nothing — so
// with this guard removed the journal verifies clean as an empty history, which is the wrong
// answer for a path that is not a journal at all.
func TestVerifyIntegrityRefusesAJournalThatIsNotARegularFile(t *testing.T) {
	events, err := VerifyIntegrity(os.DevNull)
	if err == nil {
		t.Fatalf("a character device was accepted as an audit journal, returning %d events: "+
			"a path that cannot hold a journal verified as an empty one", len(events))
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
}

// NOT PINNED, DELIBERATELY: the per-event decode at verifyEvents is redundant with the chain
// check that follows it. A line that fails to decode leaves a zero-valued event whose
// PreviousHash cannot match, so the chain refuses the same input with its own message and
// removing the decode guard changes no outcome. Measured: a journal with a non-JSON line appended
// still fails with the guard mutated away.
//
// Redundant-but-clearer, not load-bearing. A test here would pass for the chain check's reason
// while appearing to cover the decode.

// THE DRAFT IS THE LAST POINT AT WHICH A MALFORMED RECORD CAN BE REFUSED. After this it is in the
// chain, and the chain's whole value is that nothing in it can be changed afterwards — including
// a record that should never have been admitted.
func TestRecordRefusesADraftThatWouldPoisonTheChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	// ANCHOR, first: the unmodified draft records, so each refusal below is about the one field
	// that row changes.
	if err := recorder.Record(context.Background(), validDraft(0), false); err != nil {
		t.Fatalf("anchor: a valid draft was refused: %v", err)
	}

	for _, bad := range []struct {
		name   string
		break_ func(*Draft)
		wants  string
	}{
		{"no timestamp", func(d *Draft) { d.Timestamp = time.Time{} }, "invalid audit metadata"},
		{"a request id that is not a UUID", func(d *Draft) { d.RequestID = "not-a-uuid" }, "invalid audit metadata"},
		{"a negative latency", func(d *Draft) { d.LatencyMilliseconds = -1 }, "invalid audit metadata"},
		{"a decision that is neither allow nor deny", func(d *Draft) { d.Decision = "maybe" }, "invalid audit decision"},
		{"an empty decision", func(d *Draft) { d.Decision = "" }, "invalid audit decision"},
	} {
		t.Run(bad.name, func(t *testing.T) {
			draft := validDraft(1)
			bad.break_(&draft)
			err := recorder.Record(context.Background(), draft, false)
			if err == nil {
				t.Fatalf("Record accepted a draft with %s: it is now in the chain and cannot be removed", bad.name)
			}
			if !strings.Contains(err.Error(), bad.wants) {
				t.Fatalf("refused by the wrong rule: got %q, want %q", err, bad.wants)
			}
		})
	}
}

// failingCollector answers CommittedHead with an error, which is the state ReconcileContinuity
// exists to handle and which no test drove before this one.
type failingCollector struct{ err error }

func (failingCollector) Send(context.Context, Event) error { return nil }
func (failingCollector) Ready(context.Context) bool        { return true }
func (collector failingCollector) CommittedHead(context.Context, string) (uint64, string, error) {
	return 0, "", collector.err
}

// A COLLECTOR THAT CANNOT ANSWER IS NOT A COLLECTOR THAT HOLDS NOTHING.
//
// #234's whole argument is that the collector's committed head is the one value the host cannot
// author. If an error from CommittedHead were swallowed, head would be the zero value and the
// reconciliation would take the "collector holds nothing" branch — turning an unreachable
// collector into a positive assertion that this host has shipped nothing, which is the opposite
// of what happened. Nothing detected that.
func TestReconcileRefusesWhenTheCollectorCannotAnswer(t *testing.T) {
	path, _ := reconcileJournal(t, 3)
	err := ReconcileContinuity(context.Background(), path,
		failingCollector{err: errors.New("collector unreachable")}, "sitea")
	if err == nil {
		t.Fatal("reconciliation succeeded while the collector could not report its position: " +
			"an unreachable collector was read as a collector holding nothing")
	}
	if !strings.Contains(err.Error(), "collector position") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
}

// countingCollector records whether it was asked anything. Order is not observable from an error
// message, and this is the only thing that makes it observable.
type countingCollector struct{ asked int }

func (*countingCollector) Send(context.Context, Event) error { return nil }
func (*countingCollector) Ready(context.Context) bool        { return true }
func (collector *countingCollector) CommittedHead(context.Context, string) (uint64, string, error) {
	collector.asked++
	return 0, "", nil
}

// THE LOCAL JOURNAL IS VERIFIED BEFORE THE COLLECTOR IS ASKED ABOUT IT.
//
// The refusal alone does not prove the ORDER, which is what this test's name claims: a collector
// returning (0, "") makes the "collector holds nothing and neither do we" branch refuse too, so a
// reordering that asked the collector first would still produce an error and the test would pass
// having checked nothing about sequence. The observable that separates them is whether the
// collector was asked at all — the same kind of side-effect discriminator as whether an operation
// body ran.
//
// Order matters here for a reason beyond tidiness: asking a collector about a journal already
// known to be corrupt invites reporting the disagreement as a continuity failure rather than as
// the corruption it is, which is the wrong page of the runbook.
func TestReconcileRefusesBeforeAskingAboutAnUnverifiableJournal(t *testing.T) {
	path, _ := reconcileJournal(t, 2)
	if err := os.WriteFile(path, []byte("not a journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	collector := &countingCollector{}
	err := ReconcileContinuity(context.Background(), path, collector, "sitea")
	if err == nil {
		t.Fatal("a journal that does not verify reconciled clean")
	}
	if !strings.Contains(err.Error(), "local journal") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
	if collector.asked != 0 {
		t.Fatalf("the collector was asked %d times about a journal that does not verify: the "+
			"local check must come first, or a corrupt journal is reported as a continuity failure",
			collector.asked)
	}
}

// THE SHIPPED-MARK READ ERROR IN ReconcileContinuity IS UNREACHABLE (§17), and this is the
// evidence rather than the assertion.
//
// reconcile.go reads the collector-acknowledged mark after the collector answers, and refuses on
// a read error with "local shipped mark". No input reaches it: ReconcileContinuity calls
// VerifyIntegrity first, and VerifyIntegrity reads THE SAME FILE via readShippedMark. Any state
// that makes the reconcile read fail has already made the earlier one fail.
//
// Measured, not reasoned. A directory placed where audit.jsonl.shipped belongs:
//
//	ReconcileContinuity -> "local journal: read audit mark: ...: is a directory"
//
// — refused by VerifyIntegrity, one call earlier, with a different prefix. I wrote the test for
// this guard first and it failed exactly that way: red by the wrong detector, in a test written
// to pin a specific detector.
//
// Only a TOCTOU race makes it reachable — the mark becoming unreadable between the two reads —
// which is not constructible from the public path. If the two reads are ever collapsed into one,
// or VerifyIntegrity stops reading the shipped mark, this becomes testable and wants a row.
