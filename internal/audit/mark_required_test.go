package audit

// #223: a journal with history cannot have no prior position. The matrix is the test because
// each row alone passes against the wrong rule — refusing every markless journal would pass
// the truncation row and brick the first-write crash window; tolerating absence passes the
// crash-window row and hides the deletion. The rows are built with the real Recorder so the
// fixtures are legitimate histories, not hand-chains that agree with the hand that wrote them.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nullSink struct{}

func (nullSink) Send(context.Context, Event) error { return nil }
func (nullSink) Ready(context.Context) bool        { return true }

// recordOnly writes events with NO sink: the journal-only host, defined by the ABSENT
// .shipped — the collector's acknowledged position does not exist. Note what it does NOT
// mean: .high-water is still written (it is on the synchronous append path, sink or no
// sink), so "journal-only" is not "markless". A fixture that assumes recordOnly leaves no
// mark file fails on its own assumption, not on the code — measured on #227 review.
func recordOnly(t *testing.T, path string, count int) {
	t.Helper()
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatalf("open journal-only: %v", err)
	}
	for i := 0; i < count; i++ {
		draft := Draft{
			Timestamp: time.Date(2026, 9, 6, 12, 0, i, 0, time.UTC),
			RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			Principal: "test-principal", Decision: "allow", ObjectID: "object-1",
			Purpose: "test-purpose", Operation: "release-secret", DeviceID: "device-1",
			Outcome:        "ok",
			RegistryDigest: "aa" + strings.Repeat("bb", 31),
			PolicyDigest:   "cc" + strings.Repeat("dd", 31),
			RBACDigest:     "ee" + strings.Repeat("ff", 31),
		}
		if err := recorder.Record(context.Background(), draft, false); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
}

func recordEvents(t *testing.T, path string, count int) {
	t.Helper()
	recorder, err := Open(path, nullSink{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < count; i++ {
		draft := Draft{
			Timestamp: time.Date(2026, 9, 6, 12, 0, i, 0, time.UTC),
			RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			Principal: "test-principal", Decision: "allow", ObjectID: "object-1",
			Purpose: "test-purpose", Operation: "release-secret", DeviceID: "device-1",
			Outcome:        "ok",
			RegistryDigest: "aa" + strings.Repeat("bb", 31),
			PolicyDigest:   "cc" + strings.Repeat("dd", 31),
			RBACDigest:     "ee" + strings.Repeat("ff", 31),
		}
		if err := recorder.Record(context.Background(), draft, false); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAJournalWithHistoryCannotHaveNoPriorPosition(t *testing.T) {
	truncateTo := func(t *testing.T, path string, keepLines int) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(data), "\n")
		if err := os.WriteFile(path, []byte(strings.Join(lines[:keepLines], "")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("tail and mark deleted together is refused on a journal-only host", func(t *testing.T) {
		// JOURNAL-ONLY on purpose: with a collector, .shipped refuses the same journal
		// and this row would pass under a removed mark rule — red by the wrong detector,
		// the §19 shape. Without a sink the mark rule is the sole detector.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordOnly(t, path, 5)
		truncateTo(t, path, 2)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err == nil {
			t.Fatal("a truncated journal-only host's journal with its mark deleted verified clean — the deletion the mark exists to detect")
		}
	})
	t.Run("the same deletion on a shipping host is caught twice over — AGAINST A CRASH, NOT AN ATTACKER", func(t *testing.T) {
		// Documentation row, with its threat model stated: with a collector, BOTH nets
		// refuse this deletion — the mark rule and the collector-acknowledged position.
		// The layering is real for a CRASH and NOT real for an attacker with write
		// access to the directory: .high-water and .shipped are both plain 0600 JSON
		// beside the journal, so whoever can truncate can also rewrite both, and
		// measured rows 2 and 4 of the #220 table do exactly that and verify clean.
		// Each net here covers the other's CRASH window (a markless-but-shipped state is
		// caught by .shipped; a shipped-mark-lost state is caught by the mark rule); the
		// attacker case needs memory the host cannot write and is #220's boundary, not
		// this rule's claim.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(t, path, 5)
		truncateTo(t, path, 2)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err == nil {
			t.Fatal("a shipping host's truncated, markless journal verified clean")
		}
	})
	t.Run("the same journal with its mark intact still verifies", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(t, path, 5)
		if _, err := VerifyIntegrity(path); err != nil {
			t.Fatalf("an intact journal with its mark refused: %v", err)
		}
	})
	t.Run("one event without a mark on a JOURNAL-ONLY host is the first-write crash window and stays open", func(t *testing.T) {
		// recordOnly, deterministically: the first version used the nullSink fixture, whose
		// async shipper writes .shipped for the event — so the row intermittently tested
		// the COMPOSED state (shipped=1, mark absent) and failed ~4% of runs under -race
		// (#246). The crash window this row means has nothing shipped; the sink row now
		// exists below as its own assertion with its own verdict.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordOnly(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err != nil {
			t.Fatalf("the first event's crash window is a legitimate state and was refused: %v", err)
		}
	})
	t.Run("one event, mark absent, but the collector acknowledged it — durability loss, refused honestly", func(t *testing.T) {
		// The composed state #246 found: the nullSink shipper acknowledged the event, the
		// mark is gone. The write order (mark before ship) makes this durability loss or
		// deletion — NOT the innocent crash window, whose shipper never ran — so the
		// refusal is correct and the MESSAGE must say which of the two states it is. The
		// old message called it a forged sidecar, sending an operator to hunt an attacker
		// for what their filesystem did.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		// The shipped mark is written EXPLICITLY rather than left to the nullSink's async
		// shipper: whether the goroutine acked before Verify runs is the same 4% race the
		// row exists to retire, and a row that intermittently tests its own fixture race
		// is the failure arriving twice. The real event hash is quoted — a competent
		// state, not a sloppy one.
		events, verifyErr := Verify(path)
		if verifyErr != nil || len(events) != 1 {
			t.Fatalf("fixture: %v (%d events)", verifyErr, len(events))
		}
		if err := writeShippedMark(path, highWaterMark{Sequence: 1, Hash: events[0].Hash}); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyIntegrity(path)
		if err == nil || !strings.Contains(err.Error(), "durability loss or deletion") {
			t.Fatalf("the composed crash state was refused with the wrong diagnosis (err=%v)", err)
		}
	})
	t.Run("truncated to one on a SHIPPING host is caught by the collector's memory", func(t *testing.T) {
		// The first version of this row asserted the residual and FAILED — because the
		// nullSink had acknowledged events the truncation dropped, and .shipped (the
		// collector's position, written only after acknowledgement) refused the journal.
		// That is the outer net working: on a shipping host, truncation-to-one is caught
		// by memory the journal does not hold. Kept as a row so it stays true.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(t, path, 5)
		truncateTo(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err == nil {
			t.Fatal("a shipping host's truncated journal verified clean — the collector-acknowledged mark should have refused it")
		}
	})
	t.Run("truncated to one on a JOURNAL-ONLY host is the stated residual", func(t *testing.T) {
		// Without a collector there is no .shipped and no off-host memory, so one event
		// with no mark is byte-for-byte the first write's crash window and this rule
		// cannot see the difference — by construction, not oversight. The net that
		// closes it is site-level provenance (#220). If this row ever FAILS, that
		// layering moved and this comment must move with it.
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordOnly(t, path, 5)
		truncateTo(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err != nil {
			t.Fatalf("the boundary moved: %v", err)
		}
	})
	t.Run("a genesis-valued mark beside history is a downgrade and is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(t, path, 5)
		if err := os.WriteFile(path+highWaterSuffix, []byte(`{"sequence":0,"hash":"`+strings.TrimPrefix(genesisHash, "sha256:")+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIntegrity(path); err == nil {
			t.Fatal("a mark reset to genesis beside five events verified — the mark was forged down")
		}
	})
}

func TestOneEventWithAGenesisValuedPresentMarkIsADowngrade(t *testing.T) {
	// The gap #227 review found: the original rule keyed on "mark records progress" AND
	// len >= 2, so exactly one event beside a PRESENT genesis mark verified clean — outside
	// my own stated "genesis beside history is a downgrade" rule by one event. The writers
	// cannot produce that state (the single write site always records event.Sequence >= 1),
	// so refusing it costs no crash window: crashes leave the mark absent or behind, never
	// zero.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 1)
	if err := os.WriteFile(path+highWaterSuffix, []byte(`{"sequence":0,"hash":"`+strings.TrimPrefix(genesisHash, "sha256:")+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIntegrity(path); err == nil {
		t.Fatal("one event beside a mark reset to genesis verified — the downgrade hid the journal's whole reach")
	}
}

func TestAnUnknowableMarkIsNeitherAbsentNorPresent(t *testing.T) {
	// The third state: a stat error that is not ErrNotExist (permissions, I/O) must refuse
	// with its own message — the default-true it replaces read "cannot tell" as "exists" and
	// verified against whatever a failed read left behind. The parent directory is made
	// unreadable rather than the file, because chmod on the file alone does not stop Stat.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 3)
	if err := os.Chmod(filepath.Dir(path), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Dir(path), 0o755)
	_, err := VerifyIntegrity(path)
	if err == nil {
		t.Fatal("an unreadable state directory verified clean — 'cannot tell' read as 'mark present'")
	}
}
