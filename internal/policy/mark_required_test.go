package policy

// #223, the policy twin: same rule, same matrix, real writer. See internal/audit's
// mark_required_test.go for the reasoning — the two packages share one write discipline
// (append+fsync, then the mark), so they share one boundary: one reservation without a mark
// is the first write's crash window; two or more with no prior position is a deletion.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func reserveEvents(t *testing.T, path string, count int) {
	t.Helper()
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < count; i++ {
		reservation := Reservation{
			PolicyID: "policy-1", ObjectID: "object-1", Principal: "test-principal",
			Nonce:   fmt.Sprintf("nonce-%08d-0123abcd", i),
			UTCDate: "2026-09-06",
			Amounts: map[string]uint64{"release": 1}, DailyCaps: map[string]uint64{"release": 10},
		}
		if err := state.Reserve(context.Background(), reservation); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAPolicyJournalWithHistoryCannotHaveNoPriorPosition(t *testing.T) {
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
	t.Run("tail and mark deleted together is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-state.jsonl")
		reserveEvents(t, path, 3)
		truncateTo(t, path, 2)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyState(path); err == nil {
			t.Fatal("a truncated policy journal with its mark deleted verified clean — spent quota and consumed nonces reopened")
		}
	})
	t.Run("intact with its mark verifies", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-state.jsonl")
		reserveEvents(t, path, 3)
		if _, err := VerifyState(path); err != nil {
			t.Fatalf("an intact journal with its mark refused: %v", err)
		}
	})
	t.Run("one reservation without a mark is the crash window and stays open", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-state.jsonl")
		reserveEvents(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyState(path); err != nil {
			t.Fatalf("the first reservation's crash window was refused: %v", err)
		}
	})
	t.Run("truncated to exactly one event is the stated residual, not an oversight", func(t *testing.T) {
		// A journal with ONE event and no mark is byte-for-byte the first write's crash
		// window, so this rule cannot distinguish deletion-to-one from crash — by
		// construction, not by accident. What closes it is memory OUTSIDE the journal:
		// the collector-acknowledged position for a shipping host, and the site-level
		// provenance marker for a rebuilt one (#220). If this row ever FAILS, that layer
		// moved and this comment must move with it.
		path := filepath.Join(t.TempDir(), "policy-state.jsonl")
		reserveEvents(t, path, 3)
		truncateTo(t, path, 1)
		if err := os.Remove(path + highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyState(path); err != nil {
			t.Fatalf("the boundary moved: %v", err)
		}
	})
}

func TestAGenesisValuedPresentMarkIsADowngrade(t *testing.T) {
	// The policy twin of audit's downgrade row, which this matrix lacked (#227 review):
	// the only write site records event.Sequence, never zero, so a genesis-valued PRESENT
	// mark beside any history is written after the fact.
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	reserveEvents(t, path, 2)
	if err := os.WriteFile(path+highWaterSuffix, []byte(`{"sequence":0,"hash":"0000000000000000000000000000000000000000000000000000000000000000"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyState(path); err == nil {
		t.Fatal("a mark reset to genesis beside two reservations verified — spent quota reopened invisibly")
	}
}

func TestAnUnknowableMarkIsNeitherAbsentNorPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	reserveEvents(t, path, 2)
	// Was a bare os.Chmod, which root ignores: as root the directory stays readable, VerifyState
	// succeeds, and this row fails claiming the guard is broken when what actually happened is
	// that the fault was never injected. denyAllAccess (#334) gates on what the kernel recorded
	// and on a real open attempt, and skips rather than reporting about a fault that is not there.
	denyAllAccess(t, filepath.Dir(path))
	_, err := VerifyState(path)
	if err == nil {
		t.Fatal("an unreadable state directory verified clean — 'cannot tell' read as 'mark present'")
	}
	// WHICH REFUSAL THIS IS, MEASURED (#334), because the name reads like a claim about the
	// high-water stat switch and it is not one. With the directory unreadable, the os.Stat at
	// the TOP of VerifyState fails first and refuses there; the switch is never reached, and
	// neutralising it (default: -> markFileExists = true) leaves the whole package green. What
	// this row pins is real and worth keeping — an unreadable state directory does not verify
	// clean — but it is evidence about the entry guard, not about the switch.
	if !strings.Contains(err.Error(), "cannot verify") {
		t.Fatalf("the refusal came from %q rather than from the entry guard this row actually reaches — if the ordering changed, the comment above is now wrong", err)
	}
}
