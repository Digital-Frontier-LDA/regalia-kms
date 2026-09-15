package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func reservation(nonce, date string, amount, cap uint64) Reservation {
	return Reservation{
		PolicyID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer",
		Principal: "spiffe://regalia/workload/tx-signer", Nonce: nonce, UTCDate: date,
		Amounts: map[string]uint64{"uatom": amount}, DailyCaps: map[string]uint64{"uatom": cap},
	}
}

func TestFileStatePersistsReplayAndQuotaAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	first := reservation("nonce_000000000001", "2026-09-03", 600, 1_000)
	if err := state.Reserve(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	state, err = OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Reserve(context.Background(), first); !errors.Is(err, ErrReplay) {
		t.Fatalf("duplicate error = %v", err)
	}
	if err := state.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-03", 401, 1_000)); !errors.Is(err, ErrLimit) {
		t.Fatalf("quota error = %v", err)
	}
	if err := state.Reserve(context.Background(), reservation("nonce_000000000003", "2026-09-04", 401, 1_000)); err != nil {
		t.Fatalf("new UTC day rejected: %v", err)
	}
}

func TestFileStateRejectsCorruptJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-03", 1, 10))
	_ = state.Close()
	contents, _ := os.ReadFile(path)
	contents = []byte(strings.Replace(string(contents), `"amounts":{"uatom":1}`, `"amounts":{"uatom":9}`, 1))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileState(path); err == nil {
		t.Fatal("corrupt journal accepted")
	}
}

func TestFileStateSerializesConcurrentQuotaReservations(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	var allowed atomic.Int32
	var unexpected atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 20; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			err := state.Reserve(context.Background(), reservation("nonce_0000000000"+string(rune('A'+index)), "2026-09-03", 1, 10))
			if err == nil {
				allowed.Add(1)
			} else if !errors.Is(err, ErrLimit) {
				unexpected.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if allowed.Load() != 10 || unexpected.Load() != 0 {
		t.Fatalf("allowed=%d unexpected=%d", allowed.Load(), unexpected.Load())
	}
}
