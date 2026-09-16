package fencing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"
)

// THE LEASE STATE MUST BE VISIBLE WITHOUT ASKING THE LEASE A QUESTION.
//
// During a failover the operator's questions are "does this site believe it holds
// the lease", "at what epoch", and "when did it last check" — and until now the
// only answer was a readiness false that cannot distinguish "never held it" from
// "lost it". The snapshot is passive: reading it performs no I/O and cannot move
// the lease, because the values are recorded when the gate evaluates, not when they
// are read.
func TestStandbySnapshotDistinguishesNeverHeldFromHeldFromLost(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := privateTempDir(t)
	leasePath, statePath := filepath.Join(directory, "lease.json"), filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	standby, err := NewStandby(leasePath, statePath, "sitea", "sha256:registry", public, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, ok := standby.Snapshot(); ok {
		t.Fatal("snapshot reports acquired before any lease check: never-held must be distinguishable from lost")
	}

	writeLease(t, leasePath, private, "sitea", "sha256:registry", 3, now.Add(-time.Minute), now.Add(5*time.Minute))
	if !standby.Ready(context.Background()) {
		t.Fatal("valid lease was not accepted")
	}
	held, epoch, checked, ok := standby.Snapshot()
	if !ok || !held || epoch != 3 {
		t.Fatalf("Snapshot = held:%t epoch:%d ok:%t, want held:true epoch:3 ok:true", held, epoch, ok)
	}
	if !checked.Equal(now) {
		t.Fatalf("snapshot check time = %s, want the evaluation time %s", checked, now)
	}

	// The lease expires while the process is running: the site loses it.
	now = now.Add(10 * time.Minute)
	if standby.Ready(context.Background()) {
		t.Fatal("an expired lease was still held")
	}
	held, epoch, checked, ok = standby.Snapshot()
	if !ok || held || epoch != 3 {
		t.Fatalf("after loss Snapshot = held:%t epoch:%d ok:%t, want held:false epoch:3 ok:true — the high-water epoch survives the loss", held, epoch, ok)
	}
	if !checked.Equal(now) {
		t.Fatalf("snapshot check time after loss = %s, want %s", checked, now)
	}
}
