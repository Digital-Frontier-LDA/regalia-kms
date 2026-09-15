package fencing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A PASSIVE SITE MUST BE ABLE TO BECOME ACTIVE WITHOUT A RESTART.
//
// Open() reports ErrFenced when no lease is present, so a daemon that called it directly at startup
// would refuse to boot on the standby — and a failover that needs someone to restart the standby is
// not a failover. The site has to come up, serve health, report itself not ready, and pick the lease
// up the moment it is granted.
func TestStandbyBecomesActiveWhenTheLeaseArrivesWithoutRestart(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	standby, err := NewStandby(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil {
		t.Fatalf("a standby site refused to start with no lease present: %v", err)
	}
	if standby.Ready(context.Background()) {
		t.Fatal("a site with no lease reported itself ready: two sites could sign at once")
	}

	// The lease is granted. No restart, no re-construction.
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	if !standby.Ready(context.Background()) {
		t.Fatal("a granted lease did not activate the standby: failover would require a restart")
	}
}

// Configuration mistakes must be startup errors, not a site that quietly never becomes ready. From
// outside, "misconfigured" and "correctly passive" look identical, and only one of them is fixable.
func TestStandbyRefusesIncompleteConfigurationImmediately(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	lease := filepath.Join(directory, "lease.json")
	state := filepath.Join(directory, "epochs.jsonl")
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for name, build := range map[string]func() (*Standby, error){
		"no lease path": func() (*Standby, error) {
			return NewStandby("", state, "sitea", digest, public, time.Now)
		},
		"no epoch journal": func() (*Standby, error) {
			return NewStandby(lease, "", "sitea", digest, public, time.Now)
		},
		"no site": func() (*Standby, error) {
			return NewStandby(lease, state, "", digest, public, time.Now)
		},
		"no registry digest": func() (*Standby, error) {
			return NewStandby(lease, state, "sitea", "", public, time.Now)
		},
		"truncated key": func() (*Standby, error) {
			return NewStandby(lease, state, "sitea", digest, public[:16], time.Now)
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s was accepted: the site would sit permanently unready with no error to fix", name)
		}
	}
}

// A SITE THAT LOSES THE LEASE MID-FLIGHT MUST STOP, not finish the signature it had started. This is
// the case active/passive exists for: the lease was revoked because another site is taking over, so
// completing the in-flight operation is exactly the double-signing ADR-0001 §8 forbids.
func TestLosingTheLeaseMidFlightStopsTheOperation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	clock := now
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))

	standby, err := NewStandby(leasePath, statePath, "sitea", digest, public, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(standby, &immediateRunner{})

	// Admission succeeds, then the lease is revoked while the operation is in flight — the shape of
	// a real takeover, since a signature takes long enough for a lease to lapse underneath it.
	signed := false
	err = runner.Run(context.Background(), func(context.Context) error {
		clock = now.Add(2 * time.Minute) // the lease expires while the token is signing
		signed = true
		return nil
	})
	if !signed {
		t.Fatal("the operation never ran: this test is not exercising the mid-flight case")
	}
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("an operation that outlived its lease returned %v: its signature would be published by a site that had already been replaced", err)
	}

	// And the site must now refuse admission outright.
	if standby.Ready(context.Background()) {
		t.Fatal("a site whose lease expired still reported itself ready")
	}
}

// TWO SITES SHARING AN EPOCH JOURNAL MUST NOT BOTH BE ACTIVE. The old active coming back with its
// still-unexpired lease is the dangerous case: the epoch it observed has moved on.
func TestAnOldActiveCannotResumeAfterTheEpochMoves(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	writeLease(t, leasePath, private, "sitea", digest, 5, now.Add(-time.Minute), now.Add(time.Minute))
	site, err := NewStandby(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil || !site.Ready(context.Background()) {
		t.Fatalf("epoch 5 lease was not accepted: %v", err)
	}

	// The operator grants the site again at a higher epoch, then someone replays the older lease.
	writeLease(t, leasePath, private, "sitea", digest, 6, now.Add(-time.Minute), now.Add(time.Minute))
	if !site.Ready(context.Background()) {
		t.Fatal("a newer epoch was refused")
	}
	writeLease(t, leasePath, private, "sitea", digest, 5, now.Add(-time.Minute), now.Add(time.Minute))
	if site.Ready(context.Background()) {
		t.Fatal("a replayed older lease reactivated the site: an evicted active could sign alongside its replacement")
	}

	// A fresh process reading the same journal must reach the same conclusion.
	revived, err := NewStandby(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if revived.Ready(context.Background()) {
		t.Fatal("restarting the daemon cleared the epoch fence: a restart became a way to double-sign")
	}
	_ = os.Remove(statePath)
}
