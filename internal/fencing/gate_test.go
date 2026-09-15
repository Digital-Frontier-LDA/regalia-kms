package fencing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeLease(t *testing.T, path string, private ed25519.PrivateKey, site, digest string, epoch uint64, before, expiry time.Time) {
	t.Helper()
	payload := signedLease{Version: 1, Site: site, Epoch: epoch, NotBefore: before.UTC().Format(time.RFC3339Nano), ExpiresAt: expiry.UTC().Format(time.RFC3339Nano), RegistryDigest: digest}
	encoded, _ := json.Marshal(payload)
	document := leaseDocument{Version: payload.Version, Site: payload.Site, Epoch: payload.Epoch, NotBefore: payload.NotBefore, ExpiresAt: payload.ExpiresAt, RegistryDigest: payload.RegistryDigest, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, encoded))}
	contents, _ := json.Marshal(document)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestGateRejectsExpirySubstitutionAndEpochRollback(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath, statePath := filepath.Join(directory, "lease.json"), filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	clock := now
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", digest, public, func() time.Time { return clock })
	if err != nil || !gate.Ready(context.Background()) {
		t.Fatalf("open/ready = %v/%v", err, gate.Ready(context.Background()))
	}
	clock = now.Add(2 * time.Minute)
	if gate.Ready(context.Background()) {
		t.Fatal("expired site remained active")
	}
	clock = now
	writeLease(t, leasePath, private, "siteb", digest, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatal("wrong-site lease accepted")
	}
	writeLease(t, leasePath, private, "sitea", digest, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if !gate.Ready(context.Background()) {
		t.Fatal("new epoch not accepted")
	}
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatal("rolled-back epoch accepted")
	}
}

func TestGateRejectsInvalidSignatureRegistryAndJournalTamper(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	_, attacker, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath, statePath := filepath.Join(directory, "lease.json"), filepath.Join(directory, "epochs.jsonl")
	now := time.Now().UTC()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, attacker, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	if _, err := Open(leasePath, statePath, "sitea", digest, public, time.Now); !errors.Is(err, ErrFenced) {
		t.Fatalf("invalid signature error = %v", err)
	}
	writeLease(t, leasePath, private, "sitea", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, now.Add(-time.Minute), now.Add(time.Minute))
	if _, err := Open(leasePath, statePath, "sitea", digest, public, time.Now); !errors.Is(err, ErrFenced) {
		t.Fatalf("wrong registry error = %v", err)
	}
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	if _, err := Open(leasePath, statePath, "sitea", digest, public, time.Now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(leasePath, statePath, "sitea", digest, public, time.Now); err == nil {
		t.Fatal("tampered epoch journal accepted")
	}
}

type immediateRunner struct{ calls int }

func (runner *immediateRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	runner.calls++
	return operation(ctx)
}

func TestFencedRunnerChecksLeaseBeforeHardware(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	now := time.Now().UTC()
	clock := now
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	leasePath := filepath.Join(directory, "lease.json")
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, filepath.Join(directory, "state.jsonl"), "sitea", digest, public, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	inner := &immediateRunner{}
	runner := NewRunner(gate, inner)
	hardwareCalls := 0
	if err := runner.Run(context.Background(), func(context.Context) error { hardwareCalls++; return nil }); err != nil || hardwareCalls != 1 {
		t.Fatalf("active run = %v calls=%d", err, hardwareCalls)
	}
	clock = now.Add(2 * time.Minute)
	if err := runner.Run(context.Background(), func(context.Context) error { hardwareCalls++; return nil }); !errors.Is(err, ErrFenced) || hardwareCalls != 1 || inner.calls != 1 {
		t.Fatalf("fenced run = %v hardware=%d runner=%d", err, hardwareCalls, inner.calls)
	}
}
