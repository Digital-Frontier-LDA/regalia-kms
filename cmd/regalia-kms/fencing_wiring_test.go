package main

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

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
)

type passthroughRunner struct{ ran bool }

func (runner *passthroughRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	runner.ran = true
	return operation(ctx)
}

func writeSiteLease(t *testing.T, path string, private ed25519.PrivateKey, site, digest string, epoch uint64, before, expiry time.Time) {
	t.Helper()
	payload := map[string]any{
		"version": 1, "site": site, "epoch": epoch,
		"not_before": before.UTC().Format(time.RFC3339Nano), "expires_at": expiry.UTC().Format(time.RFC3339Nano),
		"registry_digest": digest,
	}
	// The signature covers the field order the gate reconstructs, so build the signed form the same way.
	signed, _ := json.Marshal(struct {
		Version        int    `json:"version"`
		Site           string `json:"site"`
		Epoch          uint64 `json:"epoch"`
		NotBefore      string `json:"not_before"`
		ExpiresAt      string `json:"expires_at"`
		RegistryDigest string `json:"registry_digest"`
	}{1, site, epoch, payload["not_before"].(string), payload["expires_at"].(string), digest})
	payload["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(private, signed))
	contents, _ := json.Marshal(payload)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

// THE DAEMON MUST ACTUALLY TAKE THE LEASE.
//
// internal/fencing was complete and well tested and had NO non-test importer: nothing in the daemon
// ever opened a gate, so ADR-0001 §8 — never two simultaneous signers — was enforced by nothing at
// runtime. Two hosts pointed at the same key would both have signed, and every test in the fencing
// package would still have been green. This test fails if that wiring is ever removed again.
func TestFenceRunnerRefusesWorkUntilTheSiteHoldsTheLease(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	keyPath := filepath.Join(directory, "fencing.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	settings := config.Config{
		Site: "sitea", FencingLeasePath: leasePath, FencingStatePath: statePath, FencingPublicKeyPath: keyPath,
	}

	base := &passthroughRunner{}
	runner, probe, err := fenceRunner(settings, digest, base)
	if err != nil {
		t.Fatalf("the daemon refused to start on a passive site: %v", err)
	}
	if probe == nil {
		t.Fatal("fencing was configured but contributed no readiness probe: a passive site would report itself ready")
	}
	if probe.Ready(context.Background()) {
		t.Fatal("a site with no lease reported ready")
	}
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, fencing.ErrFenced) {
		t.Fatalf("a site with no lease ran an operation (err=%v): the runner is not fenced", err)
	}
	if base.ran {
		t.Fatal("the unfenced runner was reached on a site holding no lease")
	}

	// Grant the lease. The same runner must now work, with no restart.
	writeSiteLease(t, leasePath, private, "sitea", digest, 1, time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	if !probe.Ready(context.Background()) {
		t.Fatal("a granted lease did not make the site ready")
	}
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("an active site was refused: %v", err)
	}
	if !base.ran {
		t.Fatal("the operation never reached the real runner")
	}
}

// An unfenced deployment must keep working, and must not gain a readiness dependency it cannot
// satisfy — otherwise adding the fence would make every single-site install permanently unready.
func TestUnfencedConfigurationIsUnchanged(t *testing.T) {
	base := &passthroughRunner{}
	runner, probe, err := fenceRunner(config.Config{Site: "sitea"}, "sha256:aa", base)
	if err != nil {
		t.Fatal(err)
	}
	if probe != nil {
		t.Fatal("an unfenced deployment gained a readiness probe it can never satisfy")
	}
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); err != nil || !base.ran {
		t.Fatalf("an unfenced deployment stopped running operations: err=%v ran=%v", err, base.ran)
	}
}

// A key that cannot be read is a mistake someone can fix; a site that silently never becomes ready
// looks identical to a correctly passive one. Fail at startup instead.
func TestFencingRefusesAnUnusableKeyAtStartup(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "fencing.pub")
	settings := config.Config{
		Site: "sitea", FencingLeasePath: filepath.Join(directory, "l.json"),
		FencingStatePath: filepath.Join(directory, "e.jsonl"), FencingPublicKeyPath: keyPath,
	}
	for name, contents := range map[string]string{
		"not base64":   "!!!!not base64!!!!",
		"wrong length": base64.StdEncoding.EncodeToString([]byte("too short")),
	} {
		if err := os.WriteFile(keyPath, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := fenceRunner(settings, "sha256:aa", &passthroughRunner{}); err == nil {
			t.Fatalf("%s fencing key was accepted: the site would sit unready with nothing to fix", name)
		}
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fenceRunner(settings, "sha256:aa", &passthroughRunner{}); err == nil {
		t.Fatal("a missing fencing key was accepted")
	}
}

// THE EPOCH THE SPEND JOURNAL STAMPS (#428). Three observable states of the source the
// daemon binds into the policy engine, each of which must fail or spend correctly:
// a held lease names its epoch; a lease not held stamps 0 (which the journal refuses
// once fenced history exists — fail closed); the source is read per reservation so a
// promotion mid-run changes what the next reservation stamps.
func TestEpochSourceNamesTheHeldLeaseAndZeroOtherwise(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	standby, err := fencing.NewStandby(leasePath, statePath, "sitea", digest, public, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	// No lease on disk: the source must stamp 0 — the unheld state the journal refuses
	// against fenced history, not an epoch that would spend.
	if epoch := epochSourceFor(standby)(); epoch != 0 {
		t.Fatalf("without a lease the epoch source stamped %d, want 0 — the spend journal must see the unheld state", epoch)
	}

	// The lease is granted at epoch 9. Snapshot reads the gate's LAST acquire, and in the
	// daemon the admission check is what re-acquires before Evaluate stamps — so the test
	// forces the same refresh (Ready) before sampling, which is the production ordering.
	writeSiteLease(t, leasePath, private, "sitea", digest, 9, time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	if !standby.Ready(context.Background()) {
		t.Fatal("the granted lease did not make the standby ready")
	}
	source := epochSourceFor(standby)
	if epoch := source(); epoch != 9 {
		t.Fatalf("with the lease held at epoch 9 the source stamped %d", epoch)
	}

	// Promotion mid-run: the lease file is replaced with a higher epoch, and the SAME
	// source (already bound into the engine) must stamp the new one on its next call —
	// a construction-time capture would keep stamping 9 onto the epoch-10 leader.
	writeSiteLease(t, leasePath, private, "sitea", digest, 10, time.Now().Add(-time.Minute), time.Now().Add(5*time.Minute))
	if !standby.Ready(context.Background()) {
		t.Fatal("the promoted lease did not keep the standby ready")
	}
	if epoch := source(); epoch != 10 {
		t.Fatalf("after promotion the source still stamped %d, want 10 — the epoch must be read per reservation", epoch)
	}
}
