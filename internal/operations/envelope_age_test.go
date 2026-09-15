package operations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// An envelope's created_at was authenticated and compared to nothing, so one sealed years ago
// released exactly like one sealed this morning: #6's "bounded by size and lifetime" held for the
// plaintext in memory and never for the ciphertext at rest.
//
// These run through a REAL registry and a REAL releaser so the chain from the manifest field to the
// refusal is the one that ships; only the authorizer, policy, audit sink and card are doubles, and
// none of them can expire anything.

const agingManifest = `{"schema_version":1,"manifest_id":"aging","generated_at":"2026-09-05T00:00:00Z","objects":[{"id":"production-sops","name":"aging","kind":"opaque-secret","classification":"restricted","environment":"production","owner":"security","purpose":"sops-data-key","custody":"hardware-envelope","algorithm":"opaque","operations":["seal-envelope","release-secret"],"policy_id":"sops","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null%s},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}]}`

// releaseAfter seals an envelope, then releases it `age` later against a manifest declaring
// `bound` (or no bound when bound is empty). Returns the audit outcomes so a refusal can be
// identified by name rather than only by status code.
func releaseAfter(t *testing.T, bound string, age time.Duration) ([]byte, []string, error) {
	t.Helper()
	sealedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oldEnvelope := envelopeAt(t, "1", sealedAt)

	rotationExtra := ""
	if bound != "" {
		rotationExtra = "," + bound
	}
	reg, err := registry.Load(strings.NewReader(fmt.Sprintf(agingManifest, retiredSlot1+","+activeSlot2+","+standbySiteB, rotationExtra)), "sitea", allHealthy{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	releaser, err := secrets.NewReleaser(&slotCard{})
	if err != nil {
		t.Fatal(err)
	}
	recorder := &fakeAudit{}
	coordinator, err := New(fakeAuthorizer{allowed: true}, reg,
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		recorder, directRunner{}, releaser, "sha256:policy", nil,
		func() time.Time { return sealedAt.Add(age) })
	if err != nil {
		t.Fatal(err)
	}

	result, execErr := coordinator.Execute(context.Background(), releaseRequest(oldEnvelope))
	outcomes := make([]string, 0, len(recorder.drafts))
	for _, draft := range recorder.drafts {
		outcomes = append(outcomes, draft.Outcome)
	}
	return result.Data, outcomes, execErr
}

func TestAnEnvelopePastItsObjectsBoundIsRefused(t *testing.T) {
	data, outcomes, err := releaseAfter(t, `"envelope_max_age_days":30`, 31*24*time.Hour)

	if err == nil {
		t.Fatalf("a 31-day-old envelope released under a 30-day bound: %q", data)
	}
	var failed *api.Failure
	if !errors.As(err, &failed) || failed.Code != "DENIED" {
		t.Fatalf("error = %v, want DENIED", err)
	}
	if failed.Retryable {
		t.Fatal("an expired envelope was reported retryable: waiting makes it older, not younger")
	}
	// NAMED, not merely denied. An operator woken by a release that stopped working must see that
	// the envelope aged out -- which re-sealing fixes -- rather than go hunting through RBAC for a
	// grant nobody removed.
	found := false
	for _, outcome := range outcomes {
		if outcome == "envelope-expired" {
			found = true
		}
		if outcome == "routing-denied" {
			t.Fatalf("the expiry was recorded as a routing denial; outcomes = %v", outcomes)
		}
	}
	if !found {
		t.Fatalf("no audit event names the expiry; outcomes = %v", outcomes)
	}
}

func TestAnEnvelopeInsideTheBoundStillReleases(t *testing.T) {
	data, _, err := releaseAfter(t, `"envelope_max_age_days":30`, 29*24*time.Hour)
	if err != nil {
		t.Fatalf("a 29-day-old envelope was refused under a 30-day bound: %v — the bound is off by a day or measured from the wrong end", err)
	}
	if string(data) != "the secret" {
		t.Fatalf("released %q", data)
	}
}

// TestTheBoundIsInclusiveAtItsEdge pins which side of the boundary the refusal falls on, because
// "30 days" is otherwise two different rules and an operator cannot tell which one they configured.
func TestTheBoundIsInclusiveAtItsEdge(t *testing.T) {
	if _, _, err := releaseAfter(t, `"envelope_max_age_days":30`, 30*24*time.Hour); err != nil {
		t.Fatalf("an envelope exactly 30 days old was refused under a 30-day bound: %v — the bound is exceeded only when the age is GREATER, so the last day is still inside it", err)
	}
	if _, _, err := releaseAfter(t, `"envelope_max_age_days":30`, 30*24*time.Hour+time.Second); err == nil {
		t.Fatal("an envelope one second past 30 days released: the bound does not bite at all")
	}
}

// TestAnObjectWithNoBoundNeverExpires is the safety property of the default, and the reason the
// field is opt-in. A lifetime bound is the one control here that causes an outage by working
// correctly: every envelope past it stops opening at once, on a clock nobody was watching.
func TestAnObjectWithNoBoundNeverExpires(t *testing.T) {
	data, outcomes, err := releaseAfter(t, "", 4000*24*time.Hour)
	if err != nil {
		t.Fatalf("an eleven-year-old envelope was refused by an object that declares no bound: %v; outcomes = %v", err, outcomes)
	}
	if string(data) != "the secret" {
		t.Fatalf("released %q", data)
	}
}
