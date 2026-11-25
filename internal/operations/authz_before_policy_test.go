package operations

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// AUTHORIZATION IS DECIDED BEFORE POLICY (threat model T02, epic #40 AC1, gap .1.5).
//
// TestCoordinatorDenialAndAuditFailureNeverReachHardware shows an RBAC denial never reaches the
// card. It does not show the denial is decided before policy: policy.Evaluate spends replay and
// quota state (a nonce, a reservation), so a coordinator that evaluated policy first and checked
// RBAC second would let an unauthorized principal burn an authorized caller's nonce or quota, and
// the trail would still say rbac-denied. This test records the order of the two calls on one log.
type orderedAuthorizer struct {
	allowed bool
	log     *[]string
}

func (value orderedAuthorizer) Allowed(string, string, string, string) bool {
	*value.log = append(*value.log, "authorizer")
	return value.allowed
}
func (orderedAuthorizer) Digest() string { return "sha256:rbac" }

type orderedPolicy struct {
	decision policy.Decision
	log      *[]string
}

func (value orderedPolicy) Evaluate(context.Context, policy.Request) policy.Decision {
	*value.log = append(*value.log, "policy")
	return value.decision
}

func (orderedPolicy) ReservesCosmosSequence(objectID, operation, contentType string) bool {
	return false
}

func TestADenyingAuthorizerIsDecidedBeforePolicyIsEvaluated(t *testing.T) {
	allow := policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}
	deny := policy.Decision{Allowed: false, Code: policy.CodeLimitExceeded, PolicyID: "sops", Rule: "rate"}
	for _, c := range []struct {
		name        string
		allowed     bool
		decision    policy.Decision
		wantOrder   []string
		wantOutcome string
	}{
		// CONTROL, first: with a granting authorizer the same request reaches policy, so a zero
		// below is not a coordinator that never calls policy at all.
		{"control: granted, policy evaluated after the grant", true, allow, []string{"authorizer", "policy"}, "authorized"},
		{"denied, policy would allow", false, allow, []string{"authorizer"}, "rbac-denied"},
		// A policy that would also deny: the trail must name RBAC, which it can only do if RBAC
		// was decided first.
		{"denied, policy would deny too", false, deny, []string{"authorizer"}, "rbac-denied"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log []string
			router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
			hardware := &fakeHardware{output: []byte("data-key")}
			recorder := &fakeAudit{}
			coordinator, err := New(orderedAuthorizer{allowed: c.allowed, log: &log}, router, orderedPolicy{decision: c.decision, log: &log}, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = coordinator.Execute(context.Background(), operationRequest())

			if !c.allowed && slices.Contains(log, "policy") {
				t.Fatalf("DEFECT: policy was evaluated for a principal the authorizer denies (calls in order: %v)", log)
			}
			if !slices.Equal(log, c.wantOrder) {
				t.Fatalf("calls in order = %v, want %v", log, c.wantOrder)
			}
			if len(recorder.drafts) == 0 || recorder.drafts[0].Outcome != c.wantOutcome {
				t.Fatalf("first audit draft = %#v, want outcome %q", recorder.drafts, c.wantOutcome)
			}
			if !c.allowed && (router.calls != 0 || hardware.calls != 0) {
				t.Fatalf("a denied principal reached routing (%d) or hardware (%d)", router.calls, hardware.calls)
			}
		})
	}
}
