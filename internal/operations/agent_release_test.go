package operations

import (
	"context"
	"errors"
	"net/http"
	"testing"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
)

// AN AGENT IS NEVER SERVED A SECRET, EVEN WHEN THE AUTHORIZER WOULD ALLOW IT (regalia-kms-sv3.2, CB4A Model C).
//
// The fixture's authorizer allows everything, so the refusal below can only come from the agent rule, and it must come
// before routing, policy and the token: a refused release spends no nonce and touches no key.
func TestAnAgentPrincipalIsRefusedReleaseSecretWithItsOwnRule(t *testing.T) {
	coordinator, semantic, recorder, hardware, router := admissionFixture(t, &scriptedAdmission{answers: []bool{true, true, true, true}})
	request := operationRequest()
	request.Principal, request.Operation = "spiffe://regalia/agent/support-bot", "release-secret"
	result, err := coordinator.Execute(context.Background(), request)
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Code != "DENIED" || failure.Status != http.StatusForbidden || failure.Retryable {
		t.Fatalf("Execute = %v, want a permanent 403 DENIED", err)
	}
	if result.Data != nil {
		t.Fatal("a refused release returned data")
	}
	if semantic.calls != 0 || hardware.calls != 0 || router.calls != 0 {
		t.Fatalf("refused release: policy evaluated %d times, token used %d times, routing asked %d times", semantic.calls, hardware.calls, router.calls)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" || recorder.drafts[0].Outcome != auth.AgentReleaseRefused ||
		recorder.drafts[0].Principal != request.Principal || recorder.drafts[0].Operation != "release-secret" {
		t.Fatalf("audit events = %#v, want one deny %q naming the agent and the operation", recorder.drafts, auth.AgentReleaseRefused)
	}
	if auth.AgentReleaseRefused != "agent-release-refused" {
		t.Fatalf("the rule id is part of the audit contract; it changed to %q", auth.AgentReleaseRefused)
	}
}

// The rule refuses one operation for one class of principal, and nothing else: an agent still gets operations on keys
// that stay on the token, and a workload is still served release-secret.
func TestTheAgentRuleRefusesNothingElse(t *testing.T) {
	for _, c := range []struct{ principal, operation string }{
		{"spiffe://regalia/agent/support-bot", "unwrap"},
		{"spiffe://regalia/agent/support-bot", "sign"},
		{"spiffe://regalia/workload/sops-prod", "release-secret"},
		{"spiffe://regalia/agents/support-bot", "release-secret"}, // not under the agent prefix
	} {
		t.Run(c.principal+" "+c.operation, func(t *testing.T) {
			coordinator, _, recorder, _, router := admissionFixture(t, &scriptedAdmission{answers: []bool{true, true, true, true}})
			request := operationRequest()
			request.Principal, request.Operation = c.principal, c.operation
			_, _ = coordinator.Execute(context.Background(), request)
			for _, draft := range recorder.drafts {
				if draft.Outcome == auth.AgentReleaseRefused {
					t.Fatalf("refused by the agent rule: %#v", recorder.drafts)
				}
			}
			if router.calls == 0 {
				t.Fatalf("never reached routing: %#v", recorder.drafts)
			}
		})
	}
}
