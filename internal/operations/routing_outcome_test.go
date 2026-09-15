package operations

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// AN UNREACHABLE HSM AND A POLICY REFUSAL MUST NOT BE THE SAME AUDIT EVENT.
//
// The caller has always been told which of three things happened — DENIED, NOT_FOUND, or a
// retryable BACKEND_UNAVAILABLE. The audit recorded "routing-denied" for all three, with the same
// decision and nothing else in the event to separate them. So an operator could not count
// availability incidents, a spike of denials caused by a dead card read as an authorization
// problem, and real denials were diluted by outage noise.
//
// The envelope-expired branch in the same function already makes this argument — an operator woken
// by a failure needs to see which failure — and it was not applied one branch above.
func TestEachRoutingFailureIsRecordedAsItsOwnOutcome(t *testing.T) {
	for _, refusal := range []struct {
		what    string
		err     error
		code    string
		outcome string
		retry   bool
	}{
		{"policy refuses the route", &registry.Error{Code: registry.CodeDenied}, "DENIED", "routing-denied", false},
		{"the object is not in the manifest", &registry.Error{Code: registry.CodeNotFound}, "NOT_FOUND", "routing-object-unknown", false},
		{"the backend cannot be reached", &registry.Error{Code: registry.CodeDependencyUnavailable}, "BACKEND_UNAVAILABLE", "routing-backend-unavailable", true},
	} {
		t.Run(refusal.what, func(t *testing.T) {
			recorder := &fakeAudit{}
			coordinator, err := New(fakeAuthorizer{allowed: true},
				&fakeRouter{routeErr: refusal.err},
				&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
				recorder, directRunner{}, &fakeHardware{output: []byte("x")}, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, execErr := coordinator.Execute(context.Background(), operationRequest())

			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("Execute() = %v, want an api.Failure", execErr)
			}
			if failed.Code != refusal.code || failed.Retryable != refusal.retry {
				t.Fatalf("caller saw %s retryable=%v, want %s retryable=%v",
					failed.Code, failed.Retryable, refusal.code, refusal.retry)
			}
			var outcomes []string
			for _, draft := range recorder.drafts {
				outcomes = append(outcomes, draft.Outcome)
			}
			last := outcomes[len(outcomes)-1]
			if last != refusal.outcome {
				t.Fatalf("audit recorded %q, want %q, for %s: the caller was told %s and the trail "+
					"says %q, so an operator reading it cannot tell an outage from a denial. outcomes = %v",
					last, refusal.outcome, refusal.what, refusal.code, last, outcomes)
			}
		})
	}
}

// NO SEPARATE "THE THREE ARE DISTINCT" CASE, DELIBERATELY, AND FOR THE SECOND TIME.
//
// It reads like the useful companion assertion, and it cannot fail on its own: the case above
// pins each outcome to an exact string, so any mutation that makes two of them collide — to an
// existing name or to a new shared one — reddens that case first. Measured, not assumed: renaming
// both to "routing-other" fails two of its subtests and the distinctness case together, never the
// distinctness case alone.
//
// The same test was written and deleted in the nitrokey package for the same reason (the two KEK
// quarantine reasons). Keeping one and deleting the other would leave the next reader unable to
// tell which treatment is the rule. TESTING.md 17.

// A TAMPERED ENVELOPE AND AN UNREACHABLE CARD MUST NOT BE THE SAME AUDIT EVENT.
//
// Both were recorded as "failure", together with a third case — the backend reporting success and
// returning nothing, which is a defect in this daemon. The response told the caller which:
// INVALID_ARGUMENT for ciphertext failing its AEAD proof, a classified execution error for a
// backend fault, INTERNAL for the empty result. The trail said "failure" three times.
//
// The comment beside that branch already said the distinction "is what tells tampering apart from
// an outage". It was true of the response and false of the record, in a system whose purpose is a
// tamper-evident trail: ciphertext failing its proof is a security event, an unreachable card is
// an availability event, and an empty success is a bug in this process.
func TestEachExecutionFailureIsRecordedAsItsOwnOutcome(t *testing.T) {
	for _, execution := range []struct {
		what     string
		hardware *fakeHardware
		code     string
		retry    bool
		outcome  string
	}{
		{"ciphertext fails its AEAD proof", &fakeHardware{err: envelope.ErrInvalidEnvelope}, "INVALID_ARGUMENT", false, "integrity-failed"},
		{"the card cannot be reached", &fakeHardware{err: errors.New("card gone")}, "BACKEND_UNAVAILABLE", true, "backend-failed"},
		{"the backend succeeds and returns nothing", &fakeHardware{output: nil}, "INTERNAL", false, "empty-output"},
	} {
		t.Run(execution.what, func(t *testing.T) {
			recorder := &fakeAudit{}
			coordinator, err := New(fakeAuthorizer{allowed: true},
				&fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}},
				&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
				recorder, directRunner{}, execution.hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			_, execErr := coordinator.Execute(context.Background(), operationRequest())
			// THE CALLER'S CODE IS ASSERTED TOO, because the outcome being right does not make the
			// response right: separating these outcomes is only worth something if the trail and
			// the reply describe the same event. A table carrying an expected code and never
			// checking it is exactly the shape that lets the two drift apart unnoticed.
			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("Execute() = %v, want an api.Failure", execErr)
			}
			if failed.Code != execution.code || failed.Retryable != execution.retry {
				t.Fatalf("caller saw %s retryable=%v for %s, want %s retryable=%v",
					failed.Code, failed.Retryable, execution.what, execution.code, execution.retry)
			}
			last := recorder.drafts[len(recorder.drafts)-1].Outcome
			if last != execution.outcome {
				t.Fatalf("audit recorded %q for %s, want %q — an operator reading the trail cannot "+
					"tell a security event from an outage", last, execution.what, execution.outcome)
			}
		})
	}
}

// THE CONTROL: a successful operation still records "success", so the split above did not simply
// rename everything. Without it, a mutation making every outcome unique would satisfy each case.
func TestASuccessfulOperationStillRecordsSuccess(t *testing.T) {
	recorder := &fakeAudit{}
	coordinator, err := New(fakeAuthorizer{allowed: true},
		&fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}},
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		recorder, directRunner{}, &fakeHardware{output: []byte("data-key")}, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, execErr := coordinator.Execute(context.Background(), operationRequest()); execErr != nil {
		t.Fatalf("a well-formed operation failed: %v", execErr)
	}
	if last := recorder.drafts[len(recorder.drafts)-1].Outcome; last != "success" {
		t.Fatalf("a successful operation recorded %q", last)
	}
}
