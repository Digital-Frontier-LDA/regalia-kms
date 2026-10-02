package operations

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// scriptedAdmission answers Ready from a list, one answer per call, and false once it runs out.
type scriptedAdmission struct {
	answers []bool
	calls   int
}

func (gate *scriptedAdmission) Ready(context.Context) bool {
	answer := gate.calls < len(gate.answers) && gate.answers[gate.calls]
	gate.calls++
	return answer
}

func admissionFixture(t *testing.T, gate *scriptedAdmission) (*Coordinator, *fakePolicy, *fakeAudit, *fakeHardware) {
	t.Helper()
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-sitea"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("data-key")}
	// The runner the daemon builds: the admission runner over the executor, on the same gate.
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder,
		admission.NewRunner(gate, directRunner{}), hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.RequireAdmission(gate)
	return coordinator, semantic, recorder, hardware
}

func wantNotAdmitted(t *testing.T, result api.Result, err error) {
	t.Helper()
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Code != "DEPENDENCY_UNAVAILABLE" || failure.Status != http.StatusServiceUnavailable || !failure.Retryable {
		t.Fatalf("Execute = %v, want a retryable 503 DEPENDENCY_UNAVAILABLE", err)
	}
	if result.Data != nil {
		t.Fatal("a refused operation returned data")
	}
}

// A NODE WITH NO RUNTIME LEASE DOES NO KEY OPERATION, AND SPENDS NO POLICY STATE ON ONE.
//
// The refusal comes before policy is evaluated: evaluating reserves the request's nonce and its
// quota, and a node that will not do the work must not consume either.
func TestANodeThatIsNotAdmittedRefusesBeforePolicyIsEvaluated(t *testing.T) {
	gate := &scriptedAdmission{}
	coordinator, semantic, recorder, hardware := admissionFixture(t, gate)
	result, err := coordinator.Execute(context.Background(), operationRequest())
	wantNotAdmitted(t, result, err)
	if semantic.calls != 0 || hardware.calls != 0 {
		t.Fatalf("policy evaluated %d times and the token used %d times for a node that is not admitted", semantic.calls, hardware.calls)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" || recorder.drafts[0].Outcome != "not-admitted" ||
		recorder.drafts[0].DeviceID != "hsm-sitea" {
		t.Fatalf("audit events = %#v", recorder.drafts)
	}
}

func TestAnAdmittedNodeServes(t *testing.T) {
	gate := &scriptedAdmission{answers: []bool{true, true, true, true}}
	coordinator, _, recorder, hardware := admissionFixture(t, gate)
	result, err := coordinator.Execute(context.Background(), operationRequest())
	if err != nil || string(result.Data) != "data-key" || hardware.calls != 1 {
		t.Fatalf("Execute = %#v, %v; token used %d times", result, err, hardware.calls)
	}
	// once by the coordinator, three times by the runner: before, at the start of, and after the operation
	if gate.calls != 4 {
		t.Fatalf("admission was checked %d times, want 4", gate.calls)
	}
	if len(recorder.drafts) != 2 || recorder.drafts[1].Outcome != "success" {
		t.Fatalf("audit events = %#v", recorder.drafts)
	}
}

// THE LEASE CAN LAPSE WHILE AN OPERATION WAITS OR RUNS. The token may already have signed; what is
// prevented is handing the result back. And the trail says why: "backend-failed" would send an
// operator to look at a healthy token.
func TestALeaseThatLapsesMidOperationYieldsNoOutputAndIsAuditedAsSuch(t *testing.T) {
	for name, c := range map[string]struct {
		answers  []bool
		executed int
	}{
		"while queued":           {[]bool{true, true, false}, 0},
		"while the token worked": {[]bool{true, true, true, false}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			gate := &scriptedAdmission{answers: c.answers}
			coordinator, semantic, recorder, hardware := admissionFixture(t, gate)
			result, err := coordinator.Execute(context.Background(), operationRequest())
			wantNotAdmitted(t, result, err)
			if hardware.calls != c.executed || semantic.calls != 1 {
				t.Fatalf("token used %d times (want %d), policy evaluated %d times", hardware.calls, c.executed, semantic.calls)
			}
			last := recorder.drafts[len(recorder.drafts)-1]
			if last.Decision != "deny" || last.Outcome != "not-admitted" {
				t.Fatalf("last audit event = %#v, want deny/not-admitted", last)
			}
			for _, draft := range recorder.drafts {
				if draft.Outcome == "backend-failed" || draft.Outcome == "success" {
					t.Fatalf("recorded %q for an operation whose lease lapsed", draft.Outcome)
				}
			}
		})
	}
}

// A coordinator that was never told to require admission behaves as before: a lab host, or one with
// no token, has no lease service to satisfy.
func TestWithoutRequireAdmissionNothingChanges(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-sitea"}}}
	recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("data-key")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}},
		recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := coordinator.Execute(context.Background(), operationRequest()); err != nil || string(result.Data) != "data-key" {
		t.Fatalf("Execute = %#v, %v", result, err)
	}
}

// EVERY CHANGE OF ADMISSION IS IN THE TRAIL, with the epoch the lease service decided under.
func TestAnAdmissionTransitionIsOneCompleteAuditEvent(t *testing.T) {
	coordinator, _, recorder, _ := admissionFixture(t, &scriptedAdmission{})
	if err := coordinator.RecordAdmission(context.Background(), "site-a", false, 8); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RecordAdmission(context.Background(), "site-a", true, 9); err != nil {
		t.Fatal(err)
	}
	want := []struct{ decision, outcome, purpose string }{{"deny", "not-admitted", "epoch-8"}, {"allow", "admitted", "epoch-9"}}
	if len(recorder.drafts) != 2 {
		t.Fatalf("audit events = %#v", recorder.drafts)
	}
	for i, draft := range recorder.drafts {
		if draft.Decision != want[i].decision || draft.Outcome != want[i].outcome || draft.Purpose != want[i].purpose ||
			draft.Operation != "runtime-admission" || draft.ObjectID != "site-a" || draft.Principal != "system:runtime-admission" {
			t.Fatalf("event %d = %#v", i, draft)
		}
		// What the journal requires of every event: without these it refuses to write it.
		if draft.Timestamp.IsZero() || !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(draft.RequestID) ||
			draft.RegistryDigest != "sha256:registry" || draft.PolicyDigest != "sha256:policy" || draft.RBACDigest != "sha256:rbac" {
			t.Fatalf("event %d is not a complete audit event: %#v", i, draft)
		}
	}
	if recorder.drafts[0].RequestID == recorder.drafts[1].RequestID {
		t.Fatal("two transitions share a request ID")
	}
	failing := &fakeAudit{err: audit.ErrSinkUnavailable}
	coordinator.audit = failing
	if err := coordinator.RecordAdmission(context.Background(), "site-a", true, 9); !errors.Is(err, audit.ErrSinkUnavailable) {
		t.Fatalf("RecordAdmission = %v, want the journal's error", err)
	}
}
