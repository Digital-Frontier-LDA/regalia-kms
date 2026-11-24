package operations

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// regalia-kms-dx7.9 (PA decision D2): under the single-node profile's self-issued lease
// (admission.ModeSingle) a STATEFUL operation — one that reserves policy or opstate state:
// a spend-once approval, a Cosmos sequence, a data key bound to that spend — is refused while
// no audit collector is configured, before any of that state is reserved. The node's one disk
// is the only history; without the off-host copy the spend could be replayed after a disk loss,
// and no alert could ever say so. A configured collector that is UNREACHABLE does not refuse:
// the trail ships later and RegaliaAuditTrailBehind alerts. A STATELESS operation (sign,
// decrypt, ...) keeps serving: it reserves nothing.
//
// The gate the coordinator is handed reports the mode through the admission package's own
// Status, so the refusal lives in the real shape of the answer.

// modeGate is an Admission that also reports the mode its answer was made under
// (admission.Status.Mode), the way the production gate will.
type modeGate struct {
	ready bool
	mode  string
}

func (gate *modeGate) Ready(context.Context) bool { return gate.ready }
func (gate *modeGate) Mode() string               { return gate.mode }

// collectorFixture builds the coordinator the way the daemon does (New, admission runner over the
// executor on the same gate, RequireAdmission) and, when the mode is single, names the single-node
// collector requirement: the two knobs are the admission's mode and whether the collector is
// configured.
func collectorFixture(t *testing.T, mode string, collectorConfigured bool) (*Coordinator, *fakePolicy, *fakeAudit, *fakeHardware, *fakeRouter) {
	t.Helper()
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-sitea"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("data-key")}
	gate := &modeGate{ready: true, mode: mode}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder,
		admission.NewRunner(gate, directRunner{}), hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.RequireAdmission(gate)
	coordinator.SetStatelessOperations(api.StatelessOperations()...)
	if mode == admission.ModeSingle {
		coordinator.SetSingleNodeAdmission(true, collectorConfigured)
	}
	return coordinator, semantic, recorder, hardware, router
}

func wantCollectorNotConfigured(t *testing.T, result api.Result, err error) {
	t.Helper()
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Code != "DEPENDENCY_UNAVAILABLE" || failure.Status != http.StatusServiceUnavailable || !failure.Retryable {
		t.Fatalf("Execute = %v, want a retryable 503 DEPENDENCY_UNAVAILABLE", err)
	}
	if result.Data != nil {
		t.Fatal("a refused operation returned data")
	}
}

func wantServed(t *testing.T, hardware *fakeHardware, recorder *fakeAudit, result api.Result, err error) {
	t.Helper()
	if err != nil || hardware.calls != 1 || string(result.Data) != "data-key" {
		t.Fatalf("Execute = %#v, %v; token used %d times: the operation should have served", result, err, hardware.calls)
	}
	last := recorder.drafts[len(recorder.drafts)-1]
	if last.Decision != "allow" || last.Outcome != "success" {
		t.Fatalf("audit events = %#v: a served operation is recorded as such", recorder.drafts)
	}
}

// THE REFUSAL: a single admission, no collector configured, a stateful operation. It is refused
// before policy is evaluated, so nothing is reserved: the spend-once nonce, the quota, the
// sequence — none is spent on work the node will not be able to prove it did.
func TestASingleNodeWithNoCollectorRefusesAStatefulOperationBeforePolicy(t *testing.T) {
	coordinator, semantic, recorder, hardware, router := collectorFixture(t, admission.ModeSingle, false)
	result, err := coordinator.Execute(context.Background(), operationRequest())
	wantCollectorNotConfigured(t, result, err)
	if semantic.calls != 0 {
		t.Fatalf("policy was evaluated %d times: the refusal must come before any policy state is reserved", semantic.calls)
	}
	if hardware.calls != 0 || router.calls != 0 {
		t.Fatalf("token used %d times, routing asked %d times: a refused operation does no work", hardware.calls, router.calls)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" || recorder.drafts[0].Outcome != "collector-not-configured" {
		t.Fatalf("audit events = %#v: the refusal is recorded and named", recorder.drafts)
	}
}

// THE OUTAGE IS NOT A REFUSAL: the collector is CONFIGURED (the gate is up, the sink is built),
// and a stateful operation serves as it does under multi-node. Whether the sink can reach the
// collector right now is the shipper's problem — it ships later, and the backlog alerts.
func TestASingleNodeWithACollectorServesAStatefulOperation(t *testing.T) {
	coordinator, semantic, recorder, hardware, _ := collectorFixture(t, admission.ModeSingle, true)
	result, err := coordinator.Execute(context.Background(), operationRequest())
	if err != nil {
		t.Fatalf("a configured-but-silent collector refuses the operation: %v (an outage alerts, it does not refuse)", err)
	}
	wantServed(t, hardware, recorder, result, err)
	if semantic.calls != 1 {
		t.Fatalf("policy evaluated %d times, want 1", semantic.calls)
	}
}

// STATELESS STAYS SERVED: the same configuration refuses the stateful half, and a sign — which
// reserves no policy or opstate state — still does its work.
func TestASingleNodeWithNoCollectorStillServesStateless(t *testing.T) {
	coordinator, _, _, hardware, _ := collectorFixture(t, admission.ModeSingle, false)
	coordinator.SetStatelessOperations([]string{"sign"})
	result, err := coordinator.Execute(context.Background(), signRequest())
	wantServed(t, hardware, nil, result, err)
}

// MULTI-NODE IS UNCHANGED: no collector configured, a stateful operation serves, as it always
// has (the fleet's reconciliation and backlog alerts are its controls).
func TestAMultiNodeNodeWithoutACollectorIsUnchanged(t *testing.T) {
	coordinator, semantic, recorder, hardware, _ := collectorFixture(t, admission.ModeLease, false)
	result, err := coordinator.Execute(context.Background(), operationRequest())
	wantServed(t, hardware, recorder, result, err)
	if semantic.calls != 1 {
		t.Fatalf("policy evaluated %d times, want 1", semantic.calls)
	}
}

// No admission at all (no lease service configured) is the old path, whatever the profile:
// nothing refuses.
func TestNoAdmissionAtAllIsUnchanged(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-sitea"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("data-key")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Execute(context.Background(), operationRequest())
	wantServed(t, hardware, recorder, result, err)
}

func signRequest() api.Request {
	request := operationRequest()
	request.Operation = "sign"
	request.Format = ""
	request.Data = []byte("the digest")
	request.Context.Purpose = "sops-data-key"
	return request
}
