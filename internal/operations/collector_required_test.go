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
// unwrap, certificate-sign — the set api.StatelessOperations names) keeps serving: it reserves
// nothing. The fixture mirrors the daemon's wiring (cmd/regalia-kms/main.go): the requirement is
// on by the mode, not the profile, and the stateless set is the daemon's own.
//
// The gate the coordinator is handed reports the mode through the admission package's own
// Status, so the refusal lives in the real shape of the answer.

// modeGate is an Admission that also reports the mode its answer was made under
// (ModeAdmission: admission.Status.Mode), the way the production gate does.
// SetSingleNodeCollectorRequirement accepts only a gate that reports its mode, so the fixture is
// the interface, not a superset of it.
type modeGate struct {
	ready bool
	mode  string
}

func (gate *modeGate) Ready(context.Context) bool  { return gate.ready }
func (gate *modeGate) Mode(context.Context) string { return gate.mode }

var _ ModeAdmission = (*modeGate)(nil)

// collectorFixture builds the coordinator the way the daemon does (New, admission runner over the
// executor on the same gate, RequireAdmission) and names the single-node collector requirement
// against the gate itself: the live mode its answer reports and whether the collector is
// configured. The daemon turns it on whenever a gate exists, whatever the mode reads (multi-node
// and no collector must keep serving), so the fixture does the same.
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
	coordinator.SetSingleNodeCollectorRequirement(gate, collectorConfigured)
	coordinator.SetStatelessOperations(api.StatelessOperations()...)
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
	if recorder == nil {
		return
	}
	last := recorder.drafts[len(recorder.drafts)-1]
	if last.Decision != "allow" || last.Outcome != "success" {
		t.Fatalf("audit events = %#v: a served operation is recorded as such", recorder.drafts)
	}
}

// THE REFUSAL: a single admission, no collector configured, a stateful operation — a wrap, the
// operation that reserves the spend-once nonce and quota the trail would record as spent. It is
// refused before policy is evaluated, so nothing is reserved: the nonce, the quota, the sequence —
// none is spent on work the node will not be able to prove it did. (The fixture's default request
// is an unwrap: the open of a spend already made at seal time, stateless by D2.)
func TestASingleNodeWithNoCollectorRefusesAStatefulOperationBeforePolicy(t *testing.T) {
	coordinator, semantic, recorder, hardware, router := collectorFixture(t, admission.ModeSingle, false)
	result, err := coordinator.Execute(context.Background(), statefulRequest())
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
	result, err := coordinator.Execute(context.Background(), statefulRequest())
	if err != nil {
		t.Fatalf("a configured-but-silent collector refuses the operation: %v (an outage alerts, it does not refuse)", err)
	}
	wantServed(t, hardware, recorder, result, err)
	if semantic.calls != 1 {
		t.Fatalf("policy evaluated %d times, want 1", semantic.calls)
	}
}

// THE SET IS THE DAEMON'S OWN, AND ITS COMPLEMENT CROSSES NO LINE: every operation the daemon
// names stateless (sign, unwrap, certificate-sign) is served under the refusal, and every
// operation it does not name is refused. One list, two sides, no drift: a name added to
// api.StatelessOperations that should stay refused (or removed that should be served) fails here,
// not in production.
func TestEveryOperationTheDaemonNamesStatelessIsServedUnderTheRefusal(t *testing.T) {
	for _, name := range api.StatelessOperations() {
		t.Run(name, func(t *testing.T) {
			coordinator, _, _, hardware, _ := collectorFixture(t, admission.ModeSingle, false)
			result, err := coordinator.Execute(context.Background(), statelessNamedRequest(name))
			wantServed(t, hardware, nil, result, err)
		})
	}
	for _, name := range []string{"wrap", "key-agreement", "release-secret", "seal-envelope"} {
		t.Run(name, func(t *testing.T) {
			coordinator, semantic, recorder, hardware, router := collectorFixture(t, admission.ModeSingle, false)
			result, err := coordinator.Execute(context.Background(), statelessNamedRequest(name))
			wantCollectorNotConfigured(t, result, err)
			if semantic.calls != 0 || hardware.calls != 0 || router.calls != 0 {
				t.Fatalf("a refused %s did work: policy %d, token %d, routing %d", name, semantic.calls, hardware.calls, router.calls)
			}
			if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" || recorder.drafts[0].Outcome != "collector-not-configured" {
				t.Fatalf("audit events = %#v: the refusal is recorded and named", recorder.drafts)
			}
		})
	}
}

// MULTI-NODE IS UNCHANGED: no collector configured, a stateful operation serves, as it always
// has (the fleet's reconciliation and backlog alerts are its controls).
func TestAMultiNodeNodeWithoutACollectorIsUnchanged(t *testing.T) {
	coordinator, semantic, recorder, hardware, _ := collectorFixture(t, admission.ModeLease, false)
	result, err := coordinator.Execute(context.Background(), statefulRequest())
	wantServed(t, hardware, recorder, result, err)
	if semantic.calls != 1 {
		t.Fatalf("policy evaluated %d times, want 1", semantic.calls)
	}
}

// THE REQUIREMENT FOLLOWS THE LIVE ADMISSION, NOT A READING OF IT AT STARTUP (regalia-kms-dx7.9).
// The lease service writes the admission file after the daemon has opened its gate (main.go
// names the ordering): a single node starts unadmitted, the first lease arrives later, and the
// requirement must be in force for the FIRST stateful operation it admits. A snapshot of the
// mode at startup would read "" (not single) and serve stateful operations with no collector
// for the life of the process. The same gate that stopped being admitted is refused
// "not-admitted" by the earlier check, never "collector-not-configured": the two refusals are
// distinct and both named.
func TestTheSingleNodeRequirementFollowsTheLiveAdmission(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-sitea"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("data-key")}
	// The node starts UNADMITTED, as a single node does before its lease service's first write.
	gate := &modeGate{ready: false, mode: ""}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder,
		admission.NewRunner(gate, directRunner{}), hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.RequireAdmission(gate)
	coordinator.SetSingleNodeCollectorRequirement(gate, false)
	coordinator.SetStatelessOperations(api.StatelessOperations()...)

	// Unadmitted: refused not-admitted, before the collector question.
	if result, err := coordinator.Execute(context.Background(), statefulRequest()); err == nil {
		t.Fatalf("Execute = %#v, nil: an unadmitted node serves nothing", result)
	} else if len(recorder.drafts) != 1 || recorder.drafts[0].Outcome != "not-admitted" {
		t.Fatalf("audit events = %#v: the unadmitted refusal is named", recorder.drafts)
	}
	// The lease service admits the node single. From THIS operation on, the stateful work is the
	// collector's: no collector configured, so it is refused collector-not-configured, and no
	// policy state is reserved.
	gate.ready, gate.mode = true, admission.ModeSingle
	result, err := coordinator.Execute(context.Background(), statefulRequest())
	wantCollectorNotConfigured(t, result, err)
	if semantic.calls != 0 {
		t.Fatalf("policy was evaluated %d times: the refusal must come before any policy state is reserved", semantic.calls)
	}
	if hardware.calls != 0 || router.calls != 0 {
		t.Fatalf("token used %d times, routing asked %d times: a refused operation does no work", hardware.calls, router.calls)
	}
	if len(recorder.drafts) != 2 || recorder.drafts[1].Decision != "deny" || recorder.drafts[1].Outcome != "collector-not-configured" {
		t.Fatalf("audit events = %#v: the live single admission is refused and named", recorder.drafts)
	}
	// A stateless operation is served under the same requirement: the refusal is for state, not
	// for the node.
	statelessResult, statelessErr := coordinator.Execute(context.Background(), statelessNamedRequest("sign"))
	wantServed(t, hardware, recorder, statelessResult, statelessErr)
	// And a node that STOPS being admitted is refused not-admitted again, not collector-not-configured:
	// the two refusals stay distinct.
	gate.ready = false
	recorder.drafts = recorder.drafts[:0]
	if result, err := coordinator.Execute(context.Background(), statefulRequest()); err == nil {
		t.Fatalf("Execute = %#v, nil: a node that stopped being admitted serves nothing", result)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Outcome != "not-admitted" {
		t.Fatalf("audit events = %#v: the lapse is not-admitted, a distinct refusal", recorder.drafts)
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

// statefulRequest is a wrap: the operation that reserves the spend-once nonce and quota (the
// data key the trail would record as spent). operationRequest is its complement, the unwrap of an
// already-spent seal.
// THE SIGN THAT CARRIES A COSMOS TRANSACTION IS THE STATEFUL ONE (regalia-kms-dx7.9 review
// finding 3, the D2 set narrowed the way the review's remedy allows). D2 is "every route that
// reserves policy or opstate state is refused" under a single-node admission with no collector,
// and the policy engine reserves on EVERY allowed evaluation — a nonce and a quota, and, for a
// Cosmos transaction, the account sequence. The daemon's stateless set names sign among the
// operations that keep serving, so the coordinator cannot tell a plain sign from the one that
// carries a Cosmos transaction by name alone: the POLICY says. A sign whose content is a Cosmos
// SignDoc under a policy that names a Cosmos section will reserve the sequence if allowed, so it
// is refused like the stateful set — before the reservation — and the plain sign keeps serving.
// unwrap and certificate-sign reserve only the nonce and quota the D2 set itself accepts without
// the collector; they are not refused.
func TestASingleNodeWithNoCollectorRefusesASignWithACosmosTransaction(t *testing.T) {
	coordinator, semantic, recorder, hardware, router := collectorFixture(t, admission.ModeSingle, false)
	semantic.cosmos = true // this object's sign policy names a Cosmos section: its content is a SignDoc
	result, err := coordinator.Execute(context.Background(), cosmosSignRequest())
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

// THE PLAIN SIGN KEEPS SERVING: the same refusal, the same node, a sign that carries a digest —
// no Cosmos section in its policy, no sequence to reserve. The D2 set's acceptance: a nonce and
// a quota are the spend the PA decided a node without the collector may still make.
func TestASingleNodeWithNoCollectorServesAPlainSign(t *testing.T) {
	coordinator, semantic, recorder, hardware, _ := collectorFixture(t, admission.ModeSingle, false)
	result, err := coordinator.Execute(context.Background(), statelessNamedRequest("sign"))
	wantServed(t, hardware, recorder, result, err)
	if semantic.calls != 1 {
		t.Fatalf("policy evaluated %d times, want 1", semantic.calls)
	}
}

// THE REQUIREMENT FOLLOWS THE POLICY'S OWN ANSWER, NOT A STATIC LIST: a policy that names no
// Cosmos section reserves no sequence, so a sign under it is not refused by the requirement — the
// plain sign serves (the fixture's route signs a digest); a sign that carries a Cosmos transaction
// under a policy that names a Cosmos section IS refused, before the reservation. The judgment is
// the engine's own (ReservesCosmosSequence), not a list of operation names.
func TestTheCosmosRefusalFollowsThePolicyAnswer(t *testing.T) {
	// A policy that names no Cosmos section: its plain sign is not refused and serves.
	coordinator, semantic, _, hardware, _ := collectorFixture(t, admission.ModeSingle, false)
	semantic.cosmos = false
	if result, err := coordinator.Execute(context.Background(), statelessNamedRequest("sign")); err != nil {
		t.Fatalf("a sign whose policy names no Cosmos section is refused by the requirement: %v", err)
	} else if string(result.Data) != "data-key" {
		t.Fatalf("the served sign returned %q", result.Data)
	}
	if hardware.calls != 1 {
		t.Fatalf("the token was used %d times, want 1", hardware.calls)
	}
	// A sign that carries a Cosmos transaction, under a policy that names a Cosmos section: refused.
	coordinator, semantic, recorder, hardware, router := collectorFixture(t, admission.ModeSingle, false)
	semantic.cosmos = true
	result, err := coordinator.Execute(context.Background(), cosmosSignRequest())
	wantCollectorNotConfigured(t, result, err)
	if semantic.calls != 0 || hardware.calls != 0 || router.calls != 0 {
		t.Fatalf("a refused sign did work: policy %d, token %d, routing %d", semantic.calls, hardware.calls, router.calls)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Outcome != "collector-not-configured" {
		t.Fatalf("audit events = %#v: the refusal is named", recorder.drafts)
	}
}

// cosmosSignRequest is a sign carrying the Cosmos content type: the ONE shape whose allowed
// evaluation reserves a Cosmos account sequence, under a policy that names a Cosmos section.
func cosmosSignRequest() api.Request {
	request := operationRequest()
	request.Operation = "sign"
	request.Format = ""
	request.Data = []byte("a cosmos SignDoc")
	request.ContentType = policy.CosmosSignDocContentType
	request.Context.Purpose = "sops-data-key"
	return request
}

func statefulRequest() api.Request {
	request := operationRequest()
	request.Operation = "wrap"
	request.Format = ""
	request.Data = []byte("the key to spend")
	request.Context.Purpose = "sops-data-key"
	return request
}

// statelessNamedRequest is the daemon's own stateless set, one request at a time: sign opens
// nothing, unwrap opens a spend already made at seal time, certificate-sign issues a certificate.
func statelessNamedRequest(name string) api.Request {
	request := operationRequest()
	request.Operation = name
	request.Format = ""
	if name == "sign" {
		request.Data = []byte("the digest")
	} else if name == "certificate-sign" {
		request.Data = []byte("the certificate request")
	}
	request.Context.Purpose = "sops-data-key"
	return request
}
