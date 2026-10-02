package operations

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type fakeAuthorizer struct {
	allowed bool
	digest  string
}

func (value fakeAuthorizer) Allowed(string, string, string, string) bool { return value.allowed }
func (value fakeAuthorizer) Digest() string {
	if value.digest != "" {
		return value.digest
	}
	return "sha256:rbac"
}

type fakeRouter struct {
	route registry.Route
	calls int
	// askedKEKVersion records what RouteForUnwrap was asked to resolve. A double that ignored the
	// version would let every release test pass while the coordinator sent a constant, which is
	// the defect this field exists to make visible.
	askedKEKVersion string
	unwrapErr       error
	// routeErr drives the default Route path's failure branch. Nil for every existing test.
	routeErr error
}

func (value *fakeRouter) Route(context.Context, string, string, string) (registry.Route, error) {
	value.calls++
	if value.routeErr != nil {
		return registry.Route{}, value.routeErr
	}
	return value.route, nil
}
func (value *fakeRouter) RouteForSeal(_ context.Context, _, _ string) (registry.Route, error) {
	value.calls++
	return value.route, nil
}
func (value *fakeRouter) RouteForUnwrap(_ context.Context, _, _, kekVersion string) (registry.Route, error) {
	value.calls++
	value.askedKEKVersion = kekVersion
	if value.unwrapErr != nil {
		return registry.Route{}, value.unwrapErr
	}
	return value.route, nil
}
func (*fakeRouter) Digest() string { return "sha256:registry" }

type fakePolicy struct {
	decision    policy.Decision
	calls       int
	lastRequest policy.Request
}

func (value *fakePolicy) Evaluate(_ context.Context, request policy.Request) policy.Decision {
	value.calls++
	value.lastRequest = request
	return value.decision
}

type fakeAudit struct {
	drafts []audit.Draft
	err    error
}

func (value *fakeAudit) Record(_ context.Context, draft audit.Draft, requireRemote bool) error {
	value.drafts = append(value.drafts, draft)
	return value.err
}

type directRunner struct{}

func (directRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	return operation(ctx)
}

type fakeHardware struct {
	calls  int
	data   []byte
	output []byte
	err    error
}

func (value *fakeHardware) Execute(_ context.Context, _ registry.Route, _ string, _ string, _ string, data, _ []byte) ([]byte, string, error) {
	value.calls++
	value.data = append(value.data[:0], data...)
	return append([]byte(nil), value.output...), "application/octet-stream", value.err
}

func operationRequest() api.Request {
	return api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000001",
		Principal: "spiffe://regalia/workload/sops-prod", ObjectID: "production-sops", Operation: "unwrap",
		Context: api.OperationContext{Environment: "production", Purpose: "sops-data-key", ExpiresAt: time.Now().Add(time.Minute), Nonce: "018f0000000070008000000000000001"},
		Format:  "regalia-envelope-v2", Data: []byte("wrapped"),
	}
}

func TestCoordinatorExecutesOnlyAfterAuthorizationPolicyAndPreAudit(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("data-key")}
	coordinator, coordErr := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	result, err := coordinator.Execute(context.Background(), operationRequest())
	if err != nil || string(result.Data) != "data-key" || hardware.calls != 1 || semantic.calls != 1 || router.calls != 1 {
		t.Fatalf("Execute() = %#v, %v; calls hardware=%d policy=%d route=%d", result, err, hardware.calls, semantic.calls, router.calls)
	}
	if len(recorder.drafts) != 2 || recorder.drafts[0].Outcome != "authorized" || recorder.drafts[1].Outcome != "success" {
		t.Fatalf("audit events = %#v", recorder.drafts)
	}
}

func TestCoordinatorDenialAndAuditFailureNeverReachHardware(t *testing.T) {
	for name, test := range map[string]struct {
		allowed  bool
		auditErr error
	}{
		"RBAC denial":       {allowed: false},
		"audit unavailable": {allowed: true, auditErr: audit.ErrSinkUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
			hardware := &fakeHardware{output: []byte("must-not-escape")}
			coordinator, coordErr := New(fakeAuthorizer{allowed: test.allowed}, router, &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}, &fakeAudit{err: test.auditErr}, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if coordErr != nil {
				t.Fatal(coordErr)
			}
			result, err := coordinator.Execute(context.Background(), operationRequest())
			if err == nil || result.Data != nil || hardware.calls != 0 {
				t.Fatalf("Execute() = %#v, %v; hardware calls=%d", result, err, hardware.calls)
			}
		})
	}
}

func TestCoordinatorHardwareFailureReturnsNoOutput(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	hardware := &fakeHardware{output: []byte("must-not-escape"), err: errors.New("PIN 123456 failed")}
	coordinator, coordErr := New(fakeAuthorizer{allowed: true}, router, &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}, &fakeAudit{}, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	result, err := coordinator.Execute(context.Background(), operationRequest())
	if err == nil || result.Data != nil || err.Error() != "KMS operation failed" {
		t.Fatalf("Execute() = %#v, %q", result, err)
	}
}

// TestCoordinatorAuditDraftCarriesAuthorizerDigest pins the wiring: every audit
// draft emitted from Coordinator.record carries the RBAC digest of the authorizer
// in effect when the decision was made. Without this, the journal answers
// "who signed?" but not "under what policy?" — and the latter is what an
// operator reads first when reviewing an incident.
//
// Delete-fix scenario: drop RBACDigest from record(). The captured draft has
// RBACDigest == ""; this test fails with the DEFECT message below.
func TestCoordinatorAuditDraftCarriesAuthorizerDigest(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("data-key")}
	const want = "sha256:authorizer-v1"
	coordinator, coordErr := New(fakeAuthorizer{allowed: true, digest: want}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	if _, err := coordinator.Execute(context.Background(), operationRequest()); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if len(recorder.drafts) == 0 {
		t.Fatal("no audit drafts recorded")
	}
	for _, draft := range recorder.drafts {
		if draft.RBACDigest != want {
			t.Fatalf("DEFECT: audit draft RBACDigest = %q, want %q — Coordinator dropped the authorizer digest", draft.RBACDigest, want)
		}
	}
}

// TestCoordinatorDenialAuditDraftCarriesAuthorizerDigest pins the negative
// path: the deny branch records BEFORE returning, and that draft must also
// carry the digest. An audit trail that omits the digest on denials is
// exactly the trail the operator cannot defend — denials are the events
// a reviewer reads first.
//
// Delete-fix scenario: same as the allow test; the deny draft would also be
// missing the digest. Verify this test fails on the same DEFECT message.
func TestCoordinatorDenialAuditDraftCarriesAuthorizerDigest(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	const want = "sha256:authorizer-v2"
	coordinator, coordErr := New(fakeAuthorizer{allowed: false, digest: want}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	if _, err := coordinator.Execute(context.Background(), operationRequest()); err == nil {
		t.Fatal("denied Execute() returned no error")
	}
	if len(recorder.drafts) == 0 || recorder.drafts[0].Decision != "deny" {
		t.Fatalf("expected a deny draft, got %#v", recorder.drafts)
	}
	if recorder.drafts[0].RBACDigest != want {
		t.Fatalf("DEFECT: deny audit draft RBACDigest = %q, want %q", recorder.drafts[0].RBACDigest, want)
	}
}

// TestCoordinatorAuditDraftDigestChangesWhenAuthorizerDigestChanges pins
// the opposite direction: a different RBAC policy must produce a different
// digest in the audit draft. A regression that hard-codes the digest
// (passes through "sha256:rbac" from a struct field regardless of the
// authorizer) would pass the previous tests and fail here.
//
// Delete-fix scenario: assign authorizerDigest from a constant in
// Coordinator.New. Two coordinators with different Digest() methods produce
// the same captured value; this test fails on "digests should differ".
func TestCoordinatorAuditDraftDigestChangesWhenAuthorizerDigestChanges(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}
	hardware := &fakeHardware{output: []byte("data-key")}

	first := &fakeAudit{}
	coordFirst, coordErrFirst := New(fakeAuthorizer{allowed: true, digest: "sha256:policy-v1"}, router, semantic, first, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErrFirst != nil {
		t.Fatal(coordErrFirst)
	}
	if _, err := coordFirst.Execute(context.Background(), operationRequest()); err != nil {
		t.Fatalf("first Execute() = %v", err)
	}

	second := &fakeAudit{}
	coordSecond, coordErrSecond := New(fakeAuthorizer{allowed: true, digest: "sha256:policy-v2"}, router, semantic, second, directRunner{}, &fakeHardware{output: []byte("data-key")}, "sha256:policy", nil, time.Now)
	if coordErrSecond != nil {
		t.Fatal(coordErrSecond)
	}
	if _, err := coordSecond.Execute(context.Background(), operationRequest()); err != nil {
		t.Fatalf("second Execute() = %v", err)
	}

	if len(first.drafts) == 0 || len(second.drafts) == 0 {
		t.Fatal("expected drafts in both runs")
	}
	if first.drafts[0].RBACDigest == second.drafts[0].RBACDigest {
		t.Fatalf("DEFECT: audit draft RBACDigest does not change when authorizer digest changes: both = %q", first.drafts[0].RBACDigest)
	}
	if first.drafts[0].RBACDigest != "sha256:policy-v1" || second.drafts[0].RBACDigest != "sha256:policy-v2" {
		t.Fatalf("digests do not match the authorizers: first=%q second=%q", first.drafts[0].RBACDigest, second.drafts[0].RBACDigest)
	}
}

// TestCoordinatorRefusesAuthorizerWithEmptyDigest pins the loud-fail posture:
// a policy without a digest cannot be used to make authorization decisions.
// A blank digest would land as RBACDigest == "" in every audit draft, which
// validateDraft already refuses. The check now happens at New() — the daemon
// fails to start rather than to serve the first request. Execute() still
// defends against the same condition for any future code path that bypasses
// New() (e.g., a Coordinator built by reflection in a test fixture).
func TestCoordinatorRefusesAuthorizerWithEmptyDigest(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	// digest is unset -> fakeAuthorizer returns "sha256:rbac"; override with a custom fake.
	authorizer := emptyDigestAuthorizer{}
	coordinator, coordErr := New(authorizer, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if coordErr == nil {
		t.Fatal("DEFECT: New() with empty authorizer digest returned no error — daemon would start with a digest-less authorizer and silently stamp RBACDigest == \"\" on every audit")
	}
	if coordinator != nil {
		t.Fatalf("New() returned a Coordinator alongside the empty-digest error: %+v", coordinator)
	}
}

type emptyDigestAuthorizer struct{}

func (emptyDigestAuthorizer) Allowed(string, string, string, string) bool { return true }
func (emptyDigestAuthorizer) Digest() string                              { return "" }

// A DENIAL MUST SAY WHICH RULE, NOT ONLY THAT POLICY SAID NO.
//
// The audit reason was "policy-" plus the decision CODE, so denials from unknown-object,
// invalid-context, purpose-mismatch and every other rule collapsed into a single "policy-DENIED".
// Decision.Rule names the rule that fired, is set at every decision site in the engine, and was read
// at none — the answer existed and was discarded one line before it would have been recorded.
//
// Found by the carrier-field detector, not by reading.
func TestPolicyDenialRecordsWhichRuleFired(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	recorder := &fakeAudit{}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: false, Code: policy.CodeDenied, PolicyID: "sops", Rule: "purpose-mismatch"}}

	coordinator, err := New(fakeAuthorizer{allowed: true, digest: "sha256:rbac"}, router, semantic, recorder, directRunner{}, &fakeHardware{output: []byte("x")}, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), operationRequest()); err == nil {
		t.Fatal("a denied operation succeeded")
	}
	if len(recorder.drafts) == 0 {
		t.Fatal("the denial recorded no audit draft")
	}
	for _, draft := range recorder.drafts {
		if !strings.Contains(draft.Outcome, "purpose-mismatch") {
			t.Fatalf("DEFECT: the audit outcome is %q and does not name the rule that fired: a reviewer cannot tell this denial from any other policy denial", draft.Outcome)
		}
		if !strings.Contains(draft.Outcome, string(policy.CodeDenied)) {
			t.Fatalf("the audit outcome %q dropped the decision code, which is the stable value clients match on", draft.Outcome)
		}
	}
}

// THE REAL ENGINE, NOT A FAKE DECISION. The test above proves the coordinator copies whatever rule
// it is handed; this one proves the engine hands it the DIMENSION, end to end from sign bytes to
// audit outcome: a transfer to a destination the policy does not list is recorded as
// policy-DENIED:cosmos-destination, one over the fee cap as policy-DENIED:cosmos-fee.
//
// The sign bytes are the cosmpy-generated reference SignDoc (internal/policy/testdata), never an
// encoder written here; each arm changes the POLICY around the same transaction.
func TestACosmosDenialIsAuditedUnderTheDimensionThatRefusedIt(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil || len(transaction.Messages) != 1 || len(transaction.Messages[0].Amounts) != 1 || len(transaction.Fee) != 1 {
		t.Fatalf("the reference SignDoc is not one MsgSend of one coin with one fee coin: %#v %v", transaction, err)
	}
	message, fee := transaction.Messages[0], transaction.Fee[0]
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	// The policy that admits exactly this transaction; each arm then breaks one dimension of it.
	admitting := func() *policy.CosmosPolicy {
		return &policy.CosmosPolicy{ChainIDs: []string{transaction.ChainID}, AccountNumbers: []uint64{transaction.AccountNumber},
			MessageTypes: []string{message.Type}, Sources: []string{message.Source}, Destinations: []string{message.Destination},
			MaxGasLimit: transaction.GasLimit, MaxFee: map[string]uint64{fee.Denom: fee.Amount},
			MaxPerTransaction: map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount},
			MaxPerDay:         map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount}}
	}
	for name, test := range map[string]struct {
		breakIt func(*policy.CosmosPolicy)
		outcome string
		signed  bool
	}{
		"the policy admits it":             {func(*policy.CosmosPolicy) {}, "success", true},
		"a destination outside the policy": {func(p *policy.CosmosPolicy) { p.Destinations = []string{"akash1someoneelse"} }, "policy-DENIED:" + policy.RuleCosmosDestination, false},
		"a fee over the cap":               {func(p *policy.CosmosPolicy) { p.MaxFee[fee.Denom] = fee.Amount - 1 }, "policy-DENIED:" + policy.RuleCosmosFee, false},
		"a gas limit over the cap":         {func(p *policy.CosmosPolicy) { p.MaxGasLimit = transaction.GasLimit - 1 }, "policy-DENIED:" + policy.RuleCosmosGas, false},
		"another chain":                    {func(p *policy.CosmosPolicy) { p.ChainIDs = []string{"cosmoshub-4"} }, "policy-DENIED:" + policy.RuleCosmosChain, false},
	} {
		t.Run(name, func(t *testing.T) {
			cosmos := admitting()
			test.breakIt(cosmos)
			engine, err := policy.New([]policy.Policy{{
				ID: "wallet", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
				Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
				MaxPayloadBytes: 10000, MaxFuture: time.Minute, Cosmos: cosmos,
			}}, bridgeReservationState{}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "secp256k1", PolicyID: "wallet", Binding: registry.Binding{DeviceID: "hsm-1"}}}
			recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("signature")}
			coordinator, err := New(fakeAuthorizer{allowed: true, digest: "sha256:rbac"}, router, engine, recorder, directRunner{}, hardware, "sha256:policy", nil, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			request := operationRequest()
			request.Operation, request.Format, request.ContentType, request.Data = "sign", "", "application/vnd.cosmos.tx+protobuf", signDoc
			request.Context.ExpiresAt = now.Add(30 * time.Second)
			_, err = coordinator.Execute(context.Background(), request)
			if signed := err == nil; signed != test.signed || (hardware.calls != 0) != test.signed {
				t.Fatalf("signed=%v (token calls %d), want signed=%v: %v", signed, hardware.calls, test.signed, err)
			}
			if len(recorder.drafts) == 0 || recorder.drafts[len(recorder.drafts)-1].Outcome != test.outcome {
				t.Fatalf("audit drafts = %#v, want the last outcome to be %q", recorder.drafts, test.outcome)
			}
		})
	}
}
