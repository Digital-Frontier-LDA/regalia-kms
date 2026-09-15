package operations

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE SECOND DEPENDENCY CHAIN WAS THE UNTESTED ONE, AND IT IS THE ONE ON THE REQUEST PATH.
//
// New and Execute check the same dependencies. The 2026-09-08 sweep of internal/operations
// separated them completely:
//
//	New's guard      8 operands   8 KILLED
//	Execute's guard  10 operands  1 KILLED (coordinator == nil), 9 SURVIVOR
//
// Not chance. Tests get written against the layer where a bug was once found, and a defensive
// second chain has by definition never had a bug found in it — so the first chain is covered
// BECAUSE it failed once, and the second is uncovered BECAUSE it never has.
//
// The duplication is deliberate; New's own comment says it guards "a future code path that
// builds a Coordinator some other way". This is that code path, exercised: Coordinator's fields
// are unexported, so only an in-package literal can produce a nil one, which New never will and
// this test trivially does.
//
// Each row is what an operator gets instead of the refusal: a nil interface method call on the
// request path. `authorizer` dereferences one line later at Allowed(); the rest follow.
func TestExecuteRefusesAnIncompleteCoordinatorRatherThanDereferencingIt(t *testing.T) {
	// complete returns a Coordinator with every field populated, built the way a future
	// constructor would build one. Each row below zeroes exactly one field of it.
	complete := func() *Coordinator {
		return &Coordinator{
			authorizer:       fakeAuthorizer{allowed: true, digest: "sha256:rbac"},
			router:           &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}},
			policy:           &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
			audit:            &fakeAudit{},
			runner:           directRunner{},
			hardware:         &fakeHardware{output: []byte("unwrapped")},
			policyDigest:     "sha256:policy",
			authorizerDigest: "sha256:rbac",
			now:              time.Now,
		}
	}

	for _, testCase := range []struct {
		field  string
		zeroed func(*Coordinator)
	}{
		{"authorizer", func(c *Coordinator) { c.authorizer = nil }},
		{"router", func(c *Coordinator) { c.router = nil }},
		{"policy", func(c *Coordinator) { c.policy = nil }},
		{"audit", func(c *Coordinator) { c.audit = nil }},
		{"runner", func(c *Coordinator) { c.runner = nil }},
		{"hardware", func(c *Coordinator) { c.hardware = nil }},
		{"now", func(c *Coordinator) { c.now = nil }},
		{"policyDigest", func(c *Coordinator) { c.policyDigest = "" }},
		{"authorizerDigest", func(c *Coordinator) { c.authorizerDigest = "" }},
	} {
		t.Run("a coordinator whose "+testCase.field+" is missing", func(t *testing.T) {
			coordinator := complete()
			testCase.zeroed(coordinator)

			// A panic here is the defect, not a test error: without the guard the request path
			// dereferences the missing dependency. Recover so the row reports WHICH field, rather
			// than aborting the binary and truncating every row after it.
			var result api.Result
			var err error
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("DEFECT: Execute panicked (%v) on a coordinator with no %s — the guard at "+
							"Execute's dependency guard is what turns a missing dependency into a 503; without it the "+
							"daemon dereferences it on the request path", recovered, testCase.field)
					}
				}()
				result, err = coordinator.Execute(context.Background(), operationRequest())
			}()

			var failure *api.Failure
			if !errors.As(err, &failure) {
				t.Fatalf("DEFECT: Execute with no %s returned (%+v, %v) — an incomplete coordinator "+
					"served the request instead of refusing it", testCase.field, result, err)
			}
			if failure.Code != "DEPENDENCY_UNAVAILABLE" || failure.Status != http.StatusServiceUnavailable {
				t.Fatalf("Execute with no %s = %q/%d, want DEPENDENCY_UNAVAILABLE/503 — the operator must "+
					"learn the daemon is misconfigured, not that the operation failed",
					testCase.field, failure.Code, failure.Status)
			}
			if !failure.Retryable {
				t.Fatalf("Execute with no %s reported a non-retryable failure — a missing dependency is "+
					"restored by fixing the daemon, and the caller should be told to try again", testCase.field)
			}
		})
	}

	// ANCHOR, not a gate. Without this row every refusal above is compatible with "an in-package
	// struct literal cannot serve a request at all", which would make the nine rows prove nothing
	// about the operands they name.
	t.Run("the same literal with every field present is served", func(t *testing.T) {
		if _, err := complete().Execute(context.Background(), operationRequest()); err != nil {
			t.Fatalf("a fully populated Coordinator literal = %v, want it to serve — the rows above "+
				"would then be refusing the construction rather than the missing field", err)
		}
	})
}

// THE PAYLOAD CAP STOPS GOVERNING SEALS IF ONE DISPATCH LOSES ITS SEAL ARM.
//
// payloadBytes is not a refusal guard — it is a branch choosing a number:
//
//	if request.Operation == "seal-envelope" { return len(SealCiphertext) }
//	return len(Data)
//
// Its result becomes policy.Request.PayloadBytes, which policy.Evaluate caps against
// MaxPayloadBytes. A seal carries NO Data, so with the seal arm gone every seal reports 0 and
// the cap silently stops applying to seal-envelope entirely. Nothing else measures those bytes.
//
// The sweep found this operand surviving in BOTH directions — the only one of 256 operand-
// directions in operations+api to do so, meaning no test drives either arm of the dispatch.
// It is worth naming as a class: a DISPATCH operand whose output feeds a guard in another
// package. It looks inert in a survivor list — no refusal, no error, just a branch picking a
// number — and the guard it disarms is elsewhere.
func TestThePolicyCapIsMeasuredOnTheBytesThatActuallyArrived(t *testing.T) {
	route := sealRoute()
	router := &fakeRouter{route: route}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, &fakeAudit{}, directRunner{},
		&fakeHardware{output: []byte("wrapped-by-the-card")}, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))
	// The fixture is only meaningful if the two candidate measurements differ. A seal carries no
	// Data, so len(Data) is 0 and len(SealCiphertext) is not — assert that rather than assume it,
	// because a ciphertext that happened to be empty would make both arms agree and the row pass
	// with the operand deleted.
	request := sealRequest(route, ciphertext, nonce, dataKey)
	if len(request.Data) != 0 {
		t.Fatalf("fixture: a seal request carries %d bytes of Data, want none — the two arms of the "+
			"dispatch would not be distinguishable", len(request.Data))
	}
	if len(request.SealCiphertext) == 0 {
		t.Fatalf("fixture: the seal ciphertext is empty, so both arms of the dispatch measure 0 and " +
			"this row cannot detect the seal arm being lost")
	}
	wantBytes := int64(len(request.SealCiphertext))

	if _, err := coordinator.Execute(context.Background(), request); err != nil {
		t.Fatalf("seal-envelope = %v", err)
	}
	if semantic.calls != 1 {
		t.Fatalf("policy consulted %d times, want 1", semantic.calls)
	}
	if semantic.lastRequest.PayloadBytes != wantBytes {
		t.Fatalf("DEFECT: policy was asked to cap %d bytes for a seal carrying %d bytes of ciphertext. "+
			"A seal has no Data, so measuring Data reports 0 and MaxPayloadBytes stops governing "+
			"seal-envelope entirely — nothing else measures these bytes",
			semantic.lastRequest.PayloadBytes, wantBytes)
	}

	// The other arm, so this pins a dispatch rather than one branch of it. An operation that is
	// not a seal must be measured on Data — swapping the arms would satisfy the row above alone.
	plain := operationRequest()
	semantic.calls = 0
	if _, err := coordinator.Execute(context.Background(), plain); err != nil {
		t.Fatalf("unwrap = %v", err)
	}
	if semantic.lastRequest.PayloadBytes != int64(len(plain.Data)) {
		t.Fatalf("DEFECT: policy was asked to cap %d bytes for a non-seal carrying %d bytes of Data — "+
			"the cap must measure the payload that arrived",
			semantic.lastRequest.PayloadBytes, len(plain.Data))
	}
}
