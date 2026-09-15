package operations

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// SECOND ROUND OF THE SAME SWEEP THAT PRODUCED guard_coverage_test.go, AND THE SAME RULES APPLY.
//
// Both guards below were mutated away on main and the whole module stayed green, so each comment
// records what the SAME fixture was observed to do with the guard gone. The helpers here reuse
// guardRoute, sealRoute, assembleSealInputs, sealRequest, fakeAuthorizer, fakeRouter, fakePolicy,
// fakeAudit, fakeHardware and directRunner from the files already in this package rather than
// restating them.
//
// Both guards refuse a construction that would otherwise DEREFERENCE A NIL: one in New, one in
// seal. A panic is not a refusal -- it is fail-unpredictable where the whole daemon is designed
// to be fail-closed -- so every case here recovers deliberately. An unrecovered panic takes the
// test binary down with it, which would make "this test is the only detector" unmeasurable: the
// run stops before the other cases report.

// round2Deps is New's argument list as a value, so a table row can remove exactly one entry and
// nothing else. Building the arguments positionally at each call site instead would make a row
// that drops the auditor look identical to one that drops the runner.
type round2Deps struct {
	authorizer   Authorizer
	router       Router
	semantic     Policy
	recorder     Auditor
	runner       Runner
	hardware     Hardware
	policyDigest string
	now          func() time.Time
}

// round2CompleteDeps is a set New accepts. Every row below is this set minus one operand, which
// is what makes the refusal attributable to that operand: the ANCHOR row proves the untouched set
// really does construct and really does serve a request.
func round2CompleteDeps() round2Deps {
	return round2Deps{
		authorizer:   fakeAuthorizer{allowed: true},
		router:       &fakeRouter{route: guardRoute()},
		semantic:     &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		recorder:     &fakeAudit{},
		runner:       directRunner{},
		hardware:     &fakeHardware{output: []byte("data-key")},
		policyDigest: "sha256:policy",
		now:          time.Now,
	}
}

// round2Construct calls New and reports a panic as a value instead of letting it escape. The
// nil-authorizer row panics inside New once the guard is gone, and a panic that reaches the
// runtime kills the binary for every other row in the table too.
func round2Construct(deps round2Deps) (coordinator *Coordinator, err error, panicked any) {
	defer func() { panicked = recover() }()
	coordinator, err = New(deps.authorizer, deps.router, deps.semantic, deps.recorder,
		deps.runner, deps.hardware, deps.policyDigest, nil, deps.now)
	return coordinator, err, nil
}

// A MISWIRED DAEMON MUST FAIL AT STARTUP, NOT SEGFAULT AND NOT START.
//
// New's own doc comment makes the argument: it "returns an error (not a panic) when any required
// dependency is nil or the authorizer reports an empty digest", because "a panic would be
// fail-unpredictable, while a returned error is fail-closed and the daemon's usual startup path
// will surface it". Nothing measured that claim. Every caller in the module -- main.go's wiring
// and three internal/integration tests -- hands New a complete set, so the guard's entire
// population of inputs was unexercised, and TestCoordinatorRefusesAuthorizerWithEmptyDigest
// covers only the SEPARATE digest check one line below it.
//
// WITHOUT the guard, this exact table splits into two different disasters:
//
//   - THE nil AUTHORIZER, which is why that row is written out on its own and not folded into a
//     loop over interchangeable operands. New(nil, nil, nil, nil, nil, nil, "sha256:policy", nil,
//     time.Now) was observed to produce `panic: runtime error: invalid memory address or nil
//     pointer dereference` / `[signal SIGSEGV: segmentation violation code=0x2 addr=0x20]` raised
//     inside New itself, at the `digest := authorizer.Digest()` line -- the exact line the guard's
//     doc comment says it exists to protect. Pristine, the same call returns
//     `coordinator=<nil> err=operations: required dependency is missing`.
//
//   - EVERY OTHER OPERAND, e.g. a complete set whose policyDigest is "": observed
//     `coordinator!=nil=true err=<nil>`. New hands back a *Coordinator that looks usable, main.go
//     starts a daemon on it, and the dependency check at the head of Execute then answers every
//     request for the life of the process: `code="DEPENDENCY_UNAVAILABLE" status=503 data=0
//     bytes`. A configuration error that should have failed the deploy becomes a running service
//     that serves nothing.
//
// ALL EIGHT OPERANDS SHARE ONE MESSAGE, DELIBERATELY. New returns
// errors.New("operations: required dependency is missing") whichever operand is missing -- which
// dependency is nil is the operator's problem and not a distinction the constructor draws -- so
// the message is asserted exactly and the ROW is what names the operand under test.
func TestNewRefusesEveryMissingDependencyRatherThanPanicking(t *testing.T) {
	const wantMessage = "operations: required dependency is missing"

	for _, missing := range []struct {
		what   string
		remove func(*round2Deps)
		anchor bool
	}{
		// This row is the SIGSEGV one. It stays first and stays separate: it is the only operand
		// whose absence is dereferenced by the very next statement in New.
		{what: "the authorizer is nil, and New reads its digest on the next line", remove: func(deps *round2Deps) { deps.authorizer = nil }},
		{what: "the router is nil", remove: func(deps *round2Deps) { deps.router = nil }},
		{what: "the policy engine is nil", remove: func(deps *round2Deps) { deps.semantic = nil }},
		{what: "the auditor is nil", remove: func(deps *round2Deps) { deps.recorder = nil }},
		{what: "the runner is nil", remove: func(deps *round2Deps) { deps.runner = nil }},
		{what: "the hardware is nil", remove: func(deps *round2Deps) { deps.hardware = nil }},
		{what: "the clock is nil", remove: func(deps *round2Deps) { deps.now = nil }},
		{what: "the policy digest is empty", remove: func(deps *round2Deps) { deps.policyDigest = "" }},
		// ANCHOR, deliberately last (TESTING.md 18): the same set with nothing removed constructs
		// AND serves. Without it every refusal above is equally consistent with a fixture New
		// would reject for some reason that has nothing to do with the operand the row removed --
		// a fake that does not satisfy the interface it is standing in for, a digest the second
		// check rejects -- and the test would pin the fixture rather than the guard.
		{what: "ANCHOR: nothing is missing", remove: func(*round2Deps) {}, anchor: true},
	} {
		t.Run(missing.what, func(t *testing.T) {
			deps := round2CompleteDeps()
			missing.remove(&deps)

			coordinator, err, panicked := round2Construct(deps)

			if panicked != nil {
				t.Fatalf("DEFECT: New() panicked (%v) when %s: the constructor's contract is a returned error, and a panic here takes down whatever goroutine is wiring the daemon instead of failing the startup path that would have reported it",
					panicked, missing.what)
			}

			if missing.anchor {
				if err != nil || coordinator == nil {
					t.Fatalf("ANCHOR: New() with a complete set = %v, %v -- the fixture itself is unacceptable to New, so every refusal above is attributable to the fixture and not to the operand the row removed", coordinator, err)
				}
				// Constructed is not the same as usable: a Coordinator that refuses this request
				// would leave the rows above consistent with a set New tolerates and Execute does
				// not, which is precisely the failure the empty-policyDigest row is about.
				result, execErr := coordinator.Execute(context.Background(), operationRequest())
				if execErr != nil || string(result.Data) != "data-key" {
					t.Fatalf("ANCHOR: the coordinator built from the complete set answered %#v, %v for a plain unwrap", result, execErr)
				}
				return
			}

			if err == nil {
				t.Fatalf("DEFECT: New() returned no error when %s; it returned coordinator!=nil=%v. A daemon started on this coordinator answers DEPENDENCY_UNAVAILABLE/503 to every request instead of failing the deploy",
					missing.what, coordinator != nil)
			}
			if err.Error() != wantMessage {
				t.Fatalf("New() when %s = %q, want %q: some check other than the required-dependency guard refused this fixture, so the row is measuring a different guard",
					missing.what, err.Error(), wantMessage)
			}
			if coordinator != nil {
				t.Fatalf("DEFECT: New() when %s returned %#v alongside the refusal: a caller that logs the error and carries on holds a half-built Coordinator", missing.what, coordinator)
			}
		})
	}
}

// A SEAL WHOSE WRAPPER CANNOT BE BUILT MUST BE REFUSED BEFORE THE ENVELOPE IS ASSEMBLED.
//
// secrets.NewSealWrapper refuses a route that names no KEK algorithm, no KEK version, or no
// backend, and sealer.go argues at length why those refusals are worth making early: "The
// construction is the last point where the cause is still legible." When it refuses it returns
// (nil, error) -- and seal's `err != nil` check is the only thing standing between that nil
// envelope.Wrapper and envelope.SealAssembled.
//
// WITHOUT that check, this fixture -- a route carrying a real backend and KEK version but an
// EMPTY KEKAlgorithm, and genuine AES-GCM ciphertext over the server-derived contentAAD so
// nothing upstream refuses it -- was observed to produce `panic: runtime error: invalid memory
// address or nil pointer dereference` / `[signal SIGSEGV: segmentation violation code=0x2
// addr=0x28]` at envelope.SealAssembled, called from seal. The nil wrapper survives everything
// upstream of the dereference because envelope's own validateKeyRef guards its backend comparison
// with `if wrapper != nil && ...`; WrapKey is the first unguarded use. Pristine, the same request
// answers `err=KMS operation failed result.Data=0 bytes lastAuditOutcome="backend-failed"
// dataKeyZeroed=true hardwareCalls=0`.
//
// Under the directRunner these tests use that panic is a crashed test binary; in the daemon's
// wiring the recover in internal/executor converts it to INTERNAL/500. Either way a route the
// manifest never finished describing is reported as a fault in this daemon, which is the exact
// misdiagnosis sealer.go's comment says the early refusal exists to prevent.
//
// THE SEALER'S MESSAGE IS NOT ASSERTABLE FROM HERE, and that is not an oversight. seal returns
// the error verbatim, and Execute converts it into an *api.Failure whose Error() is the constant
// "KMS operation failed" and records the constant outcome "backend-failed" -- the wire response
// is not allowed to narrate why the daemon refused. What distinguishes this refusal from the
// panic, and from the other refusals on the seal path, is the {Code, Status, Retryable} triple,
// the audit outcome, the fact that the card was never asked, and the zeroed data key. Those are
// what the rows below pin.
func TestASealWhoseWrapperCannotBeBuiltIsRefusedBeforeTheEnvelopeIsAssembled(t *testing.T) {
	for _, broken := range []struct {
		what   string
		spoil  func(*registry.Route)
		anchor bool
	}{
		{what: "the route names no KEK algorithm", spoil: func(route *registry.Route) { route.KEKAlgorithm = "" }},
		{what: "the route names no KEK version", spoil: func(route *registry.Route) { route.KEKVersion = "" }},
		{what: "the route names no backend", spoil: func(route *registry.Route) { route.Binding.Backend = "" }},
		// ANCHOR, deliberately last (TESTING.md 18): the identical parts through a route that
		// names all three produce an envelope. It is what bounds the fixture -- ciphertext whose
		// AEAD tag did not verify, or a card that refused, would also be refused with an
		// api.Failure and would also leave the data key zeroed, and the rows above would then be
		// pinning some other refusal on the same path.
		{what: "ANCHOR: the route names all three", spoil: func(*registry.Route) {}, anchor: true},
	} {
		t.Run(broken.what, func(t *testing.T) {
			route := sealRoute()
			broken.spoil(&route)
			recorder := &fakeAudit{}
			hardware := &fakeHardware{output: []byte("wrapped-by-the-card")}
			coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: route},
				&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
				recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			// The spoiled fields are the KEK identity and the binding's backend; the object,
			// purpose and environment the content AAD is derived from are untouched, so the
			// client's ciphertext verifies in every row and no AEAD failure can be mistaken for
			// the refusal under test.
			ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))

			// Recovered on purpose. Without the guard this Execute panics inside SealAssembled,
			// and an escaping panic ends the whole binary -- the ANCHOR row below would never
			// run, and "this test is the only thing that detects the missing guard" could not be
			// measured at all.
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("DEFECT: seal-envelope panicked (%v) when %s: the nil wrapper NewSealWrapper returned alongside its error reached envelope.SealAssembled, so a route the manifest never finished describing is reported as a fault in this daemon instead of a legible refusal",
						recovered, broken.what)
				}
			}()
			result, execErr := coordinator.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey))

			// THE DETECTOR, NAMED BEFORE THE VERDICT IS BELIEVED (TESTING.md 19): the request got
			// past RBAC, routing, approvals and policy and was recorded as authorized, so the
			// refusal below came from inside seal. Every earlier refusal on this path writes a
			// single "deny" draft instead, and a status assertion alone would be satisfied by
			// several of them.
			if len(recorder.drafts) != 2 || recorder.drafts[0].Decision != "allow" || recorder.drafts[0].Outcome != "authorized" {
				t.Fatalf("audit drafts = %#v, want an authorized draft followed by the operation's outcome: this row was refused before seal ran, so whatever it asserts below is about an earlier guard", recorder.drafts)
			}
			outcome := recorder.drafts[1].Outcome

			if broken.anchor {
				if execErr != nil {
					t.Fatalf("ANCHOR: seal through a complete route = %v -- the parts are refused for their own reasons, so the rows above are not attributable to the missing KEK identity", execErr)
				}
				if hardware.calls != 1 {
					t.Fatalf("ANCHOR: hardware calls = %d, want exactly 1: a complete route must reach the card, or hardwareCalls==0 above measures nothing", hardware.calls)
				}
				if outcome != "success" || result.ContentType != "application/vnd.regalia.envelope" || len(result.Data) == 0 {
					t.Fatalf("ANCHOR: seal produced outcome %q and %#v, want a successful envelope", outcome, result)
				}
				return
			}

			if hardware.calls != 0 {
				t.Fatalf("DEFECT: hardware calls = %d when %s, want 0: the data key was handed to a card selected by a route that does not identify one", hardware.calls, broken.what)
			}
			if outcome != "backend-failed" {
				t.Fatalf("DEFECT: audit outcome = %q when %s, want \"backend-failed\": the trail is the only place an operator can see that this seal never reached a card", outcome, broken.what)
			}
			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("DEFECT: seal when %s = %#v, %v; want an *api.Failure -- the wrapper could not be built and the request was answered as though it could", broken.what, result, execErr)
			}
			if failed.Code != "BACKEND_UNAVAILABLE" || failed.Status != http.StatusServiceUnavailable || !failed.Retryable {
				t.Fatalf("seal when %s = {Code:%s Status:%d Retryable:%v}, want {BACKEND_UNAVAILABLE 503 true}: an INTERNAL/500 is what the recovered panic produces, and it tells the caller this daemon is broken rather than that the route it was given names no card",
					broken.what, failed.Code, failed.Status, failed.Retryable)
			}
			if result.Data != nil || result.OperationID != "" || result.ContentType != "" {
				t.Fatalf("DEFECT: a refused seal returned %#v", result)
			}
			// seal zeroes request.SealDataKey on this branch specifically, and the branch is the
			// guard body: the plaintext data key the caller handed over must not outlive a seal
			// that never happened.
			for index, b := range dataKey {
				if b != 0 {
					t.Fatalf("DEFECT: the caller's data key survived the refusal (byte %d = %#x when %s): the secret being wrapped is still in memory after an operation that produced no envelope to justify holding it", index, b, broken.what)
				}
			}
		})
	}
}
