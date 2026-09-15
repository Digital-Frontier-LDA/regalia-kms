package operations

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// EVERY REFUSAL ON THIS PATH CARRIES THE SAME MESSAGE, SO NOTHING HERE ASSERTS ONE.
//
// api.Failure.Error() is the constant "KMS operation failed" for all of them, deliberately -- the
// wire response must not narrate why it refused. What separates one refusal from another is the
// triple {Code, Status, Retryable} the client acts on and the audit outcome the operator reads,
// so that is what every case below pins. A test in this file that checked only `err != nil` would
// be satisfied by all six guards it covers at once, and by a seventh nobody wrote.
//
// The guards here were named by a mutation sweep as reachable, load-bearing, and detected by no
// existing test. Each comment records what the SAME fixture observed with the guard mutated away,
// because that observed value -- not the guard's plausibility -- is the reason the test exists.

// guardRoute is a route as the default Route path returns one: a served binding for the
// production-sops object. Nothing in this file is testing routing, so it is the same route
// everywhere except in the seal cases, which need sealRoute's KEK identity.
func guardRoute() registry.Route {
	return registry.Route{
		ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"},
	}
}

// stagedAudit refuses the failOn'th Record call and remembers the decision/outcome of every call.
//
// fakeAudit cannot express this: its single err field refuses EVERY call, so the "authorized"
// draft is refused first and the operation never reaches the success record at all. A sink that
// goes down mid-operation -- the two drafts are milliseconds apart and both require the remote
// sink -- is the only fixture that reaches the guard these cases are about.
type stagedAudit struct {
	failOn   int // 1-based index of the Record call that fails; 0 means every call succeeds
	outcomes []string
	remote   []bool
}

func (sink *stagedAudit) Record(_ context.Context, draft audit.Draft, requireRemote bool) error {
	sink.outcomes = append(sink.outcomes, draft.Decision+"/"+draft.Outcome)
	sink.remote = append(sink.remote, requireRemote)
	if len(sink.outcomes) == sink.failOn {
		return audit.ErrSinkUnavailable
	}
	return nil
}

// A SUCCESS RECORD THE SINK REFUSED MUST NOT SHIP THE PLAINTEXT ANYWAY.
//
// Execute writes two drafts on the allow path: "authorized" before the operation runs and
// "success" after it produced output, both with requireRemote=true. The first refusal is already
// pinned (TestCoordinatorDenialAndAuditFailureNeverReachHardware, "audit unavailable"); the
// second was not, and it is the one that matters more, because by then the key material exists.
//
// WITHOUT the `err != nil` check on the "success" record, this exact fixture was observed to
// answer HTTP 200 carrying OperationID "0d842a06-733a-4657-a5b3-31b4242ab6ef", ContentType
// "application/octet-stream" and Data "the-unwrapped-data-key", with err = <nil>. The caller
// keeps the released key and the tamper-evident trail never learns the operation completed --
// a release that is invisible to the audit is exactly the event this daemon exists to make
// impossible. Every other failure on this path withholds output; a swallowed error here is the
// single place that hands it over.
func TestSuccessRecordFailureAfterAuthorizedRecordSucceedsStillWithholdsOutput(t *testing.T) {
	for _, stage := range []struct {
		what     string
		failOn   int
		wantCode string
	}{
		{"the sink goes down between the authorized draft and the success draft", 2, "DEPENDENCY_UNAVAILABLE"},
		// ANCHOR, deliberately last (TESTING.md 18): the identical fixture with a healthy sink
		// releases the bytes. Without it the refusal above is equally consistent with a
		// coordinator that refuses this request for some reason that has nothing to do with the
		// record -- a route it will not serve, a policy that says no, a card that returns nothing.
		{"ANCHOR: a sink that accepts both drafts releases the same bytes", 0, ""},
	} {
		t.Run(stage.what, func(t *testing.T) {
			sink := &stagedAudit{failOn: stage.failOn}
			hardware := &fakeHardware{output: []byte("the-unwrapped-data-key")}
			coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: guardRoute()},
				&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
				sink, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			result, execErr := coordinator.Execute(context.Background(), operationRequest())

			// THE DETECTOR, NAMED BEFORE THE VERDICT IS BELIEVED (TESTING.md 19). Both drafts were
			// offered, in order, so the refusal landed on the "success" record and not on the
			// "authorized" one, which has its own guard, its own return, and its own test.
			if got := strings.Join(sink.outcomes, " "); got != "allow/authorized allow/success" {
				t.Fatalf("audit drafts = %v, want [allow/authorized allow/success]: this case never reached the success record, so whatever it asserts below is about some other guard", sink.outcomes)
			}
			if len(sink.remote) != 2 || !sink.remote[0] || !sink.remote[1] {
				t.Fatalf("requireRemote per draft = %v, want [true true]: a success record the sink may drop locally is not the durable record this guard is protecting", sink.remote)
			}
			if hardware.calls != 1 {
				t.Fatalf("hardware calls = %d, want exactly 1: the card must have produced the output that is now being withheld, or there is nothing to withhold", hardware.calls)
			}

			if stage.wantCode == "" {
				if execErr != nil {
					t.Fatalf("ANCHOR: Execute() = %v with a sink that accepts both drafts -- the fixture is refused for its own reasons and the case above proves nothing", execErr)
				}
				if string(result.Data) != "the-unwrapped-data-key" || result.OperationID == "" || result.ContentType != "application/octet-stream" {
					t.Fatalf("ANCHOR: Execute() = %#v, want the unwrapped data key with an operation id", result)
				}
				return
			}

			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("DEFECT: Execute() = %#v, %v; want an api.Failure -- the operation whose durable success record the sink refused answered as though it had been recorded", result, execErr)
			}
			if failed.Code != stage.wantCode || failed.Status != http.StatusServiceUnavailable || !failed.Retryable {
				t.Fatalf("Execute() = {Code:%s Status:%d Retryable:%v}, want {%s 503 true}: a sink outage is a retryable dependency failure, and telling the caller anything else sends them to an operator instead of to a retry",
					failed.Code, failed.Status, failed.Retryable, stage.wantCode)
			}
			if result.Data != nil || result.OperationID != "" || result.ContentType != "" {
				t.Fatalf("DEFECT: Execute() returned %#v alongside the refusal: the released key escaped an operation whose success was never durably recorded", result)
			}
		})
	}
}

// A NIL COORDINATOR MUST ANSWER, NOT PANIC.
//
// main.go builds no Coordinator when settings.PKCS11ModulePath is empty -- config.go's
// hardwareFields check accepts 0 hardware fields as readily as 4, so the no-hardware mode is a
// supported configuration -- and the typed nil is handed to the handler anyway. The premise was
// measured, not assumed: for `var iface api.Coordinator = concrete` with a nil *Coordinator,
// `concrete == nil` is true while `iface == nil` is FALSE, so the nil check in api.Handler does
// not fire and the request arrives at this method with a nil receiver.
//
// WITHOUT the `coordinator == nil` clause at the head of Execute, this call was observed to
// produce `panic: runtime error: invalid memory address or nil pointer dereference` /
// `[signal SIGSEGV: segmentation violation code=0x2 addr=0x0]` inside Execute -- the very next
// clause of the same || chain dereferences the receiver to read coordinator.authorizer. The
// clause is not redundant with the rest of the chain: it is what makes the rest of the chain
// safe to evaluate. A panic in the request goroutine is fail-unpredictable; the guard turns it
// into the same fail-closed retryable 503 every other missing dependency produces.
func TestNilCoordinatorAnswers503RatherThanPanicking(t *testing.T) {
	var absent *Coordinator
	// The panic is caught here rather than left to crash the binary so that this test is the only
	// thing that goes red, and so the failure message names the guard instead of leaving a reader
	// with a stack trace and no test attribution.
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("DEFECT: Execute() on a nil *Coordinator panicked (%v) instead of refusing: a request that reaches the daemon in no-hardware mode takes down the goroutine serving it", recovered)
		}
	}()

	result, err := absent.Execute(context.Background(), operationRequest())

	var failed *api.Failure
	if !errors.As(err, &failed) {
		t.Fatalf("Execute() on a nil *Coordinator = %#v, %v; want an api.Failure", result, err)
	}
	if failed.Code != "DEPENDENCY_UNAVAILABLE" || failed.Status != http.StatusServiceUnavailable || !failed.Retryable {
		t.Fatalf("Execute() on a nil *Coordinator = {Code:%s Status:%d Retryable:%v}, want {DEPENDENCY_UNAVAILABLE 503 true}: a daemon with no coordinator wired is unavailable, not a caller error",
			failed.Code, failed.Status, failed.Retryable)
	}
	if result.Data != nil || result.OperationID != "" {
		t.Fatalf("Execute() on a nil *Coordinator returned %#v alongside the refusal", result)
	}

	// GATE, deliberately after the assertions above (TESTING.md 18): the same request through a
	// fully wired Coordinator succeeds. Without it, the 503 is equally consistent with
	// operationRequest() being malformed in a way every Coordinator would refuse, and the nil
	// receiver would be doing none of the work this test claims for it.
	wired, buildErr := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: guardRoute()},
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		&fakeAudit{}, directRunner{}, &fakeHardware{output: []byte("data-key")}, "sha256:policy", nil, time.Now)
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	gated, gateErr := wired.Execute(context.Background(), operationRequest())
	if gateErr != nil || string(gated.Data) != "data-key" {
		t.Fatalf("GATE: a wired Coordinator answered %#v, %v for the same request -- the refusal above measured the fixture, not the nil receiver", gated, gateErr)
	}
}

// AN UNREACHABLE CARD DURING A SEAL IS AN OUTAGE, NOT CALLER TAMPERING.
//
// The seal path has two ways to produce a 4xx/5xx that look alike from outside and mean opposite
// things: ciphertext failing its AEAD proof (the caller's bytes, 400, a security event) and the
// card refusing to wrap (an availability event, 503, retryable).
//
// WITHOUT the `err != nil` check after envelope.SealAssembled, this fixture -- real AES-GCM
// ciphertext over the server-derived contentAAD, so the AEAD round-trip passes, and a card that
// answers CKR_DEVICE_REMOVED -- was observed to answer {Code:"INVALID_ARGUMENT", Status:400,
// Retryable:false} and to write audit outcome "integrity-failed": the zero Envelope falls through
// to sealed.Marshal(), whose validateEnvelope rejects it. So a pulled card is reported to the
// caller as their own tampering, filed in the tamper-evident trail as a security event, and told
// not to retry -- which is the one instruction that cannot fix it.
//
// TestSealEnvelopeRejectsTamperedCiphertextAsIntegrityFailure does not see this: it also expects
// 400, and stays green under the mutation. The audit outcome is what separates the two.
func TestSealWithUnreachableCardIsBackendUnavailableNotIntegrityFailed(t *testing.T) {
	for _, attempt := range []struct {
		what          string
		hardware      *fakeHardware
		wantCode      string
		wantStatus    int
		wantRetryable bool
		wantOutcome   string
	}{
		{"the card is pulled between authorization and the wrap", &fakeHardware{err: errors.New("pkcs11: CKR_DEVICE_REMOVED")}, "BACKEND_UNAVAILABLE", http.StatusServiceUnavailable, true, "backend-failed"},
		// ANCHOR, deliberately last (TESTING.md 18): the identical parts through a card that
		// wraps produce an envelope. It is what bounds the fixture -- a ciphertext whose tag did
		// not verify would be refused with the SAME 400 the mutation produces, and the case above
		// would then be pinning the integrity check it exists to distinguish itself from.
		{"ANCHOR: the same parts through a card that wraps", &fakeHardware{output: []byte("wrapped-by-the-card")}, "", 0, false, "success"},
	} {
		t.Run(attempt.what, func(t *testing.T) {
			route := sealRoute()
			recorder := &fakeAudit{}
			coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: route},
				&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
				recorder, directRunner{}, attempt.hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))
			result, execErr := coordinator.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey))

			// THE DETECTOR (TESTING.md 19): the seal really reached WrapKey. A request refused
			// before the card was asked cannot be telling us anything about how a card failure is
			// classified, and the failure would be attributed to the wrong guard.
			if attempt.hardware.calls != 1 {
				t.Fatalf("hardware calls = %d, want exactly 1: the seal never reached the wrap, so this case is measuring an earlier refusal", attempt.hardware.calls)
			}
			if len(recorder.drafts) == 0 {
				t.Fatal("the seal recorded no audit draft at all")
			}
			last := recorder.drafts[len(recorder.drafts)-1].Outcome
			if last != attempt.wantOutcome {
				t.Fatalf("DEFECT: audit outcome = %q, want %q -- an operator reading the trail cannot tell a pulled card from a caller forging ciphertext, and only one of those is a security incident",
					last, attempt.wantOutcome)
			}

			if attempt.wantCode == "" {
				if execErr != nil {
					t.Fatalf("ANCHOR: seal through a working card = %v -- the parts are malformed, so the refusal above is not attributable to the card", execErr)
				}
				if len(result.Data) == 0 || result.ContentType != "application/vnd.regalia.envelope" {
					t.Fatalf("ANCHOR: seal produced %#v, want an envelope", result)
				}
				return
			}

			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("seal against an unreachable card = %#v, %v; want an api.Failure", result, execErr)
			}
			if failed.Code != attempt.wantCode || failed.Status != attempt.wantStatus || failed.Retryable != attempt.wantRetryable {
				t.Fatalf("DEFECT: seal against an unreachable card = {Code:%s Status:%d Retryable:%v}, want {%s %d %v}: a 400 tells the caller their bytes are bad and not to retry, when the bytes were fine and the card was gone",
					failed.Code, failed.Status, failed.Retryable, attempt.wantCode, attempt.wantStatus, attempt.wantRetryable)
			}
			if result.Data != nil {
				t.Fatalf("a failed seal returned %#v", result)
			}
		})
	}
}

// A POLICY DENIAL'S CODE IS THE INSTRUCTION THE CLIENT ACTS ON, AND ALL THREE SPECIAL CASES WERE
// UNPINNED.
//
// This one test covers three separate operands of the same if/else-if chain, which the sweep
// counted separately -- the three suggested names were
// TestPolicyStateUnavailableIsRetryable503NotDenied403,
// TestReplayedNonceIsConflict409NotDenied403 and
// TestPolicyQuotaDenialIsResourceExhausted429AndRetryable. They differ only in which
// policy.Code the engine returns, so three near-identical tests would be three copies of one
// fixture; a row each in one table kills all three and keeps the DENIED default beside them
// where a reader can see what each row is a departure FROM.
//
// WITHOUT each clause the observed answer to its own row collapses to the default
// {Code:"DENIED", Status:403, Retryable:false}:
//   - STATE_UNAVAILABLE -> DENIED/403: a transient durable-state outage is reported as a
//     permanent authorization refusal, so the client stops instead of retrying and the operator
//     is sent to look at grants nobody changed.
//   - REPLAY -> DENIED/403: a duplicate idempotent submission is indistinguishable from an
//     authorization failure, so a retried-but-already-applied request reads as a break-in.
//   - LIMIT_EXCEEDED -> DENIED/403: a client that should back off is told to stop permanently.
//
// The audit side of these decisions is already covered by TestPolicyDenialRecordsWhichRuleFired.
// The trail names the rule correctly while the response the client acts on is misclassified,
// which is why the outcome assertion below is a detector here and not the subject.
func TestPolicyDenialCodeChoosesWhatTheCallerDoesNext(t *testing.T) {
	for _, denial := range []struct {
		what          string
		code          policy.Code
		rule          string
		wantCode      string
		wantStatus    int
		wantRetryable bool
	}{
		{"the durable state backing the decision is unreachable", policy.CodeStateUnavailable, "durable-state", "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true},
		{"the nonce has already been spent", policy.CodeReplay, "replay", "CONFLICT", http.StatusConflict, false},
		{"the object's quota is exhausted", policy.CodeLimitExceeded, "quota", "RESOURCE_EXHAUSTED", http.StatusTooManyRequests, true},
		// ANCHOR, deliberately last (TESTING.md 18): a plain refusal still lands on the default.
		// It is what makes each row above a DEPARTURE from something rather than a lone
		// observation -- and it is the case that would go red if a fix widened one of the three
		// clauses into a catch-all, which is the other way this mapping breaks.
		{"ANCHOR: a plain policy refusal keeps the default", policy.CodeDenied, "purpose-mismatch", "DENIED", http.StatusForbidden, false},
	} {
		t.Run(denial.what, func(t *testing.T) {
			recorder := &fakeAudit{}
			hardware := &fakeHardware{output: []byte("must-not-escape")}
			coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: guardRoute()},
				&fakePolicy{decision: policy.Decision{Allowed: false, Code: denial.code, PolicyID: "sops", Rule: denial.rule}},
				recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			result, execErr := coordinator.Execute(context.Background(), operationRequest())

			// THE DETECTOR (TESTING.md 19): the refusal came out of the policy branch, carrying
			// this row's code and rule. RBAC, routing and the execution failures all refuse with
			// their own codes too, and any of them would satisfy a status assertion alone.
			if len(recorder.drafts) != 1 {
				t.Fatalf("audit drafts = %#v, want exactly the policy denial", recorder.drafts)
			}
			if got, want := recorder.drafts[0].Decision+"/"+recorder.drafts[0].Outcome, "deny/policy-"+string(denial.code)+":"+denial.rule; got != want {
				t.Fatalf("audit draft = %q, want %q: the refusal did not come from the policy branch, so the mapping below is being read off some other guard", got, want)
			}
			if hardware.calls != 0 {
				t.Fatalf("hardware calls = %d after a policy denial", hardware.calls)
			}

			var failed *api.Failure
			if !errors.As(execErr, &failed) {
				t.Fatalf("a denied operation returned %#v, %v; want an api.Failure", result, execErr)
			}
			if failed.Code != denial.wantCode || failed.Status != denial.wantStatus || failed.Retryable != denial.wantRetryable {
				t.Fatalf("DEFECT: policy %s denial answered {Code:%s Status:%d Retryable:%v}, want {%s %d %v} -- the trail names the rule correctly while the client is told to do the wrong thing about it",
					denial.code, failed.Code, failed.Status, failed.Retryable, denial.wantCode, denial.wantStatus, denial.wantRetryable)
			}
			if result.Data != nil {
				t.Fatalf("a denied operation returned %#v", result)
			}
		})
	}
}
