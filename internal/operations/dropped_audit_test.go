package operations

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// #279. Nine of the eleven Coordinator.record call sites discarded the error, and that discard is
// CORRECT -- every one of them already returns an error, so no output is released unrecorded, and
// failing closed there would turn an audit-sink outage into a denial of service on the refusal
// path. What was wrong is that the drop left no trace anywhere: the recorder's sequence advances
// only after Write and Sync succeed, so a failed record leaves no gap, the chain still verifies,
// and every other regalia_audit_* series describes events that REACHED the journal. Degrade the
// sink, then probe, and the refusals still happen while the record of probing does not exist.
//
// These tests pin the counter that closes that gap, and pin that nothing else changed.

// The two errors Record can actually return, distinguished by whether the event reached the
// journal. Using a bare ErrSinkUnavailable here would be a fixture the real writer never
// produces: Record wraps that sentinel in ErrDurable, because it only reaches that return
// AFTER Write and Sync have both succeeded.
var (
	// Pre-durability: Write itself failed, nothing is on disk.
	errNotWritten = errors.New("append audit event: no space left on device")
	// Post-durability: on disk, synced, queued to ship, remote acknowledgement missing.
	errWrittenNotShipped = fmt.Errorf("%w: %w", audit.ErrDurable, audit.ErrSinkUnavailable)
)

func denialCoordinator(t *testing.T, sink Auditor, decision policy.Decision, allowed bool) (*Coordinator, *fakeHardware) {
	t.Helper()
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	coordinator, err := New(fakeAuthorizer{allowed: allowed}, router, &fakePolicy{decision: decision}, sink, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, hardware
}

func TestADeniedRecordThatFailsToWriteIsCounted(t *testing.T) {
	coordinator, hardware := denialCoordinator(t, &fakeAudit{err: errNotWritten},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)

	result, err := coordinator.Execute(context.Background(), operationRequest())

	if err == nil || result.Data != nil || hardware.calls != 0 {
		t.Fatalf("the refusal itself changed: Execute() = %#v, %v; hardware calls=%d", result, err, hardware.calls)
	}
	dropped := coordinator.DroppedAuditRecords()
	if dropped["rbac-denied"] != 1 {
		t.Fatalf("a denial whose audit write failed was not counted: %#v\n"+
			"this is the whole point of #279 — the record never reached the journal, the sequence "+
			"did not advance, the chain still verifies, and no other metric moves, so this counter "+
			"is the only evidence the event was ever attempted", dropped)
	}
}

func TestADeniedRecordThatWritesIsNotCounted(t *testing.T) {
	// THE DISCRIMINATING CONTROL. Same refusal, same path, same outcome — only the sink differs.
	// Without it, a counter that incremented on every denial would satisfy the test above exactly
	// as well as one that counts drops, and the metric would be a denial counter wearing the wrong
	// name. Asserting "a success does not count" is weaker: it varies two things at once.
	coordinator, hardware := denialCoordinator(t, &fakeAudit{},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)

	result, err := coordinator.Execute(context.Background(), operationRequest())

	if err == nil || result.Data != nil || hardware.calls != 0 {
		t.Fatalf("Execute() = %#v, %v; hardware calls=%d", result, err, hardware.calls)
	}
	if dropped := coordinator.DroppedAuditRecords(); len(dropped) != 0 {
		t.Fatalf("a denial whose audit write SUCCEEDED was counted as dropped: %#v — the counter is "+
			"tracking denials rather than lost records", dropped)
	}
}

// NOT AN INDEPENDENT GATE, and recorded as such so nobody counts it as coverage it does not
// provide. The success path records through the two CHECKED sites, never through recordOrCount, so
// no mutation of the counting helper can make this fail — it was the sole survivor of every
// mutation run against this change. The discriminating test is the sibling above: same refusal,
// same path, only the sink differs. This one states the end-to-end invariant readably and would
// catch a future refactor that routed success through the counter AND counted successes; the
// second half of that conjunction is what the sibling already pins.
func TestASuccessfulOperationCountsNothing(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	hardware := &fakeHardware{output: []byte("data-key")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router,
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		&fakeAudit{}, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Execute(context.Background(), operationRequest()); err != nil {
		t.Fatal(err)
	}
	if dropped := coordinator.DroppedAuditRecords(); len(dropped) != 0 {
		t.Fatalf("a clean operation moved the dropped-records counter: %#v", dropped)
	}
}

func TestCountingADropDoesNotChangeWhatTheCallerSees(t *testing.T) {
	// The design claim of #279 stated as a test: observability improves, behaviour does not. If
	// these two errors ever differ, counting the drop has leaked into the response and an
	// audit-sink outage has become visible to callers as something else.
	failing, _ := denialCoordinator(t, &fakeAudit{err: errNotWritten},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)
	working, _ := denialCoordinator(t, &fakeAudit{},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)

	_, withFailingSink := failing.Execute(context.Background(), operationRequest())
	_, withWorkingSink := working.Execute(context.Background(), operationRequest())

	// COMPARED BY FIELD, NOT BY Error(). The first version of this test compared error strings and
	// could never fail: api.Failure.Error() returns the constant "KMS operation failed" whatever the
	// Code, Status and Retryable are. Two responses that differ in every field a caller can act on
	// compared equal, so the test read as a gate and bound nothing. Found by falsifying it — a
	// mutation that made the failing-sink path return DEPENDENCY_UNAVAILABLE instead of DENIED left
	// the whole package green.
	var failed, worked *api.Failure
	if !errors.As(withFailingSink, &failed) || !errors.As(withWorkingSink, &worked) {
		t.Fatalf("both refusals must be *api.Failure: failing=%#v working=%#v", withFailingSink, withWorkingSink)
	}
	if failed.Code != worked.Code || failed.Status != worked.Status || failed.Retryable != worked.Retryable {
		t.Fatalf("the audit sink's health changed what the caller sees:\n"+
			"  sink failing: code=%s status=%d retryable=%t\n"+
			"  sink working: code=%s status=%d retryable=%t",
			failed.Code, failed.Status, failed.Retryable, worked.Code, worked.Status, worked.Retryable)
	}
}

func TestTheCounterIsKeyedByTheOutcomeThatWasLost(t *testing.T) {
	// Why the label is worth its cardinality: rbac-denied disappearing is a different incident from
	// a policy rule's denials disappearing, and an unlabelled total cannot tell an operator which.
	// Every value is a compile-time literal — the policy reasons are `policy-<Code>:<Rule>` over
	// five Code constants and twelve Rule literals, none read from configuration or request data.
	coordinator, _ := denialCoordinator(t, &fakeAudit{err: errNotWritten},
		policy.Decision{Allowed: false, Code: policy.CodeDenied, PolicyID: "sops", Rule: "approval"}, true)

	if _, err := coordinator.Execute(context.Background(), operationRequest()); err == nil {
		t.Fatal("a policy denial must still refuse")
	}
	dropped := coordinator.DroppedAuditRecords()
	if dropped["policy-DENIED:approval"] != 1 {
		t.Fatalf("the lost record is not keyed by its outcome: %#v — an operator cannot tell which "+
			"kind of event stopped being written", dropped)
	}
	if _, generic := dropped["rbac-denied"]; generic {
		t.Fatalf("a policy denial was counted under another outcome: %#v", dropped)
	}
}

func TestDroppedAuditRecordsReturnsACopy(t *testing.T) {
	// The metrics handler reads this on another goroutine while Execute writes. Handing out the
	// live map would be a data race that -race catches only when the two happen to interleave;
	// mutating the returned map here proves the caller cannot reach the counter's state at all.
	coordinator, _ := denialCoordinator(t, &fakeAudit{err: errNotWritten},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)
	if _, err := coordinator.Execute(context.Background(), operationRequest()); err == nil {
		t.Fatal("expected a refusal")
	}
	coordinator.DroppedAuditRecords()["rbac-denied"] = 99
	if again := coordinator.DroppedAuditRecords(); again["rbac-denied"] != 1 {
		t.Fatalf("the accessor handed out its internal map: %#v", again)
	}
}

// THE REVIEWER'S CASE, and the one that would have made this metric lie. Record advances its
// sequence only after Write and Sync succeed, and three of its failure returns happen after that:
// the high-water-mark write, the no-shipper case under requireRemote, and a remote acknowledgement
// that never arrives. Three of the nine call sites pass requireRemote=true, so this is a live path.
//
// In every one of them the operation still fails closed AND the record is on disk, queued, and
// ships when the collector recovers. Counting it would make regalia_audit_dropped_records_total
// measure collector latency and call it data loss -- while the metric's own HELP says the record
// never reached the journal.
func TestARecordThatIsDurableButUnshippedIsNotCounted(t *testing.T) {
	coordinator, hardware := denialCoordinator(t, &fakeAudit{err: errWrittenNotShipped},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)

	result, err := coordinator.Execute(context.Background(), operationRequest())

	if err == nil || result.Data != nil || hardware.calls != 0 {
		t.Fatalf("the refusal itself changed: Execute() = %#v, %v; hardware calls=%d", result, err, hardware.calls)
	}
	if dropped := coordinator.DroppedAuditRecords(); len(dropped) != 0 {
		t.Fatalf("an event that reached the journal was counted as dropped: %#v\n"+
			"the write succeeded and only the remote acknowledgement is missing — the record ships "+
			"when the collector recovers, so this counts collector latency as data loss", dropped)
	}
	// The control: the same call site DOES count when the write genuinely failed, so the exclusion
	// above is discriminating rather than a counter that never moves.
	lost, _ := denialCoordinator(t, &fakeAudit{err: errNotWritten},
		policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}, false)
	if _, err := lost.Execute(context.Background(), operationRequest()); err == nil {
		t.Fatal("expected a refusal")
	}
	if lost.DroppedAuditRecords()["rbac-denied"] != 1 {
		t.Fatalf("the control did not count a genuine loss: %#v", lost.DroppedAuditRecords())
	}
}
