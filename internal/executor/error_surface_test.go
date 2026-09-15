package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Executor.Error is what reaches the API boundary and Cause is what reaches the audit trail. The
// two must not be the same string: the caller learns that the operation failed, and the operator
// learns why. An Error() that rendered its cause would put backend detail — module paths, PKCS#11
// return codes, file names — into a response body that anyone holding a client certificate can read.

var errBackendDetail = errors.New("pkcs11: CKR_DEVICE_ERROR on /usr/lib/opensc-pkcs11.so slot 3")

func TestTheBoundaryMessageNeverCarriesTheCause(t *testing.T) {
	err := &Error{Code: CodeInternal, Retryable: false, Cause: errBackendDetail}

	if err.Error() != "KMS operation failed" {
		t.Fatalf("Error() = %q, want the fixed safe message", err.Error())
	}
	for _, leak := range []string{"pkcs11", "CKR_DEVICE_ERROR", "opensc", "slot 3"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the boundary message contains %q: backend detail reaches anyone who can call the API", leak)
		}
	}
}

// ...and the cause must still be reachable, or hiding it from the boundary would also hide it from
// the operator. errors.Is is how the coordinator classifies a failure it must not re-render.
func TestTheCauseSurvivesForTheAuditTrail(t *testing.T) {
	err := &Error{Code: CodeInternal, Retryable: false, Cause: errBackendDetail}

	if !errors.Is(err, errBackendDetail) {
		t.Fatal("errors.Is cannot reach the cause: it is not hidden, it is lost, and nothing downstream can classify the failure")
	}
	if unwrapped := errors.Unwrap(err); unwrapped != errBackendDetail {
		t.Fatalf("Unwrap() = %v, want the cause", unwrapped)
	}
	// A wrapped chain, since a cause is usually itself wrapped by the time it arrives.
	wrapped := &Error{Code: CodeInternal, Cause: errors.Join(errBackendDetail, context.Canceled)}
	if !errors.Is(wrapped, errBackendDetail) || !errors.Is(wrapped, context.Canceled) {
		t.Fatal("a joined cause is not reachable through the Error")
	}
	if wrapped.Error() != "KMS operation failed" {
		t.Fatalf("a joined cause changed the boundary message to %q", wrapped.Error())
	}
}

func TestAnErrorWithNoCauseUnwrapsToNothing(t *testing.T) {
	// CodeBusy is produced with no cause at all: capacity is not a failure with a story.
	err := &Error{Code: CodeBusy, Retryable: true}

	if errors.Unwrap(err) != nil {
		t.Fatalf("Unwrap() = %v, want nil", errors.Unwrap(err))
	}
	if err.Error() != "KMS operation failed" {
		t.Fatalf("Error() = %q", err.Error())
	}
}

// TestNewRefusesAConfigurationThatWouldRemoveTheCap.
//
// The concurrency cap is what keeps the daemon inside the hardware's limits, and the timeout is
// what stops a wedged middleware call holding a slot forever. A zero or negative value for either
// is not a permissive setting — it is a cap that does not exist and a deadline that has already
// passed — so New panics rather than starting a daemon whose limits are decorative.
func TestNewRefusesAConfigurationThatWouldRemoveTheCap(t *testing.T) {
	for _, test := range []struct {
		name          string
		maxConcurrent int
		timeout       time.Duration
		wants         string
	}{
		{"zero concurrency", 0, time.Second, "maxConcurrent"},
		{"negative concurrency", -1, time.Second, "maxConcurrent"},
		{"zero timeout", 4, 0, "timeout"},
		{"negative timeout", 4, -time.Second, "timeout"},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					t.Fatalf("New(%d, %v) returned an executor: the limit it is supposed to enforce would not exist",
						test.maxConcurrent, test.timeout)
				}
				message, ok := recovered.(string)
				if !ok || !strings.Contains(message, test.wants) {
					t.Fatalf("panic = %v, want it to name %q — panicking for the other reason leaves this one unproven",
						recovered, test.wants)
				}
			}()
			New(test.maxConcurrent, test.timeout)
		})
	}
}

func TestNewAcceptsTheSmallestUsableConfiguration(t *testing.T) {
	// One slot and one nanosecond are degenerate but meaningful, and refusing them would make the
	// panics above about validity rather than about the limits being real.
	if executor := New(1, time.Nanosecond); executor == nil {
		t.Fatal("New(1, 1ns) returned nil")
	}
}

// TestACallerCancellationIsNotReportedAsATimeout. The two are different operationally: a timeout is
// retryable and points at the backend, a cancellation is the caller's own doing and retrying it is
// the caller's decision. classifyContextError checks the PARENT first for exactly this reason —
// the operation context always carries a deadline, so reading it alone would call every
// cancellation a timeout.
func TestACallerCancellationIsNotReportedAsATimeout(t *testing.T) {
	executor := New(2, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- executor.Run(ctx, func(operationCtx context.Context) error {
			close(started)
			<-operationCtx.Done()
			return operationCtx.Err()
		})
	}()
	<-started
	cancel()

	err := <-done
	var failure *Error
	if !errors.As(err, &failure) {
		t.Fatalf("Run() = %v, want an *Error", err)
	}
	if failure.Code != CodeCanceled {
		t.Fatalf("code = %v, want CodeCanceled: a caller hanging up was reported as a backend timeout", failure.Code)
	}
	if failure.Retryable {
		t.Fatal("a caller's own cancellation was marked retryable")
	}
}

// TestTheParentIsConsultedBeforeTheCause.
//
// classifyContextError checks the PARENT for cancellation before it checks the cause for a
// deadline, and the ordering only matters in one combination: the parent was cancelled and the
// cause is DeadlineExceeded. That is a race — the operation's own deadline firing in the same
// instant the caller hangs up — so it cannot be produced reliably through Run, and a behavioural
// test of Run passes with the parent check deleted (measured; the child context reports Canceled,
// not DeadlineExceeded, so the second check never matches either).
//
// Called directly for that reason. The distinction it protects is operational: a timeout is
// retryable and points at the backend, a cancellation is the caller's own doing. Getting it
// backwards tells an operator to investigate hardware because a client hung up.
func TestTheParentIsConsultedBeforeTheCause(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
	defer stop()

	for _, test := range []struct {
		name      string
		parent    context.Context
		cause     error
		wantCode  Code
		retryable bool
	}{
		{"cancelled parent, deadline cause", cancelled, context.DeadlineExceeded, CodeCanceled, false},
		{"cancelled parent, cancelled cause", cancelled, context.Canceled, CodeCanceled, false},
		{"expired parent, deadline cause", expired, context.DeadlineExceeded, CodeTimeout, true},
		{"live parent, deadline cause", context.Background(), context.DeadlineExceeded, CodeTimeout, true},
		{"live parent, some other cause", context.Background(), errors.New("neither"), CodeCanceled, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failure *Error
			if !errors.As(classifyContextError(test.parent, test.cause), &failure) {
				t.Fatal("classifyContextError did not return an *Error")
			}
			if failure.Code != test.wantCode {
				t.Fatalf("code = %v, want %v: a %s must not be reported as the other, or an operator "+
					"investigates hardware because a client hung up", failure.Code, test.wantCode, test.name)
			}
			if failure.Retryable != test.retryable {
				t.Fatalf("retryable = %v, want %v", failure.Retryable, test.retryable)
			}
			if !errors.Is(failure, test.cause) {
				t.Fatal("the cause was not preserved for the audit trail")
			}
		})
	}
}
