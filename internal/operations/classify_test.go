package operations

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// classifyExecution turns an execution failure into what the caller is told, and the caller's
// retry behaviour follows from it. Getting the mapping wrong is not a cosmetic error: a client
// that retries an unretryable failure hammers a card that will never answer, and one that gives up
// on a transient failure turns a busy moment into an outage.
//
// It also decides what happens to a failure the executor did not produce, which is the arm that
// matters most — an unclassified error must not reach the caller as itself.

func TestEveryExecutorFailureMapsToItsOwnStatus(t *testing.T) {
	for _, test := range []struct {
		name      string
		cause     error
		code      string
		status    int
		retryable bool
	}{
		{"at capacity", &executor.Error{Code: executor.CodeBusy, Retryable: true},
			string(executor.CodeBusy), http.StatusTooManyRequests, true},
		{"the operation timed out", &executor.Error{Code: executor.CodeTimeout, Retryable: true},
			string(executor.CodeTimeout), http.StatusGatewayTimeout, true},
		// A cancellation is the caller's own doing, so it is NOT retryable even though it shares
		// the 504 with a timeout. A client that retried its own cancellations would resurrect
		// requests its user abandoned.
		{"the caller hung up", &executor.Error{Code: executor.CodeCanceled, Retryable: false},
			string(executor.CodeCanceled), http.StatusGatewayTimeout, false},
		{"an internal fault", &executor.Error{Code: executor.CodeInternal, Retryable: false},
			string(executor.CodeInternal), http.StatusInternalServerError, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var failed *api.Failure
			if !errors.As(classifyExecution(test.cause), &failed) {
				t.Fatal("classifyExecution did not return an *api.Failure")
			}
			if failed.Code != test.code {
				t.Fatalf("code = %q, want %q", failed.Code, test.code)
			}
			if failed.Status != test.status {
				t.Fatalf("%s reported HTTP %d, want %d", test.name, failed.Status, test.status)
			}
			if failed.Retryable != test.retryable {
				t.Fatalf("%s reported retryable=%v, want %v: the client's backoff decision comes from this",
					test.name, failed.Retryable, test.retryable)
			}
		})
	}
}

// TestTheRetryableFlagComesFromTheExecutorNotTheStatus. Status and retryability are set separately,
// and a mapping that inferred one from the other would be wrong for the 504 pair: timeout and
// cancellation share a status and differ in whether retrying makes sense.
func TestTheRetryableFlagComesFromTheExecutorNotTheStatus(t *testing.T) {
	timeout := classifyExecution(&executor.Error{Code: executor.CodeTimeout, Retryable: true})
	cancelled := classifyExecution(&executor.Error{Code: executor.CodeCanceled, Retryable: false})

	var timedOut, wasCancelled *api.Failure
	if !errors.As(timeout, &timedOut) || !errors.As(cancelled, &wasCancelled) {
		t.Fatal("classifyExecution did not return *api.Failure for both")
	}
	if timedOut.Status != wasCancelled.Status {
		t.Fatalf("the two 504 cases report %d and %d; this test's premise is gone and the assertion below proves nothing",
			timedOut.Status, wasCancelled.Status)
	}
	if timedOut.Retryable == wasCancelled.Retryable {
		t.Fatal("timeout and cancellation share a status AND a retryable flag: retryability is being inferred from the status")
	}
}

// TestAnythingTheExecutorDidNotProduceIsReportedAsAnUnavailableBackend.
//
// This is the catch-all, and its job is to be safe rather than accurate: an error from a driver, a
// PKCS#11 module or a nil-pointer recovery has no place in a response, and the caller still needs
// an answer it can act on. BACKEND_UNAVAILABLE with 503 and retryable is the honest description of
// "something below us failed and we do not know what".
func TestAnythingTheExecutorDidNotProduceIsReportedAsAnUnavailableBackend(t *testing.T) {
	detail := errors.New("pkcs11: CKR_DEVICE_ERROR on /usr/lib/opensc-pkcs11.so slot 3")

	for name, cause := range map[string]error{
		"a bare error":                  detail,
		"a wrapped error":               fmt.Errorf("execute: %w", detail),
		"a sentinel from another layer": secrets.ErrUnavailable,
		"nothing at all":                nil,
	} {
		t.Run(name, func(t *testing.T) {
			result := classifyExecution(cause)
			var failed *api.Failure
			if !errors.As(result, &failed) {
				t.Fatalf("classifyExecution(%s) = %v, want an *api.Failure", name, result)
			}
			if failed.Code != "BACKEND_UNAVAILABLE" || failed.Status != http.StatusServiceUnavailable || !failed.Retryable {
				t.Fatalf("%s classified as %s/%d retryable=%v, want BACKEND_UNAVAILABLE/503/true",
					name, failed.Code, failed.Status, failed.Retryable)
			}
			// THE CAUSE MUST NOT TRAVEL WITH IT. errors.Is catches a wrapped cause that
			// errors.As/Unwrap would expose to code.
			//
			// The message checks below cannot fail on their own today and are kept deliberately
			// (TESTING.md §17). api.Failure holds only a code, a status and a flag, and its
			// Error() is the fixed "KMS operation failed" -- so the only way detail reaches a
			// caller's string is through the Code field, which the assertion above already pins.
			// Measured: leaking the cause into the code is caught there, not here.
			//
			// They stay because that is a property of api.Failure's SHAPE rather than of this
			// function, and they do fire when the shape changes -- verified by adding a Detail
			// field rendered by Error(): "the returned message \"KMS operation failed: pkcs11:
			// ...\" contains \"pkcs11\"". That is the day the catch-all's guarantee should break,
			// and it is not a change anyone would make while thinking about this function.
			if errors.Is(result, detail) {
				t.Fatalf("%s: the cause is reachable from the returned failure — backend detail would reach anyone holding a client certificate", name)
			}
			for _, leak := range []string{"pkcs11", "CKR_DEVICE_ERROR", "opensc", "slot 3"} {
				if strings.Contains(result.Error(), leak) {
					t.Fatalf("%s: the returned message %q contains %q", name, result.Error(), leak)
				}
			}
			if result.Error() != "KMS operation failed" {
				t.Fatalf("%s: message = %q, want the fixed safe string", name, result.Error())
			}
		})
	}
}
