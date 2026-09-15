package executor

// EXECUTOR WAS EXPECTED TO BE SATURATED. It is the smallest package in #237 — 7 sites / 7
// operands / 14 operand-directions — and the sweep found three surviving directions. All
// three are on the same seam: the SELECT statements, where two channels can be ready at once
// and Go picks between ready cases uniformly at random.
//
// That randomness is why one iteration proves nothing here. With the operand neutralised the
// wrong outcome happens roughly half the time, so a single-shot assertion passes against the
// defect every other run — it would be a flaky test that reads as a passing one. Each test
// below therefore loops, and the loop is the gate rather than decoration.

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// iterations is large enough that a defect occurring with probability ~1/2 per iteration
// cannot survive the loop, and small enough to stay well inside the package's runtime.
const iterations = 200

// TestAnAlreadyCancelledCallerNeverReachesTheOperation pins executor.go's entry
// `if err := ctx.Err(); err != nil`.
//
// MEASURED WITH THE OPERAND NEUTRALISED: Run falls through to the select below it, where a
// free semaphore slot and an already-closed Done channel are BOTH ready, so the operation is
// admitted about half the time and the middleware call is made on behalf of a caller who has
// already hung up.
//
// The returned error does not show it. Once admitted, operationCtx inherits the cancelled
// parent, so Run still returns CodeCanceled and any assertion about the code passes. What
// changes is that the hardware was touched — which for a KMS is the whole question, because
// the call consumed a slot on a token and may have moved a key.
func TestAnAlreadyCancelledCallerNeverReachesTheOperation(t *testing.T) {
	executor := New(4, time.Minute)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	var invoked atomic.Int64
	for i := range iterations {
		err := executor.Run(cancelled, func(context.Context) error {
			invoked.Add(1)
			return nil
		})
		var failure *Error
		if !errors.As(err, &failure) || failure.Code != CodeCanceled {
			t.Fatalf("iteration %d: Run over a cancelled caller = %v, want an *Error with CodeCanceled", i, err)
		}
	}

	// The operation runs in a goroutine, so an admission may land after Run has returned.
	// Waiting before the assertion can only make it STRICTER — it gives every straggler a
	// chance to be counted, and the assertion is that none exists.
	settle(t, 500*time.Millisecond, func() bool { return invoked.Load() != 0 })

	if got := invoked.Load(); got != 0 {
		t.Fatalf("the operation ran %d times out of %d for a caller who had already cancelled — "+
			"the entry guard is what makes this deterministic, and without it the select below "+
			"admits the request whenever the runtime happens to pick the semaphore case", got, iterations)
	}
}

// THE THIRD SURVIVOR HAS NO TEST HERE, AND THIS IS THE REASON.
//
// `if operationCtx.Err() != nil` in Run's result arm survived `(false && …)` and no test in
// this file pins it. That is a THIRD classification, distinct from the two the sweep normally
// produces: it is not untested-and-reachable (a fixture exists, write one) and it is not
// unreachable-by-any-fixture (nothing can construct the state). It is
// CANNOT-BE-DETERMINISTICALLY-PINNED — the state is reachable, and reaching it is a coin flip
// no assertion can be conditioned on.
//
// The branch matters only in one instant: the operation returns its own error AT THE SAME
// MOMENT its deadline fires. Both of Run's select arms are then ready, the runtime picks
// between ready arms uniformly at random, and the operand is what makes the two arms agree on
// an answer.
//
// I TRIED TO PIN IT AND THE ATTEMPT FAILED ON PRISTINE CODE, which is the useful part.
// The construction was `New(64, time.Nanosecond)` with an operation returning at once, then
// 200 iterations asserting the operation's own error never reaches the caller. It failed on
// unmutated source at iteration 192. It was not a flaky test of a real defect; the assertion
// was WRONG. A one-nanosecond deadline may or may not have elapsed by the time the result arm
// runs, so BOTH outcomes are legitimate:
//
//	deadline already elapsed   the guard fires, Run returns DEADLINE_EXCEEDED  — correct
//	deadline not yet elapsed   the operation finished in time, Run returns its
//	                           error unclassified                              — also correct
//
// Nothing observable from outside Run distinguishes those two, so no assertion can hold for
// both, and a test that passes most of the time is a broken instrument rather than a gate.
// Shortening the deadline does not help: `New` refuses a non-positive timeout, which is the
// only value that would make elapse-before-check certain.
//
// COULD A SEAM PIN IT? Yes, and I judged it not worth adding. An injected clock — the
// `now func() time.Time` shape internal/server took — would let a test force
// `operationCtx.Err() != nil` while the result arm wins, and would turn this into an ordinary
// gate. The cost is that the seam would have to reach inside Run's select, because that is
// where the race is; a clock on the Executor does not help, since the deadline is owned by
// context.WithTimeout rather than by us. Pinning this branch means either replacing
// context.WithTimeout with an injectable timer or adding a test-only release channel into the
// middle of the hot path. Both put a test-shaped seam in the one function whose entire job is
// to bound a hardware call under concurrency, and the branch it would pin is a two-line
// classification that cannot produce a wrong ANSWER — only a less useful one, for one request,
// in a race. That trade reads the wrong way round to me, so the operand is recorded here
// rather than closed.
//
// TestTheParentIsConsultedBeforeTheCause hit the same wall on the sibling race and solved it
// by calling classifyContextError DIRECTLY, outside Run. That door is shut here: this branch
// is inline in Run, not a function a test can call.

// TestATimedOutOperationDoesNotParkAGoroutineForever pins the WIDENING direction of
// executor.go's `if recovered := recover(); recovered != nil`.
//
// The refusing direction is covered — TestRunContainsPanicAndRestoresCapacity fails if the
// branch stops firing on a real panic. The widening direction is not, and MY FIRST ATTEMPT AT
// THIS TEST DID NOT DETECT IT EITHER: it drove operations that SUCCEEDED, and on that path the
// extra send is harmless. `result` has capacity one, Run has already taken the operation's
// value out of it, so the deferred send lands in the empty buffer and the goroutine exits.
// The mutant survived my test, which is the only reason this comment can say where the defect
// actually lives.
//
// It lives on the TIMEOUT path. There Run returns through `<-operationCtx.Done()` and never
// reads `result`, so the operation's own return fills the one-slot buffer and the deferred
// send has nowhere to go. The goroutine blocks on it forever.
//
// MEASURED WITH THE OPERAND WIDENED: one goroutine parked per timed-out operation, while
// every error Run returned stayed correct — the leak is entirely after the caller has been
// answered, which is why no assertion about a result could see it. A wedged token is exactly
// the condition that produces timeouts in bulk, so the leak arrives when the daemon is
// already in trouble.
func TestATimedOutOperationDoesNotParkAGoroutineForever(t *testing.T) {
	executor := New(8, 5*time.Millisecond)
	const operations = 60

	timesOut := func(operationCtx context.Context) error {
		<-operationCtx.Done()
		return operationCtx.Err()
	}

	// Warm up first, so the baseline includes anything the runtime creates lazily on the first
	// call rather than counting it as a leak.
	for range 5 {
		_ = executor.Run(context.Background(), timesOut)
	}
	settle(t, 200*time.Millisecond, func() bool { return false })
	before := runtime.NumGoroutine()

	for i := range operations {
		err := executor.Run(context.Background(), timesOut)
		var failure *Error
		if !errors.As(err, &failure) || failure.Code != CodeTimeout {
			t.Fatalf("iteration %d: Run() = %v, want a timeout — this test only reaches the leaking "+
				"path if the operations actually time out", i, err)
		}
	}

	// A generous ceiling: the defect parks one goroutine per operation, so it overshoots this
	// threefold. Anything below it is scheduling noise, not a leak.
	const tolerated = 20
	settle(t, 2*time.Second, func() bool { return runtime.NumGoroutine()-before <= tolerated })
	if grown := runtime.NumGoroutine() - before; grown > tolerated {
		t.Fatalf("%d timed-out operations left %d goroutines parked (tolerating %d) — each is "+
			"blocked forever on a send into a full one-slot channel nobody will read again, so a "+
			"daemon talking to a wedged token leaks one goroutine per request while every error "+
			"it returns is correct", operations, grown, tolerated)
	}
}

// settle waits for a condition, or for a short budget to expire, before an assertion runs.
//
// It never fails: it exists to give asynchronous work a chance to become VISIBLE, so that
// the assertion after it is the strictest one available rather than a race the test wins by
// being early.
func settle(t *testing.T, budget time.Duration, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
