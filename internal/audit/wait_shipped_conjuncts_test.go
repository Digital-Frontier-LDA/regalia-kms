package audit

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitShipped's early fail-closed is `failures != failures0 && shipped < sequence`. Until #458
// the suite pinned that condition only as a whole: forcing EITHER conjunct true survived, and
// only forcing both together was caught (ledger rows shipper.go:115[0] and [1]). The two tests
// here pin each conjunct on its own.

// gatedSink holds each gated sequence's Send until the test releases it, and records the moment
// each sequence is first attempted — which is how a test learns that the shipper acknowledged
// the previous event and moved on, without sleeping.
type gatedSink struct {
	mu        sync.Mutex
	gates     map[uint64]chan struct{}
	attempted map[uint64]chan struct{}
}

func newGatedSink(sequences ...uint64) *gatedSink {
	sink := &gatedSink{gates: map[uint64]chan struct{}{}, attempted: map[uint64]chan struct{}{}}
	for _, sequence := range sequences {
		sink.gates[sequence] = make(chan struct{})
		sink.attempted[sequence] = make(chan struct{})
	}
	return sink
}

func (sink *gatedSink) Send(ctx context.Context, event Event) error {
	sink.mu.Lock()
	gate := sink.gates[event.Sequence]
	if attempted, ok := sink.attempted[event.Sequence]; ok {
		close(attempted)
		delete(sink.attempted, event.Sequence)
	}
	sink.mu.Unlock()
	if gate == nil {
		return nil
	}
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (sink *gatedSink) Ready(context.Context) bool { return true }

func (sink *gatedSink) release(sequence uint64) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if gate, ok := sink.gates[sequence]; ok {
		close(gate)
		delete(sink.gates, sequence)
	}
}

func (sink *gatedSink) releaseAll() {
	sink.mu.Lock()
	sequences := make([]uint64, 0, len(sink.gates))
	for sequence := range sink.gates {
		sequences = append(sequences, sequence)
	}
	sink.mu.Unlock()
	for _, sequence := range sequences {
		sink.release(sequence)
	}
}

func (sink *gatedSink) attemptedChannel(sequence uint64) <-chan struct{} {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if attempted, ok := sink.attempted[sequence]; ok {
		return attempted
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

// parkedWaiters counts goroutines blocked in select inside waitShipped.
//
// WHY A STACK AND NOT A SLEEP. Both tests need to know a waiter has taken its snapshot of
// `failures` and `changed` and is blocked on the channel, because a wake that arrives before then
// is never observed and the mutant goes unnoticed. A goroutine blocked in select reports
// "[select]"; closing the channel makes it runnable at once, so "[select]" seen AFTER a wake means
// the waiter has processed that wake and parked again — a settled state, not a guess about timing.
// Counting rather than testing for presence keeps a waiter left behind by some other test from
// satisfying the handshake.
func parkedWaiters() int {
	buffer := make([]byte, 1<<20)
	stacks := string(buffer[:runtime.Stack(buffer, true)])
	parked := 0
	for _, goroutine := range strings.Split(stacks, "\n\n") {
		header, _, _ := strings.Cut(goroutine, "\n")
		if strings.Contains(header, "[select") && strings.Contains(goroutine, ".(*shipper).waitShipped(") {
			parked++
		}
	}
	return parked
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// AN EARLIER EVENT'S ACKNOWLEDGEMENT IS NOT A FAILURE OF THIS ONE.
//
// Pins conjunct [0], `failures != failures0`. Forced true, the condition reduces to
// `shipped < sequence`, and any wake with this event still unshipped fails the operation — so a
// high-risk operation recorded behind an ordinary one is told its audit write failed the moment
// the collector acknowledges the event ahead of it, under entirely healthy shipping.
//
// Built at the Recorder boundary with the shape production has: an event recorded without
// waiting, then a high-risk event recorded behind it. Both sequences are gated, so when event 1
// is acknowledged, event 2 cannot also be acknowledged before the waiter looks.
//
// Falsifier: force [0] true in shipper.go's early fail-closed. This test fails, alone.
func TestAnEarlierEventsAcknowledgementDoesNotFailAWaitingOperation(t *testing.T) {
	sink := newGatedSink(1, 2)
	recorder, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"), sink)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		sink.releaseAll()
		_ = recorder.Close()
	}()
	ctx := context.Background()

	if err := recorder.Record(ctx, draft("018f0000-0000-7000-8000-000000000001", "allow"), false); err != nil {
		t.Fatalf("recording event 1 without waiting: %v", err)
	}
	<-sink.attemptedChannel(1) // the shipper is now blocked sending event 1

	before := parkedWaiters()
	result := make(chan error, 1)
	go func() { result <- recorder.Record(ctx, draft("018f0000-0000-7000-8000-000000000002", "allow"), true) }()
	eventually(t, "the high-risk operation's waiter to park", func() bool { return parkedWaiters() > before })

	sink.release(1)
	<-sink.attemptedChannel(2) // event 1 acknowledged and the waiter woken; event 2 held at its gate

	settled := func() bool {
		select {
		case err := <-result:
			result <- err
			return true
		default:
			return parkedWaiters() > before
		}
	}
	eventually(t, "the woken waiter to either re-park or return", settled)
	select {
	case err := <-result:
		t.Fatalf("the high-risk operation returned %v when the event AHEAD of it was acknowledged: event 2 "+
			"was still unshipped and no attempt had failed, so waitShipped must keep waiting, not fail closed", err)
	default:
	}

	sink.release(2)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("the high-risk operation returned %v after its own event was acknowledged", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the high-risk operation never returned after its event was acknowledged")
	}
}

// AN ACKNOWLEDGED EVENT IS NEVER REPORTED AS A FAILED AUDIT WRITE.
//
// Pins conjunct [1], `shipped < sequence`. Forced true, the condition reduces to
// `failures != failures0`, and a failure recorded between the wake and the waiter re-taking the
// lock fails an operation whose event the collector DID acknowledge — the caller is told the audit
// write failed when it succeeded.
//
// THIS DRIVES shipper STATE DIRECTLY, BELOW THE Recorder BOUNDARY, and that boundary is why. Record
// holds recorder.mu across waitShipped, and Record is the only caller of enqueue and waitShipped, so
// while sequence S waits no event after S can be queued: the interleaving #458 hypothesised, a LATER
// event's attempt failing, cannot be produced through the Recorder at all. The remaining path is a
// failed attempt on an event up to S followed by a retry that acknowledges S, both landing while the
// woken waiter has not yet re-taken shipper.mu. The retry waits at least minShipBackoff (100ms), so
// that needs the waiter descheduled for a whole backoff interval — reachable under load, but ordered
// by the scheduler, not by anything a test at the Recorder boundary can control. The contract itself
// is ordinary, and this test holds it without depending on timing.
//
// Falsifier: force [1] true in shipper.go's early fail-closed. This test fails, alone.
func TestAnAcknowledgedEventIsNotReportedFailedWhenAFailureAlsoLanded(t *testing.T) {
	shipper := &shipper{changed: make(chan struct{})}
	before := parkedWaiters()
	result := make(chan error, 1)
	go func() { result <- shipper.waitShipped(context.Background(), 1) }()
	eventually(t, "the waiter to park", func() bool { return parkedWaiters() > before })

	shipper.mu.Lock()
	shipper.failures++  // an attempt failed ...
	shipper.shipped = 1 // ... and a retry acknowledged the event, both before the waiter re-took the lock
	shipper.signalLocked()
	shipper.mu.Unlock()

	select {
	case err := <-result:
		if errors.Is(err, ErrSinkUnavailable) {
			t.Fatalf("waitShipped returned %v for sequence 1 after the collector acknowledged it: a failure "+
				"seen alongside the acknowledgement must not turn a successful audit write into a failed one", err)
		} else if err != nil {
			t.Fatalf("waitShipped returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitShipped never returned for an acknowledged sequence")
	}
}
