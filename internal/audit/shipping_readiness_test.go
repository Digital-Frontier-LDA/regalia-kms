package audit

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// The audit trail is shipped off-host, and the sink is the one collaborator this package does not
// own — an HTTP client today, whatever a deployment configures tomorrow. Two of its failure modes
// are wrapped in panic recovery, and neither arm was covered.
//
// A sink that panics must not take the daemon down with it, and it must be treated as UNAVAILABLE
// rather than as ready. The direction matters: recovering to `ready` would mean a sink that
// crashes on every call reads as a healthy off-host copy, which is the worst available answer for
// a control whose entire job is proving the trail left the machine.

type panickingSink struct {
	onSend  bool
	onReady bool
	sends   int
	readies int
	mu      sync.Mutex
}

func (sink *panickingSink) Send(context.Context, Event) error {
	sink.mu.Lock()
	sink.sends++
	sink.mu.Unlock()
	if sink.onSend {
		panic("the sink exploded")
	}
	return nil
}

func (sink *panickingSink) Ready(context.Context) bool {
	sink.mu.Lock()
	sink.readies++
	sink.mu.Unlock()
	if sink.onReady {
		panic("the sink exploded")
	}
	return true
}

func TestASinkThatPanicsIsUnavailableRatherThanFatal(t *testing.T) {
	sink := &panickingSink{onSend: true}

	err := sendEvent(context.Background(), sink, Event{})
	if err == nil {
		t.Fatal("a panicking sink reported a successful send")
	}
	if !errors.Is(err, ErrSinkUnavailable) {
		t.Fatalf("error = %v, want ErrSinkUnavailable: a panic must degrade to unavailable, which the shipper retries, rather than to some class it does not handle", err)
	}
	if sink.sends != 1 {
		t.Fatalf("the sink was called %d times", sink.sends)
	}
}

func TestASinkThatPanicsOnReadyIsNotReady(t *testing.T) {
	sink := &panickingSink{onReady: true}

	if sinkReady(context.Background(), sink) {
		t.Fatal("a sink that panics on Ready was reported ready: a collaborator that crashes on every call would read as a healthy off-host copy")
	}
	if sink.readies != 1 {
		t.Fatalf("Ready was called %d times", sink.readies)
	}
	// And the healthy case, so the recovery is shown to be about the panic rather than about
	// sinkReady refusing everything.
	if !sinkReady(context.Background(), &panickingSink{}) {
		t.Fatal("a sink that returns true was reported not ready")
	}
}

// TestReadinessFailsOnBacklogEvenWhenTheCollectorIsHealthy is the compound condition's point, and
// the reason Recorder.Ready is not simply sink.Ready.
//
// A collector answering its health check while acknowledging nothing is the failure this guards:
// events pile up locally, the off-host copy falls further behind, and every individual component
// reports fine. Readiness has to drop on the BACKLOG, not on the collector's opinion of itself.
func TestReadinessFailsOnBacklogEvenWhenTheCollectorIsHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{ready: true}
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })

	if !recorder.Ready(context.Background()) {
		t.Fatal("a fresh recorder with a healthy sink is not ready, so the refusal below would not be attributable to the backlog")
	}

	// STOP THE DRAIN LOOP BEFORE FILLING THE BACKLOG, OR THE FIXTURE RACES ITSELF.
	//
	// Open starts a shipper that drains pending into the sink. This test then fills pending
	// directly and asks whether Ready notices -- but between the Unlock below and the Ready call,
	// the drain loop can take the mutex and ship the lot. Against a HEALTHY sink, which is
	// precisely the sink this test configures, draining succeeds, backlog returns to zero, and
	// Ready answers true. The test then reports "ready with a backlog of 4097" and blames the
	// threshold for a backlog that no longer existed when it looked.
	//
	// Measured at 1 failure in 300 runs before this line, 0 in 300 after. It fires on CI often
	// enough to have blocked #216, a PR whose only change was one file in adapters/sops.
	//
	// close() stops the loop without draining (events stay durable in the journal), and Ready
	// consults only backlog() and the sink -- never `stopped` -- so the property under test is
	// unchanged. Filling directly is still right: the point is the threshold, and driving it
	// through Record would test the drain loop instead.
	recorder.shipper.close()

	recorder.shipper.mu.Lock()
	recorder.shipper.pending = make([]Event, maxAuditBacklog+1)
	recorder.shipper.mu.Unlock()

	if recorder.Ready(context.Background()) {
		// Report the backlog actually observed. Naming maxAuditBacklog+1 here describes what the
		// fixture intended, not what Ready saw, and that is exactly what made the flake read as a
		// threshold defect for as long as it did.
		t.Fatalf("ready with a backlog of %d (max %d) while the sink reports healthy: the off-host copy is falling behind and nothing says so",
			recorder.shipper.backlog(), maxAuditBacklog)
	}

	// Exactly at the limit is still ready — the bound is "past", not "at", and a max that refuses
	// its own maximum is a different number than the one documented.
	recorder.shipper.mu.Lock()
	recorder.shipper.pending = make([]Event, maxAuditBacklog)
	recorder.shipper.mu.Unlock()
	if !recorder.Ready(context.Background()) {
		t.Fatalf("a backlog of exactly %d is refused; the cap is one tighter than it reads", maxAuditBacklog)
	}
}

func TestAnUnwiredRecorderIsNeverReady(t *testing.T) {
	var absent *Recorder
	if absent.Ready(context.Background()) {
		t.Fatal("a nil recorder reports ready")
	}

	// A journal-only deployment has no sink. That is a legitimate configuration, and it must read
	// as NOT shipping rather than as shipping fine — the distinction #32's
	// regalia_audit_shipping_configured series exists to make.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	journalOnly, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journalOnly.Close() })
	if journalOnly.Ready(context.Background()) {
		t.Fatal("a journal-only recorder reports the trail as shipped: not-configured must not read as healthy")
	}

	// THE nil-SINK CLAUSE CANNOT BE FALSIFIED ALONE, and this records why rather than pretending
	// otherwise (TESTING.md §17). Two other things already refuse a nil sink:
	//
	//   Open leaves the shipper nil when there is no sink, so the journal-only case above is
	//   caught by the shipper clause.
	//
	//   And with a shipper present, calling Ready on a nil interface PANICS, which sinkReady
	//   recovers to false. Measured: removing the sink clause alone leaves this green; removing
	//   the clause AND sinkReady's recovery is what finally panics.
	//
	// The clause stays because relying on a panic for control flow is not the same as a check —
	// it works, and it is one refactor of sinkReady away from being a crash. The state is built by
	// hand because no wiring produces it today: a shipper that exists and a sink it ships to that
	// does not.
	shipped, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"), &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shipped.Close() })
	if !shipped.Ready(context.Background()) {
		t.Fatal("the control recorder is not ready, so the assertion below proves nothing")
	}
	shipped.mu.Lock()
	shipped.sink = nil
	shipped.mu.Unlock()
	if shipped.Ready(context.Background()) {
		t.Fatal("a recorder with a live shipper and no sink reports ready: there is nowhere for the trail to go and nothing says so")
	}
}
