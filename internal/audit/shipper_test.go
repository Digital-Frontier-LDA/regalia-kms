package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Shipping is asynchronous: assertions must wait for the shipper, but a missing
// shipper must fail the test with the defect named, never hang it.
func waitForShip(t *testing.T, what string, condition func() bool) {
	t.Helper()
	waitForShipWithin(t, what, 5*time.Second, condition)
}

func waitForShipWithin(t *testing.T, what string, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(what)
}

// waitForProgress waits for a condition reached by INCREMENTAL work, and fails only when that
// work has STALLED -- not when a wall clock ran out.
//
// A fixed deadline over a long drain measures the machine, not the code. The 4098-event backlog
// below took 4.1s to 9.1s across passing -race runs on one idle host -- a 2.2x spread against a
// 15s bound -- and failed 5 times in 20 under -race here, 1 in 20 without it. The message then
// read "a healthy collector never drained the backlog", naming a cause it had not established.
// Slow and stuck are different and only one is a defect.
//
// So the primary signal is STALL, not elapsed time: give up when `stall` has passed with no
// forward movement, and report how far it got -- the number that tells the two apart. There is
// also an absolute ceiling, far above any legitimate run, so that a drain which inches forward
// forever cannot run to the package timeout; see the comment on it below.
func waitForProgress(t *testing.T, what string, stall time.Duration, progress func() int, done func() bool) {
	t.Helper()
	// A CEILING AS WELL AS A STALL DETECTOR. Without one, a drain that keeps inching forward --
	// one event every few seconds under load -- never trips the stall check and runs to the
	// package timeout, which fails the whole package with no message about this test at all.
	// Trading a 15s flake for a 10m hang would be a worse bug than the one being fixed.
	//
	// 2 minutes is roughly 13x the slowest passing -race run observed (9.1s), so it is not a
	// deadline this test races -- it is the point past which "slow" has stopped being a useful
	// reading. The message says which bound was hit and how far the drain got, because those are
	// different failures and the operator-facing distinction is the whole reason this helper
	// exists.
	const ceiling = 2 * time.Minute
	started := time.Now()
	last, lastMoved := progress(), time.Now()
	for {
		if done() {
			return
		}
		switch now := progress(); {
		case now != last:
			last, lastMoved = now, time.Now()
		case time.Since(lastMoved) > stall:
			t.Fatalf("%s: no progress for %s, stuck at %d", what, stall, last)
		case time.Since(started) > ceiling:
			t.Fatalf("%s: still progressing but did not finish within %s, reached %d", what, ceiling, last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func setSinkState(sink *memorySink, ready bool, err error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.ready, sink.err = ready, err
}

func sinkReceived(sink *memorySink) []Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]Event(nil), sink.events...)
}

// A collector that rejects a chosen sequence forever, counting every attempt so the
// test can distinguish "retried the head" from "dropped it" and "skipped past it".
type poisonSink struct {
	mu           sync.Mutex
	poisoned     map[uint64]bool
	failuresLeft map[uint64]int
	attempts     map[uint64]int
	delivered    []Event
}

func newPoisonSink(poisoned ...uint64) *poisonSink {
	sink := &poisonSink{poisoned: make(map[uint64]bool), failuresLeft: make(map[uint64]int), attempts: make(map[uint64]int)}
	for _, sequence := range poisoned {
		sink.poisoned[sequence] = true
	}
	return sink
}

func (sink *poisonSink) Send(_ context.Context, event Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.attempts[event.Sequence]++
	if sink.poisoned[event.Sequence] {
		return errors.New("collector rejects event")
	}
	if sink.failuresLeft[event.Sequence] > 0 {
		sink.failuresLeft[event.Sequence]--
		return errors.New("collector blip")
	}
	sink.delivered = append(sink.delivered, event)
	return nil
}

func (sink *poisonSink) Ready(context.Context) bool { return true }

func (sink *poisonSink) heal() {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.poisoned = make(map[uint64]bool)
}

func (sink *poisonSink) failOnce(sequence uint64) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.failuresLeft[sequence] = 1
}

func (sink *poisonSink) attemptCount(sequence uint64) int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.attempts[sequence]
}

func (sink *poisonSink) deliveredSequences() []uint64 {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sequences := make([]uint64, 0, len(sink.delivered))
	for _, event := range sink.delivered {
		sequences = append(sequences, event.Sequence)
	}
	return sequences
}

// A collector that delivers only the first quota events it is offered, so a test
// can hold a backlog at an exact depth while remaining perfectly healthy.
type quotaSink struct {
	mu        sync.Mutex
	quota     int
	delivered []Event
}

func (sink *quotaSink) Send(_ context.Context, event Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.delivered) >= sink.quota {
		return errors.New("collector at capacity")
	}
	sink.delivered = append(sink.delivered, event)
	return nil
}

func (sink *quotaSink) Ready(context.Context) bool { return true }

func (sink *quotaSink) setQuota(quota int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.quota = quota
}

func (sink *quotaSink) deliveredCount() int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return len(sink.delivered)
}

// writeChainFixture mints a valid journal of count chained events without the
// recorder, so a test can open a large backlog instantly instead of fsyncing
// thousands of records one at a time.
func writeChainFixture(t *testing.T, path string, count int) {
	t.Helper()
	var contents []byte
	previous := genesisHash
	var last string
	for sequence := 1; sequence <= count; sequence++ {
		event := Event{Sequence: uint64(sequence), PreviousHash: previous}
		event.Hash = eventHash(event)
		line, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		contents = append(contents, line...)
		contents = append(contents, '\n')
		previous, last = event.Hash, event.Hash
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAuditHighWater(path, highWaterMark{Sequence: uint64(count), Hash: last}); err != nil {
		t.Fatal(err)
	}
}

// THE OFF-HOST COPY MUST NOT HAVE A PERMANENT HOLE AFTER A COLLECTOR BLIP.
//
// A collector outage used to drop every event recorded during it: Send returned
// ErrSinkUnavailable and nothing retried, while the local journal verified clean.
// The hole was silent precisely because the journal looked intact.
func TestEventsRecordedDuringOutageShipAfterRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{}
	setSinkState(sink, false, errors.New("collector down"))
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	ids := []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002", "018f0000-0000-7000-8000-000000000003"}
	for _, id := range ids {
		if err := recorder.Record(context.Background(), draft(id, "allow"), false); err != nil {
			t.Fatalf("routine record must not fail during a collector outage: %v", err)
		}
	}
	setSinkState(sink, true, nil)
	waitForShip(t, "events recorded while the collector was down were never shipped: the off-host copy has a permanent hole", func() bool {
		return len(sinkReceived(sink)) == 3
	})
	events, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	for index, received := range sinkReceived(sink) {
		if received.Sequence != uint64(index+1) || received.Hash != events[index].Hash {
			t.Fatalf("shipped event %d out of chain order or altered: %#v", index, received)
		}
	}
}

// FAIL-CLOSED MUST SURVIVE DURABLE SHIPPING — IN BOTH DIRECTIONS.
//
// AUDIT.md requires a high-risk operation to fail closed when the collector cannot
// acknowledge its event, and the queue must not re-open the hole it exists to close:
// the failed event still ships when the collector recovers.
func TestRequireRemoteFailureFailsClosedAndStillShipsLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{}
	setSinkState(sink, false, errors.New("collector down"))
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), true); !errors.Is(err, ErrSinkUnavailable) {
		t.Fatalf("high-risk record did not fail closed during a collector outage: %v", err)
	}
	setSinkState(sink, true, nil)
	waitForShip(t, "event whose Record failed closed was never shipped after recovery: the hole is still there", func() bool {
		return len(sinkReceived(sink)) == 1
	})
}

// A RESTART MUST NOT ABANDON UNSHIPPED EVENTS.
//
// The in-flight queue lives in process memory; a deploy or crash is exactly when a
// collector outage is likeliest to overlap. The journal is the durable queue, so
// reopening must resume shipping where the acknowledged head left off.
func TestUnshippedEventsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{}
	setSinkState(sink, false, errors.New("collector down"))
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002"} {
		if err := recorder.Record(context.Background(), draft(id, "allow"), false); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	setSinkState(sink, true, nil)
	reopened, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	waitForShip(t, "events pending at shutdown were never shipped after restart: the shipping queue is not durable", func() bool {
		return len(sinkReceived(sink)) == 2
	})
	for index, received := range sinkReceived(sink) {
		if received.Sequence != uint64(index+1) {
			t.Fatalf("reshipped out of order after restart: %v", sinkReceived(sink))
		}
	}
}

// A REJECTED HEAD MUST WEDGE SHIPPING LOUDLY, NEVER BE SKIPPED.
//
// Shipping event N+1 while event N is unshipped would reorder the chain around a
// hole, and a reordered audit chain is not a chain. The head retries until the
// collector accepts it; nothing overtakes it.
func TestShipperNeverReordersOrSkipsAroundARejectedHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := newPoisonSink(1)
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	for _, id := range []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002", "018f0000-0000-7000-8000-000000000003"} {
		if err := recorder.Record(context.Background(), draft(id, "allow"), false); err != nil {
			t.Fatal(err)
		}
	}
	for _, sequence := range sink.deliveredSequences() {
		if sequence > 1 {
			t.Fatalf("event %d shipped while event 1 was unshipped: the off-host chain was reordered around a hole", sequence)
		}
	}
	waitForShip(t, "a rejected head event was never retried: one collector error dropped it permanently", func() bool {
		return sink.attemptCount(1) >= 3
	})
	sink.heal()
	waitForShip(t, "rejected head never shipped after the collector recovered", func() bool {
		return len(sink.deliveredSequences()) == 3
	})
	sequences := sink.deliveredSequences()
	for index, sequence := range sequences {
		if sequence != uint64(index+1) {
			t.Fatalf("shipped out of chain order after recovery: %v", sequences)
		}
	}
}

// A BACKLOG PAST THE STATED LIMIT MUST MAKE READINESS FALSE.
//
// The synchronous-send design hid the backlog entirely: readiness probed only
// whether the collector answered a health check, so events could pile up unshipped
// behind a "ready" service. The limit is 4096 events (maxAuditBacklog); this test
// opens one past it.
func TestReadinessReportsAnOverLimitBacklog(t *testing.T) {
	t.Run("over-limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainFixture(t, path, 4097)
		// The collector answers health checks but rejects every event: only a
		// backlog-aware readiness can see this failure.
		sink := &memorySink{}
		setSinkState(sink, true, errors.New("collector rejects every event"))
		recorder, err := Open(path, sink)
		if err != nil {
			t.Fatal(err)
		}
		defer recorder.Close()
		if recorder.Ready(context.Background()) {
			t.Fatal("readiness reported healthy while 4097 audited events had never reached the collector: the backlog was hidden")
		}
	})
	t.Run("within-limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		writeChainFixture(t, path, 3)
		sink := &memorySink{}
		setSinkState(sink, true, nil)
		recorder, err := Open(path, sink)
		if err != nil {
			t.Fatal(err)
		}
		defer recorder.Close()
		waitForShip(t, "healthy collector with a small backlog reported unready: the gate is too tight", func() bool {
			return recorder.Ready(context.Background())
		})
	})
}

// A RETRIED SHIPMENT MUST CARRY THE SAME IDEMPOTENCY KEY.
//
// Retrying is only safe because the collector dedupes on Idempotency-Key. The key
// is the chained event hash; a retry that changed it would double-apply the event
// collector-side, and a shipment never retried leaves the hole this fixes.
func TestRetriedShipmentReusesTheSameIdempotencyKey(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/v1/health/ready" {
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		var event Event
		if err := json.Unmarshal(body, &event); err != nil {
			return nil, err
		}
		mu.Lock()
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		attempt := len(keys)
		mu.Unlock()
		if attempt == 1 {
			// The connection drops; whether the collector committed is unknowable.
			// The retry must be recognizable as the same event.
			return nil, errors.New("connection reset by peer")
		}
		return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{event.Hash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	sink, err := NewHTTPSink("https://audit.internal", client, 2*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), false); err != nil {
		t.Fatal(err)
	}
	waitForShip(t, "a failed shipment was never retried: one dropped connection cost the event permanently", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(keys) >= 2
	})
	events, err := Verify(path)
	if err != nil || len(events) != 1 {
		t.Fatalf("journal unreadable: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for attempt, key := range keys {
		if key != events[0].Hash {
			t.Fatalf("retry %d changed the idempotency key to %q: collector dedupe cannot recognize it as the same event", attempt+1, key)
		}
	}
}

// A JOURNAL MISSING COLLECTOR-ACKNOWLEDGED EVENTS MUST NOT REOPEN.
//
// The high-water sidecar detects truncation, but an attacker who knows the old
// scheme deletes it alongside the events. The collector's acknowledged head is the
// ground truth the local journal may not fall behind; a marker of how far shipping
// reached makes that comparison possible after the journal is tampered with.
func TestJournalMissingCollectorAcknowledgedEventsIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{}
	setSinkState(sink, true, nil)
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002"} {
		if err := recorder.Record(context.Background(), draft(id, "allow"), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.SplitAfter(string(contents), "\n")[0]
	if err := os.WriteFile(path, []byte(first), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + highWaterSuffix); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, sink)
	if err == nil {
		_ = reopened.Close()
		t.Fatal("reopened a journal missing events the collector already acknowledged: the loss left no trace")
	}
	if !strings.Contains(err.Error(), "acknowledged") {
		t.Fatalf("error does not name the missing collector-acknowledged events: %v", err)
	}
}

// A FORGED .shipped MARK MUST NOT BE TRUSTED ON ITS OWN.
//
// The sidecar holds only a position, and a position can be forged forward: write a
// high sequence into .shipped and the shipper skips everything below it, leaving
// the off-host copy silently short — the exact hole durable shipping exists to
// close. Open cross-checks the mark against the journal and the high-water record
// and refuses to start on any disagreement.
func TestForgedShippedMarkIsRefused(t *testing.T) {
	forge := func(t *testing.T, mutate func(path string, events []Event)) (string, *memorySink) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		sink := &memorySink{}
		setSinkState(sink, true, nil)
		recorder, err := Open(path, sink)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002"} {
			if err := recorder.Record(context.Background(), draft(id, "allow"), true); err != nil {
				t.Fatal(err)
			}
		}
		if err := recorder.Close(); err != nil {
			t.Fatal(err)
		}
		events, err := Verify(path)
		if err != nil {
			t.Fatal(err)
		}
		mutate(path, events)
		return path, sink
	}
	writeShipped := func(t *testing.T, path string, sequence uint64, hash string) {
		t.Helper()
		encoded, err := json.Marshal(highWaterMark{Sequence: sequence, Hash: hash})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".shipped", encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("beyond-journal-head", func(t *testing.T) {
		path, sink := forge(t, func(path string, events []Event) {
			writeShipped(t, path, 3, events[1].Hash)
		})
		reopened, err := Open(path, sink)
		if err == nil {
			_ = reopened.Close()
			t.Fatal("a .shipped mark beyond the journal head was trusted: forged shipping positions can suppress delivery")
		}
	})
	t.Run("hash-mismatch", func(t *testing.T) {
		path, sink := forge(t, func(path string, events []Event) {
			writeShipped(t, path, 1, events[1].Hash)
		})
		reopened, err := Open(path, sink)
		if err == nil {
			_ = reopened.Close()
			t.Fatal("a .shipped mark disagreeing with the journal was trusted: the forged position would have hidden a hole")
		}
	})
	t.Run("ahead-of-high-water", func(t *testing.T) {
		path, sink := forge(t, func(path string, events []Event) {
			// A forgery thorough enough to match the journal at sequence 2 still has
			// to outrun the high-water record; the two sidecars are written by
			// different steps and cannot legitimately cross.
			writeShipped(t, path, 2, events[1].Hash)
			if err := writeAuditHighWater(path, highWaterMark{Sequence: 1, Hash: events[0].Hash}); err != nil {
				t.Fatal(err)
			}
		})
		reopened, err := Open(path, sink)
		if err == nil {
			_ = reopened.Close()
			t.Fatal("a .shipped mark ahead of the high-water record was trusted: the sidecars crossing means one was forged")
		}
	})
}

// A SINGLE FAILED ATTEMPT MUST NOT REORDER WHAT IS RECORDED DURING ITS BACKOFF.
//
// Event N failing once while N+1 and N+2 are recorded is the ordinary shape of a
// collector blip. The collector must still observe N, N+1, N+2 in that order — the
// backoff belongs to the head, and nothing overtakes it.
func TestTransientFailureKeepsChainOrderWhileRecording(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := newPoisonSink()
	sink.failOnce(2)
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	for _, id := range []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002", "018f0000-0000-7000-8000-000000000003"} {
		if err := recorder.Record(context.Background(), draft(id, "allow"), false); err != nil {
			t.Fatal(err)
		}
	}
	waitForShip(t, "an event whose first shipment failed was dropped: one blip put a permanent hole in the off-host copy", func() bool {
		return len(sink.deliveredSequences()) == 3
	})
	sequences := sink.deliveredSequences()
	for index, sequence := range sequences {
		if sequence != uint64(index+1) {
			t.Fatalf("a transient failure reordered the off-host chain: delivered %v", sequences)
		}
	}
}

// READINESS RETURNS WHEN THE BACKLOG DRAINS, NOT WHEN IT BUDGES.
//
// Crossing the limit down by one event still leaves the off-host copy thousands of
// events behind; flipping ready on the first successful shipment would flap a
// recovering service into accepting work behind a collector that has not caught up.
func TestReadinessReturnsOnlyAfterBacklogDrains(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeChainFixture(t, path, 4098)
	sink := &quotaSink{quota: 1}
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	waitForShip(t, "the quota-limited collector never received its first event", func() bool {
		return sink.deliveredCount() == 1
	})
	if recorder.Ready(context.Background()) {
		t.Fatal("readiness returned after a single shipment while 4097 events were still unshipped: the gate trips on progress, not position")
	}
	sink.setQuota(1 << 30)
	waitForProgress(t, "a healthy collector stopped draining the backlog", 10*time.Second,
		sink.deliveredCount,
		func() bool { return sink.deliveredCount() == 4098 })
	waitForShip(t, "readiness did not return once the backlog drained", func() bool {
		return recorder.Ready(context.Background())
	})
}

// THE BACKLOG IS A NUMBER AN OPERATOR CAN SEE, NOT A READINESS SIDE EFFECT.
//
// During #9 the backlog existed only as a boolean gate: readiness failed past the
// limit and nothing said how deep the hole was, how old the oldest unshipped event
// was, or how far the collector had acknowledged. Those are the three questions an
// operator asks during a collector outage, and the shipper already has the answers.
func TestShippingStateReportsBacklogAgeAndAcknowledgedHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{}
	setSinkState(sink, false, errors.New("collector down"))
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	first := draft("018f0000-0000-7000-8000-000000000001", "allow")
	if err := recorder.Record(context.Background(), first, false); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000002", "allow"), false); err != nil {
		t.Fatal(err)
	}
	state := recorder.ShippingState()
	if !state.Configured {
		t.Fatal("a recorder with a sink reports shipping unconfigured")
	}
	if state.Backlog != 2 || state.ShippedSequence != 0 {
		t.Fatalf("ShippingState = %+v, want backlog 2 shipped 0", state)
	}
	if !state.OldestUnshipped.Equal(first.Timestamp.UTC()) {
		t.Fatalf("oldest unshipped = %s, want the first event's timestamp %s", state.OldestUnshipped, first.Timestamp.UTC())
	}
	setSinkState(sink, true, nil)
	waitForShip(t, "backlog never drained after the collector recovered", func() bool {
		return len(sinkReceived(sink)) == 2
	})
	state = recorder.ShippingState()
	if state.Backlog != 0 || state.ShippedSequence != 2 || !state.OldestUnshipped.IsZero() {
		t.Fatalf("after drain ShippingState = %+v, want backlog 0 shipped 2 no oldest", state)
	}
}

// A journal-only deployment has no shipping position at all; the state must say so
// rather than report a zero backlog that looks like a healthy shipper.
func TestShippingStateWithoutSinkIsUnconfigured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if state := recorder.ShippingState(); state.Configured {
		t.Fatalf("no sink configured but ShippingState = %+v", state)
	}
}
