package audit

import (
	"context"
	"sync"
	"time"
)

// Durable shipping: the journal is the queue.
//
// Every recorded event is already durable in the fsynced local journal, so shipping
// persists no second copy of event data — only a POSITION: the .shipped sidecar
// naming the sequence and hash the collector has acknowledged. A background shipper
// replays the journal tail past that position, in chain order, until the collector
// acknowledges the exact chained hash (204 + X-Regalia-Audit-Hash; see HTTPSink).
//
// The properties that make this safe:
//   - order: only the head is ever attempted, so the off-host copy is always a
//     prefix of the chain; a rejected head wedges shipping loudly instead of
//     reordering around a hole;
//   - dedupe: every retry carries the same Idempotency-Key (the event hash), so a
//     shipment whose acknowledgement was lost is retried without double-applying;
//   - recovery: a crash loses only the in-memory tail; Open replays from the
//     journal starting one past the last acknowledged sequence;
//   - visibility: a backlog past maxAuditBacklog makes the recorder unready even
//     while the collector still answers health checks.

const (
	// shippedSuffix names the sidecar recording how far the collector-acknowledged
	// copy of the chain has reached. It is written only AFTER acknowledgement, so a
	// crash leaves it behind the collector rather than ahead of it, and the replay
	// that follows is absorbed by collector-side idempotency.
	shippedSuffix = ".shipped"

	// maxAuditBacklog bounds how many recorded events may be awaiting shipment
	// before readiness fails. Events run about 600 bytes, so the in-memory tail
	// stays near 2.5 MB, and at 50 operations a second the service tolerates
	// roughly 80 seconds of full-rate outage before it stops accepting work behind
	// a collector that is not keeping the off-host copy current.
	maxAuditBacklog = 4096

	// Shipments retry with exponential backoff from minShipBackoff to
	// maxShipBackoff, doubling per failure and resetting on success. Nudges during
	// a backoff are ignored so a busy workload cannot hammer a down collector.
	minShipBackoff = 100 * time.Millisecond
	maxShipBackoff = 30 * time.Second
)

type shipper struct {
	sink   Sink
	path   string
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	changed  chan struct{} // closed and replaced on every state change, waking runners and waiters
	pending  []Event       // unshipped tail of the chain, in order
	shipped  uint64        // sequence the collector has acknowledged
	failures uint64        // generation counter, bumped per failed attempt
	stopped  bool
}

// newShipper starts draining pending (the journal tail one past shipped) immediately.
func newShipper(sink Sink, path string, pending []Event, shipped uint64) *shipper {
	ctx, cancel := context.WithCancel(context.Background())
	shipper := &shipper{
		sink: sink, path: path, ctx: ctx, cancel: cancel,
		changed: make(chan struct{}), pending: pending, shipped: shipped,
	}
	shipper.wg.Add(1)
	go shipper.run()
	return shipper
}

func (shipper *shipper) signalLocked() {
	close(shipper.changed)
	shipper.changed = make(chan struct{})
}

func (shipper *shipper) enqueue(event Event) {
	shipper.mu.Lock()
	defer shipper.mu.Unlock()
	shipper.pending = append(shipper.pending, event)
	shipper.signalLocked()
}

// waitShipped returns nil once the collector has acknowledged sequence, and
// ErrSinkUnavailable when an attempt fails first — the operation fails closed, and
// the event stays queued for the shipper to deliver later. A caller whose context
// ends first gets ErrSinkUnavailable as well; the queued event is unaffected.
func (shipper *shipper) waitShipped(ctx context.Context, sequence uint64) error {
	shipper.mu.Lock()
	for {
		if shipper.shipped >= sequence {
			shipper.mu.Unlock()
			return nil
		}
		if shipper.stopped {
			shipper.mu.Unlock()
			return ErrSinkUnavailable
		}
		failures := shipper.failures
		changed := shipper.changed
		shipper.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ErrSinkUnavailable
		}
		shipper.mu.Lock()
		// Shipping is head-of-line, so any failure since the wait began with the
		// event still unshipped means ITS attempt failed: fail the operation now
		// rather than hold it through the backoff.
		if shipper.failures != failures && shipper.shipped < sequence {
			shipper.mu.Unlock()
			return ErrSinkUnavailable
		}
	}
}

func (shipper *shipper) backlog() int {
	shipper.mu.Lock()
	defer shipper.mu.Unlock()
	return len(shipper.pending)
}

func (shipper *shipper) run() {
	defer shipper.wg.Done()
	backoff := minShipBackoff
	for {
		shipper.mu.Lock()
		if shipper.stopped || shipper.ctx.Err() != nil {
			shipper.stopped = true
			shipper.signalLocked()
			shipper.mu.Unlock()
			return
		}
		if len(shipper.pending) == 0 {
			shipper.pending = nil
			changed := shipper.changed
			shipper.mu.Unlock()
			select {
			case <-changed:
			case <-shipper.ctx.Done():
			}
			continue
		}
		head := shipper.pending[0]
		shipper.mu.Unlock()

		err := sendEvent(shipper.ctx, shipper.sink, head)

		shipper.mu.Lock()
		if err == nil {
			shipper.pending = shipper.pending[1:]
			shipper.shipped = head.Sequence
			// Losing this write is safe: the next start replays one extra event and
			// the collector dedupes it on the unchanged Idempotency-Key.
			_ = writeShippedMark(shipper.path, highWaterMark{Sequence: head.Sequence, Hash: head.Hash})
			backoff = minShipBackoff
			shipper.signalLocked()
			shipper.mu.Unlock()
			continue
		}
		if shipper.ctx.Err() != nil {
			shipper.stopped = true
			shipper.signalLocked()
			shipper.mu.Unlock()
			return
		}
		shipper.failures++
		shipper.signalLocked()
		shipper.mu.Unlock()
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-shipper.ctx.Done():
			timer.Stop()
		}
		backoff = nextShipBackoff(backoff)
	}
}

// nextShipBackoff is the retry interval after one more failed attempt: doubled, and held at
// maxShipBackoff. Both comparisons are live. Doubling from minShipBackoff reaches 25.6s and
// then 51.2s, which is past the maximum, so the cap is overshot and pulled back rather than
// landed on exactly. It is a function so that both can be tested without a 51-second wait
// on real timers.
func nextShipBackoff(backoff time.Duration) time.Duration {
	if backoff < maxShipBackoff {
		backoff *= 2
		if backoff > maxShipBackoff {
			backoff = maxShipBackoff
		}
	}
	return backoff
}

// close stops the shipper without draining it: events still pending are durable in
// the journal and resume from the .shipped sidecar on the next Open.
func (shipper *shipper) close() {
	shipper.cancel()
	shipper.wg.Wait()
}

func readShippedMark(path string) (highWaterMark, error) {
	return readMark(path + shippedSuffix)
}

func writeShippedMark(path string, mark highWaterMark) error {
	return writeMark(path+shippedSuffix, mark)
}

// snapshot is the operator's readout: how deep the unshipped tail is, how old its
// oldest event is, and how far the collector has acknowledged. Read-only; the lock
// is held only to copy the three values.
func (shipper *shipper) snapshot() (backlog int, oldest time.Time, shipped uint64) {
	shipper.mu.Lock()
	defer shipper.mu.Unlock()
	if len(shipper.pending) > 0 {
		oldest = shipper.pending[0].Timestamp
	}
	return len(shipper.pending), oldest, shipper.shipped
}
