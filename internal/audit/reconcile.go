package audit

// COLLECTOR RECONCILIATION — the off-host memory for the journal (see
// doc/AUDIT-COLLECTOR-RECONCILIATION.md). On-host rules (#223's marks, the chain itself) are
// all satisfiable by whoever can write the state directory: truncate the journal, rewrite the
// marks to match, and every local check passes. The collector commits each event's exact hash
// before acknowledging it, so its per-stream head is the one value the host cannot author.
// This is the moment that memory gets used.

import (
	"context"
	"fmt"
)

// PositionedSink is a sink whose collector can report the last event it committed for a
// stream. HTTPSink implements it; a sink that cannot has no off-host memory to reconcile
// against, and ReconcileContinuity says so rather than pretending.
type PositionedSink interface {
	Sink
	// CommittedHead returns the sequence and hash of the last event the collector committed
	// durably for this stream, or (0, "") when it has never committed anything.
	CommittedHead(ctx context.Context, site string) (uint64, string, error)
}

// ReconcileContinuity refuses to let the daemon serve a journal that disagrees with what it
// already shipped. Fail-closed in every branch: the acceptable outcomes are a genuinely fresh
// stream and demonstrated continuity; everything else — a rewritten journal, history the host
// no longer holds, a collector that forgot, a local mark ahead of the collector — is an
// incident, and the daemon's job is to be an alarm rather than a fresh start.
func ReconcileContinuity(ctx context.Context, journalPath string, sink Sink, site string) error {
	positioned, ok := sink.(PositionedSink)
	if !ok {
		if sink == nil {
			return nil // journal-only host: no off-host memory exists to reconcile against
		}
		return fmt.Errorf("audit sink cannot report its committed position, so the journal's continuity against the off-host copy cannot be established")
	}
	events, err := VerifyIntegrity(journalPath)
	if err != nil {
		return fmt.Errorf("local journal: %w", err)
	}
	head, headHash, err := positioned.CommittedHead(ctx, site)
	if err != nil {
		return fmt.Errorf("collector position: %w", err)
	}
	if head == 0 {
		if len(events) > 0 {
			return fmt.Errorf("collector holds nothing for this stream but the journal has %d events — the off-host memory forgot what this host already shipped", len(events))
		}
		return nil
	}
	// The local .shipped mark only ever LAGS the collector (it is written after
	// acknowledgement), so being ahead of the collector is impossible without forgery or a
	// collector that acknowledged without committing.
	shipped, err := readShippedForReconcile(journalPath)
	if err != nil {
		return fmt.Errorf("local shipped mark: %w", err)
	}
	return reconcilePositions(events, head, headHash, shipped)
}

func reconcilePositions(events []Event, head uint64, headHash string, shipped uint64) error {
	if shipped > head {
		return fmt.Errorf("local shipped mark records sequence %d but the collector committed only through %d — a mark ahead of the collector is impossible without forgery or an ack-without-commit", shipped, head)
	}
	if head > sequenceOf(events) {
		return fmt.Errorf("the collector committed through sequence %d but the local journal ends at %d — the host holds less history than it already shipped; the missing events exist off-host and their absence here is an incident", head, sequenceOf(events))
	}
	// Indexing, not searching: verifyEvents guarantees sequences are contiguous from 1
	// (it refuses any event whose sequence is not len(events)+1), so event N lives at
	// N-1. If that contiguity rule ever gains an exception, this line is the one that
	// breaks with it — the guarantee, not the luck, is what makes it an index.
	local := events[head-1]
	if local.Hash != headHash {
		return fmt.Errorf("the journal's event at sequence %d does not match what this site already shipped (collector hash %s) — the journal was rewritten after the off-host copy was made", head, headHash)
	}
	return nil
}

func sequenceOf(events []Event) uint64 {
	if len(events) == 0 {
		return 0
	}
	return events[len(events)-1].Sequence
}

// readShippedForReconcile reads the collector-acknowledged mark. A missing mark is sequence 0
// (the collector may be ahead; it can never be behind it).
func readShippedForReconcile(journalPath string) (uint64, error) {
	shipped, err := readShippedMark(journalPath)
	if err != nil {
		return 0, err
	}
	return shipped.Sequence, nil
}
