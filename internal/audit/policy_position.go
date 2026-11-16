package audit

import (
	"context"
	"errors"
	"fmt"
)

// ErrCollectorUnreachable is its own state at startup, not a kind of disagreement: the collector
// did not answer (or answered in a shape it never emits) when the daemon asked for its committed
// position, so nothing can be reconciled against the off-host memory. It fails closed like a
// disagreement does, because a host that could start whenever the collector is down could be
// rolled back by first taking the collector down. Operator recovery is in POLICY-ANCHOR.md:
// restore the collector's reachability and restart; there is deliberately no flag that skips it.
var ErrCollectorUnreachable = errors.New("audit collector unreachable at open")

// PolicyPosition is a policy spend journal head as an acknowledged audit record carries it.
// The zero value is "no position": a fresh stream, or only events from before the field existed.
type PolicyPosition struct {
	Sequence uint64
	Hash     string
}

// AcknowledgedPolicyPosition returns the GREATEST policy journal head that any event the collector
// committed for this stream carries. Only acknowledged events count: an event the collector has not
// committed is one the host could have restored away with the journal.
//
// Greatest, not last: the coordinator reads the head when it builds the authorized record, and
// that read is not serialized with audit.Record, so concurrent operations can record their heads
// out of order (A reads 1, B reserves and records 2, A records 1). Taking the last one would
// return 1 while 2 is acknowledged, and a journal restored to 1 would pass.
//
// A journal-only host (sink nil) has no off-host memory and returns no position, as
// ReconcileContinuity accepts it; that host's residual is recorded in POLICY-ANCHOR.md.
func AcknowledgedPolicyPosition(ctx context.Context, journalPath string, sink Sink, site string) (PolicyPosition, error) {
	if sink == nil {
		return PolicyPosition{}, nil
	}
	positioned, ok := sink.(PositionedSink)
	if !ok {
		return PolicyPosition{}, errors.New("audit sink cannot report its committed position, so the policy journal cannot be checked against the off-host copy")
	}
	events, err := VerifyIntegrity(journalPath)
	if err != nil {
		return PolicyPosition{}, fmt.Errorf("local journal: %w", err)
	}
	head, headHash, err := positioned.CommittedHead(ctx, site)
	if err != nil {
		return PolicyPosition{}, fmt.Errorf("collector position: %w: %w", ErrCollectorUnreachable, err)
	}
	if head == 0 {
		if len(events) > 0 {
			return PolicyPosition{}, fmt.Errorf("collector holds nothing for this stream but the journal has %d events", len(events))
		}
		return PolicyPosition{}, nil
	}
	// ReconcileContinuity has already refused both of these at startup; checked again so this
	// function never reads a position out of an event the collector did not commit.
	if head > sequenceOf(events) || events[head-1].Hash != headHash {
		return PolicyPosition{}, fmt.Errorf("the audit journal disagrees with the collector at sequence %d", head)
	}
	var greatest PolicyPosition
	for _, event := range events[:head] {
		if event.PolicySequence > greatest.Sequence {
			greatest = PolicyPosition{Sequence: event.PolicySequence, Hash: event.PolicyHash}
		}
	}
	return greatest, nil
}
