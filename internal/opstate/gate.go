package opstate

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// THE STATE GATE (ADR-0002 D32, FENCING.md "What the Gate checks", item 4; #432). Under D32 the serving lease
// is the TPM-attested runtime lease (one lease per server, 30 s, renewed every 10 s), read through the
// admission file: internal/admission already decides whether it is held, on CLOCK_BOOTTIME. What this gate
// adds is the state the lease was granted at:
//
//   - the lease names THIS daemon's session key (a lease follows the daemon instance it was made for);
//   - it names the etcd cluster this cache reads, and the state epoch it holds (a survivor's history after a
//     --force-new-cluster is another epoch than the lost tail's, which cluster and revision cannot tell apart);
//   - the cache has applied at least the lease's state_revision (no server acts on state older than its lease);
//   - the cache's last confirmation is younger than MaxStale (a stalled watch is stale state, not quiet state).
//
// A FencedRunner asks it before admission, before the hardware and before the result is handed back.

// LeaseFacts is what the held lease says, as the admission file reports it.
type LeaseFacts struct {
	Admitted      bool
	StateRevision int64
	ClusterID     uint64
	StateEpoch    int64
	SessionKey    string // 64 hex
}

// StateGateOptions configure a StateGate.
type StateGateOptions struct {
	Lease    func(context.Context) LeaseFacts
	Cache    interface{ Snapshot() Snapshot }
	Key      *SessionKey
	Boottime func() (time.Duration, error)
	// MaxStale is the oldest confirmation the gate accepts: one lease (30 s).
	MaxStale time.Duration
	// OnTransition hears every change of the answer, with the reason when it is no.
	OnTransition func(ready bool, reason string)
}

// StateGate answers whether this server may serve, as far as its state is concerned.
type StateGate struct {
	options StateGateOptions

	mu      sync.Mutex
	decided bool
	ready   bool
	reason  string
}

// NewStateGate checks the options.
func NewStateGate(options StateGateOptions) (*StateGate, error) {
	if options.Lease == nil || options.Cache == nil || options.Key == nil || options.Boottime == nil || options.MaxStale <= 0 {
		return nil, fmt.Errorf("opstate: the state gate needs the lease, the cache, the session key, a clock and a staleness bound")
	}
	return &StateGate{options: options}, nil
}

// Ready is the fencing.LeaseHolder answer.
func (g *StateGate) Ready(ctx context.Context) bool {
	ready, reason := g.evaluate(ctx)
	g.mu.Lock()
	changed := !g.decided || ready != g.ready || reason != g.reason
	g.decided, g.ready, g.reason = true, ready, reason
	hook := g.options.OnTransition
	g.mu.Unlock()
	if changed && hook != nil {
		hook(ready, reason)
	}
	return ready
}

// Reason is why the last answer was no; empty when it was yes.
func (g *StateGate) Reason() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.reason
}

func (g *StateGate) evaluate(ctx context.Context) (bool, string) {
	if ctx.Err() != nil {
		return false, "the request was cancelled"
	}
	lease := g.options.Lease(ctx)
	if !lease.Admitted {
		return false, "no serving lease is held"
	}
	if lease.SessionKey != g.options.Key.Hex() {
		return false, "the lease names another session key: it was granted to another instance of this daemon"
	}
	state := g.options.Cache.Snapshot()
	if !state.Live {
		return false, "the operational state is not being watched"
	}
	if lease.ClusterID != state.ClusterID {
		return false, fmt.Sprintf("the lease names etcd cluster %016x, this server reads %016x", lease.ClusterID, state.ClusterID)
	}
	if state.StateEpoch < 0 {
		return false, "the store's state-epoch entry does not verify, or was deleted after it was seen: no history to serve on"
	}
	if lease.StateEpoch != state.StateEpoch {
		return false, fmt.Sprintf("the lease names state epoch %d, this server holds %d", lease.StateEpoch, state.StateEpoch)
	}
	if state.Revision < lease.StateRevision {
		return false, fmt.Sprintf("the operational state is at revision %d, behind the lease's %d: catching up", state.Revision, lease.StateRevision)
	}
	now, err := g.options.Boottime()
	if err != nil {
		return false, "CLOCK_BOOTTIME cannot be read"
	}
	if age := now - state.ConfirmedAt; age >= g.options.MaxStale {
		return false, fmt.Sprintf("the operational state was last confirmed %s ago, longer than one lease (%s): the watch has stalled", age.Round(time.Second), g.options.MaxStale)
	}
	return true, ""
}
