package audit

import (
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// Periodic self-verification of the live journal.
//
// `-verify-audit` answers when an operator asks; this loop asks continuously.
// Between startup and shutdown the daemon is the only thing watching its own
// trail, so it re-verifies the durable prefix on an interval and reports the
// outcome where the metrics surface can see it. A verifier that has stopped
// running is indistinguishable from a healthy one unless the last run carries a
// timestamp, so VerifyState always says when.
//
// Two properties keep the check honest on a file being appended to:
//
//   - It verifies only up to durableOffset — the recorder's last fsynced write.
//     A live journal has a tail in flight; reading to the end could catch a torn
//     line and page someone for a write that is still happening.
//   - It compares the verified prefix against the recorder's in-memory head,
//     snapshotted under the same lock, rather than re-reading the sidecar marks.
//     The marks are rewritten during Record; consulting them mid-flight would
//     race, and they were already verified against the journal at Open.

// DefaultVerifyInterval is how often the daemon re-verifies its journal. The
// alert fires at twice this, so a single slow or skipped run pages nobody.
const DefaultVerifyInterval = time.Minute

type VerifyOutcome string

const (
	// VerifyIntact means the durable prefix still chains to the recorder's head.
	VerifyIntact VerifyOutcome = "intact"
	// VerifyChainBroken means the bytes on disk no longer match what was written:
	// altered, truncated, or rewritten. This pages security.
	VerifyChainBroken VerifyOutcome = "chain-broken"
	// VerifyUnreadable means the verifier could not run — a permission error, a
	// missing journal, a canceled context. This pages operations, and it must
	// never masquerade as intact.
	VerifyUnreadable VerifyOutcome = "unreadable"
)

// VerifyState is the last completed verification: its outcome, when it ran, and
// how many events the durable prefix held.
type VerifyState struct {
	Outcome VerifyOutcome
	At      time.Time
	Events  int
}

// VerifyNow runs one bounded verification and records its outcome. It is safe to
// call concurrently with Record: the prefix bound and the expected head are read
// under the same lock, and the file read itself is a separate read-only handle.
func (recorder *Recorder) VerifyNow(ctx context.Context) VerifyState {
	state := VerifyState{Outcome: VerifyUnreadable, At: time.Now().UTC()}
	if ctx.Err() != nil {
		recorder.noteVerify(state)
		return state
	}
	recorder.mu.Lock()
	if recorder.closed {
		recorder.mu.Unlock()
		return recorder.VerifyState()
	}
	offset, sequence, lastHash, path := recorder.durableOffset, recorder.sequence, recorder.lastHash, recorder.path
	recorder.mu.Unlock()

	file, err := os.Open(path)
	if err != nil {
		recorder.noteVerify(state)
		return state
	}
	defer file.Close()
	events, err := verifyEvents(io.LimitReader(file, offset))
	if err != nil {
		// An I/O failure is not a broken chain: the bytes could not be read, which
		// is disk or permissions, and pages operations. Chain failures are the bytes
		// not being what was written, and page security.
		state.Outcome = VerifyChainBroken
		if errors.Is(err, ErrChainRead) {
			state.Outcome = VerifyUnreadable
		}
		recorder.noteVerify(state)
		return state
	}
	var head uint64
	headHash := genesisHash
	if len(events) > 0 {
		head, headHash = events[len(events)-1].Sequence, events[len(events)-1].Hash
	}
	if head != sequence || headHash != lastHash {
		// The durable prefix is a valid chain but not the one this process wrote:
		// the journal has been replaced or truncated under a running recorder.
		state.Outcome = VerifyChainBroken
		recorder.noteVerify(state)
		return state
	}
	state.Outcome = VerifyIntact
	state.Events = len(events)
	recorder.noteVerify(state)
	return state
}

func (recorder *Recorder) noteVerify(state VerifyState) {
	recorder.mu.Lock()
	recorder.lastVerify = state
	recorder.mu.Unlock()
}

// VerifyState returns the last completed verification. The zero value means the
// verifier has never run — which is itself the answer "no one is watching".
func (recorder *Recorder) VerifyState() VerifyState {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.lastVerify
}

// StartVerifier runs VerifyNow on the interval until the context ends or the
// recorder closes. Starting twice is a no-op: one verifier per recorder.
func (recorder *Recorder) StartVerifier(ctx context.Context, interval time.Duration) {
	recorder.mu.Lock()
	if recorder.closed || recorder.verifyStarted {
		recorder.mu.Unlock()
		return
	}
	recorder.verifyStarted = true
	loopCtx, stop := context.WithCancel(ctx)
	recorder.verifyStop = stop
	recorder.mu.Unlock()

	recorder.verifyWg.Add(1)
	go func() {
		defer recorder.verifyWg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				recorder.VerifyNow(loopCtx)
			}
		}
	}()
}
