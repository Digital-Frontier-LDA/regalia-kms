package fencing

// FencedRunner.Run MUST HAND BACK THE OPERATION'S OWN ERROR, and nothing tested that. Defeating
// the propagation left the whole kms module green — 25 packages, zero failures.
//
// The consequence is a misclassification rather than a release, and the distinction is worth
// stating precisely because it is easy to overstate. Coordinator.Execute assigns its output inside
// the closure it hands to Run, and every backend returns nil output on every error path, so a
// dropped error still meets the `len(output) == 0` check further down and nothing reaches the
// caller.
//
// What changes is what the daemon SAYS happened. With the error propagated, a tampered envelope is
// ErrInvalidEnvelope: INVALID_ARGUMENT, 400, audit outcome "integrity-failed". With it dropped, the
// same request becomes INTERNAL, 500, audit outcome "empty-output" — a defect in this daemon rather
// than a security event about the caller's bytes.
//
// coordinator.go already argues why that matters, about this exact pair of outcomes: "a tampered
// envelope and an unreachable card produced the same audit event in a system whose purpose is a
// tamper-evident record. Ciphertext failing its AEAD proof is a security event someone should see
// as one; a backend fault is an availability event." Dropping the error collapses BOTH of them into
// a third thing that is neither.

import (
	"context"
	"errors"
	"testing"
)

type alwaysReadyGate struct{}

func (alwaysReadyGate) Ready(context.Context) bool { return true }

// directRunner runs the operation without adding behaviour, so the only thing between the
// operation's error and Run's return value is the propagation under test.
type directRunner struct{}

func (directRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	return operation(ctx)
}

func TestRunHandsBackTheOperationsOwnError(t *testing.T) {
	runner := NewRunner(alwaysReadyGate{}, directRunner{})

	// ANCHOR: an operation that succeeds must return nil. Without it a Run that returned the
	// sentinel unconditionally would satisfy the row below.
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("anchor: Run over a succeeding operation = %v, want nil — the row below would prove nothing", err)
	}

	// GATE: the operation's own error must come back, by identity and not merely as "some error".
	// A wrapper that substituted its own error would still be non-nil here, and the coordinator
	// branches on errors.Is(err, envelope.ErrInvalidEnvelope) to tell a tampered envelope from an
	// unreachable card — so an error that is non-nil but not THIS one is already the defect.
	sentinel := errors.New("the operation refused its input")
	err := runner.Run(context.Background(), func(context.Context) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run over a failing operation = %v, want the operation's own error — with the "+
			"propagation removed this returns nil, and the coordinator reports a tampered envelope "+
			"as INTERNAL/\"empty-output\" instead of INVALID_ARGUMENT/\"integrity-failed\"", err)
	}
}
