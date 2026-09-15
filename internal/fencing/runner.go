package fencing

import "context"

type Runner interface {
	Run(context.Context, func(context.Context) error) error
}

// LeaseHolder answers whether this site may act right now. It is an interface rather than *Gate so
// a standby — a site that does not hold the lease yet and must become able to act without a restart
// — can be fenced by the same runner.
type LeaseHolder interface {
	Ready(context.Context) bool
}

type FencedRunner struct {
	gate   LeaseHolder
	runner Runner
}

func NewRunner(gate LeaseHolder, runner Runner) *FencedRunner {
	return &FencedRunner{gate: gate, runner: runner}
}

func (runner *FencedRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	if runner == nil || runner.gate == nil || runner.runner == nil || !runner.gate.Ready(ctx) {
		return ErrFenced
	}
	return runner.runner.Run(ctx, func(operationCtx context.Context) error {
		if !runner.gate.Ready(operationCtx) {
			return ErrFenced
		}
		if err := operation(operationCtx); err != nil {
			return err
		}
		// THE LEASE MUST STILL BE HELD WHEN THE RESULT IS HANDED BACK.
		//
		// Both earlier checks happen before the operation starts, and neither can help once it has.
		// An RSA-2048 signature takes about 800ms on this hardware, which is ample room for a lease
		// to expire or be revoked to another site in between — so admission alone would let a site
		// that has already been replaced return a signature it had no authority to produce.
		//
		// The token has signed by this point and that cannot be undone. What can be prevented is
		// PUBLISHING it: the coordinator zeroes the output whenever Run returns an error, so an
		// operation that outlived its lease yields nothing to the caller. The risk that matters is
		// two published signatures, and only the site that still holds the lease produces one.
		if !runner.gate.Ready(operationCtx) {
			return ErrFenced
		}
		return nil
	})
}
