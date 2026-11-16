package operations

import (
	"context"
	"fmt"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// AcknowledgedPolicyState is the policy spend journal as startup checks it (policy.FileState).
type AcknowledgedPolicyState interface {
	RequireAcknowledged(sequence uint64, hash string) error
}

// ReconcilePolicyState refuses to serve a policy spend journal that is behind, or differs from,
// the head the audit collector last acknowledged an operation under (epic #40 gap .1.2, T09).
// Called at startup after audit.ReconcileContinuity, before the coordinator serves anything.
// Every refusal fails closed; an unreachable collector is audit.ErrCollectorUnreachable.
func ReconcilePolicyState(ctx context.Context, state AcknowledgedPolicyState, journalPath string, sink audit.Sink, site string) error {
	position, err := audit.AcknowledgedPolicyPosition(ctx, journalPath, sink, site)
	if err != nil {
		return fmt.Errorf("policy state against the audit collector: %w", err)
	}
	if err := state.RequireAcknowledged(position.Sequence, position.Hash); err != nil {
		return fmt.Errorf("policy state against the audit collector: %w", err)
	}
	return nil
}
