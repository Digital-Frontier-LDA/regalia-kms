package admission

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// The gate's answer carries the MODE it was made under (regalia-kms-dx7.9): the coordinator
// refuses a stateful operation under a single admission while no audit collector is configured,
// and it can only do that if the mode is readable from the same answer it already checks.
func TestStatusCarriesTheAdmissionMode(t *testing.T) {
	for _, c := range []struct{ profile, mode string }{
		{membership.ProfileSingleNode, ModeSingle},
		{membership.ProfileMultiNode, ModeLease},
	} {
		t.Run(c.mode, func(t *testing.T) {
			_, gate, _ := chained(t, c.profile, c.mode)
			status := gate.Check(context.Background())
			if !status.Admitted {
				t.Fatalf("not admitted in mode %s: %s", c.mode, status.Reason)
			}
			if status.Mode != c.mode {
				t.Fatalf("status.Mode = %q, want %q: the coordinator cannot tell a single admission from a peer's", status.Mode, c.mode)
			}
		})
	}
}
