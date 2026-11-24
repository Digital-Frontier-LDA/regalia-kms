package admission

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// The coordinator's single-node collector requirement (regalia-kms-dx7.9) reads the mode from the
// gate's own answer: a node that stops being admitted must not keep refusing (or serving) on a
// stale mode, and a node never admitted reports none. The Status test holds the admitted answers;
// this holds the rest of the gate's surface.
func TestTheGateReportsTheModeOfItsAnswer(t *testing.T) {
	_, gate, _ := chained(t, membership.ProfileSingleNode, ModeSingle)
	if mode := gate.Mode(context.Background()); mode != ModeSingle {
		t.Fatalf("gate.Mode() = %q, want %q: the coordinator refuses a stateful operation on exactly this reading", mode, ModeSingle)
	}
	if status := gate.Check(context.Background()); status.Admitted && status.Mode != ModeSingle {
		t.Fatalf("status.Mode = %q under an admitted single: the two must agree", status.Mode)
	}
	_, leaseGate, _ := chained(t, membership.ProfileMultiNode, ModeLease)
	if mode := leaseGate.Mode(context.Background()); mode != ModeLease {
		t.Fatalf("gate.Mode() = %q, want %q", mode, ModeLease)
	}
}
