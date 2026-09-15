package server

import (
	"context"
	"testing"
	"time"
)

// READINESS COMPOSITION DECIDES WHETHER THE DAEMON SERVES, AND NOTHING EXERCISED IT.
//
// RequireAll is what main.go wraps the RBAC policy and the policy engine in, and every
// branch of it was uncovered. Each branch is a fail-closed guard, which is the kind that
// costs nothing while it works, and costs everything on the single occasion it does not: this repository
// has already shipped a registry loaded with a nil backend-health probe that denied every
// object while the daemon reported itself ready, and a fencing probe that was attached and
// never read so a passive site said READY. Both were compositions nobody had asserted.

type stubProbe struct {
	ready bool
	block time.Duration
}

func (probe stubProbe) Ready(ctx context.Context) bool {
	if probe.block > 0 {
		select {
		case <-time.After(probe.block):
		case <-ctx.Done():
			return false
		}
	}
	return probe.ready
}

func TestRequireAllIsReadyOnlyWhenEveryProbeIs(t *testing.T) {
	for _, test := range []struct {
		name   string
		probes []ReadinessProbe
		want   bool
		why    string
	}{
		{"no probes at all", nil, false,
			"an empty composition must not be ready: a daemon wired with nothing would report itself healthy"},
		{"an explicitly empty list", []ReadinessProbe{}, false,
			"same as nil — RequireAll() with no arguments is a configuration mistake, not a green light"},
		{"a single nil probe", []ReadinessProbe{nil}, false,
			"a nil probe is an unwired dependency, which is exactly the shape of the nil BackendHealth defect"},
		{"one ready probe", []ReadinessProbe{stubProbe{ready: true}}, true,
			"the positive control: without it every assertion here passes on a composition that is never ready"},
		{"every probe ready", []ReadinessProbe{stubProbe{ready: true}, stubProbe{ready: true}}, true, ""},
		{"one of two not ready", []ReadinessProbe{stubProbe{ready: true}, stubProbe{ready: false}}, false,
			"ALL means all"},
		{"the unready probe first", []ReadinessProbe{stubProbe{ready: false}, stubProbe{ready: true}}, false,
			"order must not decide the answer"},
		{"a nil probe beside ready ones", []ReadinessProbe{stubProbe{ready: true}, nil}, false,
			"an unwired dependency next to working ones must still refuse"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := RequireAll(test.probes...).Ready(context.Background()); got != test.want {
				t.Fatalf("RequireAll(%s).Ready() = %v, want %v — %s", test.name, got, test.want, test.why)
			}
		})
	}
}

// The caller's slice must not be able to change the composition afterwards. RequireAll
// copies, and if it stopped copying a caller reusing its slice would silently repoint a
// live readiness gate at different probes.
func TestRequireAllCopiesTheProbesItWasGiven(t *testing.T) {
	probes := []ReadinessProbe{stubProbe{ready: true}}
	composed := RequireAll(probes...)
	probes[0] = stubProbe{ready: false}
	if !composed.Ready(context.Background()) {
		t.Fatal("DEFECT: mutating the caller's slice changed an already-composed readiness gate — " +
			"a live gate can be repointed by code that has no idea it holds one")
	}
}

// A cancelled context must not read as ready. A probe that blocks past cancellation is what
// a hung dependency looks like, and reporting ready through it is how a wedged daemon stays
// in a load balancer.
func TestRequireAllRefusesWhenTheContextIsAlreadyDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The block is short on purpose. If the probe ever regresses to ignore ctx.Done() this
	// test still fails, but in milliseconds rather than stalling the suite for a minute --
	// and a slow suite is one people stop running, which is its own way of losing a check.
	// The context is already cancelled, so the select resolves immediately either way.
	if RequireAll(stubProbe{ready: true, block: 50 * time.Millisecond}).Ready(ctx) {
		t.Fatal("DEFECT: a cancelled context reported ready through a blocking probe — a hung " +
			"dependency would keep the daemon in service")
	}
}

type panickingProbe struct{}

func (panickingProbe) Ready(context.Context) bool { panic("the dependency exploded") }

// probeReady recovers from a panicking probe and reports not-ready. That recovery existed
// and nothing exercised it, so the question of which way it failed was open: a panic that
// propagated would take down the readiness handler, and one that was swallowed into `true`
// would be worse than either.
func TestAPanickingProbeIsNotReadyAndDoesNotEscape(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("DEFECT: a panicking probe escaped the readiness check (%v) — one broken "+
				"dependency takes down the endpoint that reports on all of them", recovered)
		}
	}()
	if RequireAll(stubProbe{ready: true}, panickingProbe{}).Ready(context.Background()) {
		t.Fatal("DEFECT: a probe that panicked was counted as ready")
	}
}
