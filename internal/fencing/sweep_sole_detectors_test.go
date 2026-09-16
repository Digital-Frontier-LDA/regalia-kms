package fencing

// SOLE-DETECTORS for constructor-nil refusal guards the 2026-09-07 sweep of
// internal/fencing left UNCOVERED. The two `Open` constructors each carry
// a six-operand validation chain whose only realistic sole-detector fixtures
// are the kind each test below provides: every OTHER operand valid, only the
// operand under test violated.
//
// Why each is the sole-detector and not a contributor to the existing
// table-driven test:
//
//   - The existing TestGateGoRefusesInvalidConfiguration (gate.go) and
//     TestStandbyRefusesIncompleteConfigurationImmediately (standby.go) walk
//     five distinct fixtures — each with one operand empty — and assert
//     `err != nil`. Mutation under any one operand of those five swaps
//     which sibling fires, but the test stays green because the message is
//     the same. The five siblings are covered-but-vague; this is a known
//     weakness of the table-driven shape but is NOT a coverage gap the
//     measure is hiding.
//
//   - The now==nil operand is the one the table-driven tests do NOT
//     exercise at all — its fixture is `now == nil` rather than an empty
//     string, and the existing tables do not construct that fixture. The
//     mutation measure finds it SURVIVOR for a different reason: no test
//     ever sets the clock to nil, so the operand is silently absent.
//
// Runner.go:26 carries a four-operand guard `runner == nil || runner.gate
// == nil || runner.runner == nil || !runner.gate.Ready(ctx)`. The fourth
// operand is covered by the existing TestFencedRunnerChecksLeaseBeforeHardware
// and TestFencedRunnerRecoversLeaseMidFlight. The first (`runner == nil`,
// the receiver) is §17 — NewRunner always returns a non-nil *FencedRunner,
// and no public path can construct a nil receiver. The second and third
// (runner.gate and runner.runner) are reachable via NewRunner(nil, _)
// and NewRunner(_, nil) respectively, and the only test that would pin
// them is one with a nil-fixture. Both tests below provide that fixture.
//
// The §18 anchors (the fully-valid call in each test) distinguish
// "the constructor refused what we asked it to refuse" from "the
// constructor refuses every input" — the latter would also leave the row
// green, and a future regression that hardens the constructor into
// "return an error for any input" would pass without the anchor.
//
// THREE OF THE FOUR ROWS PANIC ON MUTATION, AND THE WRAP IS NOT
// DECORATIVE. The first three rows (Open / FencedRunner.Run with nil
// gate / FencedRunner.Run with nil runner) panic when the targeted
// operand is removed: the operand stops a nil value from reaching an
// inner call, and without it the inner call dereferences nil and aborts
// the test binary. Without `recoveredPanic`, an unrecovered panic names
// the panic site — MEASURED by re-running each mutation against a probe
// that does NOT recover: gate.go:98 (the `gate.now()` call inside
// refreshLocked) for the clock, runner.go:26 for runner.gate.Ready, and
// runner.go:29 (the `runner.runner.Run` CALL, not the guard line) for the
// inner runner — not the operand under test, and the failing
// set after a panic is a LOWER BOUND — anything that would have run
// after did not. The recoveredPanic helper turns the same defect into a
// single `--- FAIL: TestXxx` line whose fatal names the operand, which
// is what the falsification claim ("the test fails on its targeted
// operand") needs to be true. Measured; see each test's "Falsifier"
// comment for the actual failing output pasted below.
//
// THE FOURTH ROW (TestNewStandbyRefusesANilClock) DOES NOT PANIC.
// NewStandby captures `now` in a closure at standby.go:40 and only
// invokes it at acquire() when the standby becomes active. The mutation
// makes the constructor return a valid Standby with nil error, and the
// row's first assertion catches the missing error — there is no panic
// to recover.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// recoveredPanic runs call and returns whatever it panicked with, or nil.
// See the file preamble for why three of the four tests below need this.
func recoveredPanic(call func()) (recovered any) {
	defer func() { recovered = recover() }()
	call()
	return recovered
}

// notReadyGate is a LeaseHolder whose Ready returns false. Used as the
// §18 anchor for TestFencedRunnerWithANilGateReturnsErrFenced: with a
// real (non-nil) gate that reports not ready, Run returns ErrFenced and
// does NOT panic.
//
// It does NOT pin the fourth operand of runner.go:26. That was measured,
// not assumed: neutralising `!runner.gate.Ready(ctx)` to
// `(false && !runner.gate.Ready(ctx))` leaves that anchor GREEN, because
// the inner re-check at runner.go:30 returns ErrFenced for the same
// fixture — two guards, one outcome. The mutation reds
// TestFencedRunnerChecksLeaseBeforeHardware and
// TestFencedRunnerRecoversLeaseMidFlight instead; those are the tests
// that pin the fourth operand.
type notReadyGate struct{}

func (notReadyGate) Ready(context.Context) bool { return false }

// TestOpenRefusesANilClock is the sole-detector for the now==nil operand of
// gate.go:64. The five siblings (leasePath=="", statePath=="", site=="",
// registryDigest=="", len(publicKey)!=ed25519.PublicKeySize) are exercised
// by TestGateGoRefusesInvalidConfiguration at sweep_uncovered_test.go:75
// — the existing tests are covered-but-vague. The now==nil operand is the
// one no test reaches.
//
// Falsifier (replace the `now == nil` check with `false && (now == nil)`).
// Measured output:
//
//	--- FAIL: TestOpenRefusesANilClock (0.00s)
//	    sweep_sole_detectors_test.go:160: Open with a nil clock panicked
//	    (runtime error: invalid memory address or nil pointer dereference)
//	    instead of refusing — the now == nil operand at gate.go:64 is what
//	    stops Open reaching gate.now() at gate.go:98; without it the nil
//	    func is called and the daemon aborts inside a fencing decision
//	FAIL
//	(the t.Fatalf body is ONE line in the real output; wrapped here only)
//
// Without `recoveredPanic` the same defect produces a Go-runtime panic stack
// pointing at gate.go:98 (the gate.now() call site inside refreshLocked)
// and the §18 anchor below never runs — the failing set is a lower bound.
// The recovered fatal names the operand under test (gate.go:64) AND the
// inner call site (gate.go:98), and the consequence spelled in the message
// is what removing the guard does in production.
func TestOpenRefusesANilClock(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("fixture: ed25519.GenerateKey: %v", err)
	}
	// The fixture must assert its own shape. If a future change replaces
	// `ed25519.GenerateKey` with another key source that returns a wrong-
	// length slice (the package's contract says 32, but a handcrafted test
	// key or an alternate constructor could differ), the row would trip
	// `len(publicKey) != ed25519.PublicKeySize` at gate.go:64 INSTEAD OF
	// `now == nil`, and the row would silently pin the sibling rather than
	// the operand it is named against.
	if len(public) != ed25519.PublicKeySize {
		t.Fatalf("fixture: public key is %d bytes, want %d — a wrong-length key trips the "+
			"len(publicKey) != ed25519.PublicKeySize operand of the SAME guard and would "+
			"pin that instead of now == nil", len(public), ed25519.PublicKeySize)
	}

	var (
		gate    *Gate
		openErr error
	)
	if recovered := recoveredPanic(func() {
		gate, openErr = Open(
			filepath.Join(privateTempDir(t), "lease.json"),
			filepath.Join(privateTempDir(t), "state.jsonl"),
			"sitea",
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			public,
			nil,
		)
	}); recovered != nil {
		t.Fatalf("Open with a nil clock panicked (%v) instead of refusing — the now == nil "+
			"operand at gate.go:64 is what stops Open reaching gate.now() at gate.go:98; "+
			"without it the nil func is called and the daemon aborts inside a fencing decision",
			recovered)
	}
	if gate != nil || openErr == nil || openErr.Error() != "invalid fencing configuration" {
		t.Fatalf("Open with nil clock: want (nil, errors.New('invalid fencing configuration')) from "+
			"gate.go:64, got (%v, %v)", gate, openErr)
	}

	// §18 control — Open with valid paths + non-nil clock against an empty temp dir.
	// MEASURED on unmodified source: Open returns exactly (nil, ErrFenced) — no lease
	// file exists, so refreshLocked reports not-held — and NOT "invalid fencing
	// configuration".
	//
	// The assertion pins that whole tuple, not just the refusal message. A check of
	// the form `control.Error() == "invalid fencing configuration"` would stay green
	// if Open returned (nil, nil) or any other error, which are precisely the two
	// regressions that would make the row above stop meaning what it says: a nil
	// error means Open no longer fences an unleased site, and a different error
	// means the row's refusal is no longer distinguishable from Open's normal
	// failure mode.
	//
	// The anchor was falsified, and the message-only form was measured blind to
	// the same defect. Mutating `!gate.refreshLocked(...)` to
	// `false && !gate.refreshLocked(...)` makes Open hand back a live *Gate and
	// a nil error for an unleased site. Measured, with the *Gate dump elided:
	//
	//	--- FAIL: TestOpenRefusesANilClock (0.00s)
	//	    sweep_sole_detectors_test.go:207: control: Open with a non-nil
	//	    clock and valid paths = (&{...}, <nil>), want (nil, ErrFenced) — ...
	//
	// Against that same mutation a probe evaluating the pre-fix form
	// (`control != nil && control.Error() == "invalid fencing configuration"`)
	// reported `OLD form fires? false | NEW form fires? true`: with a nil error
	// the old form never reached its second operand. The row's own assertion
	// still passes under it — the run reds HERE, so only this anchor catches it.
	directory := privateTempDir(t)
	controlGate, controlErr := Open(
		filepath.Join(directory, "lease.json"),
		filepath.Join(directory, "state.jsonl"),
		"sitea",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		public,
		time.Now,
	)
	if controlGate != nil || !errors.Is(controlErr, ErrFenced) {
		t.Fatalf("control: Open with a non-nil clock and valid paths = (%v, %v), want (nil, ErrFenced) "+
			"— on an empty directory Open must get past the gate.go:64 validity chain and refuse for "+
			"want of a lease. \"invalid fencing configuration\" here means every path through Open is "+
			"a configuration error and the row above is green-on-broken; a nil error means Open "+
			"stopped fencing an unleased site", controlGate, controlErr)
	}
}

// TestNewStandbyRefusesANilClock is the sole-detector for the now==nil
// operand of standby.go:36. Same six-operand chain as gate.go:64; same
// coverage-but-vague pattern for the other five siblings.
//
// NewStandby does NOT call now() — it captures it in a closure (standby.go:40)
// and the closure runs only at acquire() when the standby becomes active.
// The mutation makes the constructor return a valid *Standby with nil error;
// the row's first assertion catches the missing error; no panic to recover.
//
// Falsifier (replace the `now == nil` check with `false && (now == nil)`).
// Measured output:
//
//	--- FAIL: TestNewStandbyRefusesANilClock (0.00s)
//	    sweep_sole_detectors_test.go:259: NewStandby with nil clock: want
//	    (nil, errors.New('invalid fencing configuration')) from
//	    standby.go:36, got (&{{{} {0 0}} <nil> 0x104ad2770}, <nil>)
//	FAIL
//	(one line in the real output; wrapped here. The closure address varies.)
//
// The fatal names the operand (standby.go:36) and shows the wrong return
// tuple directly — a *Standby whose `open` closure was wired up with the
// nil clock, paired with a nil error. Without the guard the standby
// would later panic at acquire(), but at construction time the refusal
// is the only signal the operator gets.
func TestNewStandbyRefusesANilClock(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("fixture: ed25519.GenerateKey: %v", err)
	}
	if len(public) != ed25519.PublicKeySize {
		t.Fatalf("fixture: public key is %d bytes, want %d — a wrong-length key trips the "+
			"len(publicKey) != ed25519.PublicKeySize operand of the SAME guard and would pin "+
			"that instead of now == nil", len(public), ed25519.PublicKeySize)
	}

	standby, err := NewStandby(
		filepath.Join(privateTempDir(t), "lease.json"),
		filepath.Join(privateTempDir(t), "state.jsonl"),
		"sitea",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		public,
		nil,
	)
	if standby != nil || err == nil || err.Error() != "invalid fencing configuration" {
		t.Fatalf("NewStandby with nil clock: want (nil, errors.New('invalid fencing configuration')) "+
			"from standby.go:36, got (%v, %v)", standby, err)
	}
	// §18 control — non-nil clock + valid paths. MEASURED on unmodified source:
	// NewStandby returns (non-nil *Standby, nil) — the `open` closure is wired
	// but not yet called, and the standby reports Ready()==false until it
	// acquires.
	//
	// The assertion pins BOTH halves of that tuple. A message-only check would
	// stay green if NewStandby returned (nil, some other error), which is the
	// same regression seen from a different angle: the validity chain at
	// standby.go:36 refusing valid input. The row above only ever passes an
	// INVALID clock, so it cannot notice that on its own. It also pins the
	// *Standby half of the tuple, which the pre-fix form discarded with `_`.
	//
	// Anchor falsified by inverting a sibling operand
	// (`registryDigest == ""` -> `registryDigest != ""`, i.e. NewStandby
	// refuses everything). Measured:
	//
	//	--- FAIL: TestNewStandbyRefusesANilClock (0.00s)
	//	    sweep_sole_detectors_test.go:296: control: NewStandby with a
	//	    non-nil clock and valid paths = (<nil>, invalid fencing
	//	    configuration), want (non-nil *Standby, nil) — ...
	//
	// The row's own assertion still passes under that mutation — it asks for a
	// refusal and gets one, and the run reds HERE instead. Only the anchor
	// separates "refused the nil clock" from "refuses everything".
	directory := privateTempDir(t)
	controlStandby, controlErr := NewStandby(
		filepath.Join(directory, "lease.json"),
		filepath.Join(directory, "state.jsonl"),
		"sitea",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		public,
		time.Now,
	)
	if controlStandby == nil || controlErr != nil {
		t.Fatalf("control: NewStandby with a non-nil clock and valid paths = (%v, %v), want "+
			"(non-nil *Standby, nil) — standby.go:36 is now refusing configuration it must accept, "+
			"so the row above is passing for a reason other than the now == nil operand",
			controlStandby, controlErr)
	}
}

// TestFencedRunnerWithANilGateReturnsErrFenced is the sole-detector for the
// runner.gate==nil operand of runner.go:26. NewRunner(nil, directRunner{})
// returns a non-nil *FencedRunner whose gate field is nil — reachable from
// the public path because NewRunner accepts an interface. Without the guard,
// Run falls through to `runner.gate.Ready(ctx)` on a nil interface and
// panics. The fourth operand `!runner.gate.Ready(ctx)` is covered by the
// existing TestFencedRunnerChecksLeaseBeforeHardware and
// TestFencedRunnerRecoversLeaseMidFlight; the receiver-nil guard is §17.
//
// Falsifier (replace `runner.gate == nil` with `false && (runner.gate ==
// nil)`). Measured output:
//
//	--- FAIL: TestFencedRunnerWithANilGateReturnsErrFenced (0.00s)
//	    sweep_sole_detectors_test.go:334: FencedRunner.Run panicked with a
//	    nil gate (runtime error: invalid memory address or nil pointer
//	    dereference) instead of returning ErrFenced — the runner.gate ==
//	    nil operand at runner.go:26 is what stops Run reaching
//	    runner.gate.Ready on a nil interface; without it the daemon aborts
//	    on the first fencing decision
//	FAIL
//
// Without `recoveredPanic` the same defect produces a Go-runtime panic stack
// pointing at the runner.gate.Ready call site, and the §18 anchor below
// never runs. The recovered fatal names the operand (runner.go:26) and the
// inner call.
func TestFencedRunnerWithANilGateReturnsErrFenced(t *testing.T) {
	var err error
	if recovered := recoveredPanic(func() {
		fr := NewRunner(nil, directRunner{})
		err = fr.Run(context.Background(), func(context.Context) error { return nil })
	}); recovered != nil {
		t.Fatalf("FencedRunner.Run panicked with a nil gate (%v) instead of returning ErrFenced — "+
			"the runner.gate == nil operand at runner.go:26 is what stops Run reaching "+
			"runner.gate.Ready on a nil interface; without it the daemon aborts on the first "+
			"fencing decision", recovered)
	}
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("FencedRunner.Run with nil gate = %v, want ErrFenced — runner.go:26 caught it", err)
	}
	// §18 control — a non-nil gate that reports not ready, against the same
	// directRunner{} fixture. MEASURED on unmodified source: Run returns
	// ErrFenced and does NOT panic.
	//
	// WHAT IT PROVES: the recovered panic above is attributable to the NIL gate
	// specifically, not to the FencedRunner fixture shape — swap only the gate
	// for a non-nil one and the same call is orderly. Without it the row above
	// would also be satisfied by a Run that panics on every input.
	//
	// WHAT IT DOES NOT PROVE — measured, not reasoned. It does NOT pin the
	// fourth operand `!runner.gate.Ready(ctx)`: neutralising that operand to
	// `(false && !runner.gate.Ready(ctx))` leaves this control GREEN, because
	// the inner re-check at runner.go:30 returns ErrFenced for the same
	// fixture. That mutation reds TestFencedRunnerChecksLeaseBeforeHardware and
	// TestFencedRunnerRecoversLeaseMidFlight instead. Nor does it prove Run is
	// not hard-coded to `return ErrFenced` — this control EXPECTS ErrFenced;
	// the control in TestFencedRunnerWithANilRunnerReturnsErrFenced, which
	// requires a NIL return from a fully-valid runner, is what pins that.
	if recovered := recoveredPanic(func() {
		notReady := NewRunner(notReadyGate{}, directRunner{})
		err = notReady.Run(context.Background(), func(context.Context) error { return nil })
	}); recovered != nil {
		t.Fatalf("control: FencedRunner.Run with a not-ready gate panicked (%v) — the "+
			"runner.gate.Ready branch of runner.go:26 is now dead, and the row above would "+
			"be green-on-broken", recovered)
	}
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("control: FencedRunner.Run with a not-ready gate = %v, want ErrFenced", err)
	}
}

// TestFencedRunnerWithANilRunnerReturnsErrFenced is the sole-detector for the
// runner.runner==nil operand of runner.go:26. Symmetric to the gate test:
// NewRunner(alwaysReadyGate{}, nil) returns a non-nil *FencedRunner whose
// inner runner field is nil. Without the guard, Run calls runner.runner.Run
// at runner.go:29 on a nil interface and panics.
//
// Falsifier (replace `runner.runner == nil` with `false && (runner.runner ==
// nil)`). Measured output:
//
//	--- FAIL: TestFencedRunnerWithANilRunnerReturnsErrFenced (0.00s)
//	    sweep_sole_detectors_test.go:397: FencedRunner.Run panicked with a
//	    nil runner (runtime error: invalid memory address or nil pointer
//	    dereference) instead of returning ErrFenced — the runner.runner ==
//	    nil operand at runner.go:26 is what stops Run reaching
//	    runner.runner.Run at runner.go:29 on a nil interface; without it
//	    the daemon aborts when the first fenced operation runs
//	FAIL
//	(the t.Fatalf body is ONE line in the real output; wrapped here only)
func TestFencedRunnerWithANilRunnerReturnsErrFenced(t *testing.T) {
	var err error
	if recovered := recoveredPanic(func() {
		fr := NewRunner(alwaysReadyGate{}, nil)
		err = fr.Run(context.Background(), func(context.Context) error { return nil })
	}); recovered != nil {
		t.Fatalf("FencedRunner.Run panicked with a nil runner (%v) instead of returning ErrFenced — "+
			"the runner.runner == nil operand at runner.go:26 is what stops Run reaching "+
			"runner.runner.Run at runner.go:29 on a nil interface; without it the daemon aborts "+
			"when the first fenced operation runs", recovered)
	}
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("FencedRunner.Run with nil runner = %v, want ErrFenced — runner.go:26 caught it", err)
	}
	// §18 control — Run on a fully-valid FencedRunner returns nil from a
	// succeeding operation. MEASURED on unmodified source: nil.
	//
	// This is the only anchor in the file that requires a NON-ErrFenced return,
	// so it is the one that forecloses `return ErrFenced` at the top of Run:
	// that regression would satisfy all four rows above and pin nothing about
	// runner.runner==nil specifically.
	//
	// Falsified by hard-coding exactly that (`if runner == nil ||` ->
	// `if true || runner == nil ||`, so Run returns ErrFenced for every input).
	// Measured: of the four rows in this file only THIS one reds, and it reds
	// here at the anchor, not at the row's own assertion —
	//
	//	--- FAIL: TestFencedRunnerWithANilRunnerReturnsErrFenced (0.00s)
	//	    sweep_sole_detectors_test.go:425: control: FencedRunner.Run with
	//	    real leaseHolder + real runner = KMS site is fenced, want nil — ...
	//
	// which is the claim in the file preamble, measured rather than assumed.
	fr2 := NewRunner(alwaysReadyGate{}, directRunner{})
	if err := fr2.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("control: FencedRunner.Run with real leaseHolder + real runner = %v, want nil — "+
			"the row above would pass against a Run that always errors, and that is not the "+
			"assertion we are trying to make", err)
	}
}
