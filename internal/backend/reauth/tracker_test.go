package reauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// lease stands for internal/admission.Gate: the node is admitted, under a lease it asked for at
// requestedMs.
type lease struct {
	admitted    bool
	requestedMs int64
	asked       []int64
	during      func()
	unlisted    map[string]bool // serials the manifest does not list; nil: every serial is listed
	serials     []string        // the serials asked about
}

func (gate *lease) Admits(_ context.Context, serial string, boottimeMs int64) bool {
	gate.serials = append(gate.serials, serial)
	if serial == "" || gate.unlisted[serial] {
		return false
	}
	gate.asked = append(gate.asked, boottimeMs)
	if gate.during != nil {
		gate.during()
	}
	return gate.admitted && gate.requestedMs > boottimeMs
}

type world struct {
	gate     *lease
	now      int64
	clockErr error
	tracker  *Tracker
}

// newWorld starts a process at boot-clock 1000 that holds a lease asked for at 900.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{now: 1_000, gate: &lease{admitted: true, requestedMs: 900}, tracker: &Tracker{}}
	if err := w.tracker.Require(w.gate, func() (int64, error) { return w.now, w.clockErr }, w.now); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestTheZeroTrackerRequiresNothing(t *testing.T) {
	var tracker Tracker
	tracker.Gone("card")
	if !tracker.Serves(context.Background(), "card", "SERIAL1") {
		t.Fatal("a tracker nobody turned on kept a token out")
	}
	if waiting := tracker.Awaiting(); len(waiting) != 0 {
		t.Fatalf("a tracker nobody turned on lists %v", waiting)
	}
}

func TestATokenServesOnlyUnderALeaseAskedForAfterTheProcessStarted(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("served under a lease asked for before the process started")
	}
	if want := map[string]int64{"card": 1_000}; !reflect.DeepEqual(w.tracker.Awaiting(), want) {
		t.Fatalf("awaiting %v, want %v", w.tracker.Awaiting(), want)
	}
	w.gate.requestedMs = 1_000 // asked for AT the start is not after it
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("served under a lease asked for at the very moment of the start")
	}
	w.gate.requestedMs = 1_001
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("refused under a lease asked for after the start")
	}
	if len(w.tracker.Awaiting()) != 0 {
		t.Fatalf("still listed after serving: %v", w.tracker.Awaiting())
	}
	// once vouched for, the token serves under any later lease, and under this one
	w.gate.requestedMs = 5
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a token already serving was held back")
	}
}

func TestATokenThatWasGoneWaitsForALeaseAskedForAfterItWasSeenBack(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.gate.requestedMs = 1_500
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("setup: the token should serve")
	}
	w.now = 2_000
	w.tracker.Gone("card")
	if want := map[string]int64{"card": -1}; !reflect.DeepEqual(w.tracker.Awaiting(), want) {
		t.Fatalf("awaiting %v, want %v", w.tracker.Awaiting(), want)
	}
	w.now = 3_000 // first seen back now: the return is dated here, not when it left
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a returned token served on the lease held before it left")
	}
	if last := w.gate.asked[len(w.gate.asked)-1]; last != 3_000 {
		t.Fatalf("the gate was asked about %d, want the moment the token was seen back (3000)", last)
	}
	w.gate.requestedMs = 2_500 // asked for while it was away: before the return
	w.now = 3_200
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a returned token served on a lease asked for while it was away")
	}
	if last := w.gate.asked[len(w.gate.asked)-1]; last != 3_000 {
		t.Fatalf("the return moved to %d on a later look; it is dated by the first", last)
	}
	w.gate.requestedMs = 3_001
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("refused under a lease asked for after the return")
	}
	// another device is not affected by this one's absence
	w.tracker.Gone("card")
	if !w.tracker.Serves(ctx, "other", "SERIAL1") {
		t.Fatal("one token's absence kept another out")
	}
}

// No device is nameless. The baseline for a device never seen must not be reachable as a device:
// serving "" once would otherwise mark every device seen later as already vouched for.
func TestTheNamelessDeviceIsNeitherServedNorRecorded(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.gate.requestedMs = 1_500
	if w.tracker.Serves(ctx, "", "SERIAL1") {
		t.Fatal("a device with no name was served")
	}
	w.tracker.Gone("")
	if len(w.tracker.Awaiting()) != 0 {
		t.Fatalf("a device with no name was recorded: %v", w.tracker.Awaiting())
	}
	w.gate.requestedMs = 900 // before the start: a device never seen must still wait
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("after the nameless device was asked about, a device never seen served on a lease from before the start")
	}
	if !w.tracker.Required() || (&Tracker{}).Required() {
		t.Fatal("Required must be true once Require succeeded and false for the zero tracker")
	}
}

func TestANodeThatIsNotAdmittedServesNothing(t *testing.T) {
	w := newWorld(t)
	w.gate.requestedMs, w.gate.admitted = 9_999, false
	if w.tracker.Serves(context.Background(), "card", "SERIAL1") {
		t.Fatal("served on a node that is not admitted")
	}
}

func TestATokenThatLeavesDuringTheCheckStaysMarked(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.gate.requestedMs = 1_500
	w.gate.during = func() { w.tracker.Gone("card") } // it goes while the gate is being asked
	w.tracker.Serves(ctx, "card", "SERIAL1")
	w.gate.during = nil
	if want := map[string]int64{"card": -1}; !reflect.DeepEqual(w.tracker.Awaiting(), want) {
		t.Fatalf("the absence seen during the check was cleared: awaiting %v", w.tracker.Awaiting())
	}
	w.now = 2_000
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("served on the old lease after an absence seen during the check")
	}
}

func TestAnUnreadableBootClockKeepsAReturnedTokenOut(t *testing.T) {
	w := newWorld(t)
	w.gate.requestedMs = 9_999
	w.tracker.Gone("card")
	w.clockErr = errors.New("clock")
	if w.tracker.Serves(context.Background(), "card", "SERIAL1") {
		t.Fatal("served although the return could not be dated")
	}
	w.clockErr = nil
	w.now = 9_000
	if !w.tracker.Serves(context.Background(), "card", "SERIAL1") {
		t.Fatal("refused once the clock reads again and the lease is after the return")
	}
}

// Require starts over: what was seen before is forgotten, and every token is again taken to have
// arrived at the new start. The daemon therefore tells each provider once.
func TestRequireCalledAgainForgetsWhatWasSeen(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.gate.requestedMs = 1_500
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("setup: the token should serve")
	}
	w.tracker.Gone("other")
	w.now = 2_000
	if err := w.tracker.Require(w.gate, func() (int64, error) { return w.now, nil }, 2_000); err != nil {
		t.Fatal(err)
	}
	if len(w.tracker.Awaiting()) != 0 {
		t.Fatalf("marks survived a second Require: %v", w.tracker.Awaiting())
	}
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a token served on a lease asked for before the second start")
	}
}

func TestRequireNeedsItsParts(t *testing.T) {
	gate, clock := &lease{}, func() (int64, error) { return 1_000, nil }
	for name, call := range map[string]func() error{
		"no gate":  func() error { return (&Tracker{}).Require(nil, clock, 1_000) },
		"no clock": func() error { return (&Tracker{}).Require(gate, nil, 1_000) },
		"clock fails": func() error {
			return (&Tracker{}).Require(gate, func() (int64, error) { return 0, errors.New("x") }, 1_000)
		},
		"start is zero":       func() error { return (&Tracker{}).Require(gate, clock, 0) },
		"start in the future": func() error { return (&Tracker{}).Require(gate, clock, 1_001) },
		"nil tracker":         func() error { return (*Tracker)(nil).Require(gate, clock, 1_000) },
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&Tracker{}).Require(gate, clock, 1_000); err != nil {
		t.Errorf("a start at the present moment was refused: %v", err)
	}
}

// THE SERIAL IS ASKED ON EVERY OPERATION (regalia-kms#72, G1), also once a token serves: a token the
// manifest stops listing is refused at once, and served again when it is listed again.
func TestATokenServesOnlyWhileTheManifestListsIt(t *testing.T) {
	w := newWorld(t)
	w.gate.admitted, w.gate.requestedMs = true, w.now+1
	ctx := context.Background()
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a listed token under a lease asked for since does not serve")
	}
	w.gate.unlisted = map[string]bool{"SERIAL1": true}
	if w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a token de-listed while serving still serves")
	}
	if got := w.gate.serials[len(w.gate.serials)-1]; got != "SERIAL1" {
		t.Fatalf("the gate was asked about %q", got)
	}
	w.gate.unlisted = nil
	if !w.tracker.Serves(ctx, "card", "SERIAL1") {
		t.Fatal("a token listed again does not serve")
	}
	if w.tracker.Serves(ctx, "card", "") {
		t.Fatal("a token with no serial serves")
	}
}
