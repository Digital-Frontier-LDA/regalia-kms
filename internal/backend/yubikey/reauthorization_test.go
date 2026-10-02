package yubikey

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// removableCard is a YubiKey that can be pulled. While it is gone the driver cannot open it; a
// session opened before it left answers nothing afterwards.
type removableCard struct {
	fakeSession
	gone         bool
	failSign     error // the card is there and refuses the request
	pullOnSign   bool  // the card is pulled while it signs
	closeErr     error
	panicOnSign  bool
	identityRead int
	// leaves pulls the card when the named call is made on an open session.
	leaves string
}

func (card *removableCard) Policies(ctx context.Context, slot string) (string, string, error) {
	if card.leaves == "policies" {
		card.gone = true
		return "", "", errors.New("the card was removed")
	}
	return card.fakeSession.Policies(ctx, slot)
}
func (card *removableCard) PINRetries(ctx context.Context) (int, error) {
	if card.leaves == "retries" {
		card.gone = true
		return 0, errors.New("the card was removed")
	}
	return card.fakeSession.PINRetries(ctx)
}

func (card *removableCard) Open(context.Context, string) (Session, error) {
	if card.gone {
		return nil, errors.New("no card with that serial")
	}
	return card, nil
}
func (*removableCard) Ready(context.Context) bool { return true }
func (card *removableCard) Identity(context.Context) (string, error) {
	card.identityRead++
	if card.leaves == "identity" {
		card.gone = true
	}
	if card.gone {
		return "", errors.New("the card was removed")
	}
	return card.serial, nil
}
func (card *removableCard) Sign(ctx context.Context, slot, algorithm string, payload []byte) ([]byte, error) {
	switch {
	case card.panicOnSign:
		panic("card library")
	case card.pullOnSign:
		card.gone = true
		return nil, errors.New("the card was removed")
	case card.failSign != nil:
		return nil, card.failSign
	}
	return card.fakeSession.Sign(ctx, slot, algorithm, payload)
}
func (card *removableCard) Close() error { return card.closeErr }

type leaseGate struct {
	admitted    bool
	requestedMs int64
}

func (gate *leaseGate) RequestedAfter(_ context.Context, boottimeMs int64) bool {
	return gate.admitted && gate.requestedMs > boottimeMs
}

type reauthWorld struct {
	t        *testing.T
	card     *removableCard
	gate     *leaseGate
	now      int64
	provider *Provider
}

// newReauthWorld is a daemon started at boot-clock 1000 on a node whose lease was asked for at
// 1500: after the start, so the card serves.
func newReauthWorld(t *testing.T) *reauthWorld {
	t.Helper()
	w := &reauthWorld{t: t, now: 1_000, gate: &leaseGate{admitted: true, requestedMs: 1_500},
		card: &removableCard{fakeSession: fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}}}
	provider, err := New(w.card, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RequireReauthorization(w.gate, func() (int64, error) { return w.now, nil }, w.now); err != nil {
		t.Fatal(err)
	}
	w.provider = provider
	return w
}

func (w *reauthWorld) sign() error {
	w.t.Helper()
	_, _, err := w.provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	return err
}

func (w *reauthWorld) healthy() bool {
	return w.provider.Healthy(context.Background(), route().Binding)
}

// requireServing fails unless the card signs, is healthy and nothing is listed as waiting.
func (w *reauthWorld) requireServing(when string) {
	w.t.Helper()
	if err := w.sign(); err != nil {
		w.t.Fatalf("%s: the card does not sign: %v", when, err)
	}
	if !w.healthy() || len(w.provider.AwaitingReauthorization()) != 0 {
		w.t.Fatalf("%s: healthy=%v awaiting=%v", when, w.healthy(), w.provider.AwaitingReauthorization())
	}
}

// requireWaiting fails if the card signs, presents its PIN, or reports healthy.
func (w *reauthWorld) requireWaiting(when string, since int64) {
	w.t.Helper()
	logins := w.card.loginCalls
	if err := w.sign(); err == nil {
		w.t.Fatalf("%s: the card signed", when)
	}
	if w.card.loginCalls != logins {
		w.t.Fatalf("%s: the PIN was presented to a card that is waiting", when)
	}
	if w.healthy() {
		w.t.Fatalf("%s: the card reports healthy", when)
	}
	if want := map[string]int64{route().Binding.DeviceID: since}; !reflect.DeepEqual(w.provider.AwaitingReauthorization(), want) {
		w.t.Fatalf("%s: awaiting %v, want %v", when, w.provider.AwaitingReauthorization(), want)
	}
}

func TestAfterTheDaemonStartsACardServesOnlyUnderALeaseAskedForSince(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 900 // the lease the node held before this process started
	w.requireWaiting("under the lease held before the start", 1_000)
	if _, _, err := w.provider.Execute(context.Background(), route(), "public-key", "", "", nil, nil); err == nil {
		t.Fatal("the public key was served by a card that is waiting: every operation waits, not only those that log in")
	}
	w.gate.requestedMs = 1_001
	w.requireServing("under a lease asked for after the start")
}

func TestACardThatCouldNotBeOpenedWaitsForALeaseAskedForAfterItsReturn(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the card is pulled")
	w.card.gone = true
	w.now = 2_000
	if w.sign() == nil {
		t.Fatal("a card that is gone signed")
	}
	if want := map[string]int64{route().Binding.DeviceID: -1}; !reflect.DeepEqual(w.provider.AwaitingReauthorization(), want) {
		t.Fatalf("awaiting %v, want the card listed as gone", w.provider.AwaitingReauthorization())
	}
	w.card.gone = false
	w.now = 3_000
	w.requireWaiting("back, under the lease held before it left", 3_000)
	w.gate.requestedMs = 2_500
	w.requireWaiting("back, under a lease asked for while it was away", 3_000)
	w.gate.requestedMs = 3_001
	w.requireServing("under a lease asked for after its return")
}

func TestTheHealthCheckAloneNoticesAnAbsence(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the card is pulled")
	w.card.gone = true
	if w.healthy() {
		t.Fatal("a card that is gone reports healthy")
	}
	w.card.gone = false
	w.now = 3_000
	w.requireWaiting("back after an absence only the health check saw", 3_000)
}

// The health check opens the card and asks three things of it. A card pulled at any of them is
// back before the next look, so no Open fails: each must be seen as the absence it is.
func TestACardPulledDuringAHealthCheckWaitsAlthoughTheNextOpenSucceeds(t *testing.T) {
	for _, call := range []string{"identity", "policies", "retries"} {
		w := newReauthWorld(t)
		w.requireServing(call + ": before the card is pulled")
		w.card.leaves = call
		if w.healthy() {
			t.Fatalf("%s: a card pulled during the health check reports healthy", call)
		}
		w.card.leaves, w.card.gone = "", false
		w.now = 3_000
		w.requireWaiting(call+": back after an absence seen only inside a health check", 3_000)
	}
}

// A slot whose policy is not the binding's is a configuration fault on a card that is there.
func TestAPolicyMismatchSeenByTheHealthCheckIsNotAnAbsence(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before")
	w.card.pinPolicy = "always"
	if w.healthy() {
		t.Fatal("setup: a slot with another PIN policy should be unhealthy")
	}
	w.card.pinPolicy = "once"
	w.requireServing("after a policy mismatch")
}

func TestACardPulledDuringAnOperationWaitsAlthoughTheNextOpenSucceeds(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the card is pulled")
	w.card.pullOnSign = true
	w.now = 2_000
	if w.sign() == nil {
		t.Fatal("a signature came from a card pulled while signing")
	}
	// It is back before anything opens it again: no Open ever failed.
	w.card.pullOnSign, w.card.gone = false, false
	w.now = 3_000
	w.requireWaiting("back after an absence seen only as a failed signature", 3_000)
	w.gate.requestedMs = 3_001
	w.requireServing("under a lease asked for after its return")
}

// A REQUEST THE CARD REFUSES IS NOT AN ABSENCE. Otherwise any caller who may use a key could take
// the card out of service, for every key on it, with one request the card will not perform.
func TestARefusedRequestDoesNotTakeTheCardOutOfService(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the refused request")
	w.card.failSign = errors.New("the payload is not what this key type is sent")
	reads := w.card.identityRead
	if w.sign() == nil {
		t.Fatal("setup: the request should be refused")
	}
	if w.card.identityRead != reads+2 {
		t.Fatalf("the card was asked for its serial %d times, want 2: once to identify it and once after the failure", w.card.identityRead-reads)
	}
	w.card.failSign = nil
	w.requireServing("after a request the card refused")
}

func TestARefusedPINDoesNotCountAsAnAbsence(t *testing.T) {
	w := newReauthWorld(t)
	w.card.loginErr = errors.New("bad PIN")
	if w.sign() == nil {
		t.Fatal("setup: the PIN should be refused")
	}
	if waiting := w.provider.AwaitingReauthorization(); len(waiting) != 0 {
		t.Fatalf("a refused PIN marked the card as gone or waiting: %v", waiting)
	}
}

func TestASessionThatWillNotCloseOrPanicsMarksTheCardGone(t *testing.T) {
	for name, arrange := range map[string]func(*removableCard){
		"close fails": func(card *removableCard) { card.closeErr = errors.New("still connected") },
		"panic":       func(card *removableCard) { card.panicOnSign = true },
	} {
		w := newReauthWorld(t)
		w.requireServing(name + ": before")
		arrange(w.card)
		if w.sign() == nil {
			t.Fatalf("%s: the operation succeeded", name)
		}
		w.card.closeErr, w.card.panicOnSign = nil, false
		w.now = 3_000
		w.requireWaiting(name+": afterwards", 3_000)
	}
}

func TestWithoutReauthorizationAReturnedCardResumesAsBefore(t *testing.T) {
	card := &removableCard{fakeSession: fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}}
	provider, err := New(card, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	sign := func() error {
		_, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
		return err
	}
	card.gone = true
	if sign() == nil {
		t.Fatal("a card that is gone signed")
	}
	card.gone = false
	if err := sign(); err != nil {
		t.Fatalf("with no admission gate a returned card must resume: %v", err)
	}
}
