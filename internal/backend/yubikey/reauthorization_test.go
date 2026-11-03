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
	cancelOnSign func() // the caller hangs up while the card signs
	closePanics  bool
	frame        []byte // what Unwrap returns
	unwraps      int
	publicReads  int
	// afterIdentity runs after a successful identity read: a caller hanging up at that moment.
	afterIdentity func()
	identityRead  int
	// leaves pulls the card when the named call is made on an open session.
	leaves string
	// other is the serial of another card that sits where the bound one was.
	other string
	// onOpen runs when the card is opened: a caller hanging up at that moment.
	onOpen func()
	// panicOnIdentity makes the n-th identity read from now panic (1: the next one).
	panicOnIdentity int
}

func (card *removableCard) Policies(ctx context.Context, slot string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
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

func (card *removableCard) Open(ctx context.Context, _ string) (Session, error) {
	// as the PIV driver does: nothing is opened under a context that has ended
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if card.gone {
		return nil, errors.New("no card with that serial")
	}
	if card.onOpen != nil {
		card.onOpen()
	}
	return card, nil
}
func (*removableCard) Ready(context.Context) bool { return true }
func (card *removableCard) Identity(ctx context.Context) (string, error) {
	// as the PIV session does: nothing is done under a context that has ended
	if err := ctx.Err(); err != nil {
		return "", err
	}
	card.identityRead++
	if card.panicOnIdentity > 0 {
		if card.panicOnIdentity--; card.panicOnIdentity == 0 {
			panic("card library")
		}
	}
	if card.leaves == "identity" {
		card.gone = true
	}
	if card.gone {
		return "", errors.New("the card was removed")
	}
	if card.other != "" {
		return card.other, nil
	}
	if card.afterIdentity != nil {
		card.afterIdentity()
	}
	return card.serial, nil
}
func (card *removableCard) Sign(ctx context.Context, slot, algorithm string, payload []byte) ([]byte, error) {
	switch {
	case card.panicOnSign:
		panic("card library")
	case card.cancelOnSign != nil:
		card.cancelOnSign()
		return nil, context.Canceled
	case card.pullOnSign:
		card.gone = true
		return nil, errors.New("the card was removed")
	case card.failSign != nil:
		return nil, card.failSign
	}
	return card.fakeSession.Sign(ctx, slot, algorithm, payload)
}
func (card *removableCard) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	card.unwraps++
	return append([]byte{}, card.frame...), nil
}
func (card *removableCard) PublicKey(ctx context.Context, slot string) ([]byte, error) {
	card.publicReads++
	return card.fakeSession.PublicKey(ctx, slot)
}
func (card *removableCard) Close() error {
	if card.closePanics {
		panic("card library")
	}
	return card.closeErr
}

type leaseGate struct {
	admitted    bool
	requestedMs int64
	unlisted    map[string]bool // serials the manifest does not list; nil: every serial is listed
	serials     []string        // the serials asked about
}

func (gate *leaseGate) Admits(_ context.Context, serial string, boottimeMs int64) bool {
	gate.serials = append(gate.serials, serial)
	if serial == "" || gate.unlisted[serial] {
		return false
	}
	return gate.admitted && gate.requestedMs > boottimeMs
}

type reauthWorld struct {
	t        *testing.T
	card     *removableCard
	gate     *leaseGate
	now      int64
	provider *Provider
	readers  readerGenerations
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
	w.readers = readerGenerations{testReader: 1} // the PC/SC watcher (G2): the card's reader, watched
	provider.WatchReaders(w.readers)
	w.provider = provider
	return w
}

// readerGenerations stands for the PC/SC watcher (internal/backend/pcscwatch).
type readerGenerations map[string]uint64

func (readers readerGenerations) Generation(name string) (uint64, bool) {
	generation, ok := readers[name]
	return generation, ok
}

// A CARD PULLED AND PUT BACK BETWEEN TWO OPERATIONS WAITS FOR A FRESH LEASE (regalia-kms#72, G2), and a
// card whose reader is not watched is refused before the PIN.
func TestACardAwayBetweenTwoOperationsWaitsForAFreshLease(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("watched, under a lease asked for since the daemon started")
	w.readers[testReader], w.now = 4, 2_000 // pulled and back between two operations
	w.requireWaiting("its reader moved", 2_000)
	w.gate.requestedMs = 2_001
	w.requireServing("under a lease asked for after it")
	delete(w.readers, testReader) // pcscd lost
	logins := w.card.loginCalls
	if err := w.sign(); err == nil || w.card.loginCalls != logins || w.healthy() {
		t.Fatalf("a card whose reader is not watched signed, presented its PIN or reported healthy: %v", err)
	}
	unwatched := newReauthWorld(t)
	unwatched.provider.WatchReaders(nil)
	if err := unwatched.sign(); err == nil {
		t.Fatal("a card was served with no watcher")
	}
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
	w.now = 2_000
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
	w.now = 2_000 // after the lease was asked for: an absence wrongly recorded now would keep the card out
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

// A CALLER WHO HANGS UP IS NOT A CARD THAT LEFT. The request's context ends, the operation fails,
// and the session answers nothing more under that context; the card is still there.
func TestACancelledRequestDoesNotTakeTheCardOutOfService(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the cancelled request")
	w.now = 2_000 // after the lease was asked for: an absence wrongly recorded now would keep the card out
	ctx, cancel := context.WithCancel(context.Background())
	w.card.cancelOnSign = cancel
	if _, _, err := w.provider.Execute(ctx, route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
		t.Fatal("setup: the cancelled request should fail")
	}
	w.card.cancelOnSign = nil
	w.requireServing("after a request its caller cancelled")

	// and a card that really left during a request whose caller also hung up is still seen gone
	ctx, cancel = context.WithCancel(context.Background())
	w.card.cancelOnSign = func() { cancel(); w.card.gone = true }
	if _, _, err := w.provider.Execute(ctx, route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
		t.Fatal("setup: the request should fail")
	}
	w.card.cancelOnSign, w.card.gone = nil, false
	w.now = 3_000
	w.requireWaiting("back after leaving during a cancelled request", 3_000)
}

// The same, one step earlier: the caller is gone before the card is reached, or its time ran out
// waiting for its turn. The driver opens nothing under a context that has ended.
func TestARequestThatHadAlreadyEndedDoesNotTakeTheCardOutOfService(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before")
	w.now = 2_000
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := w.provider.Execute(ended, route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
		t.Fatal("setup: a request whose context has ended should fail")
	}
	if w.provider.Healthy(ended, route().Binding) {
		t.Fatal("setup: a health check whose context has ended should fail")
	}
	if waiting := w.provider.AwaitingReauthorization(); len(waiting) != 0 {
		t.Fatalf("a request that had already ended marked the card: %v", waiting)
	}
	w.requireServing("after requests that had already ended")
}

// PoC 12.4's own sequence, seen only by the health check: the bound card out, another in its
// place, the bound card back. Routing and readiness look far more often than operations do.
func TestAnotherCardInItsPlaceSeenByTheHealthCheckIsAnAbsence(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before the swap")
	w.card.other = "87654321"
	w.now = 2_000
	if w.healthy() {
		t.Fatal("another card in the bound card's place reports healthy")
	}
	w.card.other = ""
	w.now = 3_000
	w.requireWaiting("the bound card back after another sat in its place", 3_000)
}

// The health check runs under the request's context on the routing path, so the caller can end it
// at any step: after the card was opened, and after it was identified.
func TestAHealthCheckWhoseCallerHangsUpPartWayDoesNotTakeTheCardOutOfService(t *testing.T) {
	for _, when := range []string{"while the card is opened", "after the card was identified"} {
		w := newReauthWorld(t)
		w.requireServing(when + ": before")
		w.now = 2_000
		ctx, cancel := context.WithCancel(context.Background())
		if when == "while the card is opened" {
			w.card.onOpen = cancel
		} else {
			w.card.afterIdentity = cancel
		}
		if w.provider.Healthy(ctx, route().Binding) {
			t.Fatalf("%s: setup: the health check should fail", when)
		}
		cancel()
		w.card.onOpen, w.card.afterIdentity = nil, nil
		if waiting := w.provider.AwaitingReauthorization(); len(waiting) != 0 {
			t.Fatalf("%s: a health check whose caller hung up marked the card: %v", when, waiting)
		}
		w.requireServing(when + ": afterwards")
	}
}

// Every operation waits, not only signing: a waiting card is asked neither for its public key
// (wrap) nor to unwrap, and is not shown the PIN.
func TestAWaitingCardNeitherWrapsNorUnwraps(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 900 // the lease held before this process started
	rsa := route()
	rsa.Algorithm = "rsa2048"
	aad, key := []byte("aad-for-the-waiting-card-test"), []byte("decrypted-data-key-32-bytes-long")
	w.card.frame = boundaryV2Frame(aad, key)
	for _, operation := range []string{"wrap", "unwrap"} {
		if _, _, err := w.provider.Execute(context.Background(), rsa, operation, "regalia-envelope-v2", "", []byte("ciphertext"), aad); err == nil {
			t.Fatalf("a waiting card performed %s", operation)
		}
	}
	if w.card.loginCalls != 0 || w.card.publicReads != 0 || w.card.unwraps != 0 {
		t.Fatalf("a waiting card was used: %d logins, %d public-key reads, %d unwraps", w.card.loginCalls, w.card.publicReads, w.card.unwraps)
	}
	w.gate.requestedMs = 1_001
	if _, _, err := w.provider.Execute(context.Background(), rsa, "unwrap", "regalia-envelope-v2", "", []byte("ciphertext"), aad); err != nil || w.card.unwraps != 1 {
		t.Fatalf("under a lease asked for after the start the card must unwrap: %v (%d unwraps)", err, w.card.unwraps)
	}
	// wrap needs only the public key; the stand-in's is not a real one, so reaching it is the evidence
	_, _, _ = w.provider.Execute(context.Background(), rsa, "wrap", "regalia-envelope-v2", "", []byte("0123456789abcdef0123456789abcdef"), aad)
	if w.card.publicReads != 1 {
		t.Fatalf("under a lease asked for after the start wrap must reach the card's public key (%d reads)", w.card.publicReads)
	}
}

// The question "does it still answer" is itself a card call, and a card library can panic in it.
func TestACardWhoseFollowUpIdentityReadPanicsIsGoneAndNothingEscapes(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before")
	w.card.failSign = errors.New("refused")
	w.card.panicOnIdentity = 2 // the first read identifies the card; the second is the question
	w.now = 2_000
	if w.sign() == nil {
		t.Fatal("setup: the request should fail")
	}
	w.card.failSign = nil
	w.now = 3_000
	w.requireWaiting("after the follow-up read panicked", 3_000)
}

func TestAHealthCheckOnASessionThatWillNotCloseOrPanicsIsUnhealthyAndTheCardWaits(t *testing.T) {
	for name, arrange := range map[string]func(*removableCard){
		"close fails":  func(card *removableCard) { card.closeErr = errors.New("still connected") },
		"close panics": func(card *removableCard) { card.closePanics = true },
		"panic":        func(card *removableCard) { card.panicOnIdentity = 1 },
	} {
		w := newReauthWorld(t)
		w.requireServing(name + ": before")
		arrange(w.card)
		w.now = 2_000
		if w.healthy() {
			t.Fatalf("%s: reported healthy", name)
		}
		w.card.closeErr, w.card.closePanics, w.card.panicOnIdentity = nil, false, 0
		w.now = 3_000
		w.requireWaiting(name+": afterwards", 3_000)
	}
}

// A panic while closing must not escape Execute, and the card waits.
func TestASessionThatPanicsWhileClosingAfterAnOperationIsGone(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("before")
	w.card.closePanics = true
	w.now = 2_000
	if w.sign() == nil {
		t.Fatal("an operation whose session panicked while closing succeeded")
	}
	w.card.closePanics = false
	w.now = 3_000
	w.requireWaiting("afterwards", 3_000)
}

func TestARefusedPINDoesNotCountAsAnAbsence(t *testing.T) {
	w := newReauthWorld(t)
	w.now = 2_000
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
	// and the retry counter's fallback is as it was: an illegible count is answered from the last
	// legible reading without the card being asked anything more
	logins, reads := card.loginCalls, card.identityRead
	card.leaves = "retries"
	if err := sign(); err != nil || card.loginCalls != logins+1 {
		t.Fatalf("with no admission gate an illegible retry count must fall back to the last reading: %v (%d logins)", err, card.loginCalls-logins)
	}
	if card.identityRead != reads+1 {
		t.Fatalf("with no admission gate the card was asked for its serial %d times in one request, want once", card.identityRead-reads)
	}
}

// A YUBIKEY THE MANIFEST DOES NOT LIST IS NOT SERVED (regalia-kms#72, G1): the node's tokens are its
// manifest entry's hsm_serials, its YubiKey as much as its HSM. Refused before the PIN, unhealthy, and
// serving again once listed.
func TestAYubiKeyTheManifestDoesNotListIsRefusedBeforeThePIN(t *testing.T) {
	w := newReauthWorld(t)
	w.requireServing("listed, under a lease asked for since the daemon started")
	w.gate.unlisted = map[string]bool{"12345678": true}
	logins := w.card.loginCalls
	if err := w.sign(); err == nil || w.card.loginCalls != logins {
		t.Fatalf("a card the manifest does not list signed, or its PIN was presented: %v", err)
	}
	if w.healthy() {
		t.Fatal("a card the manifest does not list reports healthy")
	}
	if got := w.gate.serials[len(w.gate.serials)-1]; got != "12345678" {
		t.Fatalf("the gate was asked about %q, not the card's own serial", got)
	}
	w.gate.unlisted = nil
	w.requireServing("listed again")
}
