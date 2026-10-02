package nitrokey

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// removableDriver is a token that can be pulled: while gone, Open fails, as a PKCS#11 driver's does.
type removableDriver struct {
	session *fakeSession
	// override, when set, is the session handed out instead (a wrapper around session).
	override Session
	gone     bool
	opens    int
}

func (driver *removableDriver) Open(context.Context, registry.Binding) (Session, error) {
	driver.opens++
	if driver.gone {
		return nil, errors.New("token not present")
	}
	if driver.override != nil {
		return driver.override, nil
	}
	return driver.session, nil
}
func (driver *removableDriver) Ready(context.Context) bool { return true }

// leaseGate stands for internal/admission.Gate: the node is admitted, under a lease it asked for at
// requestedMs.
type leaseGate struct {
	admitted    bool
	requestedMs int64
	asked       []int64
}

func (gate *leaseGate) RequestedAfter(_ context.Context, boottimeMs int64) bool {
	gate.asked = append(gate.asked, boottimeMs)
	return gate.admitted && gate.requestedMs > boottimeMs
}

type reauthWorld struct {
	t        *testing.T
	driver   *removableDriver
	pins     *fakePIN
	gate     *leaseGate
	now      int64
	clockErr error
	provider *Provider
}

func newReauthWorld(t *testing.T) *reauthWorld {
	t.Helper()
	w := &reauthWorld{t: t, now: 1_000,
		driver: &removableDriver{session: &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}},
		pins:   &fakePIN{value: []byte("123456")}, gate: &leaseGate{admitted: true, requestedMs: 900}}
	provider, err := New(w.driver, w.pins)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.RequireReauthorization(w.gate, func() (int64, error) { return w.now, w.clockErr }, w.now); err != nil {
		t.Fatal(err)
	}
	w.provider = provider
	return w
}

func (w *reauthWorld) execute(operation string) error {
	w.t.Helper()
	_, _, err := w.provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, operation,
		"regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	return err
}

func (w *reauthWorld) serves() bool {
	w.t.Helper()
	return w.execute("unwrap") == nil
}

func (w *reauthWorld) healthy() bool {
	return w.provider.Healthy(context.Background(), binding())
}

func (w *reauthWorld) waiting() map[string]int64 { return w.provider.AwaitingReauthorization() }

// A TOKEN THAT WAS GONE WAITS FOR A LEASE ASKED FOR AFTER IT CAME BACK (regalia-kms#72, PoC 12.4).
//
// Before this, the same provider released again by itself the moment the card was back: the cached
// PIN path was all it took. Now a peer must have vouched for the node since.
func TestAReturnedTokenWaitsForALeaseAskedForAfterItsReturn(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001 // a lease asked for after the daemon started
	if !w.serves() || !w.healthy() {
		t.Fatal("the fixture does not serve before the token is pulled")
	}
	if len(w.waiting()) != 0 {
		t.Fatalf("waiting = %v before anything happened", w.waiting())
	}
	// the token is pulled
	w.driver.gone = true
	if err := w.execute("unwrap"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("with the token gone: %v", err)
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v, want the device marked gone", w.waiting())
	}
	// and put back, at boot time 5000; the lease the node holds was asked for at 1001
	w.driver.gone, w.now = false, 5_000
	fetched, logins := w.pins.calls, w.driver.session.loginCalls
	if err := w.execute("unwrap"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a returned token served on the lease from before it left: %v", err)
	}
	if w.pins.calls != fetched || w.driver.session.loginCalls != logins {
		t.Fatal("the PIN was fetched or presented for a token that is waiting for a fresh lease")
	}
	if w.healthy() {
		t.Fatal("a token waiting for a fresh lease reports healthy: routing and readiness would not show it")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": 5_000}) {
		t.Fatalf("waiting = %v, want the return at 5000", w.waiting())
	}
	// time passes; the return time does not move with it
	w.now = 9_000
	w.gate.requestedMs = 5_000 // asked for AT the return: not after it
	if w.serves() {
		t.Fatal("a lease asked for at the moment of return was accepted")
	}
	w.gate.requestedMs = 5_001
	if !w.serves() || !w.healthy() {
		t.Fatal("a lease asked for after the return did not restore service")
	}
	if len(w.waiting()) != 0 {
		t.Fatalf("waiting = %v after reauthorization", w.waiting())
	}
	// and it stays served on later renewals and later operations
	w.gate.requestedMs = 70_000
	if !w.serves() {
		t.Fatal("service did not continue")
	}
}

// The return is noticed by whichever looks first, and the health check looks on every routing
// decision. The moment it records is the return, not the moment somebody later asks for a key.
func TestTheReturnIsRecordedByTheFirstLookAndTheHealthCheckLooks(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.gone = true
	if w.healthy() {
		t.Fatal("healthy with the token gone")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("the health check did not mark the token gone: %v", w.waiting())
	}
	w.driver.gone, w.now = false, 5_000
	if w.healthy() {
		t.Fatal("healthy on the old lease")
	}
	w.now, w.gate.requestedMs = 9_000, 6_000 // a lease asked for after 5000, before the first key request at 9000
	if !w.serves() {
		t.Fatal("the return was dated by the first key request and not by the health check that saw it")
	}
}

// AFTER A RESTART OF THE DAEMON EVERY TOKEN IS TREATED AS JUST ARRIVED. A token pulled, the daemon
// restarted, the token put back: the new process never saw it gone. So the lease must have been
// asked for after this process began.
func TestAfterTheDaemonStartsATokenServesOnlyUnderALeaseAskedForSince(t *testing.T) {
	w := newReauthWorld(t) // started at boot time 1000, lease asked for at 900
	if w.serves() || w.healthy() {
		t.Fatal("served on a lease asked for before the daemon started")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": 1_000}) {
		t.Fatalf("waiting = %v, want the daemon's start", w.waiting())
	}
	w.gate.requestedMs = 1_000
	if w.serves() {
		t.Fatal("a lease asked for at the start was accepted")
	}
	w.gate.requestedMs = 1_001
	if !w.serves() {
		t.Fatal("a lease asked for after the start was refused")
	}
}

// A token first looked at some time after the daemon started is still dated from the start: it may
// have been there all along, and a lease asked for in between is a lease asked for since.
func TestATokenFirstSeenLaterIsDatedFromTheDaemonsStart(t *testing.T) {
	w := newReauthWorld(t) // started at 1000
	w.now, w.gate.requestedMs = 3_000, 2_000
	if !w.serves() {
		t.Fatal("a lease asked for after the daemon started, before the token was first looked at, was refused")
	}
}

// THE BASELINE IS THE PROCESS'S START, NOT THE CALL. The daemon reaches RequireReauthorization some
// time after it started (the PKCS#11 module is loaded first). A lease the lease service asked for in
// between was asked for after this daemon started, and counts.
func TestALeaseAskedForAfterTheProcessStartedButBeforeTheCallCounts(t *testing.T) {
	driver := &removableDriver{session: &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}}
	provider, _ := New(driver, &fakePIN{value: []byte("123456")})
	gate := &leaseGate{admitted: true, requestedMs: 1_500}
	if err := provider.RequireReauthorization(gate, func() (int64, error) { return 4_000, nil }, 1_000); err != nil {
		t.Fatal(err)
	}
	execute := func() error {
		_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap",
			"regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
		return err
	}
	if err := execute(); err != nil {
		t.Fatalf("a lease asked for at 1500, by a process started at 1000 and called at 4000, was refused: %v", err)
	}
	gate.requestedMs = 1_000
	other, _ := New(driver, &fakePIN{value: []byte("123456")})
	if err := other.RequireReauthorization(gate, func() (int64, error) { return 4_000, nil }, 1_000); err != nil {
		t.Fatal(err)
	}
	provider = other
	if execute() == nil {
		t.Fatal("a lease asked for at the process's start, not after it, was accepted")
	}
}

func TestANodeThatIsNotAdmittedDoesNotResume(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs, w.gate.admitted = 1_001, false
	if w.serves() || w.healthy() {
		t.Fatal("served with no admission")
	}
	w.gate.admitted = true
	if !w.serves() {
		t.Fatal("did not serve once admitted")
	}
	w.gate.admitted = false // the lease lapses later: the token did not move, and still nothing is served
	if w.serves() {
		t.Fatal("served after admission lapsed")
	}
}

// A DIFFERENT CARD IN THE SLOT IS STILL A SWAP. The wait is for the right token, back; another one
// is latched out by the identity check before reauthorization is even asked.
func TestASwappedTokenIsQuarantinedNotLeftWaiting(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.gone = true
	_ = w.execute("unwrap")
	w.driver.gone, w.now = false, 5_000
	w.driver.session.serial = "another-card"
	asked := len(w.gate.asked)
	if err := w.execute("unwrap"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a swapped card: %v", err)
	}
	if reason, quarantined := w.provider.QuarantineReason("hsm-sitea"); !quarantined || reason == "" {
		t.Fatal("a swapped card was not quarantined")
	}
	if len(w.gate.asked) != asked {
		t.Fatal("reauthorization was asked for a card that is not the bound one")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v: the swapped card must not count as the token's return", w.waiting())
	}
}

// Nothing is done with a waiting token: not the public key, not a wrap, which need no PIN.
func TestEveryOperationWaitsNotOnlyTheOnesThatLogIn(t *testing.T) {
	for _, operation := range []string{"public-key", "wrap", "unwrap", "sign"} {
		t.Run(operation, func(t *testing.T) {
			w := newReauthWorld(t) // waiting from the start: the lease is older than the daemon
			if err := w.execute(operation); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s on a token waiting for a fresh lease: %v", operation, err)
			}
			if w.pins.calls != 0 {
				t.Fatal("the PIN was fetched")
			}
		})
	}
}

func TestATokenThatLeavesAgainWhileWaitingStartsOver(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.gone = true
	_ = w.execute("unwrap")
	w.driver.gone, w.now = false, 5_000
	_ = w.execute("unwrap") // back at 5000, waiting
	w.driver.gone = true
	_ = w.execute("unwrap") // gone again
	w.driver.gone, w.now = false, 8_000
	w.gate.requestedMs = 6_000 // after the first return, before the second
	if w.serves() {
		t.Fatal("a lease from between two absences was accepted after the second")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": 8_000}) {
		t.Fatalf("waiting = %v, want the second return", w.waiting())
	}
	w.gate.requestedMs = 8_001
	if !w.serves() {
		t.Fatal("a lease asked for after the second return was refused")
	}
}

func TestAnUnreadableBootClockKeepsTheTokenOut(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.gone = true
	_ = w.execute("unwrap")
	w.driver.gone, w.clockErr = false, errors.New("no clock")
	w.gate.requestedMs = 1 << 40
	if w.serves() {
		t.Fatal("served although the return could not be dated")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v, want it still marked gone", w.waiting())
	}
	w.clockErr, w.now = nil, 5_000
	if !w.serves() {
		t.Fatal("did not recover once the clock could be read")
	}
}

func TestRequireReauthorizationNeedsItsParts(t *testing.T) {
	provider, _ := New(&removableDriver{session: &fakeSession{}}, &fakePIN{value: []byte("123456")})
	clock := func() (int64, error) { return 1, nil }
	if err := provider.RequireReauthorization(nil, clock, 1); err == nil {
		t.Fatal("accepted no gate")
	}
	if err := provider.RequireReauthorization(&leaseGate{}, nil, 1); err == nil {
		t.Fatal("accepted no clock")
	}
	if err := provider.RequireReauthorization(&leaseGate{}, func() (int64, error) { return 0, errors.New("no clock") }, 1); err == nil {
		t.Fatal("accepted a clock that cannot be read")
	}
	for _, since := range []int64{0, -1, 2} { // the clock reads 1: 2 is in the future
		if err := provider.RequireReauthorization(&leaseGate{}, clock, since); err == nil {
			t.Fatalf("accepted a start time of %d", since)
		}
	}
	if len(provider.AwaitingReauthorization()) != 0 {
		t.Fatal("a provider with no reauthorization lists waiting devices")
	}
}

// Without RequireReauthorization nothing changes: a lab host, or one with no admission, has no lease
// to wait for, and a returned token resumes as it always did.
func TestWithoutReauthorizationAReturnedTokenResumesAsBefore(t *testing.T) {
	driver := &removableDriver{session: &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}}
	provider, _ := New(driver, &fakePIN{value: []byte("123456")})
	execute := func() error {
		_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap",
			"regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
		return err
	}
	if execute() != nil {
		t.Fatal("the fixture does not serve")
	}
	driver.gone = true
	if !errors.Is(execute(), ErrUnavailable) {
		t.Fatal("served with the token gone")
	}
	driver.gone = false
	if execute() != nil || !provider.Healthy(context.Background(), binding()) {
		t.Fatal("a returned token did not resume on a provider that requires no reauthorization")
	}
}

// AN ABSENCE THE DAEMON SAW AS A FAILURE IS AN ABSENCE (found by an independent read of #151). A
// token pulled while its session is open does not show up as a failed Open: the operation fails.
// Before this, that failure was discarded, and a token back before the next Open served at once on
// the old lease.
func TestATokenPulledWhileItsSessionIsOpenWaitsForAFreshLease(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	if !w.serves() {
		t.Fatal("the fixture does not serve")
	}
	w.driver.session.pullOnSign = true // pulled during the signature: Open had succeeded
	if err := w.execute("sign"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a signature on a pulled token: %v", err)
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v: the token stopped answering mid-operation and was not marked gone", w.waiting())
	}
	// back before anything tried to open it again
	w.driver.session.pullOnSign, w.driver.session.pulled, w.now = false, false, 5_000
	if w.serves() {
		t.Fatal("a token pulled mid-operation and put back served on the lease from before")
	}
	w.gate.requestedMs = 5_001
	if !w.serves() {
		t.Fatal("a lease asked for after the return did not restore service")
	}
}

// A REFUSED REQUEST IS NOT AN ABSENCE. The token still answers for its identity, so the failure was
// about the request. Marking it gone would let any caller who may sign take the token out of
// service, for up to a third of a lease, with one malformed payload.
func TestAFailedOperationOnATokenThatStillAnswersChangesNothing(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.session.signErr = errors.New("CKR_DATA_LEN_RANGE")
	for range 3 {
		if err := w.execute("sign"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a refused payload: %v", err)
		}
	}
	if len(w.waiting()) != 0 {
		t.Fatalf("waiting = %v: a refused payload took the token out of service", w.waiting())
	}
	w.driver.session.signErr = nil
	if !w.serves() || !w.healthy() {
		t.Fatal("the token does not serve after a refused payload")
	}
}

func TestASessionThatWillNotCloseOrThatPanicsMarksTheTokenGone(t *testing.T) {
	for name, breakIt := range map[string]func(*fakeSession){
		"close fails": func(session *fakeSession) { session.closeErr = errors.New("C_CloseSession failed") },
		"panic":       func(session *fakeSession) { session.panicOnSign = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newReauthWorld(t)
			w.gate.requestedMs = 1_001
			breakIt(w.driver.session)
			if err := w.execute("sign"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%v", err)
			}
			if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
				t.Fatalf("waiting = %v", w.waiting())
			}
		})
	}
}

func TestTheHealthCheckAlsoSeesATokenThatStoppedAnswering(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	w.driver.session.retries, w.driver.session.retriesSet = 3, true
	w.driver.session.retriesErr = errors.New("C_GetTokenInfo failed")
	if w.healthy() {
		t.Fatal("healthy although the retry counter cannot be read")
	}
	if len(w.waiting()) != 0 {
		t.Fatalf("waiting = %v: the token still answers for its identity", w.waiting())
	}
	w.driver.session.pulled = false
	pulling := &pullingSession{fakeSession: w.driver.session}
	w.driver.override = pulling
	if w.healthy() {
		t.Fatal("healthy on a token that stopped answering")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v: the health check saw the token stop answering and did not mark it", w.waiting())
	}
	w.driver.override = nil
	w.driver.session.retriesErr = nil
	w.driver.session.closeErr = errors.New("C_CloseSession failed")
	w.gate.requestedMs, w.now = 9_000, 5_000
	w.healthy() // back and reauthorized, but the session will not close
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"hsm-sitea": -1}) {
		t.Fatalf("waiting = %v after a close failure in the health check", w.waiting())
	}
}

// pullingSession is a token pulled between the reauthorization check and the retry counter: the
// first identity read (the binding check) answers, every later one does not.
type pullingSession struct {
	*fakeSession
	identities int
}

func (session *pullingSession) Identity(ctx context.Context) (string, string, error) {
	session.identities++
	if session.identities > 1 {
		return "", "", errors.New("token not present")
	}
	return session.fakeSession.Identity(ctx)
}

// Without RequireReauthorization nothing is asked twice: a host with no runtime admission has no
// lease to wait for, and the token is not probed after a failure.
func TestWithoutReauthorizationAFailureDoesNotProbeTheToken(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, pullOnSign: true}
	provider, _ := New(&removableDriver{session: session}, &fakePIN{value: []byte("123456")})
	_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "sign",
		"", "application/vnd.regalia.digest", []byte("digest"), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	asked := 0
	for _, call := range session.order {
		if call == "Identity" {
			asked++
		}
	}
	if asked != 1 || len(provider.AwaitingReauthorization()) != 0 {
		t.Fatalf("identity asked %d times, waiting %v", asked, provider.AwaitingReauthorization())
	}
}

// A YUBIKEY'S OPENPGP APPLET IS SERVED BY THIS SAME PROVIDER (#130), so it waits like any token here.
// Proved, not assumed: the rule must hold for every key the daemon serves.
func TestAnOpenPGPAppletTokenWaitsLikeAnyOther(t *testing.T) {
	w := newReauthWorld(t)
	w.gate.requestedMs = 1_001
	applet := binding()
	applet.Backend, applet.DeviceID = OpenPGPAppletBackend, "yubikey-openpgp"
	sign := func() error {
		_, _, err := w.provider.Execute(context.Background(), registry.Route{Algorithm: "ed25519", Binding: applet}, "sign",
			"", "application/vnd.regalia.signature", []byte("message"), nil)
		return err
	}
	if err := sign(); err != nil {
		t.Fatalf("the applet fixture does not sign: %v", err)
	}
	w.driver.gone = true
	if !errors.Is(sign(), ErrUnavailable) {
		t.Fatal("signed with the applet's token gone")
	}
	w.driver.gone, w.now = false, 5_000
	if !errors.Is(sign(), ErrUnavailable) || w.provider.Healthy(context.Background(), applet) {
		t.Fatal("a returned OpenPGP applet token served on the lease from before")
	}
	if !reflect.DeepEqual(w.waiting(), map[string]int64{"yubikey-openpgp": 5_000}) {
		t.Fatalf("waiting = %v", w.waiting())
	}
	w.gate.requestedMs = 5_001
	if err := sign(); err != nil {
		t.Fatalf("a lease asked for after the return did not restore the applet: %v", err)
	}
}
