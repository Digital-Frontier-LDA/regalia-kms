package yubikey

import (
	"context"
	"errors"
	"testing"
)

// A REQUEST THAT ENDS BEFORE THE PIN IS PRESENTED SETS NO PIN LATCH (regalia-kms#178, the PIV
// counterpart of #180).
//
// The PIN latch protects the card's retry budget: after a login the card refused, the provider
// presents nothing more until an operator resets it. The real session refuses a login under an
// ended context before the PIN goes anywhere, and the provider used to latch on that too: a caller
// who hung up between the retry-counter read and the login took the card out of service, for every
// key on it, with no try spent.

// endingSession is a card as the real session behaves with a request's context: a login under an
// ended context is refused before the PIN is presented, and says so.
type endingSession struct {
	fakeSession
	// atRetries runs when the retry counter is read: the last card call before the login.
	atRetries func()
	// duringLogin runs while the PIN is on the wire.
	duringLogin func()
	presented   int
	wrongPIN    bool
}

func (s *endingSession) PINRetries(ctx context.Context) (int, error) {
	if s.atRetries != nil {
		s.atRetries()
	}
	return s.fakeSession.PINRetries(ctx)
}

func (s *endingSession) Login(ctx context.Context, pin []byte) error {
	if ctx.Err() != nil {
		return ErrPINNotPresented
	}
	s.presented++
	if s.duringLogin != nil {
		s.duringLogin()
	}
	if s.wrongPIN {
		return ErrUnavailable
	}
	return nil
}

func newEndingProvider(t *testing.T) (*Provider, *endingSession) {
	t.Helper()
	session := &endingSession{fakeSession: fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}}
	provider, err := New(&sessionDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider, session
}

func signUnder(ctx context.Context, provider *Provider) error {
	_, _, err := provider.Execute(ctx, route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	return err
}

func TestARequestThatEndsBeforeThePINIsPresentedSetsNoLatch(t *testing.T) {
	provider, session := newEndingProvider(t)
	ended, end := context.WithCancel(context.Background())
	session.atRetries = end // the request ends after the counter was read and before the login
	if err := signUnder(ended, provider); err == nil {
		t.Fatal("setup: a request that ended before the login must fail")
	}
	session.atRetries = nil
	if session.presented != 0 {
		t.Fatalf("the PIN was presented %d times under a request that had ended", session.presented)
	}
	if provider.pinBlocked(route().Binding.DeviceID) {
		t.Fatal("a request that ended before the PIN was presented latched the card: no try was spent, and every key on it is out of service until an operator resets it")
	}
	// The next request is served, and presents the PIN once.
	if err := signUnder(context.Background(), provider); err != nil || session.presented != 1 {
		t.Fatalf("the next request: err=%v, PIN presented %d times, want served and once", err, session.presented)
	}
	// The counter reading taken before the ended request is still the provider's: it was not forgotten.
	if _, known := provider.PINRetriesReadings()[route().Binding.DeviceID]; !known {
		t.Fatal("the retry-counter reading was forgotten although no login was attempted")
	}
}

// THE LATCH STILL DOES ITS JOB. A PIN the card refused is latched, whatever the request did
// meanwhile: a context that ends while the PIN is on the wire is not evidence that it was not
// presented, and without the latch the next request would present the same wrong PIN again.
func TestAPINTheCardRefusedIsLatchedEvenIfTheRequestEndsMeanwhile(t *testing.T) {
	for name, endsMeanwhile := range map[string]bool{"the request lives": false, "the request ends while the PIN is on the wire": true} {
		provider, session := newEndingProvider(t)
		session.wrongPIN = true
		ctx, end := context.WithCancel(context.Background())
		if endsMeanwhile {
			session.duringLogin = end
		}
		if err := signUnder(ctx, provider); err == nil {
			t.Fatalf("%s: a refused PIN was accepted", name)
		}
		end()
		session.duringLogin = nil
		if !provider.pinBlocked(route().Binding.DeviceID) {
			t.Fatalf("%s: a PIN the card refused set no latch", name)
		}
		// and the counter reading taken before it is forgotten: the card's count has moved
		if _, known := provider.PINRetriesReadings()[route().Binding.DeviceID]; known {
			t.Fatalf("%s: the retry-counter reading from before the refused PIN was kept", name)
		}
		if err := signUnder(context.Background(), provider); err == nil || session.presented != 1 {
			t.Fatalf("%s: after a refused PIN the next request presented it again (%d presentations, err=%v)", name, session.presented, err)
		}
	}
}

// Whatever a session returns that is not ErrPINNotPresented counts as "may have been presented".
func TestOnlyTheSessionsOwnWordSkipsTheLatch(t *testing.T) {
	for name, test := range map[string]struct {
		err     error
		latched bool
	}{
		"ErrPINNotPresented":            {ErrPINNotPresented, false},
		"ErrPINNotPresented, wrapped":   {errors.Join(errors.New("login"), ErrPINNotPresented), false},
		"ErrUnavailable":                {ErrUnavailable, true},
		"a context error from a driver": {context.Canceled, true},
		"any other error":               {errors.New("6982"), true},
	} {
		session := &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", loginErr: test.err}
		provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
		if err != nil {
			t.Fatal(err)
		}
		if signUnder(context.Background(), provider) == nil {
			t.Fatalf("%s: a failed login served", name)
		}
		if latched := provider.pinBlocked(route().Binding.DeviceID); latched != test.latched {
			t.Errorf("%s: latched=%v, want %v", name, latched, test.latched)
		}
	}
	if !errors.Is(ErrPINNotPresented, ErrUnavailable) {
		t.Fatal("ErrPINNotPresented must still be ErrUnavailable to a caller that asks")
	}
}
