package yubikey

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type fakePIN struct{ value []byte }

func (source *fakePIN) PIN(context.Context, string) ([]byte, error) {
	return append([]byte(nil), source.value...), nil
}

type fakeDriver struct{ session *fakeSession }

func (driver *fakeDriver) Open(context.Context, string) (Session, error) { return driver.session, nil }
func (*fakeDriver) Ready(context.Context) bool                           { return true }

type fakeSession struct {
	serial, pinPolicy, touchPolicy string
	pin                            []byte
	signed, closed                 bool
	retries, loginCalls            int
	loginErr                       error
}

type postLoginRetrySession struct {
	fakeSession
	retryReads int
}

type sessionDriver struct{ session Session }

func (driver *sessionDriver) Open(context.Context, string) (Session, error) {
	return driver.session, nil
}
func (*sessionDriver) Ready(context.Context) bool { return true }

func (s *postLoginRetrySession) PINRetries(context.Context) (int, error) {
	s.retryReads++
	if s.loginCalls > 0 {
		return 0, errors.New("PIV retry counter unavailable after verification")
	}
	return 3, nil
}

func (s *postLoginRetrySession) Login(ctx context.Context, pin []byte) error {
	return s.fakeSession.Login(ctx, pin)
}

func TestRepeatedOperationsUseTheLastSuccessfulPreLoginRetryReading(t *testing.T) {
	session := &postLoginRetrySession{fakeSession: fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}}
	provider, err := New(&sessionDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}

	for operation := 1; operation <= 2; operation++ {
		output, _, executeErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
		if executeErr != nil || string(output) != "signature" {
			t.Fatalf("operation %d: output=%q err=%v; a post-login retry read failure must use the last successful count", operation, output, executeErr)
		}
	}
	if reading, ok := provider.PINRetriesReadings()[route().Binding.DeviceID]; !ok || reading.Retries != 3 {
		t.Fatalf("cached retry reading = %v; want the successful pre-login count of 3", provider.PINRetriesReadings())
	}
	// NO ASSERTION ON HOW OFTEN THE CARD WAS ASKED, deliberately.
	//
	// This test used to require exactly one PINRetries call, calling the post-login read
	// "poisoned". It is not: the status query is an empty VERIFY that consumes no retry, and
	// after Login it simply fails, which is the #405 condition this test models. Forbidding the
	// call pinned the cache-first order that #442 found defective — with the card never re-asked,
	// a retry spent by another process is invisible. The order is now pinned by
	// TestALegibleNearLockoutCountOverridesAStaleCachedReading instead.
	//
	// A replacement "the card was re-asked" assertion is also absent on purpose: it would make
	// this test fail under a cache-first mutation too, and this test is the control that must
	// fail ONLY when the fallback stops consulting the cache.
	if !provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("Healthy reported a healthy card unavailable after its post-login retry refresh failed")
	}
}

func (s *fakeSession) Identity(context.Context) (string, error) { return s.serial, nil }
func (s *fakeSession) Policies(context.Context, string) (string, string, error) {
	return s.pinPolicy, s.touchPolicy, nil
}
func (s *fakeSession) PINRetries(context.Context) (int, error) {
	if s.retries == 0 {
		return 3, nil
	}
	return s.retries, nil
}
func (s *fakeSession) Login(_ context.Context, pin []byte) error {
	s.loginCalls++
	s.pin = pin
	return s.loginErr
}
func (s *fakeSession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	s.signed = true
	return []byte("signature"), nil
}

func TestPINFailureAndLowRetryCountPreventRepeatedLogin(t *testing.T) {
	session := &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", loginErr: errors.New("bad PIN")}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
		t.Fatal("incorrect PIN accepted")
	}
	session.loginErr = nil
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil || session.loginCalls != 1 {
		t.Fatalf("latched YubiKey retried: err=%v calls=%d", err, session.loginCalls)
	}
	// Cleared for the device the operation above latched, taken from the same
	// route rather than spelled out again. A literal that stopped matching
	// route()'s DeviceID would clear nothing, the latch would refuse the case
	// below, and the assertion would still hold — so the near-lockout guard
	// this case exists for would never be reached and nothing would say so.
	provider.ResetPINBlock(route().Binding.DeviceID)
	session.retries = 1
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil || session.loginCalls != 1 {
		t.Fatalf("near-lockout attempted login: err=%v calls=%d", err, session.loginCalls)
	}
}
func (*fakeSession) Unwrap(_ context.Context, _, _ string, _, aad []byte) ([]byte, error) {
	digest := sha256.Sum256(aad)
	return append(append([]byte{'R', 'G', 'K', 1}, digest[:]...), []byte("data-key")...), nil
}
func (*fakeSession) PublicKey(context.Context, string) ([]byte, error) { return []byte("public"), nil }
func (s *fakeSession) Close() error                                    { s.closed = true; return nil }

func route() registry.Route {
	return registry.Route{Algorithm: "p256", Binding: registry.Binding{Backend: "yubikey-piv", DeviceID: "yubi-sitea", DeviceSerial: "12345678", ObjectID: "9c", State: "active", PINPolicy: "once", TouchPolicy: "never"}}
}

func TestPINOnlySignVerifiesDeviceAndOnTokenPolicy(t *testing.T) {
	session := &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	result, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	if err != nil || string(result) != "signature" || !session.signed || !session.closed {
		t.Fatalf("result=%q err=%v session=%#v", result, err, session)
	}
	for _, value := range session.pin {
		if value != 0 {
			t.Fatal("PIN not zeroed")
		}
	}
}

func TestPresenceOrSubstitutedDeviceFailsBeforePrivateOperation(t *testing.T) {
	for name, session := range map[string]*fakeSession{
		"presence":     {serial: "12345678", pinPolicy: "once", touchPolicy: "always"},
		"substitution": {serial: "87654321", pinPolicy: "once", touchPolicy: "never"},
	} {
		t.Run(name, func(t *testing.T) {
			provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			result, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
			if err == nil || result != nil || session.signed || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("result=%q err=%v session=%#v", result, err, session)
			}
		})
	}
}

// A LEGIBLE NEAR-LOCKOUT COUNT MUST WIN OVER A STALE CACHED ONE (#442).
//
// The counter is read to keep the provider from presenting a PIN when one more rejection would
// lock the card. #407 fixed #405 by caching the last legible pre-login reading, because after
// this provider's own Login the PIV status query stops answering. But it consulted the cache
// FIRST, so once a reading existed the card was never asked again — and the card is the only
// party that knows when somebody else spent a retry.
//
// That is not hypothetical on this bench. Any other process's REJECTED VERIFY (a CI gate run,
// ykman) de-authenticates the card, which makes the counter legible again and truthfully lower.
// Two gate runs spent 3 down to 1 while this provider held a reading of 3.
//
// fakeSession's counter stays legible after Login, so this models exactly that: a first
// operation measures 3 and logs in, somebody else spends two retries, and the second operation
// must see 1 and refuse WITHOUT presenting the PIN.
//
// Falsifier: restore the cache-first order in pinRetries. This test fails and is the only one
// that does; TestRepeatedOperationsUseTheLastSuccessfulPreLoginRetryReading is the #405 control
// and must stay green under that mutation.
func TestALegibleNearLockoutCountOverridesAStaleCachedReading(t *testing.T) {
	session := &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", retries: 3}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err != nil {
		t.Fatalf("first operation on a healthy card failed: %v", err)
	}
	if session.loginCalls != 1 {
		t.Fatalf("first operation presented the PIN %d times; want 1", session.loginCalls)
	}

	session.retries = 1 // another process's rejected VERIFY spent two retries

	_, _, err = provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	if err == nil || session.loginCalls != 1 {
		t.Fatalf("second op err=%v; PIN presented=%t; the card reported 1 retry left and the provider "+
			"answered from a stale cached reading instead, so the near-lockout floor was bypassed",
			err, session.loginCalls > 1)
	}
	if provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("Healthy=true for a card reporting 1 retry left; readiness is reading the stale cache too")
	}
}
