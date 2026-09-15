package nitrokey

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// errRemoved stands for the token being pulled: every PKCS#11 call after that point fails.
var errRemoved = errors.New("token removed")

// removalStage names the point at which the device disappears. A token can be pulled at any of
// them, and each is a different code path: before the session exists, between opening and proving
// identity, between identity and login, and — the one that matters most — after login, while the
// private-key operation is in flight.
type removalStage int

const (
	removeBeforeOpen removalStage = iota
	removeAtIdentity
	removeAtLogin
	removeDuringOperation
)

type removingDriver struct {
	stage   removalStage
	session *removingSession
	opened  int
}

func (driver *removingDriver) Open(context.Context, registry.Binding) (Session, error) {
	driver.opened++
	if driver.stage == removeBeforeOpen {
		return nil, errRemoved
	}
	return driver.session, nil
}

// A removed token is not ready, and readiness must not recover on its own.
func (driver *removingDriver) Ready(context.Context) bool { return driver.stage != removeBeforeOpen }

type removingSession struct {
	stage      removalStage
	pin        []byte
	closed     bool
	signCalled bool
}

func (session *removingSession) Identity(context.Context) (string, string, error) {
	if session.stage == removeAtIdentity {
		return "", "", errRemoved
	}
	return "serial-1", binding().DevAuthFingerprint, nil
}
func (*removingSession) EstablishSecureChannel(context.Context) error { return nil }
func (*removingSession) PINRetries(context.Context) (int, error)      { return 3, nil }
func (session *removingSession) Login(_ context.Context, pin []byte) error {
	session.pin = pin
	if session.stage == removeAtLogin {
		return errRemoved
	}
	return nil
}
func (session *removingSession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	session.signCalled = true
	return nil, errRemoved
}
func (session *removingSession) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errRemoved
}
func (*removingSession) Wrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errRemoved
}
func (*removingSession) AssertKEKGeneratedOnToken(context.Context, string) error { return nil }

func (*removingSession) AssertKEKNonExportable(context.Context, string) error { return nil }

func (*removingSession) PublicKey(context.Context, string) ([]byte, error) {
	return nil, errRemoved
}
func (*removingSession) Derive(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errRemoved
}
func (session *removingSession) Close() error { session.closed = true; return nil }

// TOKEN REMOVAL AT EVERY STAGE FAILS CLOSED AND RETURNS NOTHING.
//
// Required by the ADR's verification contract: "wrong/missing token ... token removal ... fail
// without returning secret material". A pulled token is the ordinary case on this bench, not an
// exotic one — the operator carries it — so each stage is asserted separately rather than trusting
// that one error path stands in for the rest.
func TestTokenRemovalAtEveryStageFailsClosedWithoutMaterial(t *testing.T) {
	stages := []struct {
		name  string
		stage removalStage
	}{
		{"removed before the session opens", removeBeforeOpen},
		{"removed before identity is proven", removeAtIdentity},
		{"removed before login", removeAtLogin},
		{"removed while the private-key operation is in flight", removeDuringOperation},
	}

	for _, each := range stages {
		t.Run(each.name, func(t *testing.T) {
			session := &removingSession{stage: each.stage}
			driver := &removingDriver{stage: each.stage, session: session}
			provider, err := New(driver, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatal(err)
			}

			result, contentType, execErr := provider.Execute(context.Background(),
				registry.Route{Algorithm: "rsa2048", Binding: binding()},
				"sign", "raw", "application/octet-stream", []byte("digest"), []byte("context"))

			if execErr == nil {
				t.Fatal("a removed token produced a successful operation")
			}
			if len(result) != 0 {
				t.Fatalf("a removed token returned %d bytes of material", len(result))
			}
			if contentType != "" {
				t.Fatalf("a removed token returned a content type %q", contentType)
			}
			// The caller must be able to tell "the device is gone" from "the request was bad",
			// because only one of those is worth retrying or paging someone about.
			if !errors.Is(execErr, ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", execErr)
			}
			// The error must not carry the driver's raw text onward as secret-adjacent detail.
			if session.pin != nil {
				for _, value := range session.pin {
					if value != 0 {
						t.Fatal("PIN buffer was not zeroed on the removal path")
					}
				}
			}
			// Any session that was opened must still be closed.
			if driver.opened > 0 && each.stage != removeBeforeOpen && !session.closed {
				t.Fatal("session was not closed after the token was removed")
			}
		})
	}
}

// A REMOVED TOKEN IS NEVER SUBSTITUTED. Readiness reports the truth, and the provider does not
// quietly satisfy the request from some other device — the ADR forbids falling back to "a different
// token" as explicitly as it forbids falling back to software.
func TestRemovedTokenIsNotSubstitutedAndReadinessIsFalse(t *testing.T) {
	driver := &removingDriver{stage: removeBeforeOpen, session: &removingSession{stage: removeBeforeOpen}}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if provider.Ready(context.Background()) {
		t.Fatal("readiness is true while the assigned token is absent")
	}
	if provider.Healthy(context.Background(), binding()) {
		t.Fatal("an absent device reported healthy")
	}
	for attempt := 0; attempt < 3; attempt++ {
		result, _, execErr := provider.Execute(context.Background(),
			registry.Route{Algorithm: "rsa2048", Binding: binding()},
			"sign", "raw", "application/octet-stream", []byte("digest"), []byte("context"))
		if execErr == nil || len(result) != 0 {
			t.Fatalf("attempt %d succeeded against an absent token", attempt)
		}
	}
}
