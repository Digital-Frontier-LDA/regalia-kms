package nitrokey

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// swappableSession lets the device change identity between calls, which is what a physical swap
// looks like to the adapter: the slot still answers, with a different card in it.
type swappableSession struct {
	serial, devaut string
	channelErr     error
	closed         bool
	signs          int
}

func (s *swappableSession) Identity(context.Context) (string, string, error) {
	return s.serial, s.devaut, nil
}
func (s *swappableSession) EstablishSecureChannel(context.Context) error { return s.channelErr }
func (*swappableSession) PINRetries(context.Context) (int, error)        { return 3, nil }
func (*swappableSession) Login(context.Context, []byte) error            { return nil }
func (s *swappableSession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	s.signs++
	return []byte("signature"), nil
}
func (*swappableSession) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (*swappableSession) Wrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (*swappableSession) AssertKEKGeneratedOnToken(context.Context, string) error { return nil }

func (*swappableSession) AssertKEKNonExportable(context.Context, string) error { return nil }

func (*swappableSession) PublicKey(context.Context, string) ([]byte, error) {
	return []byte("public"), nil
}
func (*swappableSession) Derive(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errors.New("not used")
}
func (s *swappableSession) Close() error { s.closed = true; return nil }

type swappableDriver struct{ session *swappableSession }

func (d *swappableDriver) Open(context.Context, registry.Binding) (Session, error) {
	return d.session, nil
}
func (*swappableDriver) Ready(context.Context) bool { return true }

func swapProvider(t *testing.T) (*Provider, *swappableSession) {
	t.Helper()
	session := &swappableSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, err := New(&swappableDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider, session
}

func sign(provider *Provider) ([]byte, error) {
	output, _, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"sign", "raw", "application/octet-stream", []byte("digest"), []byte("context"))
	return output, err
}

// A SWAPPED DEVICE LATCHES THE KEY, IT DOES NOT MERELY FAIL THE CALL.
//
// Required by #8: "Identity mismatch, downgrade, or channel failure disables the affected key."
// Failing only the current call would let the next one try again against whatever is now in the
// slot — the adapter would keep talking to an impostor, one refused request at a time.
func TestDeviceSwapLatchesTheKeyUntilAnOperatorClearsIt(t *testing.T) {
	provider, session := swapProvider(t)

	if _, err := sign(provider); err != nil {
		t.Fatalf("the commissioned device was refused: %v", err)
	}

	// The card is swapped: the slot answers, with a different identity.
	session.serial = "impostor"
	if _, err := sign(provider); err == nil {
		t.Fatal("a swapped device performed an operation")
	}
	reason, latched := provider.QuarantineReason(binding().DeviceID)
	if !latched || reason != "identity-mismatch" {
		t.Fatalf("quarantine = %q/%v, want identity-mismatch", reason, latched)
	}

	// THE CORRECT DEVICE COMING BACK MUST NOT SILENTLY CLEAR THE LATCH. Between the swap and now,
	// an unknown card was in the slot; that is an event someone has to look at.
	session.serial = "serial-1"
	if _, err := sign(provider); err == nil {
		t.Fatal("the latch cleared itself when the original device returned")
	}
	if provider.Healthy(context.Background(), binding()) {
		t.Fatal("a latched device reported healthy")
	}

	// Only an explicit reset returns it to service.
	provider.ResetPINBlock(binding().DeviceID)
	if _, err := sign(provider); err != nil {
		t.Fatalf("the device was still refused after an explicit reset: %v", err)
	}
}

// A CHANNEL THAT WILL NOT ESTABLISH IS A DOWNGRADE, and everything after it would travel
// unprotected — so it latches rather than proceeding.
func TestSecureChannelFailureLatchesTheKey(t *testing.T) {
	provider, session := swapProvider(t)
	session.channelErr = errors.New("secure messaging unavailable")

	if _, err := sign(provider); err == nil {
		t.Fatal("an operation ran without a secure channel")
	}
	reason, latched := provider.QuarantineReason(binding().DeviceID)
	if !latched || reason != "secure-channel-failed" {
		t.Fatalf("quarantine = %q/%v, want secure-channel-failed", reason, latched)
	}
	// Even once the channel would establish again, the latch holds until cleared.
	session.channelErr = nil
	if _, err := sign(provider); err == nil {
		t.Fatal("the latch cleared itself when the channel recovered")
	}
}

// THE FIRST REASON WINS. A later symptom must not overwrite the cause, or the operator investigates
// the consequence instead of the event.
func TestTheFirstQuarantineReasonIsKept(t *testing.T) {
	provider, session := swapProvider(t)
	session.serial = "impostor"
	_, _ = sign(provider)

	session.channelErr = errors.New("secure messaging unavailable")
	_, _ = sign(provider)

	reason, _ := provider.QuarantineReason(binding().DeviceID)
	if reason != "identity-mismatch" {
		t.Fatalf("reason = %q, want the first cause identity-mismatch", reason)
	}
}

// HEARTBEAT: readiness must notice a swap without an operation being attempted, so the condition is
// detected by the health path rather than by a caller's failed request.
func TestHealthDetectsASwapWithoutAnOperation(t *testing.T) {
	provider, session := swapProvider(t)
	if !provider.Healthy(context.Background(), binding()) {
		t.Fatal("the commissioned device reported unhealthy")
	}
	session.serial = "impostor"
	if provider.Healthy(context.Background(), binding()) {
		t.Fatal("health did not detect the swap")
	}
	if reason, latched := provider.QuarantineReason(binding().DeviceID); !latched || reason != "identity-mismatch" {
		t.Fatalf("health did not latch the swapped device: %q/%v", reason, latched)
	}
}
