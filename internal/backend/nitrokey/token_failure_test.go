package nitrokey

// TWO DRIVER REFUSALS WITH NO DETECTOR: a login the token rejected, and a session that would not
// close. Defeating either left the whole kms module green.
//
// Both were unreachable by construction, for the same reason the secure-channel refusal was:
// fakeCryptoki's Login, Logout and CloseSession all return nil unconditionally. The package has
// exactly one cryptoki fake and it is a token that never refuses anything, so no fixture could
// reach these paths however a test was written. The wrappers below exist only to make the token
// capable of saying no.
//
// The fakes return real pkcs11.Error values rather than errors.New strings that merely spell a
// CKR_ name. A fixture whose error only LOOKS like the production one stops being a fixture the
// moment the driver inspects a code rather than a message, and it would keep passing while
// testing something the token never does.
//
// LOGIN. Intact, against a token answering C_Login with CKR_PIN_INCORRECT, Provider.Execute
// returns ErrUnavailable and latches the device as "pin-budget-spent" after one attempt.
// Defeated, the session reports itself logged in, the operation signs, and the latch never fires
// — so a token refusing the PIN is retried instead of quarantined, spending the budget it exists
// to protect.
//
// CLOSE. Intact, a close failure surfaces as ErrUnavailable and no output is released. Defeated,
// it is silent: the operation returns its bytes and the failure to log out of the token — leaving
// an authenticated session behind on the card — is discarded.

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/miekg/pkcs11"
)

// refusingToken wraps the package's permissive fake so a single operation can fail. Embedding
// keeps every other cryptoki method the shared fake's, so these tests differ from the passing
// ones in exactly the respect under test.
type refusingToken struct {
	*fakeCryptoki
	loginErr  error
	logoutErr error
	closeErr  error
	logins    int
}

func (token *refusingToken) Login(handle pkcs11.SessionHandle, user uint, pin string) error {
	token.logins++
	if token.loginErr != nil {
		return token.loginErr
	}
	return token.fakeCryptoki.Login(handle, user, pin)
}

func (token *refusingToken) Logout(handle pkcs11.SessionHandle) error {
	if token.logoutErr != nil {
		return token.logoutErr
	}
	return token.fakeCryptoki.Logout(handle)
}

func (token *refusingToken) CloseSession(handle pkcs11.SessionHandle) error {
	if token.closeErr != nil {
		return token.closeErr
	}
	return token.fakeCryptoki.CloseSession(handle)
}

func providerOverToken(t *testing.T, token cryptoki) *Provider {
	t.Helper()
	bind := binding()
	driver, err := newPKCS11Driver(token, devAuthProbe(bind.DevAuthFingerprint), secureChannelStub{}, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func signOnce(t *testing.T, provider *Provider) ([]byte, error) {
	t.Helper()
	output, _, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"sign", "", "application/octet-stream", []byte("payload"), nil)
	return output, err
}

func TestATokenThatRefusesTheLoginIsLatchedRatherThanRetried(t *testing.T) {
	bind := binding()

	// ANCHOR: the same token accepting the login must sign, or a provider refusing everything
	// would satisfy the row below.
	ok := &refusingToken{fakeCryptoki: &fakeCryptoki{serial: bind.DeviceSerial, signature: []byte("a-signature")}}
	if output, err := signOnce(t, providerOverToken(t, ok)); err != nil || len(output) == 0 {
		t.Fatalf("anchor: sign over a token that accepts the login = (%d bytes, %v), want a signature", len(output), err)
	}

	// GATE: the token rejects the PIN.
	token := &refusingToken{
		fakeCryptoki: &fakeCryptoki{serial: bind.DeviceSerial, signature: []byte("a-signature")},
		loginErr:     pkcs11.Error(pkcs11.CKR_PIN_INCORRECT),
	}
	provider := providerOverToken(t, token)
	output, err := signOnce(t, provider)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("sign over a token refusing the login = (%d bytes, %v), want ErrUnavailable — with the "+
			"refusal removed the session reports itself logged in and signs anyway", len(output), err)
	}
	if len(output) != 0 {
		t.Fatalf("%d bytes were released by a session that never logged in", len(output))
	}

	// LATCHED, and the second request must not spend another attempt. A token refusing the PIN
	// that is retried instead of quarantined burns the budget this latch exists to protect.
	reason, latched := provider.QuarantineReason(bind.DeviceID)
	if !latched || reason != "pin-budget-spent" {
		t.Fatalf("QuarantineReason = (%q, %v), want (\"pin-budget-spent\", true)", reason, latched)
	}
	before := token.logins
	if _, err := signOnce(t, provider); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("the second request after a latch returned %v, want ErrUnavailable", err)
	}
	if token.logins != before {
		t.Fatalf("the latched device was asked to log in again (%d -> %d attempts)", before, token.logins)
	}
}

func TestASessionThatWillNotCloseIsReportedRatherThanSwallowed(t *testing.T) {
	bind := binding()

	for _, row := range []struct {
		name  string
		apply func(*refusingToken)
	}{
		{"C_CloseSession fails", func(tok *refusingToken) { tok.closeErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR) }},
		{"C_Logout fails", func(tok *refusingToken) { tok.logoutErr = pkcs11.Error(pkcs11.CKR_DEVICE_ERROR) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			// ANCHOR: the same construction with a token that closes cleanly must sign.
			ok := &refusingToken{fakeCryptoki: &fakeCryptoki{serial: bind.DeviceSerial, signature: []byte("a-signature")}}
			if output, err := signOnce(t, providerOverToken(t, ok)); err != nil || len(output) == 0 {
				t.Fatalf("anchor: sign over a cleanly closing token = (%d bytes, %v), want a signature", len(output), err)
			}

			token := &refusingToken{fakeCryptoki: &fakeCryptoki{serial: bind.DeviceSerial, signature: []byte("a-signature")}}
			row.apply(token)
			output, err := signOnce(t, providerOverToken(t, token))
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s: sign = (%d bytes, %v), want ErrUnavailable — with the refusal removed this "+
					"returns its bytes and the failure to leave the token cleanly is discarded", row.name, len(output), err)
			}
			if len(output) != 0 {
				t.Fatalf("%s: %d bytes were released although the session could not be closed", row.name, len(output))
			}
		})
	}
}
