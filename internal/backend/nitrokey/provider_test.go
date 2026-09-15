package nitrokey

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type fakePIN struct {
	value []byte
	err   error
}

func (source *fakePIN) PIN(context.Context, string) ([]byte, error) {
	// Return source.value alongside source.err so a test can isolate the err clause (provider.go:191)
	// from the len(pin) clauses by setting value to a valid length (6..64) and err to non-nil —
	// otherwise both clauses fire on the same fixture and the err operand is undetectable.
	if source.err != nil {
		return append([]byte(nil), source.value...), source.err
	}
	return append([]byte(nil), source.value...), nil
}

type fakeDriver struct {
	session *fakeSession
	// opens counts Open calls. A refusal that happens BEFORE the card is reached and one that
	// happens after both return ErrUnavailable, so the error cannot tell them apart; only this
	// can. See TestABindingTheProviderCannotServeIsRefusedBeforeTheCardIsOpened.
	opens int
}

func (driver *fakeDriver) Open(context.Context, registry.Binding) (Session, error) {
	driver.opens++
	return driver.session, nil
}
func (driver *fakeDriver) Ready(context.Context) bool { return true }

type fakeSession struct {
	serial, devaut         string
	secure, logged, closed bool
	pin                    []byte
	retries, loginCalls    int
	// retriesSet makes `retries: 0` mean zero rather than "unset" -- see PINRetries.
	retriesSet bool
	// order records the sequence of calls the provider makes. Booleans can say a step happened;
	// only a sequence can say it happened FIRST, and for secure messaging that is the property.
	order      []string
	retriesErr error
	loginErr   error
	// closeErr makes Close refuse. Every other session fake in this package returns nil from
	// Close unconditionally, which is why #312's guard had nothing that could fail it: a fake
	// that makes the valid case convenient makes the invalid case unreachable.
	closeErr  error
	deriveErr error
	// notTokenGenerated and exportable make the KEK-provenance guards refuse. Both nil by
	// default: a fake token stands for a correctly provisioned one.
	notTokenGenerated error
	exportable        error
	// publicKey, when set, is returned instead of the "public" stub, so a test can exercise the
	// wrap path — which needs a parseable PKIX key — rather than only the paths that ignore it.
	publicKey    []byte
	publicKeyErr error
	// publicKeyEmpty makes PublicKey return NO bytes and no error. Without it the fake
	// substitutes []byte("public") whenever publicKey is unset, so the one state
	// provider.go:150's `len(output) == 0` clause exists for -- a card that answers
	// successfully with nothing -- is unreachable, and that operand survives every fixture.
	// Same blind spot, and same remedy, as retriesSet two fields above.
	publicKeyEmpty bool
	secureErr      bool
	cardKey        *ecdsa.PrivateKey
	// signErr backs provider.go:270's err clause via the sign operation (sign is the only path
	// that assigns output,err straight from a Session call without a per-case guard), so a test
	// can construct "non-empty signature bytes alongside a non-nil error" and isolate that
	// clause from the length clause. Same data-alongside-error discipline as PINRetries and the
	// PublicKey fix above.
	signErr error
}

func (session *fakeSession) Identity(context.Context) (string, string, error) {
	session.order = append(session.order, "Identity")
	return session.serial, session.devaut, nil
}
func (session *fakeSession) EstablishSecureChannel(context.Context) error {
	session.order = append(session.order, "EstablishSecureChannel")
	if session.secureErr {
		return errors.New("secure messaging unavailable")
	}
	session.secure = true
	return nil
}
func (session *fakeSession) Login(_ context.Context, pin []byte) error {
	session.order = append(session.order, "Login")
	session.loginCalls++
	session.logged = true
	session.pin = pin
	return session.loginErr
}
func (session *fakeSession) PINRetries(context.Context) (int, error) {
	session.order = append(session.order, "PINRetries")
	if session.retriesErr != nil {
		// Return whatever retries the test configured alongside the error, so a test can
		// isolate the err clause (provider.go:184) from the retries<=1 clause by setting
		// retries to a value > 1 — the err path is the only one that should fire.
		return session.retries, session.retriesErr
	}
	// ZERO MUST BE EXPRESSIBLE. Treating 0 as "unset" and answering 3 is convenient for the
	// twenty-six literals that do not care about the retry budget, but it makes the ONE state
	// the budget exists to prevent -- a fully spent card -- unreachable: `retries: 0` silently
	// became a healthy card. That is the defect this struct already records one field below,
	// where every fake returning nil from Close left #312's guard with nothing that could fail
	// it. retriesSet keeps the convenience and removes the blind spot.
	if session.retries == 0 && !session.retriesSet {
		return 3, nil
	}
	return session.retries, nil
}
func (session *fakeSession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	// Return non-empty signature bytes alongside session.signErr so a test can isolate the err
	// clause (provider.go:270) from the len(output)==0 clause by setting signErr — otherwise
	// both clauses fire on the same fixture and the err operand is undetectable.
	if session.signErr != nil {
		return []byte("signature"), session.signErr
	}
	return []byte("signature"), nil
}
func (*fakeSession) Wrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errors.New("wrap not exercised by unit tests — see pkcs11_integration_test.go for the SoftHSM round trip")
}
func (session *fakeSession) Unwrap(_ context.Context, _, _ string, _, aad []byte) ([]byte, error) {
	session.order = append(session.order, "Unwrap")
	digest := sha256.Sum256(aad)
	plaintext := []byte("data-key")
	// v2 frame: magic(4) || SHA256(aad)(32) || len(4 BE) || plaintext. The frame format version
	// was bumped in #206 when the length field was added so OpenFrame can ignore trailing bytes
	// from a non-compliant C_UnwrapKey (see keywrap.OpenFrame for the full reason). The fake
	// returns the same shape a real token would produce after unwrapping.
	out := make([]byte, 0, 4+sha256.Size+4+len(plaintext))
	out = append(out, 'R', 'G', 'K', 2)
	out = append(out, digest[:]...)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(plaintext)))
	out = append(out, lengthBuf[:]...)
	out = append(out, plaintext...)
	return out, nil
}
func (session *fakeSession) PublicKey(context.Context, string) ([]byte, error) {
	// Return session.publicKey alongside session.publicKeyErr so a test can isolate the err clause
	// (provider.go:150) from the len(output)==0 clause by setting publicKey to non-empty bytes
	// alongside publicKeyErr — otherwise both clauses fire on the same fixture and the err
	// operand is undetectable.
	if session.publicKeyErr != nil {
		if len(session.publicKey) > 0 {
			return session.publicKey, session.publicKeyErr
		}
		return []byte("public"), session.publicKeyErr
	}
	if session.publicKeyEmpty {
		return nil, nil
	}
	if len(session.publicKey) > 0 {
		return session.publicKey, nil
	}
	return []byte("public"), nil
}

// A fake token is a correctly provisioned one unless a test says otherwise; the refusing cases
// live in kek_provenance_test.go, which sets these.
func (session *fakeSession) AssertKEKGeneratedOnToken(context.Context, string) error {
	return session.notTokenGenerated
}

func (session *fakeSession) AssertKEKNonExportable(context.Context, string) error {
	return session.exportable
}

// Derive performs a genuine ECDH so the key-agreement path is exercised rather than stubbed: the
// value the provider runs through HKDF is a real shared secret of the right shape. When
// deriveErr is set, return non-empty bytes alongside the error so a test can isolate the err
// clause (provider.go:235) from the len(shared)==0 clause by exercising deriveErr — otherwise
// both clauses fire on the same fixture and the err operand is undetectable.
func (session *fakeSession) Derive(_ context.Context, _, _ string, peerPKIX []byte) ([]byte, error) {
	if session.deriveErr != nil {
		return []byte("shared-secret"), session.deriveErr
	}
	parsed, err := x509.ParsePKIXPublicKey(peerPKIX)
	if err != nil {
		return nil, err
	}
	peer, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	if session.cardKey == nil {
		session.cardKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	peerECDH, err := peer.ECDH()
	if err != nil {
		return nil, err
	}
	privECDH, err := session.cardKey.ECDH()
	if err != nil {
		return nil, err
	}
	return privECDH.ECDH(peerECDH)
}
func (session *fakeSession) Close() error {
	// closed records that the call was MADE, which is what the ordering tests assert; whether
	// it succeeded is closeErr's business.
	session.closed = true
	return session.closeErr
}

func binding() registry.Binding {
	return registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "serial-1", DevAuthFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObjectID: "01", State: "active"}
}

func TestExecutePinsIdentityEstablishesSecureMessagingAndZeroesPIN(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	result, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	if err != nil || string(result) != "data-key" || !session.secure || !session.logged || !session.closed {
		t.Fatalf("result=%q err=%v session=%#v", result, err, session)
	}
	for _, value := range session.pin {
		if value != 0 {
			t.Fatal("PIN buffer was not zeroed")
		}
	}
}

func TestIdentityMismatchFailsBeforeLoginAndOperation(t *testing.T) {
	session := &fakeSession{serial: "substituted", devaut: binding().DevAuthFingerprint}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	result, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	if err == nil || result != nil || session.logged || !session.closed || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("result=%q err=%v session=%#v", result, err, session)
	}
}

func TestFailedPINLatchesDeviceUntilExplicitReset(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, loginErr: errors.New("bad PIN")}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	route := registry.Route{Algorithm: "rsa2048", Binding: binding()}
	if _, _, err := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context")); err == nil {
		t.Fatal("incorrect PIN was accepted")
	}
	session.loginErr = nil
	if _, _, err := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context")); err == nil || session.loginCalls != 1 {
		t.Fatalf("latched device retried PIN: err=%v calls=%d", err, session.loginCalls)
	}
	provider.ResetPINBlock("hsm-sitea")
	if _, _, err := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context")); err != nil || session.loginCalls != 2 {
		t.Fatalf("explicit reset did not recover: err=%v calls=%d", err, session.loginCalls)
	}
}

func TestLowRetryCountFailsBeforePINRetrievalOrLogin(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 1}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), nil); err == nil || session.loginCalls != 0 {
		t.Fatalf("near-lockout attempted login: err=%v calls=%d", err, session.loginCalls)
	}
}

// Healthy has the same channel-establishment guard as Execute (provider.go:142-147), but the
// Healthy twin at L294-296 was the unverified half of the pair. When EstablishSecureChannel
// fails, Healthy must not report the device as ready.
func TestHealthyRefusesWhenEstablishSecureChannelFails(t *testing.T) {
	session := &fakeSession{
		serial:    "serial-1",
		devaut:    binding().DevAuthFingerprint,
		secureErr: true,
	}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if provider.Healthy(context.Background(), binding()) {
		t.Fatal("Healthy reported true despite EstablishSecureChannel failure")
	}
}

// Healthy validates Backend / DeviceSerial / DevAuthFingerprint at L278-280, but the matching
// Execute guard at L112-114 is the only one with tests. The session is rigged so that the
// downstream Identity check cannot mask a removed binding-validation guard: both sides of the
// comparison are blank.
func TestHealthyRefusesIncompleteBinding(t *testing.T) {
	bad := registry.Binding{
		Backend:            "nitrokey-pkcs11",
		DeviceID:           "hsm-sitea",
		DeviceSerial:       "",
		DevAuthFingerprint: "sha256:abc",
		ObjectID:           "01",
		State:              "active",
	}
	session := &fakeSession{serial: "", devaut: bad.DevAuthFingerprint}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if provider.Healthy(context.Background(), bad) {
		t.Fatal("Healthy reported true for binding with empty DeviceSerial")
	}
}

// PIN-source errors are an authentication failure, not a transient hiccup: the provider must
// refuse rather than log in with a zero-length PIN. The fake returns value alongside err so
// this fixture isolates the err clause (provider.go:191): with value at a valid length
// (6..64) and err non-nil, removing the `err != nil` operand alone is what flips this test
// red. Without the err clause at L191-194, the code falls through to the len check, but the
// len check would also pass — so the err clause carries the load and this test pins it.
func TestExecuteFailsWhenPINSourceErrors(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{
		value: []byte("123456"),
		err:   errors.New("PIN source unavailable"),
	})
	_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context"))
	if err == nil {
		t.Fatal("PIN source error was swallowed")
	}
}

// A PIN shorter than 6 bytes is not a credential. Without the len clause at L191-194, a
// 5-byte value would be accepted and a login would be attempted, potentially consuming a
// retry on a malformed credential.
func TestExecuteFailsOnTooShortPIN(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("12345")})
	_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context"))
	if err == nil {
		t.Fatal("5-byte PIN was accepted")
	}
}

// Wrap must only proceed for the envelope format it knows how to seal. Without the format
// check at L159-161, a wrap request with the SOPS format would proceed to RSAOAEP against an
// KEK that should never have been asked to seal in that shape. The fake exposes a real RSA
// public key so a removed format guard cannot be masked by an RSAOAEP parse failure on a
// non-key byte slice.
func TestExecuteWrapRefusesUnknownFormat(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, publicKey: pkix}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	_, _, err = provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "wrap", "sops-pgp", "application/octet-stream", []byte("data"), []byte("aad"))
	if err == nil {
		t.Fatal("wrap accepted sops-pgp format")
	}
}

// PINRetries errors and a low retry count are both refusal triggers. The retries<=1 path is
// exercised by TestLowRetryCountFailsBeforePINRetrievalOrLogin; this one isolates the err
// clause. retries=5 (not low) so only the err path can fire the guard.
func TestExecuteFailsWhenPINRetriesErrors(t *testing.T) {
	session := &fakeSession{
		serial:     "serial-1",
		devaut:     binding().DevAuthFingerprint,
		retries:    5,
		retriesErr: errors.New("retries unavailable"),
	}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	_, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "unwrap", "regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context"))
	if err == nil {
		t.Fatal("PINRetries error was swallowed")
	}
}

// The public-key operation returns the device's own certificate. A failure or empty result
// is a token-level fault: without the guard at L150-153, the caller gets a nil byte slice
// with content-type application/pkix — a misleading success. The fake returns non-empty
// bytes alongside publicKeyErr so this fixture isolates the err clause (provider.go:150):
// removing `err != nil` alone is what flips this test red. The fakeSession.PublicKey stub
// bytes ("public") make len(output) > 0 so the len clause cannot backstop the err clause.
func TestExecutePublicKeyRefusesWhenTokenReturnsError(t *testing.T) {
	session := &fakeSession{
		serial:       "serial-1",
		devaut:       binding().DevAuthFingerprint,
		publicKey:    []byte("non-empty-stub"),
		publicKeyErr: errors.New("public key unavailable"),
	}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	out, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "public-key", "", "", nil, nil)
	if err == nil {
		t.Fatalf("public-key error was swallowed: out=%v", out)
	}
}

// Provider.go:270 catches any error from the operation-case body, including sign, which has no
// per-case local guard. The fake returns non-empty signature bytes alongside signErr so this
// fixture isolates the err clause at L270 from the len(output)==0 clause: with output non-empty
// (the fake emits 9-byte "signature") and err non-nil, removing `err != nil` alone makes the
// function return the signature bytes with the original signErr — neither ErrUnavailable nor
// a zeroed output, so any test that asserts the refused shape is what this test pins.
func TestExecuteRefusesWhenSignReturnsError(t *testing.T) {
	session := &fakeSession{
		serial:  "serial-1",
		devaut:  binding().DevAuthFingerprint,
		retries: 3,
		signErr: errors.New("PKCS#11 sign unavailable"),
	}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	out, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "sign", "", "application/vnd.regalia.digest", make([]byte, 32), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("sign error was not normalised: err=%v out=%v", err, out)
	}
	if len(out) != 0 {
		t.Fatalf("sign error did not zero output: out=%v", out)
	}
}
