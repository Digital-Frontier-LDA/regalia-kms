package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// softWrapper stands in for the token's data-key wrapping. The data key is protected by a fixed
// transform rather than a real KEK: this test is about the RELEASE path, and the hardware unwrap
// is exercised through the Releaser's own wrapper.
type softWrapper struct{ backend string }

func (w *softWrapper) Backend() string { return w.backend }
func (w *softWrapper) WrapKey(_ context.Context, _ envelope.KeyRef, dataKey, _ []byte) ([]byte, error) {
	return append([]byte("wrapped:"), dataKey...), nil
}
func (w *softWrapper) UnwrapKey(_ context.Context, _ envelope.KeyRef, wrapped, _ []byte) ([]byte, error) {
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("not wrapped by this backend")
	}
	return bytes.TrimPrefix(wrapped, []byte("wrapped:")), nil
}

// card routes the Releaser's unwrap back through the same transform, so the whole path runs.
type card struct {
	unwrapErr error
	calls     int
	passthru  int
}

func (c *card) Execute(ctx context.Context, _ registry.Route, operation, _, _ string, data, aad []byte) ([]byte, string, error) {
	if operation != "unwrap" {
		c.passthru++
		return []byte("passed-through"), "application/octet-stream", nil
	}
	c.calls++
	if c.unwrapErr != nil {
		return nil, "", c.unwrapErr
	}
	key, err := (&softWrapper{backend: "nitrokey-pkcs11"}).UnwrapKey(ctx, envelope.KeyRef{}, data, aad)
	if err != nil {
		return nil, "", err
	}
	return key, "application/vnd.regalia.data-key", nil
}

// sealedWith seals under an explicit context, for the cases that must prove a mismatch fails.
func sealedWith(t *testing.T, objectID string, secret, bindingContext []byte) []byte {
	t.Helper()
	wrapper := &softWrapper{backend: "nitrokey-pkcs11"}
	env, err := envelope.Seal(context.Background(), wrapper,
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: objectID, Version: "2"},
		objectID, bindingContext, secret, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A release-secret route always names the algorithm of the wrapping key in the slot: the object is
// opaque, but the KEK protecting it is an RSA key, and that is what the card is asked for. The
// registry refuses a release-secret binding without it. Purpose and environment come from the
// manifest too, and the binding context is derived from them.
func route(objectID string) registry.Route {
	return registry.Route{ObjectID: objectID, Purpose: "deployment-api", Environment: "production",
		Algorithm: "opaque", KEKAlgorithm: "rsa2048", KEKVersion: "2",
		Binding: registry.Binding{Backend: "nitrokey-pkcs11", ObjectID: objectID,
			KEKAlgorithm: "rsa2048", KEKVersion: "2"}}
}

// sealed seals under the context the KMS will derive for that object's route, which is the only
// context a release can now open.
func sealed(t *testing.T, objectID string, secret []byte) []byte {
	t.Helper()
	return sealedFor(t, route(objectID), secret)
}

// THE WHOLE PATH: an envelope in, the secret out, with the data key unwrapped on the token.
func TestReleaseSecretReturnsThePlaintextAfterAHardwareUnwrap(t *testing.T) {
	secret := []byte("s3rvice-account-token")
	blob := sealed(t, "opaque-token", secret)

	backend := &card{}
	releaser, err := NewReleaser(backend)
	if err != nil {
		t.Fatal(err)
	}
	released, contentType, err := releaser.Execute(context.Background(), route("opaque-token"),
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if !bytes.Equal(released, secret) {
		t.Fatalf("released %q, want %q", released, secret)
	}
	if contentType != "application/vnd.regalia.secret" {
		t.Fatalf("content type = %q", contentType)
	}
	if backend.calls != 1 {
		t.Fatalf("hardware unwrapped %d times, want exactly 1", backend.calls)
	}
}

// ONE OBJECT'S ENVELOPE MUST NOT BE RELEASED UNDER ANOTHER OBJECT'S AUTHORIZATION.
//
// Authorization, routing and policy were all evaluated for the object the REQUEST named. Opening an
// envelope belonging to a different object would hand back a secret nobody decided to release.
func TestEnvelopeForAnotherObjectIsRefused(t *testing.T) {
	blob := sealed(t, "opaque-token", []byte("secret"))
	releaser, _ := NewReleaser(&card{})
	released, _, err := releaser.Execute(context.Background(), route("different-object"),
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("released an envelope belonging to a different object")
	}
}

// The binding context is authenticated: an envelope sealed under any other context must not open.
// The KMS derives the context it compares against, so this is now sealed under a context no route
// would produce rather than released under a mismatched one the caller chose.
func TestWrongBindingContextReleasesNothing(t *testing.T) {
	blob := sealedWith(t, "opaque-token", []byte("secret"), []byte("purpose=deploy"))
	releaser, _ := NewReleaser(&card{})
	released, _, err := releaser.Execute(context.Background(), route("opaque-token"),
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("released a secret under the wrong binding context")
	}
	// The CLASS matters as much as the refusal. TestHardwareFailureAndBadEnvelopeAreDifferentClasses
	// asserts this for a malformed envelope, but that input fails at the PARSE guard and returns
	// before the open-path classification is reached, so the branch that maps an open failure to
	// ErrUnavailable had nothing driving a non-hardware error through it. An envelope sealed under a different binding context
	// is such an error: no retry can fix it.
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("DEFECT: %v was reported as %v, which is retryable, so the caller would retry a "+
			"request that can never succeed", err, ErrUnavailable)
	}
}

// Tampered ciphertext is an authentication failure, not a partial read.
//
// THE CIPHERTEXT, NOT THE ENCODING AROUND IT. This flipped a byte three from the end of the
// MARSHALLED blob, which lands on the closing quote of the last JSON string: the envelope then fails
// to PARSE and returns "invalid secret envelope" before any key is unwrapped. So the test passed
// without ever reaching an authentication failure, and the open path's error classification had
// nothing driving a non-hardware error through it. Tampering the ciphertext field itself and
// re-marshalling produces a well-formed envelope that can only fail on the AEAD tag, which is what
// the name has always claimed.
func TestTamperedEnvelopeReleasesNothing(t *testing.T) {
	parsed, err := envelope.Parse(sealed(t, "opaque-token", []byte("secret")))
	if err != nil {
		t.Fatalf("fixture is broken before it is tampered with: %v", err)
	}
	parsed.Ciphertext[len(parsed.Ciphertext)-1] ^= 0xff
	blob, err := parsed.Marshal()
	if err != nil {
		t.Fatalf("tampered envelope no longer marshals, so it would fail at parse rather than "+
			"authentication and pin nothing: %v", err)
	}
	if _, err := envelope.Parse(blob); err != nil {
		t.Fatalf("tampered envelope no longer parses (%v), so it cannot reach the authentication "+
			"failure this test is named for", err)
	}
	releaser, _ := NewReleaser(&card{})
	released, _, err := releaser.Execute(context.Background(), route("opaque-token"),
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("released a secret from a tampered envelope")
	}
	// The CLASS matters as much as the refusal. TestHardwareFailureAndBadEnvelopeAreDifferentClasses
	// asserts this for a malformed envelope, but that input fails at the PARSE guard and returns
	// before the open-path classification is reached, so the branch that maps an open failure to
	// ErrUnavailable had nothing driving a non-hardware error through it. A tampered envelope
	// is such an error: no retry can fix it.
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("DEFECT: %v was reported as %v, which is retryable, so the caller would retry a "+
			"request that can never succeed", err, ErrUnavailable)
	}
}

// A hardware failure is retryable; a bad envelope is not. Conflating them would have clients retry
// a request that can never succeed.
func TestHardwareFailureAndBadEnvelopeAreDifferentClasses(t *testing.T) {
	blob := sealed(t, "opaque-token", []byte("secret"))

	backend := &card{unwrapErr: errors.New("token gone")}
	releaser, _ := NewReleaser(backend)
	if _, _, err := releaser.Execute(context.Background(), route("opaque-token"),
		"release-secret", "regalia-envelope-v2", "", blob, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hardware failure = %v, want ErrUnavailable", err)
	}

	releaser, _ = NewReleaser(&card{})
	_, _, err := releaser.Execute(context.Background(), route("opaque-token"),
		"release-secret", "regalia-envelope-v2", "", []byte("not-an-envelope"), nil)
	if err == nil {
		t.Fatal("a malformed envelope was accepted")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatal("a malformed envelope was reported as a backend failure and would be retried")
	}
}

// Everything else passes straight through.
func TestReleaserPassesOtherOperationsThrough(t *testing.T) {
	backend := &card{}
	releaser, _ := NewReleaser(backend)
	output, _, err := releaser.Execute(context.Background(), route("k"), "sign", "", "", []byte("x"), nil)
	if err != nil || string(output) != "passed-through" {
		t.Fatalf("passthrough failed: %q %v", output, err)
	}
	if _, err := NewReleaser(nil); err == nil {
		t.Fatal("releaser built without a backend")
	}
}
