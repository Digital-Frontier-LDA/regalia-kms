package yubikey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// riggedSession is a Session whose every failure mode can be switched on independently. The
// package's fakeSession hardcodes success for Close and PublicKey, so the paths that matter most
// here — what happens when an operation SUCCEEDS and the cleanup does not — were unreachable.
type riggedSession struct {
	serial, pinPolicy, touchPolicy string
	publicKey                      []byte
	publicErr                      error
	closeErr                       error
	closed, signed                 bool
	retries                        int
}

func (s *riggedSession) Identity(context.Context) (string, error) { return s.serial, nil }
func (s *riggedSession) Policies(context.Context, string) (string, string, error) {
	return s.pinPolicy, s.touchPolicy, nil
}
func (s *riggedSession) PINRetries(context.Context) (int, error) {
	if s.retries == 0 {
		return 3, nil
	}
	return s.retries, nil
}
func (s *riggedSession) Login(context.Context, []byte) error { return nil }
func (s *riggedSession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	s.signed = true
	return []byte("signature"), nil
}
func (*riggedSession) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errors.New("not used here")
}
func (s *riggedSession) PublicKey(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.publicKey...), s.publicErr
}
func (s *riggedSession) Close() error { s.closed = true; return s.closeErr }

type riggedDriver struct{ session *riggedSession }

func (d *riggedDriver) Open(context.Context, string) (Session, error) { return d.session, nil }
func (*riggedDriver) Ready(context.Context) bool                      { return true }

func healthySession() *riggedSession {
	return &riggedSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", publicKey: []byte("public")}
}

// TestAnOperationThatCannotCloseItsSessionReturnsNothing.
//
// The signature is produced, the card is happy, and then Close fails. Returning the signature
// anyway is the tempting behaviour and the wrong one: a session that did not close cleanly means
// the card's state is not what the daemon believes it is — the PIN may still be validated, the
// slot may still be selected — and the caller has no way to learn that from a successful result.
// The deferred cleanup zeroes the output and converts the result to ErrUnavailable.
func TestAnOperationThatCannotCloseItsSessionReturnsNothing(t *testing.T) {
	session := healthySession()
	session.closeErr = errors.New("card yanked")
	provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}

	output, _, execErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	if !session.signed {
		t.Fatal("the fixture never reached the signing call, so this proves nothing about cleanup")
	}
	if execErr == nil {
		t.Fatalf("a signature was returned though the session did not close: %q", output)
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", execErr)
	}
	if len(output) != 0 {
		t.Fatalf("output = %q, want nothing: a result the caller must not trust must not be handed back", output)
	}
}

// TestAPINThatCannotBeReleasedDiscardsTheResult. Same shape one layer along: the operation
// succeeded and the custody guarantee did not. A PIN source that cannot take its PIN back is
// holding material the daemon promised to return.
type unreleasablePIN struct{ value []byte }

func (source *unreleasablePIN) PIN(context.Context, string) ([]byte, error) {
	return append([]byte(nil), source.value...), nil
}
func (*unreleasablePIN) Release([]byte) error { return errors.New("cannot release") }

func TestAPINThatCannotBeReleasedDiscardsTheResult(t *testing.T) {
	session := healthySession()
	provider, err := New(&riggedDriver{session: session}, &unreleasablePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}

	output, _, execErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	if !session.signed {
		t.Fatal("the fixture never signed, so the release path was not the thing under test")
	}
	if execErr == nil || !errors.Is(execErr, ErrUnavailable) || len(output) != 0 {
		t.Fatalf("output=%q err=%v; want nothing and ErrUnavailable when the PIN could not be released", output, execErr)
	}
}

// TestAPINOutsideTheAcceptedLengthNeverReachesTheCard. A PIN source returning something absurd is
// a configuration or custody fault, and trying it spends a retry from a budget of three.
func TestAPINOutsideTheAcceptedLengthNeverReachesTheCard(t *testing.T) {
	for name, pin := range map[string][]byte{
		"empty":                    {},
		"five, one too few":        []byte("12345"),
		"sixty-five, one too many": bytes.Repeat([]byte("9"), 65),
	} {
		t.Run(name, func(t *testing.T) {
			session := healthySession()
			provider, err := New(&riggedDriver{session: session}, &fakePIN{value: pin})
			if err != nil {
				t.Fatal(err)
			}
			output, _, execErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
			if execErr == nil || len(output) != 0 {
				t.Fatalf("a %s PIN was accepted: output=%q err=%v", name, output, execErr)
			}
			if session.signed {
				t.Fatalf("a %s PIN reached the card and spent a retry from a budget of three", name)
			}
		})
	}
}

// TestPublicKeyRefusesAnEmptyAnswer. "public-key" is the one operation that needs no PIN, so a
// card returning nothing would otherwise be reported as a successful empty key — and a caller
// would build a certificate request around it.
func TestPublicKeyRefusesAnEmptyAnswer(t *testing.T) {
	for name, session := range map[string]*riggedSession{
		"an empty key": {serial: "12345678", pinPolicy: "once", touchPolicy: "never", publicKey: nil},
		"an error":     {serial: "12345678", pinPolicy: "once", touchPolicy: "never", publicErr: errors.New("no such slot")},
	} {
		t.Run(name, func(t *testing.T) {
			provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatal(err)
			}
			output, contentType, execErr := provider.Execute(context.Background(), route(), "public-key", "", "", nil, nil)
			if execErr == nil {
				t.Fatalf("public-key returned %q as %q for a card that gave %s", output, contentType, name)
			}
			if !errors.Is(execErr, ErrUnavailable) {
				t.Fatalf("error = %v, want ErrUnavailable", execErr)
			}
		})
	}
}

// The name says PKIX, so the test must hold the pipeline to that and not merely to "some bytes,
// non-empty, labelled application/pkix". Written first with the placeholder "public" as the card's
// answer, it asserted a content type over something no parser would accept — which is the same
// mistake as the wrap-format fixture below, one field along.
func TestPublicKeyReturnsTheCardsAnswerAsPKIX(t *testing.T) {
	publicKey := rsaPublicKeyDER(t)
	session := wrappableSession(t, publicKey)
	provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}

	output, contentType, execErr := provider.Execute(context.Background(), route(), "public-key", "", "", nil, nil)
	if execErr != nil {
		t.Fatalf("public-key error = %v: the refusals above prove nothing if the success path also fails", execErr)
	}
	if contentType != "application/pkix" {
		t.Fatalf("content type = %q, want application/pkix", contentType)
	}
	// Parsed, not just compared: the claim is that what comes back is a public key a caller can
	// use, and byte equality would hold just as well for bytes nothing can read.
	parsed, parseErr := x509.ParsePKIXPublicKey(output)
	if parseErr != nil {
		t.Fatalf("the bytes returned as application/pkix do not parse as one: %v", parseErr)
	}
	recovered, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("parsed as %T, want an RSA public key", parsed)
	}
	expected, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Equal(expected) {
		t.Fatal("the key returned is not the one the card holds")
	}
	if !session.closed {
		t.Fatal("the session was left open after a public-key read")
	}
}

// rsaPublicKeyDER is a real PKIX-encoded RSA-2048 public key. Generated once per test rather than
// once per case: key generation is the slowest thing here, and the cases differ in what they ask
// of the provider, not in which key the card holds.
func rsaPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// wrappableSession is a card holding a real key, so a wrap that gets past the format check
// actually succeeds. The format test was written first against a session whose "public key" was
// the literal "public", and it passed with the format check DELETED — the wrap failed anyway,
// because keywrap could not parse the fixture's key. Right verdict, wrong guard, and the check
// could have been removed without a red.
func wrappableSession(t *testing.T, publicKey []byte) *riggedSession {
	t.Helper()
	session := healthySession()
	session.publicKey = publicKey
	return session
}

// TestWrapRefusesAnyFormatButTheEnvelope. The wrap output is a wrapped_data_key destined for a
// regalia-envelope-v2 document; producing one for a caller who asked for another format would put
// bytes only that envelope can interpret into something that is not one.
//
// The fixture differs from TestWrapProducesAWrappedKeyForTheEnvelope in the format ALONE, which is
// what makes the refusal attributable to the format.
func TestWrapRefusesAnyFormatButTheEnvelope(t *testing.T) {
	publicKey := rsaPublicKeyDER(t)
	for _, format := range []string{"", "pkcs8"} {
		session := wrappableSession(t, publicKey)
		provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
		if err != nil {
			t.Fatal(err)
		}
		wrapRoute := route()
		wrapRoute.Algorithm = "rsa2048"

		output, _, execErr := provider.Execute(context.Background(), wrapRoute, "wrap", format, "", []byte("data-key"), []byte("aad"))
		if execErr == nil {
			t.Fatalf("wrap accepted format %q and produced %d bytes", format, len(output))
		}
		if !errors.Is(execErr, ErrUnavailable) {
			t.Fatalf("format %q: error = %v, want ErrUnavailable", format, execErr)
		}
	}
}

func TestWrapProducesAWrappedKeyForTheEnvelope(t *testing.T) {
	session := wrappableSession(t, rsaPublicKeyDER(t))
	provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	wrapRoute := route()
	wrapRoute.Algorithm = "rsa2048"

	output, contentType, execErr := provider.Execute(context.Background(), wrapRoute, "wrap", "regalia-envelope-v2", "", []byte("data-key"), []byte("aad"))
	if execErr != nil {
		t.Fatalf("wrap error = %v: the format refusals above prove nothing if no format works", execErr)
	}
	if contentType != "application/vnd.regalia.wrapped-key" {
		t.Fatalf("content type = %q", contentType)
	}
	if len(output) != 256 {
		t.Fatalf("wrapped key is %d bytes, want 256 for RSA-2048: a passthrough would not be this length", len(output))
	}
	if bytes.Contains(output, []byte("data-key")) {
		t.Fatal("the plaintext data key appears verbatim in the wrap output")
	}
}

// TestABindingTheProviderCannotServeIsRefusedBeforeTheCardIsOpened. Every one of these is a
// manifest that should never have loaded; reaching the card at all would mean the daemon is
// acting on a binding it cannot honour.
func TestABindingTheProviderCannotServeIsRefusedBeforeTheCardIsOpened(t *testing.T) {
	mutate := map[string]func(*registry.Binding){
		"another backend's binding": func(b *registry.Binding) { b.Backend = "nitrokey-pkcs11" },
		"no device id":              func(b *registry.Binding) { b.DeviceID = "" },
		"no pinned serial":          func(b *registry.Binding) { b.DeviceSerial = "" },
		"no slot":                   func(b *registry.Binding) { b.ObjectID = "" },
		"touch required":            func(b *registry.Binding) { b.TouchPolicy = "always" },
		"no touch policy at all":    func(b *registry.Binding) { b.TouchPolicy = "" },
		"an unknown PIN policy":     func(b *registry.Binding) { b.PINPolicy = "never" },
	}
	for name, apply := range mutate {
		t.Run(name, func(t *testing.T) {
			session := healthySession()
			provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatal(err)
			}
			bad := route()
			apply(&bad.Binding)

			if _, _, execErr := provider.Execute(context.Background(), bad, "sign", "", "application/octet-stream", []byte("payload"), nil); !errors.Is(execErr, ErrUnavailable) {
				t.Fatalf("%s was served: error = %v", name, execErr)
			}
			// Before the card, not merely instead of the signature: opening a session against a
			// binding the provider cannot honour is already the wrong action.
			if session.closed || session.signed {
				t.Fatalf("%s reached the card (closed=%v signed=%v)", name, session.closed, session.signed)
			}
		})
	}
}
