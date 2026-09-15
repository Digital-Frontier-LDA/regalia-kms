package nitrokey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func peerKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func agreementProvider(t *testing.T) (*Provider, *fakeSession) {
	t.Helper()
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider, session
}

func agree(t *testing.T, provider *Provider, peer, context_ []byte) ([]byte, string, error) {
	t.Helper()
	return provider.Execute(context.Background(), registry.Route{Algorithm: "p256", Binding: binding()},
		"key-agreement", "", "", peer, context_)
}

// THE RAW SHARED SECRET IS NEVER RETURNED.
//
// An ECDH result is a curve coordinate: secret, but not uniformly random, and a caller handed one
// will use it as a key. The provider runs it through HKDF, so the output must differ from the raw
// value the card produced and must be a full-length uniform key.
func TestKeyAgreementReturnsADerivedKeyNotTheRawSecret(t *testing.T) {
	provider, session := agreementProvider(t)
	peer := peerKey(t)

	derived, contentType, err := agree(t, provider, peer, []byte("sops:production:data-key"))
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if len(derived) != 32 {
		t.Fatalf("derived key is %d bytes, want 32", len(derived))
	}
	if contentType != "application/vnd.regalia.derived-key" {
		t.Fatalf("content type = %q", contentType)
	}
	raw, err := session.Derive(context.Background(), "01", "p256", peer)
	if err != nil {
		t.Fatal(err)
	}

	// ASSERT THE EXACT VALUE, not merely "different from the raw secret".
	//
	// An earlier version of this test only checked inequality, and it PASSED when the provider was
	// changed to return the raw secret: `defer zero(shared)` wipes the backing array the returned
	// slice points at, so the caller received 32 zero bytes, which differ from the raw secret and
	// satisfied a difference check. Comparing against the expected derivation catches both the
	// leak and the zeroed-output failure it was hiding behind.
	expected, err := hkdf.Key(sha256.New, raw, nil, "sops:production:data-key", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(derived, expected) {
		t.Fatalf("derived key is not HKDF over the shared secret bound to the context")
	}
	if bytes.Equal(derived, make([]byte, 32)) {
		t.Fatal("derived key is all zeroes")
	}
	if bytes.Equal(derived, raw) || bytes.Contains(derived, raw) {
		t.Fatal("the raw ECDH shared secret was returned to the caller")
	}
}

// CONTEXT BINDING IS MANDATORY AND IT CHANGES THE KEY.
//
// Without binding, one derivation could be repurposed for any other use of the same peer key.
func TestKeyAgreementIsBoundToTheRequestContext(t *testing.T) {
	provider, _ := agreementProvider(t)
	peer := peerKey(t)

	first, _, err := agree(t, provider, peer, []byte("purpose-a"))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := agree(t, provider, peer, []byte("purpose-b"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("the same peer key yields the same derived key under different contexts")
	}
	again, _, err := agree(t, provider, peer, []byte("purpose-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("derivation is not deterministic for the same peer key and context")
	}

	// An unbound derivation is refused outright.
	if output, _, err := agree(t, provider, peer, nil); err == nil || len(output) != 0 {
		t.Fatal("key agreement without a request context was permitted")
	}
}

// A failing card yields no material and the backend-unavailable class.
func TestKeyAgreementFailsClosedOnCardFailure(t *testing.T) {
	provider, session := agreementProvider(t)
	session.deriveErr = errors.New("token gone")
	output, contentType, err := agree(t, provider, peerKey(t), []byte("purpose"))
	if err == nil || len(output) != 0 || contentType != "" {
		t.Fatalf("output=%q type=%q err=%v", output, contentType, err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// A malformed peer key is refused before any derivation is attempted.
func TestKeyAgreementRefusesAMalformedPeerKey(t *testing.T) {
	provider, _ := agreementProvider(t)
	for _, peer := range [][]byte{nil, []byte("not-a-key"), {0x30, 0x00}} {
		output, _, err := agree(t, provider, peer, []byte("purpose"))
		if err == nil || len(output) != 0 {
			t.Fatalf("a malformed peer key (%d bytes) produced output", len(peer))
		}
	}
}
