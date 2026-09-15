package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// fakeCard answers the two operations the issuer depends on, the way a token would.
type fakeCard struct {
	key        crypto.Signer
	t          *testing.T
	signCalls  int
	publicErr  error
	signErr    error
	passthru   int
	lastOpName string
}

func (card *fakeCard) Execute(_ context.Context, _ registry.Route, operation, _, _ string, data, _ []byte) ([]byte, string, error) {
	card.lastOpName = operation
	switch operation {
	case "public-key":
		if card.publicErr != nil {
			return nil, "", card.publicErr
		}
		der, err := x509.MarshalPKIXPublicKey(card.key.Public())
		if err != nil {
			card.t.Fatal(err)
		}
		return der, "application/pkix", nil
	case "sign":
		card.signCalls++
		if card.signErr != nil {
			return nil, "", card.signErr
		}
		signature, err := emulateCard(card.t, card.key)(data)
		if err != nil {
			return nil, "", err
		}
		return signature, "application/octet-stream", nil
	default:
		card.passthru++
		return []byte("passed-through"), "application/octet-stream", nil
	}
}

func issuerFixture(t *testing.T) (*Issuer, *fakeCard, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	card := &fakeCard{key: caKey, t: t}
	issuer, err := NewIssuer(card, ca, staging(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, card, ca
}

// THE WHOLE PATH: a CSR in, a verifiable certificate out, signed by the card.
func TestIssuerSignsThroughTheCardAndTheResultVerifies(t *testing.T) {
	issuer, card, ca := issuerFixture(t)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)

	der, contentType, err := issuer.Execute(context.Background(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", csr, nil)
	if err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if contentType != "application/pkix-cert" {
		t.Fatalf("content type = %q", contentType)
	}
	if card.signCalls != 1 {
		t.Fatalf("card signed %d times, want exactly 1", card.signCalls)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("issued certificate does not verify against the issuer: %v", err)
	}
}

// Every other operation passes straight through: the decorator must be invisible to them.
func TestIssuerPassesOtherOperationsThrough(t *testing.T) {
	issuer, _, _ := issuerFixture(t)
	for _, operation := range []string{"sign", "wrap", "unwrap"} {
		output, _, err := issuer.Execute(context.Background(), registry.Route{}, operation, "", "", []byte("x"), nil)
		if err != nil {
			t.Fatalf("%s passthrough failed: %v", operation, err)
		}
		if operation != "sign" && string(output) != "passed-through" {
			t.Fatalf("%s did not reach the backend", operation)
		}
	}
}

// A ROUTED KEY THAT IS NOT THE CONFIGURED ISSUER MUST NOT SIGN.
//
// Otherwise the KMS would mint certificates signed by a key that does not match the issuer
// certificate it names — they would chain to nothing, and the failure would surface at every
// relying party rather than here.
func TestRoutedKeyMustMatchTheIssuerCertificate(t *testing.T) {
	issuer, card, _ := issuerFixture(t)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	card.key = otherKey // the token now holds a different key than the CA certificate names

	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	output, _, err := issuer.Execute(context.Background(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", newCSR(t, "api.staging.internal", nil, subjectKey), nil)
	if err == nil || len(output) != 0 {
		t.Fatal("signed a certificate with a key that is not the configured issuer")
	}
	if card.signCalls != 0 {
		t.Fatal("the card was asked to sign before the key was proven to be the issuer")
	}
}

// Hardware failures stay hardware failures; a bad CSR does not become one.
func TestIssuerDistinguishesHardwareFailureFromABadRequest(t *testing.T) {
	issuer, card, _ := issuerFixture(t)
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	card.publicErr = errors.New("token gone")
	if _, _, err := issuer.Execute(context.Background(), registry.Route{}, "certificate-sign", "", "",
		newCSR(t, "api.staging.internal", nil, subjectKey), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("token failure = %v, want ErrUnavailable", err)
	}

	card.publicErr = nil
	// A CSR outside the namespace is the caller's fault: it must NOT be reported as an
	// unavailable backend, or a client would retry a request that can never succeed.
	_, _, err := issuer.Execute(context.Background(), registry.Route{}, "certificate-sign", "", "",
		newCSR(t, "api.example.com", nil, subjectKey), nil)
	if err == nil {
		t.Fatal("issued a certificate outside the namespace")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatal("a caller error was reported as a backend failure and would be retried")
	}
}

// A misconfigured issuer refuses to exist rather than defaulting to something permissive.
func TestIssuerRefusesIncompleteConfiguration(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(time.Hour))
	card := &fakeCard{key: caKey, t: t}

	if _, err := NewIssuer(nil, ca, staging(), time.Now); err == nil {
		t.Fatal("issuer built without a backend")
	}
	if _, err := NewIssuer(card, nil, staging(), time.Now); err == nil {
		t.Fatal("issuer built without an issuer certificate")
	}
	if _, err := NewIssuer(card, ca, Profile{Validity: time.Hour}, time.Now); err == nil {
		t.Fatal("issuer built with a profile that permits no names")
	}
	if _, err := NewIssuer(card, ca, Profile{AllowedDNSSuffixes: []string{"staging.internal"}}, time.Now); err == nil {
		t.Fatal("issuer built with no validity")
	}
}

// A host with no configured CA must refuse certificate-sign, not crash on the absent certificate
// and not serve it under a default profile.
func TestPassthroughRefusesCertificateSignAndForwardsTheRest(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	card := &fakeCard{key: caKey, t: t}
	issuer, err := NewPassthrough(card)
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := issuer.Execute(context.Background(), registry.Route{}, "certificate-sign", "", "", []byte("csr"), nil)
	if err == nil || len(output) != 0 {
		t.Fatal("a passthrough issuer signed a certificate without a configured CA")
	}
	if _, _, err := issuer.Execute(context.Background(), registry.Route{}, "unwrap", "", "", []byte("x"), nil); err != nil {
		t.Fatalf("passthrough did not forward a normal operation: %v", err)
	}
	if _, err := NewPassthrough(nil); err == nil {
		t.Fatal("passthrough built without a backend")
	}
}
