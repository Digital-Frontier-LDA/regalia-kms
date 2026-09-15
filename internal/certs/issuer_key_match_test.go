package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// TestAnIssuerKeyMismatchIsUnavailableRatherThanAnOpaqueX509Failure pins
// issuer.go's `!matchesIssuerCertificate(parsed, issuer.certificate)`.
//
// TestRoutedKeyMustMatchTheIssuerCertificate is named for this property and does not pin it.
// It builds the right fixture — the token holding a key the CA certificate does not name — and
// then asserts only `err == nil || len(output) != 0`. An error comes back either way, so the
// assertion is satisfied with the guard removed. Measured: replacing the whole condition with
// `false` leaves the entire dependent suite green.
//
// WHAT ACTUALLY REFUSES WITHOUT THE GUARD IS crypto/x509, NOT US. CreateCertificate rejects a
// signer whose public key does not match the parent certificate, so a mismatched key cannot
// produce a certificate in either case and this is not a signing bypass. The guard is a
// fail-fast in front of a check the standard library already makes.
//
// It is still worth pinning, because the two paths do not return the same thing:
//
//	guard intact  errors.Is(err, ErrUnavailable) = true
//	              "certificate issuer unavailable"
//	guard removed errors.Is(err, ErrUnavailable) = false
//	              "certificate signing failed: x509: provided PrivateKey doesn't match parent's PublicKey"
//
// ErrUnavailable is the sentinel the coordinator branches on to tell a hardware or configuration
// problem it may retry or fail over from a request it must reject. With the guard gone that
// classification is lost and the caller receives a wrapped standard-library string instead — so
// this asserts the IDENTITY, which is the thing that changes, not the message text.
func TestAnIssuerKeyMismatchIsUnavailableRatherThanAnOpaqueX509Failure(t *testing.T) {
	issuer, card, _ := issuerFixture(t)

	// THE CONTROL, in the same run and through the same call. Without it every assertion below
	// passes against an Execute that returns ErrUnavailable for everything, and none of them is
	// evidence. It also proves the fixture reaches the signing path at all.
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, err := issuer.Execute(context.Background(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", newCSR(t, "api.staging.internal", nil, subjectKey), nil)
	if err != nil || len(certificate) == 0 {
		t.Fatalf("control: a matching issuer key produced no certificate (%v) — every assertion "+
			"below would pass against an Execute that refuses everything", err)
	}

	// THE GATE. Same issuer, same CSR shape; the only change is that the token now holds a key
	// the CA certificate does not name.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card.key = otherKey

	output, _, err := issuer.Execute(context.Background(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", newCSR(t, "api.staging.internal", nil, subjectKey), nil)
	if len(output) != 0 {
		t.Fatalf("a certificate was issued for a key that is not the configured issuer; it would "+
			"never verify against the chain this host publishes (%d bytes)", len(output))
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a routed key that disagrees with the issuer certificate returned %v, which is "+
			"not ErrUnavailable — the coordinator branches on that sentinel to tell a hardware or "+
			"configuration fault from a bad request, and without the issuer check the caller gets "+
			"a wrapped crypto/x509 string it cannot classify", err)
	}
	// crypto/x509 is what refuses when our guard is gone, so its message is the tell. Asserting
	// its absence keeps this test honest about WHICH layer answered.
	if strings.Contains(err.Error(), "x509:") {
		t.Fatalf("the refusal came from crypto/x509 rather than from the issuer check: %v", err)
	}
}
