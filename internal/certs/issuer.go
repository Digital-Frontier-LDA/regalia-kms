package certs

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Hardware is the backend contract the coordinator already depends on.
type Hardware interface {
	Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error)
}

// ErrUnavailable mirrors the backends: the coordinator classifies on it.
var ErrUnavailable = errors.New("certificate issuer unavailable")

// Issuer answers "certificate-sign" and passes every other operation straight through.
//
// It is a decorator rather than a branch inside the coordinator or a case inside a hardware
// provider, because X.509 belongs in neither: the coordinator does authorization, policy and audit,
// and the provider talks to one token. The issuer sits between them and turns one on-card SIGN into
// a certificate, so the hardware layer keeps its single job and the private key never moves.
type Issuer struct {
	inner       Hardware
	certificate *x509.Certificate
	profile     Profile
	now         func() time.Time
}

func NewIssuer(inner Hardware, caCertificate *x509.Certificate, profile Profile, now func() time.Time) (*Issuer, error) {
	if inner == nil || caCertificate == nil || now == nil {
		return nil, errors.New("issuer requires a backend, an issuer certificate and a clock")
	}
	if len(profile.AllowedDNSSuffixes) == 0 || profile.Validity <= 0 {
		return nil, errors.New("issuer requires a profile that permits at least one name and a positive validity")
	}
	return &Issuer{inner: inner, certificate: caCertificate, profile: profile, now: now}, nil
}

func (issuer *Issuer) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error) {
	if issuer == nil || issuer.inner == nil {
		return nil, "", ErrUnavailable
	}
	if operation != "certificate-sign" {
		return issuer.inner.Execute(ctx, route, operation, format, contentType, data, aad)
	}
	// A passthrough issuer has no CA. certificate-sign is then unavailable rather than served
	// under some default profile — and refusing here avoids dereferencing the absent certificate.
	if issuer.certificate == nil {
		return nil, "", errors.New("no certificate issuer is configured")
	}

	// The CA public key must be the one the route actually holds, or the certificate would be
	// signed by a key that does not match the issuer certificate it names. Ask the token.
	publicKey, _, err := issuer.inner.Execute(ctx, route, "public-key", "", "", nil, nil)
	if err != nil || len(publicKey) == 0 {
		return nil, "", ErrUnavailable
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	if !matchesIssuerCertificate(parsed, issuer.certificate) {
		// The configured issuer certificate and the routed key disagree. Signing anyway would
		// produce certificates that never verify against the chain we publish.
		return nil, "", ErrUnavailable
	}

	signer := &CardSigner{PublicKey: parsed, Sign_: func(payload []byte) ([]byte, error) {
		signature, _, signErr := issuer.inner.Execute(ctx, route, "sign", "raw", "application/octet-stream", payload, nil)
		if signErr != nil {
			return nil, signErr
		}
		return signature, nil
	}}

	certificate, err := Issue(issuer.certificate, signer, data, issuer.profile, issuer.now())
	if err != nil {
		// A refusal here is the caller's fault (a bad or out-of-namespace CSR), not a hardware
		// fault, so it must not be reported as an unavailable backend and retried.
		return nil, "", err
	}
	return certificate, "application/pkix-cert", nil
}

func matchesIssuerCertificate(candidate crypto.PublicKey, certificate *x509.Certificate) bool {
	type equalizer interface{ Equal(crypto.PublicKey) bool }
	comparable, ok := certificate.PublicKey.(equalizer)
	if !ok {
		return false
	}
	return comparable.Equal(candidate)
}

// NewPassthrough wraps a backend without certificate issuing. A host with no configured CA still
// needs an Issuer-shaped value for the coordinator, and this makes certificate-sign unavailable
// rather than available under some default profile.
func NewPassthrough(inner Hardware) (*Issuer, error) {
	if inner == nil {
		return nil, errors.New("passthrough requires a backend")
	}
	return &Issuer{inner: inner}, nil
}
