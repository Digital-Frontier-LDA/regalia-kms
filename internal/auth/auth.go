// Package auth authenticates workload certificates and applies deny-by-default RBAC.
package auth

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// DefaultClockSkew is the certificate validity tolerance the daemon runs with.
//
// It was an unexplained `time.Minute` at the call site in cmd/regalia-kms, which said what the
// value is and nothing about why that value. The tolerance exists because a workload's clock and
// the KMS's clock disagree by small amounts; it is deliberately small, because every second of it
// is a second an expired certificate is still accepted. Widening it is a security decision and
// belongs here, next to that sentence, rather than in an argument list.
//
// Tests that exercise skew behaviour pass their own value on purpose -- a test reading this constant
// would move with it and could never detect a change to it.
const DefaultClockSkew = time.Minute

type contextKey struct{}

type Authenticator struct {
	uriPrefix  string
	revocation *RevocationList
	now        func() time.Time
	clockSkew  time.Duration
	// unauthorized fires on each rejected request. Rejections die here, before any
	// route or handler runs, so nothing downstream can count them — and probing or
	// an expired client certificate would otherwise be invisible until a caller
	// complained.
	unauthorized func()
}

// OnUnauthorized registers the rejected-request counter.
func (authenticator *Authenticator) OnUnauthorized(record func()) {
	authenticator.unauthorized = record
}

func NewAuthenticator(uriPrefix string, revocation *RevocationList, now func() time.Time, clockSkew time.Duration) *Authenticator {
	return &Authenticator{uriPrefix: uriPrefix, revocation: revocation, now: now, clockSkew: clockSkew}
}

func (authenticator *Authenticator) Authenticate(request *http.Request) (string, error) {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.VerifiedChains[0]) == 0 {
		return "", errors.New("request authentication failed")
	}
	certificate := request.TLS.VerifiedChains[0][0]
	if certificate.SerialNumber == nil {
		return "", errors.New("request authentication failed")
	}
	if revocation := authenticator.revocation; revocation != nil {
		// Revocation is checked before clock-skew and SPIFFE-shape so that a revoked
		// cert with a future NotBefore still fails closed: the serial is the only
		// input the operator controls, and an unreadable list is "cannot tell", not
		// "nobody is revoked".
		revoked, err := revocation.Check(certificate.SerialNumber.String())
		if err != nil {
			return "", errors.New("request authentication failed")
		}
		if revoked {
			return "", errors.New("request authentication failed")
		}
	}
	now := authenticator.now()
	if certificate.NotBefore.After(now.Add(authenticator.clockSkew)) || certificate.NotAfter.Before(now.Add(-authenticator.clockSkew)) {
		return "", errors.New("request authentication failed")
	}
	if !permitsClientAuthentication(certificate) || len(certificate.URIs) != 1 {
		return "", errors.New("request authentication failed")
	}
	principalURI := certificate.URIs[0]
	prefix, err := url.Parse(authenticator.uriPrefix)
	if err != nil || !canonicalURISAN(principalURI, prefix) {
		return "", errors.New("request authentication failed")
	}
	principal := principalURI.String()
	return principal, nil
}

func canonicalURISAN(candidate, prefix *url.URL) bool {
	if candidate == nil || prefix == nil || prefix.Scheme == "" || prefix.Host == "" ||
		candidate.Scheme != prefix.Scheme || candidate.Host != prefix.Host || candidate.User != nil ||
		candidate.RawQuery != "" || candidate.Fragment != "" || candidate.ForceQuery ||
		candidate.Opaque != "" || candidate.RawPath != "" {
		return false
	}
	return candidate.Path != prefix.Path && strings.HasPrefix(candidate.Path, prefix.Path) &&
		path.Clean(candidate.Path) == candidate.Path
}

func permitsClientAuthentication(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth || usage == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func (authenticator *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v1/health/live" || request.URL.Path == "/v1/health/ready" {
			next.ServeHTTP(writer, request)
			return
		}
		principal, err := authenticator.Authenticate(request)
		if err != nil {
			if authenticator.unauthorized != nil {
				authenticator.unauthorized()
			}
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), contextKey{}, principal)))
	})
}

func Principal(ctx context.Context) string {
	principal, _ := ctx.Value(contextKey{}).(string)
	return principal
}

// ServerTLSConfig permits unauthenticated health handshakes but verifies any
// presented client chain. Middleware makes a verified client mandatory for all
// non-health routes. Hardware-backed keys work because tls.Certificate accepts
// crypto.Signer implementations; callers need not expose key bytes.
func ServerTLSConfig(serverCertificate tls.Certificate, clientRoots *x509.CertPool) (*tls.Config, error) {
	if clientRoots == nil {
		return nil, errors.New("client trust roots are required")
	}
	if _, ok := serverCertificate.PrivateKey.(crypto.Signer); !ok {
		return nil, errors.New("server TLS private key must implement crypto.Signer")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientRoots,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}
