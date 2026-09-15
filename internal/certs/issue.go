package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Profile is the server's decision about what a certificate may say. The caller supplies a CSR;
// the profile supplies everything that carries authority.
//
// The ADR is explicit that a caller "cannot select a reader, slot, backend or arbitrary mechanism",
// and the same reasoning applies to certificate contents: a CSR is a REQUEST, and the parts of it
// that grant power — CA status, key usage, lifetime, names outside the delegated namespace — are
// taken from here, never from the request.
type Profile struct {
	// AllowedDNSSuffixes limits the namespace this issuer may certify. Empty means nothing is
	// allowed: an unconfigured profile must not be a permissive one.
	AllowedDNSSuffixes []string
	Validity           time.Duration
	KeyUsage           x509.KeyUsage
	ExtKeyUsage        []x509.ExtKeyUsage
}

const (
	maxCSRBytes    = 8 << 10
	minRSABits     = 2048
	maxSANsPerCert = 16
)

// Issue validates a CSR against the profile and returns a signed certificate in DER.
//
// caCertificate is the issuer; caSigner is the on-card key (see CardSigner). The CSR's public key
// is certified; its requested extensions are not honoured.
func Issue(caCertificate *x509.Certificate, caSigner crypto.Signer, csrDER []byte, profile Profile, now time.Time) ([]byte, error) {
	if caCertificate == nil || caSigner == nil {
		return nil, errors.New("issuer is not configured")
	}
	if !caCertificate.IsCA || caCertificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("issuer certificate may not sign certificates")
	}
	if now.Before(caCertificate.NotBefore) || now.After(caCertificate.NotAfter) {
		return nil, errors.New("issuer certificate is not valid at this time")
	}
	if profile.Validity <= 0 {
		return nil, errors.New("profile validity must be positive")
	}
	if len(profile.AllowedDNSSuffixes) == 0 {
		return nil, errors.New("profile permits no names: refusing to issue")
	}
	if len(csrDER) == 0 || len(csrDER) > maxCSRBytes {
		return nil, errors.New("certificate request is empty or oversized")
	}

	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, errors.New("certificate request is malformed")
	}
	// A CSR proves the requester holds the private key. Skipping this check would let anyone
	// certify a public key they do not control.
	if err := request.CheckSignature(); err != nil {
		return nil, errors.New("certificate request signature does not verify")
	}
	if err := acceptableSubjectKey(request.PublicKey); err != nil {
		return nil, err
	}

	names, err := permittedNames(request, profile)
	if err != nil {
		return nil, err
	}

	// The certificate lifetime may not outlive the issuer's own.
	notAfter := now.Add(profile.Validity)
	if notAfter.After(caCertificate.NotAfter) {
		return nil, errors.New("requested validity outlives the issuer certificate")
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 127)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, errors.New("could not allocate a certificate serial")
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		// Only the common name is carried across, and only when it is itself a permitted name.
		Subject:     pkix.Name{CommonName: names[0]},
		DNSNames:    names,
		NotBefore:   now.Add(-time.Minute), // small skew allowance
		NotAfter:    notAfter,
		KeyUsage:    profile.KeyUsage,
		ExtKeyUsage: profile.ExtKeyUsage,
		// Never a CA, whatever the request asked for.
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, caCertificate, request.PublicKey, caSigner)
	if err != nil {
		return nil, fmt.Errorf("certificate signing failed: %w", err)
	}
	return certificate, nil
}

// acceptableSubjectKey refuses keys that are too weak to certify, regardless of what the CSR asks.
func acceptableSubjectKey(public crypto.PublicKey) error {
	switch key := public.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < minRSABits {
			return fmt.Errorf("RSA subject key is %d bits, minimum is %d", key.N.BitLen(), minRSABits)
		}
		return nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		}
		return errors.New("unsupported elliptic curve in certificate request")
	default:
		return errors.New("unsupported subject key type in certificate request")
	}
}

// permittedNames returns the requested names that fall inside the delegated namespace, refusing the
// whole request if any name falls outside it. Silently dropping a name would issue a certificate
// that does not say what the requester asked for, which is worse than a clear refusal.
func permittedNames(request *x509.CertificateRequest, profile Profile) ([]string, error) {
	requested := make([]string, 0, maxSANsPerCert+1)
	if request.Subject.CommonName != "" {
		requested = append(requested, request.Subject.CommonName)
	}
	requested = append(requested, request.DNSNames...)
	if len(requested) == 0 {
		return nil, errors.New("certificate request names nothing")
	}
	if len(requested) > maxSANsPerCert {
		return nil, errors.New("certificate request names too many hosts")
	}
	// IP, email and URI SANs are not delegated by this profile; a request carrying them is refused
	// rather than quietly issued without them.
	if len(request.IPAddresses) > 0 || len(request.EmailAddresses) > 0 || len(request.URIs) > 0 {
		return nil, errors.New("certificate request carries a name type this profile does not issue")
	}

	seen := make(map[string]struct{}, len(requested))
	names := make([]string, 0, len(requested))
	for _, name := range requested {
		lowered := strings.ToLower(strings.TrimSpace(name))
		if lowered == "" || strings.ContainsAny(lowered, " \t*") {
			return nil, errors.New("certificate request contains an unusable name")
		}
		if !withinSuffixes(lowered, profile.AllowedDNSSuffixes) {
			return nil, fmt.Errorf("name %q is outside this issuer's namespace", lowered)
		}
		if _, duplicate := seen[lowered]; duplicate {
			continue
		}
		seen[lowered] = struct{}{}
		names = append(names, lowered)
	}
	return names, nil
}

func withinSuffixes(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix == "" {
			continue
		}
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}
