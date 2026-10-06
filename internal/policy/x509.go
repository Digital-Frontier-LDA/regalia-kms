package policy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
)

var ErrX509Malformed = errors.New("X.509 signing input is malformed or unsupported")
var x509ProfileID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
var x509FingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// X509Policy is a server-owned issuing profile. IssuerDER is a public,
// constrained intermediate certificate; no private key belongs in this policy.
type X509Policy struct {
	ID              string
	IssuerDER       []byte
	DNSSuffixes     []string
	MaxLeafValidity time.Duration
	MaxCRLValidity  time.Duration
	LeafPerDay      uint64
	CRLPerDay       uint64
}

// X509TBS is produced from complete signing bytes by ParseX509TBS. Its private
// fields prevent callers from asserting certificate properties without parsing.
type X509TBS struct {
	certificate *x509.Certificate
	crl         *x509.RevocationList
	digest      string
}

func (input *X509TBS) Kind() string {
	if input == nil {
		return ""
	}
	if input.certificate != nil {
		return "certificate"
	}
	if input.crl != nil {
		return "crl"
	}
	return ""
}
func (input *X509TBS) Digest() string {
	if input == nil {
		return ""
	}
	return input.digest
}

type compiledX509 struct {
	profile        X509Policy
	issuer         *x509.Certificate
	keyFingerprint string
}

func compileX509(input *X509Policy) (*compiledX509, error) {
	if input == nil || !x509ProfileID.MatchString(input.ID) || len(input.IssuerDER) == 0 || len(input.IssuerDER) > 32<<10 ||
		len(input.DNSSuffixes) == 0 || len(input.DNSSuffixes) > 8 || input.MaxLeafValidity <= 0 || input.MaxLeafValidity > 24*time.Hour ||
		input.MaxCRLValidity <= 0 || input.MaxCRLValidity > 24*time.Hour || input.LeafPerDay == 0 || input.CRLPerDay == 0 {
		return nil, errors.New("X.509 profile requires bounded explicit identifiers, issuer, names, lifetimes and quotas")
	}
	profile := *input
	profile.IssuerDER = bytes.Clone(input.IssuerDER)
	profile.DNSSuffixes = slices.Clone(input.DNSSuffixes)
	seen := map[string]bool{}
	for _, suffix := range profile.DNSSuffixes {
		if !x509DNSName(suffix) || !strings.Contains(suffix, ".") || seen[suffix] {
			return nil, errors.New("X.509 profile DNS suffixes must be explicit unique lowercase DNS names")
		}
		seen[suffix] = true
	}
	issuer, err := x509.ParseCertificate(profile.IssuerDER)
	if err != nil {
		return nil, errors.New("X.509 profile issuer certificate is invalid")
	}
	fields, err := x509DERSequence(issuer.RawTBSCertificate, 12)
	if err != nil || len(fields) != 8 || fields[0].Class != 2 || fields[0].Tag != 0 || fields[7].Class != 2 || fields[7].Tag != 3 ||
		!x509CertificateDER(fields) || !x509ExtensionsDER(fields[7], issuer.Extensions) || !x509IssuerDNSConstraintsDER(issuer) {
		return nil, errors.New("X.509 profile issuer certificate contains unsupported DER fields")
	}
	key, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || !issuer.IsCA || !issuer.BasicConstraintsValid || issuer.MaxPathLen != 0 || !issuer.MaxPathLenZero ||
		issuer.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(issuer.SubjectKeyId) == 0 || len(issuer.SubjectKeyId) > 64 ||
		len(issuer.UnhandledCriticalExtensions) != 0 || !issuer.NotAfter.After(issuer.NotBefore) || bytes.Equal(issuer.RawIssuer, issuer.RawSubject) || !issuer.PermittedDNSDomainsCritical || len(issuer.PermittedDNSDomains) == 0 ||
		len(issuer.PermittedDNSDomains) > 8 || len(issuer.ExcludedDNSDomains)+len(issuer.PermittedIPRanges)+len(issuer.ExcludedIPRanges)+
		len(issuer.PermittedEmailAddresses)+len(issuer.ExcludedEmailAddresses)+len(issuer.PermittedURIDomains)+len(issuer.ExcludedURIDomains) != 0 {
		return nil, errors.New("X.509 profile issuer must be a constrained P-256 intermediate with explicit signing usages and key identity")
	}
	for _, constraint := range issuer.PermittedDNSDomains {
		if !x509DNSName(strings.TrimPrefix(constraint, ".")) {
			return nil, errors.New("X.509 profile issuer DNS constraints are unsupported")
		}
	}
	for _, suffix := range profile.DNSSuffixes {
		permitted := false
		for _, constraint := range issuer.PermittedDNSDomains {
			base := strings.TrimPrefix(constraint, ".")
			permitted = permitted || (!strings.HasPrefix(constraint, ".") && suffix == base) || strings.HasSuffix(suffix, "."+base)
		}
		if !permitted {
			return nil, errors.New("X.509 profile DNS suffix exceeds the pinned issuer constraints")
		}
	}
	digest := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return &compiledX509{profile: profile, issuer: issuer, keyFingerprint: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

func (profile *compiledX509) validate(input *X509TBS, now time.Time, signerFingerprint string) (string, string) {
	kind := input.Kind()
	if profile == nil || input == nil || kind == "" || input.digest == "" {
		return kind, "x509-input"
	}
	if signerFingerprint == "" || signerFingerprint != profile.keyFingerprint {
		return kind, "x509-key"
	}
	issuer := profile.issuer
	if now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
		return kind, "x509-issuer-validity"
	}
	if kind == "certificate" {
		cert := input.certificate
		if !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) {
			return kind, "x509-issuer"
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if cert.Version != 3 || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 160 || cert.IsCA || !cert.BasicConstraintsValid || cert.MaxPathLen != -1 || cert.MaxPathLenZero ||
			cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
			len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || !ok || key.Curve != elliptic.P256() ||
			!x509KnownExtensions(cert.Extensions, map[string]bool{"2.5.29.14": true, "2.5.29.15": true, "2.5.29.17": true, "2.5.29.19": true, "2.5.29.35": true, "2.5.29.37": true}) {
			return kind, "x509-leaf-profile"
		}
		if cert.NotBefore.Before(now.Add(-time.Minute)) || cert.NotBefore.After(now.Add(10*time.Second)) || !cert.NotAfter.After(now) ||
			!cert.NotAfter.After(cert.NotBefore) || cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.After(issuer.NotAfter) || cert.NotAfter.Sub(cert.NotBefore) > profile.profile.MaxLeafValidity {
			return kind, "x509-validity"
		}
		if !x509LeafNames(cert, profile.profile.DNSSuffixes) {
			return kind, "x509-name"
		}
		return kind, ""
	}
	crl := input.crl
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return kind, "x509-issuer"
	}
	if crl.Number == nil || crl.Number.Sign() < 0 || crl.Number.BitLen() > 64 || len(crl.RevokedCertificateEntries) > 100 ||
		!x509KnownExtensions(crl.Extensions, map[string]bool{"2.5.29.35": true, "2.5.29.20": true, "2.5.29.27": true}) {
		return kind, "x509-crl-profile"
	}
	if crl.ThisUpdate.Before(now.Add(-time.Minute)) || crl.ThisUpdate.After(now.Add(10*time.Second)) || !crl.NextUpdate.After(now) ||
		!crl.NextUpdate.After(crl.ThisUpdate) || crl.ThisUpdate.Before(issuer.NotBefore) || crl.NextUpdate.After(issuer.NotAfter) || crl.NextUpdate.Sub(crl.ThisUpdate) > profile.profile.MaxCRLValidity {
		return kind, "x509-validity"
	}
	for _, extension := range crl.Extensions {
		if extension.Id.String() == "2.5.29.27" {
			var number *big.Int
			if rest, err := asn1.Unmarshal(extension.Value, &number); err != nil || len(rest) != 0 || !extension.Critical || number == nil || number.Sign() < 0 || number.BitLen() > 64 || number.Cmp(crl.Number) >= 0 {
				return kind, "x509-crl-profile"
			}
		}
	}
	seen := map[string]bool{}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || entry.SerialNumber.BitLen() > 160 || seen[entry.SerialNumber.String()] ||
			entry.RevocationTime.IsZero() || entry.RevocationTime.After(now.Add(10*time.Second)) || entry.ReasonCode != 0 || len(entry.Extensions) != 0 {
			return kind, "x509-crl-profile"
		}
		seen[entry.SerialNumber.String()] = true
	}
	return kind, ""
}

func x509DNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 || name != strings.ToLower(name) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func x509LeafNames(cert *x509.Certificate, suffixes []string) bool {
	if len(cert.DNSNames) == 0 || len(cert.DNSNames) > 8 || len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 {
		return false
	}
	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil || len(rest) != 0 || len(subject) != 1 || len(subject[0]) != 1 || subject[0][0].Type.String() != "2.5.4.3" {
		return false
	}
	matched := false
	for _, name := range cert.DNSNames {
		if !x509DNSName(name) {
			return false
		}
		allowed := false
		for _, suffix := range suffixes {
			allowed = allowed || name == suffix || strings.HasSuffix(name, "."+suffix)
		}
		if !allowed {
			return false
		}
		matched = matched || name == cert.Subject.CommonName
	}
	if !matched {
		return false
	}
	for _, extension := range cert.Extensions {
		if extension.Id.String() != "2.5.29.17" {
			continue
		}
		values, err := x509DERSequence(extension.Value, 16)
		if err != nil || len(values) != len(cert.DNSNames) {
			return false
		}
		for i, value := range values {
			if value.Class != 2 || value.Tag != 2 || value.IsCompound || string(value.Bytes) != cert.DNSNames[i] {
				return false
			}
		}
		return true
	}
	return false
}

func x509KnownExtensions(extensions []pkix.Extension, allowed map[string]bool) bool {
	for _, extension := range extensions {
		if !allowed[extension.Id.String()] {
			return false
		}
	}
	return true
}
