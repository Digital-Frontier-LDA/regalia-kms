package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// emulateCard returns a CardSign that behaves like the PKCS#11 mechanisms actually in use:
// CKM_RSA_PKCS pads exactly the bytes it is handed, and CKM_ECDSA returns a RAW r||s signature.
// Emulating the card faithfully is the point — it is what makes a wrong encoding fail here.
func emulateCard(t *testing.T, key crypto.Signer) CardSign {
	t.Helper()
	return func(payload []byte) ([]byte, error) {
		switch typed := key.(type) {
		case *rsa.PrivateKey:
			// CKM_RSA_PKCS: PKCS#1 v1.5 over the given bytes, with no hashing of its own.
			return rsa.SignPKCS1v15(rand.Reader, typed, crypto.Hash(0), payload)
		case *ecdsa.PrivateKey:
			r, s, err := ecdsa.Sign(rand.Reader, typed, payload)
			if err != nil {
				return nil, err
			}
			size := (typed.Curve.Params().BitSize + 7) / 8
			raw := make([]byte, 2*size)
			r.FillBytes(raw[:size])
			s.FillBytes(raw[size:])
			return raw, nil
		}
		t.Fatalf("unsupported key %T", key)
		return nil, nil
	}
}

func newCA(t *testing.T, key crypto.Signer, notAfter time.Time) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "regalia-staging-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func newCSR(t *testing.T, commonName string, dnsNames []string, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func staging() Profile {
	return Profile{
		AllowedDNSSuffixes: []string{"staging.internal"},
		Validity:           90 * 24 * time.Hour,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// THE ISSUED CERTIFICATE MUST ACTUALLY VERIFY, for both card mechanisms.
//
// This is the test that catches a wrong signature encoding: a certificate built with a raw ECDSA
// signature, or with RSA over a bare digest instead of a DigestInfo, parses perfectly and fails
// verification. Both key types are exercised because they fail in opposite ways.
func TestIssuedCertificateVerifiesAgainstTheIssuerForBothMechanisms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for _, caKey := range []crypto.Signer{rsaKey, ecKey} {
		ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
		signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}

		subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		csr := newCSR(t, "api.staging.internal", []string{"api.staging.internal"}, subjectKey)

		der, err := Issue(ca, signer, csr, staging(), time.Now())
		if err != nil {
			t.Fatalf("%T issuer: Issue() = %v", caKey, err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%T issuer: issued certificate does not parse: %v", caKey, err)
		}
		// The real check: the signature verifies against the issuer.
		if err := leaf.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("%T issuer: issued certificate does not verify: %v", caKey, err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, DNSName: "api.staging.internal",
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Fatalf("%T issuer: chain verification failed: %v", caKey, err)
		}
		if leaf.IsCA {
			t.Fatal("issued a CA certificate")
		}
	}
}

// THE CSR IS A REQUEST, NOT AN INSTRUCTION. The parts that carry authority come from the profile.
func TestRequestedAuthorityIsNotHonoured(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	der, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), staging(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.MaxPathLen > 0 {
		t.Fatal("issued certificate claims CA authority")
	}
	if leaf.KeyUsage != staging().KeyUsage {
		t.Fatalf("key usage = %v, want the profile's", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("extended key usage = %v, want the profile's", leaf.ExtKeyUsage)
	}
	if leaf.NotAfter.After(time.Now().Add(staging().Validity + time.Minute)) {
		t.Fatalf("validity %s exceeds the profile", leaf.NotAfter.Sub(time.Now()))
	}
}

// NAMES OUTSIDE THE DELEGATED NAMESPACE ARE REFUSED, not silently dropped: a certificate that does
// not say what was asked for is worse than a clear refusal.
func TestNamesOutsideTheNamespaceAreRefused(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cases := []struct {
		name       string
		commonName string
		dnsNames   []string
	}{
		{"foreign domain", "api.example.com", nil},
		{"suffix lookalike", "api.notstaging.internal", nil},
		{"one bad name among good ones", "api.staging.internal", []string{"evil.example.com"}},
		{"wildcard", "*.staging.internal", nil},
		{"suffix as prefix", "staging.internal.example.com", nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := Issue(ca, signer, newCSR(t, test.commonName, test.dnsNames, subjectKey), staging(), time.Now())
			if err == nil {
				t.Fatalf("issued a certificate for %q", test.commonName)
			}
		})
	}
}

// An unconfigured profile must not be a permissive one.
func TestEmptyProfileIssuesNothing(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)

	// EACH ROW ASSERTS ITS OWN MESSAGE. Checking only err != nil made the first row pass with the
	// profile rule removed, because an empty suffix list also makes every NAME fall outside the
	// namespace and permittedNames refuses it two guards later. The test named a guard it was not
	// exercising, and the mutation that deleted that guard went red for the wrong reason (§19).
	_, err := Issue(ca, signer, csr, Profile{Validity: time.Hour}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "profile permits no names") {
		t.Fatalf("err = %v, want a refusal naming the profile, not the name it then rejects", err)
	}
	_, err = Issue(ca, signer, csr, Profile{AllowedDNSSuffixes: []string{"staging.internal"}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "validity must be positive") {
		t.Fatalf("err = %v, want a refusal naming the validity", err)
	}
}

func TestWeakOrUnsupportedSubjectKeysAreRefused(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, weak), staging(), time.Now()); err == nil {
		t.Fatal("issued a certificate for a 1024-bit RSA key")
	}
}

// A CSR whose signature does not verify proves nothing about key possession.
func TestTamperedRequestIsRefused(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	csr := newCSR(t, "api.staging.internal", nil, subjectKey)
	csr[len(csr)-1] ^= 0xff // corrupt the signature
	if _, err := Issue(ca, signer, csr, staging(), time.Now()); err == nil {
		t.Fatal("issued a certificate from a CSR whose signature does not verify")
	}
}

// The leaf must never outlive the issuer.
func TestValidityMayNotOutliveTheIssuer(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newCA(t, caKey, time.Now().Add(24*time.Hour)) // expires long before the 90-day profile
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	_, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), staging(), time.Now())
	if err == nil || !strings.Contains(err.Error(), "outlives") {
		t.Fatalf("err = %v, want a refusal naming the issuer lifetime", err)
	}
}

// A card that returns nonsense must not yield a certificate.
func TestMalformedCardSignaturesAreRefused(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("tbs"))

	// THE ODD-LENGTH BYTES MUST NOT BE ZERO. With make([]byte, 65) this row passed with the
	// length rule removed, because splitting 65 zero bytes yields r = s = 0 and the ZERO rule
	// refused it instead — the row certified a guard it never reached (§19). Non-zero bytes
	// leave the length rule as the only thing that can object, and the message is asserted.
	oddBytes := make([]byte, 65)
	for i := range oddBytes {
		oddBytes[i] = byte(i + 1)
	}
	odd := &CardSigner{PublicKey: ecKey.Public(), Sign_: func([]byte) ([]byte, error) {
		return oddBytes, nil // odd length: not r||s
	}}
	if _, err := odd.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil ||
		!strings.Contains(err.Error(), "malformed raw ECDSA signature") {
		t.Fatalf("err = %v, want a refusal naming the raw signature shape", err)
	}
	zeroed := &CardSigner{PublicKey: ecKey.Public(), Sign_: func([]byte) ([]byte, error) {
		return make([]byte, 64), nil // r = s = 0
	}}
	if _, err := zeroed.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("accepted a zero ECDSA signature")
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	short := &CardSigner{PublicKey: rsaKey.Public(), Sign_: func([]byte) ([]byte, error) {
		return make([]byte, 16), nil // wrong length for the modulus
	}}
	if _, err := short.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("accepted an RSA signature of the wrong length")
	}
}
