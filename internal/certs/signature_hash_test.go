package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// rawCard signs as a token does through the KMS: ECDSA as r||s at the width of the curve order, RSA
// as PKCS #1 v1.5 padding over exactly the bytes it is given (the DigestInfo).
func rawCard(t *testing.T, key crypto.Signer) (CardSign, *[][]byte) {
	t.Helper()
	var payloads [][]byte
	return func(payload []byte) ([]byte, error) {
		payloads = append(payloads, append([]byte{}, payload...))
		switch private := key.(type) {
		case *ecdsa.PrivateKey:
			r, s, err := ecdsa.Sign(rand.Reader, private, payload)
			if err != nil {
				return nil, err
			}
			width := (private.Curve.Params().BitSize + 7) / 8
			raw := make([]byte, 2*width)
			r.FillBytes(raw[:width])
			s.FillBytes(raw[width:])
			return raw, nil
		case *rsa.PrivateKey:
			return rsa.SignPKCS1v15(nil, private, crypto.Hash(0), payload)
		}
		t.Fatalf("unexpected key %T", key)
		return nil, nil
	}, &payloads
}

// caFor makes a self-signed CA certificate for a software key standing in for the card's.
func caFor(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regalia-kms#169 CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func csrFor(t *testing.T, name string) []byte {
	t.Helper()
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, subject)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// THE HASH FOLLOWS THE CA KEY (regalia-kms#169). The capability matrix offers certificate-sign for
// P-256, P-384 and RSA keys. A P-384 key used to be refused before the token was asked, because the
// signer took SHA-256 only and x509 signs with SHA-384 for that key.
func TestACertificateIsIssuedFromEachKindOfCAKeyWithTheHashOfThatKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsa3072, _ := rsa.GenerateKey(rand.Reader, 3072)
	profile := Profile{AllowedDNSSuffixes: []string{"internal.example"}, Validity: time.Hour, KeyUsage: x509.KeyUsageDigitalSignature}
	for name, test := range map[string]struct {
		key       crypto.Signer
		algorithm x509.SignatureAlgorithm
		payload   int // what the token is sent: the digest for ECDSA, the DigestInfo for RSA
	}{
		"p256":    {p256, x509.ECDSAWithSHA256, 32},
		"p384":    {p384, x509.ECDSAWithSHA384, 48},
		"rsa2048": {rsa2048, x509.SHA256WithRSA, 51},
		"rsa3072": {rsa3072, x509.SHA256WithRSA, 51},
	} {
		ca := caFor(t, test.key)
		card, payloads := rawCard(t, test.key)
		der, err := Issue(ca, &CardSigner{PublicKey: test.key.Public(), Sign_: card}, csrFor(t, "node.internal.example"), profile, time.Now())
		if err != nil {
			t.Fatalf("%s: a certificate could not be issued: %v", name, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := certificate.CheckSignatureFrom(ca); err != nil {
			t.Fatalf("%s: the issued certificate does not verify under the CA: %v", name, err)
		}
		if certificate.SignatureAlgorithm != test.algorithm {
			t.Errorf("%s: signed with %v, want %v", name, certificate.SignatureAlgorithm, test.algorithm)
		}
		if len(*payloads) != 1 || len((*payloads)[0]) != test.payload {
			t.Errorf("%s: the token was sent %d payload(s), the first of %d bytes; want one of %d", name, len(*payloads), len((*payloads)[0]), test.payload)
		}
	}
}

// NO OTHER PAIRING. A key is never obliged to sign over a weaker or another hash than its own, and a
// curve the matrix does not offer for certificates is not signed with at all.
func TestTheCardSignerRefusesAHashThatIsNotTheKeys(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	d256, d384, d512 := sha256.Sum256([]byte("tbs")), sha512.Sum384([]byte("tbs")), sha512.Sum512([]byte("tbs"))
	for name, test := range map[string]struct {
		key    crypto.Signer
		digest []byte
		hash   crypto.Hash
		reason string
	}{
		"P-384 asked for SHA-256":            {p384, d256[:], crypto.SHA256, "hash is not the one this key signs with"},
		"P-384 asked for SHA-512":            {p384, d512[:], crypto.SHA512, "hash is not the one this key signs with"},
		"P-256 asked for SHA-384":            {p256, d384[:], crypto.SHA384, "hash is not the one this key signs with"},
		"RSA asked for SHA-384":              {rsaKey, d384[:], crypto.SHA384, "hash is not the one this key signs with"},
		"P-384, SHA-384, a 32-byte digest":   {p384, d256[:], crypto.SHA384, "digest is not of the hash this key signs with"},
		"P-256, SHA-256, a 48-byte digest":   {p256, d384[:], crypto.SHA256, "digest is not of the hash this key signs with"},
		"P-521, which is not offered at all": {p521, d512[:], crypto.SHA512, "unsupported certificate signing key type"},
	} {
		card, payloads := rawCard(t, test.key)
		_, err := (&CardSigner{PublicKey: test.key.Public(), Sign_: card}).Sign(rand.Reader, test.digest, test.hash)
		if err == nil || !strings.Contains(err.Error(), test.reason) {
			t.Errorf("%s: got %v, want a refusal containing %q", name, err, test.reason)
		}
		if len(*payloads) != 0 {
			t.Errorf("%s: the token was asked to sign although the request was refused", name)
		}
	}
}

// The token's answer must be two field elements at the width of THIS key's curve. A 64-byte answer
// for a P-384 key (another key signed, or the read was cut) used to be taken as two 32-byte halves.
func TestARawSignatureOfTheWrongWidthForTheCurveIsRefused(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	d256, d384 := sha256.Sum256([]byte("tbs")), sha512.Sum384([]byte("tbs"))
	answer := func(length int) CardSign {
		return func([]byte) ([]byte, error) {
			raw := make([]byte, length)
			for i := range raw {
				raw[i] = 1
			}
			return raw, nil
		}
	}
	for name, test := range map[string]struct {
		key    *ecdsa.PrivateKey
		digest []byte
		hash   crypto.Hash
		length int
		ok     bool
	}{
		"P-384, 96 bytes": {p384, d384[:], crypto.SHA384, 96, true},
		"P-384, 64 bytes": {p384, d384[:], crypto.SHA384, 64, false},
		"P-384, 98 bytes": {p384, d384[:], crypto.SHA384, 98, false},
		"P-256, 64 bytes": {p256, d256[:], crypto.SHA256, 64, true},
		"P-256, 96 bytes": {p256, d256[:], crypto.SHA256, 96, false},
		"P-256, 62 bytes": {p256, d256[:], crypto.SHA256, 62, false},
		"P-256, nothing":  {p256, d256[:], crypto.SHA256, 0, false},
	} {
		_, err := (&CardSigner{PublicKey: &test.key.PublicKey, Sign_: answer(test.length)}).Sign(rand.Reader, test.digest, test.hash)
		if (err == nil) != test.ok {
			t.Errorf("%s: err=%v, want accepted=%v", name, err, test.ok)
		}
	}
}
