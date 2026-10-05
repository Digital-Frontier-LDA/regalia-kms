package openbaopoc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func TestPKIPoCRevocationSurvivesIssuanceExhaustion(t *testing.T) {
	ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, ca)
	backend := &pocSoftwareCA{key: ca, issuer: issuer, leafCap: 1, crlCap: 1}
	f := newSigningFixtureWith(t, "p256", "sha256", ca, backend, true)
	key := configuredPKIPoC(t, f, f.pki.caConfig)
	now := time.Now().UTC()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(data []byte) ([]byte, error) {
		return key.Sign(context.Background(), &kms.SignOptions{Data: data, SignerOpts: crypto.SHA256})
	}
	if _, err = sign(parsed.RawTBSCertificate); err != nil {
		t.Fatal("first leaf refused", err)
	}
	if _, err = sign(parsed.RawTBSCertificate); err == nil {
		t.Fatal("exhausted issuance budget still signed")
	}
	crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: parsed.SerialNumber, RevocationTime: now}}}
	encoded, err = x509.CreateRevocationList(rand.Reader, crl, issuer, ca)
	if err != nil {
		t.Fatal(err)
	}
	revocation, err := x509.ParseRevocationList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(revocation.RawTBSRevocationList)
	if err != nil {
		t.Fatal("issuance exhaustion blocked revocation signing", err)
	}
	if issuer.CheckSignature(x509.ECDSAWithSHA256, revocation.RawTBSRevocationList, sig) != nil {
		t.Fatal("CRL signature does not verify")
	}
	if _, err = sign(revocation.RawTBSRevocationList); err == nil {
		t.Fatal("CRL reserve is unbounded")
	}
	if f.audit.successful("sign") != 2 {
		t.Fatal("budget denials produced signatures")
	}
}
