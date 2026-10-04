package openbaopoc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func configuredPKIPoC(t *testing.T, f *signingFixture, config map[string]string) kms.Key {
	t.Helper()
	provider := NewExternalPKIPoC()
	if err := provider.Open(context.Background(), &kms.OpenOptions{ConfigMap: externalProviderConfig(config)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { provider.Close(context.Background()) })
	key, err := provider.GetKey(context.Background(), &kms.KeyOptions{ConfigMap: f.keyConfig})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPKIPoCInspectedSigningRefusals(t *testing.T) {
	ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, ca)
	backend := &pocSoftwareCA{key: ca, issuer: issuer, cap: 1}
	f := newSigningFixtureWith(t, "p256", "sha256", ca, backend, true)
	key := configuredPKIPoC(t, f, f.pki.caConfig)
	now := time.Now()
	var valid []byte
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
		ok   bool
	}{
		{"CA", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }, false},
		{"name", func(c *x509.Certificate) { c.DNSNames = []string{"outside.invalid"} }, false},
		{"lifetime", func(c *x509.Certificate) { c.NotAfter = now.Add(20 * time.Minute) }, false},
		{"unknown-critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}, false},
		{"valid", func(*x509.Certificate) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			tc.edit(cert)
			encoded, err := x509.CreateCertificate(rand.Reader, cert, issuer, &ca.PublicKey, ca)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(encoded)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := key.Sign(context.Background(), &kms.SignOptions{Data: parsed.RawTBSCertificate, SignerOpts: crypto.SHA256})
			if (err == nil) != tc.ok {
				t.Fatal("inspected KMS decision differs from profile")
			}
			if tc.ok {
				valid = parsed.RawTBSCertificate
				if issuer.CheckSignature(x509.ECDSAWithSHA256, valid, sig) != nil {
					t.Fatal("accepted KMS signature does not verify")
				}
			}
		})
	}
	if f.audit.successful("sign") != 1 {
		t.Fatal("refused inputs signed")
	}
	if _, err := key.Sign(context.Background(), &kms.SignOptions{Data: valid, SignerOpts: crypto.SHA256}); err == nil {
		t.Fatal("exhausted fixture budget still signed")
	}
	if f.audit.successful("sign") != 1 {
		t.Fatal("budget refusal reached a signature")
	}
	stranger := configuredPKIPoC(t, f, f.pki.strangerConfig)
	before := len(backend.snapshot())
	if _, err := stranger.Sign(context.Background(), &kms.SignOptions{Data: valid, SignerOpts: crypto.SHA256}); err == nil || len(backend.snapshot()) != before {
		t.Fatal("wrong workload identity reached token")
	}
	// A digest sent directly to the KMS cannot bypass the content-type policy.
	external := key.(*pkiPOCKey)
	req, err := request(external.client.binding, "sign", make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = external.client.nativeCall(context.Background(), req, "sign", versionedRequest{ContentType: "application/vnd.regalia.digest", Payload: make([]byte, 32)}, "application/octet-stream", 4096); err == nil || len(backend.snapshot()) != before {
		t.Fatal("opaque digest reached CA token")
	}
}
