package openbaopoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

func pocIssuer(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	issuer, _ := pocIssuerChain(t, key)
	return issuer
}

func pocIssuerChain(t *testing.T, key *ecdsa.PrivateKey) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	now := time.Now()
	rootKey := testSigner(t, "p256").(*ecdsa.PrivateKey)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-offline-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-pki-intermediate"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"svc.poc.invalid"}}
	encoded, err := x509.CreateCertificate(rand.Reader, issuer, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, root
}

func TestPOCCRLInspection(t *testing.T) {
	key := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, key)
	now := time.Now()
	for _, tc := range []struct {
		name string
		edit func(*x509.RevocationList)
		ok   bool
	}{
		{"empty", func(*x509.RevocationList) {}, true},
		{"long", func(c *x509.RevocationList) { c.NextUpdate = now.Add(2 * time.Hour) }, false},
		{"unknown", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}, false},
		{"delta", func(c *x509.RevocationList) {
			c.Number = big.NewInt(2)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}
		}, true},
		{"delta-base-too-new", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}
		}, false},
		{"delta-not-critical", func(c *x509.RevocationList) {
			c.Number = big.NewInt(2)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Value: []byte{2, 1, 1}}}
		}, false},
		{"delta-malformed", func(c *x509.RevocationList) {
			c.Number = big.NewInt(2)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1, 0}}}
		}, false},
		{"entry", func(c *x509.RevocationList) {
			c.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}}
		}, true},
		{"duplicate-entry", func(c *x509.RevocationList) {
			c.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}, {SerialNumber: big.NewInt(3), RevocationTime: now}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute)}
			tc.edit(crl)
			encoded, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseRevocationList(encoded)
			if err != nil {
				t.Fatal(err)
			}
			_, err = pocInspectCRL(parsed.RawTBSRevocationList, issuer, now)
			if (err == nil) != tc.ok {
				t.Fatal("CRL profile decision did not match")
			}
			if _, err = pocInspectCRL(append(parsed.RawTBSRevocationList, 0), issuer, now); err == nil {
				t.Fatal("CRL trailing DER accepted")
			}
			if tc.ok {
				fields, err := pocTBSFields(parsed.RawTBSRevocationList)
				if err != nil {
					t.Fatal(err)
				}
				// Keep valid DER while making nextUpdate earlier than thisUpdate.
				thisDER, _ := asn1.Marshal(now.UTC().Add(5 * time.Second))
				nextDER, _ := asn1.Marshal(now.UTC().Add(time.Second))
				fields[3], fields[4] = asn1.RawValue{FullBytes: thisDER}, asn1.RawValue{FullBytes: nextDER}
				inverted, err := asn1.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = pocInspectCRL(inverted, issuer, now); err == nil {
					t.Fatal("inverted CRL validity accepted")
				}
			}

		})
	}
}

func TestPOCCertificateInspection(t *testing.T) {
	key := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, key)
	now := time.Now()
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
		ok   bool
	}{
		{"valid", func(*x509.Certificate) {}, true},
		{"outside-name", func(c *x509.Certificate) { c.DNSNames = []string{"outside.invalid"} }, false},
		{"inverted-validity", func(c *x509.Certificate) { c.NotBefore = now.Add(5 * time.Second); c.NotAfter = now.Add(time.Second) }, false},
		{"long-lived", func(c *x509.Certificate) { c.NotAfter = now.Add(20 * time.Minute) }, false},
		{"CA", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }, false},
		{"client-usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, false},
		{"IP", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }, false},
		{"unknown-critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}, false},
		{"unknown-noncritical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			tc.edit(cert)
			encoded, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(encoded)
			if err != nil {
				t.Fatal(err)
			}
			_, err = pocInspectCertificate(parsed.RawTBSCertificate, issuer, now)
			if (err == nil) != tc.ok {
				t.Fatal("profile decision did not match")
			}
			if _, err = pocInspectCertificate(append(parsed.RawTBSCertificate, 0), issuer, now); err == nil {
				t.Fatal("trailing DER accepted")
			}
		})
	}
}
