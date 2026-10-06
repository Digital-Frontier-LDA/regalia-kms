package policy

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestX509ProfileRefusesUnsupportedLeafSemantics(t *testing.T) {
	p, issuer, key, now, valid, _ := x509Fixture(t)
	compiled, err := compileX509(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
	}{
		{"outside", func(c *x509.Certificate) {
			c.Subject.CommonName = "outside.invalid"
			c.DNSNames = []string{"outside.invalid"}
		}},
		{"suffix-lookalike", func(c *x509.Certificate) {
			c.Subject.CommonName = "badsvc.poc.invalid"
			c.DNSNames = []string{"badsvc.poc.invalid"}
		}},
		{"suffix-at-start", func(c *x509.Certificate) {
			c.Subject.CommonName = "svc.poc.invalid.attacker.invalid"
			c.DNSNames = []string{"svc.poc.invalid.attacker.invalid"}
		}},
		{"wildcard", func(c *x509.Certificate) {
			c.Subject.CommonName = "*.svc.poc.invalid"
			c.DNSNames = []string{"*.svc.poc.invalid"}
		}},
		{"uppercase", func(c *x509.Certificate) {
			c.Subject.CommonName = "WEB.svc.poc.invalid"
			c.DNSNames = []string{"WEB.svc.poc.invalid"}
		}},
		{"CA", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{"client-auth", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{"mixed-usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageKeyEncipherment }},
		{"no-basic-constraints", func(c *x509.Certificate) { c.BasicConstraintsValid = false }},
		{"subject-organization", func(c *x509.Certificate) { c.Subject.Organization = []string{"additional subject"} }},
		{"unknown-critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
		{"unknown-noncritical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}},
		{"IP", func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		{"CN-mismatch", func(c *x509.Certificate) { c.Subject.CommonName = "other.svc.poc.invalid" }},
		{"expired", func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Second) }},
		{"stale-start", func(c *x509.Certificate) { c.NotBefore = now.Add(-2 * time.Minute) }},
		{"future-start", func(c *x509.Certificate) { c.NotBefore = now.Add(30 * time.Second) }},
		{"excessive-lifetime", func(c *x509.Certificate) { c.NotAfter = now.Add(11 * time.Minute) }},
		{"inverted-validity", func(c *x509.Certificate) { c.NotBefore = now.Add(5 * time.Second); c.NotAfter = now.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			tc.edit(leaf)
			parsed, err := ParseX509TBS(x509LeafTBS(t, leaf, issuer, key))
			if err != nil {
				t.Fatal("well-formed semantics were treated as malformed", err)
			}
			if kind, rule := compiled.validate(parsed, now, x509Fingerprint(issuer)); kind != "certificate" || rule == "" {
				t.Fatal("unsupported leaf semantics accepted")
			}
		})
	}
	parsed, err := ParseX509TBS(valid)
	if err != nil {
		t.Fatal(err)
	}
	for _, fingerprint := range []string{"", "sha256:incorrect"} {
		if _, rule := compiled.validate(parsed, now, fingerprint); rule != "x509-key" {
			t.Fatal("missing/mismatched route key accepted")
		}
	}
	if _, rule := compiled.validate(parsed, issuer.NotAfter, x509Fingerprint(issuer)); rule != "x509-issuer-validity" {
		t.Fatal("expired issuer accepted")
	}
	if _, rule := compiled.validate(&X509TBS{}, now, x509Fingerprint(issuer)); rule != "x509-input" {
		t.Fatal("unparsed input accepted")
	}
}

func TestX509ProfileConfigurationIsExplicitAndConstrained(t *testing.T) {
	p, _, _, _, _, _ := x509Fixture(t)
	for _, tc := range []struct {
		name string
		edit func(*X509Policy)
	}{
		{"empty-id", func(p *X509Policy) { p.ID = "" }},
		{"unsafe-id", func(p *X509Policy) { p.ID = "profile/version" }},
		{"no-issuer", func(p *X509Policy) { p.IssuerDER = nil }},
		{"no-names", func(p *X509Policy) { p.DNSSuffixes = nil }},
		{"wildcard", func(p *X509Policy) { p.DNSSuffixes = []string{"*.svc.poc.invalid"} }},
		{"uppercase", func(p *X509Policy) { p.DNSSuffixes = []string{"SVC.poc.invalid"} }},
		{"duplicate", func(p *X509Policy) { p.DNSSuffixes = []string{"svc.poc.invalid", "svc.poc.invalid"} }},
		{"outside-issuer", func(p *X509Policy) { p.DNSSuffixes = []string{"outside.invalid"} }},
		{"single-label", func(p *X509Policy) { p.DNSSuffixes = []string{"invalid"} }},
		{"no-leaf-lifetime", func(p *X509Policy) { p.MaxLeafValidity = 0 }},
		{"leaf-too-long", func(p *X509Policy) { p.MaxLeafValidity = 24*time.Hour + time.Second }},
		{"no-crl-lifetime", func(p *X509Policy) { p.MaxCRLValidity = 0 }},
		{"crl-too-long", func(p *X509Policy) { p.MaxCRLValidity = 24*time.Hour + time.Second }},
		{"no-leaf-budget", func(p *X509Policy) { p.LeafPerDay = 0 }},
		{"no-crl-reserve", func(p *X509Policy) { p.CRLPerDay = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyPolicy := *p
			tc.edit(&copyPolicy)
			if _, err := compileX509(&copyPolicy); err == nil {
				t.Fatal("unsafe profile configuration accepted")
			}
		})
	}
	if _, err := compileX509(nil); err == nil {
		t.Fatal("nil profile accepted")
	}
}

func TestX509ProfileRefusesUnsupportedCRLSemantics(t *testing.T) {
	p, issuer, key, now, _, _ := x509Fixture(t)
	compiled, err := compileX509(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		edit  func(*x509.RevocationList)
		allow bool
	}{
		{"full", func(*x509.RevocationList) {}, true},
		{"delta", func(c *x509.RevocationList) {
			c.Number = big.NewInt(2)
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}
		}, true},
		{"delta-future-base", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}
		}, false},
		{"unknown", func(c *x509.RevocationList) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		}, false},
		{"stale", func(c *x509.RevocationList) { c.ThisUpdate = now.Add(-2 * time.Minute) }, false},
		{"future", func(c *x509.RevocationList) { c.ThisUpdate = now.Add(30 * time.Second) }, false},
		{"long", func(c *x509.RevocationList) { c.NextUpdate = now.Add(2 * time.Hour) }, false},
		{"expired", func(c *x509.RevocationList) {
			c.ThisUpdate = now.Add(-30 * time.Second)
			c.NextUpdate = now.Add(-time.Second)
		}, false},
		{"inverted", func(*x509.RevocationList) {}, false},
		{"duplicate", func(c *x509.RevocationList) {
			c.RevokedCertificateEntries = append(c.RevokedCertificateEntries, c.RevokedCertificateEntries[0])
		}, false},
		{"future-revocation", func(c *x509.RevocationList) { c.RevokedCertificateEntries[0].RevocationTime = now.Add(time.Minute) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}}}
			tc.edit(crl)
			encoded, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := x509.ParseRevocationList(encoded)
			if err != nil {
				t.Fatal(err)
			}
			data := decoded.RawTBSRevocationList
			if tc.name == "inverted" {
				fields, err := x509DERSequence(data, 12)
				if err != nil {
					t.Fatal(err)
				}
				thisDER, _ := asn1.Marshal(now.Add(5 * time.Second))
				nextDER, _ := asn1.Marshal(now.Add(time.Second))
				fields[3], fields[4] = asn1.RawValue{FullBytes: thisDER}, asn1.RawValue{FullBytes: nextDER}
				data, err = asn1.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			parsed, err := ParseX509TBS(data)
			if err != nil {
				t.Fatal("well-formed CRL semantics treated as malformed", err)
			}
			kind, rule := compiled.validate(parsed, now, x509Fingerprint(issuer))
			if kind != "crl" || (rule == "") != tc.allow {
				t.Fatal("CRL profile decision differs", kind, rule)
			}
		})
	}
}
