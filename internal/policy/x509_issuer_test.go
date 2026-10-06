package policy

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
)

func TestX509IssuerConstraintsMustBeExplicit(t *testing.T) {
	p, issuer, key, _, _, _ := x509Fixture(t)
	parent := *issuer
	parent.RawSubject = nil
	parent.Subject = pkix.Name{CommonName: "synthetic-offline-root"}
	for _, tc := range []struct {
		name    string
		edit    func(*x509.Certificate)
		suffix  string
		allowed bool
	}{
		{"constrained", func(*x509.Certificate) {}, "svc.poc.invalid", true},
		{"narrower-profile", func(*x509.Certificate) {}, "app.svc.poc.invalid", true},
		{"dot-constraint-narrower", func(c *x509.Certificate) { c.PermittedDNSDomains = []string{".svc.poc.invalid"} }, "app.svc.poc.invalid", true},
		{"dot-constraint-apex", func(c *x509.Certificate) { c.PermittedDNSDomains = []string{".svc.poc.invalid"} }, "svc.poc.invalid", false},
		{"noncritical-constraint", func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }, "svc.poc.invalid", false},
		{"no-constraint", func(c *x509.Certificate) { c.PermittedDNSDomains = nil }, "svc.poc.invalid", false},
		{"broad-profile", func(c *x509.Certificate) { c.PermittedDNSDomains = []string{"app.svc.poc.invalid"} }, "svc.poc.invalid", false},
		{"mixed-IP", func(c *x509.Certificate) {
			_, block, _ := net.ParseCIDR("127.0.0.0/8")
			c.PermittedIPRanges = []*net.IPNet{block}
		}, "svc.poc.invalid", false},
		{"excluded-name", func(c *x509.Certificate) { c.ExcludedDNSDomains = []string{"blocked.svc.poc.invalid"} }, "svc.poc.invalid", false},
		{"unbounded-path", func(c *x509.Certificate) { c.MaxPathLenZero = false; c.MaxPathLen = -1 }, "svc.poc.invalid", false},
		{"wrong-usage", func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageDigitalSignature }, "svc.poc.invalid", false},
		{"missing-key-identity", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{4, 0}}}
		}, "svc.poc.invalid", false},
		{"unknown-critical", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}, "svc.poc.invalid", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := *issuer
			template.RawSubject = nil
			tc.edit(&template)
			der, err := x509.CreateCertificate(rand.Reader, &template, &parent, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			policy := *p
			policy.IssuerDER = der
			policy.DNSSuffixes = []string{tc.suffix}
			_, err = compileX509(&policy)
			if (err == nil) != tc.allowed {
				t.Fatal("issuer constraints decision differs", err)
			}
		})
	}
	selfIssued := *issuer
	selfIssued.RawSubject = nil
	der, err := x509.CreateCertificate(rand.Reader, &selfIssued, &selfIssued, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	copied := *p
	copied.IssuerDER = der
	if _, err = compileX509(&copied); err == nil {
		t.Fatal("self-issued CA mapped as intermediate")
	}
}
