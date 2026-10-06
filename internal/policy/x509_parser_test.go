package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"
)

func x509Fixture(t testing.TB) (*X509Policy, *x509.Certificate, *ecdsa.PrivateKey, time.Time, []byte, []byte) {
	return x509FixtureWithKeys(t, false)
}

func x509FixtureWithKeys(t testing.TB, stable bool) (*X509Policy, *x509.Certificate, *ecdsa.PrivateKey, time.Time, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if stable {
		// Predictable public seed structures are needed across fuzz workers.
		// These scalars format test inputs only and are never provisioned.
		curve := elliptic.P256()
		key = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}, D: big.NewInt(1)}
		x, y := curve.ScalarBaseMult([]byte{2})
		rootKey = &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: big.NewInt(2)}
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-intermediate"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"svc.poc.invalid"}}
	der, err = x509.CreateCertificate(rand.Reader, issuer, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	p := &X509Policy{ID: "synthetic-profile-v1", IssuerDER: der, DNSSuffixes: []string{"svc.poc.invalid"}, MaxLeafValidity: 10 * time.Minute, MaxCRLValidity: time.Hour, LeafPerDay: 2, CRLPerDay: 2}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert := x509LeafTBS(t, leaf, issuer, key)
	crl := x509CRLTBS(t, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}}}, issuer, key)
	return p, issuer, key, now, cert, crl
}

func x509LeafTBS(t testing.TB, leaf, issuer *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawTBSCertificate
}

func x509CRLTBS(t testing.TB, crl *x509.RevocationList, issuer *x509.Certificate, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	encoded, err := x509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawTBSRevocationList
}

func x509Fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestX509ParserAndFrozenProfile(t *testing.T) {
	p, issuer, _, now, certificate, crl := x509Fixture(t)
	fingerprint := x509Fingerprint(issuer)
	compiled, err := compileX509(p)
	if err != nil {
		t.Fatal("valid profile refused", err)
	}
	for _, tc := range []struct {
		kind string
		data []byte
	}{{"certificate", certificate}, {"crl", crl}} {
		parsed, err := ParseX509TBS(tc.data)
		if err != nil {
			t.Fatal("valid signing input refused", err)
		}
		digest := sha256.Sum256(tc.data)
		if parsed.Kind() != tc.kind || parsed.Digest() != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Fatal("artifact identity/digest mismatch")
		}
		if kind, rule := compiled.validate(parsed, now, fingerprint); kind != tc.kind || rule != "" {
			t.Fatal("valid artifact refused", kind, rule)
		}
		copyData := append([]byte(nil), tc.data...)
		frozen, err := ParseX509TBS(copyData)
		if err != nil {
			t.Fatal(err)
		}
		clear(copyData)
		if _, rule := compiled.validate(frozen, now, fingerprint); rule != "" {
			t.Fatal("parsed input retained caller-owned bytes")
		}
		if _, err := ParseX509TBS(append(append([]byte(nil), tc.data...), 0)); !errors.Is(err, ErrX509Malformed) {
			t.Fatal("trailing DER accepted")
		}
	}
	clear(p.IssuerDER)
	p.DNSSuffixes[0] = "outside.invalid"
	p.LeafPerDay = 0
	parsed, err := ParseX509TBS(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, rule := compiled.validate(parsed, now, fingerprint); rule != "" {
		t.Fatal("compiled profile retained mutable input")
	}
	if compiled.profile.LeafPerDay != 2 {
		t.Fatal("compiled quota policy retained mutable input")
	}
}
