package openbaopoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func TestPKIPoCLegacySoftwareClockRollbackCannotRefillBudgets(t *testing.T) {
	ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
	beforeMidnight := time.Date(2026, time.October, 5, 23, 59, 50, 0, time.UTC)
	afterMidnight := beforeMidnight.Add(20 * time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-clock-ca"}, NotBefore: beforeMidnight.Add(-time.Hour), NotAfter: afterMidnight.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &ca.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	leafTBS := func(now time.Time, serial int64) []byte {
		t.Helper()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		encoded, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &ca.PublicKey, ca)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.RawTBSCertificate
	}
	oldLeaf, newLeaf := leafTBS(beforeMidnight, 3), leafTBS(afterMidnight, 4)
	encoded, err = x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: afterMidnight, NextUpdate: afterMidnight.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(4), RevocationTime: afterMidnight}}}, issuer, ca)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var clockNanos atomic.Int64
	clockNanos.Store(beforeMidnight.UnixNano())
	backend := &pocSoftwareCA{key: ca, issuer: issuer, leafCap: 1, crlCap: 1, clock: func() time.Time { return time.Unix(0, clockNanos.Load()).UTC() }}
	route := registry.Route{ObjectID: "poc-pki-ca", Purpose: "openbao-pki-poc", Environment: "development", Algorithm: "p256"}
	sign := func(data []byte, want bool, failure string) {
		t.Helper()
		signature, _, err := backend.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.x509-tbs", data, nil)
		if (err == nil) != want {
			t.Fatal(failure)
		}
		if !want {
			if len(signature) != 0 {
				t.Fatal("clock or budget refusal returned a signature")
			}
			return
		}
		digest := sha256.Sum256(data)
		if len(signature) != 64 || !ecdsa.Verify(&ca.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			t.Fatal("clock-window signature does not verify")
		}
	}

	// This models both wall-clock rollback and an earlier request whose clock
	// sample reaches reservation after another request advanced the time bucket.
	// It tests fixture accounting, not durable or distributed time fencing.
	sign(oldLeaf, true, "first day leaf refused")
	sign(oldLeaf, false, "first day budget was not exhausted")
	clockNanos.Store(afterMidnight.UnixNano())
	sign(newLeaf, true, "forward day transition did not allow its bounded leaf budget")
	clockNanos.Store(beforeMidnight.UnixNano())
	sign(oldLeaf, false, "clock rollback refilled the earlier day budget")
	clockNanos.Store(afterMidnight.UnixNano())
	sign(newLeaf, false, "returning to the current day refilled its exhausted budget")
	sign(crl.RawTBSRevocationList, true, "clock rollback or issuance exhaustion consumed CRL reserve")
	sign(crl.RawTBSRevocationList, false, "CRL reserve was not bounded after clock rollback")
	allowed := map[string]int{}
	for _, record := range backend.snapshot() {
		if record.Allowed {
			allowed[record.Kind]++
		}
	}
	if allowed["certificate"] != 2 || allowed["crl"] != 1 {
		t.Fatal("clock transitions changed the number of permitted signatures")
	}
}
