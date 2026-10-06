package openbaopoc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func TestPKIPoCBudgetsRemainIndependentUnderConcurrentCalls(t *testing.T) {
	ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, ca)
	backend := &pocDaemonCA{key: ca, issuer: issuer, leafCap: 2, crlCap: 3}
	f := newSigningFixtureWith(t, "p256", "sha256", ca, backend, true)
	key := configuredPKIPoC(t, f, f.pki.caConfig)
	now := time.Now().UTC()
	leafTBS := func(name string) []byte {
		t.Helper()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
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
	leaf := leafTBS("web.svc.poc.invalid")
	outside := leafTBS("outside.invalid")
	encoded, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}}}, issuer, ca)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(encoded)
	if err != nil {
		t.Fatal(err)
	}

	// These are concurrent callers of the real mTLS API, including its
	// authorization, replay, audit and shared executor boundaries. The fixture
	// executor serializes hardware work; this does not prove HA fencing.
	batch := func(signer kms.Key, inputs [][]byte, want int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		type result struct {
			data, signature []byte
			err             error
		}
		results := make(chan result, len(inputs))
		start := make(chan struct{})
		for _, input := range inputs {
			go func(data []byte) {
				<-start
				signature, err := signer.Sign(ctx, &kms.SignOptions{Data: data, SignerOpts: crypto.SHA256})
				results <- result{data, signature, err}
			}(input)
		}
		close(start)
		allowed := 0
		for range inputs {
			r := <-results
			if r.err != nil {
				if len(r.signature) != 0 {
					t.Error("refusal returned a signature")
				}
				continue
			}
			allowed++
			if issuer.CheckSignature(x509.ECDSAWithSHA256, r.data, r.signature) != nil {
				t.Error("accepted signature does not verify")
			}
		}
		if allowed != want {
			t.Fatalf("concurrent batch signed %d requests; want %d", allowed, want)
		}
	}

	malformed := []byte{0x30, 0x00}
	trailingCRL := append(append([]byte(nil), crl.RawTBSRevocationList...), 0)
	batch(key, [][]byte{malformed, outside, trailingCRL, malformed, outside, trailingCRL}, 0)
	stranger := configuredPKIPoC(t, f, f.pki.strangerConfig)
	before := len(backend.snapshot())
	batch(stranger, [][]byte{crl.RawTBSRevocationList}, 0)
	if len(backend.snapshot()) != before {
		t.Fatal("unauthorized caller reached the signing backend")
	}
	if f.audit.successful("sign") != 0 {
		t.Fatal("denied inputs produced successful signing audit records")
	}

	batch(key, [][]byte{leaf, leaf, leaf, leaf, leaf, leaf}, 2)
	batch(key, [][]byte{crl.RawTBSRevocationList, crl.RawTBSRevocationList, crl.RawTBSRevocationList, crl.RawTBSRevocationList, crl.RawTBSRevocationList, crl.RawTBSRevocationList}, 3)
	allowed := map[string]int{}
	digests := map[[32]byte]string{sha256.Sum256(leaf): "certificate", sha256.Sum256(crl.RawTBSRevocationList): "crl"}
	for _, record := range backend.snapshot() {
		kind, ok := digests[record.Digest]
		if !record.Allowed || record.Kind != "digest" || !ok {
			t.Fatal("token received a digest unrelated to inspected inputs")
		}
		allowed[kind]++
	}
	if allowed["certificate"] != 2 || allowed["crl"] != 3 || f.audit.successful("sign") != 5 {
		t.Fatal("concurrent calls overshot durable budgets or consumed CRL reserve")
	}
	counts := map[string]int{}
	for _, event := range f.audit.snapshotEvents() {
		if event.Outcome != "success" {
			continue
		}
		if event.X509ProfileID != f.profile.ID || event.KeyFingerprint != f.keyConfig["public_key_sha256"] {
			t.Fatal("successful signing lacks server-owned profile/key identity")
		}
		counts[event.ArtifactKind]++
	}
	if counts["certificate"] != 2 || counts["crl"] != 3 {
		t.Fatal("audit intent counts differ from actual token calls")
	}
	t.Run("legacy-software-reservation-concurrency", func(t *testing.T) {
		// Preserve the earlier software-only PoC mutex regression for comparison.
		// Server-owned durable reservations are exercised through the API above.
		backend := &pocSoftwareCA{key: ca, issuer: issuer, leafCap: 2, crlCap: 3}
		route := registry.Route{ObjectID: "poc-pki-ca", Purpose: "openbao-pki-poc", Environment: "development", Algorithm: "p256"}
		type result struct {
			data, signature []byte
			err             error
		}
		allowed := map[string]int{}
		for range 2 {
			results := make(chan result, 6)
			start := make(chan struct{})
			for _, input := range [][]byte{leaf, crl.RawTBSRevocationList, leaf, crl.RawTBSRevocationList, leaf, crl.RawTBSRevocationList} {
				go func(data []byte) {
					<-start
					signature, _, err := backend.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.x509-tbs", data, nil)
					results <- result{data, signature, err}
				}(input)
			}
			close(start)
			for range 6 {
				r := <-results
				if r.err != nil {
					if len(r.signature) != 0 {
						t.Error("backend refusal returned a signature")
					}
					continue
				}
				digest := sha256.Sum256(r.data)
				if len(r.signature) != 64 || !ecdsa.Verify(&ca.PublicKey, digest[:], new(big.Int).SetBytes(r.signature[:32]), new(big.Int).SetBytes(r.signature[32:])) {
					t.Fatal("concurrent backend signature does not verify")
				}
			}
		}
		for _, record := range backend.snapshot() {
			if record.Allowed {
				allowed[record.Kind]++
			}
		}
		if allowed["certificate"] != 2 || allowed["crl"] != 3 {
			t.Fatal("concurrent backend reservations overshot independent budgets")
		}
	})
}
