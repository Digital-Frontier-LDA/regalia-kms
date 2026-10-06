package openbaopoc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

const pocPKIProfileID = "poc-pki-profile-v1"

// This token fixture receives only the coordinator-approved SHA-256 digest.
// It cannot inspect a certificate, choose a profile, enforce a quota, or infer
// the artifact kind. Those responsibilities belong to the real daemon policy.
type pocDaemonCA struct {
	key             *ecdsa.PrivateKey
	issuer          *x509.Certificate
	leafCap, crlCap uint64
	mu              sync.Mutex
	records         []pocCARecord
}

func (s *pocDaemonCA) PKIProfile() *policy.X509Policy {
	return &policy.X509Policy{ID: pocPKIProfileID, IssuerDER: s.issuer.Raw, DNSSuffixes: []string{"svc.poc.invalid"}, MaxLeafValidity: 10 * time.Minute, MaxCRLValidity: time.Hour, LeafPerDay: s.leafCap, CRLPerDay: s.crlCap}
}

func (s *pocDaemonCA) Execute(ctx context.Context, route registry.Route, op, format, content string, data, aad []byte) ([]byte, string, error) {
	if ctx.Err() != nil || op != "sign" || format != "" || content != "application/vnd.regalia.digest" || len(data) != sha256.Size || len(aad) != 0 ||
		route.ObjectID != "poc-pki-ca" || route.Purpose != "openbao-pki-poc" || route.Environment != "development" || route.Algorithm != "p256" {
		return nil, "", backend.ErrUnavailable
	}
	spki, err := x509.MarshalPKIXPublicKey(s.key.Public())
	if err != nil {
		return nil, "", err
	}
	expected := sha256.Sum256(spki)
	if route.Binding.PublicKeySHA256 != "sha256:"+hex.EncodeToString(expected[:]) {
		return nil, "", backend.ErrUnavailable
	}
	r, sigS, err := ecdsa.Sign(rand.Reader, s.key, data)
	if err != nil {
		return nil, "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sigS.FillBytes(sig[32:])
	var digest [32]byte
	copy(digest[:], data)
	s.mu.Lock()
	s.records = append(s.records, pocCARecord{Kind: "digest", Digest: digest, Allowed: true})
	s.mu.Unlock()
	return sig, "application/octet-stream", nil
}
func (*pocDaemonCA) Healthy(context.Context, registry.Binding) bool { return true }
func (*pocDaemonCA) Ready(context.Context) bool                     { return true }
func (s *pocDaemonCA) snapshot() []pocCARecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]pocCARecord(nil), s.records...)
}

func (s *fixtureAudit) snapshotEvents() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Event(nil), s.events...)
}

func pocDurableIntent(t *testing.T, f *signingFixture, event audit.Event, kind string) {
	t.Helper()
	if _, err := policy.VerifyState(f.policyStatePath); err != nil {
		t.Fatal("policy journal verification failed", err)
	}
	data, err := os.ReadFile(f.policyStatePath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var record struct {
			Reservation policy.Reservation `json:"reservation"`
		}
		if json.Unmarshal(line, &record) != nil {
			t.Fatal("invalid policy journal record")
		}
		intent := record.Reservation.SigningIntent
		if intent != nil && intent.ProfileID == event.X509ProfileID && intent.PayloadDigest == event.PayloadDigest && intent.ArtifactKind == kind && intent.KeyFingerprint == event.KeyFingerprint {
			unit := "x509-leaf"
			if kind == "crl" {
				unit = "x509-crl"
			}
			if record.Reservation.QuotaID != "x509-count-v1" || len(record.Reservation.Amounts) != 1 || record.Reservation.Amounts[unit] != 1 {
				t.Fatal("signing intent has no durable X.509 quota namespace")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("audited signature has no durable reservation intent")
	}
	events, err := audit.VerifyIntegrity(f.auditPath)
	if err != nil {
		t.Fatal("audit journal integrity verification failed", err)
	}
	found = false
	for _, durable := range events {
		found = found || durable.RequestID == event.RequestID && durable.Outcome == event.Outcome && durable.X509ProfileID == event.X509ProfileID && durable.PayloadDigest == event.PayloadDigest && durable.ArtifactKind == event.ArtifactKind && durable.KeyFingerprint == event.KeyFingerprint
	}
	if !found {
		t.Fatal("signature intent absent from durable audit journal")
	}
}
