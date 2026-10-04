package openbaopoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type pocCARecord struct {
	Kind    string
	Digest  [32]byte
	Allowed bool
}

type pocSoftwareCA struct {
	key       *ecdsa.PrivateKey
	issuer    *x509.Certificate
	mu        sync.Mutex
	records   []pocCARecord
	cap, used int
	day       string
}

func (s *pocSoftwareCA) Execute(ctx context.Context, route registry.Route, op, format, content string, data, aad []byte) ([]byte, string, error) {
	if ctx.Err() != nil || op != "sign" || format != "" || content != "application/vnd.regalia.x509-tbs" || len(aad) != 0 || len(data) == 0 || len(data) > 32<<10 ||
		route.ObjectID != "poc-pki-ca" || route.Purpose != "openbao-pki-poc" || route.Environment != "development" || route.Algorithm != "p256" {
		return nil, "", errPOCProfile
	}
	now := time.Now().UTC()
	kind := "refused"
	if _, err := pocInspectCertificate(data, s.issuer, now); err == nil {
		kind = "certificate"
	} else if _, err := pocInspectCRL(data, s.issuer, now); err == nil {
		kind = "crl"
	}
	digest := sha256.Sum256(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	// The fixture budget is in memory. Production needs a durable reservation,
	// fencing and recovery semantics; this demonstrates only the refusal path.
	day := now.Format("2006-01-02")
	if s.day != day {
		s.day, s.used = day, 0
	}
	allowed := kind != "refused" && s.cap > 0 && s.used < s.cap && ctx.Err() == nil
	s.records = append(s.records, pocCARecord{kind, digest, allowed})
	if !allowed {
		return nil, "", errPOCProfile
	}
	s.used++
	r, sigS, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return nil, "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sigS.FillBytes(sig[32:])
	return sig, "application/octet-stream", nil
}
func (*pocSoftwareCA) Healthy(context.Context, registry.Binding) bool { return true }
func (*pocSoftwareCA) Ready(context.Context) bool                     { return true }

func (s *pocSoftwareCA) snapshot() []pocCARecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]pocCARecord(nil), s.records...)
}
