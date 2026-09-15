package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/certs"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// softCard is a hardware provider backed by in-memory keys. It exists so the FULL request path —
// TLS identity, RBAC, routing, purpose policy, audit, then hardware — is exercised in ordinary CI,
// with no token and no PKCS#11 module. It answers exactly the operations a token would.
type softCard struct {
	key *ecdsa.PrivateKey
	t   *testing.T
}

func (card *softCard) Execute(_ context.Context, _ registry.Route, operation, _, _ string, data, aad []byte) ([]byte, string, error) {
	switch operation {
	case "public-key":
		der, err := x509.MarshalPKIXPublicKey(card.key.Public())
		return der, "application/pkix", err
	case "sign":
		digest := data
		if len(digest) > 32 { // the DigestInfo-prefixed RSA form is not used by this EC card
			digest = digest[len(digest)-32:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, card.key, digest)
		if err != nil {
			return nil, "", err
		}
		size := (card.key.Curve.Params().BitSize + 7) / 8
		raw := make([]byte, 2*size)
		r.FillBytes(raw[:size])
		s.FillBytes(raw[size:])
		return raw, "application/octet-stream", nil
	case "key-agreement":
		parsed, err := x509.ParsePKIXPublicKey(data)
		if err != nil {
			return nil, "", err
		}
		peer, _ := parsed.(*ecdsa.PublicKey)
		peerECDH, err := peer.ECDH()
		if err != nil {
			return nil, "", err
		}
		ownECDH, err := card.key.ECDH()
		if err != nil {
			return nil, "", err
		}
		shared, err := ownECDH.ECDH(peerECDH)
		if err != nil {
			return nil, "", err
		}
		derived, err := hkdf.Key(sha256.New, shared, nil, string(aad), 32)
		return derived, "application/vnd.regalia.derived-key", err
	}
	return nil, "", fmt.Errorf("unsupported operation %q", operation)
}

func (*softCard) Healthy(context.Context, registry.Binding) bool { return true }
func (*softCard) Ready(context.Context) bool                     { return true }

type stack struct {
	handler http.Handler
	ca      *x509.Certificate
	card    *softCard
	now     time.Time
}

func buildStack(t *testing.T) *stack {
	t.Helper()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regalia-e2e-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	card := &softCard{key: caKey, t: t}
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": card})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := certs.NewIssuer(hardware, ca, certs.Profile{
		AllowedDNSSuffixes: []string{"staging.internal"},
		Validity:           90 * 24 * time.Hour,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}

	manifest := `{
      "schema_version":1,"manifest_id":"e2e","generated_at":"2026-09-04T12:00:00Z",
      "objects":[
      {"id":"e2e-ca","name":"CA","kind":"asymmetric-key","classification":"restricted","environment":"development",
       "owner":"security","purpose":"e2e-pki","custody":"direct-hardware","algorithm":"p256",
       "operations":["certificate-sign"],"policy_id":"e2e-pki","bindings":[{"site":"e2e","backend":"nitrokey-pkcs11",
       "device_id":"hsm-e2e","device_serial":"serial-1","devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_id":"01",
       "public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],
       "recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}},
      {"id":"e2e-agree","name":"Agree","kind":"asymmetric-key","classification":"restricted","environment":"development",
       "owner":"security","purpose":"e2e-agreement","custody":"direct-hardware","algorithm":"p256",
       "operations":["key-agreement"],"policy_id":"e2e-agree","bindings":[{"site":"e2e","backend":"nitrokey-pkcs11",
       "device_id":"hsm-e2e","device_serial":"serial-1","devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_id":"02",
       "public_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"active"}],
       "recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`
	router, err := registry.Load(bytes.NewBufferString(manifest), "e2e", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(bytes.NewBufferString(`{"schema_version":1,"principals":[
      {"uri":"spiffe://regalia/workload/e2e","grants":[
        {"objects":["e2e-ca"],"operations":["certificate-sign"],"environments":["development"]},
        {"objects":["e2e-agree"],"operations":["key-agreement"],"environments":["development"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "policy.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	engine, err := policy.New([]policy.Policy{
		{ID: "e2e-pki", ObjectID: "e2e-ca", Purpose: "e2e-pki", Environment: "development",
			Operation: "certificate-sign", Algorithm: "p256",
			ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 8 << 10, MaxFuture: time.Minute},
		{ID: "e2e-agree", ObjectID: "e2e-agree", Purpose: "e2e-agreement", Environment: "development",
			Operation: "key-agreement", Algorithm: "p256",
			ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 4096, MaxFuture: time.Minute},
	}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), &auditSink{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })

	coordinator, err := operations.New(rbac, router, engine, recorder, executor.New(2, 5*time.Second),
		issuer, "sha256:e2e-policy", nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Second).
		Middleware(api.NewHandler(coordinator))
	return &stack{handler: handler, ca: ca, card: card, now: now}
}

func (s *stack) call(t *testing.T, path, principal, objectID, purpose, nonce string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"object_id":%q,"context":{"environment":"development","purpose":%q,"expires_at":%q,"nonce":%q},"payload_base64":%q}`,
		objectID, purpose, s.now.Add(30*time.Second).Format(time.RFC3339Nano), nonce,
		base64.StdEncoding.EncodeToString(payload))
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "12345678-1234-4234-8234-123456789abc")
	request.Header.Set("Idempotency-Key", nonce)
	principalURI, _ := url.Parse(principal)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		SerialNumber: big.NewInt(1), NotBefore: s.now.Add(-time.Hour), NotAfter: s.now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{principalURI},
	}}}}
	response := httptest.NewRecorder()
	s.handler.ServeHTTP(response, request)
	return response
}

func decodeResult(t *testing.T, response *httptest.ResponseRecorder) []byte {
	t.Helper()
	var result struct {
		Result      []byte `json:"result_base64"`
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("body = %s", response.Body.String())
	}
	return result.Result
}

func csrFor(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// CERTIFICATE-SIGN, END TO END: a CSR posted over the authenticated API comes back as a
// certificate that verifies against the CA the KMS is configured with.
func TestCertificateSignThroughTheWholeStack(t *testing.T) {
	s := buildStack(t)
	response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
		"e2e-ca", "e2e-pki", "1234567890abcdef", csrFor(t, "api.staging.internal"))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	leaf, err := x509.ParseCertificate(decodeResult(t, response))
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(s.ca); err != nil {
		t.Fatalf("issued certificate does not verify: %v", err)
	}
	if leaf.Subject.CommonName != "api.staging.internal" || leaf.IsCA {
		t.Fatalf("unexpected certificate %+v", leaf.Subject)
	}
}

// KEY-AGREEMENT, END TO END: a peer public key comes back as a 32-byte derived key, never the
// raw shared secret.
func TestKeyAgreementThroughTheWholeStack(t *testing.T) {
	s := buildStack(t)
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerDER, err := x509.MarshalPKIXPublicKey(peer.Public())
	if err != nil {
		t.Fatal(err)
	}
	response := s.call(t, "/v1/operations/key-agreement", "spiffe://regalia/workload/e2e",
		"e2e-agree", "e2e-agreement", "abcdef1234567890", peerDER)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	derived := decodeResult(t, response)
	if len(derived) != 32 {
		t.Fatalf("derived key is %d bytes, want 32", len(derived))
	}
	if bytes.Equal(derived, make([]byte, 32)) {
		t.Fatal("derived key is all zeroes")
	}
}

// THE CONTRACT ITEMS, THROUGH THE REAL PATH. Each must fail without returning material.
func TestNewOperationsRefuseUnauthorizedWrongPurposeReplayAndOversize(t *testing.T) {
	s := buildStack(t)
	csr := csrFor(t, "api.staging.internal")

	t.Run("unauthorized principal", func(t *testing.T) {
		response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/stranger",
			"e2e-ca", "e2e-pki", "1111111111111111", csr)
		if response.Code == http.StatusOK {
			t.Fatal("an unauthorized principal obtained a certificate")
		}
	})

	t.Run("wrong purpose", func(t *testing.T) {
		response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
			"e2e-ca", "e2e-agreement", "2222222222222222", csr)
		if response.Code == http.StatusOK {
			t.Fatal("a certificate was issued under the wrong purpose")
		}
	})

	t.Run("replayed nonce", func(t *testing.T) {
		first := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
			"e2e-ca", "e2e-pki", "3333333333333333", csr)
		if first.Code != http.StatusOK {
			t.Fatalf("first call failed: %s", first.Body.String())
		}
		second := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
			"e2e-ca", "e2e-pki", "3333333333333333", csr)
		if second.Code == http.StatusOK {
			t.Fatal("a replayed nonce was accepted")
		}
	})

	t.Run("oversized payload", func(t *testing.T) {
		response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
			"e2e-ca", "e2e-pki", "4444444444444444", make([]byte, 9<<10))
		if response.Code == http.StatusOK {
			t.Fatal("an oversized certificate request was accepted")
		}
	})

	t.Run("csr outside the delegated namespace", func(t *testing.T) {
		response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
			"e2e-ca", "e2e-pki", "5555555555555555", csrFor(t, "api.example.com"))
		if response.Code == http.StatusOK {
			t.Fatal("a certificate was issued outside the delegated namespace")
		}
	})
}
