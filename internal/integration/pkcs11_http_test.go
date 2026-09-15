package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type pinSource struct{ value []byte }

func (source pinSource) PIN(context.Context, string) ([]byte, error) {
	return append([]byte(nil), source.value...), nil
}

type devAuthProbe string

func (probe devAuthProbe) Fingerprint(context.Context, string, string) (string, error) {
	return string(probe), nil
}

type secureChannel struct{}

func (secureChannel) Establish(context.Context, string, string) error { return nil }

type retryProbe int

func (probe retryProbe) Remaining(context.Context, string, string) (int, error) {
	return int(probe), nil
}

type auditSink struct{ events []audit.Event }

func (sink *auditSink) Send(_ context.Context, event audit.Event) error {
	sink.events = append(sink.events, event)
	return nil
}
func (*auditSink) Ready(context.Context) bool { return true }

func TestHTTPToCoordinatorToConcretePKCS11(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	principal := "spiffe://regalia/workload/e2e"
	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	driver, err := nitrokey.NewPKCS11Driver(modulePath, devAuthProbe(devAuth), secureChannel{}, retryProbe(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := nitrokey.New(driver, pinSource{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
	if err != nil {
		t.Fatal(err)
	}

	manifest := fmt.Sprintf(`{
      "schema_version":1,"manifest_id":"e2e-manifest","generated_at":"2026-09-03T12:00:00Z",
      "objects":[{"id":"e2e-signing-key","name":"E2E","kind":"asymmetric-key","classification":"restricted","environment":"development",
      "owner":"security","purpose":"e2e-signing","custody":"direct-hardware","algorithm":"secp256k1",
      "operations":["sign"],"policy_id":"e2e-policy","bindings":[{"site":"e2e-site","backend":"nitrokey-pkcs11",
      "device_id":"hsm-e2e","device_serial":%q,"devaut_fingerprint":%q,"object_id":"01",
      "public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],
      "recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`, serial, devAuth)
	router, err := registry.Load(bytes.NewBufferString(manifest), "e2e-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(bytes.NewBufferString(`{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/e2e","grants":[{"objects":["e2e-signing-key"],"operations":["sign"],"environments":["development"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "policy.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := policy.New([]policy.Policy{{
		ID: "e2e-policy", ObjectID: "e2e-signing-key", Purpose: "e2e-signing", Environment: "development",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.regalia.digest"},
		MaxPayloadBytes: 32, MaxFuture: time.Minute,
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	sink := &auditSink{}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	coordinator, err := operations.New(rbac, router, engine, recorder, executor.New(1, 5*time.Second), hardware, "sha256:e2e-policy", nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Second).Middleware(api.NewHandler(coordinator))

	body := fmt.Sprintf(`{"object_id":"e2e-signing-key","context":{"environment":"development","purpose":"e2e-signing","expires_at":%q,"nonce":"1234567890abcdef"},"content_type":"application/vnd.regalia.digest","payload_base64":%q}`,
		now.Add(30*time.Second).Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(make([]byte, 32)))
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "12345678-1234-4234-8234-123456789abc")
	request.Header.Set("Idempotency-Key", "1234567890abcdef")
	principalURI, _ := url.Parse(principal)
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{principalURI},
	}
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Result []byte `json:"result_base64"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || len(result.Result) != 64 {
		t.Fatalf("signature length=%d err=%v body=%s", len(result.Result), err, response.Body.String())
	}
	if len(sink.events) != 2 || sink.events[0].Outcome != "authorized" || sink.events[1].Outcome != "success" {
		t.Fatalf("audit events=%#v", sink.events)
	}
}
