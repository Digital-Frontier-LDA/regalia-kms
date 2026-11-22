package operations

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
)

const (
	httpFixturePrincipal = "spiffe://regalia/workload/http-fixture"
	httpFixtureResult    = "inert operation output"
)

type httpOperation struct {
	name, algorithm, contentType string
}

var httpCapacityOperations = []httpOperation{
	{"sign", "p256", "application/vnd.regalia.digest"},
	{"wrap", "rsa2048", DataKeyContentType},
	{"unwrap", "rsa2048", DataKeyContentType},
	{"certificate-sign", "p256", DataKeyContentType},
	{"key-agreement", "p256", DataKeyContentType},
}

type httpAdmission struct{ serving atomic.Bool }

func (gate *httpAdmission) Ready(context.Context) bool { return gate.serving.Load() }

type httpHardwareCall struct{ object, operation, algorithm, version, slot string }

// The first backend call can occupy the real executor until the test releases it.
type httpFixtureHardware struct {
	mu           sync.Mutex
	calls        []httpHardwareCall
	entered      chan struct{}
	release      chan struct{}
	apiOperation string
}

func (*httpFixtureHardware) Healthy(context.Context, registry.Binding) bool { return true }

func (h *httpFixtureHardware) Execute(ctx context.Context, route registry.Route, operation, _, _ string, data, _ []byte) ([]byte, string, error) {
	h.mu.Lock()
	h.calls = append(h.calls, httpHardwareCall{route.ObjectID, operation, route.Algorithm, route.KEKVersion, route.Binding.ObjectID})
	first := len(h.calls) == 1
	h.mu.Unlock()
	if first && h.release != nil {
		close(h.entered)
		select {
		case <-h.release:
		case <-ctx.Done():
			return nil, "", ctx.Err()
		}
	}
	switch h.apiOperation {
	case "release-secret":
		if operation != "unwrap" || string(data) != httpWrappedKey {
			return nil, "", fmt.Errorf("release fixture backend expected the envelope's wrapped key")
		}
		return []byte(httpDataKey), DataKeyContentType, nil
	case "seal-envelope":
		if operation != "wrap" || string(data) != httpDataKey {
			return nil, "", fmt.Errorf("seal fixture backend expected the assembled data key")
		}
		return []byte(httpWrappedKey), DataKeyContentType, nil
	default:
		return []byte(httpFixtureResult), "application/octet-stream", nil
	}
}

type httpServingFixture struct {
	op          httpOperation
	now         time.Time
	handler     http.Handler
	gate        *httpAdmission
	hardware    *httpFixtureHardware
	state       *policy.FileState
	journal     string
	auditPath   string
	wirePayload map[string]string
}

func newHTTPServingFixture(t *testing.T, op httpOperation, blockFirst bool, cosmos *policy.CosmosPolicy) *httpServingFixture {
	t.Helper()
	f := &httpServingFixture{op: op, now: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		gate: &httpAdmission{}, hardware: &httpFixtureHardware{apiOperation: op.name}}
	f.gate.serving.Store(true)
	if blockFirst {
		f.hardware.entered, f.hardware.release = make(chan struct{}), make(chan struct{})
	}

	rbac, err := auth.LoadPolicy(strings.NewReader(fmt.Sprintf(
		`{"schema_version":1,"principals":[{"uri":%q,"grants":[{"objects":["http-object"],"operations":[%q],"environments":["staging"]}]}]}`,
		httpFixturePrincipal, op.name)))
	if err != nil {
		t.Fatalf("fixture RBAC: %v", err)
	}

	routes, err := registry.Load(strings.NewReader(httpFixtureManifest(op)), "sitea", f.hardware)
	if err != nil {
		t.Fatalf("fixture registry: %v", err)
	}
	clock := func() time.Time { return f.now }
	routes.SetClock(clock)
	dir := t.TempDir()
	f.journal, f.auditPath = filepath.Join(dir, "policy.jsonl"), filepath.Join(dir, "audit.jsonl")
	f.state, err = policy.OpenFileState(f.journal)
	if err != nil {
		t.Fatalf("fixture FileState: %v", err)
	}
	t.Cleanup(func() {
		if err := f.state.Close(); err != nil {
			t.Errorf("close fixture FileState: %v", err)
		}
	})
	engine, err := policy.New([]policy.Policy{{ID: "http-policy", ObjectID: "http-object", Purpose: "http-test",
		Environment: "staging", Operation: op.name, Algorithm: op.algorithm, ContentTypes: []string{op.contentType},
		MaxPayloadBytes: 4096, MaxFuture: time.Minute, Cosmos: cosmos}}, f.state, clock)
	if err != nil {
		t.Fatalf("fixture policy: %v", err)
	}
	recorder, err := audit.Open(f.auditPath, &ackSink{})
	if err != nil {
		t.Fatalf("fixture audit recorder: %v", err)
	}
	t.Cleanup(func() {
		if err := recorder.Close(); err != nil {
			t.Errorf("close fixture audit: %v", err)
		}
	})
	var hardware Hardware = f.hardware
	if op.name == "release-secret" {
		hardware, err = secrets.NewReleaser(hardware)
		if err != nil {
			t.Fatal(err)
		}
	}
	coordinator, err := New(rbac, routes, engine, recorder,
		admission.NewRunner(f.gate, executor.New(1, 15*time.Second)), hardware, "sha256:http-policy", nil, clock)
	if err != nil {
		t.Fatalf("fixture coordinator: %v", err)
	}
	coordinator.RequireAdmission(f.gate)
	coordinator.SetPolicyHead(f.state.Head)
	router := server.Routes(nil, api.NewHandler(coordinator), nil, nil)
	f.handler = auth.NewAuthenticator("spiffe://regalia/", nil, clock, 0).Middleware(router)
	if op.algorithm == "opaque" {
		f.wirePayload = httpEnvelopePayload(t, op, f.now)
	} else {
		f.wirePayload = httpPayload(t, op, cosmos != nil)
	}
	return f
}

func httpPayload(t *testing.T, op httpOperation, cosmos bool) map[string]string {
	t.Helper()
	encode := base64.StdEncoding.EncodeToString
	switch op.name {
	case "sign":
		payload := bytes.Repeat([]byte{1}, 32)
		if cosmos {
			payload = bridgeCosmosSignDoc()
		}
		return map[string]string{"content_type": op.contentType, "payload_base64": encode(payload)}
	case "wrap":
		return map[string]string{"format": "regalia-envelope-v2", "plaintext_data_key_base64": encode(bytes.Repeat([]byte{2}, 32)),
			"envelope_aad_base64": encode([]byte("fixture binding"))}
	case "unwrap":
		return map[string]string{"format": "regalia-envelope-v2", "wrapped_data_key_base64": encode(bytes.Repeat([]byte{3}, 256)),
			"envelope_aad_base64": encode([]byte("fixture binding"))}
	case "certificate-sign", "key-agreement":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if op.name == "certificate-sign" {
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "http.fixture.invalid"}, DNSNames: []string{"http.fixture.invalid"},
			}, key)
			if err != nil {
				t.Fatal(err)
			}
			return map[string]string{"payload_base64": encode(csr)}
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"payload_base64": encode(public), "envelope_aad_base64": encode([]byte("fixture binding"))}
	default:
		t.Fatalf("unknown fixture operation %q", op.name)
		return nil
	}
}

func httpNonce(n int) string { return fmt.Sprintf("%032x", n) }

func (f *httpServingFixture) request(t *testing.T, nonce, requestNumber int) *http.Request {
	t.Helper()
	fields := map[string]any{"object_id": "http-object", "context": map[string]string{
		"environment": "staging", "purpose": "http-test", "expires_at": f.now.Add(30 * time.Second).Format(time.RFC3339),
		"nonce": httpNonce(nonce)}}
	for k, v := range f.wirePayload {
		fields[k] = v
	}
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/operations/"+f.op.name, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", httpNonce(nonce))
	request.Header.Set("X-Request-ID", fmt.Sprintf("018f0000-0000-7000-8000-%012d", requestNumber))
	// Supply the verified peer-chain state that the HTTP middleware receives from TLS.
	principal, err := url.Parse(httpFixturePrincipal)
	if err != nil {
		t.Fatal(err)
	}
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		SerialNumber: big.NewInt(1), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{principal},
	}}}}
	return request
}

func (f *httpServingFixture) send(request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func expectHTTPFailure(t *testing.T, what string, request *http.Request, response *httptest.ResponseRecorder, status int, code string, retryable bool) {
	t.Helper()
	var document struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
		Message   string `json:"message"`
		Retryable *bool  `json:"retryable"`
	}
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields() // An operation ID or result, even an empty one, is a failure.
	err := decoder.Decode(&document)
	trailing := decoder.Decode(new(json.RawMessage))
	if response.Code != status || err != nil || trailing != io.EOF || document.Code != code || document.Retryable == nil ||
		*document.Retryable != retryable || document.RequestID != request.Header.Get("X-Request-ID") || document.Message == "" {
		t.Fatalf("%s: got HTTP %d code=%q retryable=%v decode=%v trailing=%v; want HTTP %d %s retryable=%t with no operation result",
			what, response.Code, document.Code, document.Retryable != nil && *document.Retryable, err, trailing, status, code, retryable)
	}
}

func expectHTTPSuccess(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	var document struct {
		OperationID string `json:"operation_id"`
		Result      []byte `json:"result_base64"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); response.Code != http.StatusOK || err != nil ||
		document.OperationID == "" || string(document.Result) != httpFixtureResult {
		t.Fatalf("same-route positive control: HTTP %d, %s (decode %v)", response.Code, response.Body, err)
	}
}

func (f *httpServingFixture) expectCalls(t *testing.T, n int) {
	t.Helper()
	f.hardware.mu.Lock()
	defer f.hardware.mu.Unlock()
	if len(f.hardware.calls) != n {
		t.Fatalf("backend invoked %d times, want %d", len(f.hardware.calls), n)
	}
	expected := httpHardwareCall{"http-object", f.op.name, f.op.algorithm, "", "01"}
	switch f.op.name {
	case "release-secret":
		expected = httpHardwareCall{"http-object", "unwrap", "rsa2048", "v1", "02"}
	case "seal-envelope":
		expected = httpHardwareCall{"http-object", "wrap", "rsa2048", "v2", "01"}
	}
	for _, call := range f.hardware.calls {
		if call != expected {
			t.Fatalf("backend call %v, want selected operation, object and binding %v", call, expected)
		}
	}
}

func (f *httpServingFixture) expectJournal(t *testing.T, count uint64) {
	t.Helper()
	onDisk, err := policy.VerifyState(f.journal)
	if err != nil || onDisk.Reservations != count {
		t.Fatalf("verified on-disk reservations = %d (%v), want %d", onDisk.Reservations, err, count)
	}
}

func (f *httpServingFixture) expectAudit(t *testing.T, request *http.Request, want ...string) {
	t.Helper()
	events, err := audit.VerifyIntegrity(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, event := range events {
		if event.RequestID == request.Header.Get("X-Request-ID") {
			got = append(got, event.Decision+"/"+event.Outcome)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("request audit = %v, want %v", got, want)
	}
}

func TestHTTPOperationBusySpendsNonce(t *testing.T) {
	for _, op := range append(httpCapacityOperations, httpEnvelopeOperations...) {
		t.Run(op.name, func(t *testing.T) {
			f := newHTTPServingFixture(t, op, true, nil)
			initial := f.request(t, 1, 1)
			done := make(chan struct{})
			var first *httptest.ResponseRecorder
			go func() {
				defer close(done)
				first = f.send(initial)
			}()
			release := sync.OnceFunc(func() { close(f.hardware.release) })
			t.Cleanup(func() {
				release()
				<-done
			})
			select {
			case <-f.hardware.entered:
			case <-done:
				t.Fatalf("holder never entered the real executor: HTTP %d %s", first.Code, first.Body)
			case <-initial.Context().Done():
				t.Fatal("holder did not reach the backend")
			}
			f.expectJournal(t, 1)

			busy := f.request(t, 2, 2)
			expectHTTPFailure(t, "at capacity", busy, f.send(busy), http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", true)
			f.expectCalls(t, 1)
			f.expectJournal(t, 2)
			f.expectAudit(t, busy, "allow/authorized", "allow/backend-failed")

			release()
			<-done
			f.expectSuccess(t, first)

			replay := f.request(t, 2, 3)
			expectHTTPFailure(t, "busy nonce reuse", replay, f.send(replay), http.StatusConflict, "CONFLICT", false)
			f.expectCalls(t, 1)
			f.expectJournal(t, 2)
			f.expectAudit(t, replay, "deny/policy-REPLAY:replay")
		})
	}
}

func TestHTTPOperationAlreadyReserved(t *testing.T) {
	for _, op := range append(httpCapacityOperations[1:], httpEnvelopeOperations...) {
		t.Run(op.name, func(t *testing.T) {
			f := newHTTPServingFixture(t, op, false, nil)
			f.expectSuccess(t, f.send(f.request(t, 1, 1)))
			f.expectCalls(t, 1)
			f.expectJournal(t, 1)

			replay := f.request(t, 1, 2)
			expectHTTPFailure(t, "duplicate committed nonce", replay, f.send(replay), http.StatusConflict, "CONFLICT", false)
			f.expectCalls(t, 1)
			f.expectJournal(t, 1)
			f.expectAudit(t, replay, "deny/policy-REPLAY:replay")
		})
	}
}

func TestHTTPPolicyCapacityControls(t *testing.T) {
	t.Run("admission-refuses-before-reservation", func(t *testing.T) {
		f := newHTTPServingFixture(t, httpCapacityOperations[0], false, nil)
		f.gate.serving.Store(false)
		denied := f.request(t, 1, 1)
		expectHTTPFailure(t, "earlier admission refusal", denied, f.send(denied), http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", true)
		f.expectCalls(t, 0)
		f.expectJournal(t, 0)
		f.expectAudit(t, denied, "deny/not-admitted")
		f.gate.serving.Store(true)
		expectHTTPSuccess(t, f.send(f.request(t, 1, 2)))
		f.expectCalls(t, 1)
		f.expectJournal(t, 1)
	})
	t.Run("actual-quota-refusal-has-no-reservation", func(t *testing.T) {
		op := httpOperation{"sign", "secp256k1", "application/vnd.cosmos.tx+protobuf"}
		cosmos := &policy.CosmosPolicy{
			ChainIDs: []string{"cosmoshub-4"}, AccountNumbers: []uint64{42}, MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"},
			Sources: []string{"cosmos1source"}, Destinations: []string{"cosmos1dest"}, MaxGasLimit: 200_000,
			MaxFee: map[string]uint64{"uatom": 1_000}, MaxPerTransaction: map[string]uint64{"uatom": 900_000},
			MaxPerDay: map[string]uint64{"uatom": 900_000},
		}
		control := newHTTPServingFixture(t, op, false, cosmos)
		expectHTTPSuccess(t, control.send(control.request(t, 1, 1)))
		control.expectCalls(t, 1)
		control.expectJournal(t, 1)

		f := newHTTPServingFixture(t, op, false, cosmos)
		// Seed only quota, without a Cosmos sequence, so the fresh request reaches the quota rule.
		if err := f.state.Reserve(context.Background(), policy.Reservation{
			PolicyID: "http-policy", ObjectID: "http-object", Principal: httpFixturePrincipal, Nonce: httpNonce(9),
			UTCDate: f.now.Format("2006-01-02"), Amounts: map[string]uint64{"uatom": 900_000},
			DailyCaps: map[string]uint64{"uatom": 900_000},
		}); err != nil {
			t.Fatalf("seed durable quota control: %v", err)
		}
		denied := f.request(t, 1, 1)
		expectHTTPFailure(t, "quota, despite free executor capacity", denied, f.send(denied), http.StatusTooManyRequests, "RESOURCE_EXHAUSTED", true)
		f.expectCalls(t, 0)
		f.expectJournal(t, 1)
		f.expectAudit(t, denied, "deny/policy-LIMIT_EXCEEDED:quota")
	})
}
