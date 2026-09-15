package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
)

type fakeCoordinator struct {
	request Request
	result  Result
	err     error
	calls   int
}

func (coordinator *fakeCoordinator) Execute(_ context.Context, request Request) (Result, error) {
	coordinator.calls++
	request.Data = append([]byte(nil), request.Data...)
	request.EnvelopeAAD = append([]byte(nil), request.EnvelopeAAD...)
	// The handler zeroes the seal parts on return, as it does Data above; capture them first.
	request.SealCiphertext = append([]byte(nil), request.SealCiphertext...)
	request.SealNonce = append([]byte(nil), request.SealNonce...)
	request.SealDataKey = append([]byte(nil), request.SealDataKey...)
	coordinator.request = request
	return coordinator.result, coordinator.err
}

func authenticated(t *testing.T, handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	identity, _ := url.Parse("spiffe://regalia/workload/sops-prod")
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
	}
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "018f0000-0000-7000-8000-000000000001")
	request.Header.Set("Idempotency-Key", "018f0000000070008000000000000001")
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	recorder := httptest.NewRecorder()
	auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(handler).ServeHTTP(recorder, request)
	return recorder
}

func TestIdempotencyKeyMustEqualDurableReplayNonce(t *testing.T) {
	coordinator := &fakeCoordinator{}
	body := `{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"different_nonce_0001"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"d3JhcHBlZA=="}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/unwrap", body)
	if recorder.Code != http.StatusBadRequest || coordinator.calls != 0 {
		t.Fatalf("mismatched idempotency response = %d calls=%d", recorder.Code, coordinator.calls)
	}
}

func TestDuplicateJSONKeysAreRejectedBeforeDispatch(t *testing.T) {
	coordinator := &fakeCoordinator{}
	body := `{"object_id":"production-sops","object_id":"other-key","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"d3JhcHBlZA=="}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/unwrap", body)
	if recorder.Code != http.StatusBadRequest || coordinator.calls != 0 {
		t.Fatalf("duplicate-key response = %d calls=%d body=%s", recorder.Code, coordinator.calls, recorder.Body.String())
	}
}

func TestUnwrapValidatesAndDispatchesBoundRequest(t *testing.T) {
	coordinator := &fakeCoordinator{result: Result{OperationID: "018f0000-0000-7000-8000-000000000002", ContentType: "application/octet-stream", Data: []byte("data-key")}}
	body := `{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001","subject":"sha256:context"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"d3JhcHBlZA==","envelope_aad_base64":"e30="}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/unwrap", body)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d %#v %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if coordinator.calls != 1 || coordinator.request.Principal != "spiffe://regalia/workload/sops-prod" || coordinator.request.Operation != "unwrap" || string(coordinator.request.Data) != "wrapped" {
		t.Fatalf("dispatch = %#v", coordinator.request)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response["result_base64"] != "ZGF0YS1rZXk=" {
		t.Fatalf("response = %#v, %v", response, err)
	}
}

func TestMalformedUnknownAndUnauthenticatedRequestsNeverDispatch(t *testing.T) {
	coordinator := &fakeCoordinator{}
	handler := NewHandler(coordinator)
	malformed := `{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"%%%","unexpected":true}`
	recorder := authenticated(t, handler, http.MethodPost, "/v1/operations/unwrap", malformed)
	if recorder.Code != http.StatusBadRequest || coordinator.calls != 0 {
		t.Fatalf("malformed response = %d calls=%d", recorder.Code, coordinator.calls)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/operations/unwrap", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || coordinator.calls != 0 {
		t.Fatalf("unauthenticated response = %d calls=%d", recorder.Code, coordinator.calls)
	}
}

func TestCoordinatorFailureUsesStableSafeError(t *testing.T) {
	coordinator := &fakeCoordinator{err: &Failure{Code: "DENIED", Status: http.StatusForbidden, Retryable: false}}
	body := `{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"d3JhcHBlZA=="}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/unwrap", body)
	if recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "hardware") || !strings.Contains(recorder.Body.String(), `"code":"DENIED"`) {
		t.Fatalf("failure response = %d %s", recorder.Code, recorder.Body.String())
	}
}

func FuzzOperationBoundaryNeverPanicsOrEchoesInput(f *testing.F) {
	f.Add([]byte(`{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","wrapped_data_key_base64":"U0VOU0lUSVZFX0NBTkFSWQ=="}`))
	f.Add([]byte(`{"unexpected":"SENSITIVE_CANARY"}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	identity, _ := url.Parse("spiffe://regalia/workload/fuzz")
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		coordinator := &fakeCoordinator{result: Result{OperationID: "018f0000-0000-7000-8000-000000000002", ContentType: "application/octet-stream", Data: []byte("fixed-result")}}
		request := httptest.NewRequest(http.MethodPost, "/v1/operations/unwrap", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Request-ID", "018f0000-0000-7000-8000-000000000001")
		request.Header.Set("Idempotency-Key", "018f0000000070008000000000000001")
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
		response := httptest.NewRecorder()
		auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(NewHandler(coordinator)).ServeHTTP(response, request)
		if strings.Contains(response.Body.String(), "SENSITIVE_CANARY") {
			t.Fatal("response echoed request content")
		}
		if response.Code < 200 || response.Code > 599 {
			t.Fatalf("invalid status %d", response.Code)
		}
	})
}

// SEALING IS A SERVED OPERATION, GUARDED LIKE RELEASE.
//
// The KMS could release envelopes and not produce them: the primitive existed, the
// registry could route it, and no request could reach either. The seventh path
// carries the assembled parts — ciphertext, nonce, data key — and nothing else:
// the plaintext never crosses the wire.
func TestSealEnvelopeValidatesAndDispatches(t *testing.T) {
	coordinator := &fakeCoordinator{}
	body := `{"object_id":"production-sops","context":{"environment":"production","purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","ciphertext_base64":"` + base64.StdEncoding.EncodeToString([]byte("sealed-ciphertext")) + `","nonce_base64":"` + base64.StdEncoding.EncodeToString([]byte("123456789012")) + `","data_key_base64":"` + base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + `"}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/seal-envelope", body)
	if recorder.Code != http.StatusOK || coordinator.calls != 1 {
		t.Fatalf("seal-envelope = %d calls=%d", recorder.Code, coordinator.calls)
	}
	if coordinator.request.Operation != "seal-envelope" || string(coordinator.request.SealDataKey) != "0123456789abcdef0123456789abcdef" ||
		string(coordinator.request.SealNonce) != "123456789012" || string(coordinator.request.SealCiphertext) != "sealed-ciphertext" {
		t.Fatalf("assembled fields did not reach the coordinator: %#v", coordinator.request)
	}

	// 400 IS ONLY HALF THE CLAIM. The claim is that these are refused AT THE BOUNDARY, so the
	// call count must not move -- without that, a request rejected after reaching the
	// coordinator looks identical from out here, and "validated before dispatch" is the whole
	// point of doing it in the handler.
	//
	// Honestly: the status assertion is what catches a relaxed bound, and the call count is
	// defence in depth. For it to fire on its own the handler would have to dispatch AND still
	// answer 400, which no single mutation here produces -- the status check trips first. It is
	// kept because the property it states is the one the handler exists for, not because a
	// mutation was found that only it catches.
	refusedAtTheBoundary := func(name, payload string) {
		t.Helper()
		before := coordinator.calls
		got := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/seal-envelope", payload).Code
		if got != http.StatusBadRequest {
			t.Fatalf("%s = %d, want 400", name, got)
		}
		if coordinator.calls != before {
			t.Fatalf("%s reached the coordinator: calls %d -> %d", name, before, coordinator.calls)
		}
	}

	// The data key is the sensitive half: wrong size is a 400, not a wrap attempt.
	refusedAtTheBoundary("short data key", strings.Replace(body,
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		base64.StdEncoding.EncodeToString([]byte("short")), 1))

	// A GCM tag is SIXTEEN bytes, so a 16-byte ciphertext is the tag over zero plaintext and the
	// smallest valid one is 17. This previously used 12 and called it "a GCM tag over nothing",
	// which is neither the tag length nor the boundary -- it passed because 12 is also below the
	// minimum, so the test was right about the outcome and wrong about the reason, and would not
	// have noticed the bound moving to anywhere between 13 and 17.
	refusedAtTheBoundary("tag-sized ciphertext with no plaintext", strings.Replace(body,
		base64.StdEncoding.EncodeToString([]byte("sealed-ciphertext")),
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), 1))
}
