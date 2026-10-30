package openbaopoc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func transportResponse(r *http.Request, status int, code string, retry bool) *http.Response {
	body, _ := json.Marshal(map[string]any{"request_id": r.Header.Get("X-Request-ID"), "code": code, "retryable": retry, "message": "private backend credentials", "future_field": true})
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(string(body)))}
}

func TestNativeRetryPolicyAndCorrelation(t *testing.T) {
	for _, tc := range []struct {
		code     string
		status   int
		retry    bool
		attempts int
	}{
		{"BACKEND_UNAVAILABLE", 503, true, 3}, {"DEPENDENCY_UNAVAILABLE", 503, true, 3}, {"RESOURCE_EXHAUSTED", 429, true, 3}, {"DEADLINE_EXCEEDED", 504, true, 3},
		{"BACKEND_UNAVAILABLE", 503, false, 1}, {"DENIED", 403, true, 1}, {"CONFLICT", 409, true, 1}, {"CANCELED", 504, true, 1}, {"FUTURE_ERROR", 503, true, 1},
	} {
		t.Run(tc.code+"/"+map[bool]string{true: "true", false: "false"}[tc.retry], func(t *testing.T) {
			w := configuredNative(t, nativeFixtureConfig(newFixturePKI(t).config))
			seenIDs, seenNonces := map[string]bool{}, map[string]bool{}
			lastID := ""
			w.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
				id, nonce := r.Header.Get("X-Request-ID"), r.Header.Get("Idempotency-Key")
				var doc versionedRequest
				if json.NewDecoder(r.Body).Decode(&doc) != nil || doc.Context.Nonce != nonce || id == "" || nonce == "" || seenIDs[id] || seenNonces[nonce] {
					t.Fatal("retry reused or omitted correlation/nonce")
				}
				seenIDs[id], seenNonces[nonce], lastID = true, true, id
				return transportResponse(r, tc.status, tc.code, tc.retry), nil
			})
			_, err := w.Encrypt(context.Background(), []byte{1})
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != tc.code || apiErr.RequestID != lastID || len(seenIDs) != tc.attempts || strings.Contains(err.Error(), "private") {
				t.Fatalf("wrong bounded retry/error: attempts=%d error=%v", len(seenIDs), err)
			}
		})
	}
}

func TestNativeAmbiguousTransportIsNeverRetried(t *testing.T) {
	w := configuredNative(t, nativeFixtureConfig(newFixturePKI(t).config))
	calls := 0
	w.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private backend endpoint and credentials")
	})
	_, err := w.Encrypt(context.Background(), []byte{1})
	var apiErr *APIError
	if calls != 1 || !errors.As(err, &apiErr) || apiErr.Code != "TRANSPORT_UNAVAILABLE" || apiErr.Retryable || strings.Contains(err.Error(), "private") {
		t.Fatal("ambiguous request retried or leaked", err)
	}
}

func TestNativeCancellationInterruptsBackoff(t *testing.T) {
	w := configuredNative(t, nativeFixtureConfig(newFixturePKI(t).config))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	w.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		time.AfterFunc(10*time.Millisecond, cancel)
		return transportResponse(r, 503, "BACKEND_UNAVAILABLE", true), nil
	})
	started := time.Now()
	_, err := w.Encrypt(ctx, []byte{1})
	if calls != 1 || !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatal("cancellation did not bound retry", err)
	}
}

func TestNativeResponseExtensibilityAndProtocolRefusals(t *testing.T) {
	good := `{"request_id":"id","operation_id":"op","object_id":"object","content_type":"secret","result_base64":"AQ==","future_field":{"v":1}}`
	if out, err := decodeAPIResponse([]byte(good), 200, "id", "object", "secret", 1024); err != nil || len(out) != 1 {
		t.Fatal("additive API field refused", err)
	}
	for _, body := range []string{good + `{}`, strings.Replace(good, `"request_id":"id"`, `"request_id":"id","request_id":"id"`, 1), strings.Replace(good, `"id"`, `"wrong"`, 1), `{"request_id":"id","code":"DENIED","retryable":null}`, `{"request_id":"id","code":"BACKEND_UNAVAILABLE","retryable":true}`} {
		_, err := decodeAPIResponse([]byte(body), 403, "id", "object", "secret", 1024)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != "PROTOCOL_ERROR" || apiErr.Retryable {
			t.Fatal("malformed response accepted", err)
		}
	}
}
