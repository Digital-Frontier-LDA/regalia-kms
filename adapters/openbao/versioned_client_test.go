package openbaopoc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

type responseTransport func(*http.Request) (*http.Response, error)

func (r responseTransport) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }

func TestVersionedReleaseResponseBoundary(t *testing.T) {
	w, _ := testWrapper()
	b := w.binding
	b.KeyVersion = "g1"
	req, err := request(b, "unwrap", []byte("synthetic-envelope"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "status", "content-type", "no-store", "request-id", "object-id", "operation-id", "result-type", "unknown-field", "trailing", "oversize", "short-key"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			c := &versionedClient{base: "https://kms.poc.test", binding: b, http: &http.Client{Transport: responseTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != "/v1/operations/release-secret" || r.Header.Get("X-Request-ID") != req.RequestID {
					t.Fatal("invalid request correlation")
				}
				result := map[string]any{"request_id": req.RequestID, "operation_id": "synthetic", "object_id": b.ObjectID, "content_type": "application/vnd.regalia.secret", "result_base64": bytes.Repeat([]byte{42}, 32)}
				header := http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}
				status := http.StatusOK
				switch mode {
				case "status":
					status = http.StatusServiceUnavailable
				case "content-type":
					header.Set("Content-Type", "text/plain")
				case "no-store":
					header.Del("Cache-Control")
				case "request-id":
					result["request_id"] = "wrong"
				case "object-id":
					result["object_id"] = "wrong"
				case "operation-id":
					result["operation_id"] = ""
				case "result-type":
					result["content_type"] = "application/vnd.regalia.envelope"
				case "unknown-field":
					result["provider-private-detail"] = "synthetic-private-detail"
				case "short-key":
					result["result_base64"] = []byte{1}
				}
				data, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "trailing" {
					data = append(data, []byte(` {}`)...)
				}
				if mode == "oversize" {
					data = bytes.Repeat([]byte{'x'}, (maxWrappedKey<<1)+1)
				}
				return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}}
			out, err := c.Unwrap(context.Background(), req)
			if mode == "valid" {
				if err != nil || len(out) != 32 {
					t.Fatal("valid response refused")
				}
			} else if err != errOperation || len(out) != 0 {
				t.Fatal("untrusted response released data or exposed diagnostics")
			}
			clear(out)
			if calls != 1 {
				t.Fatal("provider operation retried")
			}
		})
	}
}
