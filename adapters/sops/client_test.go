package sopsadapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClientSendsBoundWrapRequestAndRequiredHeaders(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/operations/wrap" || request.Header.Get("X-Request-ID") == "" || request.Header.Get("Idempotency-Key") == "" {
			t.Fatalf("request path/headers = %s %#v", request.URL.Path, request.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["object_id"] != "production-sops" || body["format"] != "regalia-envelope-v2" {
			t.Fatalf("request body = %#v", body)
		}
		aad, err := base64.StdEncoding.DecodeString(body["envelope_aad_base64"].(string))
		if err != nil || !strings.Contains(string(aad), `"path":"clusters/prod/secrets.enc.yaml"`) {
			t.Fatalf("AAD = %q, %v", aad, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"request_id":"018f0000-0000-7000-8000-000000000001","operation_id":"018f0000-0000-7000-8000-000000000002","object_id":"production-sops","content_type":"application/vnd.regalia.envelope+json","result_base64":"d3JhcHBlZA=="}`))
	}))
	defer server.Close()
	client := NewHTTPClient(server.URL, server.Client(), func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) })
	result, err := client.Wrap(context.Background(), Request{
		Operation: "wrap", ObjectID: "production-sops", Repository: "regalia-kms/infrastructure",
		Path: "clusters/prod/secrets.enc.yaml", Environment: "production", Purpose: "sops-data-key",
		RequestID: "018f0000-0000-7000-8000-000000000001", IdempotencyKey: "sops-018f0000000070008000000000000001", Data: []byte("data-key"),
	})
	if err != nil || string(result) != "wrapped" {
		t.Fatalf("Wrap() = %q, %v", result, err)
	}
}

func TestHTTPClientDenialAndMalformedSuccessReturnNoData(t *testing.T) {
	for _, name := range []string{"denial", "malformed", "content-type-confusion"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if name == "denial" {
					writer.WriteHeader(http.StatusForbidden)
					_, _ = writer.Write([]byte("denied"))
					return
				}
				contentType := "application/json"
				if name == "content-type-confusion" {
					writer.Header().Set("Cache-Control", "no-store")
					contentType = "application/json-evil"
				}
				writer.Header().Set("Content-Type", contentType)
				if name == "content-type-confusion" {
					_, _ = writer.Write([]byte(`{"request_id":"018f0000-0000-7000-8000-000000000001","operation_id":"018f0000-0000-7000-8000-000000000002","object_id":"production-sops","content_type":"application/octet-stream","result_base64":"ZGF0YS1rZXk="}`))
					return
				}
				_, _ = writer.Write([]byte(`{"result_base64":`))
			}))
			defer server.Close()
			client := NewHTTPClient(server.URL, server.Client(), time.Now)
			result, err := client.Unwrap(context.Background(), Request{Operation: "unwrap", ObjectID: "production-sops", Repository: "Org/repo", Path: "prod.enc.yaml", Environment: "production", Purpose: "sops-data-key", RequestID: "018f0000-0000-7000-8000-000000000001", IdempotencyKey: "sops-018f0000000070008000000000000001", Data: []byte("wrapped")})
			if err == nil || result != nil {
				t.Fatalf("Unwrap() = %q, %v", result, err)
			}
		})
	}
}

func TestHTTPClientTimeoutReturnsNoData(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	client := NewHTTPClient(server.URL, server.Client(), time.Now)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result, err := client.Unwrap(ctx, Request{Operation: "unwrap", ObjectID: "production-sops", Repository: "Org/repo", Path: "prod.enc.yaml", Environment: "production", Purpose: "sops-data-key", RequestID: "018f0000-0000-7000-8000-000000000001", IdempotencyKey: "sops-018f0000000070008000000000000001", Data: []byte("wrapped")})
	if err == nil || result != nil {
		t.Fatalf("timeout returned %q, %v", result, err)
	}
}
