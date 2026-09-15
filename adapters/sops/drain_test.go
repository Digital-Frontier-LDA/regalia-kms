package sopsadapter

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A REFUSAL MUST STILL LEAVE THE CONNECTION REUSABLE.
//
// The unwrap path refuses a response that omits `Cache-Control: no-store`, which is correct — an
// unwrapped data key must never be cacheable. But it returned WITHOUT reading the body, and an
// unread body makes the connection unreusable: Go cannot return it to the idle pool, so every
// refusal opens a fresh TCP connection. A server that keeps omitting the header therefore turns a
// steady refusal into connection growth, which is the wrong failure to add to a KMS under load.
//
// Every other error branch already drained. This asserts the refusal branch matches them, by
// counting NEW connections across repeated refusals: with draining the client reuses one.
func TestUnwrapRefusalWithoutNoStoreStillReusesTheConnection(t *testing.T) {
	var newConnections int64
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		// Deliberately no Cache-Control: no-store — the condition under test.
		_, _ = writer.Write([]byte(`{"request_id":"018f0000-0000-7000-8000-000000000001",` +
			`"operation_id":"018f0000-0000-7000-8000-000000000002","object_id":"production-sops",` +
			`"content_type":"application/vnd.regalia.envelope+json","result_base64":"cGxhaW4="}`))
	})
	// INSTALL ConnState BEFORE THE SERVER STARTS. Setting it on an already-serving httptest server
	// races the first connection: the hook may miss it, so the count under-reports and the
	// assertion passes or fails by timing. It passed consistently on macOS and failed on Linux CI.
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt64(&newConnections, 1)
		}
	}
	server.StartTLS()
	defer server.Close()

	client := NewHTTPClient(server.URL, server.Client(), func() time.Time {
		return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	})

	const attempts = 4
	for i := 0; i < attempts; i++ {
		result, err := client.Unwrap(context.Background(), Request{
			Operation: "unwrap", ObjectID: "production-sops",
			Repository: "regalia-kms/infrastructure",
			Path:       "clusters/prod/secrets.enc.yaml", Environment: "production",
			Purpose:   "sops-data-key",
			RequestID: "018f0000-0000-7000-8000-000000000001",
			// Idempotency key must equal the durable replay nonce shape used elsewhere.
			IdempotencyKey: "sops-018f0000000070008000000000000001",
			Data:           []byte("wrapped"),
		})
		if err == nil {
			t.Fatal("Unwrap() accepted a response without Cache-Control: no-store")
		}
		if len(result) != 0 {
			t.Fatalf("refusal returned %d bytes of material", len(result))
		}
	}

	if got := atomic.LoadInt64(&newConnections); got > 1 {
		t.Fatalf("%d refusals opened %d connections; an undrained body prevents reuse", attempts, got)
	}
}
