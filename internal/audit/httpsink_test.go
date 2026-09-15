package audit

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPSinkRequiresAcknowledgedHashAndUsesNoRedirect(t *testing.T) {
	event := Event{Sequence: 1, Hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	var eventCalls, healthCalls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/events":
			eventCalls++
			if request.Method != http.MethodPost || request.Header.Get("Idempotency-Key") != event.Hash || request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("unsafe event request: %s %#v", request.Method, request.Header)
			}
			body, _ := io.ReadAll(request.Body)
			if strings.Contains(string(body), "private") {
				t.Fatal("unexpected body")
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{event.Hash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		case "/v1/health/ready":
			healthCalls++
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
			return nil, nil
		}
	})}
	sink, err := NewHTTPSink("https://audit.internal", client, 2*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if !sink.Ready(context.Background()) {
		t.Fatal("healthy collector reported unavailable")
	}
	if err := sink.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if eventCalls != 1 || healthCalls != 1 || sink.client.CheckRedirect == nil {
		t.Fatalf("calls events=%d health=%d redirect-set=%t", eventCalls, healthCalls, sink.client.CheckRedirect != nil)
	}
}

func TestHTTPSinkFailsClosedOnBadURLStatusOrAcknowledgement(t *testing.T) {
	if _, err := NewHTTPSink("http://audit.internal", &http.Client{}, time.Second, ""); err == nil {
		t.Fatal("plaintext collector URL accepted")
	}
	for name, response := range map[string]*http.Response{
		"status": {StatusCode: http.StatusAccepted, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))},
		"ack":    {StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{"sha256:wrong"}}, Body: io.NopCloser(strings.NewReader(""))},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil })}
			sink, err := NewHTTPSink("https://audit.internal", client, time.Second, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.Send(context.Background(), Event{Hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
				t.Fatal("collector failure was accepted")
			}
		})
	}
}
