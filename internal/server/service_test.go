package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type switchProbe struct{ ready atomic.Bool }

func (probe *switchProbe) Ready(context.Context) bool { return probe.ready.Load() }

func TestRequiredDependenciesLoseAndRecoverReadiness(t *testing.T) {
	probes := []*switchProbe{{}, {}, {}, {}}
	for _, probe := range probes {
		probe.ready.Store(true)
	}
	handler := NewRequired(Dependencies{Policy: probes[0], Registry: probes[1], Audit: probes[2], Token: probes[3]})
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusOK {
		t.Fatalf("initial readiness = %d, want 200", got)
	}
	probes[2].ready.Store(false)
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("readiness after audit loss = %d, want 503", got)
	}
	probes[2].ready.Store(true)
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusOK {
		t.Fatalf("readiness after recovery = %d, want 200", got)
	}
}

func TestServeStartsAndShutsDown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, New(nil), Options{ShutdownTimeout: time.Second}) }()

	response, err := http.Get("http://" + listener.Addr().String() + "/v1/health/live")
	if err != nil {
		cancel()
		t.Fatalf("GET liveness: %v", err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("liveness = %d, want 200", response.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not shut down")
	}
}
