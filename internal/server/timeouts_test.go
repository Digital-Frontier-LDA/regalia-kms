package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// The HTTP write deadline must always outlive the configured operation deadline. It was a 10s
// constant while operation_timeout defaults to 15s and may be set to 10m, so the server cut the
// connection before the operation's own deadline and the caller saw a truncated response rather
// than the timeout the configuration promised.
func TestWriteDeadlineAlwaysOutlivesTheOperationDeadline(t *testing.T) {
	for _, operation := range []time.Duration{
		100 * time.Millisecond, // config minimum
		15 * time.Second,       // config default
		30 * time.Second,
		10 * time.Minute, // config maximum
	} {
		server := httpServerFor(New(nil), operation)
		if server.WriteTimeout <= operation {
			t.Fatalf("operation deadline %s: write deadline %s does not outlive it",
				operation, server.WriteTimeout)
		}
	}
}

// A zero Options value must not be weaker than the default configuration.
func TestZeroOperationDeadlineStillOutlivesTheDefault(t *testing.T) {
	server := httpServerFor(New(nil), 0)
	if server.WriteTimeout <= defaultOperationTimeout {
		t.Fatalf("write deadline %s does not outlive the default operation deadline %s",
			server.WriteTimeout, defaultOperationTimeout)
	}
}

// The bounds that are deliberately NOT derived stay put: request bodies are small and bounded, so
// the read deadlines remain fixed slowloris cover.
func TestFixedReadBoundsAreUnchangedByTheOperationDeadline(t *testing.T) {
	short := httpServerFor(New(nil), time.Second)
	long := httpServerFor(New(nil), 10*time.Minute)
	if short.ReadTimeout != long.ReadTimeout || short.ReadHeaderTimeout != long.ReadHeaderTimeout {
		t.Fatal("read deadlines must not scale with the operation deadline")
	}
	if short.MaxHeaderBytes != 32<<10 {
		t.Fatalf("header bound changed: %d", short.MaxHeaderBytes)
	}
}

// END TO END, AND FALSIFIABLE AGAINST THE OLD CONSTANT. A handler that runs longer than the former
// 10s write deadline must still deliver its response when the configured operation deadline allows
// it. This test FAILS against the previous hard-coded 10s and passes once the deadline is derived.
func TestHandlerLongerThanTheOldConstantStillCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~11s by construction: it must exceed the former 10s write deadline")
	}
	const handlerRuntime = 11 * time.Second

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	slow := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(handlerRuntime)
		writer.WriteHeader(http.StatusNoContent)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, slow, Options{
			ShutdownTimeout:  2 * time.Second,
			OperationTimeout: handlerRuntime + 5*time.Second,
		})
	}()

	client := &http.Client{Timeout: handlerRuntime + 20*time.Second}
	response, err := client.Get(fmt.Sprintf("http://%s/", listener.Addr().String()))
	if err != nil {
		t.Fatalf("request cut short before the handler finished: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	cancel()
	<-done
}
