package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

// A ZERO SHUTDOWN TIMEOUT MUST NOT DROP AN IN-FLIGHT REQUEST.
//
// Zero does not mean "shut down immediately" — it builds an already-expired context, so Shutdown
// gives in-flight work no grace, returns context.DeadlineExceeded, and the error branch calls
// Close(), dropping the connection. Measured before the guard existed, with one request in flight:
//
//	ShutdownTimeout=0   Serve returned "context deadline exceeded", client got EOF
//	ShutdownTimeout=2s  Serve returned nil,                         client got 200 OK
//
// For this service an in-flight request is a signing operation against hardware, so the caller sees
// a failure for an operation that completed and a key that was used.
//
// Config validates shutdown_timeout into 1s..2m so the daemon cannot reach zero. That makes this
// safe because of the one caller, not because Serve is safe — and Serve is exported.
//
// THE IN-FLIGHT REQUEST IS THE WHOLE TEST. With an idle server, Shutdown returns nil on an expired
// context and both arms look identical; the first version of this probe was written that way and
// reported no difference at all.
func TestZeroShutdownTimeoutStillDrainsInFlightWork(t *testing.T) {
	for _, timeout := range []struct {
		what  string
		value time.Duration
	}{
		{"zero, meaning unset", 0},
		{"negative", -time.Second},
		// The control: an explicitly generous timeout must behave the same, or the assertions
		// above would be satisfied by a server that never drains anything.
		{"explicitly generous", 5 * time.Second},
	} {
		t.Run(timeout.what, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := listener.Addr().String()
			started := make(chan struct{})
			handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				close(started)
				time.Sleep(400 * time.Millisecond)
				fmt.Fprintln(writer, "done")
			})

			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan error, 1)
			go func() { served <- Serve(ctx, listener, handler, Options{ShutdownTimeout: timeout.value}) }()

			response := make(chan *http.Response, 1)
			failed := make(chan error, 1)
			go func() {
				resp, err := http.Get("http://" + address + "/")
				if err != nil {
					failed <- err
					return
				}
				response <- resp
			}()

			<-started
			cancel() // shutdown begins while the handler is still working

			select {
			case err := <-failed:
				t.Fatalf("DEFECT: the in-flight request was dropped during shutdown (%v). A zero or "+
					"negative ShutdownTimeout builds an already-expired context, so Shutdown grants no "+
					"grace and Close() takes the connection — the caller sees a failure for an "+
					"operation that ran.", err)
			case resp := <-response:
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("in-flight request finished with %s, want 200", resp.Status)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the request neither completed nor failed within 5s")
			}

			// BOUNDED, because an unbounded receive turns "shutdown blocks" into a ten-minute CI
			// hang ending in a panic dump, instead of a named failure here. The regression this
			// test exists to catch and the regression that would hang it are neighbours.
			select {
			case err := <-served:
				if err != nil {
					t.Fatalf("DEFECT: Serve reported %v on a clean shutdown", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("DEFECT: Serve did not return within 5s of the context being cancelled — " +
					"shutdown is blocking rather than draining")
			}
		})
	}
}
