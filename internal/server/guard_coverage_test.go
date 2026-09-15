package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingProbe answers whatever it is currently set to and records every evaluation
// that reached it. The call count is the point: a request refused BEFORE the probes run
// and one refused after are the same status code to the caller and two entirely
// different things to the dependencies sitting behind the endpoint.
type countingProbe struct {
	calls atomic.Int64
	ready atomic.Bool
}

func (probe *countingProbe) Ready(context.Context) bool {
	probe.calls.Add(1)
	return probe.ready.Load()
}

// readinessRequest sends one request to /v1/health/ready. It carries a body on purpose:
// an unauthenticated route that would run its dependency probes for any verb is
// reachable with a payload attached, and the fixture should look like the thing being
// refused rather than like a bare probe. The package's own request() helper always
// sends a nil body, which is why this one exists.
func readinessRequest(t *testing.T, handler http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, "/v1/health/ready", strings.NewReader(`{"attacker":"body"}`)))
	return recorder
}

// THE HTTP METHOD IS THE ONLY THING NARROWING /v1/health/ready, AND NOTHING ASSERTED IT.
//
// Routes forwards both health paths to Handler, and the authentication middleware lets
// /v1/health/live and /v1/health/ready straight through without ever calling
// Authenticate. The method check in Handler.ServeHTTP's "/v1/health/ready" case is
// therefore the whole of the narrowing on that route.
//
// WITHOUT THAT CHECK, measured: POST, PUT, DELETE and PATCH to /v1/health/ready all
// answer 200 with body {"status":"ok"}, each one runs every ReadinessProbe exactly once,
// and each one writes readiness history — ReadinessStats().Evaluated flips to true and
// CheckedAt stops being zero. Seeding one GET and then sending only POSTs while the
// probe answer flapped underneath moved ReadinessStats().Transitions from 0 to 6.
// Operators page on that counter, so a verb the endpoint does not serve would both drive
// unauthenticated probe traffic into every dependency and forge the flap history that is
// supposed to describe real evaluations.
//
// The /v1/health/live twin is covered by TestHealthRejectsWrongMethodWithoutDetail. Every
// other request to /v1/health/ready in this package — in health_test.go,
// readiness_stats_test.go, readiness_wiring_test.go and service_test.go — is a GET, so
// this route's method check was unexercised.
func TestReadinessRejectsNonGetWithoutRunningProbes(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			// A probe that would answer READY. The method is then the only thing in the
			// handler that can refuse this request, so a 405 here cannot be an unready
			// dependency wearing the wrong status code.
			probe := &countingProbe{}
			probe.ready.Store(true)
			handler := New([]ReadinessProbe{probe})

			recorder := readinessRequest(t, handler, method)
			if recorder.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /v1/health/ready = %d, want 405 — the only unauthenticated narrowing on this route",
					method, recorder.Code)
			}
			if body := recorder.Body.String(); body != "" {
				t.Fatalf("%s /v1/health/ready body = %q, want empty: readiness answers %q when it serves the "+
					"request and %q when the dependencies are down, and a refused verb must say neither",
					method, body, `{"status":"ok"}`+"\n", `{"status":"unavailable"}`+"\n")
			}
			if calls := probe.calls.Load(); calls != 0 {
				t.Fatalf("%s /v1/health/ready ran the readiness probes %d times, want 0: a verb nobody serves "+
					"is driving unauthenticated traffic into every dependency", method, calls)
			}
			stats := handler.ReadinessStats()
			if stats.Evaluated || !stats.CheckedAt.IsZero() {
				t.Fatalf("%s /v1/health/ready wrote readiness history %+v, want an untouched record: a refused "+
					"request must not be able to claim an evaluation happened", method, stats)
			}
		})
	}

	// AND THE HISTORY IS NOT FORGEABLE BY A VERB. The assertions above pin one request;
	// this pins the consequence operators actually see. Seed one real GET, flap the probe
	// answer underneath, and send only POSTs: Transitions must not move. The same
	// sequence recorded 6 transitions with the method check removed.
	t.Run("non-GET traffic cannot move the transition counter", func(t *testing.T) {
		probe := &countingProbe{}
		probe.ready.Store(true)
		handler := New([]ReadinessProbe{probe})

		if code := readinessRequest(t, handler, http.MethodGet).Code; code != http.StatusOK {
			t.Fatalf("the seeding GET answered %d, want 200 — starting from an unevaluated or unready handler "+
				"would let the flap below pass while proving nothing", code)
		}
		before := handler.ReadinessStats().Transitions
		for attempt := 0; attempt < 6; attempt++ {
			probe.ready.Store(attempt%2 == 0)
			if code := readinessRequest(t, handler, http.MethodPost).Code; code != http.StatusMethodNotAllowed {
				t.Fatalf("POST %d during the flap = %d, want 405", attempt, code)
			}
		}
		if after := handler.ReadinessStats().Transitions; after != before {
			t.Fatalf("transitions moved %d -> %d with nothing but POSTs in between: the flap history operators "+
				"page on can be written by a verb the endpoint does not serve", before, after)
		}
	})

	// ANCHOR, PLACED LAST BY DESIGN (TESTING.md §18): a t.Fatal in a known-good row put
	// first can stop the run before the refusals above ever execute. GET is the one verb
	// this route serves, and it must still reach the probes and answer 200 — otherwise
	// every 405 asserted above would be equally satisfied by a handler that refuses
	// everything, and this whole test would pin a broken endpoint.
	t.Run("ANCHOR GET still reaches the probes and is served", func(t *testing.T) {
		probe := &countingProbe{}
		probe.ready.Store(true)
		handler := New([]ReadinessProbe{probe})

		recorder := readinessRequest(t, handler, http.MethodGet)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET /v1/health/ready = %d, want 200", recorder.Code)
		}
		if body := recorder.Body.String(); body != `{"status":"ok"}`+"\n" {
			t.Fatalf("GET /v1/health/ready body = %q, want the ok status document", body)
		}
		if calls := probe.calls.Load(); calls != 1 {
			t.Fatalf("GET /v1/health/ready ran the readiness probes %d times, want exactly 1", calls)
		}
		if stats := handler.ReadinessStats(); !stats.Evaluated || stats.CheckedAt.IsZero() {
			t.Fatalf("GET /v1/health/ready recorded no evaluation: %+v", stats)
		}
	})
}

// A NON-POSITIVE OPERATION DEADLINE MUST NOT REACH THE WRITE-DEADLINE ARITHMETIC.
//
// httpServerFor derives WriteTimeout as operationTimeout + writeHeadroom. The
// substitution of defaultOperationTimeout is the only thing keeping a zero or negative
// Options value out of that sum, and WITHOUT IT, measured:
//
//	httpServerFor(handler,   0s).WriteTimeout = 30s
//	httpServerFor(handler,  -1s).WriteTimeout = 29s
//	httpServerFor(handler, -30s).WriteTimeout = 0s     <- net/http: no write deadline at all
//	httpServerFor(handler, -45s).WriteTimeout = -15s   <- likewise, no write deadline at all
//
// The two failure modes are opposite and both wrong: a write deadline shorter than the
// operations this service performs, and — from -30s down — a server with no write
// deadline whatsoever, which is the slowloris cover these bounds exist to provide.
//
// Serve validates only ShutdownTimeout and hands Options.OperationTimeout to
// httpServerFor unchecked, and Serve is exported, so an embedder's zero Options value
// reaches this. That is the same shape as the defaultShutdownTimeout guard beside it: an
// exported function must not be safe only because of its current caller's validation.
//
// TestZeroOperationDeadlineStillOutlivesTheDefault does not detect this. It asserts
// WriteTimeout > defaultOperationTimeout, and the unguarded value for a zero input is
// 30s, which clears the 15s default — so the assertion holds whether or not the
// substitution happens. The table in TestWriteDeadlineAlwaysOutlivesTheOperationDeadline
// feeds only 100ms, 15s, 30s and 10m, and never reaches the guard at all.
func TestNonPositiveOperationDeadlineSubstitutesTheDefaultWriteDeadline(t *testing.T) {
	const substituted = defaultOperationTimeout + writeHeadroom

	// Exact equality, not "outlives it": an inequality is exactly how the existing test
	// for this line came to assert nothing. t.Errorf rather than t.Fatalf so one bad row
	// does not hide the others, or the end-to-end case below it.
	for _, operation := range []time.Duration{
		0,                 // an unset Options field
		-time.Second,      // unguarded: 29s, shorter than a default-length operation
		-writeHeadroom,    // unguarded: exactly 0s, which net/http reads as no deadline
		-45 * time.Second, // unguarded: -15s, same meaning, reached by going further negative
	} {
		if got := httpServerFor(New(nil), operation).WriteTimeout; got != substituted {
			t.Errorf("httpServerFor(handler, %s).WriteTimeout = %s, want %s (the default operation deadline "+
				"plus the write headroom): a non-positive configuration reached the arithmetic instead of "+
				"being replaced", operation, got, substituted)
		}
	}

	// THE SAME DEFECT THROUGH THE EXPORTED API, because httpServerFor is unexported and a
	// unit assertion on it only shows the helper agreeing with itself. Serve passes
	// OperationTimeout straight through, so -29s yields a 1s write deadline without the
	// substitution and 45s with it. A handler that runs 2s therefore either delivers its
	// response or has the connection cut under it — observed, unguarded, as
	// `Get "http://127.0.0.1:...": EOF`.
	t.Run("a negative deadline reaching Serve does not cut the response", func(t *testing.T) {
		const handlerRuntime = 2 * time.Second
		if testing.Short() {
			t.Skip("runs a 2s handler by construction: it must outlast the 1s write deadline the guard prevents")
		}

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		slow := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			time.Sleep(handlerRuntime)
			writer.WriteHeader(http.StatusNoContent)
		})
		cancel, done := startServe(t, listener, slow, Options{
			ShutdownTimeout:  2 * time.Second,
			OperationTimeout: -29 * time.Second,
		})

		client := &http.Client{Timeout: handlerRuntime + 15*time.Second, Transport: clientTransport(t)}
		response, err := client.Get(fmt.Sprintf("http://%s/", listener.Addr().String()))
		if err != nil {
			t.Fatalf("Serve(OperationTimeout: -29s) severed a %s handler's response: %v — the negative value "+
				"became a 1s write deadline instead of being replaced by the default",
				handlerRuntime, err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
		}

		cancel()
		if err := awaitServe(t, done, 5*time.Second); err != nil {
			t.Fatalf("Serve() error = %v, want nil after a clean shutdown", err)
		}
	})

	// ANCHOR, PLACED LAST BY DESIGN (TESTING.md §18). A positive deadline must still be
	// the value the write deadline is derived FROM. Without this, every assertion above
	// would be satisfied by an httpServerFor that returned 45s for every input, and a
	// substitution would be indistinguishable from a constant — which is the defect this
	// function was written to remove in the first place. Neither anchor value sums to the
	// substituted 45s, so the two answers cannot be confused.
	t.Run("ANCHOR a positive deadline is still what the write deadline derives from", func(t *testing.T) {
		for _, anchor := range []struct{ operation, want time.Duration }{
			{time.Second, time.Second + writeHeadroom},         // 31s
			{10 * time.Minute, 10*time.Minute + writeHeadroom}, // 10m30s, the config maximum
		} {
			if got := httpServerFor(New(nil), anchor.operation).WriteTimeout; got != anchor.want {
				t.Fatalf("httpServerFor(handler, %s).WriteTimeout = %s, want %s", anchor.operation, got, anchor.want)
			}
		}
	})
}
