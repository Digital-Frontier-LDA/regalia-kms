package integration_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// recordingHandler captures every slog record the request path emits. It records rather than failing
// inline so the failure can name what leaked, and so a leak on a background goroutine is still
// attributed to this test.
type recordingHandler struct {
	shared *recorded
	// Attributes carried by a handler obtained through With/WithGroup. slog attaches them to the
	// logger rather than to each record, so a handler that drops them would still FAIL correctly and
	// report a record with none of the identifying values on it -- and the values are the whole
	// point of the message. slog.Default().With("principal", p).Info("request") is the shape that
	// exposes this, and it is a likely shape for the logging this test exists to catch.
	prefix []string
}

type recorded struct {
	mu      sync.Mutex
	records []string
}

func newRecordingHandler() *recordingHandler { return &recordingHandler{shared: &recorded{}} }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := append([]string(nil), h.prefix...)
	record.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a.Key+"="+a.Value.String())
		return true
	})
	h.shared.mu.Lock()
	defer h.shared.mu.Unlock()
	h.shared.records = append(h.shared.records, strings.TrimSpace(record.Message+" "+strings.Join(attrs, " ")))
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	carried := append([]string(nil), h.prefix...)
	for _, a := range attrs {
		carried = append(carried, a.Key+"="+a.Value.String())
	}
	return &recordingHandler{shared: h.shared, prefix: carried}
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	return &recordingHandler{shared: h.shared, prefix: append(append([]string(nil), h.prefix...), name+"=")}
}

func (h *recordingHandler) seen() []string {
	h.shared.mu.Lock()
	defer h.shared.mu.Unlock()
	return append([]string(nil), h.shared.records...)
}

// THE REQUEST PATH LOGS NOTHING, AND THAT IS THE INVARIANT.
//
// #58 asked for a redaction test: capture the logger, drive the daemon, grep the buffer for a cert
// serial, a peer IP, a raw payload. That premise does not hold -- there is no logging in
// kms/internal at all, and the daemon's only log statements are eight slog calls in main.go at
// startup, emitting digests, a site name and config paths. A substring grep would have searched an
// empty buffer, and it is a weak instrument besides: a fixed list only catches leaks of those exact
// values on the paths a test happens to drive, so a later slog.Info("request", "principal", p)
// sails straight past it.
//
// So the invariant is inverted. The request path emits NOTHING, and this fails the moment that stops
// being true -- which is the moment a person should be deciding what may be logged, rather than a
// year later when the forbidden-substring list turns out not to have covered the new field.
//
// If you are reading this because you just tripped it: the bar is not "delete this test". It is
// "decide what this line may say about a request, redact the rest, and update this test on purpose".
// A principal, a certificate serial, an object id, a peer address and any payload byte are all
// identifying; a digest, a route and a decision are not.
func TestTheRequestPathEmitsNoLogs(t *testing.T) {
	captured := newRecordingHandler()
	previous := slog.Default()
	slog.SetDefault(slog.New(captured))
	t.Cleanup(func() { slog.SetDefault(previous) })

	// THE INSTRUMENT MUST BE ABLE TO SEE THE THING. A handler that fails on call proves nothing if
	// the code under test writes somewhere else, and "nothing was logged" is exactly what a
	// misinstalled handler reports. Prove it observes a log written the way the daemon writes one,
	// through the package-level logger, before trusting its silence.
	slog.Info("instrument check", "detail", "visible")
	if len(captured.seen()) != 1 {
		t.Fatalf("the recording handler did not observe a package-level slog.Info: it is not installed where the daemon logs, so its silence below would mean nothing")
	}
	captured.shared.mu.Lock()
	captured.shared.records = nil
	captured.shared.mu.Unlock()

	s := buildStack(t)

	// SCOPE THE ASSERTION TO REQUEST HANDLING. buildStack constructs the registry, policy engine,
	// audit recorder and issuer -- startup work, and startup is where this daemon's only logging
	// lives. Anything it emitted would otherwise be counted below as a request-path leak and named
	// as one, sending a reader to look for logging in a request path that never produced it. What
	// this test claims is about handling a request, so the buffer starts empty at the first one.
	if startup := captured.seen(); len(startup) != 0 {
		t.Logf("buildStack emitted %d startup record(s), which are not this test's subject: %s",
			len(startup), strings.Join(startup, "; "))
	}
	captured.shared.mu.Lock()
	captured.shared.records = nil
	captured.shared.mu.Unlock()

	// A success, a denial and a replay: the paths most likely to grow a log line.
	if code := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
		"e2e-ca", "e2e-pki", "1234567890abcdef", csrFor(t, "api.staging.internal")).Code; code != http.StatusOK {
		t.Fatalf("the control request did not succeed (status %d), so a silent log would prove nothing", code)
	}
	s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/stranger",
		"e2e-ca", "e2e-pki", "1234567890abcdee", csrFor(t, "api.staging.internal"))
	s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
		"e2e-ca", "e2e-pki", "1234567890abcdef", csrFor(t, "api.staging.internal"))

	if leaked := captured.seen(); len(leaked) != 0 {
		t.Fatalf("the request path emitted %d log record(s), and every request-scoped value the daemon holds is identifying -- principal, certificate serial, object id, peer address, payload:\n  %s\nIf this logging is deliberate, redact it and update this test on purpose rather than removing it.",
			len(leaked), strings.Join(leaked, "\n  "))
	}
}
