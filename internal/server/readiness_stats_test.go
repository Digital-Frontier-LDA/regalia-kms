package server

import (
	"net/http"
	"testing"
)

// READINESS HAS A HISTORY, NOT JUST A PRESENT.
//
// A site that flapped fourteen times in an hour and happens to be ready at this
// instant looks identical to one that has been steady for a week — the /ready
// answer is point-in-time by design, so the transition count is the only place the
// flapping is visible. Each evaluation records its outcome; the counter moves only
// when the answer CHANGES.
func TestReadinessTransitionsAreCounted(t *testing.T) {
	probes := []*switchProbe{{}, {}, {}, {}}
	for _, probe := range probes {
		probe.ready.Store(true)
	}
	handler := NewRequired(Dependencies{Policy: probes[0], Registry: probes[1], Audit: probes[2], Token: probes[3]})

	if stats := handler.ReadinessStats(); stats.Evaluated {
		t.Fatal("readiness reported a history before any evaluation happened")
	}
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusOK {
		t.Fatalf("initial readiness = %d, want 200", got)
	}
	stats := handler.ReadinessStats()
	if !stats.Evaluated || !stats.Ready || stats.Transitions != 0 {
		t.Fatalf("after first ready evaluation stats = %+v, want ready:true 0 transitions", stats)
	}
	if stats.CheckedAt.IsZero() {
		t.Fatal("an evaluation with no timestamp: a stale readiness reading is indistinguishable from a fresh one")
	}

	probes[0].ready.Store(false)
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("readiness after probe loss = %d, want 503", got)
	}
	// Losing readiness twice in a row is ONE transition: the flap count must not
	// count evaluations, only changes.
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("readiness while still down = %d, want 503", got)
	}
	probes[0].ready.Store(true)
	if got := request(t, handler, http.MethodGet, "/v1/health/ready").Code; got != http.StatusOK {
		t.Fatalf("readiness after recovery = %d, want 200", got)
	}
	stats = handler.ReadinessStats()
	if !stats.Ready || stats.Transitions != 2 {
		t.Fatalf("stats = %+v, want ready:true with exactly 2 transitions (down, up)", stats)
	}
}
