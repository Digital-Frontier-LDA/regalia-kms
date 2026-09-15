package audit

// #237 class sweep: every two-sided refusal bound in the tree (`x < lo || x > hi`) had each
// operand mutated separately. Nine exist; five had at least one untested side and TWO had
// NEITHER side tested. This is one of the two.
//
// NewHTTPSink's timeout window was entirely unpinned: `timeout < 100ms || timeout > 30s`
// could be deleted outright and the whole kms tree stayed green. Every existing caller in
// the package passes 1s or 2s — comfortably inside the window — so the guard was exercised
// only on its accepting path.
//
// A whole-guard mutation would have found this one, because neither side was covered. The
// per-operand pass is what finds the commoner case next door, where one side is tested and
// the other is not: three of the four bounds in internal/config were in that state, and
// which side was missing ALTERNATED between them, so all three "had a test".

import (
	"net/http"
	"testing"
	"time"
)

func TestTheCollectorTimeoutWindowIsRefusedAtBothEnds(t *testing.T) {
	const url = "https://audit.internal"

	for _, row := range []struct {
		name    string
		timeout time.Duration
	}{
		// One step outside each bound, so the guard under test is the only thing that can
		// object — the URL and client are the same ones the package's own passing tests use.
		{"below the floor", 100*time.Millisecond - time.Nanosecond},
		{"zero, the value a caller gets by forgetting the field", 0},
		{"negative", -time.Second},
		{"above the ceiling", 30*time.Second + time.Nanosecond},
		{"far above the ceiling", time.Hour},
	} {
		t.Run(row.name, func(t *testing.T) {
			sink, err := NewHTTPSink(url, &http.Client{}, row.timeout, "")
			if err == nil {
				t.Fatalf("a %v collector timeout was accepted (sink=%v) — a shipper that waits an hour on a dead collector stops shipping, and one that gives up in microseconds never ships at all", row.timeout, sink != nil)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18): a timeout inside the window is accepted, so none of
	// the rows above is satisfied by a constructor that refuses everything. Both boundary
	// values are included because an off-by-one in either direction would otherwise pass —
	// the rows above sit one nanosecond outside, and these sit exactly on the edge.
	for _, good := range []time.Duration{100 * time.Millisecond, time.Second, 30 * time.Second} {
		if _, err := NewHTTPSink(url, &http.Client{}, good, ""); err != nil {
			t.Fatalf("a %v timeout was refused (%v) — it is inside the documented window, and the rows above prove nothing if the constructor refuses every value", good, err)
		}
	}
}
