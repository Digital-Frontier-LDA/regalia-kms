package audit

// COLLECTOR RECONCILIATION (#220 rows 2/4): the matrix, with real Recorder journals and a
// scripted collector. Each refusal must fire for its own reason — the messages are the
// contract, and a rule that refuses everything would pass every negative row.

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingCollector struct {
	sequence uint64
	hash     string
}

func (collector *recordingCollector) Send(context.Context, Event) error { return nil }
func (collector *recordingCollector) Ready(context.Context) bool        { return true }
func (collector *recordingCollector) CommittedHead(context.Context, string) (uint64, string, error) {
	return collector.sequence, collector.hash, nil
}

type plainSink struct{}

func (plainSink) Send(context.Context, Event) error { return nil }
func (plainSink) Ready(context.Context) bool        { return true }

func reconcileJournal(t *testing.T, events int) (string, []Event) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < events; i++ {
		draft := Draft{
			Timestamp: time.Date(2026, 9, 6, 12, 0, i, 0, time.UTC),
			RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			Principal: "p", Decision: "allow", ObjectID: "o", Purpose: "pu",
			Operation: "op", DeviceID: "d", Outcome: "ok",
			RegistryDigest: "aa" + strings.Repeat("bb", 31),
			PolicyDigest:   "cc" + strings.Repeat("dd", 31),
			RBACDigest:     "ee" + strings.Repeat("ff", 31),
		}
		if err := recorder.Record(context.Background(), draft, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	// The REAL chain values, read back. The first version of this helper recomputed the
	// hashes from the drafts — without the PreviousHash linkage — so the "continuity" row
	// quoted invented hashes and failed against the genuine journal; a fixture that
	// restates the chain construction can only agree with itself.
	written, err := Verify(path)
	if err != nil {
		t.Fatalf("fixture journal does not verify: %v", err)
	}
	return path, written
}

// writeShippedMarkForTest writes the collector-acknowledged mark the way the shipper does.
// The first version called writeAuditHighWater(path+shippedSuffix, …) — which appends the
// high-water suffix itself, so the mark landed at .shipped.high-water and nobody read it;
// the ahead-row then failed through the mismatch branch for a reason that had nothing to do
// with the rule under test.
func writeShippedMarkForTest(path string, sequence uint64) error {
	return writeShippedMark(path, highWaterMark{Sequence: sequence, Hash: "sha256:" + strings.Repeat("0", 64)})
}

func TestHTTPSinkCommittedHeadTalksToTheWire(t *testing.T) {
	var gotSite string
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		gotSite = request.Header.Get("X-Regalia-Site")
		if request.URL.Path != "/v1/stream-position" || request.Method != http.MethodGet {
			return &http.Response{StatusCode: http.StatusNotFound, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sequence":7,"hash":"sha256:` + strings.Repeat("ab", 32) + `"}`))}, nil
	})}
	sink, err := NewHTTPSink("https://collector.test", client, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	sequence, hash, err := sink.CommittedHead(context.Background(), "sitea")
	if err != nil || sequence != 7 || !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("CommittedHead round trip failed: seq=%d hash=%s err=%v", sequence, hash, err)
	}
	if gotSite != "sitea" {
		t.Fatalf("the site header did not travel: %q", gotSite)
	}
	// A non-200 is an error, never a zero — a collector answering 404 must not read as
	// "holds nothing", which would pass every host as a fresh stream.
	failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	failingSink, err := NewHTTPSink("https://collector.test", failing, time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := failingSink.CommittedHead(context.Background(), "sitea"); err == nil {
		t.Fatal("a failing collector answered as a zero position — 'holds nothing' and 'cannot answer' must not be the same state")
	}
}

func TestReconcileContinuity(t *testing.T) {
	t.Run("fresh stream: empty journal, collector holds nothing", func(t *testing.T) {
		path, _ := reconcileJournal(t, 0)
		collector := &recordingCollector{}
		if err := ReconcileContinuity(context.Background(), path, collector, "sitea"); err != nil {
			t.Fatalf("a fresh stream was refused: %v", err)
		}
	})
	t.Run("continuity: collector head matches the journal's event", func(t *testing.T) {
		path, written := reconcileJournal(t, 5)
		collector := &recordingCollector{sequence: 3, hash: written[2].Hash}
		if err := ReconcileContinuity(context.Background(), path, collector, "sitea"); err != nil {
			t.Fatalf("demonstrated continuity was refused: %v", err)
		}
	})
	t.Run("row 2: journal rewritten, collector remembers the real hash", func(t *testing.T) {
		path, _ := reconcileJournal(t, 5)
		collector := &recordingCollector{sequence: 3, hash: "sha256:" + strings.Repeat("c0ffee", 10) + "c0f"}
		err := ReconcileContinuity(context.Background(), path, collector, "sitea")
		if err == nil || !strings.Contains(err.Error(), "does not match what this site already shipped") {
			t.Fatalf("a rewritten journal passed reconciliation (err=%v) — rows 2 and 4 are the attacks this exists for", err)
		}
	})
	t.Run("row 4: the PERFECT forgery — truncated journal, both marks rewritten consistently", func(t *testing.T) {
		// The full row-4 attacker: truncate to 2 events, then rewrite .high-water AND
		// .shipped to match the shortened journal using the truncated chain's real hashes,
		// so every on-host rule — #223's marks, the chain, the shipped cross-check — passes.
		// Only the collector's committed head disagrees, and it must be the refusal.
		// (A sloppier forgery — invented hashes in the marks — is caught earlier by
		// VerifyIntegrity's own cross-checks, red by the wrong detector for this row.)
		path, written := reconcileJournal(t, 5)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(data), "\n")
		if err := os.WriteFile(path, []byte(strings.Join(lines[:2], "")), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := writeAuditHighWater(path, highWaterMark{Sequence: 2, Hash: written[1].Hash}); err != nil {
			t.Fatal(err)
		}
		if err := writeShippedMark(path, highWaterMark{Sequence: 2, Hash: written[1].Hash}); err != nil {
			t.Fatal(err)
		}
		collector := &recordingCollector{sequence: 3, hash: written[2].Hash}
		err = ReconcileContinuity(context.Background(), path, collector, "sitea")
		if err == nil || !strings.Contains(err.Error(), "less history than it already shipped") {
			t.Fatalf("a locally-perfect forgery passed reconciliation (err=%v) — the collector's head is the only remaining witness", err)
		}
	})
	t.Run("host holds less than it shipped", func(t *testing.T) {
		path, _ := reconcileJournal(t, 2)
		collector := &recordingCollector{sequence: 9, hash: "sha256:" + strings.Repeat("ab", 32)}
		err := ReconcileContinuity(context.Background(), path, collector, "sitea")
		if err == nil || !strings.Contains(err.Error(), "less history than it already shipped") {
			t.Fatalf("a journal behind the collector passed (err=%v)", err)
		}
	})
	t.Run("local mark ahead of the collector is impossible without forgery", func(t *testing.T) {
		// The mark must carry the journal's REAL event-5 hash: an invented hash is caught
		// by VerifyIntegrity's shipped cross-check before this rule ever runs — red by the
		// wrong detector. A competent forger quotes the true hash; only the position
		// relative to the collector gives them away.
		path, written := reconcileJournal(t, 5)
		// The recorder's real .high-water (5) is left untouched: a competent forger keeps
		// the sidecars mutually consistent, and forging it BELOW the shipped mark merely
		// trips the existing cross-check — red by the wrong detector. Only .shipped moves.
		if err := writeShippedMark(path, highWaterMark{Sequence: 5, Hash: written[4].Hash}); err != nil {
			t.Fatal(err)
		}
		collector := &recordingCollector{sequence: 3, hash: written[2].Hash}
		err := ReconcileContinuity(context.Background(), path, collector, "sitea")
		if err == nil || !strings.Contains(err.Error(), "ahead of the collector") {
			t.Fatalf("a shipped mark ahead of the collector passed (err=%v)", err)
		}
	})
	t.Run("collector forgot a shipped stream", func(t *testing.T) {
		path, _ := reconcileJournal(t, 5)
		collector := &recordingCollector{sequence: 0}
		err := ReconcileContinuity(context.Background(), path, collector, "sitea")
		if err == nil || !strings.Contains(err.Error(), "off-host memory forgot") {
			t.Fatalf("a collector with amnesia passed (err=%v) — its memory must be durable", err)
		}
	})
	t.Run("a sink without a position has no memory to reconcile", func(t *testing.T) {
		path, _ := reconcileJournal(t, 1)
		err := ReconcileContinuity(context.Background(), path, plainSink{}, "sitea")
		if err == nil || !strings.Contains(err.Error(), "cannot report its committed position") {
			t.Fatalf("a positionless sink was silently accepted (err=%v)", err)
		}
	})
	t.Run("journal-only host reconciles nothing and returns nil", func(t *testing.T) {
		path, _ := reconcileJournal(t, 1)
		if err := ReconcileContinuity(context.Background(), path, nil, "sitea"); err != nil {
			t.Fatalf("a journal-only host was refused: %v", err)
		}
	})
}

func TestCommittedHeadRefusesShapesTheCollectorCannotEmit(t *testing.T) {
	// The head is authoritative in reconciliation — the one value the host cannot author —
	// so the sink must not hand the reconciler a shape its own source would never produce.
	// "Holds nothing" (0,""), a position (N, hash), and "answered something impossible"
	// are three states; the third refuses like the others (#234 review).
	for name, body := range map[string]string{
		"sequence without a hash":  `{"sequence":5,"hash":""}`,
		"hash without a sequence":  `{"sequence":0,"hash":"sha256:` + strings.Repeat("ab", 32) + `"}`,
		"trailing second document": `{"sequence":5,"hash":"sha256:` + strings.Repeat("ab", 32) + `"}{"sequence":9}`,
		// A position whose hash is present but is not a chained hash. The coupling above is
		// satisfied, so only the pattern check refuses it (httpsink.go:165[1] and [2], each forced
		// false, survived until this row).
		"a hash that is not a chained hash": `{"sequence":5,"hash":"sha256:` + strings.Repeat("AB", 32) + `"}`,
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		sink, err := NewHTTPSink("https://collector.test", client, time.Second, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := sink.CommittedHead(context.Background(), "sitea"); err == nil {
			t.Fatalf("%s was accepted as a committed head — an impossible shape in the one authoritative value", name)
		}
	}
}

func repeatFor(unit string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += unit
	}
	return out
}
