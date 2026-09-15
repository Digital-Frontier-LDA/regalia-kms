package audit

// The seven operands ledger_test.go carried as "unclassified" after the round-three sweep, plus
// two more found on the way: the Send twin of the CommittedHead site guard, and the outer
// comparison of the ship backoff, which the ledger had recorded as unreachable. Each was
// re-measured on 363ce16 before anything was written here, and each row below names the
// direction that survived.
//
// One of the seven is not here, because no test can reach it: audit.go:224[0] forced true only
// differs from the real guard on a stat error that is not "does not exist", and every such error
// is refused one call earlier by readMark. That guarantee is pinned where it is enforced, in
// TestAMarkWhoseFileCannotBeStattedIsRefusedByTheReadBeforeTheStat (§17, TESTING.md).

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

// THE DIAGNOSIS IS THE POINT OF THE SWITCH, not the refusal. When the collector acknowledged more
// than the high-water mark records, the mark file being absent means durability loss and the mark
// being present but behind means a forged sidecar. Both refuse, so a test asserting only that
// VerifyIntegrity failed passes whichever message an operator is handed. The absent reading is
// pinned in mark_required_test.go; this is the present one.
//
// Survived before this test: audit.go:301[0] forced true, which sends every case down the absent
// arm and tells the operator to look for disk loss while an attacker's edited sidecar sits there.
func TestAMarkBehindTheCollectorIsDiagnosedAsForgedRatherThanLost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recordOnly(t, path, 3)
	events, err := Verify(path)
	if err != nil || len(events) != 3 {
		t.Fatalf("fixture: %v (%d events)", err, len(events))
	}
	// The mark says the trail reached 1; the collector says it acknowledged 2. Both hashes are the
	// real ones, so only the ordering is wrong.
	if err := writeMark(path+highWaterSuffix, highWaterMark{Sequence: 1, Hash: events[0].Hash}); err != nil {
		t.Fatal(err)
	}
	if err := writeShippedMark(path, highWaterMark{Sequence: 2, Hash: events[1].Hash}); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyIntegrity(path)
	if err == nil {
		t.Fatal("a mark behind the collector's acknowledged head verified clean")
	}
	if !strings.Contains(err.Error(), "one of the audit sidecars was forged") || strings.Contains(err.Error(), "durability loss") {
		t.Fatalf("a present mark behind the collector was given the wrong diagnosis: %v", err)
	}
}

// AN EMPTY SITE IS NO SITE HEADER, ON BOTH CALLS. NewHTTPSink documents the empty site as the
// identity-keyed stream, and the collector contract keys a stream by identity "plus the
// X-Regalia-Site header when present". Send and CommittedHead must address the same stream, so
// they must agree on present versus absent: a header sent empty on one and omitted on the other is
// two streams to any collector that tells the difference. This repository's collector reads both as
// "" and so cannot catch it, which is why the assertion is on the request.
//
// Survived before this test: httpsink.go:95[0] (Send) and httpsink.go:127[0] (CommittedHead),
// each forced true, sending "X-Regalia-Site: " with an empty value.
func TestAnEmptySiteSendsNoSiteHeaderOnEitherCall(t *testing.T) {
	for _, site := range []string{"", "sitea"} {
		seen := map[string][]string{}
		client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			values, present := request.Header["X-Regalia-Site"]
			if present {
				seen[request.URL.Path] = values
			} else {
				seen[request.URL.Path] = nil
			}
			if request.URL.Path == "/v1/events" {
				return &http.Response{StatusCode: http.StatusNoContent, Header: http.Header{"X-Regalia-Audit-Hash": []string{chainedHash}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"sequence":0,"hash":""}`))}, nil
		})}
		sink, err := NewHTTPSink("https://audit.internal", client, time.Second, site)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Send(context.Background(), Event{Sequence: 1, Hash: chainedHash}); err != nil {
			t.Fatalf("site %q: Send: %v", site, err)
		}
		if _, _, err := sink.CommittedHead(context.Background(), site); err != nil {
			t.Fatalf("site %q: CommittedHead: %v", site, err)
		}
		for _, call := range []string{"/v1/events", "/v1/stream-position"} {
			values, reached := seen[call]
			if !reached {
				t.Fatalf("site %q: %s was never requested, so nothing below was checked", site, call)
			}
			switch {
			case site == "" && values != nil:
				t.Errorf("an empty site sent X-Regalia-Site %q on %s: the empty site is no header, or Send and CommittedHead can address different streams", values, call)
			case site != "" && (len(values) != 1 || values[0] != site):
				t.Errorf("site %q travelled as %q on %s", site, values, call)
			}
		}
	}
}

// A RECORDER THAT HAS WRITTEN NOTHING VERIFIES AS INTACT, AND THE RUN RETURNS. The periodic
// verifier starts with the recorder, so on every fresh site its first run reads an empty journal.
//
// Survived before this test: verifier.go:93[0] forced true, which reads the head of an empty slice
// and panics the verifier.
func TestVerifyingARecorderThatHasWrittenNothingIsIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	var state VerifyState
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("verifying an empty journal panicked: %v", recovered)
			}
		}()
		state = recorder.VerifyNow(context.Background())
	}()
	if state.Outcome != VerifyIntact || state.Events != 0 {
		t.Fatalf("an empty journal verified as %q with %d events, want intact with 0", state.Outcome, state.Events)
	}
}

// THE BACKOFF DOUBLES, AND THE CAP PULLS AN OVERSHOOT BACK. Both halves survived because the only
// way to see either through the shipper is to fail it for a minute on real timers.
//
// Survived before this test: the outer comparison forced false (formerly shipper.go:181[0]), which
// retries a failing collector every 100ms forever; and the cap forced false (formerly
// shipper.go:183[0]), which settles at 51.2s instead of 30s. The outer comparison forced true is
// not in this list because it cannot be told apart: doubling the maximum is capped straight back.
func TestShipBackoffDoublesAndIsHeldAtItsMaximum(t *testing.T) {
	// Doubling is what stops a down collector being hammered: without it, every failed attempt
	// waits minShipBackoff again and the shipper retries every 100ms for as long as the outage lasts.
	for _, backoff := range []time.Duration{minShipBackoff, 2 * minShipBackoff, maxShipBackoff / 2} {
		if got := nextShipBackoff(backoff); got != 2*backoff {
			t.Fatalf("after a failure at %v the next wait is %v, want %v: a backoff that does not double retries a down collector at a fixed rate for as long as it is down", backoff, got, 2*backoff)
		}
	}
	backoff, steps := minShipBackoff, 0
	for backoff < maxShipBackoff {
		next := nextShipBackoff(backoff)
		if next > maxShipBackoff {
			t.Fatalf("the backoff went from %v to %v, past its maximum %v: an uncapped overshoot leaves a recovered collector unvisited for that long after every outage", backoff, next, maxShipBackoff)
		}
		if next <= backoff {
			t.Fatalf("the backoff went from %v to %v and stopped growing below its maximum", backoff, next)
		}
		backoff, steps = next, steps+1
	}
	// 100ms doubles to 25.6s in eight steps; the ninth doubling overshoots to 51.2s and is capped.
	if steps != 9 || backoff != maxShipBackoff {
		t.Fatalf("reached %v in %d steps, want %v in 9", backoff, steps, maxShipBackoff)
	}
	if got := nextShipBackoff(maxShipBackoff); got != maxShipBackoff {
		t.Fatalf("at its maximum the backoff moved to %v", got)
	}
}

// §17: THE STAT CLASSIFICATION'S FIRST OPERAND CANNOT BE REACHED ON THE WRONG SIDE.
//
// audit.go:224[0], `case errors.Is(statErr, os.ErrNotExist):`, is false on the wrong side only for
// a stat error that is not ENOENT, and it survives forced true because no such error arrives:
// readMark read the same path one call earlier, and it refuses every read failure except
// not-existing. Reaching the operand would need the path's stat class to change between those two
// calls, which unreadable_mark_test.go records for the second classification too.
//
// So the guarantee is pinned here, where it is enforced, with the two stat failures a fixture can
// build without mode bits (a root runner ignores those): a symlink loop at the mark's path, and a
// journal name whose mark name is longer than the filesystem allows. Each must be refused by the
// read. If readMark ever relaxes, these fail by message, and the classification's default arm is
// what catches them next.
func TestAMarkWhoseFileCannotBeStattedIsRefusedByTheReadBeforeTheStat(t *testing.T) {
	t.Run("symlink loop at the mark", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordOnly(t, path, 1)
		mark := path + highWaterSuffix
		if err := os.Remove(mark); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(mark+".loop", mark); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(mark, mark+".loop"); err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(mark); statErr == nil || os.IsNotExist(statErr) {
			t.Fatalf("fixture: the mark must fail to stat with something other than not-exist, got %v", statErr)
		}
		_, err := VerifyIntegrity(path)
		if err == nil || !strings.Contains(err.Error(), "read audit mark") {
			t.Fatalf("a mark in a symlink loop was not refused by the read: %v", err)
		}
	})
	t.Run("mark name longer than the filesystem allows", func(t *testing.T) {
		dir := t.TempDir()
		short := filepath.Join(dir, "audit.jsonl")
		recordOnly(t, short, 1)
		// 250 bytes is a legal file name; with ".high-water" appended the mark's is not.
		long := filepath.Join(dir, strings.Repeat("a", 250))
		if err := os.Rename(short, long); err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(long + highWaterSuffix); statErr == nil || os.IsNotExist(statErr) {
			t.Fatalf("fixture: the mark must fail to stat with something other than not-exist, got %v", statErr)
		}
		_, err := VerifyIntegrity(long)
		if err == nil || !strings.Contains(err.Error(), "read audit mark") {
			t.Fatalf("a mark whose name is too long was not refused by the read: %v", err)
		}
	})
}
