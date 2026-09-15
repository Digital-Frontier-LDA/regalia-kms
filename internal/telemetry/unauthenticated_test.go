package telemetry

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// `RegaliaUnauthenticatedProbing` alerts on sustained 401s, and the whole chain behind it is:
// the authenticator rejects → its OnUnauthorized callback runs → this collector increments →
// the counter is scraped. `internal/auth` tests the first two links; this file tested only that
// the counter starts at ZERO.
//
// So RecordUnauthenticated could have been an empty function and every test in this repository
// would still have passed — the auth test counts with its own closure, and the scrape test asserts
// the value is 0. An alert whose metric never moves is the "appears to be watched" failure that
// `regalia_http_unauthenticated_total` exists to prevent, pointed at itself.

const monitoringReader = "spiffe://regalia/operator/monitoring"

func scrapeBody(t *testing.T, handler http.Handler) string {
	t.Helper()
	return requestAs(t, handler, monitoringReader, http.MethodGet, Path).Body.String()
}

func TestTheUnauthenticatedCounterActuallyMoves(t *testing.T) {
	collector := NewCollector(nil)
	handler := NewHandler(collector, Sources{Now: func() time.Time { return testNow }}, []string{monitoringReader})

	if !strings.Contains(scrapeBody(t, handler), "regalia_http_unauthenticated_total 0") {
		t.Fatal("the counter does not start at zero, so the increments below cannot be attributed")
	}
	for count := 1; count <= 3; count++ {
		collector.RecordUnauthenticated()
		want := fmt.Sprintf("regalia_http_unauthenticated_total %d", count)
		if !strings.Contains(scrapeBody(t, handler), want) {
			t.Fatalf("after %d rejections the scrape does not contain %q: the alert on sustained 401s can never fire", count, want)
		}
	}
}

// TestConcurrentRejectionsAreAllCounted. Rejections arrive from every connection at once, and a
// lost increment under load is exactly when probing looks like noise. The counter is mutex-guarded;
// this is what says so, and `go test -race` is what makes it mean something.
func TestConcurrentRejectionsAreAllCounted(t *testing.T) {
	collector := NewCollector(nil)
	handler := NewHandler(collector, Sources{Now: func() time.Time { return testNow }}, []string{monitoringReader})

	const workers, each = 8, 50
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for i := 0; i < each; i++ {
				collector.RecordUnauthenticated()
			}
		}()
	}
	group.Wait()

	want := fmt.Sprintf("regalia_http_unauthenticated_total %d", workers*each)
	if !strings.Contains(scrapeBody(t, handler), want) {
		t.Fatalf("scrape does not contain %q after %d concurrent rejections: increments were lost, and a probe that arrives fast enough undercounts itself",
			want, workers*each)
	}
}

// TestTheOutcomeClassBucketsCoverEveryStatus. The class is a metric LABEL, so a status falling
// outside the named ranges must land in "other" rather than minting a bucket or vanishing —
// `RegaliaOperationErrors` alerts on `outcome="5xx"`, and a 5xx counted as anything else is an
// error nobody is told about.
func TestTheOutcomeClassBucketsCoverEveryStatus(t *testing.T) {
	for _, test := range []struct {
		status int
		want   string
	}{
		{200, "2xx"}, {204, "2xx"}, {299, "2xx"},
		{400, "4xx"}, {429, "4xx"}, {499, "4xx"},
		{500, "5xx"}, {503, "5xx"}, {599, "5xx"},
		// The boundaries either side of the named ranges, and the redirects between them. A 3xx
		// from this API would itself be a defect, but it must be visible as "other" rather than
		// silently joining a neighbouring bucket.
		{100, "other"}, {199, "other"},
		{300, "other"}, {301, "other"}, {399, "other"},
		{600, "other"}, {0, "other"},
	} {
		t.Run(fmt.Sprintf("%d", test.status), func(t *testing.T) {
			if got := outcomeClass(test.status); got != test.want {
				t.Fatalf("outcomeClass(%d) = %q, want %q", test.status, got, test.want)
			}
		})
	}
}
