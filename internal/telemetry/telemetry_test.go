package telemetry

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
)

var testNow = time.Date(2026, 9, 4, 18, 0, 0, 0, time.UTC)

// requestAs runs a request through the real authenticator with a client
// certificate for principal, exactly as the daemon serves it: no context
// injection, no bypass.
func requestAs(t *testing.T, handler http.Handler, principal, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if principal == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		identity, err := url.Parse(principal)
		if err != nil {
			t.Fatal(err)
		}
		certificate := &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
		}
		request = httptest.NewRequest(method, path, nil)
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	}
	recorder := httptest.NewRecorder()
	auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(handler).ServeHTTP(recorder, request)
	return recorder
}

func fullSources() Sources {
	return Sources{
		AuditShipping: func() (bool, int, time.Time, uint64) {
			return true, 2, testNow.Add(-90 * time.Second), 41
		},
		Fencing: func() (bool, bool, uint64, time.Time) {
			return true, true, 7, testNow.Add(-30 * time.Second)
		},
		Quarantined: func() map[string]string { return map[string]string{"hsm-sitea": "pin-budget-spent"} },
		PINRetries: func() map[string]PINReading {
			return map[string]PINReading{"hsm-sitea": {Retries: 3, At: testNow.Add(-60 * time.Second)}}
		},
		QuotaRejections: func() uint64 { return 5 },
		AuditVerify: func() (string, time.Time) {
			return "intact", testNow.Add(-20 * time.Second)
		},
		Readiness: func() server.ReadinessStats {
			return server.ReadinessStats{Ready: true, Transitions: 2, Evaluated: true, CheckedAt: testNow.Add(-10 * time.Second)}
		},
		Now: func() time.Time { return testNow },
	}
}

// THE METRICS ENDPOINT IS AN AUTHORIZED SURFACE, NOT AN AUTHENTICATED ONE.
//
// Aggregate per-route rates still reveal the business rhythm of what is being
// signed, so a valid workload certificate is not enough: the identity must be a
// configured reader. The failure mode of the opposite default is silent exposure.
func TestMetricsEndpointRequiresAConfiguredReader(t *testing.T) {
	handler := NewHandler(NewCollector([]string{"/v1/operations/sign"}), fullSources(), []string{"spiffe://regalia/operator/monitoring"})

	if got := requestAs(t, handler, "", http.MethodGet, Path).Code; got != http.StatusUnauthorized {
		t.Fatalf("no certificate = %d, want 401", got)
	}
	if got := requestAs(t, handler, "spiffe://regalia/workload/sops-prod", http.MethodGet, Path).Code; got != http.StatusForbidden {
		t.Fatalf("authenticated workload that is not a reader = %d, want 403: a valid cert is not a reading authorization", got)
	}
	if got := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodPost, Path).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", got)
	}
	response := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path)
	if response.Code != http.StatusOK {
		t.Fatalf("reader = %d, want 200", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("Content-Type = %q, want the Prometheus text format", contentType)
	}
	if !strings.Contains(response.Body.String(), "regalia_") {
		t.Fatal("authorized scrape returned no regalia series")
	}

	// An empty reader list is a complete refusal, not an open door.
	closed := NewHandler(NewCollector(nil), fullSources(), nil)
	if got := requestAs(t, closed, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Code; got != http.StatusForbidden {
		t.Fatalf("no readers configured = %d, want 403: the absent list must fail closed", got)
	}
}

// A CACHED VALUE WITHOUT ITS AGE READS AS CURRENT FOREVER.
//
// Each pull-based gauge is asserted with the timestamp or age that says how true it is right
// now. This is about VALUES and FRESHNESS, not completeness: the list below is written from
// memory rather than read from the contract, so a series missing from both the renderer and
// this list used to pass. Completeness against OBSERVABILITY.md belongs to
// TestEveryDocumentedSeriesIsActuallyEmitted in observability_closure_test.go.
func TestRenderedSeriesCarryTheirValueAndFreshness(t *testing.T) {
	handler := NewHandler(NewCollector([]string{"/v1/operations/sign"}), fullSources(), []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
	for _, expected := range []string{
		"regalia_audit_shipping_configured 1",
		"regalia_audit_backlog_events 2",
		"regalia_audit_oldest_unshipped_age_seconds 90",
		"regalia_audit_shipped_sequence 41",
		"regalia_fencing_lease_held 1",
		"regalia_fencing_lease_epoch 7",
		"regalia_fencing_last_check_seconds " + itoa(testNow.Add(-30*time.Second).Unix()),
		`regalia_backend_quarantined{device="hsm-sitea",reason="pin-budget-spent"} 1`,
		`regalia_token_pin_retries_remaining{device="hsm-sitea"} 3`,
		`regalia_token_pin_retries_updated_at_seconds{device="hsm-sitea"} ` + itoa(testNow.Add(-60*time.Second).Unix()),
		"regalia_policy_quota_rejections_total 5",
		`regalia_audit_verify_outcome{outcome="intact"} 1`,
		`regalia_audit_verify_outcome{outcome="chain-broken"} 0`,
		`regalia_audit_verify_outcome{outcome="unreadable"} 0`,
		"regalia_audit_verify_last_run_seconds " + itoa(testNow.Add(-20*time.Second).Unix()),
		"regalia_ready 1",
		"regalia_readiness_transitions_total 2",
		"regalia_readiness_last_check_seconds " + itoa(testNow.Add(-10*time.Second).Unix()),
		"regalia_http_router_decisions_total{decision=\"rejected\"} 0",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("scrape is missing %q", expected)
		}
	}
}

// A MISSING SOURCE MUST REMOVE THE SERIES, NOT REPORT A ZERO.
//
// A journal-only deployment has no shipping position; an unfenced site has no
// lease. Emitting zeros would make "not configured" indistinguishable from
// "healthy", which is the exact misreading the surface exists to prevent.
func TestAbsentSourcesOmitTheirSeries(t *testing.T) {
	handler := NewHandler(NewCollector(nil), Sources{Now: func() time.Time { return testNow }}, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
	for _, absent := range []string{
		"regalia_audit_dropped_records_total",
		"regalia_audit_verify_outcome",
		"regalia_audit_verify_last_run_seconds",
		"regalia_audit_backlog_events",
		"regalia_fencing_lease_held",
		"regalia_token_pin_retries_remaining",
		"regalia_ready",
	} {
		if strings.Contains(body, absent) {
			t.Fatalf("scrape contains %q for a source that does not exist: not-configured must not read as healthy-zero", absent)
		}
	}
	// Counters that DO exist start at zero and say so — a counter that only
	// appears on its first event cannot alert on the absence of traffic.
	if !strings.Contains(body, "regalia_http_unauthenticated_total 0") {
		t.Fatal("counters must be present from zero: an absent counter cannot be alerted on")
	}
}

// THE ROUTE LABEL SET IS CLOSED.
//
// The label's values come from the static path list, never from the request: a
// caller-controlled path must land in a fixed "unknown" bucket instead of minting
// a series per probe, or the endpoint becomes a cardinality-amplification toy.
func TestRouteLabelsNeverComeFromRequestData(t *testing.T) {
	collector := NewCollector([]string{"/v1/operations/sign"})
	stub := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	handler := collector.InstrumentOperations(stub)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/operations/definitely-not-real", nil))

	body := render(t, collector)
	if !strings.Contains(body, `regalia_http_requests_total{outcome="2xx",route="/v1/operations/sign"} 1`) {
		t.Fatalf("known route was not counted under its static label:\n%s", body)
	}
	if !strings.Contains(body, `regalia_http_requests_total{outcome="2xx",route="unknown"} 1`) {
		t.Fatalf("unknown path was not bucketed:\n%s", body)
	}
	if strings.Contains(body, "definitely-not-real") {
		t.Fatal("request-derived data reached a label value: the scrape is now an oracle")
	}
}

func render(t *testing.T, collector *Collector) string {
	t.Helper()
	handler := NewHandler(collector, Sources{Now: func() time.Time { return testNow }}, []string{"spiffe://regalia/operator/monitoring"})
	return requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
}

func itoa(value int64) string {
	return strconv.FormatInt(value, 10)
}

// THE SCRAPE COUNTS ITSELF.
//
// Through the real stack — authenticator, router, handler — a scrape must appear
// in its own output as a router decision. If it does not, either the route is not
// wired or the counter is not, and either way the surface is lying about traffic.
func TestFullStackScrapeCountsItsOwnRequest(t *testing.T) {
	collector := NewCollector([]string{"/v1/operations/sign"})
	stub := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	handler := server.Routes(stub, collector.InstrumentOperations(stub),
		NewHandler(collector, Sources{Now: func() time.Time { return testNow }}, []string{"spiffe://regalia/operator/monitoring"}), collector)

	// An operation and a rejected path, then the scrape that must report both.
	handler.ServeHTTP(httptest.NewRecorder(), authenticatedOperationRequest(t))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/operations/retired", nil))
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
	for _, expected := range []string{
		`regalia_http_router_decisions_total{decision="metrics"} 1`,
		`regalia_http_router_decisions_total{decision="operations"} 1`,
		`regalia_http_router_decisions_total{decision="rejected"} 1`,
		`regalia_http_requests_total{outcome="2xx",route="/v1/operations/sign"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("full-stack scrape is missing %q:\n%s", expected, body)
		}
	}
}

func authenticatedOperationRequest(t *testing.T) *http.Request {
	t.Helper()
	identity, err := url.Parse("spiffe://regalia/workload/sops-prod")
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return request
}

// A LEASE THAT HAS NEVER BEEN EVALUATED IS NOT A LEASE THAT WAS LOST.
//
// Standby.Snapshot returns ok=false until a gate has been acquired, so fencing already
// distinguishes the two; the metrics render discarded that flag and emitted
// regalia_fencing_lease_held 0 for both. That zero is byte-identical to a site that
// just lost the lease, so the alert on it fires on every start before the first
// evaluation — and an alert that fires on every restart is silenced, which is how a
// real lease loss goes unseen.
//
// The series is therefore absent until there is an answer, which is the rule
// TestAbsentSourcesOmitTheirSeries states for a source that is missing outright.
// regalia_fencing_evaluated stays present at 0, because an absent series on its own
// cannot be told apart from a scrape target that is down.
func TestUnevaluatedLeaseIsNotReportedAsLeaseLost(t *testing.T) {
	handler := NewHandler(NewCollector(nil), Sources{
		Now:     func() time.Time { return testNow },
		Fencing: func() (bool, bool, uint64, time.Time) { return false, false, 0, time.Time{} },
	}, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	if strings.Contains(body, "regalia_fencing_lease_held") {
		t.Error("a lease that has never been evaluated reported regalia_fencing_lease_held: " +
			"an alert on that gauge cannot tell never-evaluated from just-lost, so it pages on every start")
	}
	if strings.Contains(body, "regalia_fencing_lease_epoch") {
		t.Error("epoch 0 was reported for a lease that has never been evaluated: " +
			"indistinguishable from a site that has genuinely observed no epoch")
	}
	if !strings.Contains(body, "regalia_fencing_evaluated 0") {
		t.Error("regalia_fencing_evaluated must be present and 0 when the lease has never been " +
			"evaluated: an absent series alone cannot be told from a scrape target that is down")
	}
}

// The counterpart: once the lease HAS been evaluated, held=false is a real negative
// result and must be reported as one. Without this, omitting the series unconditionally
// would pass the test above and silently stop reporting genuine lease loss.
func TestEvaluatedButUnheldLeaseIsStillReported(t *testing.T) {
	handler := NewHandler(NewCollector(nil), Sources{
		Now:     func() time.Time { return testNow },
		Fencing: func() (bool, bool, uint64, time.Time) { return true, false, 4, testNow.Add(-time.Minute) },
	}, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	for _, expected := range []string{
		"regalia_fencing_evaluated 1",
		"regalia_fencing_lease_held 0",
		"regalia_fencing_lease_epoch 4",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("an evaluated lease that is not held must still report %q: this is the real "+
				"lease-loss signal and suppressing it would hide the condition the alert exists for", expected)
		}
	}
}

// EVERY REQUEST COUNTED MUST BE A REQUEST RENDERED.
//
// outcomeClass returns "other" for 3xx and for a status of 0 when nothing was written.
// The render loop iterated 2xx/4xx/5xx only, so those requests were counted into the
// map and then dropped from the scrape: the series did not sum to requests served, and
// an error rate computed from it had a quietly wrong denominator.
func TestEveryOutcomeClassCountedIsAlsoRendered(t *testing.T) {
	collector := NewCollector([]string{"/v1/operations/sign"})
	stub := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusFound) })
	collector.InstrumentOperations(stub).ServeHTTP(
		httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil))

	body := render(t, collector)
	expected := `regalia_http_requests_total{outcome="other",route="/v1/operations/sign"} 1`
	if !strings.Contains(body, expected) {
		t.Errorf("a 3xx response was counted and then dropped from the scrape: %q is missing, so "+
			"the per-route series does not sum to the requests actually served", expected)
	}
}

// AN OUTCOME OUTSIDE THE ENUM MUST NOT RENDER AS ALL-ZERO.
//
// A source returning an unrecognized outcome is a bug in the source — but
// rendering it as three zeroes suppresses both the chain-broken and unreadable
// alerts while last_run keeps ticking, so the failure mode is a system that looks
// verified and fresh while asserting nothing. That is the fencing gauge again:
// the unknown case gets its own alertable series.
func TestUnknownVerifyOutcomeRendersAsUnknown(t *testing.T) {
	sources := fullSources()
	sources.AuditVerify = func() (string, time.Time) { return "banana", testNow.Add(-20 * time.Second) }
	handler := NewHandler(NewCollector(nil), sources, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
	if !strings.Contains(body, `regalia_audit_verify_outcome{outcome="unknown"} 1`) {
		t.Fatalf("an outcome outside the enum rendered as all-zero — both real alerts suppressed while freshness ticks:\n%s", body)
	}
	for _, known := range []string{"intact", "chain-broken", "unreadable"} {
		if strings.Contains(body, fmt.Sprintf(`regalia_audit_verify_outcome{outcome=%q} 1`, known)) {
			t.Fatalf("outcome %q reported 1 for a source that said \"banana\"", known)
		}
	}
}

// #279. A failed audit write is invisible to every other series here: the recorder's sequence
// advances only after Write and Sync succeed, so a dropped record leaves no gap, the chain still
// verifies, and every other regalia_audit_* series describes events that REACHED the journal. This
// is the only one that moves when the sink is degraded, so what it renders is load-bearing.
func TestDroppedAuditRecordsRenderPerOutcome(t *testing.T) {
	handler := NewHandler(NewCollector(nil), Sources{
		Now: func() time.Time { return testNow },
		AuditDroppedRecords: func() map[string]uint64 {
			return map[string]uint64{"rbac-denied": 3, "policy-DENIED:approval": 1}
		},
	}, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	if !strings.Contains(body, "# TYPE regalia_audit_dropped_records_total counter") {
		t.Fatalf("a counter must be declared as one; a gauge would make increase() meaningless:\n%s", body)
	}
	for _, want := range []string{
		`regalia_audit_dropped_records_total{outcome="policy-DENIED:approval"} 1`,
		`regalia_audit_dropped_records_total{outcome="rbac-denied"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q — an operator cannot tell WHICH kind of record stopped being\n"+
				"written, which is the whole reason this carries a label:\n%s", want, body)
		}
	}
	// Deterministic order: a scrape that reshuffles between polls is a diff nobody can read.
	if strings.Index(body, `outcome="policy-DENIED:approval"`) > strings.Index(body, `outcome="rbac-denied"`) {
		t.Fatalf("series are not sorted by outcome:\n%s", body)
	}
}

// THE HEADER IS THE WIRING SIGNAL, and it is why this metric diverges from the zero-counter
// convention above. A labelled counter has no valid unlabelled zero series, so "nothing has been
// dropped" renders as a declaration with no samples. Without the declaration that state would be
// byte-identical to "the source was never wired" — and a metric whose entire purpose is to make an
// invisible loss visible must not itself be invisible when it has nothing to report.
func TestAWiredDropSourceDeclaresItselfWithNothingDropped(t *testing.T) {
	handler := NewHandler(NewCollector(nil), Sources{
		Now:                 func() time.Time { return testNow },
		AuditDroppedRecords: func() map[string]uint64 { return nil },
	}, []string{"spiffe://regalia/operator/monitoring"})
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	if !strings.Contains(body, "# TYPE regalia_audit_dropped_records_total counter") {
		t.Fatalf("a wired source with no drops did not declare the metric, so it is\n"+
			"indistinguishable from an unwired one:\n%s", body)
	}
	if strings.Contains(body, "regalia_audit_dropped_records_total{") {
		t.Fatalf("a series was emitted for an outcome nothing dropped:\n%s", body)
	}
}
