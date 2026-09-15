// Package telemetry exposes the KMS's operational state as one authenticated
// metrics endpoint. The daemon's important states — audit backlog, fencing lease,
// quarantined backends, PIN budget, readiness history — otherwise surface only as
// a 503 that says something is wrong and nothing about what.
//
// THE ORACLE RULE: label values come only from static configuration — route paths
// from the API contract, device ids from the custody manifest, fixed reason and
// outcome enums. Never from request data: a counter labelled by object id,
// principal or purpose would leak the shape of what is being signed and by whom to
// anyone who can scrape it. Cardinality is bounded by construction, and aggregate
// per-route rates still reveal business rhythm, which is why the endpoint requires
// a configured reader identity rather than mere authentication.
package telemetry

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
)

// Path is the one metrics route. It is server.MetricsPath, not a second constant
// holding the same string: the router matches on that one and this handler 404s
// anything that is not this one, so two copies means the route resolves and then
// answers 404. Stating it twice and asserting in both comments that it is stated
// once is how that drift starts.
const Path = server.MetricsPath

// PINReading is one token's last successful retry-count read and when it happened.
type PINReading struct {
	Retries int
	At      time.Time
}

// Sources are pull-based readers over live state, injected at wiring time so this
// package imports none of the packages it observes. A nil source omits its series
// entirely: "not configured" must never read as a healthy zero.
type Sources struct {
	// AuditShipping reports the shipper's position: configured, backlog depth,
	// the oldest unshipped event's timestamp, and the collector-acknowledged head.
	AuditShipping func() (configured bool, backlog int, oldestUnshipped time.Time, shippedSequence uint64)
	// Fencing reports the last lease evaluation: evaluated (a gate exists, so there has
	// been an evaluation to report), held,
	// the high-water epoch, and when the evaluation happened. Nil when unfenced.
	Fencing func() (evaluated, held bool, epoch uint64, checkedAt time.Time)
	// Quarantined enumerates latched devices with their first-latched reason.
	Quarantined func() map[string]string
	// PINRetries enumerates the last successful retry-count read per device.
	PINRetries func() map[string]PINReading
	// QuotaRejections counts limit-exceeded policy decisions.
	QuotaRejections func() uint64
	// Readiness reports the health handler's evaluation history.
	Readiness func() server.ReadinessStats
	// AuditDroppedRecords counts audit writes that FAILED, keyed by the outcome that was
	// lost. Nothing else in this file can see one: a failed record never advances the
	// recorder's sequence, so it leaves no gap, the chain still verifies, and every other
	// regalia_audit_* series describes events that reached the journal. This is the only
	// series that moves when the sink is degraded (#279).
	AuditDroppedRecords func() map[string]uint64
	// AuditVerify reports the periodic journal verification: the outcome (one of
	// intact, chain-broken, unreadable) and when it last ran. The daemon's
	// self-check is only meaningful if it is seen to keep asking.
	AuditVerify func() (outcome string, at time.Time)
	// Now supplies the clock for age gauges. Nil means time.Now.
	Now func() time.Time
}

// Collector accumulates the request counters. Gauges are pulled from Sources at
// render time; counters are pushed here by the router, the instrumented operations
// handler, and the authenticator, because those events exist only where they happen.
type Collector struct {
	mu              sync.Mutex
	routerDecisions map[string]uint64
	routeRequests   map[routeKey]uint64
	knownRoutes     map[string]struct{}
	unauthenticated uint64
}

type routeKey struct {
	route   string
	outcome string
}

func NewCollector(knownRoutes []string) *Collector {
	collector := &Collector{
		routerDecisions: make(map[string]uint64),
		routeRequests:   make(map[routeKey]uint64),
		knownRoutes:     make(map[string]struct{}, len(knownRoutes)),
	}
	for _, route := range knownRoutes {
		collector.knownRoutes[route] = struct{}{}
	}
	return collector
}

// RecordRouteDecision counts the router's decision. The rejected count is the
// #72 detector: traffic arriving for paths nothing serves, which handler-level
// counters can never see because the handler never runs.
func (collector *Collector) RecordRouteDecision(decision string) {
	collector.mu.Lock()
	collector.routerDecisions[decision]++
	collector.mu.Unlock()
}

// RecordUnauthenticated counts requests the authenticator rejected. Probing and
// expired-client-certificate outages are otherwise invisible until a caller
// complains.
func (collector *Collector) RecordUnauthenticated() {
	collector.mu.Lock()
	collector.unauthenticated++
	collector.mu.Unlock()
}

// InstrumentOperations counts one request per static route per outcome class. The
// route label comes from the known-paths set only: anything else is "unknown", so
// a caller can never mint series by choosing paths.
func (collector *Collector) InstrumentOperations(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		route := request.URL.Path
		if _, known := collector.knownRoutes[route]; !known {
			route = "unknown"
		}
		recorder := &statusRecorder{ResponseWriter: writer, status: http.StatusOK}
		next.ServeHTTP(recorder, request)
		collector.mu.Lock()
		collector.routeRequests[routeKey{route: route, outcome: outcomeClass(recorder.status)}]++
		collector.mu.Unlock()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (recorder *statusRecorder) WriteHeader(status int) {
	recorder.status = status
	recorder.ResponseWriter.WriteHeader(status)
}

func outcomeClass(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "other"
	}
}

type handler struct {
	collector *Collector
	sources   Sources
	readers   map[string]struct{}
}

// NewHandler serves the metrics endpoint. An empty readers list refuses everyone:
// metrics are authorized per identity, and the absent list fails closed.
func NewHandler(collector *Collector, sources Sources, readers []string) http.Handler {
	authorized := make(map[string]struct{}, len(readers))
	for _, reader := range readers {
		authorized[reader] = struct{}{}
	}
	return &handler{collector: collector, sources: sources, readers: authorized}
}

func (handler *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != Path {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := handler.readers[auth.Principal(request.Context())]; !ok {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = writer.Write([]byte(handler.render()))
}

func (handler *handler) render() string {
	now := time.Now().UTC()
	if handler.sources.Now != nil {
		now = handler.sources.Now().UTC()
	}
	var out strings.Builder

	writeHeader := func(name, help, kind string) {
		fmt.Fprintf(&out, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	gauge := func(name string, value any) { fmt.Fprintf(&out, "%s %v\n", name, value) }
	series := func(name, labels string, value any) { fmt.Fprintf(&out, "%s{%s} %v\n", name, labels, value) }

	if source := handler.sources.AuditShipping; source != nil {
		configured, backlog, oldest, shipped := source()
		writeHeader("regalia_audit_shipping_configured", "Whether off-host audit shipping is configured at all.", "gauge")
		if configured {
			gauge("regalia_audit_shipping_configured", 1)
			writeHeader("regalia_audit_backlog_events", "Recorded audit events the collector has not yet acknowledged.", "gauge")
			gauge("regalia_audit_backlog_events", backlog)
			writeHeader("regalia_audit_shipped_sequence", "Chain sequence the collector has acknowledged.", "gauge")
			gauge("regalia_audit_shipped_sequence", shipped)
			if backlog > 0 && !oldest.IsZero() {
				writeHeader("regalia_audit_oldest_unshipped_age_seconds", "Age of the oldest audit event the collector has not acknowledged.", "gauge")
				gauge("regalia_audit_oldest_unshipped_age_seconds", int64(now.Sub(oldest).Seconds()))
			}
		} else {
			gauge("regalia_audit_shipping_configured", 0)
		}
	}

	// NEVER EVALUATED IS NOT LEASE-LOST, AND THE GAUGE CANNOT SAY BOTH WITH A ZERO.
	//
	// Standby.Snapshot returns ok=false when no gate has ever been acquired, precisely so
	// that "never held the lease" stays distinguishable from "lost it"; fencing's own
	// snapshot_test.go asserts it. This render discarded that flag and emitted
	// lease_held 0 either way, which is byte-identical to a site that just lost the lease.
	// An alert on lease_held == 0 would therefore fire on every start before the first
	// evaluation, and an alert that fires on every restart gets silenced — which is how a
	// real lease loss goes unseen.
	//
	// So an unevaluated lease removes the series rather than zeroing it, which is the rule
	// TestAbsentSourcesOmitTheirSeries already states for a source that is absent entirely.
	// This is that same rule one level deeper: the source exists and has no answer yet.
	// regalia_fencing_evaluated stays present at 0 so the state is still alertable — an
	// absent series alone cannot be told from a scrape target that is down.
	if source := handler.sources.Fencing; source != nil {
		evaluated, held, epoch, checked := source()
		writeHeader("regalia_fencing_evaluated", "Whether the lease has been evaluated at least once.", "gauge")
		if !evaluated {
			gauge("regalia_fencing_evaluated", 0)
		} else {
			gauge("regalia_fencing_evaluated", 1)
			writeHeader("regalia_fencing_lease_held", "Whether this site currently holds the active lease.", "gauge")
			if held {
				gauge("regalia_fencing_lease_held", 1)
			} else {
				gauge("regalia_fencing_lease_held", 0)
			}
			writeHeader("regalia_fencing_lease_epoch", "Highest lease epoch this site has observed.", "gauge")
			gauge("regalia_fencing_lease_epoch", epoch)
			if !checked.IsZero() {
				writeHeader("regalia_fencing_last_check_seconds", "When the lease was last evaluated, as a Unix timestamp.", "gauge")
				gauge("regalia_fencing_last_check_seconds", checked.Unix())
			}
		}
	}

	if source := handler.sources.Quarantined; source != nil {
		quarantined := source()
		writeHeader("regalia_backend_quarantined", "Devices latched out of service, with the first reason.", "gauge")
		devices := make([]string, 0, len(quarantined))
		for device := range quarantined {
			devices = append(devices, device)
		}
		sort.Strings(devices)
		for _, device := range devices {
			series("regalia_backend_quarantined", fmt.Sprintf("device=%q,reason=%q", device, quarantined[device]), 1)
		}
	}

	if source := handler.sources.PINRetries; source != nil {
		readings := source()
		writeHeader("regalia_token_pin_retries_remaining", "Last measured PIN retries remaining per token.", "gauge")
		writeHeader("regalia_token_pin_retries_updated_at_seconds", "When the retry count was last measured, as a Unix timestamp.", "gauge")
		devices := make([]string, 0, len(readings))
		for device := range readings {
			devices = append(devices, device)
		}
		sort.Strings(devices)
		for _, device := range devices {
			reading := readings[device]
			series("regalia_token_pin_retries_remaining", fmt.Sprintf("device=%q", device), reading.Retries)
			series("regalia_token_pin_retries_updated_at_seconds", fmt.Sprintf("device=%q", device), reading.At.Unix())
		}
	}

	if source := handler.sources.QuotaRejections; source != nil {
		writeHeader("regalia_policy_quota_rejections_total", "Operations refused for exceeding a daily quota.", "counter")
		gauge("regalia_policy_quota_rejections_total", source())
	}

	if source := handler.sources.Readiness; source != nil {
		stats := source()
		if stats.Evaluated {
			writeHeader("regalia_ready", "Whether every required dependency was ready at the last evaluation.", "gauge")
			if stats.Ready {
				gauge("regalia_ready", 1)
			} else {
				gauge("regalia_ready", 0)
			}
			writeHeader("regalia_readiness_transitions_total", "Times the readiness answer changed.", "counter")
			gauge("regalia_readiness_transitions_total", stats.Transitions)
			writeHeader("regalia_readiness_last_check_seconds", "When readiness was last evaluated, as a Unix timestamp.", "gauge")
			gauge("regalia_readiness_last_check_seconds", stats.CheckedAt.Unix())
		}
	}

	if source := handler.sources.AuditDroppedRecords; source != nil {
		dropped := source()
		// The header is emitted even with nothing dropped, so a scrape distinguishes "wired,
		// no drops" from "not wired at all" -- which is the distinction this metric exists to
		// provide, and it would be self-defeating for the metric itself to lack it.
		writeHeader("regalia_audit_dropped_records_total",
			"Audit records whose write failed and never reached the journal, by the outcome lost.", "counter")
		outcomes := make([]string, 0, len(dropped))
		for outcome := range dropped {
			outcomes = append(outcomes, outcome)
		}
		sort.Strings(outcomes)
		for _, outcome := range outcomes {
			series("regalia_audit_dropped_records_total", fmt.Sprintf("outcome=%q", outcome), dropped[outcome])
		}
	}
	if source := handler.sources.AuditVerify; source != nil {
		outcome, at := source()
		writeHeader("regalia_audit_verify_outcome", "Outcome of the last journal self-verification, one-hot by result.", "gauge")
		// The outcome label is a closed enum, and an outcome outside it is a bug in
		// the source — but it must not render as three zeroes: that suppresses both
		// the chain-broken and unreadable alerts while last_run keeps ticking. The
		// unknown case gets its own series so it is alertable instead of silent.
		recognized := outcome == "intact" || outcome == "chain-broken" || outcome == "unreadable"
		for _, known := range []string{"intact", "chain-broken", "unreadable", "unknown"} {
			value := 0
			if outcome == known || (known == "unknown" && !recognized) {
				value = 1
			}
			series("regalia_audit_verify_outcome", fmt.Sprintf("outcome=%q", known), value)
		}
		if !at.IsZero() {
			writeHeader("regalia_audit_verify_last_run_seconds", "When the journal was last verified, as a Unix timestamp.", "gauge")
			gauge("regalia_audit_verify_last_run_seconds", at.Unix())
		}
	}

	collector := handler.collector
	collector.mu.Lock()
	decisions := make(map[string]uint64, len(collector.routerDecisions))
	for decision, count := range collector.routerDecisions {
		decisions[decision] = count
	}
	routes := make(map[routeKey]uint64, len(collector.routeRequests))
	for key, count := range collector.routeRequests {
		routes[key] = count
	}
	unauthenticated := collector.unauthenticated
	knownRoutes := make([]string, 0, len(collector.knownRoutes))
	for route := range collector.knownRoutes {
		knownRoutes = append(knownRoutes, route)
	}
	collector.mu.Unlock()
	sort.Strings(knownRoutes)

	writeHeader("regalia_http_router_decisions_total", "Requests by the router's decision: health, operations, metrics, or rejected.", "counter")
	for _, decision := range []string{"health", "operations", "metrics", "rejected"} {
		series("regalia_http_router_decisions_total", fmt.Sprintf("decision=%q", decision), decisions[decision])
	}
	writeHeader("regalia_http_requests_total", "Operation requests by static route and outcome class.", "counter")
	// "other" is rendered because outcomeClass can return it -- for 3xx, and for a status of
	// 0 when nothing was ever written. Iterating only 2xx/4xx/5xx counted those requests and
	// then dropped them, so the series never summed to requests served and any error-rate
	// expression built on it carried a quietly wrong denominator.
	for _, route := range append(knownRoutes, "unknown") {
		for _, outcome := range []string{"2xx", "4xx", "5xx", "other"} {
			series("regalia_http_requests_total", fmt.Sprintf("outcome=%q,route=%q", outcome, route), routes[routeKey{route: route, outcome: outcome}])
		}
	}
	writeHeader("regalia_http_unauthenticated_total", "Requests rejected by the authenticator before any routing.", "counter")
	gauge("regalia_http_unauthenticated_total", unauthenticated)

	return out.String()
}
