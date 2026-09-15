package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
)

// ReadinessProbe reports whether one required dependency can safely serve requests.
// It must not expose a reason through the public health response.
type ReadinessProbe interface {
	Ready(context.Context) bool
}

type Handler struct {
	probes []ReadinessProbe

	// now is the clock the readiness record is stamped from, the same seam
	// registry.clock, auth and operations.Coordinator already carry. New sets it to
	// time.Now; a test replaces it so an assertion about the stamp is about the value
	// that was recorded rather than about how fast the machine ran between two calls.
	now func() time.Time

	// Readiness history, recorded at each evaluation: the served answer is
	// point-in-time by design, so without this a flapping site is indistinguishable
	// from a steady one whenever someone looks.
	mu          sync.Mutex
	evaluated   bool
	lastReady   bool
	transitions uint64
	checkedAt   time.Time
}

// ReadinessStats is the observable history of the readiness answer. Evaluated is
// false until the first check, so "never checked" is distinguishable from "ready".
type ReadinessStats struct {
	Ready       bool
	Transitions uint64
	Evaluated   bool
	CheckedAt   time.Time
}

func (handler *Handler) ReadinessStats() ReadinessStats {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return ReadinessStats{
		Ready: handler.lastReady, Transitions: handler.transitions,
		Evaluated: handler.evaluated, CheckedAt: handler.checkedAt,
	}
}

// clock reads the injected clock, falling back to the wall clock. The fallback is not
// decoration: Handler's fields are all unexported, so `&server.Handler{}` from any package
// compiles, and today that zero value serves 503 rather than panicking. Without this guard
// adding the seam would turn the readiness endpoint of such a handler into a nil function
// call -- a health endpoint that crashes instead of answering, which is the class of defect
// this file exists to prevent. Same shape as registry.clock and telemetry's Sources.Now.
func (handler *Handler) clock() time.Time {
	if handler.now == nil {
		return time.Now().UTC()
	}
	return handler.now().UTC()
}

func (handler *Handler) noteReadiness(ready bool) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.evaluated && handler.lastReady != ready {
		handler.transitions++
	}
	// The clock is read UNDER the lock, where time.Now() was read before it. Hoisting it
	// out would let two concurrent evaluations stamp out of order, so the record could
	// move backwards -- and a readiness timestamp that goes backwards is the staleness
	// signal reporting a check that has not happened yet.
	handler.evaluated, handler.lastReady, handler.checkedAt = true, ready, handler.clock()
}

// MetricsPath is the metrics route, and is the single definition of it. The router
// matches on this and telemetry.Path is declared as this constant rather than as a
// second copy of the string -- the metrics handler 404s any path that is not its own,
// so two copies would mean the route resolves and then answers 404.
const MetricsPath = "/v1/metrics"

// Router decisions, counted where the decision is made. A handler-level counter
// can never see "rejected": the handler never runs.
const (
	DecisionHealth     = "health"
	DecisionOperations = "operations"
	DecisionMetrics    = "metrics"
	DecisionRejected   = "rejected"
)

// RouteDecisionRecorder counts how the router disposed of a request. It is an
// interface so the server package does not depend on the telemetry one.
type RouteDecisionRecorder interface {
	RecordRouteDecision(decision string)
}

// RouteDecisionFunc adapts a function to RouteDecisionRecorder.
type RouteDecisionFunc func(string)

func (f RouteDecisionFunc) RecordRouteDecision(decision string) { f(decision) }

// Routes keeps the public surface explicit. Health and cryptographic handlers
// cannot accidentally expose default-mux diagnostics.
// operationPath asks the API handler what it serves instead of restating it.
//
// Routes used to carry its own list — three exact paths plus prefix matches on /v1/secrets/ and
// /v1/objects/ — while the handler recognised six. The three it omitted (certificate-sign,
// key-agreement, release-secret) were implemented, documented in API.md, and unreachable: the
// router answered 404 before the handler ever saw them. The two prefixes forwarded paths the
// handler does not implement, so they 404'd one layer later instead.
//
// A second list is a second opinion. There is now one.
func operationPath(path string) bool {
	for _, served := range api.OperationPaths() {
		if path == served {
			return true
		}
	}
	return false
}

func Routes(health, operations, metrics http.Handler, recorder RouteDecisionRecorder) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/v1/health/live" || request.URL.Path == "/v1/health/ready":
			if recorder != nil {
				recorder.RecordRouteDecision(DecisionHealth)
			}
			health.ServeHTTP(writer, request)
		case request.URL.Path == MetricsPath:
			if recorder != nil {
				recorder.RecordRouteDecision(DecisionMetrics)
			}
			metrics.ServeHTTP(writer, request)
		case operationPath(request.URL.Path):
			if recorder != nil {
				recorder.RecordRouteDecision(DecisionOperations)
			}
			operations.ServeHTTP(writer, request)
		default:
			if recorder != nil {
				recorder.RecordRouteDecision(DecisionRejected)
			}
			http.NotFound(writer, request)
		}
	})
}

// Dependencies names every service required before cryptographic operations
// may be accepted. A nil or unavailable dependency fails readiness closed.
type Dependencies struct {
	Policy   ReadinessProbe
	Registry ReadinessProbe
	Audit    ReadinessProbe
	Token    ReadinessProbe
	// Fencing reports whether this site currently holds the active lease. A passive site is
	// healthy and NOT ready: it is running correctly and must not be sent work.
	Fencing ReadinessProbe
}

type allProbes struct{ probes []ReadinessProbe }

func (all allProbes) Ready(ctx context.Context) bool {
	if len(all.probes) == 0 {
		return false
	}
	for _, probe := range all.probes {
		// `probe == nil` IS NOT REDUNDANT, AND NO TEST CAN SHOW THAT IT IS NOT.
		//
		// Measured for #237, over the whole module: neutralising this operand alone leaves
		// `go test ./...` green — probeReady's recover catches the nil dereference and
		// answers false in its place, so the composition still refuses, by another route.
		// Neutralising this operand AND that recover together makes the same fixture,
		// TestRequireAllIsReadyOnlyWhenEveryProbeIs/a_single_nil_probe, panic with
		// "invalid memory address or nil pointer dereference".
		//
		// So deleting this line moves an unwired dependency off a compared value and onto
		// the panic path, and the suite cannot object. That is the reason to keep it, and
		// the reason the survivor is recorded here rather than closed with a test: a test
		// asserting the nil probe is refused passes either way.
		if probe == nil || !probeReady(ctx, probe) {
			return false
		}
	}
	return true
}

func RequireAll(probes ...ReadinessProbe) ReadinessProbe {
	return allProbes{probes: append([]ReadinessProbe(nil), probes...)}
}

// New returns the concrete handler rather than the interface: the readiness
// history lives on the handler, and an http.Handler return type would hide it
// from the metrics surface.
func New(probes []ReadinessProbe) *Handler {
	return &Handler{probes: append([]ReadinessProbe(nil), probes...), now: time.Now}
}

func NewRequired(dependencies Dependencies) *Handler {
	probes := []ReadinessProbe{
		dependencies.Policy,
		dependencies.Registry,
		dependencies.Audit,
		dependencies.Token,
	}
	// FENCING IS OPTIONAL, WHICH IS WHY IT NEEDS ITS OWN CASE.
	//
	// A nil probe fails readiness closed, which is right for Audit and Token — a host with no
	// hardware configured has nothing to serve. But an UNFENCED single-site deployment is a
	// supported configuration, not an unconfigured host, so folding a nil Fencing into the list
	// would make every one of them permanently unready.
	//
	// Appending it only when present is also the whole point of the field. It was added to
	// Dependencies and populated in main without being read here, so a passive site holding no
	// lease still reported READY: a load balancer would have kept sending it work that the fenced
	// runner could only refuse, and failover would have moved no traffic. The probe existed, the
	// readiness answer did not depend on it.
	if dependencies.Fencing != nil {
		probes = append(probes, dependencies.Fencing)
	}
	return New(probes)
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")

	switch request.URL.Path {
	case "/v1/health/live":
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeStatus(writer, http.StatusOK, "ok")
	case "/v1/health/ready":
		if request.Method != http.MethodGet {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !handler.ready(request.Context()) {
			writeStatus(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(writer, http.StatusOK, "ok")
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (handler *Handler) ready(ctx context.Context) bool {
	ready := len(handler.probes) > 0
	if ready {
		for _, probe := range handler.probes {
			// The same masked operand as in allProbes.Ready above, measured the same way
			// and for the same reason: neutralising `probe == nil` here leaves the whole
			// module green because probeReady's recover refuses in its place, and removing
			// both panics. See the note there before deciding this comparison is dead.
			if probe == nil || !probeReady(ctx, probe) {
				ready = false
				break
			}
		}
	}
	handler.noteReadiness(ready)
	return ready
}

func probeReady(ctx context.Context, probe ReadinessProbe) (ready bool) {
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return probe.Ready(ctx)
}

func writeStatus(writer http.ResponseWriter, status int, value string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(`{"status":"` + value + `"}` + "\n"))
}
