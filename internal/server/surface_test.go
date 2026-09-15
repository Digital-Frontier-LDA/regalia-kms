package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
)

// THE SPEC, THE ROUTER AND THE HANDLER MUST DESCRIBE ONE API.
//
// They described three. The handler recognised six operation paths. Routes forwarded three of them
// plus two prefixes, so certificate-sign, key-agreement and release-secret returned 404 before the
// handler ever saw them — three finished, tested, documented features unreachable over HTTP. The
// OpenAPI document meanwhile listed /v1/secrets/{secret_id}:release and
// /v1/objects/{object_id}/public-key, which nothing implements: a generated client would have been
// built against two endpoints that do not exist and would have missed three that do.
//
// Nothing caught it because every layer was tested against itself. The handler tests call the
// Handler directly and never traverse the router; the contract test validated the spec document
// against its own assertions and never against the server.
func TestSpecRouterAndHandlerDescribeTheSameAPI(t *testing.T) {
	specPaths := readSpecPaths(t)
	if len(specPaths) == 0 {
		t.Fatal("no paths were read from the OpenAPI document: this test would pass while checking nothing")
	}

	served := append([]string{"/v1/health/live", "/v1/health/ready", MetricsPath}, api.OperationPaths()...)
	sort.Strings(served)

	if strings.Join(specPaths, ",") != strings.Join(served, ",") {
		t.Fatalf("the published contract and the served surface disagree.\n  spec:   %v\n  served: %v\n"+
			"A path in the spec that nothing serves is an endpoint clients are told to call and cannot; "+
			"a path served but undocumented is unreviewed attack surface.", specPaths, served)
	}
}

// And every documented path must actually reach a handler through the router, not merely exist in
// the handler's own switch.
func TestEveryDocumentedPathIsReachableThroughTheRouter(t *testing.T) {
	var reached string
	operations := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = "operations"; w.WriteHeader(http.StatusOK) })
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = "health"; w.WriteHeader(http.StatusOK) })
	metrics := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = "metrics"; w.WriteHeader(http.StatusOK) })
	router := Routes(health, operations, metrics, nil)

	for _, path := range readSpecPaths(t) {
		reached = ""
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if recorder.Code == http.StatusNotFound || reached == "" {
			t.Errorf("%s is documented but the router answers %d without reaching any handler: the feature is unreachable over HTTP", path, recorder.Code)
		}
	}

	// And a path outside the documented surface must not be forwarded. The router used to prefix
	// match /v1/secrets/ and /v1/objects/, so anything under them reached the operations handler.
	for _, path := range []string{"/v1/secrets/anything", "/v1/objects/anything/else", "/v1/operations/", "/v1/operations/unknown"} {
		reached = ""
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s is not part of the API but the router forwarded it to the %s handler", path, reached)
		}
	}
}

func readSpecPaths(t *testing.T) []string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "api", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(document.Paths))
	for path := range document.Paths {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// THE ROUTER'S REJECTIONS ARE COUNTED WHERE THEY HAPPEN.
//
// For an hour during #72 the router 404'd three implemented operations while every
// handler-level counter stayed at zero, because the handler never ran. The only
// place "request arrived but nothing serves its path" exists is the router's
// default branch, so that is where the counter lives.
func TestRouterCountsItsOwnDecisions(t *testing.T) {
	decisions := make(map[string]int)
	var handlerCalls int
	counting := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { handlerCalls++; writer.WriteHeader(http.StatusOK) })
	handler := Routes(counting, counting, counting, RouteDecisionFunc(func(decision string) {
		decisions[decision]++
	}))

	for path, want := range map[string]string{
		"/v1/health/live":       DecisionHealth,
		"/v1/operations/sign":   DecisionOperations,
		MetricsPath:             DecisionMetrics,
		"/v1/operations/absent": DecisionRejected,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if want == DecisionRejected && response.Code != http.StatusNotFound {
			t.Fatalf("%s: rejected path answered %d, want 404", path, response.Code)
		}
	}
	for _, decision := range []string{DecisionHealth, DecisionOperations, DecisionMetrics, DecisionRejected} {
		if decisions[decision] != 1 {
			t.Fatalf("decision %q counted %d times, want 1: decisions = %v", decision, decisions[decision], decisions)
		}
	}
	if handlerCalls != 3 {
		t.Fatalf("handlers ran %d times, want 3: the rejected path must never reach a handler", handlerCalls)
	}
}
