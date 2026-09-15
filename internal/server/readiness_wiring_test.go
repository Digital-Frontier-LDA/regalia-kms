package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type readyProbe bool

func (r readyProbe) Ready(context.Context) bool { return bool(r) }

// A READINESS ENDPOINT THAT CAN NEVER BE TRUE IS NOT FAIL-CLOSED, IT IS UNINFORMATIVE.
//
// NewRequired always passes four probes and treats a nil one as not-ready. The daemon left Audit
// and Token nil, so /v1/health/ready returned 503 on a fully configured host that could in fact
// serve — and nothing could distinguish "not configured yet" from "broken right now".
//
// This pins both directions: every dependency present means ready, and any one absent or nil does
// not.
func TestReadinessRequiresEveryDependencyAndIsAchievable(t *testing.T) {
	all := Dependencies{
		Policy: readyProbe(true), Registry: readyProbe(true),
		Audit: readyProbe(true), Token: readyProbe(true),
	}
	if status := probe(t, NewRequired(all)); status != http.StatusOK {
		t.Fatalf("fully configured readiness = %d, want 200 — readiness must be achievable", status)
	}

	// Each dependency, individually unready.
	for name, mutate := range map[string]func(*Dependencies){
		"policy":   func(d *Dependencies) { d.Policy = readyProbe(false) },
		"registry": func(d *Dependencies) { d.Registry = readyProbe(false) },
		"audit":    func(d *Dependencies) { d.Audit = readyProbe(false) },
		"token":    func(d *Dependencies) { d.Token = readyProbe(false) },
	} {
		t.Run(name+" unready", func(t *testing.T) {
			dependencies := all
			mutate(&dependencies)
			if status := probe(t, NewRequired(dependencies)); status != http.StatusServiceUnavailable {
				t.Fatalf("readiness = %d with %s unready, want 503", status, name)
			}
		})
	}

	// Each dependency, individually absent. An unconfigured dependency is not a satisfied one.
	for name, mutate := range map[string]func(*Dependencies){
		"policy":   func(d *Dependencies) { d.Policy = nil },
		"registry": func(d *Dependencies) { d.Registry = nil },
		"audit":    func(d *Dependencies) { d.Audit = nil },
		"token":    func(d *Dependencies) { d.Token = nil },
	} {
		t.Run(name+" absent", func(t *testing.T) {
			dependencies := all
			mutate(&dependencies)
			if status := probe(t, NewRequired(dependencies)); status != http.StatusServiceUnavailable {
				t.Fatalf("readiness = %d with %s absent, want 503", status, name)
			}
		})
	}
}

func probe(t *testing.T, handler http.Handler) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

// THE FENCING PROBE MUST ACTUALLY DECIDE READINESS.
//
// Dependencies gained a Fencing field and main populated it, but NewRequired never read it — so a
// passive site holding no lease answered /v1/health/ready with 200. A load balancer would have kept
// routing signing traffic to a site whose fenced runner could only refuse it, and a failover would
// have moved no traffic at all. The probe existed; the answer did not depend on it.
func TestReadinessDependsOnTheFencingProbeWhenItIsConfigured(t *testing.T) {
	ready := probeFunc(func(context.Context) bool { return true })
	base := Dependencies{Policy: ready, Registry: ready, Audit: ready, Token: ready}

	// Unfenced: a single-site deployment must stay ready. A nil Fencing must not fail it closed.
	if status := readyStatus(t, NewRequired(base)); status != http.StatusOK {
		t.Fatalf("an unfenced deployment reported %d: adding the fence broke every single-site install", status)
	}

	// Fenced and holding the lease.
	held := base
	held.Fencing = probeFunc(func(context.Context) bool { return true })
	if status := readyStatus(t, NewRequired(held)); status != http.StatusOK {
		t.Fatalf("a site holding its lease reported %d", status)
	}

	// Fenced and NOT holding the lease: everything else is healthy, so only the fence can fail it.
	passive := base
	passive.Fencing = probeFunc(func(context.Context) bool { return false })
	if status := readyStatus(t, NewRequired(passive)); status == http.StatusOK {
		t.Fatal("a passive site with no lease reported itself ready: traffic would be routed to a site that can only refuse it")
	}
}

func readyStatus(t *testing.T, handler http.Handler) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	return recorder.Code
}
