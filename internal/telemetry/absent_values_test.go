package telemetry

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
)

// A METRIC MUST BE OMITTED WHEN ITS INPUT IS ABSENT, NOT EMITTED FROM A ZERO VALUE.
//
// render() gates several series on whether the underlying value exists. Every one of those gates
// survived a sweep in the WIDENING direction — the direction that matters here, because these are
// admission guards: the dangerous mutation emits the series anyway, not suppresses it. Narrowing
// them reds tests immediately (a missing metric is loud); widening them was silent, because nothing
// asserted that a series is ABSENT.
//
// What widening actually produces is worse than a missing number. `time.Time{}.Unix()` is
// -62135596800, so a lease that was never evaluated reports a check timestamp in the year 1, and
// `now.Sub(time.Time{})` is about two millennia, so an empty backlog reports an oldest-unshipped age
// of 6.4e10 seconds. Those are not obviously-wrong values to a dashboard; they are extreme values,
// which is exactly what an alert threshold fires on. The readiness gate is worse again: widened, it
// reports the KMS ready whatever the health handler concluded.
//
// Isolation: each row zeroes exactly ONE input and asserts BOTH that the dependent series is gone
// AND that a sibling series from the same source is still present. The sibling is what makes the row
// a gate rather than an assertion that the whole block vanished — without it, a mutation that
// removed the entire source block would pass every row.
func TestASeriesWithNoUnderlyingValueIsOmittedRatherThanZeroFilled(t *testing.T) {
	checked := time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)

	// A slice, not a map: map iteration order is randomised and two CI logs could not be diffed.
	for _, test := range []struct {
		name        string
		sources     func(Sources) Sources
		wantAbsent  string
		wantPresent string
		operand     string
	}{
		{
			name: "shipping is not configured",
			sources: func(s Sources) Sources {
				s.AuditShipping = func() (bool, int, time.Time, uint64) { return false, 7, checked, 3 }
				return s
			},
			wantAbsent:  "regalia_audit_backlog_events",
			wantPresent: "regalia_audit_shipping_configured 0",
			operand:     "configured",
		},
		{
			name: "nothing is backlogged",
			sources: func(s Sources) Sources {
				s.AuditShipping = func() (bool, int, time.Time, uint64) { return true, 0, checked, 3 }
				return s
			},
			wantAbsent:  "regalia_audit_oldest_unshipped_age_seconds",
			wantPresent: "regalia_audit_backlog_events 0",
			operand:     "backlog > 0",
		},
		{
			name: "backlogged but no oldest timestamp",
			sources: func(s Sources) Sources {
				s.AuditShipping = func() (bool, int, time.Time, uint64) { return true, 4, time.Time{}, 3 }
				return s
			},
			wantAbsent:  "regalia_audit_oldest_unshipped_age_seconds",
			wantPresent: "regalia_audit_backlog_events 4",
			operand:     "!oldest.IsZero()",
		},
		{
			name: "lease exists but was never evaluated",
			sources: func(s Sources) Sources {
				s.Fencing = func() (bool, bool, uint64, time.Time) { return true, true, 9, time.Time{} }
				return s
			},
			wantAbsent:  "regalia_fencing_last_check_seconds",
			wantPresent: "regalia_fencing_lease_epoch 9",
			operand:     "!checked.IsZero()",
		},
		{
			name: "readiness has never been evaluated",
			sources: func(s Sources) Sources {
				s.Readiness = func() server.ReadinessStats { return server.ReadinessStats{Evaluated: false, Ready: true} }
				return s
			},
			wantAbsent: "regalia_ready",
			// The VALUE, not the bare name: writeHeader emits "# HELP <name> ..." and
			// "# TYPE <name> gauge", so a name on its own is present whenever the header
			// is, even with the gauge line gone. The sibling exists to show the source
			// block still emits a SERIES, and only the value line shows that.
			wantPresent: "regalia_audit_shipping_configured 1",
			operand:     "stats.Evaluated",
		},
		{
			name: "the journal has never been verified",
			sources: func(s Sources) Sources {
				s.AuditVerify = func() (string, time.Time) { return "intact", time.Time{} }
				return s
			},
			wantAbsent:  "regalia_audit_verify_last_run_seconds",
			wantPresent: `regalia_audit_verify_outcome{outcome="intact"} 1`,
			operand:     "!at.IsZero()",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := NewHandler(NewCollector(nil), test.sources(fullSources()),
				[]string{"spiffe://regalia/operator/monitoring"})
			body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

			if !strings.Contains(body, test.wantPresent) {
				t.Fatalf("fixture is not isolated: the sibling series %q is missing too, so an "+
					"absence below would not show that operand %s is what suppressed it.\n%s",
					test.wantPresent, test.operand, body)
			}
			if hasSample(body, test.wantAbsent) {
				t.Fatalf("DEFECT: %q was emitted even though its input is absent; operand %s is what "+
					"omits it, and a zero-filled value here is an extreme number an alert threshold "+
					"fires on, not an obviously missing one.\n%s", test.wantAbsent, test.operand, body)
			}
		})
	}
}

// TestReadyReportsTheEvaluationRatherThanAConstant pins the readiness value itself.
//
// The sibling operand above decides whether regalia_ready is emitted at all; this one decides WHAT
// it says. Widened, the series reports 1 for every evaluation, so a KMS whose dependencies failed
// their last health check is indistinguishable on a dashboard from one that passed — and this is the
// series an operator alerts on to find out.
//
// Isolation: readiness IS evaluated in both rows, so the emission operand cannot account for the
// difference; only the reported value changes.
func TestReadyReportsTheEvaluationRatherThanAConstant(t *testing.T) {
	for _, test := range []struct {
		name  string
		ready bool
		want  string
	}{
		{"the last evaluation passed", true, "regalia_ready 1"},
		{"the last evaluation failed", false, "regalia_ready 0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sources := fullSources()
			sources.Readiness = func() server.ReadinessStats {
				return server.ReadinessStats{Evaluated: true, Ready: test.ready}
			}
			handler := NewHandler(NewCollector(nil), sources, []string{"spiffe://regalia/operator/monitoring"})
			body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
			if !strings.Contains(body, test.want) {
				t.Fatalf("DEFECT: readiness evaluated with Ready=%v did not report %q; an operator "+
					"alerting on this series cannot tell a failing KMS from a healthy one.\n%s",
					test.ready, test.want, body)
			}
		})
	}
}

// TestMetricsAreServedOnlyAtTheirOwnPath pins the path comparison.
//
// Without it every path the handler is mounted under serves the metrics body, and that body is not
// nothing: it carries the fencing lease epoch, the audit backlog depth and the readiness verdict.
// The method check one line below is covered; its path sibling was not.
func TestMetricsAreServedOnlyAtTheirOwnPath(t *testing.T) {
	handler := NewHandler(NewCollector(nil), fullSources(), []string{"spiffe://regalia/operator/monitoring"})
	const principal = "spiffe://regalia/operator/monitoring"

	if body := requestAs(t, handler, principal, http.MethodGet, Path).Body.String(); !hasSample(body, "regalia_audit_backlog_events") {
		t.Fatalf("control is broken, so the refusals below would prove nothing: the metrics path "+
			"served no metrics.\n%s", body)
	}
	for _, path := range []string{Path + "z", Path + "/extra", "/", "/v1/operations/sign"} {
		recorder := requestAs(t, handler, principal, http.MethodGet, path)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("DEFECT: GET %s returned status %d and body %q; metrics carry the lease epoch, "+
				"the audit backlog and the readiness verdict, and must be served only at %s",
				path, recorder.Code, recorder.Body.String(), Path)
		}
	}
}

// TestAnUnknownVerifyOutcomeIsExclusiveWithTheRecognisedOnes pins the operand that keeps the
// outcome series mutually exclusive.
//
// The four outcome series are a one-hot encoding: exactly one of intact / chain-broken / unreadable
// / unknown carries 1. The "unknown" row is special-cased so that an outcome the KMS does not
// recognise is alertable rather than silently absent — but the operand that makes it EXCLUSIVE is
// separate from the one that emits it. Widened, "unknown" reports 1 alongside whichever real outcome
// also reports 1, so a dashboard summing the four gets 2 and an alert on unknown fires on every
// successful verification.
//
// Isolation: the outcome is a recognised one, so the special case must not apply; the row asserting
// intact==1 is what shows the fixture reached the encoding at all.
func TestAnUnknownVerifyOutcomeIsExclusiveWithTheRecognisedOnes(t *testing.T) {
	for _, outcome := range []string{"intact", "chain-broken", "unreadable"} {
		t.Run(outcome, func(t *testing.T) {
			sources := fullSources()
			sources.AuditVerify = func() (string, time.Time) { return outcome, testNow }
			handler := NewHandler(NewCollector(nil), sources, []string{"spiffe://regalia/operator/monitoring"})
			body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

			if want := `regalia_audit_verify_outcome{outcome="` + outcome + `"} 1`; !strings.Contains(body, want) {
				t.Fatalf("fixture did not reach the outcome encoding: %q missing.\n%s", want, body)
			}
			if want := `regalia_audit_verify_outcome{outcome="unknown"} 0`; !strings.Contains(body, want) {
				t.Fatalf("DEFECT: outcome %q was recognised, yet the unknown series does not report 0; "+
					"two series report 1 at once, so the encoding is no longer one-hot and an alert on "+
					"unknown fires on a successful verification.\n%s", outcome, body)
			}
		})
	}
}

// TestRenderingWorksWithoutAnInjectedClock pins the nil check on the clock source.
//
// Sources.Now is a seam: cmd/regalia-kms/main.go:349 passes time.Now, and the tests here pass a
// fixed clock. Neither exercises the nil case, but NewHandler is exported and accepts a Sources with
// no clock at all — and without this operand that call is a nil function call, so the first metrics
// scrape takes the handler down rather than returning a page.
//
// Isolation: the only field left unset is Now; the age-derived series is the one that consumes it,
// and it is present in the output, which is what shows the clock path was actually taken.
func TestRenderingWorksWithoutAnInjectedClock(t *testing.T) {
	sources := fullSources()
	sources.Now = nil
	handler := NewHandler(NewCollector(nil), sources, []string{"spiffe://regalia/operator/monitoring"})

	var body string
	panicked := func() (recovered any) {
		defer func() { recovered = recover() }()
		body = requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()
		return nil
	}()
	if panicked != nil {
		t.Fatalf("DEFECT: rendering with no injected clock panicked with %v; NewHandler is exported "+
			"and Sources.Now is optional, so this is a nil function call on the first scrape", panicked)
	}
	if !hasSample(body, "regalia_audit_oldest_unshipped_age_seconds") {
		t.Fatalf("fixture did not reach the clock: the one series derived from it is missing, so a "+
			"panic above would not have been attributable to the clock at all.\n%s", body)
	}
}

// hasSample reports whether body carries an actual SAMPLE line for name, rather than only the
// "# HELP name ..." and "# TYPE name gauge" lines writeHeader emits alongside every series.
//
// A bare strings.Contains on a metric name is satisfied by the metric's DOCUMENTATION with the
// value line gone. Rows that can name a deterministic value assert it directly and are safe -- the
// header text after the name is prose, never a number -- but where the value is not deterministic,
// this is what distinguishes a series from its description. Both are needed: the value where it
// exists, the sample check where it does not.
func hasSample(body, name string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, name+" ") || strings.HasPrefix(line, name+"{") {
			return true
		}
	}
	return false
}
