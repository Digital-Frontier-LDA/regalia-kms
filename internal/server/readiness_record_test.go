package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// scriptedClock hands out a distinct, known instant on every read: the nth call returns
// base + n seconds. Nothing here waits on the wall clock.
//
// WHY NOT A SLEEP. The first version of the freshness test below slept 2ms between two
// evaluations and asserted the stamp had advanced. That makes the assertion depend on the
// platform's clock resolution and on how loaded the machine is — two reads can land inside
// one tick, and the test then fails for a reason that has nothing to do with the guard.
// The consequence is specific rather than general: this test is the SOLE detector for a
// defect where the daemon serves 503 while regalia_ready renders 1, and a flaky sole
// detector does not merely fail sometimes, it eventually gets quarantined or deleted —
// leaving the gap open with a test file standing where the coverage used to be.
//
// The seam is the one registry.clock, auth and operations.Coordinator already carry.
//
// last() is what makes the assertions exact rather than monotonic: the record must equal
// the most recent instant this clock handed out, so a stamp taken from somewhere else, or
// not retaken at all, is named rather than merely "not later".
type scriptedClock struct {
	mu    sync.Mutex
	base  time.Time
	calls int
}

func newScriptedClock() *scriptedClock {
	// A fixed, obviously-not-now base, so a stamp that came from the wall clock instead of
	// this seam is off by years rather than by microseconds.
	return &scriptedClock{base: time.Date(2026, 9, 4, 17, 0, 0, 0, time.UTC)}
}

func (clock *scriptedClock) read() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.calls++
	return clock.base.Add(time.Duration(clock.calls) * time.Second)
}

// last is the instant most recently handed out, and reads() how many have been. Both are
// needed: the value says WHAT should have been recorded, the count says the seam was used
// at all — without it a handler that ignored the clock entirely would be compared against
// an instant nobody produced.
func (clock *scriptedClock) last() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.base.Add(time.Duration(clock.calls) * time.Second)
}

func (clock *scriptedClock) reads() int {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.calls
}

// handlerWithClock builds a readiness handler whose record is stamped from clock.
func handlerWithClock(probes []ReadinessProbe, clock *scriptedClock) *Handler {
	handler := New(probes)
	handler.now = clock.read
	return handler
}

// THE READINESS RECORD IS A SECOND ANSWER, AND NOTHING JOINED IT TO THE FIRST.
//
// One evaluation produces two answers by two different paths. `/v1/health/ready` returns
// `Handler.ready`'s value to a load balancer; `ReadinessStats` returns what
// `noteReadiness` wrote, to Prometheus, as `regalia_ready` — whose alert condition in
// OBSERVABILITY.md is `== 0 for 2m: page`. Every test in this package asserted the first.
// The two that touch the second assert `Ready` is TRUE in states where it is true:
// `TestReadinessTransitionsAreCounted` here, and
// `TestReadyReportsTheEvaluationRatherThanAConstant` in `internal/telemetry`, which feeds
// a `ReadinessStats` LITERAL rather than a Handler — so it pins the rendering of a value
// it also supplies. Nothing asserted the record says `false` while the endpoint is
// refusing traffic.
//
// MEASURED on origin/main, `go test -count=1 ./...` over the whole module. Three wrong
// versions of the accessor, each leaving `noteReadiness` byte-identical:
//
//	Ready: true                                          0 failing tests
//	Ready: handler.evaluated                             0 failing tests
//	Ready: handler.lastReady || handler.transitions > 0  0 failing tests
//
// The third is the one somebody would actually write — latch the answer so a dashboard
// stops flapping — and under it `regalia_ready` sticks at 1 for the rest of the process's
// life after the first healthy check. Under any of them the daemon answers 503 to every
// load-balancer probe while the scrape says 1, so the page that exists to say "this KMS
// is not serving" cannot fire, and the dashboard contradicts the load balancer with no
// way to tell which is lying.
//
// WHERE THE EXISTING BOUNDARY IS, measured rather than assumed: the neighbouring variant
// that records the WIRING instead of the ANSWER — `noteReadiness(len(handler.probes) > 0)`
// — IS caught, by `TestReadinessTransitionsAreCounted`, because a record that never
// changes never counts a transition. So the covered half is the record's arithmetic and
// the uncovered half is what the accessor reports, which is the half a scrape reads.
//
// The join is pinned HERE rather than in `internal/telemetry` because this is where it is
// enforced: the record and the served status come from one call to `Handler.ready`.
func TestTheRecordedReadinessIsTheAnswerThatWasServed(t *testing.T) {
	probe := &switchProbe{}
	probe.ready.Store(true)
	handler := New([]ReadinessProbe{probe})

	// One handler throughout, driven through the real endpoint, so the record under test
	// is the history a scrape would read rather than a fresh evaluation per row.
	for _, step := range []struct {
		name   string
		ready  bool
		status int
		why    string
	}{
		{"the dependency answers", true, http.StatusOK,
			"the seed: without a ready state first, the losses below would be a handler that was never up"},
		{"the dependency is lost", false, http.StatusServiceUnavailable,
			"the record must follow the answer down, or regalia_ready stays at 1 through an outage"},
		{"it is still lost on the next probe", false, http.StatusServiceUnavailable,
			"a record that latches on its first healthy answer is right once and then wrong for the whole outage"},
	} {
		t.Run(step.name, func(t *testing.T) {
			probe.ready.Store(step.ready)
			code := request(t, handler, http.MethodGet, "/v1/health/ready").Code
			if code != step.status {
				t.Fatalf("GET /v1/health/ready = %d, want %d — the fixture did not reach the state "+
					"this row is about, so the record assertion below would prove nothing", code, step.status)
			}
			if stats := handler.ReadinessStats(); stats.Ready != step.ready {
				t.Fatalf("DEFECT: the endpoint answered %d and the record says Ready=%v, want %v. %s. "+
					"regalia_ready renders this field and alerts on `== 0 for 2m`, so a record that "+
					"disagrees with the status leaves that page unfirable while the load balancer has "+
					"already stopped routing.", code, stats.Ready, step.ready, step.why)
			}
		})
	}

	// A DAEMON WIRED WITH NOTHING must record its refusal too, and it takes its own
	// handler because the fixture is the absence of probes rather than their answer.
	// `Handler.ready` fails closed here before any probe runs, so this record is written
	// on a path that never enters the loop the rows above exercise.
	t.Run("a handler with no probes at all", func(t *testing.T) {
		empty := New(nil)
		if code := request(t, empty, http.MethodGet, "/v1/health/ready").Code; code != http.StatusServiceUnavailable {
			t.Fatalf("GET /v1/health/ready with no probes = %d, want 503", code)
		}
		stats := empty.ReadinessStats()
		if !stats.Evaluated {
			t.Fatalf("a served refusal recorded no evaluation at all (%+v): the series would be absent, "+
				"and an absent series cannot be told from a scrape target that is down", stats)
		}
		if stats.Ready {
			t.Fatalf("DEFECT: a daemon with nothing wired answered 503 and recorded Ready=true, so "+
				"regalia_ready reports 1 for a KMS that cannot serve anything at all. stats = %+v", stats)
		}
	})

	// ANCHOR, PLACED LAST BY DESIGN (TESTING.md §18). Recovery must move the record back
	// up. Without it every assertion above is equally satisfied by an accessor reporting
	// `Ready: false` unconditionally — the same defect pointed the other way, which pages
	// an operator through every healthy hour.
	t.Run("ANCHOR the dependency recovers and the record follows it back up", func(t *testing.T) {
		probe.ready.Store(true)
		if code := request(t, handler, http.MethodGet, "/v1/health/ready").Code; code != http.StatusOK {
			t.Fatalf("GET /v1/health/ready after recovery = %d, want 200", code)
		}
		if stats := handler.ReadinessStats(); !stats.Ready {
			t.Fatalf("the endpoint answered 200 and the record still says Ready=false (%+v): every "+
				"refusal asserted above would be satisfied by a record that is never ready", stats)
		}
	})
}

// A FRESHNESS STAMP THAT MOVES ONLY WHEN THE ANSWER MOVES IS NOT A FRESHNESS STAMP.
//
// `regalia_readiness_last_check_seconds` is rendered from `ReadinessStats().CheckedAt` and
// alerts on `time() - value > 120`. OBSERVABILITY.md states the rule it serves: "a gauge
// without its age reads as current forever, and a stuck reading is a blind spot, not a
// healthy subsystem".
//
// `noteReadiness` writes `evaluated`, `lastReady` and `checkedAt` in ONE assignment, so no
// single-operand mutation can separate the stamp from the transition count — the guard
// sweep behind #237 is structurally unable to ask this question, which is why it is asked
// here as a realistic wrong version instead.
//
// MEASURED on origin/main, with the stamp moved inside the answer-changed branch and the
// transition arithmetic left equivalent: `go test -count=1 ./...` over the whole module is
// GREEN, 0 failing tests. `TestReadinessTransitionsAreCounted` asserts `CheckedAt` is
// non-zero after the FIRST evaluation, which that version still satisfies.
//
// Both directions of the resulting lie are bad and the second is worse. A steadily ready
// daemon pages as one nobody is probing. A daemon that has been DOWN for three minutes
// pages for the wrong reason — the operator is told the checks stopped rather than that
// the dependencies are gone, and goes to look at the load balancer.
//
// The clock is INJECTED (see scriptedClock): each evaluation must record the instant the
// seam most recently handed out, which is an assertion about the recorded value rather
// than about how quickly the machine ran between two calls.
func TestEveryEvaluationRefreshesTheReadinessTimestamp(t *testing.T) {
	for _, state := range []struct {
		name  string
		ready bool
	}{
		{"steadily ready", true},
		// The operationally sharper row: the stamp must keep moving through an outage, or
		// the staleness alert fires alongside the readiness one and misdirects the reader.
		{"steadily unready", false},
	} {
		t.Run(state.name, func(t *testing.T) {
			probe := &switchProbe{}
			probe.ready.Store(state.ready)
			clock := newScriptedClock()
			handler := handlerWithClock([]ReadinessProbe{probe}, clock)

			request(t, handler, http.MethodGet, "/v1/health/ready")
			first := handler.ReadinessStats()
			readsAfterFirst := clock.reads()
			// CONTROL: the seam is what the record came from. Without this, every
			// assertion below compares the record against instants a handler ignoring the
			// clock never saw, and the comparison would be between two unrelated numbers.
			if readsAfterFirst == 0 {
				t.Fatalf("the evaluation never read the injected clock, so the stamp came from "+
					"somewhere this test does not control: %+v", first)
			}
			if !first.CheckedAt.Equal(clock.last()) {
				t.Fatalf("the first evaluation recorded %s, want the instant the clock handed out (%s): "+
					"the comparison below would be against a value that is already wrong",
					first.CheckedAt.Format(time.RFC3339Nano), clock.last().Format(time.RFC3339Nano))
			}

			request(t, handler, http.MethodGet, "/v1/health/ready")
			second := handler.ReadinessStats()

			// ISOLATION. The defect is only visible across an evaluation whose ANSWER did
			// not change. If the fixture flapped, a stamp that moved would prove nothing,
			// because the wrong version stamps on a change too.
			if second.Ready != first.Ready || second.Transitions != first.Transitions {
				t.Fatalf("the fixture is not steady (%+v then %+v): a stamp that advanced here could "+
					"have advanced because the answer changed", first, second)
			}
			if clock.reads() == readsAfterFirst {
				t.Fatalf("DEFECT: the second evaluation never asked the clock what time it was, so the " +
					"record cannot describe it. regalia_readiness_last_check_seconds is rendered from " +
					"this field, and a check that leaves no timestamp is a check that did not happen " +
					"as far as every alert is concerned.")
			}

			if !second.CheckedAt.Equal(clock.last()) {
				t.Fatalf("DEFECT: two evaluations, the answer unchanged at Ready=%v, and the record still "+
					"holds %s while the clock has since reached %s. "+
					"regalia_readiness_last_check_seconds renders this field and alerts on "+
					"`time() - value > 120`, so a daemon being probed every second reports that nobody "+
					"is probing it.", first.Ready, second.CheckedAt.Format(time.RFC3339Nano),
					clock.last().Format(time.RFC3339Nano))
			}
		})
	}

	// ANCHOR, PLACED LAST BY DESIGN (TESTING.md §18). Every row above is stated in terms
	// of the injected clock, so all of them would be equally satisfied by a daemon whose
	// production clock is never read at all. This is the row that says the DEFAULT handler
	// — the one main.go builds — stamps a real wall-clock reading, which is the value the
	// alert subtracts from time(). It is also the only row here that touches time.Now, and
	// it asserts a window rather than an instant, so it does not reintroduce a race.
	t.Run("ANCHOR the default handler stamps the wall clock", func(t *testing.T) {
		probe := &switchProbe{}
		probe.ready.Store(true)
		handler := New([]ReadinessProbe{probe})

		before := time.Now().UTC()
		request(t, handler, http.MethodGet, "/v1/health/ready")
		after := time.Now().UTC()

		stats := handler.ReadinessStats()
		if stats.CheckedAt.Before(before) || stats.CheckedAt.After(after) {
			t.Fatalf("the recorded check time %s is outside the window the request ran in (%s..%s): the "+
				"field is not a wall-clock reading, so subtracting it from time() means nothing",
				stats.CheckedAt.Format(time.RFC3339Nano), before.Format(time.RFC3339Nano),
				after.Format(time.RFC3339Nano))
		}
	})
}

// THE SEAM MUST NOT HAVE TURNED THE HEALTH ENDPOINT INTO A NIL FUNCTION CALL.
//
// Handler's fields are all unexported, so `&server.Handler{}` compiles in any package, and
// before the clock seam existed that zero value answered 503 — no probes, fail closed.
// `Handler.clock`'s nil fallback is what keeps it doing so. Without that fallback the
// readiness endpoint of such a handler panics on its first request: a health check that
// crashes rather than answering, which is a worse failure than the one the seam was added
// to make testable.
//
// This is the twin of telemetry's TestRenderingWorksWithoutAnInjectedClock, and it exists
// for the same reason: the clock is optional on an exported type, and nothing else in this
// package constructs one without it.
func TestAHandlerWithNoInjectedClockStillRecordsAnEvaluation(t *testing.T) {
	handler := &Handler{}

	var recorder *httptest.ResponseRecorder
	panicked := func() (recovered any) {
		defer func() { recovered = recover() }()
		recorder = request(t, handler, http.MethodGet, "/v1/health/ready")
		return nil
	}()
	if panicked != nil {
		t.Fatalf("DEFECT: a Handler with no injected clock panicked with %v on /v1/health/ready — "+
			"the zero value used to answer 503, and the readiness endpoint now crashes instead of "+
			"reporting", panicked)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("a Handler with no probes answered %d, want 503", recorder.Code)
	}

	stats := handler.ReadinessStats()
	if stats.CheckedAt.IsZero() {
		t.Fatalf("DEFECT: the evaluation recorded no timestamp (%+v), so the fallback clock produced "+
			"a zero time — regalia_readiness_last_check_seconds would render the year 1, which is an "+
			"extreme value an alert threshold fires on rather than an obviously missing one", stats)
	}

	// WHAT THIS TEST DELIBERATELY DOES NOT ASSERT: that the record says Ready=false. It is
	// true, and it belongs to TestTheRecordedReadinessIsTheAnswerThatWasServed, whose
	// "a handler with no probes at all" row already pins it. Asserting it here as well was
	// measured to cost something concrete: two of that test's four counterfactuals then
	// produced TWO failing tests instead of one, so neither was a sole detector any more
	// and a reader of the failure would have had to work out which of them named the
	// defect. A duplicated assertion is not free coverage; it is a second thing that goes
	// red for somebody else's reason.
}
