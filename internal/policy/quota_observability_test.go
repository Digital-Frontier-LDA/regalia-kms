package policy

import (
	"context"
	"testing"
	"time"
)

// A QUOTA REJECTION IS AN OPERATIONS EVENT, NOT A LOG LINE.
//
// Until now the only place a refused reservation surfaced was one more denied
// request — indistinguishable from a misconfigured client. The count of
// limit-exceeded decisions is what tells an operator "a workload hit its cap"
// apart from "the workload is broken", and it must count ONLY quota rejections:
// every other denial class is already loud elsewhere.
func TestQuotaRejectionsAreCountedSeparatelyFromOtherDenials(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state := &reservationState{err: ErrLimit}
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.QuotaRejections(); got != 0 {
		t.Fatalf("QuotaRejections before any evaluation = %d", got)
	}
	for i := 1; i <= 2; i++ {
		if decision := engine.Evaluate(context.Background(), baseRequest(now)); decision.Code != CodeLimitExceeded {
			t.Fatalf("decision = %#v, want limit-exceeded", decision)
		}
		if got := engine.QuotaRejections(); got != uint64(i) {
			t.Fatalf("QuotaRejections after %d limit decisions = %d: a quota rejection was not counted", i, got)
		}
	}

	// Other denial classes and plain allow must not move the quota counter.
	request := baseRequest(now)
	request.Purpose = "release-artifact"
	if decision := engine.Evaluate(context.Background(), request); decision.Allowed {
		t.Fatal("mismatched purpose was allowed")
	}
	state.err = nil
	if decision := engine.Evaluate(context.Background(), baseRequest(now)); !decision.Allowed {
		t.Fatalf("decision = %#v, want allow", decision)
	}
	if got := engine.QuotaRejections(); got != 2 {
		t.Fatalf("QuotaRejections = %d after non-quota denial and an allow: the counter counts the wrong thing", got)
	}
}
