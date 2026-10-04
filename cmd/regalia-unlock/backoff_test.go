package main

import (
	"testing"
	"time"
)

func TestTheBackoffDoublesFromTwoSecondsToAMinuteWithinTwentyPercent(t *testing.T) {
	for step, want := range []time.Duration{2, 4, 8, 16, 32, 60, 60, 60} {
		want *= time.Second
		low, high := backoff(step, 0), backoff(step, 0.999999)
		if low != want*8/10 || high < want*119/100 || high >= want*12/10 {
			t.Errorf("step %d: %s to %s, not %s ±20%%", step, low, high, want)
		}
	}
	if backoff(1000, 0.5) != 60*time.Second {
		t.Error("a long boot does not stay at the cap")
	}
	if backoff(0, -1) != 2*time.Second || backoff(0, 1) != 2*time.Second {
		t.Error("a jitter out of range is not taken as the middle")
	}
}

// The cadence the peers' hello limit (unlock.HELLO_RATE, #314: a burst of 10, one per 6 s) is sized
// against: at the fastest jitter, at most 6 attempts in any first minute and never more than the bucket
// gives after. The same schedule as tests/test_baremetal_unlock.py's ListenerRate simulates.
func TestTheFastestCadenceStaysUnderThePeersHelloLimit(t *testing.T) {
	const burst, refill = 10.0, 6.0 // seconds per token
	tokens, last, at := burst, 0.0, 0.0
	attempts := 0
	for step := 0; at < 7200; step++ {
		tokens = min(burst, tokens+(at-last)/refill)
		if tokens < 1 {
			t.Fatalf("attempt %d at t=%.1f s would be refused", step+1, at)
		}
		tokens, last = tokens-1, at
		if at < 60 {
			attempts++
		}
		at += backoff(step, 0).Seconds()
	}
	if attempts != 6 {
		t.Errorf("%d attempts in the first minute, not 6", attempts)
	}
}
