package main

import "time"

// The pause before the next attempt at the peers (#70: a node that boots during or after a blackout asks
// until a peer answers, with the recovery prompt at the console all along). 2 s, doubling to 60 s, each
// pause scaled by a factor drawn from [0.8, 1.2) so that nodes rebooting together do not ask in step; the
// step count is never reset within a boot (a request that systemd-cryptsetup makes again does not start it
// over). The peers' per-node hello limit (unlock.HELLO_RATE, #314: a burst of 10, one more every 6 s) is
// sized against this cadence, at its fastest: 6 attempts in the first minute, then about one a minute.
const (
	backoffFirst = 2 * time.Second
	backoffCap   = 60 * time.Second
)

// backoff is the pause after attempt `step` (0 for the first), with `jitter` in [0, 1).
func backoff(step int, jitter float64) time.Duration {
	pause := backoffFirst
	for i := 0; i < step && pause < backoffCap; i++ {
		pause *= 2
	}
	if pause > backoffCap {
		pause = backoffCap
	}
	if jitter < 0 || jitter >= 1 {
		jitter = 0.5
	}
	return time.Duration(float64(pause) * (0.8 + 0.4*jitter))
}
