//go:build piv

package yubikey

import (
	"context"
	"time"
)

// readPINRetries absorbs a short PC/SC transaction teardown race without
// turning a missing card into a healthy result. The bound is intentionally
// small and cancellation is checked between attempts.
func readPINRetries(ctx context.Context, read func() (int, error)) (int, error) {
	for attempt := 0; attempt < 3; attempt++ {
		retries, err := read()
		if err == nil {
			return retries, nil
		}
		if attempt == 2 {
			return 0, err
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return 0, ctx.Err()
		case <-timer.C:
		}
	}
	return 0, context.Canceled
}
