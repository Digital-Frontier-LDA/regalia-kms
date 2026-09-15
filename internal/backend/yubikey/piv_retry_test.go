//go:build piv

package yubikey

import (
	"context"
	"errors"
	"testing"
)

func TestReadPINRetriesRecoversTransientReaderFailure(t *testing.T) {
	attempts := 0
	wantErr := errors.New("reader busy")
	got, err := readPINRetries(context.Background(), func() (int, error) {
		attempts++
		if attempts < 3 {
			return 0, wantErr
		}
		return 3, nil
	})
	if err != nil || got != 3 || attempts != 3 {
		t.Fatalf("got retries=%d err=%v attempts=%d; want 3,nil,3", got, err, attempts)
	}
}

func TestReadPINRetriesStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	if _, err := readPINRetries(ctx, func() (int, error) {
		attempts++
		return 0, errors.New("reader busy")
	}); !errors.Is(err, context.Canceled) || attempts != 1 {
		t.Fatalf("err=%v attempts=%d; want cancellation after first read", err, attempts)
	}
}
