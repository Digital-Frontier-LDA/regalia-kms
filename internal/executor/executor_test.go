package executor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunReturnsResult(t *testing.T) {
	want := errors.New("backend refused")
	got := New(1, time.Second).Run(context.Background(), func(context.Context) error { return want })
	if !errors.Is(got, want) {
		t.Fatalf("Run() error = %v, want wrapped backend error", got)
	}
}

func TestRunRejectsWhenAtCapacity(t *testing.T) {
	executor := New(1, time.Second)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- executor.Run(context.Background(), func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	err := executor.Run(context.Background(), func(context.Context) error { return nil })
	var operationErr *Error
	if !errors.As(err, &operationErr) || operationErr.Code != CodeBusy || !operationErr.Retryable {
		t.Fatalf("Run() error = %#v, want retryable %s", err, CodeBusy)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
}

func TestRunTimesOutAndSignalsOperation(t *testing.T) {
	executor := New(1, 20*time.Millisecond)
	operationDone := make(chan struct{})
	err := executor.Run(context.Background(), func(ctx context.Context) error {
		<-ctx.Done()
		close(operationDone)
		return ctx.Err()
	})

	var operationErr *Error
	if !errors.As(err, &operationErr) || operationErr.Code != CodeTimeout || !operationErr.Retryable {
		t.Fatalf("Run() error = %#v, want retryable %s", err, CodeTimeout)
	}
	select {
	case <-operationDone:
	case <-time.After(time.Second):
		t.Fatal("operation did not observe timeout")
	}
}

func TestRunPreservesCallerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New(1, time.Second).Run(ctx, func(context.Context) error {
		t.Fatal("operation must not start after caller cancellation")
		return nil
	})

	var operationErr *Error
	if !errors.As(err, &operationErr) || operationErr.Code != CodeCanceled || operationErr.Retryable {
		t.Fatalf("Run() error = %#v, want non-retryable %s", err, CodeCanceled)
	}
}

func TestRunContainsPanicAndRestoresCapacity(t *testing.T) {
	executor := New(1, time.Second)
	err := executor.Run(context.Background(), func(context.Context) error { panic("token middleware leaked a PIN") })
	var operationErr *Error
	if !errors.As(err, &operationErr) || operationErr.Code != CodeInternal || operationErr.Retryable {
		t.Fatalf("Run() error = %#v, want non-retryable %s", err, CodeInternal)
	}
	if operationErr.Error() != "KMS operation failed" {
		t.Fatalf("public error leaked detail: %q", operationErr.Error())
	}
	if err := executor.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("capacity was not restored: %v", err)
	}
}
