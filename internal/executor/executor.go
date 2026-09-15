// Package executor bounds and supervises calls into hardware middleware.
package executor

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Code string

const (
	CodeBusy     Code = "RESOURCE_EXHAUSTED"
	CodeTimeout  Code = "DEADLINE_EXCEEDED"
	CodeCanceled Code = "CANCELED"
	CodeInternal Code = "INTERNAL"
)

// Error is safe to return at the API boundary. Cause is available for local
// classification and audit but is intentionally absent from Error's message.
type Error struct {
	Code      Code
	Retryable bool
	Cause     error
}

func (err *Error) Error() string { return "KMS operation failed" }
func (err *Error) Unwrap() error { return err.Cause }

type Executor struct {
	semaphore chan struct{}
	timeout   time.Duration
}

func New(maxConcurrent int, timeout time.Duration) *Executor {
	if maxConcurrent < 1 {
		panic("executor maxConcurrent must be positive")
	}
	if timeout <= 0 {
		panic("executor timeout must be positive")
	}
	return &Executor{semaphore: make(chan struct{}, maxConcurrent), timeout: timeout}
}

// Run fails fast at capacity. Once admitted, the operation owns its slot until
// it actually returns—even if its caller has already timed out—so a wedged
// middleware call cannot cause the daemon to exceed its hardware concurrency cap.
func (executor *Executor) Run(ctx context.Context, operation func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return classifyContextError(ctx, err)
	}
	select {
	case executor.semaphore <- struct{}{}:
	case <-ctx.Done():
		return classifyContextError(ctx, ctx.Err())
	default:
		return &Error{Code: CodeBusy, Retryable: true}
	}

	operationCtx, cancel := context.WithTimeout(ctx, executor.timeout)
	result := make(chan error, 1)
	go func() {
		defer func() {
			<-executor.semaphore
			if recovered := recover(); recovered != nil {
				result <- &Error{Code: CodeInternal, Retryable: false, Cause: fmt.Errorf("operation panic")}
			}
		}()
		result <- operation(operationCtx)
	}()

	select {
	case err := <-result:
		if operationCtx.Err() != nil {
			contextErr := classifyContextError(ctx, operationCtx.Err())
			cancel()
			return contextErr
		}
		cancel()
		return err
	case <-operationCtx.Done():
		err := classifyContextError(ctx, operationCtx.Err())
		cancel()
		return err
	}
}

func classifyContextError(parent context.Context, cause error) error {
	if errors.Is(parent.Err(), context.Canceled) {
		return &Error{Code: CodeCanceled, Retryable: false, Cause: cause}
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return &Error{Code: CodeTimeout, Retryable: true, Cause: cause}
	}
	return &Error{Code: CodeCanceled, Retryable: false, Cause: cause}
}
