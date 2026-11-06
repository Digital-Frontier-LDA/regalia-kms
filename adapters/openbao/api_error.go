package openbaopoc

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// APIError contains only public correlation metadata, never server messages,
// request bodies, credential paths, transport URLs or provider error text.
type APIError struct {
	Code      string
	RequestID string
	Retryable bool
	cause     error
}

func (e *APIError) Error() string {
	if e.RequestID == "" {
		return "Regalia " + e.Code
	}
	return fmt.Sprintf("Regalia %s (request %s)", e.Code, e.RequestID)
}

func (e *APIError) Unwrap() error      { return e.cause }
func (*APIError) Is(target error) bool { return target == errOperation }

var apiCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

func contextError(err error, id string) *APIError {
	code := "TRANSPORT_UNAVAILABLE"
	var cause error
	if errors.Is(err, context.DeadlineExceeded) {
		code, cause = "DEADLINE_EXCEEDED", context.DeadlineExceeded
	} else if errors.Is(err, context.Canceled) {
		code, cause = "CANCELED", context.Canceled
	}
	return &APIError{Code: code, RequestID: id, cause: cause}
}

func retryCode(code string) bool {
	switch code {
	case "BACKEND_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE", "RESOURCE_EXHAUSTED", "DEADLINE_EXCEEDED":
		return true
	}
	return false
}

func errorStatus(code string, status int) bool {
	switch code {
	case "UNAUTHENTICATED":
		return status == 401
	case "DENIED":
		return status == 403
	case "NOT_FOUND":
		return status == 404
	case "INVALID_ARGUMENT":
		return status == 400 || status == 405
	case "CONFLICT":
		return status == 409
	case "RESOURCE_EXHAUSTED":
		return status == 429
	case "BACKEND_UNAVAILABLE", "DEPENDENCY_UNAVAILABLE":
		return status == 503
	case "DEADLINE_EXCEEDED", "CANCELED":
		return status == 504
	case "INTERNAL":
		return status == 500
	case "INVALID_OPERATION":
		return status == 422
	default:
		return status >= 400 && status < 600
	}
}
