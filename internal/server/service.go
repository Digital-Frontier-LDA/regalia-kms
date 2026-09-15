package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Options bounds the service. OperationTimeout is the configured per-operation
// deadline; the HTTP write deadline is derived from it rather than fixed.
type Options struct {
	ShutdownTimeout  time.Duration
	OperationTimeout time.Duration
}

// writeHeadroom is added to the operation deadline so the response can be
// marshalled and flushed after the handler returns at its own limit.
const writeHeadroom = 30 * time.Second

// defaultOperationTimeout mirrors config's default, so a zero Options value
// still yields a write deadline that outlives a default-length operation.
const defaultOperationTimeout = 15 * time.Second

// defaultShutdownTimeout mirrors config's default for the same reason its sibling above does,
// and for a sharper consequence.
//
// A ZERO SHUTDOWN TIMEOUT DOES NOT MEAN "SHUT DOWN IMMEDIATELY". It builds an already-expired
// context, so Shutdown gives in-flight requests no grace at all and returns
// context.DeadlineExceeded, and the error branch then calls Close() — which drops those
// connections. Measured, with one request in flight when the context is cancelled:
//
//	ShutdownTimeout=0   Serve returns "context deadline exceeded", client gets EOF
//	ShutdownTimeout=2s  Serve returns nil,                         client gets 200 OK
//
// For this service an in-flight request is a signing operation against hardware, so the
// difference is a completed operation whose result the caller never receives — indistinguishable
// at the caller from a failure, while the key was in fact used.
//
// Config validates shutdown_timeout into 1s..2m, so the daemon cannot reach zero. That made this
// safe because of the one caller rather than because Serve is safe, which is the same shape as
// httpServerFor's own guard two lines above: an exported function must not depend on its current
// caller's validation.
const defaultShutdownTimeout = 10 * time.Second

// httpServerFor builds the bounded server. Extracted so the relationship
// between the operation deadline and the write deadline is directly testable.
//
// WHY THE WRITE DEADLINE IS NOT A CONSTANT. It was fixed at 10s while
// operation_timeout DEFAULTS to 15s and may be configured up to 10m, so the
// HTTP server cut the connection before the operation's own deadline and the
// caller saw a truncated response instead of the timeout the configuration
// promised. That made operation_timeout untrue for every value above 10s —
// including the default — and would have been read as a backend fault rather
// than a server limit.
func httpServerFor(handler http.Handler, operationTimeout time.Duration) *http.Server {
	if operationTimeout <= 0 {
		operationTimeout = defaultOperationTimeout
	}
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		// Request bodies are bounded and small; this stays fixed as slowloris cover.
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   operationTimeout + writeHeadroom,
		IdleTimeout:    30 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
}

// Serve runs the HTTP service until the context is canceled or the listener
// fails. Cancellation initiates a bounded graceful shutdown.
func Serve(ctx context.Context, listener net.Listener, handler http.Handler, options Options) error {
	shutdownTimeout := options.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = defaultShutdownTimeout
	}
	httpServer := httpServerFor(handler, options.OperationTimeout)

	serveResult := make(chan error, 1)
	go func() { serveResult <- httpServer.Serve(listener) }()

	select {
	case err := <-serveResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_ = httpServer.Close()
			return err
		}
		err := <-serveResult
		// BOTH DECISIONS IN THIS ARM SURVIVE THE ADMISSION DIRECTION, AND THAT IS §17, NOT
		// A GAP. Measured for #237 over the whole module: forcing the Shutdown-error test
		// above to `true`, and forcing this sentinel test to `true`, each leave
		// `go test ./...` green. Neither is untested — both reduce to the same
		// unreachable state, the one TESTING.md §17 records for this function.
		//
		// A non-sentinel error can only arrive here if the listener had ALREADY failed
		// before cancellation and the select above still chose ctx.Done(): Shutdown sets
		// inShutdown before it closes the listener, so from that moment net/http converts
		// every Accept failure into ErrServerClosed. That interleaving is owned by the Go
		// scheduler, so a test pinning it would be red on a schedule nobody controls —
		// which is why the statement is deliberately unmeasured rather than covered.
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
