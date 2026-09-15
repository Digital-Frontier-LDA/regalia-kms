package server

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// failingListener reports a fixed error from Accept. It stands in for a
// listener whose socket dies under the running server — an interface going
// down, a descriptor revoked — which no loopback listener will do on request.
type failingListener struct {
	err    error
	once   sync.Once
	closed chan struct{}
}

func newFailingListener(err error) *failingListener {
	return &failingListener{err: err, closed: make(chan struct{})}
}

func (listener *failingListener) Accept() (net.Conn, error) { return nil, listener.err }

func (listener *failingListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (listener *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

// startServe runs Serve in the background. The returned cancel triggers the
// shutdown path; the channel carries Serve's single return value.
func startServe(t *testing.T, listener net.Listener, handler http.Handler, options Options) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, handler, options) }()
	return cancel, done
}

func awaitServe(t *testing.T, done <-chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(within):
		t.Fatalf("Serve() did not return within %s", within)
		return nil
	}
}

// refused reports whether a fresh connection to addr is rejected outright,
// which is how the test observes that Shutdown has already closed the listener.
//
// A TIMEOUT IS NOT REFUSAL. Treating every dial error as "closed" would let a
// loaded machine satisfy the wait without the listener having closed at all,
// and the caller would then release its handler early — leaving the in-flight
// proof vacuous while still passing. Any error that is neither a refusal nor a
// timeout fails the test rather than being guessed at, because the whole point
// of this helper is to distinguish two states of the listener.
//
// ECONNRESET COUNTS AS REFUSAL, AND THAT WAS MEASURED, NOT ASSUMED. Closing a
// listening socket on darwin resets whatever is still sitting in its accept
// backlog, so a dial that lands in that window comes back
// "connect: connection reset by peer" rather than ECONNREFUSED. Accepting only
// ECONNREFUSED made this test fail roughly once in a hundred runs — found by a
// hundred-execution sweep after a single unexplained failure, which is the only
// reason it is not still intermittent. Both errors mean the same thing here:
// nothing is accepting on that port any more.
func refused(t *testing.T, addr string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	t.Fatalf("dialing %s during shutdown: %v — cannot tell a closed listener from this", addr, err)
	return false
}

// clientTransport is a transport that talks to the test listener and nothing
// else. The default transport reads HTTP(S)_PROXY and NO_PROXY from the
// environment, so on a machine that sets them these requests would be sent to a
// proxy instead of the server under test — which fails, or worse succeeds
// against something else, for a reason that has nothing to do with shutdown.
func clientTransport(t *testing.T) *http.Transport {
	t.Helper()
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

// requestContext bounds the background request goroutines so a test that fails
// early cannot leave one dialing after the server is gone.
func requestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAListenerFailureIsReportedRatherThanSwallowed(t *testing.T) {
	boom := errors.New("accept: network interface is down")
	// The context is never canceled here: if Serve returned for any reason
	// other than the listener, this case would prove nothing about it.
	_, done := startServe(t, newFailingListener(boom), New(nil), Options{ShutdownTimeout: time.Second})

	err := awaitServe(t, done, 2*time.Second)
	if !errors.Is(err, boom) {
		t.Fatalf("Serve() error = %v, want %v", err, boom)
	}
}

// TestTheServerClosedSentinelFromTheListenerIsNotAFailure covers the
// errors.Is(err, http.ErrServerClosed) arm of the serve-first branch.
//
// REACHABILITY. Nothing in this package can put that sentinel on that branch in
// production: http.Server only returns ErrServerClosed after Shutdown or Close,
// and both are called solely from the cancellation branch, which has already
// been selected by then. The arm is defensive — it keeps a listener that
// reports the sentinel itself from being logged as a startup failure — so the
// fixture supplies the sentinel directly. It differs from the case above in
// exactly one respect: the error the listener reports.
func TestTheServerClosedSentinelFromTheListenerIsNotAFailure(t *testing.T) {
	_, done := startServe(t, newFailingListener(http.ErrServerClosed), New(nil), Options{ShutdownTimeout: time.Second})

	if err := awaitServe(t, done, 2*time.Second); err != nil {
		t.Fatalf("Serve() error = %v, want nil for the server-closed sentinel", err)
	}
}

// TestAnInFlightRequestCompletesAfterTheListenerIsClosed pins the difference
// between Shutdown and Close. Swapping one for the other leaves every other
// test in this package passing, and severs a signing response mid-flight.
func TestAnInFlightRequestCompletesAfterTheListenerIsClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()

	const body = "operation-completed"
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseHandler := func() { releaseOnce.Do(func() { close(release) }) }
	// Cleanup as well as the explicit release below: an early t.Fatal must not
	// strand the handler, which would then log after the test completed and
	// turn a clean failure into a panic.
	t.Cleanup(releaseHandler)
	var handlerTimedOut atomic.Bool
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		select {
		case <-release:
		case <-time.After(5 * time.Second):
			handlerTimedOut.Store(true)
		}
		_, _ = io.WriteString(writer, body)
	})

	cancel, done := startServe(t, listener, handler, Options{ShutdownTimeout: 10 * time.Second})

	type result struct {
		body string
		err  error
	}
	responses := make(chan result, 1)
	transport := clientTransport(t)
	requestCtx := requestContext(t)
	go func() {
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+address+"/", nil)
		if requestErr != nil {
			responses <- result{err: requestErr}
			return
		}
		response, requestErr := transport.RoundTrip(request)
		if requestErr != nil {
			responses <- result{err: requestErr}
			return
		}
		defer func() { _ = response.Body.Close() }()
		received, requestErr := io.ReadAll(response.Body)
		responses <- result{body: string(received), err: requestErr}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran; the request did not reach the server")
	}

	// Cancel, then wait for the listener to actually be closed. Releasing the
	// handler only after a fresh connection is refused proves the response was
	// still outstanding when shutdown began, rather than having raced ahead of
	// it.
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for !refused(t, address) {
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting connections after cancellation")
		}
		time.Sleep(5 * time.Millisecond)
	}
	releaseHandler()

	select {
	case got := <-responses:
		if got.err != nil {
			t.Fatalf("in-flight request failed during shutdown: %v", got.err)
		}
		if got.body != body {
			t.Fatalf("in-flight response body = %q, want %q", got.body, body)
		}
		if handlerTimedOut.Load() {
			t.Fatal("handler was freed by its own timeout, not by the test observing shutdown")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	if err := awaitServe(t, done, 5*time.Second); err != nil {
		t.Fatalf("Serve() error = %v, want nil after a graceful shutdown", err)
	}
}

// TestAShutdownThatOutlivesItsBudgetIsBoundedAndReportsTheDeadline covers the
// Shutdown-error arm: a handler that will not return must not hold the process
// open past the configured budget, and the caller must be told why it did not
// finish cleanly.
func TestAShutdownThatOutlivesItsBudgetIsBoundedAndReportsTheDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()

	started := make(chan struct{})
	release := make(chan struct{})
	var released atomic.Bool
	t.Cleanup(func() {
		released.Store(true)
		close(release)
	})
	handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(writer, "too late")
	})

	// One respect separates this from the graceful case above: the budget is
	// shorter than the handler, instead of longer.
	cancel, done := startServe(t, listener, handler, Options{ShutdownTimeout: 150 * time.Millisecond})

	transport := clientTransport(t)
	requestCtx := requestContext(t)
	abandoned := make(chan error, 1)
	go func() {
		request, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://"+address+"/", nil)
		if requestErr != nil {
			abandoned <- requestErr
			return
		}
		response, requestErr := transport.RoundTrip(request)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}
		abandoned <- requestErr
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("handler never ran; the request did not reach the server")
	}

	cancel()
	err = awaitServe(t, done, 5*time.Second)
	if released.Load() {
		t.Fatal("Serve() returned only after the handler was released; the budget was not what bounded it")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Serve() error = %v, want %v", err, context.DeadlineExceeded)
	}

	// Shutdown times out with the connection still established; only the Close
	// fallback severs it. Without that call Serve still returns here — closing
	// the listener is enough for that — so the abandoned caller is the one
	// thing that distinguishes the two, and a KMS on its way out must not leave
	// a caller holding an open socket to a server that will never answer.
	select {
	case clientErr := <-abandoned:
		if clientErr == nil {
			t.Fatal("abandoned request succeeded; the handler was supposed to still be blocked")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned connection was left open after the shutdown budget expired")
	}
	if released.Load() {
		t.Fatal("the handler was released before the connection outcome was observed")
	}
}
