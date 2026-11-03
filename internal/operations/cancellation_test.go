package operations

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type delayedHardware struct {
	started           chan struct{}
	release           chan struct{}
	data, aad, output []byte
}

func (h *delayedHardware) Execute(_ context.Context, _ registry.Route, _, _, _ string, data, aad []byte) ([]byte, string, error) {
	h.data, h.aad = data, aad
	close(h.started)
	<-h.release // Model middleware that cannot immediately stop on cancellation.
	h.output = []byte("late sensitive result")
	return h.output, "application/octet-stream", nil
}

type observedRunner struct {
	*executor.Executor
	done chan struct{}
}

func (r observedRunner) Run(ctx context.Context, op func(context.Context) error) error {
	return r.Executor.Run(ctx, func(ctx context.Context) error {
		defer close(r.done)
		return op(ctx)
	})
}

func cancellationCoordinator(t *testing.T, runner Runner, hardware Hardware) *Coordinator {
	t.Helper()
	c, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", Binding: registry.Binding{DeviceID: "synthetic"}}}, &fakePolicy{decision: policy.Decision{Allowed: true}}, &fakeAudit{}, runner, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCoordinatorCancellationOwnsInputsAndDiscardsLateOutput(t *testing.T) {
	h := &delayedHardware{started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(h.release) }) }
	t.Cleanup(release)
	r := observedRunner{Executor: executor.New(1, time.Minute), done: make(chan struct{})}
	c := cancellationCoordinator(t, r, h)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := operationRequest()
	request.EnvelopeAAD = []byte("synthetic authenticated context")
	data, aad := bytes.Clone(request.Data), bytes.Clone(request.EnvelopeAAD)
	returned := make(chan error, 1)
	go func() {
		result, err := c.Execute(ctx, request)
		if len(result.Data) != 0 {
			returned <- errors.New("canceled request released output")
			return
		}
		returned <- err
	}()
	select {
	case <-h.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	cancel()
	select {
	case err := <-returned:
		var failure *api.Failure
		if !errors.As(err, &failure) || failure.Code != "CANCELED" || failure.Retryable {
			t.Fatal("cancellation classification changed")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation waited for blocked middleware")
	}
	// This is the API handler's deferred cleanup after Execute returns.
	clear(request.Data)
	clear(request.EnvelopeAAD)
	if !bytes.Equal(h.data, data) || !bytes.Equal(h.aad, aad) {
		t.Error("caller cleanup corrupted an in-flight worker's inputs")
	}
	var busy *executor.Error
	if err := r.Executor.Run(context.Background(), func(context.Context) error { t.Error("abandoned worker released its slot early"); return nil }); !errors.As(err, &busy) || busy.Code != executor.CodeBusy {
		t.Error("hardware concurrency cap was not retained")
	}
	release()
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
	for _, secret := range [][]byte{h.data, h.aad, h.output} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Error("late worker input/result was not cleared")
		}
	}
}

type aliasHardware struct{}

func (aliasHardware) Execute(_ context.Context, _ registry.Route, _, _, _ string, data, _ []byte) ([]byte, string, error) {
	return data, "application/octet-stream", nil
}

func TestCoordinatorReturnedResultOwnsAliasedBackendOutput(t *testing.T) {
	c := cancellationCoordinator(t, directRunner{}, aliasHardware{})
	request := operationRequest()
	expected := bytes.Clone(request.Data)
	result, err := c.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clear(request.Data)
	if !bytes.Equal(result.Data, expected) {
		t.Fatal("caller/worker input cleanup corrupted the returned result")
	}
	clear(result.Data)
}

type queuedRunner struct{ operation func(context.Context) error }

func (r *queuedRunner) Run(_ context.Context, operation func(context.Context) error) error {
	r.operation = operation
	return &executor.Error{Code: executor.CodeCanceled}
}

func TestCoordinatorAbandonedUndispatchedWorkerNeverTouchesHardware(t *testing.T) {
	r := &queuedRunner{}
	h := &fakeHardware{output: []byte("not released")}
	c := cancellationCoordinator(t, r, h)
	result, err := c.Execute(context.Background(), operationRequest())
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Code != "CANCELED" || len(result.Data) != 0 {
		t.Fatal("undispatched cancellation returned an unexpected result")
	}
	// A worker can be scheduled after Run has already returned on cancellation.
	if err := r.operation(context.Background()); !errors.Is(err, context.Canceled) || h.calls != 0 {
		t.Fatal("abandoned undispatched worker reached hardware")
	}
}
