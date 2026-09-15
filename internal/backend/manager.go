package backend

import (
	"context"
	"errors"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

var ErrUnavailable = errors.New("hardware backend unavailable")

type Provider interface {
	Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error)
	Healthy(context.Context, registry.Binding) bool
	Ready(context.Context) bool
}

type Manager struct{ providers map[string]Provider }

func New(providers map[string]Provider) (*Manager, error) {
	if len(providers) == 0 {
		return nil, errors.New("hardware providers are required")
	}
	copy := make(map[string]Provider, len(providers))
	for name, provider := range providers {
		if name == "" || provider == nil {
			return nil, errors.New("invalid hardware provider")
		}
		copy[name] = provider
	}
	return &Manager{providers: copy}, nil
}

// Serves reports whether this manager has a provider for a named backend. The daemon uses it to
// refuse a key registry that routes somewhere it cannot reach.
func (manager *Manager) Serves(backend string) bool {
	if manager == nil || manager.providers == nil {
		return false
	}
	_, present := manager.providers[backend]
	return present
}

func (manager *Manager) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) (output []byte, outputType string, err error) {
	// Ready already guards the nil receiver; Execute and Healthy would have panicked instead. A
	// panic in the one place that reaches the token is the worst of the three outcomes: it is not
	// fail-closed, it is fail-unpredictable.
	if manager == nil || manager.providers == nil {
		return nil, "", ErrUnavailable
	}
	provider := manager.providers[route.Binding.Backend]
	if provider == nil {
		return nil, "", ErrUnavailable
	}
	defer func() {
		if recover() != nil {
			// zero(output) reaches nothing today and is kept deliberately. `output` is assigned
			// from the call below, and a panic inside the provider means that assignment never
			// completes -- measured by instrumenting this recover, which sees len(output) == 0
			// even when the provider sets its return values and panics from its own deferred
			// function. It stays because a later change that assigns output before a point that
			// can panic would need it, and because removing it invites adding it back without
			// this note. Nothing should test it as though it fires.
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
	}()
	output, outputType, err = provider.Execute(ctx, route, operation, format, contentType, data, aad)
	if err != nil {
		zero(output)
		return nil, "", ErrUnavailable
	}
	return output, outputType, nil
}

func (manager *Manager) Healthy(ctx context.Context, binding registry.Binding) (healthy bool) {
	if manager == nil || manager.providers == nil {
		return false
	}
	provider := manager.providers[binding.Backend]
	if provider == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			healthy = false
		}
	}()
	return provider.Healthy(ctx, binding)
}

func (manager *Manager) Ready(ctx context.Context) bool {
	if manager == nil || len(manager.providers) == 0 {
		return false
	}
	for _, provider := range manager.providers {
		if !safeReady(ctx, provider) {
			return false
		}
	}
	return true
}

func safeReady(ctx context.Context, provider Provider) (healthy bool) {
	defer func() {
		if recover() != nil {
			healthy = false
		}
	}()
	return provider.Ready(ctx)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
