package openbaopoc

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Test-only immutable generation map; promotion never replaces material under
// the same name. Physical identity pinning remains separate qualification.
type generationRSA struct{ keys map[string]*rsa.PrivateKey }

func (s generationRSA) Execute(ctx context.Context, route registry.Route, op, format, content string, data, aad []byte) ([]byte, string, error) {
	key := s.keys[route.KEKVersion]
	if key == nil {
		return nil, "", backend.ErrUnavailable
	}
	return (softwareRSA{key}).Execute(ctx, route, op, format, content, data, aad)
}
func (generationRSA) Healthy(context.Context, registry.Binding) bool { return true }
func (generationRSA) Ready(context.Context) bool                     { return true }

type switchingRegistry struct {
	mu       sync.RWMutex
	registry *registry.Registry
}

func (r *switchingRegistry) Digest() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registry.Digest()
}

func (r *switchingRegistry) Route(ctx context.Context, object, purpose, op string) (registry.Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registry.Route(ctx, object, purpose, op)
}
func (r *switchingRegistry) RouteForSeal(ctx context.Context, object, purpose string) (registry.Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registry.RouteForSeal(ctx, object, purpose)
}
func (r *switchingRegistry) RouteForUnwrap(ctx context.Context, object, purpose, version string) (registry.Route, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.registry.RouteForUnwrap(ctx, object, purpose, version)
}

func generationManifest(firstState, secondState string) string {
	return fmt.Sprintf(`{"schema_version":1,"manifest_id":"synthetic-generations","generated_at":"2026-10-02T00:00:00Z","objects":[{"id":"poc-seal-key","name":"Synthetic versioned seal","kind":"opaque-secret","classification":"restricted","environment":"development","owner":"fixture","purpose":"openbao-seal","custody":"direct-hardware","algorithm":"opaque","operations":["seal-envelope","release-secret"],"policy_id":"poc-policy","bindings":[
{"site":"poc-site","backend":"nitrokey-pkcs11","device_id":"software-g1","device_serial":"synthetic-g1","devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_id":"01","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","kek_algorithm":"rsa2048","kek_version":"g1","state":%q},
{"site":"poc-site","backend":"nitrokey-pkcs11","device_id":"software-g2","device_serial":"synthetic-g2","devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_id":"02","public_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","kek_algorithm":"rsa2048","kek_version":"g2","state":%q}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`, firstState, secondState)
}

func (f *kmsFixture) generations(firstState, secondState string) {
	f.t.Helper()
	next, err := registry.Load(strings.NewReader(generationManifest(firstState, secondState)), "poc-site", f.hardware)
	if err != nil {
		f.t.Fatal(err)
	}
	f.router.mu.Lock()
	f.router.registry = next
	f.router.mu.Unlock()
}

func (s *fixtureAudit) outcomes(operation, outcome string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, event := range s.events {
		if event.Operation == operation && event.Outcome == outcome {
			n++
		}
	}
	return n
}
