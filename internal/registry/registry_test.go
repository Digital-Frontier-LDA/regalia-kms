package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRepositoryManifestLoadsAsUncommissionedRegistry(t *testing.T) {
	// LoadFile refuses a group- or world-writable manifest, and a checked-out file carries
	// whatever mode the developer's umask left it, so stage the example at 0600 first.
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "custody-manifest.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := LoadFile(path, "sitea", &healthMap{states: map[string]bool{}})
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if registry.Ready(context.Background()) {
		t.Fatal("example contains only planned bindings and must not be ready")
	}
	if !strings.HasPrefix(registry.Digest(), "sha256:") {
		t.Fatalf("Digest() = %q", registry.Digest())
	}
}

type healthMap struct {
	mu     sync.Mutex
	states map[string]bool
	calls  []string
}

func (health *healthMap) Healthy(_ context.Context, binding Binding) bool {
	health.mu.Lock()
	defer health.mu.Unlock()
	health.calls = append(health.calls, binding.DeviceID)
	return health.states[binding.DeviceID]
}

func manifest(objects string) string {
	return fmt.Sprintf(`{"schema_version":1,"manifest_id":"test-registry","generated_at":"2026-09-03T00:00:00Z","objects":[%s]}`, objects)
}

func object(id, purpose, algorithm, operation, bindings string) string {
	return fmt.Sprintf(`{
		"id":%q,"name":"Test key","kind":"asymmetric-key","classification":"critical","environment":"production",
		"owner":"security","purpose":%q,"custody":"direct-hardware","algorithm":%q,
		"operations":[%q],"policy_id":"test-policy","bindings":[%s],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}
	}`, id, purpose, algorithm, operation, bindings)
}

func binding(site, backend, device, slot, state string) string {
	extra := ""
	if backend == "yubikey-piv" || backend == "yubikey-openpgp" {
		extra = `,"pin_policy":"once","touch_policy":"never"`
		if state != "planned" && state != "retired" {
			extra += `,"device_serial":"yubi-test-serial"`
		}
	} else if backend == "nitrokey-pkcs11" && state != "planned" && state != "retired" {
		extra = `,"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`
	}
	return fmt.Sprintf(`{"site":%q,"backend":%q,"device_id":%q,"object_id":%q,"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":%q%s}`,
		site, backend, device, slot, state, extra)
}

func TestRouteSelectsOnlyActiveBindingAtConfiguredSite(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "active")
	health := &healthMap{states: map[string]bool{"local-hsm": true, "remote-hsm": true}}
	registry, err := Load(strings.NewReader(manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))), "sitea", health)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	route, err := registry.Route(context.Background(), "wallet-key", "cosmos-transaction", "sign")
	if err != nil {
		t.Fatalf("Route() error = %v", err)
	}
	if route.Binding.DeviceID != "local-hsm" || route.Binding.ObjectID != "01" {
		t.Fatalf("route = %#v", route)
	}
}

func TestRouteNeverFallsBackFromUnhealthyAssignedDevice(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "active")
	health := &healthMap{states: map[string]bool{"local-hsm": false, "remote-hsm": true}}
	registry, err := Load(strings.NewReader(manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))), "sitea", health)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.Route(context.Background(), "wallet-key", "cosmos-transaction", "sign")
	if !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("Route() error = %v", err)
	}
	if len(health.calls) != 1 || health.calls[0] != "local-hsm" {
		t.Fatalf("health calls = %v; remote fallback attempted", health.calls)
	}
}

func TestRouteDeniesWrongPurposeAndOperation(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "standby")
	registry, err := Load(strings.NewReader(manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))), "sitea", &healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ purpose, operation string }{{"release-artifact", "sign"}, {"cosmos-transaction", "unwrap"}} {
		if _, err := registry.Route(context.Background(), "wallet-key", test.purpose, test.operation); !IsCode(err, CodeDenied) {
			t.Fatalf("Route(%q, %q) error = %v", test.purpose, test.operation, err)
		}
	}
}

func TestLoadRejectsAmbiguousDuplicateUnsupportedAndIncompatibleEntries(t *testing.T) {
	validBindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," + binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "standby")
	tests := map[string]string{
		"duplicate id":        manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", validBindings) + "," + object("wallet-key", "other-purpose", "secp256k1", "sign", binding("sitea", "nitrokey-pkcs11", "other", "02", "active"))),
		"ambiguous local":     manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", binding("sitea", "nitrokey-pkcs11", "one", "01", "active")+","+binding("sitea", "nitrokey-pkcs11", "two", "01", "active"))),
		"software backend":    manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", binding("sitea", "software", "host", "file", "active"))),
		"capability mismatch": manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", binding("sitea", "fido2", "fido", "credential", "active"))),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(strings.NewReader(input), "sitea", &healthMap{}); err == nil {
				t.Fatal("Load() unexpectedly succeeded")
			}
		})
	}
}

func TestReadinessTracksAssignedDeviceHealth(t *testing.T) {
	health := &healthMap{states: map[string]bool{"local-hsm": false}}
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," + binding("siteb", "nitrokey-pkcs11", "remote", "01", "standby")
	registry, err := Load(strings.NewReader(manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))), "sitea", health)
	if err != nil {
		t.Fatal(err)
	}
	if registry.Ready(context.Background()) {
		t.Fatal("Ready() = true with failed assigned device")
	}
	health.states["local-hsm"] = true
	if !registry.Ready(context.Background()) {
		t.Fatal("Ready() = false after assigned device recovery")
	}
	if registry.Digest() == "" {
		t.Fatal("registry digest is empty")
	}
}

// THE DIGEST IS WHAT BINDS A SIGNING LEASE TO ONE MANIFEST, AND NOTHING CHECKED THAT IT BOUND.
//
// registry.go sets `digest: digest(contents)` from the manifest bytes; cmd/regalia-kms passes
// keyRegistry.Digest() into fencing.Open; and gate.go refuses a lease whose RegistryDigest does
// not equal the gate's. So this string is the reason a site cannot activate on a lease that was
// issued against a different custody manifest.
//
// The tests above assert its SHAPE — `strings.HasPrefix(Digest(), "sha256:")` and non-empty. Both
// pass for a function that ignores its input and returns a constant, and so does the entire kms
// suite: replacing digest()'s body with a fixed 32 zero bytes compiles clean and `go test ./...`
// exits 0. Every manifest would then share one digest, every lease would satisfy every gate, and
// the binding would be gone with nothing red.
//
// Both directions are asserted deliberately. "Different manifests differ" alone is satisfied by a
// random digest, which would make the gate refuse every legitimate lease — an availability
// failure instead of a security one, and just as wrong. Determinism is the other half of the
// property, not a separate nicety.
func TestTheRegistryDigestBindsTheManifestContents(t *testing.T) {
	health := &healthMap{states: map[string]bool{}}
	load := func(t *testing.T, body string) *Registry {
		t.Helper()
		loaded, err := Load(strings.NewReader(body), "sitea", health)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		return loaded
	}

	pair := binding("sitea", "nitrokey-pkcs11", "hsm-1", "01", "planned") + "," +
		binding("siteb", "nitrokey-pkcs11", "hsm-2", "02", "planned")
	base := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", pair))
	// One field of difference, in a value the loader keeps: a different object id.
	altered := manifest(object("wallet-key-2", "cosmos-transaction", "secp256k1", "sign", pair))

	first, second := load(t, base).Digest(), load(t, altered).Digest()
	if first == second {
		t.Fatalf("two manifests with different contents share the digest %q — the digest does not "+
			"bind the manifest, so a lease issued against one custody manifest would activate a "+
			"site running another", first)
	}

	// Determinism: the same bytes must produce the same digest, or every gate refuses every
	// lease it should accept.
	if again := load(t, base).Digest(); again != first {
		t.Fatalf("the same manifest produced %q then %q — a non-deterministic digest makes the "+
			"fencing gate refuse leases that are legitimately bound to it", first, again)
	}
}
