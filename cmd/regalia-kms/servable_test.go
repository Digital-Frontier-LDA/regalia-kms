package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type stubProvider struct{}

func (stubProvider) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	return []byte("x"), "application/octet-stream", nil
}
func (stubProvider) Healthy(context.Context, registry.Binding) bool { return true }
func (stubProvider) Ready(context.Context) bool                     { return true }

// A ROUTING TABLE THAT NAMES A BACKEND THE DAEMON CANNOT REACH IS A STARTUP ERROR.
//
// The registry has capability entries for yubikey-piv and yubikey-openpgp and will route to them,
// while buildHardware only ever constructs a nitrokey-pkcs11 provider. Nothing compared the two. An
// operator could bind a key to a YubiKey, watch the custody manifest validate and the daemon start
// clean, and then have every operation on that key fail as DEPENDENCY_UNAVAILABLE — fail-closed,
// but discovered one request at a time, at the moment someone needed the key.
//
// The shipped example manifest is the proof this is not hypothetical: it binds objects to
// yubikey-piv and fido2 today.
func TestRegistryRoutingToAnUnservableBackendIsRefusedAtStartup(t *testing.T) {
	// The shipped example manifest is deliberately all "planned" bindings, so it activates nothing.
	// Activate the sitea ones to get a manifest that actually routes — which is the state a real
	// deployment is in, and the only state where this failure can happen.
	source, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	// Activate only the YubiKey-bound object. An active Nitrokey binding additionally requires a
	// pinned serial and DevAut fingerprint, which is not what this test is about — and one
	// unservable backend is the whole failure.
	objects, ok := document["objects"].([]any)
	if !ok {
		t.Fatalf("the example manifest has no objects array: this test's fixture assumptions no longer match the schema")
	}
	activatedBindings := 0
	for _, raw := range objects {
		object, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("manifest object is not a JSON object: the schema changed under this test")
		}
		if object["id"] != "release-signing-key" {
			continue
		}
		bindings, ok := object["bindings"].([]any)
		if !ok {
			t.Fatalf("object %v has no bindings array: the schema changed under this test", object["id"])
		}
		for _, rawBinding := range bindings {
			binding, ok := rawBinding.(map[string]any)
			if !ok {
				t.Fatalf("binding is not a JSON object: the schema changed under this test")
			}
			if binding["site"] == "sitea" {
				binding["state"] = "active"
				// A commissioned YubiKey binding must pin the device serial.
				binding["device_serial"] = "12345678"
				activatedBindings++
			}
		}
	}
	if activatedBindings == 0 {
		t.Fatal("no sitea binding was activated: the fixture no longer produces the case under test")
	}
	activated, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("could not re-marshal the manifest fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, activated, 0o600); err != nil {
		t.Fatal(err)
	}

	keyRegistry, err := registry.LoadFile(path, "sitea", nil)
	if err != nil {
		t.Fatalf("activated example manifest does not load: %v", err)
	}
	required := keyRegistry.RequiredBackends()
	if len(required) == 0 {
		t.Fatal("the fixture activated no binding at all: this test is checking nothing")
	}
	servable := false
	for _, name := range required {
		if name == "yubikey-piv" {
			servable = true
		}
	}
	if !servable {
		t.Fatalf("the fixture routes to %v, not to the unservable backend this test exists for", required)
	}

	// What the daemon actually builds today.
	nitrokeyOnly, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": stubProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	err = bindBackendToRegistry(keyRegistry, nitrokeyOnly)
	if err == nil {
		t.Fatalf("a registry routing to %v was accepted with only nitrokey-pkcs11 available: those objects would fail at signing time", required)
	}
	for _, name := range required {
		if name == "nitrokey-pkcs11" {
			continue
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the startup error does not name the unservable backend %q: %v", name, err)
		}
	}

	// With every named backend present, the same registry must be accepted.
	complete := map[string]backend.Provider{}
	for _, name := range required {
		complete[name] = stubProvider{}
	}
	full, err := backend.New(complete)
	if err != nil {
		t.Fatal(err)
	}
	if err := bindBackendToRegistry(keyRegistry, full); err != nil {
		t.Fatalf("a fully served registry was refused: %v", err)
	}
}

// THE DAEMON MUST ATTACH A BACKEND HEALTH PROBE, OR IT SERVES NOTHING.
//
// registry.Route denies every object with DEPENDENCY_UNAVAILABLE while registry.health is nil, and
// Registry.Ready is false for the same reason. main loaded the registry with nil — it has to, since
// buildHardware needs the registry to resolve device bindings before a manager exists — and nothing
// ever replaced it. A fully configured daemon therefore refused every operation and was never
// ready, with no error logged anywhere: an unattached probe is indistinguishable from hardware that
// is down.
//
// This is the failure the reachability test cannot see. Nothing is unreachable here; a nil argument
// was passed to a reachable constructor and never updated.
func TestDaemonAttachesTheBackendHealthProbeToTheRegistry(t *testing.T) {
	keyRegistry, err := registry.LoadFile(shippedExample(t, "custody-manifest.example.json"), "sitea", nil)
	if err != nil {
		t.Fatal(err)
	}
	if keyRegistry.HasBackendHealth() {
		t.Fatal("the registry arrived with a health probe: this test cannot observe the wiring step")
	}

	manager, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": stubProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := bindBackendToRegistry(keyRegistry, manager); err != nil {
		t.Fatalf("binding the backend to the registry failed: %v", err)
	}
	if !keyRegistry.HasBackendHealth() {
		t.Fatal("the daemon did not attach a backend health probe: every operation would fail as DEPENDENCY_UNAVAILABLE and readiness would never be true")
	}
}

// And the underlying behaviour that makes the above matter: without a probe, routing denies.
func TestRegistryWithoutAHealthProbeDeniesEveryObject(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	objects, ok := document["objects"].([]any)
	if !ok {
		t.Fatal("manifest schema changed under this test")
	}
	var objectID, purpose string
	for _, raw := range objects {
		object := raw.(map[string]any)
		if object["id"] != "release-signing-key" {
			continue
		}
		objectID, _ = object["id"].(string)
		purpose, _ = object["purpose"].(string)
		for _, rawBinding := range object["bindings"].([]any) {
			binding := rawBinding.(map[string]any)
			if binding["site"] == "sitea" {
				binding["state"] = "active"
				binding["device_serial"] = "12345678"
			}
		}
	}
	activated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, activated, 0o600); err != nil {
		t.Fatal(err)
	}
	keyRegistry, err := registry.LoadFile(path, "sitea", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyRegistry.Route(context.Background(), objectID, purpose, "sign"); err == nil {
		t.Fatal("a registry with no health probe routed an object: the probe would be optional, and a daemon that forgot it would look healthy")
	}
	if keyRegistry.Ready(context.Background()) {
		t.Fatal("a registry with no health probe reported ready")
	}
}
