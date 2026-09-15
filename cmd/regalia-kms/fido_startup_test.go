package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// RECORDING A FIDO ENROLLMENT AT THE DEPLOYMENT'S OWN SITE MUST NOT STOP THE DAEMON STARTING.
//
// The startup check in bindBackendToRegistry refuses a registry that routes to backends this daemon
// cannot serve, and it is right to. But a FIDO credential is inventory: ADR-0001 §4 and API.md put
// human administrator authentication outside the cryptographic-operation surface, /v1/operations
// exposes no authenticate route, and no fido2 provider is ever constructed.
//
// Counting those bindings therefore turned doing the right thing into an outage. Issue #23 asks for
// two enrollments held in separate custody; the moment one custodian's `site` string matched a
// running daemon's, that daemon refused to start, reporting that operations on the object "would
// fail at signing time" — an object nothing signs, on a machine whose hardware had not changed.
//
// Measured on the shipped example manifest before the fix: RequiredBackends() = [fido2], startup
// refused. The example escaped only because its sites are named custodian-a/custodian-b and both
// bindings are planned, and neither of those is a rule.
func TestAnActiveFIDOEnrollmentAtTheDaemonSiteDoesNotBlockStartup(t *testing.T) {
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
		t.Fatal("the example manifest has no objects array: this test's fixture assumptions no longer match the schema")
	}
	moved := 0
	for _, raw := range objects {
		object, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("manifest object is not a JSON object: the schema changed under this test")
		}
		if object["custody"] != "fido-multi-enrollment" {
			continue
		}
		bindings, ok := object["bindings"].([]any)
		if !ok {
			t.Fatalf("FIDO object %v has no bindings array", object["id"])
		}
		// One custodian is at the SiteA site. The other stays elsewhere, because separate custody
		// is the whole point and moving both would break the manifest's own continuity rule.
		for _, rawBinding := range bindings {
			binding, ok := rawBinding.(map[string]any)
			if !ok {
				t.Fatal("binding is not a JSON object: the schema changed under this test")
			}
			if binding["site"] == "custodian-a" {
				binding["site"] = "sitea"
				binding["state"] = "active"
				moved++
			}
		}
	}
	if moved != 1 {
		t.Fatalf("moved %d FIDO bindings to the daemon site, want exactly 1: the example manifest no longer produces the case under test", moved)
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
		t.Fatalf("a FIDO enrollment recorded at the daemon's own site does not load: %v", err)
	}
	for _, name := range keyRegistry.RequiredBackends() {
		if name == "fido2" {
			t.Fatalf("DEFECT: RequiredBackends() = %v — the daemon demands a fido2 provider for a credential it never operates", keyRegistry.RequiredBackends())
		}
	}

	// What the daemon actually builds today.
	nitrokeyOnly, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": stubProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := bindBackendToRegistry(keyRegistry, nitrokeyOnly); err != nil {
		t.Fatalf("DEFECT: the daemon refuses to start because a FIDO enrollment is recorded at its own site: %v", err)
	}

	// THE CONTROL. Startup must still refuse a backend it genuinely cannot serve, or this test
	// would be satisfied by a guard that had simply been switched off.
	if err := os.WriteFile(path, unservableFixture(t, source), 0o600); err != nil {
		t.Fatal(err)
	}
	unservable, err := registry.LoadFile(path, "sitea", nil)
	if err != nil {
		t.Fatalf("the control fixture does not load: %v", err)
	}
	if err := bindBackendToRegistry(unservable, nitrokeyOnly); err == nil {
		t.Fatal("the unservable-backend guard no longer fires at all: the FIDO result above proves nothing")
	}
}

// unservableFixture activates the example's YubiKey-bound object at the daemon site, which is a
// backend the daemon really cannot serve.
func unservableFixture(t *testing.T, source []byte) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	objects, ok := document["objects"].([]any)
	if !ok {
		t.Fatal("the example manifest has no objects array: this control's fixture assumptions no longer match the schema")
	}
	activated := 0
	for _, raw := range objects {
		object, ok := raw.(map[string]any)
		if !ok {
			t.Fatal("manifest object is not a JSON object: the schema changed under this control")
		}
		if object["id"] != "release-signing-key" {
			continue
		}
		bindings, ok := object["bindings"].([]any)
		if !ok {
			t.Fatalf("object %v has no bindings array: the schema changed under this control", object["id"])
		}
		for _, rawBinding := range bindings {
			binding, ok := rawBinding.(map[string]any)
			if !ok {
				t.Fatal("binding is not a JSON object: the schema changed under this control")
			}
			if binding["site"] == "sitea" {
				binding["state"] = "active"
				binding["device_serial"] = "12345678"
				activated++
			}
		}
	}
	if activated == 0 {
		t.Fatal("the control fixture activated no yubikey-piv binding: it would not exercise the guard")
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
