package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The custody manifest says which physical key each logical object is, so a file another user can
// rewrite is a file that reassigns keys. It is the third of the daemon's three loaders to be held
// to this rule -- auth.LoadPolicyFile and policy.LoadFile are the others -- and the three now state
// the same guarantee in the same words, which is the point: an operator hardening a deployment
// should not have to discover that one of them is laxer.
func TestTheManifestFileMustNotBeWritableByAnyoneElse(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "custody-manifest.json")
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	health := &healthMap{states: map[string]bool{}}

	loaded, err := LoadFile(path, "sitea", health)
	if err != nil || loaded == nil {
		t.Fatalf("the shipped example failed to load: %v", err)
	}

	for _, test := range []struct {
		name  string
		mode  os.FileMode
		wants string
	}{
		{"group-writable", 0o620, "group- or world-writable"},
		{"world-writable", 0o602, "group- or world-writable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			_, err := LoadFile(path, "sitea", health)
			if err == nil {
				t.Fatalf("a %s manifest loaded: whoever can write it decides which physical key each object is", test.name)
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("%s: error = %q, want the writability refusal", test.name, err)
			}
		})
	}

	t.Run("readable by others is fine", func(t *testing.T) {
		// The manifest is an inventory, not a secret: it names slots and fingerprints, never key
		// material. Refusing a world-readable one would make ordinary deployments unloadable.
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path, "sitea", health); err != nil {
			t.Fatalf("a world-readable manifest was refused: %v", err)
		}
	})

	t.Run("a directory is refused by the regular-file rule", func(t *testing.T) {
		// Asserted on the message: without the IsRegular check the read fails anyway, so "an error
		// came back" cannot tell whether the rule exists.
		_, err := LoadFile(directory, "sitea", health)
		if err == nil {
			t.Fatal("a directory loaded as a manifest")
		}
		if !strings.Contains(err.Error(), "must be a regular file") {
			t.Fatalf("error = %q, want the regular-file refusal", err)
		}
	})

	t.Run("a missing manifest", func(t *testing.T) {
		if _, err := LoadFile(filepath.Join(directory, "absent.json"), "sitea", health); err == nil {
			t.Fatal("a missing manifest loaded: the daemon would start routing to nothing")
		}
	})
}

// TestBackendHealthMustBeAttachedBeforeTheRegistryCanServe.
//
// Route() treats a missing probe the same as an unhealthy backend, so a registry wired without one
// refuses every request with BACKEND_UNAVAILABLE -- retryable, and blaming hardware that is fine.
// HasBackendHealth is what lets the daemon turn that into a startup error instead.
func TestBackendHealthMustBeAttachedBeforeTheRegistryCanServe(t *testing.T) {
	registry, err := Load(strings.NewReader(manifest(object("production-sops", "sops-data-key", "secp256k1", "sign",
		binding("sitea", "nitrokey-pkcs11", "hsm-1", "slot-1", "active")+","+
			binding("siteb", "nitrokey-pkcs11", "hsm-2", "slot-2", "standby")))), "sitea", nil)
	if err != nil {
		t.Fatal(err)
	}

	if registry.HasBackendHealth() {
		t.Fatal("a registry loaded with a nil probe reports one attached")
	}
	if _, err := registry.Route(context.Background(), "production-sops", "sops-data-key", "sign"); !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("Route() error = %v with no probe, want dependency-unavailable", err)
	}

	registry.SetBackendHealth(&healthMap{states: map[string]bool{"hsm-1": true}})
	if !registry.HasBackendHealth() {
		t.Fatal("SetBackendHealth did not attach the probe")
	}
	if _, err := registry.Route(context.Background(), "production-sops", "sops-data-key", "sign"); err != nil {
		t.Fatalf("Route() error = %v after attaching a healthy probe", err)
	}

	var nilRegistry *Registry
	nilRegistry.SetBackendHealth(&healthMap{})
	if nilRegistry.HasBackendHealth() {
		t.Fatal("a nil registry reports a probe attached")
	}
}

// TestDeclaredPoliciesReportsEveryObjectOnceInAStableOrder. Preflight compares this against the
// policy engine to catch an object the manifest declares and no policy governs. A missing entry is
// an object nobody checks; an unstable order makes the comparison undiffable between runs.
func TestDeclaredPoliciesReportsEveryObjectOnceInAStableOrder(t *testing.T) {
	// FOUR objects, not two. Go randomises map iteration, so with two the unsorted order is correct
	// half the time and a mutation removing the sort would only be caught on half of runs — a
	// falsification that reports success by coin flip is not one. With four the chance is 1 in 24,
	// and the assertion below checks the whole sequence rather than the ends.
	//
	// Each object also needs its own slots: the loader refuses two objects assigned to one.
	names := []string{"zulu-object", "mike-object", "delta-object", "alpha-object"}
	objects := make([]string, 0, len(names))
	for index, name := range names {
		slot := fmt.Sprintf("slot-%d", index*2+1)
		standby := fmt.Sprintf("slot-%d", index*2+2)
		objects = append(objects, object(name, "sops-data-key", "secp256k1", "sign",
			binding("sitea", "nitrokey-pkcs11", "hsm-1", slot, "active")+","+
				binding("siteb", "nitrokey-pkcs11", "hsm-2", standby, "standby")))
	}
	registry, err := Load(strings.NewReader(manifest(strings.Join(objects, ","))),
		"sitea", &healthMap{states: map[string]bool{"hsm-1": true}})
	if err != nil {
		t.Fatal(err)
	}

	declared := registry.DeclaredPolicies()
	if len(declared) != len(names) {
		t.Fatalf("DeclaredPolicies() reported %d objects, want %d: %+v", len(declared), len(names), declared)
	}
	want := []string{"alpha-object", "delta-object", "mike-object", "zulu-object"}
	for index, item := range declared {
		if item.ObjectID != want[index] {
			t.Fatalf("position %d is %q, want %q — preflight's output would reorder between runs: %+v",
				index, item.ObjectID, want[index], declared)
		}
	}
	for _, item := range declared {
		if item.PolicyID == "" {
			t.Fatalf("%s reported no policy id: preflight would compare against the empty string and find no engine policy matching", item.ObjectID)
		}
		if len(item.Operations) == 0 {
			t.Fatalf("%s reported no operations", item.ObjectID)
		}
	}

	var nilRegistry *Registry
	if got := nilRegistry.DeclaredPolicies(); got != nil {
		t.Fatalf("a nil registry reported %+v", got)
	}
}
