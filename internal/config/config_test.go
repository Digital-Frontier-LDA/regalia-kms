package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDecodeValidConfiguration(t *testing.T) {
	input := `{
		"listen_address":"127.0.0.1:8443",
		"registry_path":"config/custody-manifest.example.json",
		"rbac_policy_path":"config/rbac.example.json",
		"policy_path":"config/policy.example.json",
		"policy_state_path":"/var/lib/regalia-kms/policy-state.jsonl",
		"site":"sitea",
		"operation_timeout":"15s",
		"shutdown_timeout":"10s",
		"max_concurrent_operations":4
	}`

	got, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.ListenAddress != "127.0.0.1:8443" {
		t.Fatalf("ListenAddress = %q", got.ListenAddress)
	}
	if got.RegistryPath != "config/custody-manifest.example.json" || got.Site != "sitea" {
		t.Fatalf("registry configuration = %q/%q", got.RegistryPath, got.Site)
	}
	if got.RBACPolicyPath != "config/rbac.example.json" {
		t.Fatalf("RBACPolicyPath = %q", got.RBACPolicyPath)
	}
	if got.PolicyPath != "config/policy.example.json" || got.PolicyStatePath != "/var/lib/regalia-kms/policy-state.jsonl" {
		t.Fatalf("policy configuration = %q/%q", got.PolicyPath, got.PolicyStatePath)
	}
	if got.OperationTimeout != 15*time.Second {
		t.Fatalf("OperationTimeout = %s", got.OperationTimeout)
	}
	if got.ShutdownTimeout != 10*time.Second {
		t.Fatalf("ShutdownTimeout = %s", got.ShutdownTimeout)
	}
	if got.MaxConcurrentOperations != 4 {
		t.Fatalf("MaxConcurrentOperations = %d", got.MaxConcurrentOperations)
	}
}

func TestLoadRejectsWritableConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() unexpectedly accepted group/world-writable file")
	}
}

func TestDecodeRejectsUnknownAndTrailingData(t *testing.T) {
	tests := []string{
		`{"listen_address":"127.0.0.1:8443","operation_timeout":"15s","shutdown_timeout":"10s","max_concurrent_operations":4,"pin":"123456"}`,
		`{"listen_address":"127.0.0.1:8443","operation_timeout":"15s","shutdown_timeout":"10s","max_concurrent_operations":4} {}`,
	}
	for _, input := range tests {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("Decode(%q) unexpectedly succeeded", input)
		}
	}
}

func TestDecodeRejectsUnsafeValues(t *testing.T) {
	tests := map[string]string{
		"non-loopback":          `{"listen_address":"0.0.0.0:8443","operation_timeout":"15s","shutdown_timeout":"10s","max_concurrent_operations":4}`,
		"zero workers":          `{"listen_address":"127.0.0.1:8443","operation_timeout":"15s","shutdown_timeout":"10s","max_concurrent_operations":0}`,
		"long operation":        `{"listen_address":"127.0.0.1:8443","operation_timeout":"11m","shutdown_timeout":"10s","max_concurrent_operations":4}`,
		"short shutdown":        `{"listen_address":"127.0.0.1:8443","operation_timeout":"15s","shutdown_timeout":"100ms","max_concurrent_operations":4}`,
		"registry without site": `{"registry_path":"manifest.json"}`,
		"policy without state":  `{"policy_path":"policy.json"}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatal("Decode() unexpectedly succeeded")
			}
		})
	}
}

func TestDecodeAppliesSafeDefaults(t *testing.T) {
	got, err := Decode(strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got.ListenAddress == "" || got.OperationTimeout <= 0 || got.ShutdownTimeout <= 0 || got.MaxConcurrentOperations <= 0 {
		t.Fatalf("unsafe defaults: %#v", got)
	}
}

// THE READER LIST IS PART OF THE AUTHENTICATION DESIGN, SO IT IS VALIDATED.
//
// A metrics reader that can never authenticate is a silent no-op; a config that
// silently ignores the field would leave an operator believing the endpoint is
// authorized when it is not wired at all. Strict decode already refuses unknown
// fields; these rules refuse unusable values.
func TestMetricsReaderPrincipalsAreValidated(t *testing.T) {
	config, err := Decode(strings.NewReader(`{"metrics_reader_principals":["spiffe://regalia/operator/monitoring"]}`))
	if err != nil {
		t.Fatalf("a valid reader list was refused: %v", err)
	}
	if len(config.MetricsReaderPrincipals) != 1 || config.MetricsReaderPrincipals[0] != "spiffe://regalia/operator/monitoring" {
		t.Fatalf("MetricsReaderPrincipals = %v", config.MetricsReaderPrincipals)
	}
	for name, input := range map[string]string{
		"outside the trust domain": `{"metrics_reader_principals":["spiffe://other/operator/monitoring"]}`,
		"not a SPIFFE identity":    `{"metrics_reader_principals":["monitoring"]}`,
		"empty":                    `{"metrics_reader_principals":[""]}`,
		"duplicated":               `{"metrics_reader_principals":["spiffe://regalia/operator/monitoring","spiffe://regalia/operator/monitoring"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(input)); err == nil {
				t.Fatalf("%s was accepted: it can never authenticate, so the config would be a silent no-op", name)
			}
		})
	}
}
