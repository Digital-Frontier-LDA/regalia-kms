package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// completeSettings builds a configuration whose every referenced file exists, using the shipped
// examples so the fixture cannot drift from what operators are told to copy.
func completeSettings(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	return config.Config{
		ListenAddress: "127.0.0.1:8443", Site: "sitea",
		RegistryPath:     shippedExample(t, "custody-manifest.example.json"),
		RBACPolicyPath:   shippedExample(t, "rbac.example.json"),
		PolicyPath:       shippedExample(t, "policy.example.json"),
		PolicyStatePath:  filepath.Join(dir, "policy-state.jsonl"),
		OperationTimeout: 15_000_000_000, ShutdownTimeout: 10_000_000_000, MaxConcurrentOperations: 4,
	}
}

// PREFLIGHT ANSWERS "WILL THIS START" WITHOUT STARTING.
//
// Every startup refusal the daemon accumulated — unservable backend, declared-vs-enforced policy,
// RBAC grants for absent objects, truncated journals — was reachable only by starting the daemon.
// On a KMS that is expensive: a restart drops the fencing lease and interrupts in-flight signing.
func TestPreflightPassesOnACompleteConfiguration(t *testing.T) {
	_, _, _, _, report, err := preflight(completeSettings(t))
	if err != nil {
		t.Fatalf("a complete configuration failed preflight: %v", err)
	}
	if len(report.Checked) < 6 {
		t.Fatalf("preflight reported only %d checks, so it is not exercising much: %v", len(report.Checked), report.Checked)
	}
	// It must say what it did NOT check. A green result that names no limits invites the reading
	// that the daemon will start, which is a stronger claim than preflight can make.
	if len(report.Unchecked) == 0 {
		t.Fatal("preflight reported nothing as unchecked, so a passing result cannot be told apart from a full guarantee")
	}
	joined := strings.Join(report.Unchecked, " ")
	if !strings.Contains(joined, "TLS") {
		t.Fatalf("the unchecked list does not mention TLS material: %v", report.Unchecked)
	}
}

// PREFLIGHT MUST NOT TAKE THE POLICY STATE LOCK. OpenFileState holds an exclusive flock for the
// process lifetime, so a preflight that took one could not be run against a live deployment — which
// is the only deployment whose configuration anybody urgently needs to check.
func TestPreflightRunsWhileTheDaemonHoldsThePolicyState(t *testing.T) {
	settings := completeSettings(t)
	state, err := policy.OpenFileState(settings.PolicyStatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()

	if _, _, _, _, _, err := preflight(settings); err != nil {
		t.Fatalf("preflight failed while a writer held the policy state journal: %v", err)
	}
}

// PREFLIGHT MUST NOT WRITE ANYTHING. It is run against production configuration by someone who has
// not decided to deploy yet.
func TestPreflightLeavesTheJournalAbsent(t *testing.T) {
	settings := completeSettings(t)
	if _, _, _, _, _, err := preflight(settings); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(settings.PolicyStatePath); !os.IsNotExist(err) {
		t.Fatalf("preflight created the policy state journal: it must not write to a deployment it is only inspecting (%v)", err)
	}
}

// The cross-document checks must run in preflight, not only at startup — that is the whole point.
func TestPreflightCatchesACrossDocumentDisagreement(t *testing.T) {
	settings := completeSettings(t)

	// A policy document that governs the objects under different ids than the manifest declares.
	source, err := os.ReadFile(settings.PolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	policies, ok := document["policies"].([]any)
	if !ok || len(policies) == 0 {
		t.Fatal("policy fixture has no policies")
	}
	policies[0].(map[string]any)["id"] = "renamed-under-the-manifest"
	altered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	settings.PolicyPath = path

	_, _, _, _, _, err = preflight(settings)
	if err == nil {
		t.Fatal("preflight accepted a manifest whose declared policy is not the one that governs: the daemon would have refused to start and preflight said it was fine")
	}
	if !strings.Contains(err.Error(), "actually governs") {
		t.Fatalf("the failure does not explain the disagreement: %v", err)
	}
}

var _ = context.Background
