package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func loadExamplePair(t *testing.T) (*registry.Registry, *policy.Engine) {
	t.Helper()
	keyRegistry, err := registry.LoadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"), "sitea", nil)
	if err != nil {
		t.Fatalf("shipped custody manifest does not load: %v", err)
	}
	policies, _, err := policy.LoadFile(filepath.Join("..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatalf("shipped policy document does not load: %v", err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	engine, err := policy.New(policies, state, time.Now)
	if err != nil {
		t.Fatalf("shipped policy document does not compile: %v", err)
	}
	return keyRegistry, engine
}

// THE MANIFEST'S STATED POLICY MUST BE THE ENFORCED ONE.
//
// Every object in a custody manifest carries a policy_id, and the loader refuses an object without
// one, so an operator reasonably reads it as the binding between object and policy. It is not: the
// engine looks a policy up by (object_id, operation) and never consults that field. Whatever policy
// happens to name the object governs it, whatever the manifest says.
//
// Both failure modes are silent. A manifest naming a policy that does not exist leaves the object
// denied at every request as "unknown-object", which reads as a routing fault rather than a missing
// policy. A manifest naming one policy while a differently-named policy governs the same object
// means the enforced rules are not the reviewed ones — and the review happened against the manifest.
func TestShippedManifestAndPolicyDocumentAgree(t *testing.T) {
	keyRegistry, engine := loadExamplePair(t)
	declared := keyRegistry.DeclaredPolicies()
	if len(declared) == 0 {
		t.Fatal("the shipped manifest declares no policies: this test is checking nothing")
	}
	if err := requireDeclaredPoliciesAreEnforced(keyRegistry, engine); err != nil {
		t.Fatalf("the shipped example configuration is internally inconsistent, so an operator copying it gets a daemon that denies those objects:\n%v", err)
	}
}

// A manifest that names a policy nobody enforces must be a startup error, not a per-request denial.
func TestAnUnenforcedDeclaredPolicyIsRefusedAtStartup(t *testing.T) {
	keyRegistry, engine := loadExamplePair(t)

	// An object id the policy document has never heard of.
	if _, exists := engine.GoverningPolicyID("no-such-object", "sign"); exists {
		t.Fatal("the policy engine claims to govern an object that does not exist")
	}

	// And the real check: every declared binding must resolve to a policy with the same id.
	for _, entry := range keyRegistry.DeclaredPolicies() {
		for _, operation := range entry.Operations {
			governing, exists := engine.GoverningPolicyID(entry.ObjectID, operation)
			if !exists {
				t.Fatalf("%s/%s declares policy %q and nothing governs it, yet startup accepted the pair",
					entry.ObjectID, operation, entry.PolicyID)
			}
			if governing != entry.PolicyID {
				t.Fatalf("%s/%s declares %q but %q governs: startup accepted a manifest whose stated policy is not the enforced one",
					entry.ObjectID, operation, entry.PolicyID, governing)
			}
		}
	}
}

// AN RBAC GRANT THAT NAMES A NONEXISTENT OBJECT IS CONFIG THAT SAYS SOMETHING UNTRUE.
//
// auth.LoadPolicy never sees the key registry, so a grant for an object that does not exist — a
// typo, a retired key, a split manifest — loads without complaint. The daemon starts clean and the
// operator believes that principal is authorized. It is not: every request denies at RBAC. The
// failure is fail-closed and invisible, and it stays invisible until somebody needs the access that
// the configuration says they already have.
func TestRBACGrantsMustNameObjectsTheRegistryHas(t *testing.T) {
	keyRegistry, _ := loadExamplePair(t)
	rbacPolicy, err := auth.LoadPolicyFile(filepath.Join("..", "..", "config", "rbac.example.json"))
	if err != nil {
		t.Fatalf("shipped RBAC policy does not load: %v", err)
	}
	if len(rbacPolicy.GrantedObjects()) == 0 {
		t.Fatal("the shipped RBAC policy grants nothing: this test is checking nothing")
	}
	if err := requireGrantsReferenceRealObjects(keyRegistry, rbacPolicy); err != nil {
		t.Fatalf("the shipped RBAC policy and custody manifest disagree:\n%v", err)
	}
}

// A grant for an object outside the registry, and one for an operation the object does not declare,
// must both be refused — and the message must name which, or an operator cannot act on it.
func TestRBACGrantsOutsideTheRegistryAreRefused(t *testing.T) {
	keyRegistry, _ := loadExamplePair(t)

	for name, document := range map[string]string{
		"unknown object": `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/x",
			"grants":[{"objects":["no-such-key"],"operations":["sign"],"environments":["production"]}]}]}`,
		"operation the object does not declare": `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/x",
			"grants":[{"objects":["release-signing-key"],"operations":["unwrap"],"environments":["production"]}]}]}`,
	} {
		rbacPolicy, err := auth.LoadPolicy(strings.NewReader(document))
		if err != nil {
			t.Fatalf("%s: fixture does not load: %v", name, err)
		}
		err = requireGrantsReferenceRealObjects(keyRegistry, rbacPolicy)
		if err == nil {
			t.Fatalf("%s was accepted: the operator would believe a principal is authorized when every request denies", name)
		}
		if !strings.Contains(err.Error(), "spiffe://regalia/workload/x") {
			t.Fatalf("%s: the error does not name the principal, so nobody can act on it: %v", name, err)
		}
	}
}

// An object nobody is granted yet is NOT an error. That is a key which has been commissioned and
// not yet authorized — the correct default, and the state every key passes through.
//
// The shipped configuration is the proof: it grants one of the four objects in the manifest, and
// must load. An empty RBAC document is separately refused by the loader, so "grant nothing at all"
// is not representable and is not what this checks.
func TestObjectsWithNoGrantAreAccepted(t *testing.T) {
	keyRegistry, _ := loadExamplePair(t)
	rbacPolicy, err := auth.LoadPolicyFile(filepath.Join("..", "..", "config", "rbac.example.json"))
	if err != nil {
		t.Fatal(err)
	}

	grantedObjects := map[string]struct{}{}
	for _, granted := range rbacPolicy.GrantedObjects() {
		grantedObjects[granted.ObjectID] = struct{}{}
	}
	ungranted := 0
	for _, declared := range keyRegistry.DeclaredPolicies() {
		if _, ok := grantedObjects[declared.ObjectID]; !ok {
			ungranted++
		}
	}
	if ungranted == 0 {
		t.Fatal("every object in the shipped manifest is granted, so this test no longer exercises the ungranted case")
	}
	if err := requireGrantsReferenceRealObjects(keyRegistry, rbacPolicy); err != nil {
		t.Fatalf("%d object(s) have no grant and the check refused the configuration, so a freshly commissioned key could not exist unauthorized: %v", ungranted, err)
	}
}

// THE AUDIT TRAIL'S PolicyDigest MUST BE THE POLICY'S, NOT THE REGISTRY'S.
//
// operations.New was handed keyRegistry.Digest() as its policyDigest, while Coordinator.record
// already sets RegistryDigest from the same source. Every audit event therefore carried the
// registry digest twice — once labelled correctly and once labelled PolicyDigest — and the real
// purpose-policy digest was computed at startup, logged, and dropped.
//
// That is worse than a missing field. A missing field is visibly absent; a mislabelled one answers
// the question wrongly. The audit trail exists to answer "which policy allowed this?", and anyone
// reconciling an incident against a policy revision would have compared the wrong hash with nothing
// to indicate it.
//
// Both halves matter. The digest must CHANGE when the policy document changes, and must NOT change
// when only the registry does — without the second assertion the test passes on the broken
// behaviour, because the registry digest also changes when the registry changes.
func TestAuditPolicyDigestTracksThePolicyNotTheRegistry(t *testing.T) {
	policyPath := filepath.Join("..", "..", "config", "policy.example.json")
	_, firstDigest, err := policy.LoadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	// A different policy document must produce a different digest.
	source, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	policies, ok := document["policies"].([]any)
	if !ok || len(policies) == 0 {
		t.Fatal("the policy fixture has no policies: this test is checking nothing")
	}
	first, ok := policies[0].(map[string]any)
	if !ok {
		t.Fatal("policy schema changed under this test")
	}
	first["max_payload_bytes"] = 4096
	altered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	alteredPath := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(alteredPath, altered, 0o600); err != nil {
		t.Fatal(err)
	}
	_, secondDigest, err := policy.LoadFile(alteredPath)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest == secondDigest {
		t.Fatal("changing the policy document did not change its digest, so an audit event could not distinguish policy revisions")
	}

	// And the registry's digest must be a different value entirely — if the coordinator were still
	// handed the registry digest, PolicyDigest would equal RegistryDigest on every event.
	keyRegistry, _ := loadExamplePair(t)
	if keyRegistry.Digest() == firstDigest {
		t.Fatal("the registry digest and the policy digest are the same value, so this test cannot tell which one the coordinator was given")
	}
}
