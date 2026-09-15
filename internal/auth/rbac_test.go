package auth

import (
	"context"
	"strings"
	"testing"
)

const validPolicy = `{
  "schema_version": 1,
  "principals": [{
    "uri": "spiffe://regalia/workload/sops-prod",
    "grants": [{
      "objects": ["production-sops"],
      "operations": ["unwrap"],
      "environments": ["production"]
    }]
  }]
}`

func TestRBACAllowsOnlyExactGrant(t *testing.T) {
	policy, err := LoadPolicy(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Allowed("spiffe://regalia/workload/sops-prod", "production-sops", "unwrap", "production") {
		t.Fatal("exact grant denied")
	}
	for _, request := range [][4]string{
		{"spiffe://regalia/workload/other", "production-sops", "unwrap", "production"},
		{"spiffe://regalia/workload/sops-prod", "other", "unwrap", "production"},
		{"spiffe://regalia/workload/sops-prod", "production-sops", "sign", "production"},
		{"spiffe://regalia/workload/sops-prod", "production-sops", "unwrap", "staging"},
	} {
		if policy.Allowed(request[0], request[1], request[2], request[3]) {
			t.Fatalf("non-exact grant allowed: %v", request)
		}
	}
}

func TestRBACRejectsUnknownFieldsWildcardsAndDuplicatePrincipals(t *testing.T) {
	duplicatePrincipal := `{
	  "schema_version": 1,
	  "principals": [
	    {"uri":"spiffe://regalia/workload/sops-prod","grants":[{"objects":["one"],"operations":["unwrap"],"environments":["production"]}]},
	    {"uri":"spiffe://regalia/workload/sops-prod","grants":[{"objects":["two"],"operations":["unwrap"],"environments":["production"]}]}
	  ]
	}`
	tests := []string{
		strings.Replace(validPolicy, `"schema_version": 1`, `"schema_version": 1, "default": "allow"`, 1),
		strings.Replace(validPolicy, `"production-sops"`, `"*"`, 1),
		duplicatePrincipal,
	}
	for _, input := range tests {
		if _, err := LoadPolicy(strings.NewReader(input)); err == nil {
			t.Fatalf("LoadPolicy() accepted unsafe policy: %s", input)
		}
	}
}

func TestRBACRejectsNonCanonicalPrincipalURI(t *testing.T) {
	for _, principal := range []string{
		"spiffe://regalia/workload/sops?role=admin",
		"spiffe://regalia/workload/sops#admin",
		"spiffe://user@regalia/workload/sops",
		"spiffe://regalia.evil/workload/sops",
	} {
		document := `{"schema_version":1,"principals":[{"uri":"` + principal + `","grants":[{"objects":["key-one"],"operations":["sign"],"environments":["production"]}]}]}`
		if _, err := LoadPolicy(strings.NewReader(document)); err == nil {
			t.Fatalf("non-canonical principal accepted: %s", principal)
		}
	}
}

// A POLICY WITH NO GRANTS IS NOT A READY POLICY.
//
// Policy.Ready gates the daemon through server.RequireAll and nothing exercised it. An RBAC
// policy that loaded but granted nothing would authorize no one, and reporting ready in that
// state puts a daemon into service that denies every request -- the same shape as the
// registry that loaded with a nil backend-health probe, served nothing, and said READY.
func TestRBACPolicyIsNotReadyWithoutGrants(t *testing.T) {
	// THE POSITIVE CONTROL COMES FIRST, because without it every assertion below passes on a
	// Ready that always says false -- which would be a daemon that never becomes ready at
	// all. I claimed in this change's own description that every test here carried a control
	// and then omitted this one; review caught it, and the falsification I ran could not
	// have: I mutated Ready to always return true and never to always return false.
	loaded, err := LoadPolicy(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatalf("the control policy does not load: %v", err)
	}
	if !loaded.Ready(context.Background()) {
		t.Fatal("DEFECT: a loaded RBAC policy with grants is not ready — the daemon would " +
			"never enter service")
	}

	var absent *Policy
	if absent.Ready(context.Background()) {
		t.Error("DEFECT: a nil RBAC policy reported ready")
	}
	if (&Policy{}).Ready(context.Background()) {
		t.Error("DEFECT: an RBAC policy with no grants reported ready — the daemon would serve " +
			"while authorizing nobody")
	}
}
