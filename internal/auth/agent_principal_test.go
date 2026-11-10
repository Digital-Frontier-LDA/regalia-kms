package auth

import (
	"strings"
	"testing"
)

func agentPolicy(uri, operation string) string {
	return `{"schema_version": 1, "principals": [{"uri": "` + uri + `", "grants": [{"objects": ["support-api-token"], "operations": ["` +
		operation + `"], "environments": ["production"]}]}]}`
}

// A POLICY THAT GRANTS AN AGENT release-secret DOES NOT LOAD (regalia-kms-sv3.2): the grant could never be served, and a
// policy saying the agent may release would be config that says something untrue. The refusal names the principal.
func TestAPolicyGrantingAnAgentReleaseSecretIsRefusedNamingIt(t *testing.T) {
	_, err := LoadPolicy(strings.NewReader(agentPolicy("spiffe://regalia/agent/support-bot", "release-secret")))
	if err == nil || !strings.Contains(err.Error(), `"spiffe://regalia/agent/support-bot"`) || !strings.Contains(err.Error(), "may not be granted release-secret") {
		t.Fatalf("LoadPolicy = %v, want a refusal naming the agent and release-secret", err)
	}
}

func TestAnAgentMayBeGrantedOperationsAndAWorkloadReleaseSecret(t *testing.T) {
	for _, c := range []struct{ uri, operation string }{
		{"spiffe://regalia/agent/support-bot", "unwrap"},
		{"spiffe://regalia/agent/support-bot", "sign"},
		{"spiffe://regalia/workload/support-api", "release-secret"},
	} {
		policy, err := LoadPolicy(strings.NewReader(agentPolicy(c.uri, c.operation)))
		if err != nil {
			t.Fatalf("%s %s: %v", c.uri, c.operation, err)
		}
		if !policy.Allowed(c.uri, "support-api-token", c.operation, "production") {
			t.Fatalf("%s %s: loaded but not allowed", c.uri, c.operation)
		}
	}
}

func TestIsAgentIsThePrefixAndNothingNear(t *testing.T) {
	for principal, want := range map[string]bool{
		"spiffe://regalia/agent/support-bot":  true,
		"spiffe://regalia/agent/":             false, // the prefix alone names no one
		"spiffe://regalia/agents/support-bot": false,
		"spiffe://regalia/workload/agent/x":   false,
		"spiffe://other/agent/support-bot":    false,
		"SPIFFE://regalia/agent/support-bot":  false,
	} {
		if got := IsAgent(principal); got != want {
			t.Errorf("IsAgent(%q) = %v, want %v", principal, got, want)
		}
	}
	if !AgentRefuses("spiffe://regalia/agent/x", "release-secret") || AgentRefuses("spiffe://regalia/agent/x", "unwrap") ||
		AgentRefuses("spiffe://regalia/workload/x", "release-secret") {
		t.Fatal("AgentRefuses is not exactly (agent, release-secret)")
	}
}

// ONE SPELLING OF A PRINCIPAL LOADS (regalia-kms#668 review, B1). url.Parse accepts spellings that its String() does not
// give back -- a scheme in any case, an empty fragment -- and canonicalURISAN, which reads the parsed fields, passes
// them. (A literal space is not one: canonicalURISAN refuses it first; asserted below.) The checks after it read the raw string, so "SPIFFE://regalia/agent/x" was not an
// agent to IsAgent and its release-secret grant loaded. Each spelling class is refused, naming the principal and the
// canonical form, for an agent's release-secret (the bypass) and for a workload's unwrap (a grant that never matches).
func TestANonCanonicalSpellingOfAPrincipalDoesNotLoad(t *testing.T) {
	for _, c := range []struct{ class, uri, canonical, operation string }{
		{"scheme upper case", "SPIFFE://regalia/agent/support-bot", "spiffe://regalia/agent/support-bot", "release-secret"},
		{"scheme mixed case", "Spiffe://regalia/agent/support-bot", "spiffe://regalia/agent/support-bot", "release-secret"},
		{"an empty fragment", "spiffe://regalia/agent/support-bot#", "spiffe://regalia/agent/support-bot", "release-secret"},
		{"scheme upper case, a workload", "SPIFFE://regalia/workload/support-api", "spiffe://regalia/workload/support-api", "unwrap"},
	} {
		_, err := LoadPolicy(strings.NewReader(agentPolicy(c.uri, c.operation)))
		if err == nil || !strings.Contains(err.Error(), "not in its canonical spelling") ||
			!strings.Contains(err.Error(), `"`+c.uri+`"`) || !strings.Contains(err.Error(), `"`+c.canonical+`"`) {
			t.Errorf("%s: LoadPolicy(%q) = %v, want a canonical-spelling refusal naming it and %q", c.class, c.uri, err, c.canonical)
		}
	}
	// A literal space is refused too, but by canonicalURISAN before the spelling check: pinned here so that the refusal
	// does not rest on that check by accident.
	if _, err := LoadPolicy(strings.NewReader(agentPolicy("spiffe://regalia/agent/support bot", "release-secret"))); err == nil ||
		!strings.Contains(err.Error(), "not a canonical workload identity") || !strings.Contains(err.Error(), `"spiffe://regalia/agent/support bot"`) {
		t.Errorf(`LoadPolicy("spiffe://regalia/agent/support bot") = %v, want the canonical-workload-identity refusal naming it`, err)
	}
	// The control: a canonical spelling, percent-encoding included, round-trips and loads (an agent's unwrap).
	for _, uri := range []string{"spiffe://regalia/agent/support-bot", "spiffe://regalia/agent/support%20bot"} {
		policy, err := LoadPolicy(strings.NewReader(agentPolicy(uri, "unwrap")))
		if err != nil || !policy.Allowed(uri, "support-api-token", "unwrap", "production") {
			t.Errorf("canonical %q: LoadPolicy = %v, want it to load and allow unwrap", uri, err)
		}
	}
}
