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
