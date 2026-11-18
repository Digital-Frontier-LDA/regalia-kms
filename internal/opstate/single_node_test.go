package opstate

import (
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// regalia-kms-dx7.3 (docs/design/single-node.md 4.3): under the single-node profile a survivor authorization is refused
// by name, first, rather than passing vacuously over "every other node" when there is none. survivor.verify_authorization
// refuses alike (tests/test_baremetal_single_node_serving.py).
func TestASurvivorAuthorizationIsRefusedUnderTheSingleNodeProfile(t *testing.T) {
	single := map[string]any{"schema": membership.SchemaV5, "epoch": 1,
		"topology": map[string]any{"profile": "single-node", "nodes": 1, "single_node_limits_sha256": strings.Repeat("5e", 32)}}
	// whatever the authorization is, even none: the profile is judged first
	for _, value := range []any{nil, map[string]any{"authorization": map[string]any{}, "signature": map[string]any{}}} {
		_, err := verifySurvivorAuthorization(value, single, "a")
		if err == nil || !strings.Contains(err.Error(), "a survivor authorization is refused under the single-node profile (epoch 1)") {
			t.Fatalf("a survivor authorization under single-node: %v", err)
		}
		if _, refused := err.(*Refused); !refused {
			t.Fatalf("not a refusal: %T", err)
		}
	}
	// a manifest whose profile cannot be read is refused too, never read as multi-node
	broken := map[string]any{"schema": membership.SchemaV5, "epoch": 1, "topology": map[string]any{"profile": "two-node"}}
	if _, err := verifySurvivorAuthorization(nil, broken, "a"); err == nil || !strings.Contains(err.Error(), "topology.profile must be") {
		t.Fatalf("an unreadable profile: %v", err)
	}
	// under multi-node the profile lets the authorization through to its own checks (here: malformed)
	multi := map[string]any{"schema": membership.SchemaV5, "epoch": 1, "topology": map[string]any{"profile": "multi-node", "nodes": 3}}
	if _, err := verifySurvivorAuthorization(nil, multi, "a"); err == nil || strings.Contains(err.Error(), "single-node") {
		t.Fatalf("under multi-node: %v", err)
	}
}

func TestProfileIsTheSignedTopologys(t *testing.T) {
	for _, c := range []struct {
		manifest map[string]any
		want     string
	}{
		{map[string]any{"schema": membership.SchemaV4}, membership.ProfileMultiNode},
		{map[string]any{"schema": membership.SchemaV5, "topology": map[string]any{"profile": "multi-node"}}, membership.ProfileMultiNode},
		{map[string]any{"schema": membership.SchemaV5, "topology": map[string]any{"profile": "single-node"}}, membership.ProfileSingleNode},
	} {
		if got, err := membership.Profile(c.manifest); err != nil || got != c.want {
			t.Fatalf("Profile(%v) = %q, %v", c.manifest, got, err)
		}
	}
	for _, bad := range []map[string]any{nil, {"schema": membership.SchemaV5}, {"schema": membership.SchemaV5, "topology": "single-node"}} {
		if _, err := membership.Profile(bad); err == nil {
			t.Fatalf("Profile(%v) read a profile", bad)
		}
	}
}
