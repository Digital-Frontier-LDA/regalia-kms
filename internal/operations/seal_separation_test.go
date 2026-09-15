package operations

import (
	"context"
	"errors"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// healthyBindings answers the registry's backend-health probe yes for everything:
// the separation question is about grants, not hardware.
type healthyBindings struct{}

func (healthyBindings) Healthy(context.Context, registry.Binding) bool { return true }

// realLayers builds the actual registry, RBAC policy and policy engine from
// documents, because the question "does a release-only grant admit sealing" is
// answered by THREE layers keyed per operation — a fake answers whatever it was
// programmed to, and the collapse this test exists to catch would live in the real
// keying.
func realLayers(t *testing.T, operations []string, grantOps, policyOps []string) (Authorizer, *registry.Registry, Policy) {
	t.Helper()
	directory := t.TempDir()

	manifest := `{"schema_version":1,"manifest_id":"test-custody","generated_at":"2026-09-05T00:00:00Z","objects":[{
		"id":"deployment-api-token","name":"token","kind":"api-token","classification":"restricted",
		"environment":"production","owner":"platform","purpose":"deployment-api","custody":"hardware-envelope",
		"algorithm":"opaque","operations":` + mustJSON(t, operations) + `,"policy_id":"deployer",
		"bindings":[{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"nitrokey-sitea","object_id":"20",
		"kek_algorithm":"rsa2048","kek_version":"1",
		"public_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","device_serial":"serial-sitea","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"active"},
		{"site":"siteb","backend":"nitrokey-pkcs11","device_id":"nitrokey-siteb","object_id":"20",
		"kek_algorithm":"rsa2048","kek_version":"1",
		"public_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","device_serial":"serial-siteb","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"standby"}],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"commissioned"},
		"rotation":{"maximum_age_days":null,"last_rotated":null},
		"migration":{"status":"none","source":""},"verification":{"status":"verified","last_verified":null,"evidence":""}}]}`
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	keyRegistry, err := registry.LoadFile(manifestPath, "sitea", healthyBindings{})
	if err != nil {
		t.Fatalf("manifest fixture does not load: %v — an earlier registry rule rejected it, so this test would prove nothing", err)
	}

	rbac := `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/sops-prod",
		"grants":[{"objects":["deployment-api-token"],"operations":` + mustJSON(t, grantOps) + `,"environments":["production"]}]}]}`
	rbacPath := filepath.Join(directory, "rbac.json")
	if err := os.WriteFile(rbacPath, []byte(rbac), 0o600); err != nil {
		t.Fatal(err)
	}
	authorizer, err := auth.LoadPolicyFile(rbacPath)
	if err != nil {
		t.Fatal(err)
	}

	var policies []policy.Policy
	for _, operation := range policyOps {
		policies = append(policies, policy.Policy{
			ID: "deployer-" + operation, ObjectID: "deployment-api-token", Purpose: "deployment-api",
			Environment: "production", Operation: operation, Algorithm: "opaque",
			ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 1 << 20,
			MaxFuture: 5 * time.Minute,
		})
	}
	state, err := policy.OpenFileState(filepath.Join(directory, "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	engine, err := policy.New(policies, state, func() time.Time { return time.Now() })
	if err != nil {
		t.Fatal(err)
	}
	return authorizer, keyRegistry, engine
}

func mustJSON(t *testing.T, values []string) string {
	t.Helper()
	out := "["
	for index, value := range values {
		if index > 0 {
			out += ","
		}
		out += `"` + value + `"`
	}
	return out + "]"
}

// A RELEASE GRANT IS NOT A SEAL GRANT — PROVEN AGAINST THE REAL LAYERS.
//
// The registry, the RBAC policy and the policy engine each key by operation. If any
// of them collapsed seal-envelope into release-secret, a read credential could mint
// envelopes, and the fakes in the unit tests could never show it: they answer what
// they are told. The control half proves the fixture can pass, so the deny half
// means what it says.
func TestSealAndReleaseAreDistinctGrantsThroughTheRealLayers(t *testing.T) {
	route := sealRoute()
	route.ObjectID, route.Purpose, route.Environment = "deployment-api-token", "deployment-api", "production"
	route.Binding = registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "nitrokey-sitea", ObjectID: "20"}

	attempt := func(t *testing.T, operations, grantOps, policyOps []string, requestID string) (api.Result, error) {
		t.Helper()
		authorizer, keyRegistry, engine := realLayers(t, operations, grantOps, policyOps)
		recorder := &fakeAudit{}
		hardware := &fakeHardware{output: []byte("wrapped-by-the-card")}
		coordinator, err := New(authorizer, keyRegistry, engine, recorder, directRunner{}, hardware, "sha256:policy", (*approval.KeySet)(nil), time.Now)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))
		retained := append([]byte(nil), dataKey...)
		request := sealRequest(route, ciphertext, nonce, dataKey)
		request.RequestID = requestID
		request.Context.Nonce = "nonce_" + requestID
		request.Context.Purpose = "deployment-api"
		request.Context.Environment = "production"
		result, err := coordinator.Execute(context.Background(), request)
		if err == nil {
			// An admitted seal must return an envelope that OPENS: "no error" with a
			// non-envelope payload is the wiring absent — the difference between the
			// control proving the path serves seal and proving nothing.
			produced, parseErr := envelope.Parse(result.Data)
			if parseErr != nil {
				t.Fatalf("an admitted seal returned no envelope: %v", parseErr)
			}
			if openErr := produced.Open(context.Background(), openStub{retained}, envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment), func([]byte) error { return nil }); openErr != nil {
				t.Fatalf("the control's envelope does not open: %v", openErr)
			}
		}
		return result, err
	}

	// CONTROL: admitted everywhere, the same fixture seals and the envelope opens.
	if _, err := attempt(t, []string{"release-secret", "seal-envelope"}, []string{"release-secret", "seal-envelope"}, []string{"release-secret", "seal-envelope"}, "018f0000-0000-7000-8000-0000000000c1"); err != nil {
		t.Fatalf("the control does not seal (%v): the deny half below would prove nothing", err)
	}

	// Release granted, seal absent — from the manifest, from RBAC, from the policy
	// document. Sealing must be denied, and the denial must name the layer.
	_, err := attempt(t, []string{"release-secret"}, []string{"release-secret"}, []string{"release-secret"}, "018f0000-0000-7000-8000-0000000000c2")
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Status != 403 {
		t.Fatalf("seal under a release-only grant = %v, want 403 DENIED: a read credential minted an envelope", err)
	}
}
