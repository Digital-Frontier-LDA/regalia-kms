package registry

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func opaqueObject(bindings string) string {
	return manifest(fmt.Sprintf(`{
		"id":"deployment-api-token","name":"Deploy token","kind":"api-token","classification":"restricted",
		"environment":"development","owner":"platform","purpose":"deployment-api","custody":"hardware-envelope",
		"algorithm":"opaque","operations":["release-secret"],"policy_id":"test-policy","bindings":[%s],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}
	}`, bindings))
}

func opaqueBinding(kekAlgorithm string) string {
	return opaqueBindingVersioned(kekAlgorithm, "1")
}

func opaqueBindingVersioned(kekAlgorithm, kekVersion string) string {
	kek := ""
	if kekAlgorithm != "" {
		kek = fmt.Sprintf(`,"kek_algorithm":%q`, kekAlgorithm)
	}
	if kekVersion != "" {
		kek += fmt.Sprintf(`,"kek_version":%q`, kekVersion)
	}
	return fmt.Sprintf(`{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"local-hsm","object_id":"20",
		"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active",
		"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"%s}`, kek)
}

// A COMMISSIONED SECRET MUST NAME THE KEY THAT CAN ACTUALLY OPEN IT.
//
// "opaque" is the only algorithm the capability matrix admits for release-secret, because an API
// token is not a key. But the release path unwraps a data key ON THE CARD, and both drivers gate on
// the key in the slot -- PKCS#11 accepts rsa2048/3072/4096, PIV accepts rsa2048 alone. A manifest
// that named only "opaque" therefore commissioned an object that passed every check here and then
// failed at its first release, as a retryable backend error that would never stop being retried.
//
// The binding names the wrapping key. This refuses a manifest that omits it, and one that names a
// key the backend cannot unwrap with -- at load, where an operator can still fix it.
func TestReleaseSecretBindingMustNameAKEKTheBackendCanUnwrapWith(t *testing.T) {
	for _, testCase := range []struct {
		name         string
		kekAlgorithm string
		wantErr      string
	}{
		{"no kek_algorithm at all", "", "must name the kek_algorithm"},
		{"a key the driver refuses", "ed25519", "cannot unwrap with kek_algorithm"},
		{"the object's own algorithm", "opaque", "cannot unwrap with kek_algorithm"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Load(bytes.NewBufferString(opaqueObject(opaqueBinding(testCase.kekAlgorithm))), "sitea", allHealthy{})
			if err == nil {
				t.Fatalf("a release-secret binding with kek_algorithm %q was accepted: this object would be commissioned and then fail at its first release, forever, as a retryable error",
					testCase.kekAlgorithm)
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, testCase.wantErr)
			}
		})
	}
}

// THE SCHEMA CANNOT EXPRESS THIS; THE LOADER CAN, AND DOES.
//
// release-secret appears only under nitrokey-pkcs11 in the capability table, so a manifest binding
// it to a YubiKey satisfies custody-manifest.schema.json and then fails. JSON Schema could only
// catch it by restating the table, and #73 removed exactly that duplication because the Go and
// Python copies had already drifted apart. The containment therefore lives here and in
// custody_manifest.py, both of which read the one exported table -- and this pins it so the
// schema's known weakness stays a documented division of labour rather than a gap.
func TestReleaseSecretIsRefusedOnBackendsTheTableDoesNotAdmit(t *testing.T) {
	for _, backend := range []string{"yubikey-piv", "yubikey-openpgp"} {
		t.Run(backend, func(t *testing.T) {
			binding := fmt.Sprintf(`{"site":"sitea","backend":%q,"device_id":"yubi-1","object_id":"20",
				"kek_algorithm":"rsa2048","kek_version":"1","pin_policy":"once","touch_policy":"never","device_serial":"yubi-1",
				"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}`, backend)
			_, err := Load(bytes.NewBufferString(opaqueObject(binding)), "sitea", allHealthy{})
			if err == nil {
				t.Fatalf("release-secret was bound to %s, which the capability table does not admit it on: the manifest would validate and the operation would fail at the token", backend)
			}
			if !strings.Contains(err.Error(), "does not support opaque/release-secret") {
				t.Fatalf("error = %v, want it to name the unsupported backend/operation pair", err)
			}
		})
	}
}

// Rotation needs a generation to compare against, so the binding must name one.
func TestReleaseSecretBindingMustNameAKEKVersion(t *testing.T) {
	// Control: with a version it loads, so the assertion below is about the version and nothing else.
	if _, err := Load(bytes.NewBufferString(opaqueObject(opaqueBindingVersioned("rsa2048", "1"))), "sitea", allHealthy{}); err != nil {
		t.Fatalf("the control manifest does not load (%v), so the case below would prove nothing", err)
	}
	_, err := Load(bytes.NewBufferString(opaqueObject(opaqueBindingVersioned("rsa2048", ""))), "sitea", allHealthy{})
	if err == nil {
		t.Fatal("a release-secret binding with no kek_version was accepted: an envelope wrapped under a superseded key would open on whatever replaced it in the same slot, and rotation would change a label only")
	}
	if !strings.Contains(err.Error(), "must name the kek_version") {
		t.Fatalf("error = %v, want it to name kek_version", err)
	}

	// A NAMED-BUT-UNUSABLE VERSION IS A DIFFERENT MISTAKE FROM AN ABSENT ONE.
	//
	// Both reported "must name the kek_version", which tells an operator to supply a field they can
	// see in front of them and sends them looking in the wrong place. The pattern exists because the
	// envelope's KEK reference has to be able to carry the value; the error should say so.
	_, err = Load(bytes.NewBufferString(opaqueObject(opaqueBindingVersioned("rsa2048", "has space"))), "sitea", allHealthy{})
	if err == nil {
		t.Fatal("a kek_version no envelope could carry was accepted")
	}
	if strings.Contains(err.Error(), "must name the kek_version") {
		t.Fatalf("a malformed kek_version reported as a missing one: %v", err)
	}
	if !strings.Contains(err.Error(), "has space") || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("error = %v, want it to quote the offending value and state the expected pattern", err)
	}
}

// The KEK algorithm reaches the Route, which is what the Releaser hands the token.
func TestRouteCarriesTheKEKAlgorithmToTheToken(t *testing.T) {
	registry, err := Load(bytes.NewBufferString(opaqueObject(opaqueBinding("rsa2048"))), "sitea", allHealthy{})
	if err != nil {
		t.Fatal(err)
	}
	route, err := registry.Route(context.Background(), "deployment-api-token", "deployment-api", "release-secret")
	if err != nil {
		t.Fatal(err)
	}
	if route.KEKAlgorithm != "rsa2048" {
		t.Fatalf("route.KEKAlgorithm = %q; the token would be asked to unwrap with %q, which no driver accepts",
			route.KEKAlgorithm, route.Algorithm)
	}
	if route.KEKVersion != "1" {
		t.Fatalf("route.KEKVersion = %q; without it a superseded envelope cannot be told from a current one", route.KEKVersion)
	}
}

// kek_algorithm must not become a second, contradictory way to say what a key is.
//
// The control below matters: this object is production, so it needs two bindings to satisfy the
// redundancy rule. Written with one, the manifest is refused for THAT reason and the test passes
// while proving nothing -- which is how it was written first.
func TestKEKAlgorithmIsRefusedOnBindingsThatDoNotReleaseSecrets(t *testing.T) {
	signing := func(kek string) string {
		return manifest(object("signing-key", "cosmos-validator", "secp256k1", "sign",
			fmt.Sprintf(`{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"local-hsm","object_id":"01",
			"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active",
			"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"%s},%s`,
				kek, binding("siteb", "nitrokey-pkcs11", "siteb-hsm", "01", "active"))))
	}

	// Control: the same manifest without the field must LOAD. Otherwise the assertion below would
	// hold for a reason that has nothing to do with kek_algorithm.
	if _, err := Load(bytes.NewBufferString(signing("")), "sitea", allHealthy{}); err != nil {
		t.Fatalf("the control manifest does not load (%v), so the case below would prove nothing", err)
	}

	_, err := Load(bytes.NewBufferString(signing(`,"kek_algorithm":"rsa2048"`)), "sitea", allHealthy{})
	if err == nil {
		t.Fatal("a signing binding declared a kek_algorithm and was accepted: the slot's key is already named by the object's algorithm, and two answers invite them to disagree")
	}
	if !strings.Contains(err.Error(), "only meaningful for release-secret") {
		t.Fatalf("error = %v, want it to name kek_algorithm as the reason", err)
	}
}

type allHealthy struct{}

func (allHealthy) Healthy(context.Context, Binding) bool { return true }
