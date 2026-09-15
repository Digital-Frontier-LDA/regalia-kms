package secrets

import (
	"context"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// sealedUnder seals for the route's derived context but lets the test lie about the KEK the
// envelope names, which is the whole point: the envelope's self-report must be checked.
func sealedUnder(t *testing.T, route registry.Route, kek envelope.KeyRef, secret []byte) []byte {
	t.Helper()
	env, err := envelope.Seal(context.Background(), &softWrapper{backend: kek.Backend}, kek,
		route.ObjectID, envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment),
		secret, rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	blob, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// THE ENVELOPE SAYS WHICH KEY OPENS IT. THAT CLAIM MUST BE CHECKED AGAINST THE ROUTE.
//
// envelope.validateKeyRef compares the wrapper's backend to the envelope's. On the release path the
// wrapper was built as `&hardwareWrapper{backend: parsed.KEK.Backend}` -- from the envelope itself --
// so the check compared the envelope against the envelope and could not fail. The backend that would
// actually perform the unwrap, route.Binding.Backend, was never consulted. Issue #6's own
// verification comment claims "backend identity must exactly match the KEK reference"; it matched
// itself.
//
// The KEK version was worse than unchecked: it selected nothing. UnwrapKey ignored ref.Version and
// routed every version to the same slot, so after a Rewrap to version 2 the version-1 envelope still
// opened on the same physical key. Retiring a KEK was impossible without retiring the object, which
// makes "supports rotation" untrue. The binding now names the version in its slot, so rotating the
// key and bumping the manifest refuses envelopes wrapped under the old one.
func TestEnvelopeMustNameTheKeyTheRouteActuallyHolds(t *testing.T) {
	authorized := route("opaque-token")
	current := envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "opaque-token", Version: "2"}

	// Control: the envelope naming exactly what the route holds must open.
	releaser, _ := NewReleaser(&card{})
	if _, _, err := releaser.Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", sealedUnder(t, authorized, current, []byte("s3cret")), nil); err != nil {
		t.Fatalf("an envelope naming the route's own KEK did not open: %v", err)
	}

	for _, testCase := range []struct {
		name string
		kek  envelope.KeyRef
	}{
		{"a different backend", envelope.KeyRef{Backend: "yubikey-piv", ID: "opaque-token", Version: "2"}},
		{"a superseded KEK version", envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "opaque-token", Version: "1"}},
		{"another object's KEK", envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "some-other-key", Version: "2"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			blob := sealedUnder(t, authorized, testCase.kek, []byte("s3cret"))
			releaser, _ := NewReleaser(&card{})
			released, _, err := releaser.Execute(context.Background(), authorized,
				"release-secret", "regalia-envelope-v2", "", blob, nil)
			if err == nil || len(released) != 0 {
				t.Fatalf("an envelope naming %s was released: the route holds %s/%s version %s, and the envelope's own account of which key opens it was never compared to it",
					testCase.name, authorized.Binding.Backend, authorized.ObjectID, authorized.Binding.KEKVersion)
			}
		})
	}
}

// THE MANIFEST AND THE ENVELOPE MUST AGREE ON WHAT A KEK VERSION LOOKS LIKE.
//
// The registry decides which versions a binding may declare; the envelope decides which its KEK
// reference may carry. They are separate literals in separate packages, and a disagreement is
// invisible until a release: a manifest could name a generation no envelope could ever claim, so
// every release for that object would be refused, or the reverse. The same independence between the
// wrapping hash and the PKCS#11 mechanism parameters is what keywrap.OAEPHash exists to prevent.
func TestManifestKEKVersionsAreNameableByAnEnvelope(t *testing.T) {
	for _, version := range []string{"1", "2026-09", "v1.2.3", "a_b", "", "with space", "one/two", "über"} {
		manifest := manifestNaming(version)
		_, registryErr := registry.Load(strings.NewReader(manifest), "sitea", healthy{})
		_, envelopeErr := envelope.Seal(context.Background(), &softWrapper{backend: "nitrokey-pkcs11"},
			envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "deployment-api-token", Version: version},
			"deployment-api-token", []byte("context"), []byte("secret"), rand.Reader, time.Now())
		if (registryErr == nil) != (envelopeErr == nil) {
			t.Errorf("kek_version %q: the manifest %s it and an envelope %s it, so this object's releases could never succeed",
				version, accepted(registryErr), accepted(envelopeErr))
		}
	}
}

func accepted(err error) string {
	if err == nil {
		return "accepts"
	}
	return "refuses"
}

type healthy struct{}

func (healthy) Healthy(context.Context, registry.Binding) bool { return true }

func manifestNaming(version string) string {
	kek := `"kek_algorithm":"rsa2048"`
	if version != "" {
		kek += `,"kek_version":` + strconv.Quote(version)
	}
	return `{"schema_version":1,"manifest_id":"kek-version","generated_at":"2026-09-04T12:00:00Z","objects":[{
		"id":"deployment-api-token","name":"Deploy token","kind":"api-token","classification":"restricted",
		"environment":"development","owner":"platform","purpose":"deployment-api","custody":"hardware-envelope",
		"algorithm":"opaque","operations":["release-secret"],"policy_id":"test-policy","bindings":[{
		"site":"sitea","backend":"nitrokey-pkcs11","device_id":"local-hsm","object_id":"20",` + kek + `,
		"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active",
		"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}}]}`
}
