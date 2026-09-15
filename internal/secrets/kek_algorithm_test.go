package secrets

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// recorder captures the route the Releaser actually hands the token.
type recorder struct {
	seen registry.Route
	card
}

func (r *recorder) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error) {
	if operation == "unwrap" {
		r.seen = route
	}
	return r.card.Execute(ctx, route, operation, format, contentType, data, aad)
}

// THE TOKEN MUST BE ASKED FOR THE KEK'S ALGORITHM, NOT THE SECRET'S.
//
// An opaque secret has no algorithm of its own -- an API token is not a key. The manifest says so:
// `algorithm: "opaque"` is the only value registry.Capabilities() admits for release-secret. But the
// Releaser performs its data-key unwrap on the card, and every driver gate is written in terms of
// the KEY in the slot: pkcs11_driver.go's wrappingAlgorithm() accepts rsa2048/3072/4096 and nothing
// else, and the PIV driver accepts rsa2048 alone.
//
// So passing the OBJECT's algorithm to the token made release-secret unserveable on real hardware.
// Every commissioned opaque object routed with algorithm "opaque", the driver refused it, and the
// caller saw BACKEND_UNAVAILABLE 503 retryable -- a permanent condition reported as a transient one.
// It survived because every test double ignores route.Algorithm, and because the one test that walks
// advertised capabilities against the driver excluded release-secret as "served by decorators".
// The decorator delegates; the algorithm arrives at the card either way.
//
// The binding names the KEK's algorithm. That is what must reach the token.
func TestReleaseUnwrapsWithTheKEKAlgorithmTheBindingNames(t *testing.T) {
	blob := sealed(t, "opaque-token", []byte("s3cret"))

	backend := &recorder{}
	releaser, err := NewReleaser(backend)
	if err != nil {
		t.Fatal(err)
	}
	route := route("opaque-token")
	if _, _, err := releaser.Execute(context.Background(), route,
		"release-secret", "regalia-envelope-v2", "", blob, nil); err != nil {
		t.Fatalf("Execute() = %v", err)
	}
	if backend.seen.Algorithm != "rsa2048" {
		t.Fatalf("the token was asked to unwrap with algorithm %q; the KEK is %q. Every PKCS#11 and PIV unwrap gate refuses anything but RSA, so this object could never release a secret on real hardware.",
			backend.seen.Algorithm, route.KEKAlgorithm)
	}
}

// A binding that names no KEK algorithm must fail closed, not fall back to the object's.
func TestReleaseRefusesABindingWithNoKEKAlgorithm(t *testing.T) {
	blob := sealed(t, "opaque-token", []byte("s3cret"))
	releaser, _ := NewReleaser(&card{})
	noKEK := route("opaque-token")
	noKEK.KEKAlgorithm, noKEK.Binding.KEKAlgorithm = "", ""
	released, _, err := releaser.Execute(context.Background(), noKEK,
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("released a secret through a binding that names no KEK algorithm")
	}
}
