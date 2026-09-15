package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// wrapRecorder captures the route the seal wrapper actually hands the token.
type wrapRecorder struct {
	seen      registry.Route
	operation string
	calls     int
}

func (r *wrapRecorder) Execute(_ context.Context, route registry.Route, operation, _, _ string, _, _ []byte) ([]byte, string, error) {
	r.calls++
	r.seen = route
	r.operation = operation
	return []byte("wrapped-data-key"), "application/vnd.regalia.wrapped-key", nil
}

// Every field is populated, including the ones this wrapper has no business touching. An
// assertion that "everything else is unchanged" is only as strong as the fields that are set:
// leaving Purpose or the binding's KEK fields empty would let a regression that dropped them
// pass, because zero equals zero.
func sealRoute() registry.Route {
	return registry.Route{
		ObjectID: "deployment-token", Purpose: "release-secret", Algorithm: "opaque",
		PolicyID: "opaque-secrets", Environment: "production",
		KEKAlgorithm: "rsa2048", KEKVersion: "2",
		Binding: registry.Binding{
			Site: "sitea", Backend: "nitrokey-pkcs11", DeviceID: "hsm-1",
			DeviceSerial: "DENK0100000", DevAuthFingerprint: "sha256:" + strings.Repeat("b", 64),
			ObjectID: "03", PublicFingerprint: "sha256:" + strings.Repeat("c", 64),
			KeyCheck: "kcv:1122334455667788", KEKAlgorithm: "rsa2048", KEKVersion: "2",
			State: "active", PINPolicy: "once", TouchPolicy: "never",
		},
	}
}

func sealWrapperFor(t *testing.T, inner Hardware) envelope.Wrapper {
	t.Helper()
	wrapper, err := NewSealWrapper(inner, sealRoute())
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

// THE SIBLING OF TestReleaseUnwrapsWithTheKEKAlgorithmTheBindingNames, IN THE OTHER DIRECTION.
//
// That test exists because passing the OBJECT's algorithm to the token made release-secret
// unserveable on real hardware: `opaque` is what the manifest says an API token is, every driver
// gate is written in terms of the KEY in the slot, and pkcs11's wrap path accepts only
// rsa2048/3072/4096. The seal direction has exactly the same hazard and had no test at all --
// sealWrapper.WrapKey was at 0%.
//
// Worse in this direction, because the failure is deferred: sealing under `opaque` either produces
// nothing, or, if a backend were laxer, an envelope no card can ever unwrap. The first is found
// when you store the secret; the second when you need it.
func TestSealWrapsWithTheKEKAlgorithmAndNotTheObjectsAlgorithm(t *testing.T) {
	card := &wrapRecorder{}
	wrapper := sealWrapperFor(t, card)

	wrapped, err := wrapper.WrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "deployment-token", Version: "2"},
		[]byte("0123456789abcdef0123456789abcdef"), []byte("aad"))
	if err != nil {
		t.Fatalf("wrapping under a complete route failed: %v", err)
	}
	if string(wrapped) != "wrapped-data-key" {
		t.Fatalf("the wrapped key was not returned: %q", wrapped)
	}
	if card.operation != "wrap" {
		t.Errorf("the card was asked for %q, not wrap", card.operation)
	}
	if card.seen.Algorithm != "rsa2048" {
		t.Fatalf("the card was asked for algorithm %q; it must be the KEK's rsa2048, not the "+
			"object's %q -- no driver accepts the latter for a wrap", card.seen.Algorithm, sealRoute().Algorithm)
	}
	// Swapping the algorithm is the ONLY edit this wrapper is entitled to make, so the whole
	// route is compared rather than a couple of fields. Route and Binding are all strings, so
	// == covers every field including ones added later -- a new field silently dropped by a
	// future change fails here without anyone remembering to add it to a list.
	expected := sealRoute()
	expected.Algorithm = "rsa2048"
	if card.seen != expected {
		t.Errorf("the wrapper altered more of the route than the algorithm:\n got %#v\nwant %#v",
			card.seen, expected)
	}
}

// SEAL CANNOT OPEN, AND RELEASE CANNOT SEAL.
//
// Each wrapper satisfies the same envelope.Wrapper interface and implements only its own
// direction. That is a capability boundary, not tidiness: a seal path that could unwrap would
// open envelopes it was never authorized to open, and the authorization it passed was for
// storing a secret, not for reading one.
//
// Both refusals were at 0%. They are one line each, which is exactly the kind of line a
// later refactor "simplifies" into delegation.
func TestEachWrapperRefusesTheDirectionItIsNotFor(t *testing.T) {
	card := &wrapRecorder{}

	sealer := sealWrapperFor(t, card)
	opened, err := sealer.UnwrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "deployment-token", Version: "2"},
		[]byte("wrapped"), []byte("aad"))
	if err == nil {
		t.Fatal("the seal wrapper unwrapped a data key: it can open envelopes it was not authorized to open")
	}
	if opened != nil {
		t.Errorf("a refused unwrap still produced %d bytes", len(opened))
	}
	if !strings.Contains(err.Error(), "does not unwrap") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if card.calls != 0 {
		t.Errorf("the seal wrapper reached the card %d times while refusing to unwrap", card.calls)
	}

	releaser := &hardwareWrapper{backend: "nitrokey-pkcs11"}
	sealed, err := releaser.WrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "deployment-token", Version: "2"},
		[]byte("data-key"), []byte("aad"))
	if err == nil {
		t.Fatal("the release wrapper wrapped a data key: release-secret can mint envelopes")
	}
	if sealed != nil {
		t.Errorf("a refused wrap still produced %d bytes", len(sealed))
	}
	if !strings.Contains(err.Error(), "does not wrap") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// THE ENVELOPE'S ACCOUNT OF WHICH KEY PROTECTS IT IS CHECKED AGAINST THE ROUTE.
//
// A caller supplies the KeyRef. If it were trusted, an envelope could name any object and any KEK
// version and the wrapper would wrap under whatever the route happened to hold -- so the envelope
// would carry an account of its own protection that nothing verified.
func TestSealRefusesAKeyRefTheRouteDoesNotHold(t *testing.T) {
	for name, ref := range map[string]envelope.KeyRef{
		"another object":      {Backend: "nitrokey-pkcs11", ID: "someone-elses-secret", Version: "2"},
		"another KEK version": {Backend: "nitrokey-pkcs11", ID: "deployment-token", Version: "1"},
		"no version at all":   {Backend: "nitrokey-pkcs11", ID: "deployment-token"},
		"no id at all":        {Backend: "nitrokey-pkcs11", Version: "2"},
	} {
		t.Run(name, func(t *testing.T) {
			card := &wrapRecorder{}
			wrapped, err := sealWrapperFor(t, card).WrapKey(context.Background(), ref,
				[]byte("0123456789abcdef0123456789abcdef"), []byte("aad"))
			if err == nil {
				t.Fatalf("%s was wrapped anyway, returning %d bytes", name, len(wrapped))
			}
			if card.calls != 0 {
				t.Errorf("%s reached the card before being refused", name)
			}
		})
	}
}

func TestSealWrapperReportsTheRoutesBackend(t *testing.T) {
	if got := sealWrapperFor(t, &wrapRecorder{}).Backend(); got != "nitrokey-pkcs11" {
		t.Fatalf("Backend() = %q, want the route's backend", got)
	}
}
