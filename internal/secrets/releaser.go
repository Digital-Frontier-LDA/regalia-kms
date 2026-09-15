// Package secrets exposes the envelope path as an authorized operation.
//
// ADR §3 draws the line this package sits on: hardware-native private keys never leave a token,
// but "consumable secrets leave only after KMS authorization". A password or API token cannot be
// used on-card, so it lives outside as authenticated ciphertext whose data key only a
// non-exportable token key can unwrap. release-secret is that path, and it is the ONLY way a
// caller obtains such a value.
package secrets

import (
	"context"
	"errors"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Hardware is the backend contract shared with the coordinator.
type Hardware interface {
	Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error)
}

// ErrUnavailable mirrors the backends so the coordinator classifies it the same way.
var ErrUnavailable = errors.New("secret release unavailable")

// Releaser answers "release-secret" and passes everything else through.
//
// It was previously advertised by the registry's capability matrix and implemented nowhere: a
// manifest could declare an opaque object with that operation, pass validation, and route to
// something no provider could perform. A capability the registry promises and the system cannot do
// is worse than an absent one, because commissioning treats the matrix as the contract.
type Releaser struct{ inner Hardware }

func NewReleaser(inner Hardware) (*Releaser, error) {
	if inner == nil {
		return nil, errors.New("releaser requires a backend")
	}
	return &Releaser{inner: inner}, nil
}

func (releaser *Releaser) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error) {
	if releaser == nil || releaser.inner == nil {
		return nil, "", ErrUnavailable
	}
	if operation != "release-secret" {
		return releaser.inner.Execute(ctx, route, operation, format, contentType, data, aad)
	}

	parsed, err := envelope.Parse(data)
	if err != nil {
		// A malformed envelope is the caller's fault and must not be reported as a backend
		// failure, or a client would retry something that can never succeed.
		return nil, "", err
	}
	// The envelope names the object it belongs to. Releasing one object's secret under another
	// object's authorization would bypass the policy decision that was actually made.
	if parsed.ObjectID != route.ObjectID {
		return nil, "", errors.New("envelope belongs to a different object than the authorized route")
	}
	// THE CONTEXT IS THE KMS'S, NOT THE CALLER'S.
	//
	// ENVELOPE.md requires that it "be independently reconstructed by the KMS" and "not be accepted
	// as an unverified opaque client assertion". It was accepted as precisely that: the caller sent
	// envelope_aad_base64, the handler decoded it, the coordinator passed it here unchanged, and
	// nothing compared it to the authorization just granted. The digest proved only that whoever
	// held the envelope knew the string it was sealed with -- so an envelope sealed for one purpose
	// and environment opened under a request naming another, because the caller supplied both halves
	// and they agreed with each other.
	//
	// A caller-supplied context is refused rather than ignored. Ignoring it would leave a field that
	// looks load-bearing, and the next caller to send a different one deserves an error, not silence.
	if len(aad) > 0 {
		return nil, "", errors.New("release-secret takes no caller-supplied binding context: the KMS derives it from the authorized route")
	}
	if route.Purpose == "" || route.Environment == "" {
		// Both come from the custody manifest and are required there. An empty one means this route
		// was built somewhere that does not carry them, and the context would bind less than it says.
		return nil, "", errors.New("route carries no purpose or environment, so no binding context can be derived from it")
	}
	bindingContext := envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment)

	// THE BACKEND THE ENVELOPE NAMES IS CHECKED AGAINST THE ONE THAT WILL OPEN IT.
	//
	// envelope.validateKeyRef compares the wrapper's backend to the envelope's KEK reference. This
	// was built from parsed.KEK.Backend, so the check compared the envelope against itself and could
	// not fail, while route.Binding.Backend -- the backend that actually performs the unwrap -- was
	// never consulted. A real card would still have refused to decrypt, but as a retryable backend
	// error rather than an invalid envelope, so the caller would retry forever.
	wrapper := &hardwareWrapper{inner: releaser.inner, route: route, backend: route.Binding.Backend}

	var released []byte
	err = parsed.Open(ctx, wrapper, bindingContext, func(plaintext []byte) error {
		// Open zeroes the plaintext when this returns, so the value must be copied out. The
		// coordinator zeroes the result on every failure path after this point.
		released = append([]byte(nil), plaintext...)
		return nil
	})
	if err != nil {
		zero(released)
		if errors.Is(err, envelope.ErrBackendUnavailable) {
			return nil, "", ErrUnavailable
		}
		return nil, "", err
	}
	if len(released) == 0 {
		return nil, "", errors.New("envelope released an empty secret")
	}
	return released, "application/vnd.regalia.secret", nil
}

// hardwareWrapper satisfies envelope.Wrapper by routing the data-key unwrap to the token. Only
// UnwrapKey is reachable: releasing a secret never wraps anything, and a wrapper that could would
// let this path create envelopes it is not authorized to create.
type hardwareWrapper struct {
	inner   Hardware
	route   registry.Route
	backend string
}

func (wrapper *hardwareWrapper) Backend() string { return wrapper.backend }

func (wrapper *hardwareWrapper) WrapKey(context.Context, envelope.KeyRef, []byte, []byte) ([]byte, error) {
	return nil, errors.New("release-secret does not wrap")
}

func (wrapper *hardwareWrapper) UnwrapKey(ctx context.Context, ref envelope.KeyRef, wrapped, aad []byte) ([]byte, error) {
	// The envelope's account of which key opens it is checked against the route, not against itself.
	// The ID used to be satisfied by either the logical object or the binding's slot id; two accepted
	// answers is one more than the question has.
	if ref.ID != wrapper.route.ObjectID {
		return nil, errors.New("envelope names a key this route does not hold")
	}
	// A KEK VERSION MUST SELECT SOMETHING.
	//
	// This ignored ref.Version and routed every version to the same slot, so after a Rewrap to
	// version 2 the version-1 envelope still opened on the same physical key: rotation changed a
	// label and nothing else, and retiring a KEK was impossible without retiring the object. The
	// binding names the generation actually in the slot, and an envelope claiming another is refused
	// until it is rewrapped.
	if wrapper.route.KEKVersion == "" {
		return nil, errors.New("route names no KEK version, so a superseded envelope could not be told from a current one")
	}
	if ref.Version != wrapper.route.KEKVersion {
		return nil, errors.New("envelope names a KEK version this route does not hold")
	}
	// THE CARD IS ASKED FOR THE KEK'S ALGORITHM, NOT THE SECRET'S.
	//
	// route.Algorithm describes the object, and for an opaque secret it is "opaque" -- the only value
	// the capability matrix admits for release-secret. But this call is an ordinary unwrap once it
	// reaches the driver, and both drivers gate on the key in the slot: PKCS#11 accepts
	// rsa2048/3072/4096, PIV accepts rsa2048. Passing "opaque" made release-secret unserveable on
	// every real card, and the failure arrived as BACKEND_UNAVAILABLE -- retryable, though nothing
	// about it was transient. The binding names the wrapping key; the registry refuses a
	// release-secret binding that does not, so an empty value here means the route was built
	// somewhere that has not been taught this and must fail closed rather than fall back.
	if wrapper.route.KEKAlgorithm == "" {
		return nil, errors.New("route names no KEK algorithm, so no card could unwrap this data key")
	}
	unwrapRoute := wrapper.route
	unwrapRoute.Algorithm = wrapper.route.KEKAlgorithm
	dataKey, _, err := wrapper.inner.Execute(ctx, unwrapRoute, "unwrap", "regalia-envelope-v2",
		"application/vnd.regalia.data-key", wrapped, aad)
	if err != nil {
		return nil, err
	}
	return dataKey, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
