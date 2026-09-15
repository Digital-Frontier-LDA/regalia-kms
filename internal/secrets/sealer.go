package secrets

import (
	"context"
	"errors"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// sealWrapper satisfies envelope.Wrapper for the SEAL direction, and is the mirror of
// hardwareWrapper. Only WrapKey is reachable: sealing never unwraps, and a wrapper that could would
// let this path open envelopes it is not authorized to open.
//
// THE CARD IS ASKED FOR THE KEK'S ALGORITHM, NOT THE SECRET'S -- the same defect the release path
// had, in the other direction. route.Algorithm is "opaque" for the objects the matrix admits for
// seal-envelope, and nitrokey's `wrap` case passes it straight to keywrap.RSAOAEP, which accepts
// only rsa2048/3072/4096. Sealing under the object's algorithm would produce nothing at all, or --
// worse if a future backend were laxer -- an envelope no card could ever unwrap, discovered when
// somebody needed the secret rather than when they stored it.
type sealWrapper struct {
	inner   Hardware
	route   registry.Route
	backend string
}

// NewSealWrapper exposes the seal-direction wrapper for callers assembling an envelope against a
// commissioned KEK. The backend comes from the ROUTE rather than from anything a caller supplies:
// the envelope's own account of which key protects it is checked against this, not against itself.
func NewSealWrapper(inner Hardware, route registry.Route) (envelope.Wrapper, error) {
	if inner == nil {
		return nil, errors.New("seal requires a backend")
	}
	if route.KEKAlgorithm == "" || route.KEKVersion == "" {
		return nil, errors.New("route names no KEK algorithm or version, so no card could wrap this data key")
	}
	// The backend is checked HERE rather than left to validateKeyRef inside SealAssembled.
	// An empty backend builds a wrapper that looks fine and then fails much later as
	// ErrInvalidEnvelope, which says the envelope is malformed when in fact the ROUTE never
	// named a device -- a diagnosis pointing at the caller's request instead of at the
	// manifest. The construction is the last point where the cause is still legible.
	if route.Binding.Backend == "" {
		return nil, errors.New("route names no backend, so nothing identifies the card that would wrap this data key")
	}
	return &sealWrapper{inner: inner, route: route, backend: route.Binding.Backend}, nil
}

func (wrapper *sealWrapper) Backend() string { return wrapper.backend }

func (wrapper *sealWrapper) UnwrapKey(context.Context, envelope.KeyRef, []byte, []byte) ([]byte, error) {
	return nil, errors.New("seal-envelope does not unwrap")
}

func (wrapper *sealWrapper) WrapKey(ctx context.Context, ref envelope.KeyRef, dataKey, aad []byte) ([]byte, error) {
	if ref.ID != wrapper.route.ObjectID {
		return nil, errors.New("envelope names a key this route does not hold")
	}
	if ref.Version != wrapper.route.KEKVersion {
		return nil, errors.New("envelope names a KEK version this route does not hold")
	}
	wrapRoute := wrapper.route
	wrapRoute.Algorithm = wrapper.route.KEKAlgorithm
	wrapped, _, err := wrapper.inner.Execute(ctx, wrapRoute, "wrap", "regalia-envelope-v2",
		"application/vnd.regalia.data-key", dataKey, aad)
	if err != nil {
		return nil, err
	}
	return wrapped, nil
}
