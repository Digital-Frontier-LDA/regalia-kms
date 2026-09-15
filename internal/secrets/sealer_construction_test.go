package secrets

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type refusingHardware struct{}

func (refusingHardware) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	return nil, "", ErrUnavailable
}

// NewSealWrapper REFUSES A ROUTE THAT NAMES NOTHING, AT CONSTRUCTION.
//
// Every field checked here is one the wrapper cannot work without, and each was reachable
// as an empty string from a manifest. Left unchecked they build a wrapper that looks
// correct and fail much later inside SealAssembled as ErrInvalidEnvelope -- which says the
// envelope is malformed when the ROUTE was the thing that named no device. That diagnosis
// points at the caller's request instead of at the manifest, and construction is the last
// point where the cause is still legible.
//
// The backend case in particular was added with no test, which is how it stayed uncovered:
// disabling the check left every existing test passing.
func TestNewSealWrapperRefusesARouteThatNamesNothing(t *testing.T) {
	complete := registry.Route{
		ObjectID: "secret-1", KEKAlgorithm: "rsa2048", KEKVersion: "1",
		Binding: registry.Binding{Backend: "nitrokey-pkcs11"},
	}

	// The control first. Without it every refusal below is satisfied by a constructor that
	// refuses everything, and the test would pin nothing.
	if _, err := NewSealWrapper(refusingHardware{}, complete); err != nil {
		t.Fatalf("a complete route was refused (%v): the cases below would prove nothing", err)
	}

	for _, missing := range []struct {
		what  string
		route registry.Route
		why   string
	}{
		{"no backend", func() registry.Route { r := complete; r.Binding.Backend = ""; return r }(),
			"nothing identifies the card, and SealAssembled would report a malformed envelope instead"},
		{"no KEK algorithm", func() registry.Route { r := complete; r.KEKAlgorithm = ""; return r }(),
			"no card could be asked to wrap"},
		{"no KEK version", func() registry.Route { r := complete; r.KEKVersion = ""; return r }(),
			"no generation to check an envelope's reference against"},
	} {
		t.Run(missing.what, func(t *testing.T) {
			if _, err := NewSealWrapper(refusingHardware{}, missing.route); err == nil {
				t.Fatalf("DEFECT: a route with %s built a wrapper — %s", missing.what, missing.why)
			}
		})
	}

	if _, err := NewSealWrapper(nil, complete); err == nil {
		t.Error("DEFECT: a nil backend built a wrapper")
	}
}
