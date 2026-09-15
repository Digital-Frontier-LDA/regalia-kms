package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A ROUTE THAT NAMES NO KEK VERSION MUST NOT REACH THE CARD.
//
// releaser.go's version guard was recorded on the sweep issue as "not a gap", on the evidence that
// the entire package suite passed with it removed. That is the definition of a survivor, not
// evidence that no input can tell the difference — and an input can.
//
// The guard is masked for every envelope that names a version: with the route's version empty and
// the envelope's set, the NEXT guard refuses the mismatch, same outcome. It is unmasked only when
// BOTH are empty, and then the two guards disagree completely. Measured, wrapper built directly:
//
//	route.KEKVersion=""  ref.Version=""   guard present -> refused, card never called
//	                                      guard removed -> CARD CALLED with the route
//	route.KEKVersion=""  ref.Version="2"  either way    -> refused (masked by the next guard)
//	route.KEKVersion="2" ref.Version="2"  either way    -> card called (control, unchanged)
//
// So without it an envelope carrying no KEK version is handed to the token against a route that
// names no KEK version, which is exactly what the code comment says must not happen: "a superseded
// envelope could not be told from a current one". Rotation stops meaning anything, because nothing
// distinguishes the generation an envelope was wrapped under from the one now in the slot.
//
// Its sibling one guard further down — the KEK ALGORITHM check — has had
// TestReleaseRefusesABindingWithNoKEKAlgorithm all along. The version twin had nothing. The
// asymmetry is in the test file, not the code.
//
// Isolation: the object id matches so the identity guard cannot fire, and the KEK algorithm is a
// real one so the guard below cannot fire either. The card is a recorder, so "refused" is
// distinguished from "refused after asking the token" — which is the distinction that matters,
// since the point of the guard is that hardware is never consulted.
func TestReleaseRefusesARouteThatNamesNoKEKVersion(t *testing.T) {
	newWrapper := func(version string) (*hardwareWrapper, *recorder) {
		rec := &recorder{}
		return &hardwareWrapper{
			inner:   rec,
			backend: "nitrokey-pkcs11",
			route: registry.Route{
				ObjectID: "opaque-token", KEKVersion: version, KEKAlgorithm: "rsa2048",
			},
		}, rec
	}

	// Control: an identical route that DOES name a version reaches the token, so a refusal below
	// cannot be blamed on the fixture being malformed in some unrelated way.
	wrapper, rec := newWrapper("2")
	_, _ = wrapper.UnwrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "opaque-token", Version: "2"},
		[]byte("wrapped-data-key"), []byte("aad"))
	if rec.seen.ObjectID != "opaque-token" {
		t.Fatalf("control is broken, so the refusal below would prove nothing: a route naming "+
			"version 2 did not reach the token (card saw route %q)", rec.seen.ObjectID)
	}

	wrapper, rec = newWrapper("")
	out, err := wrapper.UnwrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "opaque-token", Version: ""},
		[]byte("wrapped-data-key"), []byte("aad"))
	if err == nil {
		t.Fatalf("DEFECT: an envelope naming no KEK version was unwrapped against a route naming "+
			"no KEK version, releasing %q; nothing distinguishes a superseded envelope from a "+
			"current one, so rotating the key retires nothing", out)
	}
	if rec.seen.ObjectID != "" {
		t.Fatalf("DEFECT: the route reached the token (card saw %q) before being refused; the guard "+
			"exists so that an unversioned route is refused WITHOUT consulting hardware",
			rec.seen.ObjectID)
	}
	if want := "route names no KEK version"; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal is %q, want it to contain %q — the next guard down refuses the same input "+
			"whenever the envelope names a version, so only the message distinguishes the two",
			err.Error(), want)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("DEFECT: an unversioned route was reported as %v, which is retryable; no retry can "+
			"add a version to a route, so the caller would retry forever", ErrUnavailable)
	}
}
