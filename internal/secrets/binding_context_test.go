package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func productionRoute() registry.Route {
	return registry.Route{
		ObjectID: "deployment-api-token", Purpose: "deployment-api", Environment: "production",
		Algorithm: "opaque", KEKAlgorithm: "rsa2048", KEKVersion: "2",
		Binding: registry.Binding{Backend: "nitrokey-pkcs11", ObjectID: "deployment-api-token",
			KEKAlgorithm: "rsa2048", KEKVersion: "2"},
	}
}

func sealedFor(t *testing.T, route registry.Route, secret []byte) []byte {
	t.Helper()
	env, err := envelope.Seal(context.Background(), &softWrapper{backend: "nitrokey-pkcs11"},
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: route.ObjectID, Version: route.KEKVersion},
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

// THE CONTEXT AN ENVELOPE IS OPENED UNDER IS THE KMS'S, NOT THE CALLER'S.
//
// ENVELOPE.md says it in its own words: the context "must be independently reconstructed by the
// KMS ... It must not be accepted as an unverified opaque client assertion." It was exactly that.
// The caller sent `envelope_aad_base64`, the handler decoded it, the coordinator handed it to the
// hardware unchanged, and nothing compared it to anything. The digest then proved only that whoever
// presented the envelope knew the string it was sealed with -- not that the release matched the
// authorization that had just been granted.
//
// So an envelope sealed for one purpose and environment could be released under a request naming
// another, because the caller supplied both halves and they agreed with each other. The route is
// server-side: its purpose is checked against the manifest and its environment comes from the
// manifest. Deriving the context from it is what makes the binding mean something.
func TestReleaseContextComesFromTheRouteNotTheCaller(t *testing.T) {
	authorized := productionRoute()
	blob := sealedFor(t, authorized, []byte("s3cret"))

	releaser, _ := NewReleaser(&card{})
	if _, _, err := releaser.Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", blob, nil); err != nil {
		t.Fatalf("an envelope sealed for its own route did not open: %v", err)
	}

	// The same envelope, presented on a route the KMS authorized for a different environment.
	staging := authorized
	staging.Environment = "staging"
	released, _, err := releaser.Execute(context.Background(), staging,
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("a production envelope was released under a staging authorization: the environment the envelope was sealed for is not the environment that was authorized")
	}

	// And on a route authorized for a different purpose.
	other := authorized
	other.Purpose = "some-other-purpose"
	released, _, err = releaser.Execute(context.Background(), other,
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err == nil || len(released) != 0 {
		t.Fatal("an envelope sealed for one purpose was released under another")
	}
}

// ---------------------------------------------------------------------------------------------
// The context is derived from the route (above). These two hold the step after it: that the
// derived value actually reaches the token.
// ---------------------------------------------------------------------------------------------

// aadRecorder captures the binding context the wrappers hand the token.
//
// EVERY OTHER DOUBLE IN THIS PACKAGE DISCARDS IT, which is the whole reason the two forwarding
// sites below were invisible (TESTING.md §3, the test double that ignores the field under test).
// `card.Execute` accepts an aad and passes it to a softWrapper whose UnwrapKey signature is
// `(_ context.Context, _ envelope.KeyRef, wrapped, _ []byte)`; `recorder` and `wrapRecorder` keep
// the ROUTE and nothing else.
type aadRecorder struct {
	inner                card
	seenWrap, seenUnwrap []byte
	sawWrap, sawUnwrap   bool
}

// The flag is recorded separately from the bytes on purpose. `append([]byte(nil), aad...)` yields
// nil for a nil aad, so the recorded value alone cannot tell "handed nothing" from "never called"
// -- and those are exactly the two outcomes these tests have to keep apart.
func (r *aadRecorder) Execute(ctx context.Context, route registry.Route, operation, format,
	contentType string, data, aad []byte) ([]byte, string, error) {
	switch operation {
	case "unwrap":
		r.seenUnwrap, r.sawUnwrap = append([]byte(nil), aad...), true
	case "wrap":
		r.seenWrap, r.sawWrap = append([]byte(nil), aad...), true
		return []byte("wrapped-data-key"), "application/vnd.regalia.wrapped-key", nil
	}
	return r.inner.Execute(ctx, route, operation, format, contentType, data, aad)
}

// THE BINDING CONTEXT MUST REACH THE CARD, NOT MERELY BE DERIVED.
//
// TestReleaseContextComesFromTheRouteNotTheCaller proves the KMS builds the context itself instead
// of taking the caller's. It does not prove the value it built ever leaves this package.
// hardwareWrapper.UnwrapKey forwards it as the `aad` argument of Hardware.Execute, and that
// argument is what both providers turn into the OAEP label: nitrokey/provider.go calls
// `keywrap.OpenFrame(frame, aad)` and yubikey/provider.go does the same. SHA256(label) sits in
// bytes 4..36 of the frame, and comparing it is the only thing that makes an unwrapped data key
// belong to this object, purpose and environment.
//
// WHAT THE SUITE DID WITHOUT THIS TEST, measured by replacing that one argument with `nil`
// (`"application/vnd.regalia.data-key", wrapped, nil)` in hardwareWrapper.UnwrapKey): secrets,
// operations, integration and cmd/regalia-kms all stay green. Nothing at any layer noticed that
// the token had been asked to unwrap under no context at all.
//
// IT IS THE REFUSAL DIRECTION, which is the one a suite full of negative cases cannot see. On a
// real card keywrap.OpenFrame refuses an empty label outright (`len(label) == 0`), so a KMS with
// this argument dropped does not leak a secret -- it loses every one of them, and the error the
// caller receives blames the envelope rather than naming the argument that went missing.
func TestTheTokenIsHandedTheBindingContextWhenItUnwraps(t *testing.T) {
	t.Run("the release wrapper forwards it verbatim", func(t *testing.T) {
		authorized := productionRoute()
		recorder := &aadRecorder{}
		wrapper := &hardwareWrapper{inner: recorder, route: authorized,
			backend: authorized.Binding.Backend}

		// A value nothing else on this path could invent, so an assertion that finds it can only
		// have found the one passed in here.
		sent := []byte("regalia-envelope-v2\x00deployment-api-token\x00AES-256-GCM\x00sha256:" +
			strings.Repeat("d", 64) + "\x00nitrokey-pkcs11\x00deployment-api-token\x002")

		dataKey, err := wrapper.UnwrapKey(context.Background(),
			envelope.KeyRef{Backend: authorized.Binding.Backend, ID: authorized.ObjectID,
				Version: authorized.KEKVersion},
			[]byte("wrapped:0123456789abcdef0123456789abcdef"), sent)
		if err != nil {
			t.Fatalf("UnwrapKey() = %v", err)
		}
		// KNOWN-GOOD ANCHOR: the unwrap reached the token and its answer came back. Without it a
		// wrapper that returned early on every call would satisfy nothing below by never being
		// contradicted.
		if !bytes.Equal(dataKey, []byte("0123456789abcdef0123456789abcdef")) {
			t.Fatalf("UnwrapKey returned %q, want the card's data key", dataKey)
		}
		if !recorder.sawUnwrap {
			t.Fatal("the token was never asked to unwrap, so nothing here says what it was handed")
		}
		if !bytes.Equal(recorder.seenUnwrap, sent) {
			t.Fatalf("the token was handed %q as its binding context; the envelope bound %q. Both providers pass this argument straight to keywrap.OpenFrame as the OAEP label, and an empty one is refused there.",
				recorder.seenUnwrap, sent)
		}
	})

	t.Run("the context the KMS derived is the one the token sees", func(t *testing.T) {
		authorized := productionRoute()
		blob := sealedFor(t, authorized, []byte("s3cret"))
		recorder := &aadRecorder{}
		releaser, err := NewReleaser(recorder)
		if err != nil {
			t.Fatal(err)
		}

		released, _, err := releaser.Execute(context.Background(), authorized,
			"release-secret", "regalia-envelope-v2", "", blob, nil)
		// KNOWN-GOOD ANCHOR: the release itself still works. The assertions below are all about
		// what the token was told, and a Releaser that refused everything would reach none of them.
		if err != nil {
			t.Fatalf("an envelope sealed for its own route did not open: %v", err)
		}
		if !bytes.Equal(released, []byte("s3cret")) {
			t.Fatalf("released %q, want %q", released, "s3cret")
		}

		if !recorder.sawUnwrap {
			t.Fatal("the release completed without ever asking the token to unwrap the data key")
		}
		if len(recorder.seenUnwrap) == 0 {
			t.Fatal("the token was asked to unwrap under an EMPTY binding context: keywrap.OpenFrame refuses an empty label, so on a real card every release would fail and the error would name the envelope")
		}
		derived := contextDigestOf(envelope.ReleaseContext(authorized.ObjectID, authorized.Purpose,
			authorized.Environment))
		if !bytes.Contains(recorder.seenUnwrap, []byte(derived)) {
			t.Fatalf("the token was handed %q, which carries no digest of the context the KMS derived (%s): the value the route produced is not the value the card is asked to bind against",
				recorder.seenUnwrap, derived)
		}
	})
}

// THE SEAL DIRECTION, and the same measurement: replacing `aad` with `nil` in sealWrapper.WrapKey
// leaves secrets, operations, integration and cmd/regalia-kms green.
//
// Worse in this direction, for the reason TestSealWrapsWithTheKEKAlgorithmAndNotTheObjectsAlgorithm
// gives about its own field: nitrokey's `wrap` case hands this argument to keywrap.RSAOAEP as the
// label, and RSAOAEP refuses `len(label) == 0`. So the seal fails at the moment somebody stores a
// secret, with an error that describes neither the label nor the route.
func TestTheTokenIsHandedTheBindingContextWhenItWraps(t *testing.T) {
	recorder := &aadRecorder{}
	wrapper := sealWrapperFor(t, recorder)

	sent := []byte("regalia-envelope-v2\x00deployment-token\x00AES-256-GCM\x00sha256:" +
		strings.Repeat("e", 64) + "\x00nitrokey-pkcs11\x00deployment-token\x002")

	wrapped, err := wrapper.WrapKey(context.Background(),
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "deployment-token", Version: "2"},
		[]byte("0123456789abcdef0123456789abcdef"), sent)
	if err != nil {
		t.Fatalf("WrapKey() = %v", err)
	}
	// KNOWN-GOOD ANCHOR: the card was reached and its wrapped key came back.
	if !bytes.Equal(wrapped, []byte("wrapped-data-key")) {
		t.Fatalf("WrapKey returned %q, want the card's wrapped data key", wrapped)
	}
	if !recorder.sawWrap {
		t.Fatal("the token was never asked to wrap, so nothing here says what it was handed")
	}
	if !bytes.Equal(recorder.seenWrap, sent) {
		t.Fatalf("the token was handed %q as its binding context; the envelope bound %q. nitrokey's wrap case passes this argument to keywrap.RSAOAEP as the OAEP label, and an empty one is refused there.",
			recorder.seenWrap, sent)
	}
}

// A caller cannot choose the context by sending one.
func TestReleaseRefusesACallerSuppliedContext(t *testing.T) {
	route := productionRoute()
	blob := sealedFor(t, route, []byte("s3cret"))
	releaser, _ := NewReleaser(&card{})

	asserted := envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment)
	released, _, err := releaser.Execute(context.Background(), route,
		"release-secret", "regalia-envelope-v2", "", blob, asserted)
	if err == nil || len(released) != 0 {
		t.Fatal("a caller-supplied binding context was accepted: even one that happens to be correct means the field is load-bearing, and the next caller will send a different one")
	}
}
