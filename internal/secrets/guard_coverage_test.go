package secrets

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// This file closes refusal guards a mutation sweep proved no test detected. Each one was verified
// by rewriting the guard to `if false && (<original>)` and observing what the package returned
// with it gone; those observed values are quoted in the comment above each test, because a test
// whose only justification is "the guard exists" is the one a later reader deletes as redundant.
//
// Every fixture here is built so the named guard is the ONLY thing that can refuse it. On a path
// of sequential refusals that is the whole difficulty: `err != nil` is satisfied by whichever
// check happens to fire first, and the release path has seven of them in a row.

// ---------------------------------------------------------------------------------------------
// Fixture helpers.
// ---------------------------------------------------------------------------------------------

// sealedLabelled seals a secret whose envelope ObjectID, KEK reference and binding context are
// chosen INDEPENDENTLY of one another.
//
// The package's existing helpers (sealed, sealedFor, sealedUnder) all derive at least two of the
// three from the same route, which is why no existing test can separate Releaser.Execute's
// object-identity guard from the context-digest check inside Envelope.Open: change the object and
// the context changes with it, so Open refuses first and the guard is never reached.
func sealedLabelled(t *testing.T, objectID string, kek envelope.KeyRef, bindingContext, secret []byte) []byte {
	t.Helper()
	env, err := envelope.Seal(context.Background(), &softWrapper{backend: kek.Backend}, kek,
		objectID, bindingContext, secret, rand.Reader, time.Now())
	if err != nil {
		t.Fatalf("the fixture itself would not seal: %v", err)
	}
	blob, err := env.Marshal()
	if err != nil {
		t.Fatalf("the fixture itself would not marshal: %v", err)
	}
	return blob
}

// contextDigestOf and contentAADFor reproduce envelope's unexported contextDigest and contentAAD.
//
// They exist only for handAssembled below, which has to build an envelope envelope.Seal refuses to
// build (a ciphertext that is nothing but a GCM tag). The replication is not taken on trust: every
// test that uses handAssembled also releases a NON-empty envelope built by the same code, so a
// drift in either shape fails that anchor loudly instead of quietly weakening the case under test.
// envelope.Version is read rather than hardcoded so a future version bump moves this with it.
func contextDigestOf(bindingContext []byte) string {
	sum := sha256.Sum256(bindingContext)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contentAADFor(objectID, digest string) []byte {
	return []byte("regalia-envelope-v" + strconv.Itoa(envelope.Version) + "\x00" + objectID +
		"\x00AES-256-GCM\x00" + digest)
}

// handAssembled builds an envelope byte-for-byte the way an offline CLI would, for the plaintext
// lengths the exported seal entry points refuse. envelope.Seal rejects len(plaintext) == 0 and
// envelope.SealAssembled demands len(ciphertext) >= 17, but validateEnvelope -- the check Parse and
// Marshal run -- admits len(Ciphertext) >= 16. That gap is what makes an empty release reachable.
//
// The data key is protected by softWrapper's fixed transform, the same one `card` unwraps with, so
// the whole release path runs against real AES-GCM.
func handAssembled(t *testing.T, r registry.Route, plaintext []byte) []byte {
	t.Helper()
	dataKey := make([]byte, 32)
	nonce := make([]byte, 12)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	digest := contextDigestOf(envelope.ReleaseContext(r.ObjectID, r.Purpose, r.Environment))
	env := envelope.Envelope{
		Version: envelope.Version, ObjectID: r.ObjectID,
		KEK:       envelope.KeyRef{Backend: r.Binding.Backend, ID: r.ObjectID, Version: r.KEKVersion},
		Algorithm: "AES-256-GCM", ContextDigest: digest, CreatedAt: time.Now().UTC(),
		Nonce:          nonce,
		Ciphertext:     aead.Seal(nil, nonce, plaintext, contentAADFor(r.ObjectID, digest)),
		WrappedDataKey: append([]byte("wrapped:"), dataKey...),
	}
	blob, err := env.Marshal()
	if err != nil {
		t.Fatalf("a hand-assembled envelope with a %d-byte ciphertext would not marshal (%v): the "+
			"reachability argument for the empty-release guard depends on it doing so", len(env.Ciphertext), err)
	}
	return blob
}

// ---------------------------------------------------------------------------------------------
// releaser.go: Releaser.Execute -- "route carries no purpose or environment"
// ---------------------------------------------------------------------------------------------

// A ROUTE THAT NAMES NO PURPOSE OR ENVIRONMENT BINDS NOTHING, AND MUST NOT RELEASE.
//
// envelope.ReleaseContext concatenates objectID, purpose and environment. Hand it two empty strings
// and it still returns a perfectly well-formed context -- one that says only "this object", which
// is the thing the route already said. An envelope sealed under that degenerate context then opens
// under any purpose and any environment, which is precisely the property
// TestReleaseContextComesFromTheRouteNotTheCaller exists to guarantee is absent.
//
// Nothing detected this. With the guard rewritten to `if false && (route.Purpose == "" ||
// route.Environment == "")`, the observed result for the both-empty row was
// `out="secret-bound-to-neither-purpose-nor-environment" contentType="application/vnd.regalia.secret"
// err=<nil>` -- a successful release of a secret bound to neither.
//
// Each row seals under ITS OWN route's derived context, so the digest matches and Envelope.Open
// cannot refuse: the guard named above is the only refuser left standing. The complete route is an
// ANCHOR, not a gate -- without it a guard that refused every route would satisfy the whole table.
func TestReleaseRefusesARouteCarryingNoPurposeOrEnvironment(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		purpose   string
		env       string
		releases  bool
		binds     string
		secretFor string
	}{
		{name: "anchor: purpose and environment both named", purpose: "deployment-api", env: "production",
			releases: true, secretFor: "secret-bound-to-both"},
		{name: "neither purpose nor environment", purpose: "", env: "",
			binds: "neither the purpose nor the environment", secretFor: "secret-bound-to-neither-purpose-nor-environment"},
		{name: "no purpose", purpose: "", env: "production",
			binds: "no purpose, so an envelope sealed for any purpose opens", secretFor: "secret-bound-to-no-purpose"},
		{name: "no environment", purpose: "deployment-api", env: "",
			binds: "no environment, so a production envelope opens under a staging authorization", secretFor: "secret-bound-to-no-environment"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			degenerate := route("opaque-token")
			degenerate.Purpose, degenerate.Environment = testCase.purpose, testCase.env
			blob := sealedFor(t, degenerate, []byte(testCase.secretFor))

			released, contentType, err := (&Releaser{inner: &card{}}).Execute(context.Background(),
				degenerate, "release-secret", "regalia-envelope-v2", "", blob, nil)

			if testCase.releases {
				if err != nil {
					t.Fatalf("a complete route did not release (%v): every row below would then be "+
						"satisfied by a guard that refuses everything", err)
				}
				if string(released) != testCase.secretFor {
					t.Fatalf("the anchor released %q, want %q", released, testCase.secretFor)
				}
				return
			}
			if err == nil {
				t.Fatalf("DEFECT: a route naming %s released %q as %q -- the binding context derived "+
					"from it constrains less than it appears to", testCase.binds, released, contentType)
			}
			if !strings.Contains(err.Error(), "no purpose or environment") {
				t.Fatalf("refused by the wrong guard: %v -- want the route's own refusal, not a "+
					"downstream context-digest mismatch", err)
			}
			if len(released) != 0 || contentType != "" {
				t.Errorf("a refused release still produced %d bytes as %q", len(released), contentType)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// releaser.go: Releaser.Execute -- "envelope belongs to a different object than the authorized route"
// ---------------------------------------------------------------------------------------------

// THE OBJECT-IDENTITY GUARD IS NOT BACKSTOPPED BY THE CONTEXT DIGEST.
//
// TestEnvelopeForAnotherObjectIsRefused presents an envelope sealed entirely for one object on
// another object's route, and stays green with this guard removed -- but by the WRONG DETECTOR:
// the derived context no longer matches the digest, so Envelope.Open refuses with
// ErrInvalidEnvelope. The measured pristine-vs-mutated pair for that test's fixture was
// `err=envelope belongs to a different object than the authorized route` before and
// `err=invalid secret envelope isInvalidEnvelope=true` after -- refused either way, so the test
// cannot tell that the guard is gone.
//
// The envelope below is labelled for "opaque-token" while its KEK reference AND its binding
// context both belong to "different-object", the route presented. Everything downstream therefore
// agrees with the route and only Releaser.Execute's own comparison of parsed.ObjectID against
// route.ObjectID is left to refuse it. With that comparison rewritten to
// `if false && (parsed.ObjectID != route.ObjectID)`, the observed result was
// `out="secret-labelled-for-opaque-token" ct="application/vnd.regalia.secret" err=<nil>`.
//
// The first row is an ANCHOR: the identical construction with the label corrected must release, so
// the refusal below is attributable to the object label and to nothing else in the fixture.
func TestEnvelopeWhoseObjectDiffersFromItsContextAndKEKIsRefusedByObjectIdentity(t *testing.T) {
	authorized := route("different-object")
	// Both derived from the ROUTE, not from the envelope's label, so neither can refuse.
	kek := envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: authorized.ObjectID, Version: authorized.KEKVersion}
	bindingContext := envelope.ReleaseContext(authorized.ObjectID, authorized.Purpose, authorized.Environment)

	anchor := sealedLabelled(t, authorized.ObjectID, kek, bindingContext, []byte("secret-labelled-for-different-object"))
	released, _, err := (&Releaser{inner: &card{}}).Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", anchor, nil)
	if err != nil || string(released) != "secret-labelled-for-different-object" {
		t.Fatalf("the anchor did not release (%q, %v): the refusal below would then prove nothing "+
			"about the object label", released, err)
	}

	mislabelled := sealedLabelled(t, "opaque-token", kek, bindingContext, []byte("secret-labelled-for-opaque-token"))
	released, contentType, err := (&Releaser{inner: &card{}}).Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", mislabelled, nil)
	if err == nil {
		t.Fatalf("DEFECT: an envelope belonging to %q was released under authorization for %q, "+
			"returning %q as %q", "opaque-token", authorized.ObjectID, released, contentType)
	}
	if !strings.Contains(err.Error(), "belongs to a different object") {
		t.Fatalf("refused by the wrong guard: %v", err)
	}
	// The distinction matters to the caller, not only here: Coordinator.execute maps
	// envelope.ErrInvalidEnvelope to INVALID_ARGUMENT with an "integrity-failed" audit outcome,
	// which is a claim about the BYTES. These bytes are impeccable; the authorization is wrong.
	if errors.Is(err, envelope.ErrInvalidEnvelope) {
		t.Errorf("a cross-object release was reported as a malformed envelope (%v): the envelope is "+
			"well-formed and authenticates, and filing it as integrity-failed misnames the event", err)
	}
	if len(released) != 0 {
		t.Errorf("a refused release still produced %d bytes", len(released))
	}
}

// ---------------------------------------------------------------------------------------------
// sealer.go: sealWrapper.WrapKey -- the card's error must not be dropped
// ---------------------------------------------------------------------------------------------

var errCardRefusedTheWrap = errors.New("card said no")

// bytesAndErrorCard returns output AND an error from the same call. That is not a contrived
// combination: it is the ordinary shape of a partial read, a truncated APDU response, or a driver
// that fills its output buffer before discovering the operation failed.
type bytesAndErrorCard struct{ calls int }

func (c *bytesAndErrorCard) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	c.calls++
	return []byte("garbage-no-card-can-unwrap"), "application/vnd.regalia.data-key", errCardRefusedTheWrap
}

// A CARD THAT FAILS WHILE RETURNING BYTES MUST NOT PRODUCE A STORABLE ENVELOPE.
//
// The sweep's claimed backstop for this guard was SealAssembled's `err != nil || len(wrapped) == 0`,
// which holds only for a backend that returns nothing on failure. It does not hold for one that
// returns bytes alongside the error, and nothing in the Hardware contract forbids that.
//
// With `if false && (err != nil)` in sealWrapper.WrapKey, the observed results were
// `wrapped="garbage-no-card-can-unwrap" err=<nil>` from WrapKey directly, and -- through the shape
// Coordinator.seal uses -- `WrappedDataKey="garbage-no-card-can-unwrap" err=<nil>`: a complete,
// marshallable envelope whose wrapped data key is a failed card's leavings. The secret inside it is
// unrecoverable and nothing says so until someone needs it.
//
// Both halves are asserted with t.Errorf rather than t.Fatalf so a regression reports the direct
// refusal and its consequence together instead of stopping at the first.
func TestSealWrapKeyRefusesWhenTheCardErrorsEvenIfItReturnsBytes(t *testing.T) {
	sealing := sealRoute()
	kek := envelope.KeyRef{Backend: sealing.Binding.Backend, ID: sealing.ObjectID, Version: sealing.KEKVersion}

	// Directly: the card's own error is what must come back, so errors.Is names the sentinel
	// rather than trusting that "some error" appeared.
	card := &bytesAndErrorCard{}
	wrapped, err := sealWrapperFor(t, card).WrapKey(context.Background(), kek,
		make([]byte, 32), []byte("aad"))
	if !errors.Is(err, errCardRefusedTheWrap) {
		t.Errorf("DEFECT: the card refused the wrap and WrapKey returned err=%v, wrapped=%q -- the "+
			"failure was dropped because the card also returned bytes", err, wrapped)
	}
	if len(wrapped) != 0 {
		t.Errorf("a failed wrap still produced %d bytes: %q", len(wrapped), wrapped)
	}
	if card.calls != 1 {
		t.Errorf("the card was asked %d times, want exactly 1", card.calls)
	}

	// And through envelope.SealAssembled, the function Coordinator.seal calls with this wrapper:
	// the consequence of dropping the error is a stored envelope, not merely a missing error.
	bindingContext := envelope.ReleaseContext(sealing.ObjectID, sealing.Purpose, sealing.Environment)
	dataKey, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, []byte("a-deployment-token"),
		contentAADFor(sealing.ObjectID, contextDigestOf(bindingContext)))

	assembled, err := envelope.SealAssembled(context.Background(), sealWrapperFor(t, &bytesAndErrorCard{}),
		kek, sealing.ObjectID, bindingContext, ciphertext, nonce, dataKey, time.Now())
	if !errors.Is(err, envelope.ErrBackendUnavailable) {
		t.Errorf("DEFECT: SealAssembled returned err=%v against a card that refused the wrap; its "+
			"WrappedDataKey is now %q, and the envelope is marshallable and storable",
			err, assembled.WrappedDataKey)
	}
	if len(assembled.WrappedDataKey) != 0 {
		t.Errorf("a failed seal produced an envelope carrying %d wrapped-key bytes", len(assembled.WrappedDataKey))
	}
}

// ---------------------------------------------------------------------------------------------
// releaser.go: Releaser.Execute -- the receiver guard
// ---------------------------------------------------------------------------------------------

// executeRecovering turns a panic into a value. A panicking Execute would otherwise take the whole
// test binary down, which reports one crash instead of saying which receiver and which operation
// caused it -- and leaves every test after it unrun.
func executeRecovering(receiver *Releaser, r registry.Route, operation string, blob []byte) (out []byte, panicked any, err error) {
	defer func() { panicked = recover() }()
	out, _, err = receiver.Execute(context.Background(), r, operation, "regalia-envelope-v2", "", blob, nil)
	return out, nil, err
}

// A RELEASER THAT WAS NEVER GIVEN A BACKEND MUST REFUSE, NOT PANIC.
//
// NewReleaser refuses a nil backend, and TestReleaserPassesOtherOperationsThrough asserts that --
// which is a DIFFERENT guard, and is what makes this one look covered. Releaser has an unexported
// field, so `&Releaser{}` compiles in this package but not outside it; a nil *Releaser, however, is
// what any caller gets from `releaser, err := secrets.NewReleaser(...)` when it ignores err, and
// cmd/regalia-kms/main.go and Coordinator both hold this type behind an interface where a nil
// pointer is not a nil interface.
//
// With `if false && (releaser == nil || releaser.inner == nil)`, all four combinations below were
// observed to panic: `runtime error: invalid memory address or nil pointer dereference` -- on the
// passthrough path at `releaser.inner.Execute`, and on the release path at the wrapper
// construction that reads releaser.inner. A daemon-wide panic is a worse outcome than a refusal
// even when the request itself was doomed.
func TestZeroValueReleaserRefusesRatherThanPanics(t *testing.T) {
	authorized := route("opaque-token")
	blob := sealed(t, "opaque-token", []byte("s3cret"))

	// A well-formed envelope for this exact route, so the release path runs past Parse and the
	// object, context and KEK checks and actually reaches the code that dereferences inner.
	// Garbage bytes would return the parse error before any dereference and prove nothing.
	var nilReleaser *Releaser
	for _, receiver := range []struct {
		name string
		r    *Releaser
	}{
		{"a nil *Releaser, as returned alongside an error nobody checked", nilReleaser},
		{"a zero-value &Releaser{}, built without the constructor", &Releaser{}},
	} {
		for _, operation := range []string{"sign", "release-secret"} {
			t.Run(receiver.name+" / "+operation, func(t *testing.T) {
				out, panicked, err := executeRecovering(receiver.r, authorized, operation, blob)
				if panicked != nil {
					t.Fatalf("DEFECT: %s panicked instead of refusing: %v", receiver.name, panicked)
				}
				if !errors.Is(err, ErrUnavailable) {
					t.Fatalf("err = %v, want ErrUnavailable so the coordinator classifies it as a "+
						"backend fault rather than as the caller's malformed request", err)
				}
				if len(out) != 0 {
					t.Errorf("a refused call still produced %d bytes", len(out))
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------------------------
// releaser.go: Releaser.Execute -- "envelope released an empty secret"
// ---------------------------------------------------------------------------------------------

// AN ENVELOPE THAT DECRYPTS TO NOTHING MUST NOT LOOK LIKE A RELEASE.
//
// A 16-byte ciphertext is exactly an AES-GCM tag over zero bytes. envelope.Seal refuses to build
// one (len(plaintext) == 0) and SealAssembled refuses it too (len(ciphertext) >= 17), but
// validateEnvelope -- which is what Parse and Marshal run -- admits len(Ciphertext) >= 16, so such
// an envelope round-trips through both and authenticates perfectly on release. Only this guard
// stands between it and a success-shaped answer.
//
// With `if false && (len(released) == 0)`, the observed result was
// `out=[] len=0 contentType="application/vnd.regalia.secret" err=<nil>`: a successful release
// carrying a real secret content type and no secret. Coordinator.execute's
// `len(output) == 0 || outputType == ""` catches it end-to-end today, which is why this survived
// the sweep -- but Releaser.Execute is exported, is held behind an interface, and is one layer away
// from that check.
//
// The non-empty release is an ANCHOR, and it also proves handAssembled's replication of the
// envelope's content AAD is correct: if it were not, the anchor would fail to authenticate and the
// empty case below would be refused for the wrong reason.
func TestAnEnvelopeWhoseCiphertextIsOnlyATagReleasesNothing(t *testing.T) {
	authorized := route("opaque-token")

	anchor := handAssembled(t, authorized, []byte("a"))
	released, contentType, err := (&Releaser{inner: &card{}}).Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", anchor, nil)
	if err != nil || !bytes.Equal(released, []byte("a")) || contentType != "application/vnd.regalia.secret" {
		t.Fatalf("a hand-assembled 17-byte-ciphertext envelope did not release (%q, %q, %v): the "+
			"empty case below would then be refused by the AEAD rather than by the guard",
			released, contentType, err)
	}

	empty := handAssembled(t, authorized, nil)
	released, contentType, err = (&Releaser{inner: &card{}}).Execute(context.Background(), authorized,
		"release-secret", "regalia-envelope-v2", "", empty, nil)
	if err == nil {
		t.Fatalf("DEFECT: an envelope holding no plaintext released successfully as %q with %d bytes "+
			"-- a caller cannot tell that from a secret that is genuinely empty", contentType, len(released))
	}
	if !strings.Contains(err.Error(), "released an empty secret") {
		t.Fatalf("refused by the wrong guard: %v", err)
	}
	if contentType != "" {
		t.Errorf("a refused release still advertised content type %q", contentType)
	}
}

// ---------------------------------------------------------------------------------------------
// releaser.go: Releaser.Execute -- the parse error must survive as ErrInvalidEnvelope
// ---------------------------------------------------------------------------------------------

// A MALFORMED ENVELOPE MUST REACH THE CALLER AS ErrInvalidEnvelope, NOT MERELY AS SOME ERROR.
//
// TestHardwareFailureAndBadEnvelopeAreDifferentClasses feeds "not-an-envelope" in and asserts only
// `err != nil` and `!errors.Is(err, ErrUnavailable)`. Both still hold with this guard removed, so
// it stayed green: envelope.Parse returns the ZERO Envelope alongside its error, whose ObjectID is
// "", and execution falls through to the next guard. The observed result for all three inputs
// under `if false && (err != nil)` was
// `err=envelope belongs to a different object than the authorized route isInvalidEnvelope=false`.
//
// The identity of that error is load-bearing one layer up. Coordinator.execute branches on
// `errors.Is(err, envelope.ErrInvalidEnvelope)` to answer INVALID_ARGUMENT/400 and to record the
// audit outcome "integrity-failed"; everything else goes to classifyExecution. Losing the wrapper
// costs the caller its status code and costs the tamper-evident trail the one event it most needs
// to name. So the assertion is errors.Is, not err != nil.
func TestAMalformedEnvelopeIsReportedAsErrInvalidEnvelope(t *testing.T) {
	// The route names a real object on purpose. If ObjectID were also empty, the substituted
	// guard could not fire either and the zero envelope would be refused further down by
	// Envelope.Open -- still as ErrInvalidEnvelope, and the test would pass with the guard gone.
	authorized := route("opaque-token")

	for _, testCase := range []struct {
		name string
		data []byte
	}{
		{"not JSON at all", []byte("not-an-envelope")},
		{"JSON with an unknown field", []byte(`{"version":2,"nope":1}`)},
		{"no bytes at all", nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			released, contentType, err := (&Releaser{inner: &card{}}).Execute(context.Background(),
				authorized, "release-secret", "regalia-envelope-v2", "", testCase.data, nil)
			if !errors.Is(err, envelope.ErrInvalidEnvelope) {
				t.Fatalf("DEFECT: err = %v, which does not wrap envelope.ErrInvalidEnvelope -- the "+
					"coordinator will answer with classifyExecution's verdict instead of "+
					"INVALID_ARGUMENT and will file the request as backend-failed", err)
			}
			if errors.Is(err, ErrUnavailable) {
				t.Errorf("a malformed envelope was reported as a backend failure and would be retried forever")
			}
			if len(released) != 0 || contentType != "" {
				t.Errorf("a refused release still produced %d bytes as %q", len(released), contentType)
			}
		})
	}
}
