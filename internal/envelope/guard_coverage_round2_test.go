package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

// Round 2 of the refusal-guard sweep begun in guard_coverage_test.go, against guards a mutation
// sweep proved no committed test in the module detected. Same discipline as that file: one test
// per guard — or per OPERAND, where only one operand of a larger || chain is the claim — with a
// fixture built so the guard under test is the only thing in the function that can refuse it,
// and a comment naming concretely what the code returns once the guard is gone.
//
// WHAT IS ASSERTED, AND WHY IT IS NOT A MESSAGE. This package answers every refusal with one of
// two opaque package-level sentinels: ErrInvalidEnvelope ("invalid secret envelope") and
// ErrBackendUnavailable ("hardware wrapping backend unavailable"). No refusal carries a
// distinguishing message, so "assert the specific message" is not available. Each test below
// therefore asserts (a) WHICH sentinel came back — a caller's retry turns on exactly that
// distinction, an integrity failure being permanent and a backend failure transient, and
// Rewrap's own committed test already treats confusing the two as a defect — and (b) the
// distinguishing observable values: the returned envelope is the zero value, the card was called
// zero times, the KEK and wrapped data key did not move, the plaintext still comes back.
//
// PANICS. Three of these guards are the only thing between caller-supplied bytes and a panic in
// this package: coordinator.go calls envelope.Peek (which calls Parse) directly on request.Data,
// and the only recover() in the request path lives downstream in executor.go. Those tests call
// through withoutPanicking rather than letting the panic fly — an unrecovered panic takes the
// whole test binary down, which both hides which test detected a mutation (making "sole
// detector" unmeasurable) and stops every later test from running.
//
// ANCHORS ARE LAST. Every table's known-good row, and every standalone anchor, is placed AFTER
// the guard assertions. A t.Fatal in a positive control that runs first would stop the run
// before the assertions it exists to legitimise ever fire.

var round2CreatedAt = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

// round2Context is the binding context sealedFixture (peek_context_test.go) seals against.
func round2Context() []byte {
	return ReleaseContext("deployment-api-token", "deploy", "production")
}

// round2Card rebuilds the card sealedFixture sealed against: same backend, same key material,
// so an envelope that fixture produced unwraps under it. It is a SECOND card rather than the
// fixture's own so its call counter starts at zero and a test can assert that a refusal
// happened before the hardware was ever reached.
func round2Card(version string) *fakeHardware {
	return hardware("nitrokey-pkcs11", map[string][]byte{"company-kek:" + version: bytes.Repeat([]byte{1}, 32)})
}

// withoutPanicking runs call and turns a panic into an ordinary failure of this test.
//
// Needed because the guards below are exactly the ones whose removal panics. Letting the panic
// fly would kill the test binary: the run would report a crash instead of the specific refusal
// being pinned, no later test would execute, and a mutation sweep could not tell which test
// detected the mutation. Each caller's doc comment names where its input comes from and which
// line panics once the guard is gone.
func withoutPanicking(t *testing.T, what string, call func()) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("%s PANICKED: %v — the guard under test is the only thing standing between this input and that panic", what, value)
		}
	}()
	call()
}

// rewriteEnvelopeField re-encodes a real Marshal output with one top-level field replaced.
// Everything else — version, object id, algorithm, created_at, key ref, and the fields not named
// — is the fixture's own, so the guard under test is the only thing left that can refuse the
// result. []byte values re-encode as base64, matching the wire shape of nonce, ciphertext and
// wrapped key.
//
// The presence check matters: Parse sets DisallowUnknownFields, so a mistyped field name would
// ADD an unknown field and Parse would refuse for that reason instead, turning every gate below
// into a green that proves nothing.
func rewriteEnvelopeField(t *testing.T, encoded []byte, field string, value any) []byte {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if _, present := document[field]; !present {
		t.Fatalf("the fixture carries no %q field: rewriting it would add an unknown field, and Parse would then refuse the token for that reason rather than for the one under test", field)
	}
	replacement, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	document[field] = replacement
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return rewritten
}

// TestParseRefusesANonceGCMWouldPanicOn pins the len(envelope.Nonce) != 12 OPERAND of
// validateEnvelope's size guard — not the whole guard, which the sibling test below covers.
//
// Without this operand, an unmodified Marshal output whose nonce_base64 has been replaced with
// 11 bytes parses clean: err=nil, version=2, objectID="deployment-api-token", nonceLen=11.
// Calling Open on the envelope that comes back then panics —
// "crypto/cipher: incorrect nonce length given to GCM" — inside aead.Open in Envelope.Open,
// after the card has already unwrapped the data key. The panic is caller-reachable:
// coordinator.go hands request.Data to envelope.Peek (which calls Parse) and secrets/releaser.go
// calls Open on the parsed envelope, both upstream of the only recover() in the request path.
//
// Isolation: the token is an unmodified Seal+Marshal output with only nonce_base64 replaced, so
// metadata, context digest, key ref, ciphertext and wrapped key all validate — the nonce-length
// operand is the only refuser. The anchor row rewrites the SAME field with its own value, so it
// also proves the map round-trip is not what the gate is detecting.
func TestParseRefusesANonceGCMWouldPanicOn(t *testing.T) {
	sealed, encoded := sealedFixture(t, "1", round2CreatedAt)

	for _, test := range []struct {
		name     string
		nonce    []byte
		accepted bool
	}{
		{"one byte short of a GCM nonce", bytes.Repeat([]byte{0x11}, 11), false},
		{"one byte long", bytes.Repeat([]byte{0x11}, 13), false},
		{"no nonce at all", []byte{}, false},
		// ANCHOR, not a gate, and last on purpose: the fixture's own nonce, put back through
		// the same rewrite, must still parse. Without it a size guard that refused
		// everything would pass all three rows above.
		{"ANCHOR: the fixture's own 12-byte nonce", sealed.Nonce, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := rewriteEnvelopeField(t, encoded, "nonce_base64", test.nonce)

			var parsed Envelope
			var err error
			withoutPanicking(t, fmt.Sprintf("Parse of a token carrying a %d-byte nonce", len(test.nonce)), func() {
				parsed, err = Parse(token)
			})

			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil — if the rewrite itself is what Parse refuses, the rows above prove nothing about the nonce operand", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Parse accepted a %d-byte nonce: err = %v objectID = %q nonceLen = %d — without the len(Nonce) != 12 operand this envelope reaches Envelope.Open, where aead.Open panics with \"crypto/cipher: incorrect nonce length given to GCM\"",
					len(test.nonce), err, parsed.ObjectID, len(parsed.Nonce))
			}
			if parsed.ObjectID != "" {
				t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
			}
		})
	}

	// The panic itself lives in Open, not in Parse, so the guard is asserted there too — this
	// is the shape secrets/releaser.go drives, with a card that really does hold the key.
	t.Run("Open refuses the same envelope instead of panicking in GCM", func(t *testing.T) {
		card := round2Card("1")
		tampered := sealed.Clone()
		tampered.Nonce = tampered.Nonce[:11]

		var err error
		withoutPanicking(t, "Open on an envelope carrying an 11-byte nonce", func() {
			err = tampered.Open(context.Background(), card, round2Context(), func([]byte) error {
				t.Error("the callback ran on an envelope with an 11-byte nonce")
				return nil
			})
		})
		if !errors.Is(err, ErrInvalidEnvelope) {
			t.Errorf("Open() error = %v, want ErrInvalidEnvelope", err)
		}
		if card.calls != 0 {
			t.Errorf("the card was called %d times, want 0 — the nonce is refused at the entry guard, before any unwrap", card.calls)
		}
	})
}

// TestValidateEnvelopeRefusesEverySizeItsGuardBounds pins the WHOLE size guard in
// validateEnvelope. That guard is the entire body of the function after the metadata call, so
// removing it leaves validateEnvelope unable to refuse anything about sizes at all.
//
// The nonce operand is deliberately NOT exercised here: TestParseRefusesANonceGCMWouldPanicOn
// owns it, so a mutation of that single operand reds exactly one test and stays attributable.
// A mutation of the whole guard necessarily reds both, since the whole guard contains that
// operand.
//
// Without the guard, each row below parses clean. Observed: a 3-byte ciphertext returns err=nil
// objectID="deployment-api-token" ciphertextLen=3; an empty wrapped_data_key returns err=nil
// objectID="deployment-api-token" wrappedLen=0 — an envelope with no wrapped key at all, which
// no card can ever open, accepted as a valid secret.
//
// Isolation: every row is an unmodified Seal+Marshal output with exactly one field rewritten, so
// metadata, digest and key ref all validate and the size guard is the only refuser. Each row is
// also under maxEnvelopeBytes (the 1 MiB-plus ciphertext encodes to about 1.4 MB against a 2 MB
// cap), so Parse's own length check is not what refuses them.
func TestValidateEnvelopeRefusesEverySizeItsGuardBounds(t *testing.T) {
	sealed, encoded := sealedFixture(t, "1", round2CreatedAt)

	for _, test := range []struct {
		name     string
		field    string
		value    []byte
		accepted bool
	}{
		{"a ciphertext shorter than a GCM tag", "ciphertext_base64", bytes.Repeat([]byte{0x5A}, 3), false},
		{"a ciphertext one byte over the cap", "ciphertext_base64", bytes.Repeat([]byte{0x5A}, MaxPlaintextBytes+17), false},
		{"no wrapped data key at all", "wrapped_data_key_base64", []byte{}, false},
		{"a wrapped data key one byte over the cap", "wrapped_data_key_base64", bytes.Repeat([]byte{0x5A}, (64<<10)+1), false},
		// ANCHOR, not a gate, and last on purpose: the fixture's own ciphertext and wrapped
		// key, put back through the same rewrite, must parse. Without them a guard that
		// refused every size would pass all four rows above.
		{"ANCHOR: the fixture's own ciphertext", "ciphertext_base64", sealed.Ciphertext, true},
		{"ANCHOR: the fixture's own wrapped data key", "wrapped_data_key_base64", sealed.WrappedDataKey, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(rewriteEnvelopeField(t, encoded, test.field, test.value))

			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil — if the rewrite itself is what Parse refuses, the rows above prove nothing about the size guard", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Parse accepted %s (%d bytes in %s): err = %v objectID = %q — with the size guard removed validateEnvelope has no body left after the metadata call, so this token is stored and served as a valid secret",
					test.name, len(test.value), test.field, err, parsed.ObjectID)
			}
			if parsed.ObjectID != "" {
				t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
			}
		})
	}
}

// TestParseRefusesAContextDigestTooShortToSlice pins the WHOLE digest-shape guard in
// validateEnvelopeMetadata — the guard that stands immediately before
// hex.DecodeString(envelope.ContextDigest[7:]).
//
// Without it, a context_digest of "abc" panics: "runtime error: slice bounds out of range [7:3]",
// on the very next line, inside validateEnvelopeMetadata. That is caller-reachable —
// coordinator.go passes request.Data straight to envelope.Peek, which calls Parse, and the only
// recover() in the request path is downstream in executor.go. The second row is the quieter half
// of the same guard: without it, context_digest="sha512:0011" parses clean (err=nil,
// objectID="deployment-api-token"), so an envelope may name a digest algorithm this code does
// not compute.
//
// Rows are chosen so each survives a mutation of the len != 71 operand alone: "abc" is still
// caught by the len < 7 operand, and "sha512:0011" by the prefix operand. That keeps this test
// and TestParseRefusesAContextDigestThatIsNotThirtyTwoHexEncodedBytes attributable to different
// mutations; only the whole-guard mutation reds both.
//
// Isolation: each token is an unmodified Marshal output with only context_digest rewritten, and
// both replacements hex-decode cleanly after the prefix (or never reach the decode), so the
// shape guard is the only refuser.
func TestParseRefusesAContextDigestTooShortToSlice(t *testing.T) {
	sealed, encoded := sealedFixture(t, "1", round2CreatedAt)

	for _, test := range []struct {
		name     string
		digest   string
		accepted bool
	}{
		{"three characters, too short for the prefix slice", "abc", false},
		{"empty", "", false},
		{"a digest naming a different hash", "sha512:0011", false},
		// ANCHOR, not a gate, and last on purpose: the fixture's own digest, put back
		// through the same rewrite, must parse. Without it a guard that refused every
		// digest would pass all three rows above.
		{"ANCHOR: the fixture's own sha256 digest", sealed.ContextDigest, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := rewriteEnvelopeField(t, encoded, "context_digest", test.digest)

			var parsed Envelope
			var err error
			withoutPanicking(t, fmt.Sprintf("Parse of a token whose context_digest is %q", test.digest), func() {
				parsed, err = Parse(token)
			})

			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil — if the rewrite itself is what Parse refuses, the rows above prove nothing about the digest-shape guard", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Parse accepted context_digest = %q (%d chars): err = %v objectID = %q digest = %q — without the shape guard a short digest panics at hex.DecodeString(ContextDigest[7:]) and a long one carries a hash label this code never computes",
					test.digest, len(test.digest), err, parsed.ObjectID, parsed.ContextDigest)
			}
			if parsed.ObjectID != "" {
				t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
			}
		})
	}
}

// TestParseRefusesAContextDigestThatIsNotThirtyTwoHexEncodedBytes pins the
// len(envelope.ContextDigest) != 71 OPERAND of the digest-shape guard, leaving the len < 7 and
// prefix operands live.
//
// Every row below says "sha256:" and hex-decodes cleanly, so the two surviving operands accept
// them and only the length operand refuses. Without it, all three parse clean — observed err=nil
// objectID="deployment-api-token" for a digest carrying 64 bytes of hex, for one carrying a
// single byte, and for "sha256:" carrying nothing at all.
//
// This one is not a bypass: Open compares the stored digest against a freshly computed 71-char
// one, so such an envelope becomes unopenable rather than exploitable. What is lost is that
// "sha256:" means a SHA-256 digest — Parse hands back an envelope it has certified and the
// caller learns it is junk only at release time, on a card round-trip, with no diagnosis.
//
// Isolation: unmodified Marshal output, one field rewritten, and every row survives the whole
// guard's OTHER operands by construction.
func TestParseRefusesAContextDigestThatIsNotThirtyTwoHexEncodedBytes(t *testing.T) {
	sealed, encoded := sealedFixture(t, "1", round2CreatedAt)

	for _, test := range []struct {
		name     string
		digest   string
		accepted bool
	}{
		{"sha256 label over 64 hex-encoded bytes", "sha256:" + string(bytes.Repeat([]byte("ab"), 64)), false},
		{"sha256 label over one hex-encoded byte", "sha256:ab", false},
		{"the label and nothing else", "sha256:", false},
		// ANCHOR, not a gate, and last on purpose: the fixture's own 71-character digest,
		// put back through the same rewrite, must parse — and it is the row that proves the
		// length operand is not simply refusing every digest.
		{"ANCHOR: the fixture's own 71-character digest", sealed.ContextDigest, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Parse(rewriteEnvelopeField(t, encoded, "context_digest", test.digest))

			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil (digest was %d chars) — if the rewrite itself is what Parse refuses, the rows above prove nothing", err, len(test.digest))
				}
				return
			}
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Parse accepted a %d-character context_digest %q: err = %v objectID = %q — with the len != 71 operand removed, \"sha256:\" no longer means a SHA-256 digest and Parse certifies an envelope no card can ever open",
					len(test.digest), test.digest, err, parsed.ObjectID)
			}
			if parsed.ObjectID != "" {
				t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
			}
		})
	}
}

// TestOpenRefusesANilCallbackRatherThanPanickingAfterDecrypt pins the use == nil OPERAND of
// Envelope.Open's entry guard.
//
// Without it, Open runs to completion and panics at its last statement, "return use(plaintext)":
// "runtime error: invalid memory address or nil pointer dereference". By then the card has
// unwrapped the data key and the content has been decrypted, so the panic unwinds with plaintext
// live in a buffer whose deferred zero is the only thing that clears it. Open is exported and a
// caller in another package supplies the callback.
//
// Isolation: the envelope is a clean Seal output opened with a card holding its key and its own
// binding context, so the two sibling operands (the context-size bound and validateEnvelope) both
// pass and nothing else in Open can refuse. The card.calls assertion is what proves the refusal
// happens at the entry guard rather than after the unwrap.
func TestOpenRefusesANilCallbackRatherThanPanickingAfterDecrypt(t *testing.T) {
	sealed, _ := sealedFixture(t, "1", round2CreatedAt)
	card := round2Card("1")

	var err error
	withoutPanicking(t, "Open with a nil callback", func() {
		err = sealed.Open(context.Background(), card, round2Context(), nil)
	})
	// Errorf, not Fatalf: the call-count assertion below names a different half of the same
	// defect (the secret was decrypted before the panic) and must be allowed to report.
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Open(use=nil) error = %v, want ErrInvalidEnvelope", err)
	}
	if card.calls != 0 {
		t.Errorf("the card was called %d times for an Open that cannot deliver anything, want 0 — without the use == nil operand the unwrap and the AES-GCM decrypt both run before the nil dereference at \"return use(plaintext)\"", card.calls)
	}

	// ANCHOR, last on purpose: the same envelope, the same card, the same context, with a real
	// callback. Without it an Open that refused everything would pass the assertions above.
	anchorCard := round2Card("1")
	saw := false
	if err := sealed.Open(context.Background(), anchorCard, round2Context(), func(plaintext []byte) error {
		saw = bytes.Equal(plaintext, []byte("top-secret-value"))
		return nil
	}); err != nil {
		t.Fatalf("ANCHOR: Open() error = %v, want nil", err)
	}
	if !saw {
		t.Fatal("ANCHOR: the callback never saw the sealed value, so the refusal above cannot be attributed to the nil callback")
	}
}

// TestSealRefusesANilRandomSourceRatherThanPanicking pins the random == nil OPERAND of Seal's
// input guard.
//
// Without it, validateEnvelopeMetadata passes and io.ReadFull is handed a nil io.Reader:
// "runtime error: invalid memory address or nil pointer dereference", at the data-key read in
// Seal. Seal is exported and takes the reader from its caller, so nothing in this package decides
// that it is non-nil.
//
// Isolation: every other operand of the same guard is satisfied — a 16-byte plaintext (non-empty,
// under the cap), a binding context well under maxContextBytes, a non-zero createdAt — and the
// KEK and object id both pass validateEnvelopeMetadata, so random == nil is the only refuser.
func TestSealRefusesANilRandomSourceRatherThanPanicking(t *testing.T) {
	card := round2Card("1")
	kek := KeyRef{Backend: card.Backend(), ID: "company-kek", Version: "1"}

	var sealed Envelope
	var err error
	withoutPanicking(t, "Seal with a nil entropy source", func() {
		sealed, err = Seal(context.Background(), card, kek, "deployment-api-token",
			round2Context(), []byte("top-secret-value"), nil, round2CreatedAt)
	})
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Seal(random=nil) error = %v, want ErrInvalidEnvelope", err)
	}
	if card.calls != 0 {
		t.Errorf("the card was called %d times, want 0", card.calls)
	}
	if sealed.ObjectID != "" || len(sealed.Nonce) != 0 {
		t.Errorf("a refused Seal returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: the identical call with a real entropy source must succeed.
	// Without it a Seal that refused every input would pass the assertions above.
	anchorCard := round2Card("1")
	anchor, err := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"), rand.Reader, round2CreatedAt)
	if err != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", err)
	}
	if len(anchor.Nonce) != 12 || len(anchor.WrappedDataKey) == 0 {
		t.Fatalf("ANCHOR: Seal produced nonce=%d bytes wrapped=%d bytes", len(anchor.Nonce), len(anchor.WrappedDataKey))
	}
}

// failFirstReader fails its FIRST read after handing back a few bytes, then is healthy forever
// after.
//
// The obvious fixture — a reader that simply runs out — is wrong, and quietly so: it fails BOTH
// of Seal's reads, so with the data-key guard removed the nonce guard refuses instead and the
// test still goes green while certifying nothing. Failing once, early, leaves the data-key read
// as the only read that can fail.
type failFirstReader struct {
	prefix byte
	filler byte
	reads  int
}

func (reader *failFirstReader) Read(destination []byte) (int, error) {
	reader.reads++
	if reader.reads == 1 {
		count := 5
		if count > len(destination) {
			count = len(destination)
		}
		for index := 0; index < count; index++ {
			destination[index] = reader.prefix
		}
		return count, errors.New("entropy source returned EIO after 5 bytes")
	}
	for index := range destination {
		destination[index] = reader.filler
	}
	return len(destination), nil
}

// budgetedReader hands out exactly `remaining` bytes and then reports EOF, so Seal's 32-byte
// data-key read succeeds and the 12-byte nonce read is the only read that can fail.
type budgetedReader struct {
	remaining int
	filler    byte
}

func (reader *budgetedReader) Read(destination []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := len(destination)
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := 0; index < count; index++ {
		destination[index] = reader.filler
	}
	reader.remaining -= count
	return count, nil
}

// TestSealRefusesAnEntropySourceThatDidNotFillTheDataKey pins the io.ReadFull error guard on
// Seal's data-key read.
//
// Without it, Seal continues with a partially-filled key. Observed with the reader below:
// err=nil and the data key handed to the card is
// 0505050505000000000000000000000000000000000000000000000000000000 — five bytes of entropy and
// twenty-seven zeros, a 256-bit key with 40 bits in it, wrapped by the hardware and returned as
// a successful seal. Nothing downstream can notice: the envelope opens, round-trips and rotates
// normally for the whole of its life.
//
// Isolation: the reader is healthy from its second read onward, so the nonce read succeeds and
// this guard is the only read that can refuse. The card.calls assertion proves the refusal
// happens before the weak key ever reaches the hardware.
func TestSealRefusesAnEntropySourceThatDidNotFillTheDataKey(t *testing.T) {
	card := round2Card("1")
	kek := KeyRef{Backend: card.Backend(), ID: "company-kek", Version: "1"}

	sealed, err := Seal(context.Background(), card, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"),
		&failFirstReader{prefix: 0x05, filler: 0xab}, round2CreatedAt)

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Seal() error = %v, want ErrInvalidEnvelope — without the data-key read guard this returns a nil error and an envelope whose key is 5 random bytes followed by 27 zeros", err)
	}
	if card.calls != 0 {
		t.Errorf("the card wrapped %d keys, want 0 — a key the entropy source did not finish filling must never reach the hardware", card.calls)
	}
	if sealed.ObjectID != "" || len(sealed.WrappedDataKey) != 0 {
		t.Errorf("a refused Seal returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: the same reader with its one failure already spent (reads: 1
	// starts the counter past the failing read) must seal. Without it a Seal that refused every
	// reader would pass the assertions above — and it pins the refusal on the FAILED read
	// rather than on anything else about this reader type.
	anchorCard := round2Card("1")
	anchor, err := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"),
		&failFirstReader{prefix: 0x05, filler: 0xab, reads: 1}, round2CreatedAt)
	if err != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", err)
	}
	if len(anchor.Nonce) != 12 || anchorCard.calls != 1 {
		t.Fatalf("ANCHOR: nonce = %d bytes, card called %d times", len(anchor.Nonce), anchorCard.calls)
	}
}

// TestSealRefusesAnEntropySourceThatDidNotFillTheNonce pins the io.ReadFull error guard on
// Seal's nonce read.
//
// Without it, Seal continues with the nonce slice exactly as make() left it. Observed with the
// reader below: err=nil and nonce=000000000000000000000000; a second Seal on a fresh budget
// returns the same all-zero nonce. An all-zero GCM nonce reused across envelopes under one data
// key is the catastrophic AES-GCM failure mode — the authentication key is recoverable from two
// such messages — and it is delivered here as a successful seal.
//
// Isolation: the reader is budgeted at exactly 32 bytes, so the data-key read consumes all of it
// and succeeds; the nonce read is the only read left that can fail. That also means this test
// stays green under a mutation of the data-key guard, and its sibling above stays green under a
// mutation of this one, so each mutation names exactly one test.
func TestSealRefusesAnEntropySourceThatDidNotFillTheNonce(t *testing.T) {
	card := round2Card("1")
	kek := KeyRef{Backend: card.Backend(), ID: "company-kek", Version: "1"}

	sealed, err := Seal(context.Background(), card, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"),
		&budgetedReader{remaining: 32, filler: 0xcd}, round2CreatedAt)

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Seal() error = %v, want ErrInvalidEnvelope — without the nonce read guard this returns a nil error and an envelope sealed under an all-zero nonce, repeated for every envelope this reader seals", err)
	}
	if card.calls != 0 {
		t.Errorf("the card wrapped %d keys, want 0", card.calls)
	}
	if sealed.ObjectID != "" || len(sealed.Nonce) != 0 {
		t.Errorf("a refused Seal returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: one more byte of budget than the two reads need must seal, and
	// must produce a nonce that is not all zeros. Without it a Seal that refused every reader
	// would pass the assertions above.
	anchorCard := round2Card("1")
	anchor, err := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"),
		&budgetedReader{remaining: 44, filler: 0xcd}, round2CreatedAt)
	if err != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", err)
	}
	if bytes.Equal(anchor.Nonce, make([]byte, 12)) {
		t.Fatal("ANCHOR: the anchor sealed under an all-zero nonce, so the refusal above cannot be attributed to the exhausted budget")
	}
}

// TestSealReportsBackendUnavailableWhenTheCardErroredButReturnedBytes pins the err != nil guard
// on Seal's WrapKey result.
//
// It needs a scripted wrapper: fakeHardware can only fail as (nil, error), which the following
// len(WrappedDataKey) == 0 guard would catch on its own, so a card that errors AND returns bytes
// is the only input that reaches this guard alone.
//
// Without it, a card that reported CKR_DEVICE_REMOVED yields err=nil,
// WrappedDataKey="PARTIAL-WRAP-NEVER-COMMITTED", objectID="deployment-api-token" — a complete
// envelope that marshals to 429 bytes with a nil error, which coordinator.seal then persists as
// the sealed secret. The card never committed the wrap, so nothing will ever unwrap those bytes.
//
// Isolation: the plaintext, binding context, createdAt, object id and KEK all pass, and the
// wrapper names the same hardware backend as the KEK, so the wrap-result guard is the only
// refuser left in the function.
func TestSealReportsBackendUnavailableWhenTheCardErroredButReturnedBytes(t *testing.T) {
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	card := &scriptedWrapper{
		backend: kek.Backend,
		wrapped: []byte("PARTIAL-WRAP-NEVER-COMMITTED"),
		wrapErr: errors.New("C_WrapKey: CKR_DEVICE_REMOVED"),
	}

	sealed, err := Seal(context.Background(), card, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"), rand.Reader, round2CreatedAt)

	if card.calls != 1 {
		t.Fatalf("the card was called %d times, want 1 — the input must reach the wrap for this test to say anything about the wrap-result guard", card.calls)
	}
	// Errorf, not Fatalf: the returned-value assertion below is a separate half of the same
	// defect (a refusal that still hands back a usable envelope) and must report in the same run.
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("Seal() error = %v, want ErrBackendUnavailable — a card that reported CKR_DEVICE_REMOVED must not produce a secret, and ErrInvalidEnvelope here would tell the caller to stop retrying a transient fault", err)
	}
	if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
		t.Errorf("a failed wrap returned envelope %+v, want the zero value — coordinator.seal persists this return value as the sealed secret", sealed)
	}

	// ANCHOR, last on purpose: the same scripted card, succeeding, must produce an envelope
	// carrying exactly the bytes it returned. Without it a guard that refused every wrap result
	// would pass the assertions above.
	anchorCard := &scriptedWrapper{backend: kek.Backend, wrapped: bytes.Repeat([]byte{0x5A}, 60)}
	anchor, err := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"), rand.Reader, round2CreatedAt)
	if err != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", err)
	}
	if !bytes.Equal(anchor.WrappedDataKey, anchorCard.wrapped) {
		t.Fatalf("ANCHOR: WrappedDataKey = %x, want the 60 bytes the card returned", anchor.WrappedDataKey)
	}
}

// TestSealRefusesACardThatReportedSuccessAndReturnedNoWrappedKey pins the
// len(envelope.WrappedDataKey) == 0 OPERAND of Seal's wrap-result guard, leaving the
// err != nil operand live.
//
// The mirror of TestSealReportsBackendUnavailableWhenTheCardErroredButReturnedBytes: a card
// that reports success and returns nothing is the only input the err operand cannot catch.
// fakeHardware can fail only one way (nil, error), and the scriptedWrapper that returns
// ("PARTIAL-WRAP-NEVER-COMMITTED", C_WrapKey: CKR_DEVICE_REMOVED) is the err-and-bytes case
// the sibling already pins.
//
// Without this operand, a wrapper returning (nil, nil) yields err=nil and a sealed envelope
// whose WrappedDataKey is the empty slice. Observed immediately afterwards: ObjectID is set,
// Nonce is set, Ciphertext is set, WrappedDataKey=[]. coordinator.seal persists this return
// value as the sealed secret. On Open, the envelope reads as invalid secret envelope — the
// "secret" is permanently unrecoverable, and Seal reported success while producing an
// envelope that nothing can ever unwrap.
//
// Isolation: the plaintext, binding context, createdAt, object id and KEK all pass, the
// scripted wrapper names the same hardware backend as the KEK so validateEnvelopeMetadata
// accepts, and the err operand cannot fire because err is nil. The len operand is the only
// refuser left in the function.
func TestSealRefusesACardThatReportedSuccessAndReturnedNoWrappedKey(t *testing.T) {
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	silent := &scriptedWrapper{backend: kek.Backend} // wrapped == nil, wrapErr == nil

	sealed, err := Seal(context.Background(), silent, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"), rand.Reader, round2CreatedAt)

	if silent.calls != 1 {
		t.Fatalf("the card was asked to wrap %d times, want 1 — the seal must reach the wrap for this test to say anything about the wrap-result guard", silent.calls)
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("Seal() error = %v, want ErrBackendUnavailable — a card that returned no wrapped key must not produce a secret", err)
	}
	if len(sealed.WrappedDataKey) != 0 {
		t.Errorf("a refused seal returned envelope with WrappedDataKey len=%d, want 0", len(sealed.WrappedDataKey))
	}
	if sealed.ObjectID != "" {
		t.Errorf("a refused seal returned envelope with ObjectID=%q, want empty", sealed.ObjectID)
	}

	// ANCHOR, last on purpose: the same scripted wrapper, returning bytes, must seal and must
	// produce exactly those bytes in WrappedDataKey. Without it a guard that refused every wrap
	// result would pass the assertions above.
	anchorCard := &scriptedWrapper{backend: kek.Backend, wrapped: bytes.Repeat([]byte{0x5A}, 60)}
	anchor, err := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		round2Context(), []byte("top-secret-value"), rand.Reader, round2CreatedAt)
	if err != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", err)
	}
	if !bytes.Equal(anchor.WrappedDataKey, anchorCard.wrapped) {
		t.Fatalf("ANCHOR: WrappedDataKey = %x, want the 60 bytes the card returned", anchor.WrappedDataKey)
	}
}

// TestSealRefusesABindingContextOverTheCap pins the len(bindingContext) > maxContextBytes
// OPERAND of Seal's input guard, leaving every sibling operand live.
//
// The SealAssembled-side sibling lives at TestSealAssembledRefusesABindingContextOverTheCap,
// and the two functions each own their own copy of the operand — removing this one in Seal does
// not touch SealAssembled's guard, and vice versa, so the two paths are independent and each
// test stays attributable to one operand. A test on either side is necessary: fixing one
// instance of a defect class is not the work.
//
// Without this operand, Seal returns err=nil and a complete envelope: Algorithm="AES-256-GCM",
// a 60-byte wrapped data key, the wrapper called exactly once. Open later hashes bindingContext
// into contentAAD against the releaser's recomputed contextDigest; if the sealer stored a
// binding context the releaser cannot reproduce, the digest drifts and the envelope cannot be
// opened by anything except the sealer that made it.
//
// Isolation: plaintext is 16 bytes (non-empty and well under MaxPlaintextBytes), random is
// rand.Reader, createdAt is non-zero, and the KEK/object id/backend all pass validateEnvelopeMetadata
// when reached. The cap operand is the only refuser in the function that catches this input,
// and the very first guard in the function, so the card is not even reached on a refused call.
func TestSealRefusesABindingContextOverTheCap(t *testing.T) {
	card := round2Card("1")
	kek := KeyRef{Backend: card.Backend(), ID: "company-kek", Version: "1"}
	bindingContext := bytes.Repeat([]byte{0xAA}, maxContextBytes+1) // one byte over the cap

	sealed, err := Seal(context.Background(), card, kek, "deployment-api-token",
		bindingContext, []byte("top-secret-value"), rand.Reader, round2CreatedAt)

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Seal() error = %v, want ErrInvalidEnvelope -- with the operand removed this returns a complete envelope (bindingContext len=%d) and a nil error, and the backend was called %d times",
			err, len(bindingContext), card.calls)
	}
	if card.calls != 0 {
		t.Errorf("the wrapper was called %d times, want 0 -- the cap is refused at the input guard, before the data key is ever generated", card.calls)
	}
	if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
		t.Errorf("a refused Seal returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: the same hardware backend with a binding context exactly at the
	// cap must seal and must produce a non-empty WrappedDataKey. Without it an operand that
	// refused every binding context would pass the assertions above.
	anchorCard := round2Card("1")
	anchorContext := bytes.Repeat([]byte{0xAA}, maxContextBytes) // exactly at the cap
	anchor, anchorErr := Seal(context.Background(), anchorCard, kek, "deployment-api-token",
		anchorContext, []byte("top-secret-value"), rand.Reader, round2CreatedAt)
	if anchorErr != nil {
		t.Fatalf("ANCHOR: Seal() error = %v, want nil", anchorErr)
	}
	if len(anchor.WrappedDataKey) == 0 || anchorCard.calls != 1 {
		t.Fatalf("ANCHOR: wrapped %d bytes in %d calls, want a non-empty wrap in exactly 1 call", len(anchor.WrappedDataKey), anchorCard.calls)
	}
}

// TestOpenRefusesABindingContextOverTheCap pins the len(bindingContext) > maxContextBytes
// OPERAND of Open's entry guard, leaving the use == nil and validateEnvelope operands live.
//
// The same operand lives at :62 (Seal), :140 (SealAssembled), :260 (Rewrap), and now here.
// Each function owns its own copy and each one is independent: a mutation at one site cannot
// disable another. The :62[2] / :140[4] / :260 / :209 paths each have their own sole detector.
//
// The fixture has to be crafted, not just supplied. The natural oversized context
// (bytes.Repeat([]byte{0xAA}, maxContextBytes+1)) does not match the envelope's stored
// contextDigest, so removing the cap would let the input reach the digest compare at :212 and
// be refused there with the same ErrInvalidEnvelope — the test would stay green for the wrong
// reason. So the envelope's stored digest is rewritten to contextDigest(oversized), the digest
// compare accepts, the call proceeds to UnwrapKey, and the wrapAAD — which includes
// ContextDigest — also differs from what the wrap was sealed against. The fake hardware's
// aead.Open on the wrap fails, UnwrapKey returns an error, and Open returns ErrBackendUnavailable.
// The two assertions in the test (the error and the card call count) both flip from the cap-alive
// state to the cap-removed state, so removing the cap is detectable from either.
//
// Without the cap, the card is asked to unwrap a key whose AAD the wrap never certified — the
// envelope now reads as forged, and Open's signature switches from "invalid secret envelope" to
// "hardware wrapping backend unavailable". Both are refusals, but the second is one the caller
// is told to retry rather than give up on, and that distinction is what the test catches.
//
// Isolation: the unsealed use != nil (callback supplied), the envelope metadata is valid, the
// card holds the named KEK, and the only operand whose absence changes the outcome is the cap.
func TestOpenRefusesABindingContextOverTheCap(t *testing.T) {
	sealed, _ := sealedFixture(t, "1", round2CreatedAt)
	card := round2Card("1")
	oversized := bytes.Repeat([]byte{0xAA}, maxContextBytes+1)
	// Make the digest compare at :212 accept the oversized context, so removing the cap exposes
	// the card to a wrap-AAD-mismatched unwrap. The wrap was sealed against the ORIGINAL digest,
	// but wrapAAD now incorporates the edited digest, so the fake hardware's aead.Open on the
	// wrap fails and UnwrapKey returns an error.
	sealed.ContextDigest = contextDigest(oversized)

	err := sealed.Open(context.Background(), card, oversized, func([]byte) error {
		t.Error("the callback ran on a refused Open")
		return nil
	})

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Open() error = %v, want ErrInvalidEnvelope -- with the cap removed this returns ErrBackendUnavailable from the wrapAAD-mismatched UnwrapKey, and the caller's retry behaviour flips from \"give up\" to \"retry\"",
			err)
	}
	if card.calls != 0 {
		t.Errorf("the card was asked to unwrap %d times, want 0 -- the cap is refused at the entry guard, before any unwrap", card.calls)
	}

	// ANCHOR, last on purpose: the same envelope, untouched, opened with the context it was
	// sealed against. Without it an operand that refused every binding context would pass the
	// assertions above -- and the anchor proves the rejection above is specifically the cap
	// rather than the digest compare at :212 refusing a context that simply does not match.
	anchorSealed, _ := sealedFixture(t, "1", round2CreatedAt)
	anchorCard := round2Card("1")
	saw := false
	if err := anchorSealed.Open(context.Background(), anchorCard, round2Context(), func(plaintext []byte) error {
		saw = bytes.Equal(plaintext, []byte("top-secret-value"))
		return nil
	}); err != nil {
		t.Fatalf("ANCHOR: Open() error = %v, want nil", err)
	}
	if !saw {
		t.Fatal("ANCHOR: the callback never saw the sealed value, so the refusal above cannot be attributed to the cap")
	}
}

// TestRewrapRefusesAnOldWrapperThatIsNotTheBackendTheEnvelopeNames pins the
// validateEnvelope(*envelope, oldWrapper) != nil OPERAND of Rewrap's entry guard — the operand
// that checks the OLD wrapper against the KEK the envelope names.
//
// This is the defect internal/secrets/kek_identity_test.go closes for Open, left open for
// Rewrap. Without the operand, a custodian holding the key material in software — a wrapper
// reporting Backend()="software-aes" — can unwrap an envelope whose KEK says
// "nitrokey-pkcs11" and rewrap it onto a fresh hardware KEK. Observed: err=nil,
// KEK before={Backend:nitrokey-pkcs11 ID:company-kek Version:1}
// after={Backend:nitrokey-pkcs11 ID:company-kek Version:2}, wrappedKeyChanged=true. The envelope
// comes out looking freshly rotated onto hardware, and the rotation record says a card did it.
//
// Isolation: the software-named wrapper holds the SAME key material as the card, so the unwrap
// and the content AEAD both succeed; the binding context matches; and the sibling operand
// validateKeyRef(newKEK, newWrapper) passes because the new wrapper does name the new KEK's
// backend. This operand is the only refuser.
func TestRewrapRefusesAnOldWrapperThatIsNotTheBackendTheEnvelopeNames(t *testing.T) {
	sealed, card := rewrapFixture(t)
	before := sealed.Clone()

	// Same key bytes, different reported backend: the custodian really can decrypt, it just is
	// not the hardware the envelope names.
	software := hardware("software-aes", card.keys)

	err := sealed.Rewrap(context.Background(), software, card, newKEK(card), []byte(rewrapContext))

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Rewrap() error = %v, want ErrInvalidEnvelope — oldWrapper.Backend() = %q while the envelope names KEK backend %q, and without the operand this rewrap succeeds",
			err, software.Backend(), before.KEK.Backend)
	}
	if sealed.KEK != before.KEK {
		t.Errorf("the KEK moved to %+v, want %+v — a software custodian moved the envelope onto a hardware KEK and it now reads as freshly rotated", sealed.KEK, before.KEK)
	}
	if !bytes.Equal(sealed.WrappedDataKey, before.WrappedDataKey) {
		t.Errorf("the wrapped data key changed on a refused rewrap")
	}
	if software.calls != 0 {
		t.Errorf("the software custodian was asked to unwrap %d times, want 0 — the backend mismatch is refused at the entry guard, before the data key is exposed to it", software.calls)
	}

	// ANCHOR, last on purpose: the identical rewrap driven by a wrapper that DOES name the
	// envelope's backend must succeed and must move the KEK. Without it a Rewrap that refused
	// everything would pass the assertions above.
	anchorEnvelope, anchorCard := rewrapFixture(t)
	anchorBefore := anchorEnvelope.Clone()
	if err := anchorEnvelope.Rewrap(context.Background(), anchorCard, anchorCard, newKEK(anchorCard), []byte(rewrapContext)); err != nil {
		t.Fatalf("ANCHOR: Rewrap() error = %v, want nil", err)
	}
	if anchorEnvelope.KEK.Version != "2" {
		t.Fatalf("ANCHOR: KEK = %+v, want version 2 — the refusal above cannot be attributed to the backend mismatch unless the matching wrapper does rotate", anchorEnvelope.KEK)
	}
	if bytes.Equal(anchorEnvelope.WrappedDataKey, anchorBefore.WrappedDataKey) {
		t.Fatal("ANCHOR: the wrapped data key did not change, so the anchor relabelled rather than rewrapped")
	}
}

// TestRewrapRefusesAWrapThatErroredEvenWhenTheCardReturnedBytes pins the err != nil OPERAND of
// Rewrap's wrap-result guard, leaving the len(wrapped) == 0 operand live.
//
// A card that errors AND returns bytes is the only input the length operand cannot catch, which
// is why the committed TestNoFailedRewrapMutatesTheEnvelope does not reach it: its failing-wrapper
// row returns (nil, error), and the surviving length operand still refuses that.
//
// Without this operand, a wrapper returning
// ("PARTIAL-WRAP-NEVER-COMMITTED", C_WrapKey: CKR_FUNCTION_CANCELED) yields err=nil and mutates
// the envelope in place: KEK Version 1 -> 2, WrappedDataKey replaced by the bytes the card
// explicitly refused to commit. The envelope then opens under neither generation — the old
// wrapped key is gone and the new one was never made.
//
// Isolation: the old card holds the key so the unwrap and the content AEAD succeed, the binding
// context matches, and the scripted wrapper names the new KEK's backend so validateKeyRef passes.
// The wrap-result guard is the only refuser left.
func TestRewrapRefusesAWrapThatErroredEvenWhenTheCardReturnedBytes(t *testing.T) {
	sealed, card := rewrapFixture(t)
	before := sealed.Clone()
	failing := &scriptedWrapper{
		backend: card.Backend(),
		wrapped: []byte("PARTIAL-WRAP-NEVER-COMMITTED"),
		wrapErr: errors.New("C_WrapKey: CKR_FUNCTION_CANCELED"),
	}

	err := sealed.Rewrap(context.Background(), card, failing, newKEK(card), []byte(rewrapContext))

	if failing.calls != 1 {
		t.Fatalf("the new card was called %d times, want 1 — the rewrap must reach the wrap for this test to say anything about the wrap-result guard", failing.calls)
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("Rewrap() error = %v, want ErrBackendUnavailable", err)
	}
	if sealed.KEK != before.KEK {
		t.Errorf("the KEK moved to %+v on a cancelled wrap, want %+v", sealed.KEK, before.KEK)
	}
	if !bytes.Equal(sealed.WrappedDataKey, before.WrappedDataKey) {
		t.Errorf("the wrapped data key became %q on a cancelled wrap — the card never committed those bytes and no card will unwrap them", sealed.WrappedDataKey)
	}

	// ANCHOR, last on purpose: the same scripted wrapper, succeeding, must rotate the envelope
	// onto exactly the bytes it returned. Without it a guard that refused every wrap result
	// would pass the assertions above.
	anchorEnvelope, anchorCard := rewrapFixture(t)
	succeeding := &scriptedWrapper{backend: anchorCard.Backend(), wrapped: bytes.Repeat([]byte{0x5A}, 60)}
	if err := anchorEnvelope.Rewrap(context.Background(), anchorCard, succeeding, newKEK(anchorCard), []byte(rewrapContext)); err != nil {
		t.Fatalf("ANCHOR: Rewrap() error = %v, want nil", err)
	}
	if anchorEnvelope.KEK.Version != "2" || !bytes.Equal(anchorEnvelope.WrappedDataKey, succeeding.wrapped) {
		t.Fatalf("ANCHOR: KEK = %+v, WrappedDataKey = %x", anchorEnvelope.KEK, anchorEnvelope.WrappedDataKey)
	}
}

// TestRewrapRefusesACardThatReportedSuccessAndReturnedNoWrappedKey pins the len(wrapped) == 0
// OPERAND of Rewrap's wrap-result guard, leaving the err != nil operand live.
//
// The mirror of the test above: a card that reports success and returns nothing is the only input
// the err operand cannot catch, which is again why TestNoFailedRewrapMutatesTheEnvelope does not
// reach it.
//
// Without this operand, a wrapper returning (nil, nil) yields err=nil and DESTROYS the envelope
// in place: KEK Version 1 -> 2 and len(WrappedDataKey) 60 -> 0. Observed immediately afterwards,
// the rotated envelope opens with err=invalid secret envelope. Rewrap reported success while
// making the secret permanently unrecoverable, which is the one outcome worse than not rotating.
//
// Isolation: identical to the sibling above; only what the wrapper returns differs.
func TestRewrapRefusesACardThatReportedSuccessAndReturnedNoWrappedKey(t *testing.T) {
	sealed, card := rewrapFixture(t)
	before := sealed.Clone()
	silent := &scriptedWrapper{backend: card.Backend()}

	err := sealed.Rewrap(context.Background(), card, silent, newKEK(card), []byte(rewrapContext))

	if silent.calls != 1 {
		t.Fatalf("the new card was called %d times, want 1 — the rewrap must reach the wrap for this test to say anything about the wrap-result guard", silent.calls)
	}
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Errorf("Rewrap() error = %v, want ErrBackendUnavailable", err)
	}
	if sealed.KEK != before.KEK {
		t.Errorf("the KEK moved to %+v while the card returned no wrapped key, want %+v", sealed.KEK, before.KEK)
	}
	if len(sealed.WrappedDataKey) != len(before.WrappedDataKey) {
		t.Errorf("the wrapped data key went from %d bytes to %d on a rewrap that wrapped nothing", len(before.WrappedDataKey), len(sealed.WrappedDataKey))
	}
	// The consequence, asserted rather than described: after a refused rewrap the secret is
	// still there. Without the operand this Open returns ErrInvalidEnvelope, because the
	// envelope now names KEK version 2 and carries no wrapped key at all.
	saw := false
	if err := sealed.Open(context.Background(), card, []byte(rewrapContext), func(plaintext []byte) error {
		saw = bytes.Equal(plaintext, []byte("top-secret-value"))
		return nil
	}); err != nil {
		t.Errorf("after a refused rewrap the envelope no longer opens: %v — Rewrap reported a failure but destroyed the secret on its way out", err)
	}
	if !saw {
		t.Errorf("after a refused rewrap the envelope did not yield the sealed value")
	}

	// ANCHOR, last on purpose: the same scripted wrapper, returning bytes, must rotate the
	// envelope. Without it a guard that refused every wrap result would pass the above.
	anchorEnvelope, anchorCard := rewrapFixture(t)
	succeeding := &scriptedWrapper{backend: anchorCard.Backend(), wrapped: bytes.Repeat([]byte{0x5A}, 60)}
	if err := anchorEnvelope.Rewrap(context.Background(), anchorCard, succeeding, newKEK(anchorCard), []byte(rewrapContext)); err != nil {
		t.Fatalf("ANCHOR: Rewrap() error = %v, want nil", err)
	}
	if anchorEnvelope.KEK.Version != "2" || !bytes.Equal(anchorEnvelope.WrappedDataKey, succeeding.wrapped) {
		t.Fatalf("ANCHOR: KEK = %+v, WrappedDataKey = %x", anchorEnvelope.KEK, anchorEnvelope.WrappedDataKey)
	}
}

// TestOpenReturnsBackendUnavailableWhenTheCardErrorsOnUnwrap pins the err != nil OPERAND of
// :215 in Open's body — the operand that converts a card's unwrap failure into ErrBackendUnavailable
// rather than ErrInvalidEnvelope. The two errors route to different operator actions: a backend
// failure is told to retry, an integrity failure is told to give up. Mixing them means a stuck
// card looks like a corrupted envelope and the operator rotates a key that did not need rotating.
//
// Sole-detector shape: the envelope is genuinely sealed and authenticates under its declared KEK,
// but the card's key map has no entry for "company-kek:1". validateEnvelope at :209 does not check
// key presence (only backend name), so the entry guard accepts, the call reaches :215, and the
// fake hardware's aes.NewCipher rejects the nil key. The card returns an error and Open must convert
// it to ErrBackendUnavailable. With the :215 err-check disabled, UnwrapKey returns (nil, err) and
// that error is discarded; dataKey is nil; :220 fires with ErrInvalidEnvelope — the test would pass
// for the wrong reason if it asserted only on ErrInvalidEnvelope, so the assertion is specifically
// on ErrBackendUnavailable.
func TestOpenReturnsBackendUnavailableWhenTheCardErrorsOnUnwrap(t *testing.T) {
	sealed, _ := sealedFixture(t, "1", round2CreatedAt)
	bindingContext := ReleaseContext("deployment-api-token", "deploy", "production")
	// Card whose key map is empty for this KEK: validateEnvelope sees backend "nitrokey-pkcs11"
	// matches and accepts, but UnwrapKey has no key to use.
	bareCard := hardware("nitrokey-pkcs11", map[string][]byte{})

	called := false
	err := sealed.Open(context.Background(), bareCard, []byte(bindingContext), func(plaintext []byte) error {
		called = true
		return nil
	})

	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Open() error = %v, want ErrBackendUnavailable — this conversion decides whether the caller retries or gives up on a stuck card", err)
	}
	if called {
		t.Fatal("the callback ran on a refused Open: nothing was released")
	}
	if bareCard.calls != 1 {
		t.Fatalf("the card was called %d times, want exactly 1 — the entry guard accepts, the unwrap fires once", bareCard.calls)
	}
}
