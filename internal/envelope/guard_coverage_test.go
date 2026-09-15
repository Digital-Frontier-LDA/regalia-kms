package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// This file closes refusal guards a mutation sweep proved no committed test detected. Every
// test here follows the same discipline: the fixture is built so the guard under test is the
// ONLY thing that can refuse it, and the comment on each test names concretely what the code
// returns once that guard is gone. A fixture of random bytes reaches aead.Open and is refused
// there instead, which is exactly why the pre-existing refusal tests in
// seal_assembled_test.go stayed green against every mutant listed below.

// scriptedWrapper returns whatever WrapKey result a test scripts, so a wrap failure can be
// driven without a card. fakeHardware in envelope_test.go can only fail one way (a missing
// key in its map, which yields (nil, error)); the wrap-result guard in SealAssembled has a
// second operand that only a (bytes, error) return can reach.
//
// Backend() names a real hardware backend so validateKeyRef and validateEnvelopeMetadata
// both accept, leaving the wrap-result guard as the last refuser in the function.
type scriptedWrapper struct {
	backend string
	wrapped []byte
	wrapErr error
	calls   int
}

func (wrapper *scriptedWrapper) Backend() string { return wrapper.backend }

func (wrapper *scriptedWrapper) WrapKey(context.Context, KeyRef, []byte, []byte) ([]byte, error) {
	wrapper.calls++
	return wrapper.wrapped, wrapper.wrapErr
}

func (wrapper *scriptedWrapper) UnwrapKey(context.Context, KeyRef, []byte, []byte) ([]byte, error) {
	return nil, errors.New("scriptedWrapper does not unwrap")
}

// guardSealInput builds the exact triple SealAssembled's local round-trip accepts: a data key
// of the requested length, a 12-byte nonce, and a ciphertext genuinely authenticated under
// the canonical four-field contentAAD for this objectID and bindingContext.
//
// keyBytes is a parameter because a 16-byte key produces an AES-128-GCM ciphertext that still
// authenticates — the input the data-key length operand is the sole refuser of.
//
// The AAD deliberately says "AES-256-GCM" for every key length, because that is the algorithm
// SealAssembled stamps into the envelope regardless of the key it was handed.
func guardSealInput(t *testing.T, keyBytes int, objectID string, bindingContext, plaintext []byte) (dataKey, nonce, ciphertext []byte) {
	t.Helper()
	dataKey = make([]byte, keyBytes)
	if _, err := rand.Read(dataKey); err != nil {
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
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext = aead.Seal(nil, nonce, plaintext, clientContentAAD(Version, objectID, "AES-256-GCM", contextDigest(bindingContext)))
	return dataKey, nonce, ciphertext
}

// TestSealAssembledRefusesANonHardwareBackendEvenWhenTheCiphertextAuthenticates pins the
// validateEnvelopeMetadata call inside SealAssembled.
//
// The pre-existing software-backend case in
// TestSealAssembledRefusesOversizedCiphertextAndSoftwareBackendBeforeAnyHardwareCall hands
// SealAssembled 32 random bytes as the ciphertext, so with the metadata guard removed the
// round-trip refuses it at aead.Open and the test stays green. Nothing detected the guard.
//
// With the guard removed and an authenticating ciphertext, SealAssembled returns err=nil and
// a complete envelope: KEK={Backend:software-aes ID:company-kek Version:1},
// Algorithm="AES-256-GCM", a 60-byte wrapped data key, and one call into the wrapper — a
// software KEK laundered into an envelope that claims hardware custody. The second row is the
// same hole reached through the objectID: err=nil with ObjectID="NOT a valid object id".
//
// Isolation: both refusal rows pass the length guard (32-byte key, 12-byte nonce, 32-byte
// ciphertext, non-zero createdAt) and both authenticate under the round-trip, so
// validateEnvelopeMetadata is the only thing in the function that can refuse them. The
// device.calls assertion is what proves the refusal happened before the wrap rather than
// after it.
func TestSealAssembledRefusesANonHardwareBackendEvenWhenTheCiphertextAuthenticates(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name     string
		backend  string
		objectID string
		accepted bool
	}{
		// ANCHOR, not a gate: without it a validateEnvelopeMetadata that refused
		// EVERYTHING would pass the two rows below and the table would prove nothing.
		{"a hardware backend and a well-formed object id", "nitrokey-pkcs11", "deployment-api-token", true},
		{"a software backend naming itself in the KEK", "software-aes", "deployment-api-token", false},
		{"an object id the pattern refuses", "nitrokey-pkcs11", "NOT a valid object id", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			bindingContext := []byte("repository=infra/path=prod.yaml")
			dataKey, nonce, ciphertext := guardSealInput(t, 32, test.objectID, bindingContext, []byte("top-secret-value"))
			device := hardware(test.backend, keys)
			kek := KeyRef{Backend: test.backend, ID: "company-kek", Version: "1"}

			sealed, err := SealAssembled(context.Background(), device, kek, test.objectID,
				bindingContext, ciphertext, nonce, dataKey, createdAt)

			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil — the fixture must authenticate, or the two refusal rows below could be refused by the round-trip instead of by the guard under test", err)
				}
				if len(sealed.WrappedDataKey) == 0 || device.calls != 1 {
					t.Fatalf("wrapped %d bytes in %d calls, want a non-empty wrap in exactly 1 call", len(sealed.WrappedDataKey), device.calls)
				}
				return
			}
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v, want ErrInvalidEnvelope — with validateEnvelopeMetadata removed from SealAssembled this returns a complete envelope (backend=%q objectID=%q) and a nil error", err, test.backend, test.objectID)
			}
			if device.calls != 0 {
				t.Fatalf("the wrapper was called %d times, want 0 — metadata is refused before the data key ever reaches the card", device.calls)
			}
			if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
				t.Fatalf("a refused call returned envelope %+v, want the zero value", sealed)
			}
		})
	}
}

// TestSealAssembledRefusesAShorterDataKeyThatStillAuthenticatesItsCiphertext pins the
// len(dataKey) != 32 operand of SealAssembled's input guard.
//
// The pre-existing "data key not 32 bytes" row in
// TestSealAssembledRejectsBadDataKeyAndNonceLengthsBeforeAnyRoundTrip uses a 31-byte key,
// which is not a valid AES key length at all: with the operand removed, aes.NewCipher refuses
// it and the row stays green. 16 bytes IS a valid AES key length, so the operand is the only
// refuser left.
//
// With the operand removed, a 16-byte key whose ciphertext authenticates under AES-128-GCM
// returns err=nil, Algorithm="AES-256-GCM", a 44-byte wrapped key and one wrapper call — a
// 128-bit key hardware-wrapped into an envelope that declares AES-256-GCM. Open's own
// len(dataKey) != 32 check would then refuse the envelope at release, so the secret is
// unrecoverable from the moment it is sealed.
//
// api/handler.go refuses a non-32-byte key with "invalid seal data key" before this is
// reached over HTTP, but SealAssembled is exported and this input is constructible.
func TestSealAssembledRefusesAShorterDataKeyThatStillAuthenticatesItsCiphertext(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	// ANCHOR, not a gate: the same construction at 32 bytes must be accepted. Without it a
	// length check that refused every key would pass the 16-byte row below.
	device := hardware(kek.Backend, keys)
	dataKey, nonce, ciphertext := guardSealInput(t, 32, objectID, bindingContext, []byte("top-secret-value"))
	if _, err := SealAssembled(context.Background(), device, kek, objectID, bindingContext, ciphertext, nonce, dataKey, createdAt); err != nil {
		t.Fatalf("32-byte key: err = %v, want nil — if this fixture does not authenticate, the 16-byte row proves nothing about the length operand", err)
	}

	// GATE: 16 bytes is a legal AES key, so aes.NewCipher and aead.Open both succeed and the
	// length operand is the only refuser standing between this and a hardware wrap.
	shortDevice := hardware(kek.Backend, keys)
	shortKey, shortNonce, shortCiphertext := guardSealInput(t, 16, objectID, bindingContext, []byte("top-secret-value"))
	sealed, err := SealAssembled(context.Background(), shortDevice, kek, objectID, bindingContext, shortCiphertext, shortNonce, shortKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("16-byte key: err = %v, want ErrInvalidEnvelope — with the len(dataKey) != 32 operand removed this wraps a 128-bit key into an envelope declaring %q, and Open refuses it forever after", err, sealed.Algorithm)
	}
	if shortDevice.calls != 0 {
		t.Fatalf("16-byte key: the wrapper was called %d times, want 0", shortDevice.calls)
	}
}

// TestSealAssembledRefusesABindingContextOverTheCap pins the
// len(bindingContext) > maxContextBytes operand of SealAssembled's input guard.
//
// No committed test drives SealAssembled with an oversized binding context. The rewrap
// function has a test at rewrap_test.go:128 for the same cap, but SealAssembled's path is
// independent (no upstream envelope to validate against), so a sibling refutation does not
// transfer.
//
// With the operand removed, a 65537-byte binding context authenticates (the round-trip does
// not bound bindingContext), the wrapper is called exactly once, and the envelope is
// persisted with a 60-byte wrapped data key. Open later hashes the binding context into
// contentAAD; if the sealer stored a context the releaser cannot reproduce, the digest drifts
// across seal and release and the envelope cannot be opened.
//
// Isolation: the data key, nonce and ciphertext all authenticate under a 65537-byte binding
// context that hashes to its own contextDigest; the hardware backend names the KEK; and the
// other operands (key/nonce/ciphertext lengths, createdAt) all pass. The cap operand is the
// only refuser in the function that catches this input.
func TestSealAssembledRefusesABindingContextOverTheCap(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	objectID := "deployment-api-token"
	bindingContext := bytes.Repeat([]byte{0xAA}, maxContextBytes+1) // one byte over the cap
	device := hardware("nitrokey-pkcs11", keys)
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}

	dataKey, nonce, ciphertext := guardSealInput(t, 32, objectID, bindingContext, []byte("top-secret-value"))

	sealed, err := SealAssembled(context.Background(), device, kek, objectID, bindingContext, ciphertext, nonce, dataKey, time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v, want ErrInvalidEnvelope -- with the operand removed this returns a complete envelope (bindingContext len=%d) and a nil error, and the backend was called %d times",
			err, len(bindingContext), device.calls)
	}
	if device.calls != 0 {
		t.Errorf("the wrapper was called %d times, want 0 -- the cap is refused before the data key ever reaches the card", device.calls)
	}
	if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
		t.Errorf("a refused call returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: the same hardware backend with a binding context exactly at the
	// cap must seal and must produce a non-empty WrappedDataKey. Without it an operand that
	// refused every binding context would pass the assertions above.
	atCapContext := bytes.Repeat([]byte{0xAA}, maxContextBytes)
	atCap, atCapNonce, atCapCipher := guardSealInput(t, 32, objectID, atCapContext, []byte("top-secret-value"))
	anchorDevice := hardware("nitrokey-pkcs11", keys)
	anchor, anchorErr := SealAssembled(context.Background(), anchorDevice, kek, objectID, atCapContext, atCapCipher, atCapNonce, atCap, time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	if anchorErr != nil {
		t.Fatalf("ANCHOR: err = %v, want nil", anchorErr)
	}
	if len(anchor.WrappedDataKey) == 0 || anchorDevice.calls != 1 {
		t.Fatalf("ANCHOR: wrapped %d bytes in %d calls, want a non-empty wrap in exactly 1 call", len(anchor.WrappedDataKey), anchorDevice.calls)
	}
}

// TestSealAssembledRefusesACiphertextOneByteOverTheCapEvenWhenItAuthenticates pins the
// len(ciphertext) > MaxPlaintextBytes+16 operand of SealAssembled's input guard, leaving the
// len(ciphertext) < 17 operand live.
//
// The pre-existing oversize row in
// TestSealAssembledRefusesOversizedCiphertextAndSoftwareBackendBeforeAnyHardwareCall uses
// make([]byte, MaxPlaintextBytes+17) which is fresh-memory all zeros: with the operand removed,
// the round-trip's GCM tag check fails and the test stays green. Nothing detected the operand.
//
// With the operand removed and an authenticating ciphertext (MaxPlaintextBytes+1 bytes of
// plaintext + 16-byte tag = MaxPlaintextBytes+17 bytes, one byte over the cap), SealAssembled
// returns err=nil and a complete envelope: Algorithm="AES-256-GCM", a 60-byte wrapped data
// key, and one call into the wrapper — an oversized secret persisted into the seal store.
//
// Isolation: the input passes the floor operand (MaxPlaintextBytes+17 > 17), authenticates
// under the round-trip, and the backend names the KEK, so this operand is the only refuser in
// the function that catches this particular input.
func TestSealAssembledRefusesACiphertextOneByteOverTheCapEvenWhenItAuthenticates(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	device := hardware("nitrokey-pkcs11", keys)
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}

	// One byte over the cap: MaxPlaintextBytes+1 bytes of plaintext produce MaxPlaintextBytes+17
	// bytes of authenticated ciphertext (16-byte GCM tag appended). The round-trip MUST accept
	// this input -- if it does not, the assertion below fails and the test must be rewritten
	// against a different mechanism (a fixture whose ciphertext the round-trip accepts but
	// which cannot otherwise be distinguished from a fresh allocation).
	dataKey, nonce, ciphertext := guardSealInput(t, 32, objectID, bindingContext, bytes.Repeat([]byte{0xAA}, MaxPlaintextBytes+1))
	if len(ciphertext) != MaxPlaintextBytes+17 {
		t.Fatalf("fixture: ciphertext len = %d, want %d", len(ciphertext), MaxPlaintextBytes+17)
	}

	sealed, err := SealAssembled(context.Background(), device, kek, objectID, bindingContext, ciphertext, nonce, dataKey, time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))

	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v, want ErrInvalidEnvelope -- with the operand removed this returns a complete envelope (Ciphertext len=%d) and a nil error, and the backend was called %d times",
			err, len(sealed.Ciphertext), device.calls)
	}
	if device.calls != 0 {
		t.Errorf("the wrapper was called %d times, want 0 -- the cap is refused before the data key ever reaches the card", device.calls)
	}
	if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
		t.Errorf("a refused call returned envelope %+v, want the zero value", sealed)
	}

	// ANCHOR, last on purpose: the same hardware backend with ciphertext exactly at the cap must
	// seal and must produce a non-empty WrappedDataKey. Without it an operand that refused every
	// ciphertext would pass the assertions above.
	atCap, atCapNonce, atCapCipher := guardSealInput(t, 32, objectID, bindingContext, bytes.Repeat([]byte{0xAA}, MaxPlaintextBytes))
	if len(atCapCipher) != MaxPlaintextBytes+16 {
		t.Fatalf("ANCHOR fixture: ciphertext len = %d, want %d", len(atCapCipher), MaxPlaintextBytes+16)
	}
	anchorDevice := hardware("nitrokey-pkcs11", keys)
	anchor, anchorErr := SealAssembled(context.Background(), anchorDevice, kek, objectID, bindingContext, atCapCipher, atCapNonce, atCap, time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	if anchorErr != nil {
		t.Fatalf("ANCHOR: err = %v, want nil", anchorErr)
	}
	if len(anchor.WrappedDataKey) == 0 || anchorDevice.calls != 1 {
		t.Fatalf("ANCHOR: wrapped %d bytes in %d calls, want a non-empty wrap in exactly 1 call", len(anchor.WrappedDataKey), anchorDevice.calls)
	}
}

// TestSealAssembledReportsBackendUnavailableWhenTheWrapFailsWithOrWithoutBytes pins the
// wrap-result guard in SealAssembled. No committed test drives SealAssembled with a failing
// wrapper at all, so both operands were undetected.
//
// With the whole guard removed, a wrapper returning (nil, "C_WrapKey: CKR_DEVICE_REMOVED")
// yields err=nil and an envelope whose WrappedDataKey is empty — a success envelope with no
// wrapped key, which coordinator.seal persists and no later reader can open. With only the
// err != nil operand removed, a wrapper returning
// ([]byte("PARTIAL-WRAP-NEVER-COMMITTED"), "C_WrapKey: CKR_FUNCTION_CANCELED") yields err=nil
// and a 28-byte wrapped key the card never committed.
//
// Isolation: every row hands SealAssembled the same authenticating input and a hardware
// backend, so the wrap-result guard is the only refuser in the function and the rows differ
// only in what the wrapper returns. The rows are deliberately split by operand — "returned
// nothing" survives the err-operand mutation (the len operand still catches it) and
// "returned bytes" survives the len-operand mutation, so each mutation names exactly which
// operand it removed.
func TestSealAssembledReportsBackendUnavailableWhenTheWrapFailsWithOrWithoutBytes(t *testing.T) {
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name     string
		wrapped  []byte
		wrapErr  error
		accepted bool
	}{
		// ANCHOR, not a gate: a wrapper that succeeds must produce an envelope carrying
		// exactly the bytes it returned. Without it a guard that refused every wrap
		// result would pass the three rows below.
		{"the card wrapped the key", bytes.Repeat([]byte{0x5A}, 60), nil, true},
		{"the card failed and returned nothing", nil, errors.New("C_WrapKey: CKR_DEVICE_REMOVED"), false},
		{"the card failed but still returned bytes", []byte("PARTIAL-WRAP-NEVER-COMMITTED"), errors.New("C_WrapKey: CKR_FUNCTION_CANCELED"), false},
		{"the card reported success and returned nothing", nil, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataKey, nonce, ciphertext := guardSealInput(t, 32, objectID, bindingContext, []byte("top-secret-value"))
			device := &scriptedWrapper{backend: kek.Backend, wrapped: test.wrapped, wrapErr: test.wrapErr}

			sealed, err := SealAssembled(context.Background(), device, kek, objectID,
				bindingContext, ciphertext, nonce, dataKey, createdAt)

			if device.calls != 1 {
				t.Fatalf("the wrapper was called %d times, want 1 — the input must reach the wrap for this row to say anything about the wrap-result guard", device.calls)
			}
			if test.accepted {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				if !bytes.Equal(sealed.WrappedDataKey, test.wrapped) {
					t.Fatalf("WrappedDataKey = %x, want the %d bytes the wrapper returned", sealed.WrappedDataKey, len(test.wrapped))
				}
				return
			}
			// Errorf, not Fatalf: the returned-value assertion below is a separate
			// defect (a refusal that still hands back a half-populated envelope) and
			// must be allowed to report in the same run rather than be foreclosed.
			if !errors.Is(err, ErrBackendUnavailable) {
				t.Errorf("err = %v, want ErrBackendUnavailable — with the wrap-result guard removed this returns a nil error and an envelope whose WrappedDataKey is %q, which coordinator.seal persists as a sealed secret", err, sealed.WrappedDataKey)
			}
			// A refused wrap must not leak the partial result into the returned value:
			// ErrBackendUnavailable is retried by the caller, and a half-populated
			// envelope alongside it is what a retry would be tempted to reuse.
			if len(sealed.WrappedDataKey) != 0 || sealed.ObjectID != "" {
				t.Fatalf("a refused wrap returned envelope %+v, want the zero value", sealed)
			}
		})
	}
}

// TestParseRefusesATokenCarryingAnUnknownField pins the decoder.Decode error guard in Parse,
// which is the only thing that acts on DisallowUnknownFields.
//
// With the guard removed, a token carrying an extra "smuggled_field" parses clean: the
// decoder saves its unknown-field error but still populates every known field, the trailing
// Decode still returns io.EOF, and validateEnvelope passes — observed err=nil, version=2,
// objectID="deployment-api-token", kek={nitrokey-pkcs11 company-kek 1}. Two byte strings then
// name the same envelope, and whatever the extra field carries rides along into storage.
//
// Isolation: the token is a real Marshal output re-encoded through the same map, so nothing
// else about it is malformed. The anchor below proves the re-encoding itself is not what
// Parse refuses — without it, a broken round-trip through map[string]json.RawMessage would
// make the gate pass for the wrong reason.
func TestParseRefusesATokenCarryingAnUnknownField(t *testing.T) {
	_, encoded := sealedFixture(t, "1", time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))

	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}

	// ANCHOR, not a gate: the same document re-encoded with nothing added must still parse.
	clean, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(clean); err != nil {
		t.Fatalf("Parse rejected the re-encoded token unchanged: %v — the gate below would then be refusing the re-encoding rather than the smuggled field", err)
	}

	// GATE.
	document["smuggled_field"] = json.RawMessage(`"attacker-controlled"`)
	smuggled, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(smuggled)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse accepted a token carrying an unknown field: err = %v objectID = %q — DisallowUnknownFields is set but nothing acts on the error it produces unless Parse checks the Decode result", err, parsed.ObjectID)
	}
	if parsed.ObjectID != "" {
		t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
	}
}

// TestParseRefusesTrailingBytesAfterTheEnvelopeDocument pins the second Decode in Parse, the
// one that requires io.EOF after the envelope document.
//
// json.Decoder stops at the end of the first JSON value, so without this guard everything
// after the closing brace is simply never read. With the guard removed, a 481-byte token with
// {"attacker":"rider"} appended (502 bytes) parses to an envelope byte-for-byte identical to
// the one the clean 481 bytes produce — observed err=nil, objectID="deployment-api-token",
// kek={nitrokey-pkcs11 company-kek 1}. That is token malleability: two different files that
// are the same secret, so any check that hashes or compares the stored bytes can be evaded
// while the envelope stays valid.
//
// Isolation: the prefix is an unmodified Marshal output, so the first Decode and
// validateEnvelope both succeed on it; the appended bytes are the only difference and the
// trailing-EOF guard is the only thing that can see them.
func TestParseRefusesTrailingBytesAfterTheEnvelopeDocument(t *testing.T) {
	_, encoded := sealedFixture(t, "1", time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))

	// ANCHOR, not a gate: the clean token must parse, otherwise the refusal below could be
	// about the token rather than about what was appended to it.
	clean, err := Parse(encoded)
	if err != nil {
		t.Fatalf("Parse rejected the clean token: %v", err)
	}

	for _, test := range []struct {
		name    string
		trailer string
	}{
		{"a second JSON document", `{"attacker":"rider"}`},
		{"a bare JSON scalar", `"rider"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ridden := append(append([]byte(nil), encoded...), test.trailer...)
			parsed, err := Parse(ridden)
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Parse accepted %d bytes where %d were the envelope: err = %v — it returned objectID %q, the same envelope the clean %d bytes produce (%q), so two different files are one secret",
					len(ridden), len(encoded), err, parsed.ObjectID, len(encoded), clean.ObjectID)
			}
			if parsed.ObjectID != "" {
				t.Fatalf("a refused token returned objectID = %q, want the zero envelope", parsed.ObjectID)
			}
		})
	}
}

// TestMarshalReturnsNoBytesWhenTheEnvelopeCannotBeEncoded pins the json.Marshal result guard
// in Marshal.
//
// Marshal appends '\n' to whatever json.Marshal returned. json.Marshal returns nil on error,
// so with the guard removed the function returns exactly one byte — "\n" — and a nil error.
// Observed: err=nil, encoded="\n", len=1. coordinator.seal writes that return value out as
// the sealed secret, so the failure mode is a one-byte file on disk in place of an envelope,
// with nothing anywhere reporting a problem.
//
// The input is built through the package's own API: validateEnvelope only checks
// CreatedAt.IsZero(), so Seal accepts a year-10000 timestamp, and time.Time.MarshalJSON then
// refuses to encode it ("year outside of range [0,9999]"). This one input kills both the
// whole-guard mutation and the err != nil operand — the surviving len(encoded) >
// maxEnvelopeBytes operand catches nothing, because the largest envelope validateEnvelope
// admits encodes to roughly 1.49 MB against a 2 MB cap.
//
// Isolation: validateEnvelope runs first and passes (the envelope came out of Seal), so the
// encode guard is the only refuser Marshal has left.
func TestMarshalReturnsNoBytesWhenTheEnvelopeCannotBeEncoded(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	kek := KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"}
	bindingContext := ReleaseContext("deployment-api-token", "deploy", "production")

	seal := func(createdAt time.Time) Envelope {
		t.Helper()
		sealed, err := Seal(context.Background(), device, kek, "deployment-api-token",
			bindingContext, []byte("top-secret-value"), rand.Reader, createdAt)
		if err != nil {
			t.Fatalf("Seal(createdAt=%s) error = %v", createdAt, err)
		}
		return sealed
	}

	// ANCHOR, not a gate: the same envelope at an encodable timestamp must marshal to a
	// real token. Without it a Marshal that returned ErrInvalidEnvelope for everything
	// would pass the gate below.
	if encoded, err := seal(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)).Marshal(); err != nil || len(encoded) < 2 {
		t.Fatalf("an encodable envelope marshalled to %d bytes with err = %v", len(encoded), err)
	}

	// GATE: Seal stamps this straight through — validateEnvelope only rejects a ZERO
	// CreatedAt, so a year-10000 envelope is constructible through the public API and only
	// json.Marshal notices.
	unencodable := seal(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	encoded, err := unencodable.Marshal()
	// Errorf, not Fatalf: with the guard removed BOTH halves are wrong (nil error AND one
	// byte returned), and the byte count is the half that names the failure mode. A Fatalf
	// here would stop the run before the more informative assertion could report.
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Marshal of an unencodable envelope: err = %v, want ErrInvalidEnvelope", err)
	}
	if len(encoded) != 0 {
		t.Errorf("Marshal returned %d bytes (%q) alongside its refusal, want none — coordinator.seal writes this return value out as the sealed secret", len(encoded), encoded)
	}
}
