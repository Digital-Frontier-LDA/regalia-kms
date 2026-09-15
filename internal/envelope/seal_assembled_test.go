package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"
)

// clientContentAAD replicates what a client computes locally to encrypt. It is the same
// four-field contentAAD SealAssembled uses on the server side so the AEAD tag computed
// from one authenticates under the other. Kept in this test file, not the package, so
// the production surface does not expose AAD shape to callers -- the whole point of the
// round-trip check is that callers must replicate it without API help.
func clientContentAAD(version int, objectID, algorithm, digest string) []byte {
	return []byte(fmt.Sprintf("regalia-envelope-v%d\x00%s\x00%s\x00%s", version, objectID, algorithm, digest))
}

func TestSealAssembledRoundTripsWhenClientUsedTheCanonicalContentAAD(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	objectID := "deployment-api-token"
	bindingContext := []byte("repository=infra/path=prod.yaml")
	plaintext := []byte("top-secret-value")
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	// Client side: generate (dataKey, nonce) with crypto/rand, encrypt with the same
	// 4-field contentAAD the server will use.
	digest := contextDigest(bindingContext)
	aad := clientContentAAD(Version, objectID, "AES-256-GCM", digest)
	dataKey := make([]byte, 32)
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
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	// Server side: take (ciphertext, nonce, dataKey) and produce the envelope.
	envelope, err := SealAssembled(context.Background(), device,
		KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		objectID, bindingContext, ciphertext, nonce, dataKey, createdAt)
	if err != nil {
		t.Fatalf("SealAssembled: %v", err)
	}
	if envelope.ObjectID != objectID {
		t.Fatalf("ObjectID = %q want %q", envelope.ObjectID, objectID)
	}
	if !bytes.Equal(envelope.Ciphertext, ciphertext) {
		t.Fatal("SealAssembled altered ciphertext")
	}
	if !bytes.Equal(envelope.Nonce, nonce) {
		t.Fatal("SealAssembled altered nonce")
	}
	if envelope.CreatedAt != createdAt.UTC() {
		t.Fatalf("CreatedAt = %v want %v", envelope.CreatedAt, createdAt.UTC())
	}
	if envelope.ContextDigest != digest {
		t.Fatalf("ContextDigest = %q want %q", envelope.ContextDigest, digest)
	}
	// FALSIFIABLE: deleting the local AEAD round-trip in SealAssembled makes this assertion pass
	// even for random (dataKey, nonce, ciphertext) -- the test that demonstrates that is the
	// mismatch test below. This test confirms only that an honest client produces an Open'able
	// envelope.
	var recovered []byte
	err = envelope.Open(context.Background(), device, bindingContext, func(value []byte) error {
		recovered = append(recovered, value...)
		return nil
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered = %q want %q", recovered, plaintext)
	}
}

func TestSealAssembledRefusesACiphertextTheDataKeyDoesNotAuthenticate(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	objectID := "deployment-api-token"
	bindingContext := []byte("test-context")
	plaintext := []byte("secret")
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	// Encrypt with the REAL data key, then call SealAssembled with a DIFFERENT data key.
	// The local AEAD round-trip inside SealAssembled must catch the lie: a valid GCM tag
	// under the real key does not authenticate under a different key.
	realKey := bytes.Repeat([]byte{1}, 32)
	block, err := aes.NewCipher(realKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	aad := clientContentAAD(Version, objectID, "AES-256-GCM", contextDigest(bindingContext))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	lieKey := bytes.Repeat([]byte{2}, 32)
	_, err = SealAssembled(context.Background(), device,
		KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		objectID, bindingContext, ciphertext, nonce, lieKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("SealAssembled: err = %v want ErrInvalidEnvelope (delete fix: comment out the local AEAD round-trip in SealAssembled and this test will fail)", err)
	}
	if device.calls != 0 {
		t.Fatalf("backend called %d times before round-trip refused the mismatch", device.calls)
	}
}

func TestSealAssembledRefusesOversizedCiphertextAndSoftwareBackendBeforeAnyHardwareCall(t *testing.T) {
	keys := map[string][]byte{"kek:1": bytes.Repeat([]byte{1}, 32)}
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	bindingContext := []byte("ctx")

	// Oversized ciphertext -- one byte past the upper bound used by validateEnvelope.
	device := hardware("nitrokey-pkcs11", keys)
	oversized := make([]byte, MaxPlaintextBytes+17)
	_, err := SealAssembled(context.Background(), device,
		KeyRef{Backend: "nitrokey-pkcs11", ID: "kek", Version: "1"},
		"secret-id", bindingContext, oversized, nonce, dataKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("oversized: err = %v want ErrInvalidEnvelope", err)
	}
	if device.calls != 0 {
		t.Fatalf("oversized: backend called %d times", device.calls)
	}

	// Software backend -- refused by validateEnvelopeMetadata before the round-trip.
	softwareDevice := hardware("software", keys)
	smallCiphertext := make([]byte, 32)
	if _, err := rand.Read(smallCiphertext); err != nil {
		t.Fatal(err)
	}
	_, err = SealAssembled(context.Background(), softwareDevice,
		KeyRef{Backend: "software", ID: "kek", Version: "1"},
		"secret-id", bindingContext, smallCiphertext, nonce, dataKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("software backend: err = %v want ErrInvalidEnvelope", err)
	}
	if softwareDevice.calls != 0 {
		t.Fatalf("software backend: called %d times", softwareDevice.calls)
	}
}

func TestSealAssembledRejectsBadDataKeyAndNonceLengthsBeforeAnyRoundTrip(t *testing.T) {
	// Same hardware fixture as the others so the length checks at the top of SealAssembled
	// run before any backend call or AEAD operation. This pins that an attacker cannot
	// reach the AES path with a malformed data key.
	keys := map[string][]byte{"kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	ciphertext := make([]byte, 32)
	bindingContext := []byte("ctx")

	cases := map[string]func() (dataKey, nonce []byte){
		"data key not 32 bytes": func() ([]byte, []byte) {
			nonce := make([]byte, 12)
			return bytes.Repeat([]byte{1}, 31), nonce
		},
		"nonce not 12 bytes": func() ([]byte, []byte) {
			dataKey := bytes.Repeat([]byte{1}, 32)
			return dataKey, bytes.Repeat([]byte{2}, 11)
		},
	}
	for name, make_ := range cases {
		t.Run(name, func(t *testing.T) {
			dataKey, nonce := make_()
			_, err := SealAssembled(context.Background(), device,
				KeyRef{Backend: "nitrokey-pkcs11", ID: "kek", Version: "1"},
				"secret-id", bindingContext, ciphertext, nonce, dataKey, createdAt)
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("err = %v want ErrInvalidEnvelope", err)
			}
			if device.calls != 0 {
				t.Fatalf("backend called %d times", device.calls)
			}
		})
	}
}

// TestSealAssembledBoundariesAroundEmptyPlaintext asserts the ciphertext length floor from
// BOTH sides. Seal in this package refuses len(plaintext) == 0; SealAssembled must agree,
// which means the ciphertext length check has to refuse 16 bytes (a GCM tag over no
// plaintext) and accept 17 bytes (one byte of plaintext plus the 16-byte tag).
//
// Both halves of the assertion use REAL authenticated ciphertexts (random nonces, real GCM
// tags under the same contentAAD the function uses), so neither half can succeed by
// coincidence: random bytes would have failed the round-trip and masked the floor's
// regression, but here the round-trip accepts and the boundary is what stands or falls.
//
// The positive case asserts the full success path -- err == nil, envelope returned, backend
// called, wrapped data key non-empty -- because only that pins the floor at 17 from both
// sides. A weaker "err is not a length-check refusal" would accept the same outcome the
// negative case expects (ErrInvalidEnvelope from the round-trip) and pass even if the floor
// wrongly rejected valid 17-byte ciphertexts.
func TestSealAssembledBoundariesAroundEmptyPlaintext(t *testing.T) {
	keys := map[string][]byte{"kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	bindingContext := []byte("ctx")
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad := clientContentAAD(Version, "secret-id", "AES-256-GCM", contextDigest(bindingContext))

	// Negative: 16-byte ciphertext (GCM tag over EMPTY plaintext) must be refused at the
	// length check, before any AEAD call and before any hardware call.
	empty := gcm.Seal(nil, nonce, []byte{}, aad)
	if len(empty) != 16 {
		t.Fatalf("empty plaintext ciphertext length = %d, want 16", len(empty))
	}
	callsBefore := device.calls
	_, err = SealAssembled(context.Background(), device,
		KeyRef{Backend: "nitrokey-pkcs11", ID: "kek", Version: "1"},
		"secret-id", bindingContext, empty, nonce, dataKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("16-byte ciphertext: err = %v want ErrInvalidEnvelope (delete fix: change the lower bound in SealAssembled back to 16 and the two seal paths stop agreeing about empty secrets)", err)
	}
	if device.calls != callsBefore {
		t.Fatalf("16-byte ciphertext: backend called %d times (was %d); the length check must reject before any hardware call", device.calls, callsBefore)
	}

	// Positive: 17-byte ciphertext (one byte of plaintext plus the 16-byte tag) must round-trip
	// cleanly and the backend must wrap the data key. Asserting "no err" alone would be
	// insufficient against a regression that wrongly refuses 17 bytes; pairing
	// device.calls > callsBefore and len(WrappedDataKey) > 0 with err == nil pins the floor
	// from the success side too.
	oneByte := gcm.Seal(nil, nonce, []byte{0xAA}, aad)
	if len(oneByte) != 17 {
		t.Fatalf("oneByte ciphertext length = %d, want 17", len(oneByte))
	}
	out, err := SealAssembled(context.Background(), device,
		KeyRef{Backend: "nitrokey-pkcs11", ID: "kek", Version: "1"},
		"secret-id", bindingContext, oneByte, nonce, dataKey, createdAt)
	if err != nil {
		t.Fatalf("17-byte ciphertext: err = %v; want nil -- if the floor wrongly refuses valid ciphertext the message names the defect", err)
	}
	if device.calls == callsBefore {
		t.Fatalf("17-byte ciphertext: backend never called; the round-trip succeeded but the wrap was skipped")
	}
	if len(out.WrappedDataKey) == 0 {
		t.Fatalf("17-byte ciphertext: envelope WrappedDataKey is empty; the wrap ran but produced nothing")
	}
}

// TestSealAssembledZeroesCallerDataKeyOnValidationFailure pins that defer zero(dataKey) is
// registered before any return path can leak the caller's slice. The error paths (length
// check, validateEnvelopeMetadata, newAEAD, aead.Open) are exactly where a rejected key
// should vanish rather than linger -- the failed-authentication path is the one an attacker
// drives, since a valid GCM tag under a known key is what proves possession.
//
// The validation rejection here uses a backend mismatch (KeyRef.Backend != wrapper.Backend())
// so validateEnvelopeMetadata returns ErrInvalidEnvelope before any AEAD call. Before the
// fix, defer zero(dataKey) was registered AFTER aead.Open succeeded, so this path returned
// with the caller's slice untouched. After the fix, the defer is registered immediately
// after the length check, and the slice is zeroed on every return.
func TestSealAssembledZeroesCallerDataKeyOnValidationFailure(t *testing.T) {
	keys := map[string][]byte{"kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	createdAt := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	bindingContext := []byte("ctx")
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, 32)
	if _, err := rand.Read(ciphertext); err != nil {
		t.Fatal(err)
	}

	// Recognizable non-zero pattern so we can see if any byte survived.
	dataKey := bytes.Repeat([]byte{0xAA}, 32)

	// Backend mismatch: wrapper is "nitrokey-pkcs11", KeyRef claims "yubikey-openpgp".
	// validateKeyRef refuses before any AEAD call.
	_, err := SealAssembled(context.Background(), device,
		KeyRef{Backend: "yubikey-openpgp", ID: "kek", Version: "1"},
		"secret-id", bindingContext, ciphertext, nonce, dataKey, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("err = %v want ErrInvalidEnvelope (backend mismatch should refuse at validateEnvelopeMetadata)", err)
	}

	// The caller's slice must be all zeros. Before the fix, defer was registered after
	// aead.Open so this path returned with dataKey untouched (every byte 0xAA); pinning
	// that this now reads all-zero is what makes the test causally targeted.
	for i, b := range dataKey {
		if b != 0 {
			t.Errorf("dataKey[%d] = 0x%02X; want 0x00 -- SealAssembled did not zero the caller's slice when validateEnvelopeMetadata refused (delete fix: move 'defer zero(dataKey)' back below aead.Open and the caller's slice keeps 0xAA all the way to t.Error)", i, b)
			break
		}
	}
}
