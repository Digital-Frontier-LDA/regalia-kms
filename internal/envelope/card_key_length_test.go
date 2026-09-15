package envelope

// THE LENGTH OF THE DATA KEY THE CARD RETURNS IS CHECKED ON THREE PATHS AND TESTED ON ONE.
// SealAssembled's `len(dataKey) != 32` has
// TestSealAssembledRefusesAShorterDataKeyThatStillAuthenticatesItsCiphertext; the identical guards in Open and Rewrap had nothing, and the whole
// kms tree stayed green with either of them removed.
//
// The seal path takes its data key from the CALLER. These two take it from the WRAPPER — what the
// card handed back after an unwrap. That is the side where a substituted, degraded or compromised
// device is the threat, and this guard is the only thing standing between such a device and the
// daemon acting on whatever it returns.
//
// Sixteen bytes is a legal AES key: crypto/aes accepts 16, 24 and 32 and rejects everything else,
// so newAEAD builds a working AES-128 cipher and the AEAD authenticates, because the ciphertext
// really was sealed under that key. Measured with Open's operand removed: err=<nil> and
// "top-secret-value" released, out of an envelope declaring Algorithm "AES-256-GCM".
//
// Each test pairs the gate with an ANCHOR at 32 bytes, per TESTING.md §18: without it a guard that
// refused every key would satisfy the 16-byte row and the test would pin nothing.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// cardReturning is a wrapper whose UnwrapKey hands back a key of the caller's choosing — the one
// thing the fakes in this package cannot express, because they all return a correct 32-byte key.
type cardReturning struct {
	backend  string
	key      []byte
	rewrapTo []byte
}

func (card *cardReturning) Backend() string { return card.backend }

func (card *cardReturning) WrapKey(_ context.Context, _ KeyRef, dataKey, _ []byte) ([]byte, error) {
	card.rewrapTo = append([]byte(nil), dataKey...)
	return []byte("rewrapped-by-the-new-kek"), nil
}

func (card *cardReturning) UnwrapKey(context.Context, KeyRef, []byte, []byte) ([]byte, error) {
	return append([]byte(nil), card.key...), nil
}

// envelopeSealedUnder builds an envelope whose ciphertext genuinely authenticates under a key of
// the given length, while the envelope declares AES-256-GCM. Constructed directly rather than
// through SealAssembled because SealAssembled's own length guard — the one that IS tested —
// refuses to produce this.
func envelopeSealedUnder(t *testing.T, keyBytes int, objectID string, bindingContext []byte, kek KeyRef) (Envelope, []byte) {
	t.Helper()
	dataKey := make([]byte, keyBytes)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatalf("aes.NewCipher(%d bytes): %v — this fixture depends on %d being a legal AES key", keyBytes, err, keyBytes)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		Version: Version, ObjectID: objectID, KEK: kek, Algorithm: "AES-256-GCM",
		ContextDigest:  contextDigest(bindingContext),
		CreatedAt:      time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
		Nonce:          make([]byte, aead.NonceSize()),
		WrappedDataKey: []byte("wrapped-by-the-card"),
	}
	if _, err := rand.Read(envelope.Nonce); err != nil {
		t.Fatal(err)
	}
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, []byte("top-secret-value"), envelope.contentAAD())
	return envelope, dataKey
}

func TestOpenRefusesADataKeyTheCardReturnedAtTheWrongLength(t *testing.T) {
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}

	// ANCHOR: the identical construction at 32 bytes must be served, or the row below proves
	// nothing about the LENGTH — a guard refusing every key would satisfy it.
	good, goodKey := envelopeSealedUnder(t, 32, objectID, bindingContext, kek)
	var releasedGood []byte
	if err := good.Open(context.Background(), &cardReturning{backend: kek.Backend, key: goodKey}, bindingContext,
		func(plaintext []byte) error {
			releasedGood = append([]byte(nil), plaintext...)
			return nil
		}); err != nil {
		t.Fatalf("32-byte card key: err = %v, want nil — if this fixture does not authenticate, the 16-byte row is meaningless", err)
	}
	if !bytes.Equal(releasedGood, []byte("top-secret-value")) {
		t.Fatalf("32-byte card key released %q", releasedGood)
	}

	// GATE: the card returns 16 bytes. aes.NewCipher accepts it, the AEAD authenticates, and the
	// length guard is the only refuser between that and released plaintext.
	short, shortKey := envelopeSealedUnder(t, 16, objectID, bindingContext, kek)
	var released []byte
	err := short.Open(context.Background(), &cardReturning{backend: kek.Backend, key: shortKey}, bindingContext,
		func(plaintext []byte) error {
			released = append([]byte(nil), plaintext...)
			return nil
		})
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("16-byte card key: err = %v, want ErrInvalidEnvelope — the daemon decrypted under AES-128 with a key the device chose, from an envelope declaring %q", err, short.Algorithm)
	}
	if released != nil {
		t.Fatalf("16-byte card key: %q reached the callback; nothing may be released on this path", released)
	}
}

func TestRewrapRefusesADataKeyTheCardReturnedAtTheWrongLength(t *testing.T) {
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	newKEK := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "2"}

	// ANCHOR: 32 bytes must rewrap, and must rewrap THAT key.
	good, goodKey := envelopeSealedUnder(t, 32, objectID, bindingContext, kek)
	newCard := &cardReturning{backend: kek.Backend}
	if err := good.Rewrap(context.Background(), &cardReturning{backend: kek.Backend, key: goodKey}, newCard, newKEK, bindingContext); err != nil {
		t.Fatalf("32-byte card key: err = %v, want nil — without this the 16-byte row proves nothing", err)
	}
	if !bytes.Equal(newCard.rewrapTo, goodKey) {
		t.Fatal("32-byte card key: the new KEK wrapped something other than the unwrapped data key")
	}

	// GATE: rewrap is worse than open. Open releases once; rewrap BINDS the short key to the new
	// KEK and writes it back into the envelope, so the downgrade persists.
	short, shortKey := envelopeSealedUnder(t, 16, objectID, bindingContext, kek)
	before := append([]byte(nil), short.WrappedDataKey...)
	shortCard := &cardReturning{backend: kek.Backend}
	err := short.Rewrap(context.Background(), &cardReturning{backend: kek.Backend, key: shortKey}, shortCard, newKEK, bindingContext)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("16-byte card key: err = %v, want ErrInvalidEnvelope — a 128-bit key would be re-bound to %s and persisted under an envelope declaring %q", err, newKEK.Version, short.Algorithm)
	}
	if shortCard.rewrapTo != nil {
		t.Fatalf("16-byte card key: the new KEK was asked to wrap %d bytes; it must not be reached", len(shortCard.rewrapTo))
	}
	if !bytes.Equal(short.WrappedDataKey, before) || short.KEK.Version != kek.Version {
		t.Fatal("16-byte card key: the envelope was mutated by a rewrap that must have refused")
	}
}
