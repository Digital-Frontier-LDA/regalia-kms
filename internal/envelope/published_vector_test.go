package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// TestTheEnvelopeConstructionIsTheBytesEnvelopeMdPublishes holds three things to one another: the
// construction ENVELOPE.md publishes for a client outside this module, the sealing path, and the
// text of ENVELOPE.md itself.
//
// The vector is rebuilt here from string literals and the standard library ONLY. Nothing from this
// package is called until the bytes exist, because the claim under test is that a client with no
// access to this package can produce them. clientContentAAD in seal_assembled_test.go shows the AAD
// shape but takes the digest from contextDigest; this test takes nothing.
func TestTheEnvelopeConstructionIsTheBytesEnvelopeMdPublishes(t *testing.T) {
	const (
		objectID    = "example-seal-object"
		purpose     = "example-purpose"
		environment = "staging"
		plaintext   = "the secret being sealed"

		publishedNonce      = "oKGio6Slpqeoqaqr"
		publishedDigest     = "sha256:ec7edc0f534a0ce8cfb1a34a534de69e517fa146ed0146dc9a3a8c3c6101663e"
		publishedCiphertext = "knAZDTauYc0HEaexYhOuuVDfPHH+0iYtSQbBtxneCzv/SC8qVDRB"
	)

	// The client's side, as ENVELOPE.md states it.
	bindingContext := "regalia-release-v1\x00" + objectID + "\x00" + purpose + "\x00" + environment
	sum := sha256.Sum256([]byte(bindingContext))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	contentAAD := "regalia-envelope-v2\x00" + objectID + "\x00AES-256-GCM\x00" + digest
	dataKey, nonce := make([]byte, 32), make([]byte, 12)
	for index := range dataKey {
		dataKey[index] = byte(index)
	}
	for index := range nonce {
		nonce[index] = byte(0xa0 + index)
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), []byte(contentAAD))

	for name, pair := range map[string][2]string{
		"nonce":      {base64.StdEncoding.EncodeToString(nonce), publishedNonce},
		"digest":     {digest, publishedDigest},
		"ciphertext": {base64.StdEncoding.EncodeToString(ciphertext), publishedCiphertext},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("DEFECT: the %s built from ENVELOPE.md's steps is %q, and the published one is %q", name, pair[0], pair[1])
		}
	}
	if len(bindingContext) != 62 || len(contentAAD) != 123 || len(ciphertext) != 39 || len(digest) != 71 {
		t.Fatalf("DEFECT: the published lengths are 62, 123, 39 and 71; built %d, %d, %d and %d",
			len(bindingContext), len(contentAAD), len(ciphertext), len(digest))
	}

	// The package's own derivations are the published ones.
	if got := string(ReleaseContext(objectID, purpose, environment)); got != bindingContext {
		t.Fatalf("DEFECT: ReleaseContext is no longer the binding context ENVELOPE.md publishes: %q", got)
	}
	if got := contextDigest([]byte(bindingContext)); got != digest {
		t.Fatalf("DEFECT: contextDigest is no longer the digest ENVELOPE.md publishes: %q", got)
	}

	// The sealing path accepts exactly these bytes, and what it seals opens to the plaintext. The
	// context is derived the way the coordinator derives it, from object, purpose and environment.
	device := hardware("nitrokey-pkcs11", map[string][]byte{
		"example-seal-object:1": bytes.Repeat([]byte{7}, 32), "another-object:1": bytes.Repeat([]byte{8}, 32),
	})
	kek := KeyRef{Backend: device.Backend(), ID: objectID, Version: "1"}
	sealed, err := SealAssembled(context.Background(), device, kek, objectID,
		ReleaseContext(objectID, purpose, environment), ciphertext, nonce, append([]byte(nil), dataKey...),
		time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("DEFECT: the sealing path refuses the published vector: %v", err)
	}
	var opened []byte
	if err := sealed.Open(context.Background(), device, ReleaseContext(objectID, purpose, environment), func(value []byte) error {
		opened = append([]byte(nil), value...)
		return nil
	}); err != nil || string(opened) != plaintext {
		t.Fatalf("DEFECT: the sealed vector does not open to its plaintext: %q, %v", opened, err)
	}

	// The context is the caller's to match, not to choose: the same bytes under another purpose or
	// environment do not seal. Without these the acceptance above would prove nothing about binding.
	for name, other := range map[string][]byte{
		"another purpose":     ReleaseContext(objectID, "another-purpose", environment),
		"another environment": ReleaseContext(objectID, purpose, "production"),
	} {
		if _, err := SealAssembled(context.Background(), device, kek, objectID, other, ciphertext, nonce,
			append([]byte(nil), dataKey...), time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalidEnvelope) {
			t.Fatalf("DEFECT: the published vector under %s is not refused as an invalid envelope: %v", name, err)
		}
	}
	if _, err := SealAssembled(context.Background(), device, KeyRef{Backend: device.Backend(), ID: "another-object", Version: "1"},
		"another-object", ReleaseContext("another-object", purpose, environment), ciphertext, nonce,
		append([]byte(nil), dataKey...), time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("DEFECT: the published vector for another object is not refused as an invalid envelope: %v", err)
	}

	// ENVELOPE.md carries these values and the two layouts, so the text cannot drift from the test.
	document, err := os.ReadFile("../../ENVELOPE.md")
	if err != nil {
		t.Fatal(err)
	}
	// The data key is the bytes 0x00 to 0x1f. Its base64 form is taken from those bytes here, not
	// written as a literal: the published ciphertext already pins it, since no other key yields it.
	for _, want := range []string{
		base64.StdEncoding.EncodeToString(dataKey), publishedNonce, publishedDigest, publishedCiphertext,
		"`" + objectID + "`", "`" + purpose + "`", "`" + environment + "`", "`" + plaintext + "`",
		"regalia-release-v1 NUL <object_id> NUL <purpose> NUL <environment>",
		"regalia-envelope-v2 NUL <object_id> NUL AES-256-GCM NUL <context digest>",
		"TestTheEnvelopeConstructionIsTheBytesEnvelopeMdPublishes",
	} {
		if !strings.Contains(string(document), want) {
			t.Fatalf("DEFECT: ENVELOPE.md no longer carries %q", want)
		}
	}
}
