package controlplane

// ONE DOCUMENT, NOTHING AFTER IT.
//
// Open decoded the envelope with a json.Decoder and never asked whether anything followed it.
// Decode stops at the end of the first JSON value, so an export and the same export with any
// bytes appended opened to the SAME payload. Measured before the fix: 255 bytes and 275 bytes,
// two different SHA-256s, one identical result.
//
// Fifteen of the sixteen json.NewDecoder sites in this module already made this check --
// loadConfig, readLease, decodeRequest, LoadKeySet and the rest. This was the one that did not,
// and it is the package whose output operators carry offline.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestOpenRefusesAnythingAppendedAfterTheEnvelopeDocument(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("control plane payload")
	clean, err := Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// ANCHOR, placed first here on purpose: it establishes that the fixture opens at all, so a
	// refusal below is about the appended bytes and not about the envelope. It is an anchor and
	// not a gate -- the round-trip test already covers acceptance -- so it may t.Fatal.
	opened, err := Open(clean, authorityKey(t, privatePEM))
	if err != nil {
		t.Fatalf("anchor: the clean envelope must open, got %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Fatal("anchor: the clean envelope opened to different bytes")
	}

	for _, rider := range []struct {
		name   string
		suffix string
	}{
		{"a second JSON document", ` {"attacker":"rider"}`},
		{"a bare scalar", ` 1`},
		{"an unterminated fragment", ` {`},
		{"a newline and a document", "\n{\"attacker\":\"rider\"}"},
	} {
		t.Run(rider.name, func(t *testing.T) {
			appended := append(append([]byte(nil), clean...), []byte(rider.suffix)...)
			if bytes.Equal(appended, clean) {
				t.Fatal("fixture: the two encodings must differ")
			}
			// The bytes differ, so if Open accepts both then a digest of this file no longer
			// identifies what was opened. That is the whole property.
			if sha256.Sum256(appended) == sha256.Sum256(clean) {
				t.Fatal("fixture: the digests must differ")
			}
			also, err := Open(appended, authorityKey(t, privatePEM))
			if err == nil {
				t.Fatalf("Open accepted %d bytes where %d were sealed, returning %d bytes of payload: "+
					"two byte-different exports now open to the same result, so a recorded digest "+
					"names nothing", len(appended), len(clean), len(also))
			}
			if !errors.Is(err, errOpen) {
				t.Fatalf("refused by the wrong rule: %v", err)
			}
		})
	}
}
