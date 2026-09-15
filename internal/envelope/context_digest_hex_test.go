package envelope

// A CONTEXT DIGEST THAT IS THE RIGHT SHAPE BUT NOT HEX IS REFUSED BY EXACTLY ONE CHECK, and
// nothing tested it. Found by re-running #237's sweep over this package.
//
// validateEnvelopeMetadata checks the digest in two steps: the length and the "sha256:" prefix,
// then that the remaining 64 characters actually decode as hex. Only the second rejects
// "sha256:" followed by 64 'z' characters — the first is satisfied, because the string is exactly
// as long as a real digest and starts the same way.
//
// Measured with the hex check defeated:
//
//	validateEnvelopeMetadata(non-hex digest) -> <nil>
//	Parse(an envelope carrying it)           -> <nil>
//
// Both accept it. Parse is the boundary that is supposed to establish that an envelope's own
// fields are well formed before anything downstream reasons about them, and Coordinator.Execute
// reaches Peek — which is Parse plus a KEK-version check — before it routes.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func digestFixture(t *testing.T, digest string) Envelope {
	t.Helper()
	objectID := "deployment-api-token"
	return Envelope{
		Version: Version, ObjectID: objectID,
		KEK:            KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"},
		Algorithm:      "AES-256-GCM",
		ContextDigest:  digest,
		CreatedAt:      time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
		Nonce:          make([]byte, 12),
		WrappedDataKey: []byte("wrapped-by-the-card"),
		// 32 is comfortably above what this path needs. Measured: Parse accepts a 16-byte
		// ciphertext (a bare GCM tag) and refuses 15. The 17-byte floor lives in the SEAL paths,
		// which reject empty plaintext; it does not apply here, and saying it did would send a
		// reader to the wrong guard. Nothing decrypts on this path in any case.
		Ciphertext: make([]byte, 32),
	}
}

func TestAContextDigestMustBeHexNotJustTheRightShape(t *testing.T) {
	objectID := "deployment-api-token"
	realDigest := contextDigest(ReleaseContext(objectID, "deploy", "production"))

	// ANCHOR: the same envelope with a genuine digest must parse, or a validator that refused
	// every digest would satisfy the row below and this would pin nothing.
	good := digestFixture(t, realDigest)
	encodedGood, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(encodedGood); err != nil {
		t.Fatalf("anchor: Parse of a well-formed envelope = %v, want nil — the row below would prove nothing", err)
	}

	// GATE: right length, right prefix, not hex. The shape check passes; only the hex decode
	// stands between this and an accepted envelope.
	notHex := "sha256:" + strings.Repeat("z", 64)
	if len(notHex) != len(realDigest) {
		t.Fatalf("fixture is not the same shape as a real digest: %d vs %d — the shape check would "+
			"refuse it and the hex check would never be reached", len(notHex), len(realDigest))
	}
	bad := digestFixture(t, notHex)
	if err := validateEnvelopeMetadata(bad, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("validateEnvelopeMetadata(non-hex digest) = %v, want ErrInvalidEnvelope", err)
	}
	encodedBad, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(encodedBad); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse(envelope with a non-hex context digest) = %v, want ErrInvalidEnvelope — "+
			"with the hex decode removed this parses cleanly, and Coordinator.Execute reaches Peek "+
			"before it routes", err)
	}
}
