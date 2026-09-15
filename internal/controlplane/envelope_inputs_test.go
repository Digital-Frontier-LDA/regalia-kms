package controlplane

// THE ENVELOPE INPUTS THAT CRASH THE INSPECTOR INSTEAD OF BEING REFUSED BY IT (#237 sweep).
//
// Open is the offline half of the custody path. It runs on a machine with no network, against a
// file that has been on removable media, and every byte it is handed is attacker-controllable:
// the envelope is sealed to a PUBLISHED public key, so anyone can produce one. Its whole design
// answers that — one opaque error for every failure, so a holder of a file they cannot read
// learns nothing from which field was wrong.
//
// Three of its guards had no detector, and their failure mode is not "a refusal did not happen".
// It is a PANIC: the inspector dies on the operator's terminal, mid-restore, with a stack trace
// instead of a verdict. Measured with each neutralised in turn, not inferred from the code:
//
//	envelope.go:149  len(nonce) != gcmNonceSize  -> PANIC "crypto/cipher: incorrect nonce length
//	                                                given to GCM", from an envelope field
//	envelope.go:112  recipient == nil (Open)     -> PANIC, nil dereference in recipient.Curve()
//	envelope.go:69   recipient == nil (Seal)     -> PANIC, same shape on the sealing side
//
// THE NONCE ROW CORRECTS A DISMISSAL, which is why it is worth stating at length. The previous
// sweep recorded this operand as REDUNDANT — "the nonce-size and PEM-type checks (AEAD and
// PKIX/PKCS8 parsing catch the same inputs downstream)". The AEAD does not catch it. Measured
// against crypto/cipher directly, every wrong length — 0, 1, 11, 13, 64 — makes gcm.Open PANIC
// rather than return an error:
//
//	gcm.Open(nil, make([]byte, 11), ...) -> panic: crypto/cipher: incorrect nonce length given to GCM
//
// A panic is not a refusal. It is the one outcome this package spends its whole design avoiding,
// reached from a base64 field an attacker writes. The dismissal answered the adjacent question
// ("is the envelope still unopenable?" — yes) rather than the one that mattered ("does the
// process survive to say so?" — no).
//
// AND THE EXISTING NONCE COVERAGE READS LIKE IT PINS THIS AND DOES NOT.
// TestOpenRefusesEverythingExceptTheRightKeyAndBytes tampers the nonce with "AAAAAAAAAAAAAAAA" — sixteen base64
// characters, which decode to exactly TWELVE bytes. It is a wrong-VALUE nonce of the RIGHT
// LENGTH, so it exercises the AEAD and never reaches the length guard. A reader scanning for
// "is the nonce checked" finds a row and stops.

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

// openEnvelope is a genuine sealed envelope plus the key that opens it, decoded so a single
// field can be rewritten and re-encoded.
func openEnvelope(t *testing.T) (Envelope, *ecdh.PrivateKey) {
	t.Helper()
	publicPEM, privatePEM := testKeys(t)
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal([]byte("control plane payload"), recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := json.Unmarshal(sealed, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded, authorityKey(t, privatePEM)
}

func TestOpenRefusesANonceThatIsNotTwelveBytes(t *testing.T) {
	genuine, key := openEnvelope(t)

	// ANCHOR, first: the fixture opens. Without it every refusal below is compatible with
	// "Open refuses everything", and the length rows would prove nothing.
	encoded, err := json.Marshal(genuine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(encoded, key); err != nil {
		t.Fatalf("anchor: the untouched envelope must open, got %v", err)
	}

	// ANCHOR, second: a wrong nonce of the RIGHT length is refused by the AEAD. This is the
	// case the existing suite already covers, kept here so the rows below are visibly about
	// LENGTH and not about the nonce being wrong.
	rightLength := genuine
	rightLength.Nonce = base64.StdEncoding.EncodeToString(make([]byte, gcmNonceSize))
	encoded, err = json.Marshal(rightLength)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(encoded, key); !errors.Is(err, errOpen) {
		t.Fatalf("anchor: a zeroed 12-byte nonce must be refused by the AEAD, got %v", err)
	}

	// THE GATES. Each is valid base64 — so the decode operand beside this one cannot be what
	// refuses them — and each is a length crypto/cipher panics on.
	for _, size := range []int{0, 1, 11, 13, 24, 64} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			// RECOVERED DELIBERATELY. Without the guard this input does not return, it
			// panics, and an unrecovered panic aborts the whole test binary: every other
			// test in the package stops reporting and the failing set no longer says which
			// input got there. Recovering keeps this row as the thing that names it.
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Open PANICKED on a %d-byte nonce instead of refusing: %v\n"+
						"The nonce is a base64 field of a file anyone can produce and an operator "+
						"carries to an offline machine. crypto/cipher panics on any length but 12, "+
						"so without the length guard the inspector dies mid-restore instead of "+
						"printing a verdict — and no AEAD failure happens, because the AEAD is "+
						"never reached.", size, recovered)
				}
			}()
			wrong := genuine
			nonce := make([]byte, size)
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			wrong.Nonce = base64.StdEncoding.EncodeToString(nonce)
			if _, decodeErr := base64.StdEncoding.Strict().DecodeString(wrong.Nonce); decodeErr != nil {
				t.Fatalf("fixture: the nonce must be VALID base64 so the decode guard beside "+
					"the length guard cannot be what refuses it: %v", decodeErr)
			}
			encoded, err := json.Marshal(wrong)
			if err != nil {
				t.Fatal(err)
			}

			opened, err := Open(encoded, key)

			if err == nil {
				t.Fatalf("a %d-byte nonce opened the envelope, returning %d bytes", size, len(opened))
			}
			if !errors.Is(err, errOpen) {
				t.Fatalf("refused by the wrong rule: %v — every Open failure is one opaque "+
					"error on purpose, so a distinguishable one is itself the leak", err)
			}
		})
	}
}

func TestSealAndOpenRefuseANilRecipientRatherThanDereferencingIt(t *testing.T) {
	// Both halves take a *ecdh.PublicKey / *ecdh.PrivateKey and both immediately call a method
	// on it. The nil check is the only thing between a nil argument and a nil dereference, and
	// nothing exercised either. The CLI cannot pass nil today — ParseRecipient never returns a
	// nil key beside a nil error — so this is the exported API's own contract, in the same
	// class as the four constructor-nil guards closed on #344.
	genuine, key := openEnvelope(t)
	encoded, err := json.Marshal(genuine)
	if err != nil {
		t.Fatal(err)
	}
	// ANCHOR: the fixture opens with the key it was sealed to, so the refusals below are
	// about the recipient argument and not about the bytes.
	if _, err := Open(encoded, key); err != nil {
		t.Fatalf("anchor: the untouched envelope must open, got %v", err)
	}

	t.Run("Seal", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Seal PANICKED on a nil recipient instead of refusing: %v", recovered)
			}
		}()
		if _, err := Seal([]byte("payload"), nil); err == nil {
			t.Fatal("Seal accepted a nil recipient and produced an envelope sealed to nobody")
		}
	})

	t.Run("Open", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Open PANICKED on a nil authority key instead of refusing: %v", recovered)
			}
		}()
		if _, err := Open(encoded, nil); !errors.Is(err, errOpen) {
			t.Fatalf("Open with a nil key returned %v, want the one opaque refusal", err)
		}
	})

	// ANCHORS, NOT GATES, and labelled so no future reader mistakes them. A recipient on the
	// wrong curve is refused by the SIBLING operand rather than by the curve check: measured,
	// with `recipient.Curve() != ecdh.P256()` neutralised, Seal still fails at ephemeral.ECDH
	// ("curves do not match") and Open still fails at recipient.ECDH. These rows therefore pass
	// with the curve operand present OR absent — they pin that the refusal happens, not which
	// guard makes it, and they exist so a change that stops refusing a P-384 key fails here.
	wrongCurve, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Seal([]byte("payload"), wrongCurve.PublicKey()); err == nil {
		t.Fatal("anchor: Seal accepted a P-384 recipient")
	}
	if _, err := Open(encoded, wrongCurve); err == nil {
		t.Fatal("anchor: Open accepted a P-384 authority key")
	}
}
