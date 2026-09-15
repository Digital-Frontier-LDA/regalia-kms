package certs

// GUARD COVERAGE (#237 sweep). 59 mutations across this package, verdicts from exit codes:
// 9 survived (15%) — the best-covered of the nine packages the campaign never named, which
// is itself worth recording rather than leaving as an assumption.
//
// The three pinned here are the ECDSA card-signature rules, and they survived for the same
// reason twice over: THE EXISTING FIXTURE TRIPS BOTH OPERANDS AT ONCE. certs_test.go's
// `zeroed` row returns make([]byte, 64), so r AND s are both zero and neither
// `r.Sign() == 0` nor `s.Sign() == 0` can be shown to matter on its own. A card that
// returned a valid r with a zero s would be a signature that verifies against nothing, and
// no test could tell you whether this package refuses it.
//
// The same file already carries the scar from the other direction (§19, at its own line):
// its odd-length row used to be all zeros and was refused by the zero rule rather than the
// length rule it named. Both defects are the same one — one fixture, two guards.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestEachZeroECDSAComponentIsRefusedOnItsOwn(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("tbs"))

	nonZero := func() []byte {
		half := make([]byte, 32)
		for i := range half {
			half[i] = byte(i + 1)
		}
		return half
	}
	zero := func() []byte { return make([]byte, 32) }

	for _, row := range []struct {
		name string
		raw  []byte
	}{
		{"r is zero, s is valid", append(zero(), nonZero()...)},
		{"r is valid, s is zero", append(nonZero(), zero()...)},
	} {
		t.Run(row.name, func(t *testing.T) {
			card := &CardSigner{PublicKey: key.Public(), Sign_: func([]byte) ([]byte, error) {
				return row.raw, nil
			}}
			_, err := card.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err == nil {
				t.Fatalf("a signature with one zero component was accepted — it verifies against nothing, and the half that is valid makes it look like a signature")
			}
			if !strings.Contains(err.Error(), "zero ECDSA signature component") {
				t.Fatalf("refused, but by a different rule: %v — the length is even and 64 bytes, so only the zero-component rule can object", err)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18). Two non-zero halves are marshalled, so the rows above
	// are not passing against a rule that refuses every raw signature.
	good := &CardSigner{PublicKey: key.Public(), Sign_: func([]byte) ([]byte, error) {
		return append(nonZero(), nonZero()...), nil
	}}
	if _, err := good.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("a well-formed raw r||s signature was refused: %v", err)
	}
}

// AN EMPTY SIGNATURE IS EMPTY, NOT ZERO-COMPONENT. Both refuse, so `err != nil` cannot tell
// them apart — but the diagnoses point an operator at different faults. Measured with the
// length operand mutated away: an empty read reaches the split, produces r = s = 0 from no
// bytes, and is reported as "zero ECDSA signature component", sending whoever reads it
// looking at the card's key material instead of at a truncated read. The operand earns its
// place by giving the failure its right name, which `err != nil` would never have shown.
func TestAnEmptyCardSignatureIsReportedAsMalformedRatherThanAsZero(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("tbs"))
	empty := &CardSigner{PublicKey: key.Public(), Sign_: func([]byte) ([]byte, error) {
		return []byte{}, nil
	}}
	_, err = empty.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("an empty card signature was accepted")
	}
	if !strings.Contains(err.Error(), "malformed raw ECDSA signature") {
		t.Fatalf("an empty signature was reported as %v — zero length and zero components are different faults, and the message is what sends an operator to the right one", err)
	}
}
