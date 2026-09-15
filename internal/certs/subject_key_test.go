package certs

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strconv"
	"strings"
	"testing"
)

// acceptableSubjectKey decides what the KMS will issue a certificate FOR, and the existing coverage
// was a single 1024-bit RSA key. The rule has three arms and each fails differently: an RSA key can
// be merely too small, an EC key can be on a curve nobody chose, and any other algorithm is outside
// the set entirely. A certificate issued for a key the profile did not intend is not recoverable by
// revoking it later — it exists, signed, in whatever trust store accepted it.

func TestAnRSASubjectKeyIsAcceptedExactlyAtTheMinimum(t *testing.T) {
	// 2048 is the boundary, so both sides of it are asserted: a minimum that refuses its own
	// smallest allowed key is a different minimum than the one documented.
	atMinimum, err := rsa.GenerateKey(rand.Reader, minRSABits)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptableSubjectKey(&atMinimum.PublicKey); err != nil {
		t.Fatalf("a %d-bit RSA key was refused: %v", minRSABits, err)
	}

	belowMinimum, err := rsa.GenerateKey(rand.Reader, minRSABits-1)
	if err != nil {
		t.Fatal(err)
	}
	err = acceptableSubjectKey(&belowMinimum.PublicKey)
	if err == nil {
		t.Fatalf("a %d-bit RSA key was accepted, one bit under the minimum", minRSABits-1)
	}
	// The message carries both numbers because an operator holding a refused CSR needs to know how
	// far short it is, not merely that it is short.
	// Derived from minRSABits rather than written as "2047"/"2048": raising the floor should fail
	// this test on the invariant it checks, not on a string that happens to have moved.
	if !strings.Contains(err.Error(), strconv.Itoa(minRSABits-1)) || !strings.Contains(err.Error(), strconv.Itoa(minRSABits)) {
		t.Fatalf("error = %q, want it to name the key's size (%d) and the minimum (%d)", err, minRSABits-1, minRSABits)
	}
}

func TestALargerRSASubjectKeyIsStillAcceptable(t *testing.T) {
	// The rule is a floor, not a range. Refusing 3072 would be a surprising way to fail and is the
	// kind of thing a `!=` typo produces.
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptableSubjectKey(&key.PublicKey); err != nil {
		t.Fatalf("a 3072-bit RSA key was refused: %v", err)
	}
}

func TestOnlyTheThreeNamedCurvesAreAccepted(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := acceptableSubjectKey(&key.PublicKey); err != nil {
				t.Fatalf("%s was refused: %v", curve.Params().Name, err)
			}
		})
	}

	// P-224 is a real curve Go implements and this profile does not choose. It is the case that
	// separates "the curve list is enforced" from "anything ECDSA is accepted".
	t.Run("P-224", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		err = acceptableSubjectKey(&key.PublicKey)
		if err == nil {
			t.Fatal("P-224 was accepted: the curve list is not being enforced, only the key type")
		}
		if !strings.Contains(err.Error(), "elliptic curve") {
			t.Fatalf("error = %q, want the curve refusal — refused as a type would leave the curve list unproven", err)
		}
	})
}

func TestAKeyOfAnotherAlgorithmIsRefusedByType(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdhKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for name, key := range map[string]any{
		// Ed25519 is a perfectly good signing key and still refused: the profile issues for RSA and
		// ECDSA, and silently widening that at the CSR boundary would mean the issued certificate
		// is for an algorithm no policy considered.
		"an Ed25519 key":             edPublic,
		"an ECDH key":                ecdhKey.PublicKey(),
		"an RSA key passed by value": rsa.PublicKey{},
		"nothing at all":             nil,
	} {
		t.Run(name, func(t *testing.T) {
			err := acceptableSubjectKey(key)
			if err == nil {
				t.Fatalf("%s was accepted as a subject key", name)
			}
			if !strings.Contains(err.Error(), "subject key type") {
				t.Fatalf("%s: error = %q, want the type refusal", name, err)
			}
		})
	}
}
