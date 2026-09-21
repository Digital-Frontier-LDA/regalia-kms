package nitrokey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// halfOrder is N/2 — the boundary the Cosmos SDK enforces.
func halfOrder() *big.Int { return new(big.Int).Rsh(secp256k1Order, 1) }

func sigBytes(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// TestHighSIsRewrittenToLowS is the defect itself: a token-produced high-S signature is what the
// chain refuses, and 11 of 24 signatures from DENK0404144 were high-S on 2026-09-21.
func TestHighSIsRewrittenToLowS(t *testing.T) {
	r := big.NewInt(0x1234)
	high := new(big.Int).Sub(secp256k1Order, big.NewInt(9)) // far above N/2
	if high.Cmp(halfOrder()) <= 0 {
		t.Fatal("fixture is not high-S; the test would prove nothing")
	}
	out, rewritten := normalizeLowS("secp256k1", sigBytes(r, high))
	if !rewritten {
		t.Fatal("a high-S signature was left as it was; the chain would reject it")
	}
	if len(out) != 64 {
		t.Fatalf("normalized signature is %d bytes, want 64", len(out))
	}
	if got := new(big.Int).SetBytes(out[32:]); got.Cmp(halfOrder()) > 0 {
		t.Fatalf("s is still above N/2 after normalization: %x", out[32:])
	}
	if got := new(big.Int).SetBytes(out[:32]); got.Cmp(r) != 0 {
		t.Fatalf("r was altered: got %x want %x", out[:32], r)
	}
	if want := new(big.Int).Sub(secp256k1Order, high); new(big.Int).SetBytes(out[32:]).Cmp(want) != 0 {
		t.Fatalf("s is not N-s: got %x want %x", out[32:], want)
	}
}

func TestLowSIsLeftExactlyAsItIs(t *testing.T) {
	in := sigBytes(big.NewInt(0x99), big.NewInt(0x11))
	out, rewritten := normalizeLowS("secp256k1", in)
	if rewritten {
		t.Fatal("a low-S signature was rewritten; nothing needed changing")
	}
	if !bytes.Equal(in, out) {
		t.Fatalf("a low-S signature was altered: %x -> %x", in, out)
	}
}

// Exactly N/2 is LOW by the SDK's rule (s > N/2 is what it rejects), so it must not be rewritten.
func TestExactlyHalfOrderIsNotRewritten(t *testing.T) {
	if _, rewritten := normalizeLowS("secp256k1", sigBytes(big.NewInt(1), halfOrder())); rewritten {
		t.Fatal("s == N/2 was rewritten; the boundary is s > N/2, and an off-by-one here changes a valid signature")
	}
}

// A small s must stay right-aligned in its 32 bytes. big.Int.Bytes() drops leading zeros, and a
// left-aligned write would be read as a completely different, enormous s.
func TestSmallSStaysRightAligned(t *testing.T) {
	high := new(big.Int).Sub(secp256k1Order, big.NewInt(1)) // normalizes to s' = 1
	out, rewritten := normalizeLowS("secp256k1", sigBytes(big.NewInt(0x55), high))
	if !rewritten {
		t.Fatal("fixture was not rewritten")
	}
	want := make([]byte, 32)
	want[31] = 1
	if !bytes.Equal(out[32:], want) {
		t.Fatalf("s' = 1 was not written right-aligned: %x", out[32:])
	}
}

// The claim is about secp256k1 only. Reinterpreting an Ed25519 or RSA result as r||s would corrupt
// it, and a DER-encoded ECDSA signature is not 64 bytes either.
func TestOtherAlgorithmsAndLengthsAreUntouched(t *testing.T) {
	high := sigBytes(big.NewInt(1), new(big.Int).Sub(secp256k1Order, big.NewInt(9)))
	for _, algorithm := range []string{"ed25519", "p256", "p384", "rsa2048", ""} {
		out, rewritten := normalizeLowS(algorithm, high)
		if rewritten || !bytes.Equal(out, high) {
			t.Fatalf("%s signature was rewritten as if it were secp256k1 r||s", algorithm)
		}
	}
	for _, size := range []int{0, 1, 63, 65, 70, 72} {
		blob := make([]byte, size)
		for i := range blob {
			blob[i] = 0xFF
		}
		out, rewritten := normalizeLowS("secp256k1", blob)
		if rewritten || !bytes.Equal(out, blob) {
			t.Fatalf("a %d-byte signature was treated as raw r||s", size)
		}
	}
}

// THE POINT OF THE WHOLE THING: normalizing must not break verification. (r, N-s) verifies under
// the same key for the same digest — this proves it on real signatures rather than asserting it.
func TestNormalizedSignatureStillVerifies(t *testing.T) {
	// P-256 is used here only because the standard library has it; the identity s -> N-s is a
	// property of ECDSA, not of the curve, and the arithmetic under test is exercised above
	// against the real secp256k1 order.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	order := elliptic.P256().Params().N
	half := new(big.Int).Rsh(order, 1)
	checked := 0
	for i := 0; i < 32; i++ {
		digest := sha256.Sum256([]byte{byte(i)})
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		if s.Cmp(half) > 0 {
			s = new(big.Int).Sub(order, s)
			checked++
		}
		if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
			t.Fatal("a low-S-normalized signature no longer verifies — normalization is not safe as implemented")
		}
	}
	if checked == 0 {
		t.Skip("no high-S signature occurred in 32 attempts; nothing was normalized to check")
	}
	t.Logf("normalized and re-verified %d high-S signatures", checked)
}

// The driver must apply it. A normalization nothing calls is a comment.
func TestSignReturnsLowSForSecp256k1(t *testing.T) {
	high := sigBytes(big.NewInt(0x77), new(big.Int).Sub(secp256k1Order, big.NewInt(3)))
	module := &fakeCryptoki{serial: "SERIAL-1", objectHandle: 42, signature: append([]byte(nil), high...)}
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	session, err := driver.Open(context.Background(), registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "SERIAL-1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := session.EstablishSecureChannel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := session.Login(context.Background(), []byte("123456")); err != nil {
		t.Fatal(err)
	}
	out, err := session.Sign(context.Background(), "02", "secp256k1", []byte("digest"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(out) != 64 {
		t.Fatalf("Sign returned %d bytes, want the 64-byte r||s it was given", len(out))
	}
	if got := new(big.Int).SetBytes(out[32:]); got.Cmp(halfOrder()) > 0 {
		t.Fatalf("Sign returned a HIGH-S secp256k1 signature; a Cosmos node would reject it: %x", out[32:])
	}
}
