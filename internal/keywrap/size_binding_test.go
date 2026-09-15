package keywrap

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
)

// The algorithm name in the manifest and the key actually in the slot must agree exactly, and
// expectedBits is the only thing making them. Two of its three arms were untested: a mapping that
// returned 2048 for "rsa3072" would accept a 2048-bit key for an object the manifest declares at
// 3072 — a downgrade that nothing downstream would notice, because the wrap succeeds and the
// envelope is well-formed.
//
// The existing coverage was one direction of one pair (a 2048 key offered as rsa3072). This is the
// full matrix, so no single arm can be wrong in either direction.

// publicKeyOfSize builds a PKIX public key of exactly `bits` bits WITHOUT generating one.
//
// A real 4096-bit keygen takes about a second and varies with the runner; the modulus below takes
// 170µs. Nothing here needs a valid key: RSAOAEP parses the DER, compares BitLen to the algorithm,
// and encrypts — and OAEP encryption is modular exponentiation, which does not care whether the
// modulus is a product of primes.
//
// IT IS NOT A USABLE KEY. Nothing can decrypt what it encrypts, so a round-trip assertion must not
// be added to a test using this helper; TestRSAOAEPBindsContext does that with a real key. The
// modulus is 2^(bits-1)+1, which is odd and has the top bit set, so BitLen is exactly `bits`.
func publicKeyOfSize(t *testing.T, bits int) []byte {
	t.Helper()
	modulus := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	modulus.Add(modulus, big.NewInt(1))
	if modulus.BitLen() != bits {
		t.Fatalf("the synthetic modulus is %d bits, not %d", modulus.BitLen(), bits)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestTheAlgorithmNameMustMatchTheKeyExactly(t *testing.T) {
	sizes := map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}
	keys := make(map[string][]byte, len(sizes))
	for algorithm, bits := range sizes {
		keys[algorithm] = publicKeyOfSize(t, bits)
	}

	for _, declared := range []string{"rsa2048", "rsa3072", "rsa4096"} {
		for _, actual := range []string{"rsa2048", "rsa3072", "rsa4096"} {
			t.Run(declared+" declared, "+actual+" key", func(t *testing.T) {
				wrapped, err := RSAOAEP(keys[actual], []byte("data-key"), []byte("context"), declared)
				if declared == actual {
					if err != nil {
						t.Fatalf("a matching %s key was refused: %v", actual, err)
					}
					if len(wrapped) != sizes[actual]/8 {
						t.Fatalf("wrapped output is %d bytes, want %d for %s", len(wrapped), sizes[actual]/8, actual)
					}
					return
				}
				if err == nil {
					t.Fatalf("an %s key was accepted for an object declared %s: the manifest's algorithm and the key in the slot no longer have to agree, and a smaller key would pass as a larger one",
						actual, declared)
				}
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("error = %v, want ErrInvalid", err)
				}
			})
		}
	}
}

// TestAnUnnamedAlgorithmIsRefused.
//
// THE ALLOWLIST AND expectedBits' DEFAULT ARM ENFORCE THE SAME RULE, so neither can be falsified
// alone (TESTING.md §17). Delete the allowlist and an unknown algorithm still fails, because
// expectedBits returns 0 and no key has zero bits; make the default arm permissive and the
// allowlist catches it first. Measured: only removing the allowlist AND making the default return
// 2048 turns this red, which is what the test is really holding — that an unnamed algorithm is
// refused by SOMETHING, not by arithmetic that happens to disagree.
//
// The redundancy is worth keeping. The allowlist states the rule where a reader looks for it; the
// default arm makes a new algorithm added to expectedBits and forgotten in the allowlist fail
// closed rather than open.
func TestAnUnnamedAlgorithmIsRefused(t *testing.T) {
	key := publicKeyOfSize(t, 2048)
	for _, algorithm := range []string{"", "rsa1024", "rsa2049", "RSA2048", "rsa-2048", "ed25519", "aes-256"} {
		// t.Run("") produces an unnamed subtest, which cannot be re-run with -run and reads as a
		// gap in the output.
		name := algorithm
		if name == "" {
			name = "<empty>"
		}
		t.Run(name, func(t *testing.T) {
			if _, err := RSAOAEP(key, []byte("data-key"), []byte("context"), algorithm); !errors.Is(err, ErrInvalid) {
				t.Fatalf("algorithm %q returned %v, want ErrInvalid", algorithm, err)
			}
		})
	}
	// And a valid algorithm does not excuse a malformed key.
	//
	// THIS PINS THE GUARANTEE, NOT THE GUARD -- the ParsePKIXPublicKey error check above the type
	// assertion is a second §17 site in this function, alongside the allowlist. It is REACHED (this
	// row reaches it) but it cannot be the sole refuser, because ParsePKIXPublicKey returns a nil
	// `pub` on every error path, so the `*rsa.PublicKey` assertion on the next line refuses the
	// identical input. Both return the same bare ErrInvalid, so no message separates them and no
	// fixture can tell which one fired.
	//
	// MEASURED, not reasoned. With `err != nil` alone mutated to `(false && (err != nil))`,
	// RSAOAEP("not a key", ...) returns exactly what it returns today -- `err=key wrapping failed,
	// out=0 bytes, nil=true` -- and the whole package set stays green. With that operand AND the
	// `!ok` assertion neutralised together, the same call instead panics with a nil pointer
	// dereference at key.N.BitLen(). One arm indistinguishable, the other distinguishable: the type
	// assertion is what masks it, and the redundancy is worth keeping for the same reason the
	// allowlist's is.
	if _, err := RSAOAEP([]byte("not a key"), []byte("data-key"), []byte("context"), "rsa2048"); !errors.Is(err, ErrInvalid) {
		t.Fatal("a malformed key was accepted under a valid algorithm")
	}

	// KNOWN-GOOD ANCHOR (§18). Every assertion above is a refusal, so an RSAOAEP that returned
	// ErrInvalid for everything would pass this whole function. The accepting path is held in
	// TestTheAlgorithmNameMustMatchTheKeyExactly, but not in the same test, which is where §18 asks
	// for it. Last, so a t.Fatal here cannot foreclose the rows it is the control for.
	wrapped, err := RSAOAEP(key, []byte("data-key"), []byte("context"), "rsa2048")
	if err != nil {
		t.Fatalf("the same 2048-bit key was refused under its own algorithm: %v", err)
	}
	if len(wrapped) != 256 {
		t.Fatalf("wrapped output is %d bytes, want 256", len(wrapped))
	}
}
