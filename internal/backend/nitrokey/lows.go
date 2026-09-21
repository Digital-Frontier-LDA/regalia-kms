package nitrokey

import "math/big"

// secp256k1Order is the order of the secp256k1 group, N.
//
// WHY THIS FILE EXISTS. A PKCS#11 token returns whichever of the two equivalent ECDSA signatures
// its implementation computed: for every valid (r, s) the pair (r, N-s) is equally valid for the
// same message and key, and nothing in PKCS#11 says which one you get. The Cosmos SDK accepts only
// the LOW one — cosmos-sdk/crypto/keys/secp256k1 rejects a signature whose s exceeds N/2 outright,
// as malleability protection — so roughly half the signatures a token produces are refused
// on-chain.
//
// MEASURED, not assumed: 24 signatures from Nitrokey HSM 2 DENK0404144 on 2026-09-21 were 13 low-S
// and 11 HIGH-S. Those 11 transactions would have been rejected by any Cosmos node, while
// e2e/cosmos-hardware-sign-verify.sh reported "signature verified" for every one of them, because
// a general ECDSA verifier accepts both forms. A qualification that cannot fail is not a
// qualification, and a signer that works half the time is worse than one that never does.
//
// Normalising is not a weakening. (r, N-s) verifies under exactly the same public key for exactly
// the same digest; the signature is not re-derived, no private key is touched, and no additional
// nonce is consumed. It is a choice between two encodings of the same signature.
var secp256k1Order = mustOrder("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

func mustOrder(hexOrder string) *big.Int {
	n, ok := new(big.Int).SetString(hexOrder, 16)
	if !ok {
		panic("nitrokey: secp256k1 order constant is not hexadecimal")
	}
	return n
}

// normalizeLowS rewrites a raw r||s secp256k1 signature so that s <= N/2, which is the only form
// the Cosmos SDK accepts. Any other algorithm, or anything that is not a 64-byte r||s pair, is
// returned untouched: this makes a claim about secp256k1 and must not silently reinterpret an
// Ed25519 or RSA result, nor a DER-encoded one.
//
// It returns the signature and whether it rewrote it, so a caller that must REPORT what the token
// produced (a qualification harness) can tell the two apart.
func normalizeLowS(algorithm string, signature []byte) ([]byte, bool) {
	if algorithm != "secp256k1" || len(signature) != 64 {
		return signature, false
	}
	s := new(big.Int).SetBytes(signature[32:])
	half := new(big.Int).Rsh(secp256k1Order, 1)
	if s.Cmp(half) <= 0 {
		return signature, false
	}
	// s' = N - s. It is < N/2 by construction whenever s > N/2, and never zero for a valid
	// signature, so the result is a well-formed s.
	s.Sub(secp256k1Order, s)
	normalized := make([]byte, 64)
	copy(normalized, signature[:32])
	// FixedBytes, not Bytes: a big.Int drops leading zeros, and an s that happens to be small
	// would otherwise be written left-aligned and read as a completely different value.
	s.FillBytes(normalized[32:])
	return normalized, true
}
