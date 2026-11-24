package operations

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// TestCosmosVerifierRefusesWhenNeitherPinNorSignerKeyIsBound is the verifier's SECOND LOCK
// (regalia-kms-35b, #774 mutant A4). The coordinator refuses a binding with no pin and no SignDoc
// signer key before the token signs (cosmosSignerBound, TestCosmosUnboundSignerIsRefusedBeforeTheToken).
// verifyCosmosSignature must refuse the same case on its own: with neither, the only key left is the
// one the token reports about itself, and a token that signs with the wrong key reports that key too.
// So a signature that is mathematically valid under the token's key is still not verified.
//
// verifyCosmosSignature takes the token's key as bytes and calls nothing, so "no token call" is a
// property of its signature, not something to assert here; the coordinator test above asserts it.
func TestCosmosVerifierRefusesWhenNeitherPinNorSignerKeyIsBound(t *testing.T) {
	key := testSigner(t)
	tokenKey := secp256k1SPKI(key.PubKey())
	digest := sha256.Sum256(cosmosFixture(t))
	signed := secp256k1ecdsa.Sign(key, digest[:])
	r, s := signed.R(), signed.S()
	rBytes, sBytes := r.Bytes(), s.Bytes()
	raw := append(rBytes[:], sBytes[:]...)

	// Controls: the same signature verifies once something independent of the token names the key,
	// so a refusal below is the missing binding and nothing else.
	if err := verifyCosmosSignature("secp256k1", spkiPin(tokenKey), tokenKey, nil, digest[:], raw); err != nil {
		t.Fatalf("control (pinned) does not verify: %v -- the test proves nothing", err)
	}
	signer := &policy.CosmosPublicKey{TypeURL: secp256k1KeyType, Key: compressed(key)}
	if err := verifyCosmosSignature("secp256k1", "", tokenKey, signer, digest[:], raw); err != nil {
		t.Fatalf("control (SignDoc signer key) does not verify: %v -- the test proves nothing", err)
	}

	err := verifyCosmosSignature("secp256k1", "", tokenKey, nil, digest[:], raw)
	if !errors.Is(err, errCosmosSignatureUnverified) {
		t.Fatalf("DEFECT: with no pin and no SignDoc signer key the verifier returned %v, want errCosmosSignatureUnverified: it trusted the token's own word for its key", err)
	}
}
