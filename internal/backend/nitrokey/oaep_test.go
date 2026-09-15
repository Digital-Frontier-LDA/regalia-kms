package nitrokey

import (
	"crypto"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/miekg/pkcs11"
)

// THE CARD MUST UNWRAP WITH THE HASH THE KMS WRAPPED WITH.
//
// The wrapping hash and these mechanism parameters were independent literals in different files.
// Changing either alone produced envelopes the token could not open, and nothing would have said
// so until a secret release failed in production — a runtime failure for what is a build-time
// mistake. This test pins the two together: the parameters must be the ones for whatever
// keywrap.OAEPHash currently names, and a hash with no PKCS#11 expression must be an error rather
// than a silent fallback.
func TestOAEPParametersExpressTheWrappingHash(t *testing.T) {
	expected := map[crypto.Hash]struct{ hashAlg, mgf uint }{
		crypto.SHA1:   {pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1},
		crypto.SHA256: {pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256},
	}

	// An unmappable hash is a FAILURE, not an exemption. oaepParameters returns an error for it,
	// which is fail-closed but only at the first unwrap — a secret release in production is where
	// the operator would find out. The choice is made at compile time, so it must break here.
	want, mapped := expected[keywrap.OAEPHash]
	if !mapped {
		t.Fatalf("keywrap.OAEPHash is %v, which no PKCS#11 OAEP mechanism here expresses: the token could never unwrap what this KMS wraps, and nothing would say so until a release failed", keywrap.OAEPHash)
	}
	hashAlg, mgf, err := oaepParameters()
	if err != nil {
		t.Fatalf("oaepParameters rejected the configured wrapping hash %v: %v", keywrap.OAEPHash, err)
	}
	if hashAlg != want.hashAlg || mgf != want.mgf {
		t.Fatalf("OAEP parameters (hash=%#x mgf=%#x) do not match the wrapping hash %v (want hash=%#x mgf=%#x): envelopes would be unopenable by the card",
			hashAlg, mgf, keywrap.OAEPHash, want.hashAlg, want.mgf)
	}
}

// The constant must name a hash that is actually linked into the binary. crypto.Hash.New() panics
// on an unregistered hash, and the panic would land inside a wrap operation rather than at startup.
func TestWrappingHashIsAvailableAtRuntime(t *testing.T) {
	if !keywrap.OAEPHash.Available() {
		t.Fatalf("keywrap.OAEPHash is %v but its implementation is not linked in: wrapping would panic at the first request", keywrap.OAEPHash)
	}
}
