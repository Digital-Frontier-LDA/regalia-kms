//go:build piv

package yubikey

import (
	"crypto"
	"sort"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/go-piv/piv-go/v2/piv"
)

// pivAlgorithms maps an advertised algorithm name to the PIV algorithm a card reports for it.
//
// Deliberately written out rather than derived, because it is the thing under test: the driver's
// gates are the other half of this mapping, and deriving both from one source would make the test
// agree with itself. The floor below requires it to cover everything the matrix advertises, so
// adding rsa3072 to yubikey-piv fails here rather than passing unnoticed.
var pivAlgorithms = map[string]piv.Algorithm{
	"p256":    piv.AlgorithmEC256,
	"p384":    piv.AlgorithmEC384,
	"rsa2048": piv.AlgorithmRSA2048,
	"ed25519": piv.AlgorithmEd25519,
}

// digestSizes is the digest length each advertised signing algorithm must accept.
var digestSizes = map[string]int{
	"p256": crypto.SHA256.Size(),
	"p384": crypto.SHA384.Size(),
	// RSA is sent the PKCS #1 DigestInfo, not a bare digest (sign_contract.go).
	"rsa2048": len(digestInfoPrefixes[crypto.SHA256]) + crypto.SHA256.Size(),
	"ed25519": crypto.SHA256.Size(),
}

func advertisedForYubiKeyPIV(t *testing.T) map[string]map[string]bool {
	t.Helper()
	advertised, ok := registry.Capabilities()["yubikey-piv"]
	if !ok || len(advertised) == 0 {
		t.Fatal("the capability matrix advertises nothing for yubikey-piv, so both directions below check nothing")
	}
	return advertised
}

// NOTHING THE MATRIX PROMISES FOR yubikey-piv MAY BE REFUSED BY THE DRIVER.
//
// nitrokey has had both directions of this since a real divergence was found there — the driver
// accepted secp256k1 for key agreement while the matrix advertised that curve for sign alone.
// yubikey had neither direction. TestPIVSlotAndAlgorithmAllowlist checks the same gates against a
// hand-written list, which is green whatever the matrix says: add rsa3072 to yubikey-piv and the
// driver refuses it with nothing failing.
func TestEveryAdvertisedYubiKeyAlgorithmIsAcceptedByTheDriver(t *testing.T) {
	for algorithm, operations := range advertisedForYubiKeyPIV(t) {
		pivAlgorithm, mapped := pivAlgorithms[algorithm]
		if !mapped {
			t.Fatalf("the matrix advertises %q for yubikey-piv and this test has no PIV algorithm for it, "+
				"so the driver's gates are unchecked for it — add it to pivAlgorithms and digestSizes", algorithm)
		}
		if !algorithmMatches(pivAlgorithm, algorithm) {
			t.Errorf("algorithmMatches(%v, %q) = false, but the matrix advertises it", pivAlgorithm, algorithm)
		}
		if !operations["sign"] {
			continue
		}
		size, known := digestSizes[algorithm]
		if !known {
			t.Fatalf("%q is advertised for sign and this test has no digest size for it", algorithm)
		}
		if _, ok := signingHash(algorithm, size); !ok {
			t.Errorf("signingHash(%q, %d) refused an algorithm the matrix advertises for sign", algorithm, size)
		}
	}
}

// AND NOTHING THE MATRIX WITHHOLDS MAY BE QUIETLY ACCEPTED.
//
// The corpus is every algorithm named anywhere in the matrix, not a hand-picked list, so an
// algorithm another backend supports cannot be added to yubikey's gates without being advertised
// for yubikey.
func TestTheDriverRefusesEveryAlgorithmTheMatrixWithholdsFromYubiKey(t *testing.T) {
	advertised := advertisedForYubiKeyPIV(t)
	corpus := map[string]bool{}
	for _, algorithms := range registry.Capabilities() {
		for algorithm := range algorithms {
			corpus[algorithm] = true
		}
	}
	var withheld []string
	for algorithm := range corpus {
		if _, allowed := advertised[algorithm]; !allowed {
			withheld = append(withheld, algorithm)
		}
	}
	sort.Strings(withheld)
	if len(withheld) == 0 {
		t.Fatal("every algorithm in the matrix is advertised for yubikey-piv, so this converse checks nothing")
	}

	for _, algorithm := range withheld {
		// Against every PIV algorithm the driver knows, not just the matching one: the question is
		// whether any card algorithm can be paired with a withheld name and accepted.
		for name, pivAlgorithm := range pivAlgorithms {
			if algorithmMatches(pivAlgorithm, algorithm) {
				t.Errorf("algorithmMatches(%v, %q) = true, but the matrix withholds %q from yubikey-piv "+
					"(it is %q on the card)", pivAlgorithm, algorithm, algorithm, name)
			}
		}
		for _, size := range []int{crypto.SHA256.Size(), crypto.SHA384.Size(), crypto.SHA512.Size()} {
			if _, ok := signingHash(algorithm, size); ok {
				t.Errorf("signingHash(%q, %d) accepted an algorithm the matrix withholds from yubikey-piv", algorithm, size)
			}
		}
	}
}

// A DIGEST OF THE WRONG LENGTH IS NOT THE ALGORITHM IT CLAIMS TO BE. Advertised or not, the size
// gate is what stops a SHA-256 digest being signed as though it were SHA-384.
func TestSigningRefusesADigestOfTheWrongLength(t *testing.T) {
	for algorithm, size := range digestSizes {
		if algorithm == "ed25519" {
			continue // it signs a message, not a digest of one size: see the test below
		}
		if _, ok := signingHash(algorithm, size); !ok {
			t.Fatalf("signingHash(%q, %d) refused the correct digest size, so the case below proves nothing", algorithm, size)
		}
		if _, ok := signingHash(algorithm, size-1); ok {
			t.Errorf("signingHash(%q, %d) accepted a digest one byte short", algorithm, size-1)
		}
		if _, ok := signingHash(algorithm, size+1); ok {
			t.Errorf("signingHash(%q, %d) accepted a digest one byte long", algorithm, size+1)
		}
	}
}

// ED25519 IS SIGNED WITH NO HASH NAMED, AND WITHIN ITS BOUND.
//
// piv-go refuses an Ed25519 signature requested with any hash ("ed25519ph not supported"), so a
// hash value here that is not zero would turn every signature into a failure that only a card
// would show. The bound is the contract's (OPENBAO-COMPATIBILITY.md), not the card's.
func TestEd25519IsSignedAsAMessageOfBoundedLength(t *testing.T) {
	for _, size := range []int{1, crypto.SHA256.Size(), 200, maxEd25519MessageBytes} {
		hash, ok := signingHash("ed25519", size)
		if !ok || hash != crypto.Hash(0) {
			t.Errorf("signingHash(ed25519, %d) = (%v, %v), want (0, true)", size, hash, ok)
		}
	}
	for _, size := range []int{0, maxEd25519MessageBytes + 1, 4096} {
		if _, ok := signingHash("ed25519", size); ok {
			t.Errorf("signingHash(ed25519, %d) accepted a message outside the bound", size)
		}
	}
	if maxEd25519MessageBytes != 1024 {
		t.Fatalf("the Ed25519 bound is %d; OPENBAO-COMPATIBILITY.md states 1024, and the two must move together", maxEd25519MessageBytes)
	}
}
