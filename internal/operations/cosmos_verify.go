package operations

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// errCosmosSignatureUnverified marks a Cosmos signature the daemon could not verify against the
// object's registered public key. It is never success: the coordinator records it as
// "signature-unverified" and returns no bytes.
var errCosmosSignatureUnverified = errors.New("operations: cosmos signature does not verify under the registered key")

var (
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

type spkiAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type spki struct {
	Algorithm spkiAlgorithm
	PublicKey asn1.BitString
}

// cosmosKeyTypeURL is the SignerInfo.public_key type a chain verifies a signature of this
// algorithm with. Only these two curves have a Cosmos key type: a p384 (or any other) object has
// no key a chain could verify it under, so it is not a Cosmos signer here.
var cosmosKeyTypeURL = map[string]string{
	"secp256k1": "/cosmos.crypto.secp256k1.PubKey",
	"p256":      "/cosmos.crypto.secp256r1.PubKey",
}

// cosmosKey is a public key on one of the two Cosmos curves, held as a point so two encodings of
// the same key (the SignDoc's compressed SEC1, the token's uncompressed SPKI) compare equal.
type cosmosKey struct {
	k1   *secp256k1.PublicKey
	nist *ecdsa.PublicKey
}

func (key cosmosKey) equal(other cosmosKey) bool {
	if key.k1 != nil && other.k1 != nil {
		return key.k1.IsEqual(other.k1)
	}
	if key.nist != nil && other.nist != nil {
		return key.nist.Equal(other.nist)
	}
	return false
}

// signerKeyPoint parses the SignDoc's own signer key for algorithm: its type must be the one a
// chain verifies that algorithm with, and its bytes a COMPRESSED SEC1 point -- 33 bytes, prefix 02
// or 03, on the curve. The Cosmos SDK refuses a 65-byte (uncompressed) public_key at key decode
// (crypto/keys/internal/ecdsa pubkeys require the compressed form), so an uncompressed SignDoc key
// would be spent here and refused by the chain: the account's bug class, not the token's. It is
// therefore refused before the reservation and before any token call (cosmosSignerBound runs
// before policy.Evaluate), on the pinned and the unpinned route alike. The token side is
// unchanged: its SPKI parses either SEC1 form and is compared as a POINT, so a compressed
// SignDoc key still matches the same uncompressed token key.
func signerKeyPoint(algorithm string, key *policy.CosmosPublicKey) (cosmosKey, bool) {
	if key == nil || cosmosKeyTypeURL[algorithm] == "" || key.TypeURL != cosmosKeyTypeURL[algorithm] {
		return cosmosKey{}, false
	}
	if len(key.Key) != 33 || (key.Key[0] != 0x02 && key.Key[0] != 0x03) {
		return cosmosKey{}, false
	}
	switch algorithm {
	case "secp256k1":
		parsed, err := secp256k1.ParsePubKey(key.Key)
		if err != nil {
			return cosmosKey{}, false
		}
		return cosmosKey{k1: parsed}, true
	case "p256":
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key.Key)
		if x == nil {
			return cosmosKey{}, false
		}
		return cosmosKey{nist: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}}, true
	}
	return cosmosKey{}, false
}

// tokenKeyPoint parses the token's "public-key" answer, an SPKI, as a key on algorithm's curve.
func tokenKeyPoint(algorithm string, publicKey []byte) (cosmosKey, bool) {
	switch algorithm {
	case "secp256k1":
		// crypto/x509 does not know this curve, so the SPKI is read here: id-ecPublicKey with the
		// secp256k1 OID as its parameter, and nothing after it.
		var info spki
		rest, err := asn1.Unmarshal(publicKey, &info)
		if err != nil || len(rest) != 0 || !info.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) || info.PublicKey.BitLength%8 != 0 {
			return cosmosKey{}, false
		}
		var curve asn1.ObjectIdentifier
		if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &curve); err != nil || len(rest) != 0 || !curve.Equal(oidCurveSecp256k1) {
			return cosmosKey{}, false
		}
		parsed, err := secp256k1.ParsePubKey(info.PublicKey.Bytes)
		if err != nil {
			return cosmosKey{}, false
		}
		return cosmosKey{k1: parsed}, true
	case "p256":
		parsed, err := x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return cosmosKey{}, false
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return cosmosKey{}, false
		}
		return cosmosKey{nist: key}, true
	}
	return cosmosKey{}, false
}

// cosmosSignerBound says, BEFORE anything is signed or reserved, whether a signature for this
// SignDoc could be checked against a key the token does not choose (regalia-kms-35b AC4): the
// SignDoc's own signer key, which must be a key of this route's curve, or else the binding's
// public_key_sha256 pin. A binding with neither (DevAut-only, signing a SignDoc that leaves
// public_key out) is refused: the only key left is the one the token reports about itself, and a
// token that signs with the wrong key reports that key too.
func cosmosSignerBound(algorithm, pin string, signerKey *policy.CosmosPublicKey) bool {
	if cosmosKeyTypeURL[algorithm] == "" {
		return false
	}
	if signerKey != nil {
		_, ok := signerKeyPoint(algorithm, signerKey)
		return ok
	}
	return pin != ""
}

// verifyCosmosSignature checks a Cosmos signature before the daemon reports it as success
// (regalia-kms-35b).
//
// WHY THE DAEMON CHECKS ITS OWN OUTPUT. A signature that does not verify is not harmless: policy has
// already reserved the account sequence and the daily spend, so a signature nobody can verify costs
// the account a sequence number. Before this check the daemon had no way to notice. The token's
// answer is checked here, in the daemon, before it counts.
//
// WHICH KEY. tokenKey is the token's own answer to "public-key" (application/pkix). It is never
// trusted on its own word, because a token that signs with the wrong key reports that wrong key:
//   - when the binding pins a key (public_key_sha256), tokenKey must hash to the pin, compared in
//     constant time;
//   - when the SignDoc carries the signer's key (SignerInfo.public_key, the key the chain verifies
//     with), tokenKey must be the same POINT -- the SignDoc's key is compressed SEC1 and the
//     token's an uncompressed SPKI, so bytes are not compared;
//   - with neither, nothing independent says which key is right, and the answer is unverified
//     (the coordinator refuses that case before signing; this is the second lock).
//
// The signature is then verified under that key.
//
// THE SIGNATURE IS THE API'S CONTRACT FORM: raw r||s at the width of the curve order (see the
// yubikey sign_contract.go and nitrokey lows.go). r and s must be in [1, N-1], never reduced modulo
// N, and s must be low (s <= N/2) on both curves: the Cosmos SDK's secp256k1 and secp256r1 keys
// accept only that form, so a high-S signature is not verified, the same way a chain would treat
// it. Any other algorithm on the Cosmos content type is refused: a key type this function cannot
// check cannot be reported as checked.
func verifyCosmosSignature(algorithm, pin string, tokenKey []byte, signerKey *policy.CosmosPublicKey, digest, signature []byte) error {
	if pin == "" && signerKey == nil {
		return errCosmosSignatureUnverified
	}
	if pin != "" {
		sum := sha256.Sum256(tokenKey)
		if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
			return errCosmosSignatureUnverified
		}
	}
	key, ok := tokenKeyPoint(algorithm, tokenKey)
	if !ok {
		return errCosmosSignatureUnverified
	}
	if signerKey != nil {
		signer, ok := signerKeyPoint(algorithm, signerKey)
		if !ok || !signer.equal(key) {
			return errCosmosSignatureUnverified
		}
	}
	switch {
	case key.k1 != nil && verifySecp256k1(key.k1, digest, signature):
		return nil
	case key.nist != nil && verifyNISTLowS(key.nist, digest, signature):
		return nil
	}
	return errCosmosSignatureUnverified
}

func verifySecp256k1(key *secp256k1.PublicKey, digest, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	var r, s secp256k1.ModNScalar
	// SetByteSlice reports overflow: an r or s not below N is not a signature, and zero is not one
	// either. Reducing them modulo N would verify bytes a chain refuses.
	if r.SetByteSlice(signature[:32]) || s.SetByteSlice(signature[32:]) || r.IsZero() || s.IsZero() || s.IsOverHalfOrder() {
		return false
	}
	return secp256k1ecdsa.NewSignature(&r, &s).Verify(digest, key)
}

// verifyNISTLowS is crypto/ecdsa.Verify plus the low-S rule the Cosmos SDK's secp256r1 key applies
// (its VerifySignature refuses an s above N/2); ecdsa.Verify alone accepts both twins.
func verifyNISTLowS(key *ecdsa.PublicKey, digest, signature []byte) bool {
	order := key.Curve.Params().N
	width := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*width {
		return false
	}
	r, s := new(big.Int).SetBytes(signature[:width]), new(big.Int).SetBytes(signature[width:])
	if s.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		return false
	}
	return ecdsa.Verify(key, digest, r, s)
}
