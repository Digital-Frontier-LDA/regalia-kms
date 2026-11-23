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

// verifyCosmosSignature checks a Cosmos signature before the daemon reports it as success
// (regalia-kms-35b).
//
// WHY THE DAEMON CHECKS ITS OWN OUTPUT. A signature that does not verify is not harmless: policy has
// already reserved the account sequence and the daily spend, so a signature nobody can verify costs
// the account a sequence number. Before this check the daemon had no way to notice. The token's
// answer is checked here, in the daemon, before it counts.
//
// The key is the token's public key for the object ("public-key", application/pkix). When the
// binding pins one (public_key_sha256), that SPKI must hash to the pin, compared in constant time,
// so a token that signs with one key and reports another is caught. A binding pinned by DevAut
// alone has no key pin, and the provider has already proved the device's identity before
// answering.
//
// THE SIGNATURE IS THE API'S CONTRACT FORM: raw r||s at the width of the curve order (see the
// yubikey sign_contract.go and nitrokey lows.go). For secp256k1 s must also be low (s <= N/2), the
// only form the Cosmos SDK accepts, so a high-S signature is not verified, the same way a chain
// would treat it. Any other algorithm on the Cosmos content type is refused: a key type this
// function cannot check cannot be reported as checked.
func verifyCosmosSignature(algorithm, pin string, publicKey, digest, signature []byte) error {
	if pin != "" {
		sum := sha256.Sum256(publicKey)
		if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
			return errCosmosSignatureUnverified
		}
	}
	switch algorithm {
	case "secp256k1":
		if verifySecp256k1(publicKey, digest, signature) {
			return nil
		}
	case "p256":
		if verifyNISTCurve(elliptic.P256(), publicKey, digest, signature) {
			return nil
		}
	case "p384":
		if verifyNISTCurve(elliptic.P384(), publicKey, digest, signature) {
			return nil
		}
	}
	return errCosmosSignatureUnverified
}

func verifySecp256k1(publicKey, digest, signature []byte) bool {
	// crypto/x509 does not know this curve, so the SPKI is read here: id-ecPublicKey with the
	// secp256k1 OID as its parameter, and nothing after it.
	var info spki
	rest, err := asn1.Unmarshal(publicKey, &info)
	if err != nil || len(rest) != 0 || !info.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) || info.PublicKey.BitLength%8 != 0 {
		return false
	}
	var curve asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(info.Algorithm.Parameters.FullBytes, &curve); err != nil || len(rest) != 0 || !curve.Equal(oidCurveSecp256k1) {
		return false
	}
	key, err := secp256k1.ParsePubKey(info.PublicKey.Bytes)
	if err != nil || len(signature) != 64 {
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

func verifyNISTCurve(curve elliptic.Curve, publicKey, digest, signature []byte) bool {
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return false
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	width := (curve.Params().BitSize + 7) / 8
	if !ok || key.Curve != curve || len(signature) != 2*width {
		return false
	}
	r, s := new(big.Int).SetBytes(signature[:width]), new(big.Int).SetBytes(signature[width:])
	return ecdsa.Verify(key, digest, r, s)
}
