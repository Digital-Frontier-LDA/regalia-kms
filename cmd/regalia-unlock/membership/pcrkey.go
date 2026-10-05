package membership

import (
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
)

// The approved-image policy from a PCR-signing public key (#242 B2a), as signkey.py computes it: the
// key's TPM Name, and the PolicyAuthorize digest over that Name with an empty policyRef. The anchor's
// counter and record slots written under a policy carry this digest as their authPolicy, so only a
// session authorized by a signature of that key (a signed PCR policy, an approved image) writes them.
//
// The Name is the TPM's: nameAlg || SHA-256(TPMT_PUBLIC), the public area exactly as the TPM computes it
// for this key loaded by TPM2_LoadExternal: type RSA, nameAlg SHA-256, attributes 0x00060040 (sign,
// decrypt, userWithAuth), an empty authPolicy, no symmetric algorithm, no scheme, 2048 bits, the
// exponent written out (65537; a TPM refuses any other at LoadExternal), and the modulus. Checked
// against a real TPM when the shared vectors are made (tests/vectors/make-pcr-key-policy-v1.py).

const (
	algRSA                = 0x0001
	algSHA256             = 0x000B
	algNull               = 0x0010
	pcrKeyAttributes      = 0x00060040
	ccPolicyAuthorize     = 0x0000016A
	pcrKeyBits            = 2048
	pcrKeyExponent        = 65537
	pcrKeyPEMType         = "PUBLIC KEY"
	maxPCRPublicKeyLength = 16 << 10
)

// PCRKeyPolicy reads a PEM public key (an RSA-2048 SubjectPublicKeyInfo with exponent 65537, as
// systemd-stub's .pcrpkey section holds it) and returns its TPM Name and the PolicyAuthorize digest.
// Anything else is refused.
func PCRKeyPolicy(raw []byte) (name, policy []byte, err error) {
	if len(raw) > maxPCRPublicKeyLength {
		return nil, nil, refuse("the PCR public key is over %d bytes", maxPCRPublicKeyLength)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != pcrKeyPEMType || len(block.Headers) != 0 || len(trimSpace(rest)) != 0 {
		return nil, nil, refuse("the PCR public key is not one PEM %q block", pcrKeyPEMType)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, refuse("the PCR public key is not a public key: %v", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, nil, refuse("the PCR public key is not an RSA key")
	}
	if key.N.BitLen() != pcrKeyBits {
		return nil, nil, refuse("the PCR public key is %d bits, not %d", key.N.BitLen(), pcrKeyBits)
	}
	if key.E != pcrKeyExponent {
		return nil, nil, refuse("the PCR public key's exponent is %d, not %d", key.E, pcrKeyExponent)
	}
	name = tpmName(key.N)
	return name, policyAuthorize(name), nil
}

// tpmName is the Name of the RSA key's public area: nameAlg (SHA-256) || SHA-256(TPMT_PUBLIC).
func tpmName(modulus *big.Int) []byte {
	var public []byte
	u16 := func(v uint16) { public = binary.BigEndian.AppendUint16(public, v) }
	u32 := func(v uint32) { public = binary.BigEndian.AppendUint32(public, v) }
	u16(algRSA)
	u16(algSHA256)
	u32(pcrKeyAttributes)
	u16(0)       // authPolicy: empty
	u16(algNull) // symmetric: none (TPMT_SYM_DEF_OBJECT is its algorithm alone when null)
	u16(algNull) // scheme: none
	u16(pcrKeyBits)
	u32(pcrKeyExponent)
	n := modulus.FillBytes(make([]byte, pcrKeyBits/8))
	u16(uint16(len(n)))
	public = append(public, n...)
	digest := sha256.Sum256(public)
	return append(binary.BigEndian.AppendUint16(nil, algSHA256), digest[:]...)
}

// policyAuthorize is the digest of a trial session that ran only TPM2_PolicyAuthorize for keyName with an
// empty policyRef: H(H(0^32 || TPM_CC_PolicyAuthorize || keyName) || policyRef).
func policyAuthorize(keyName []byte) []byte {
	return PolicyAuthorizeRef(keyName, nil)
}

// PolicyAuthorizeRef is the digest of a trial session that ran only TPM2_PolicyAuthorize for keyName with the
// policyRef `ref`: H(H(0^32 || TPM_CC_PolicyAuthorize || keyName) || ref). The anchor-policy authority's indices
// carry one per class (#361: "anchor" for the counter, "slots" for the record slots, ...).
func PolicyAuthorizeRef(keyName, ref []byte) []byte {
	step := binary.BigEndian.AppendUint32(make([]byte, sha256.Size), ccPolicyAuthorize)
	first := sha256.Sum256(append(step, keyName...))
	second := sha256.Sum256(append(first[:], ref...))
	return second[:]
}

// The anchor-policy authority K_A (#361): a P-256 key the manifest pins (anchor_policy_key, a typed ecdsa-p256 key,
// 130 hex: 04 || X || Y). Its TPM Name is the TPM's for this public area loaded by TPM2_LoadExternal: type ECC,
// nameAlg SHA-256, attributes 0x00060040 (sign, decrypt, userWithAuth), an empty authPolicy, no symmetric algorithm,
// no scheme, curve NIST P-256, no KDF, then X and Y. Held to tests/vectors/anchor-policy-v1.json, measured on swtpm.
const (
	algECC        = 0x0023
	curveNISTP256 = 0x0003
	anchorKeyHex  = 130
)

// AnchorPolicyKeyName is K_A's TPM Name (nameAlg || SHA-256(TPMT_PUBLIC)) from its 130-hex uncompressed point.
// A point that is not on P-256 is refused.
func AnchorPolicyKeyName(keyHex string) ([]byte, error) {
	if err := hexField(keyHex, anchorKeyHex, "anchor_policy_key: an ecdsa-p256 key (04 || X || Y)"); err != nil {
		return nil, err
	}
	raw, _ := hex.DecodeString(keyHex)
	if raw[0] != 0x04 {
		return nil, refuse("anchor_policy_key: an ecdsa-p256 key must be an uncompressed point")
	}
	x, y := new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, refuse("anchor_policy_key: the point is not on P-256")
	}
	public := anchorPolicyPublic(raw[1:33], raw[33:])
	digest := sha256.Sum256(public)
	return append(binary.BigEndian.AppendUint16(nil, algSHA256), digest[:]...), nil
}

// anchorPolicyPublic is K_A's TPMT_PUBLIC (without the TPM2B size), as tpm2_loadexternal builds it.
func anchorPolicyPublic(x, y []byte) []byte {
	var public []byte
	u16 := func(v uint16) { public = binary.BigEndian.AppendUint16(public, v) }
	u16(algECC)
	u16(algSHA256)
	public = binary.BigEndian.AppendUint32(public, pcrKeyAttributes)
	u16(0)       // authPolicy: empty
	u16(algNull) // symmetric: none
	u16(algNull) // scheme: none
	u16(curveNISTP256)
	u16(algNull) // kdf: none
	u16(uint16(len(x)))
	public = append(public, x...)
	u16(uint16(len(y)))
	return append(public, y...)
}

// AnchorPolicy is the authPolicy an index of class `ref` carries when it is defined under K_A (#361):
// PolicyAuthorize(Name(K_A), ref).
func AnchorPolicy(keyHex string, ref string) ([]byte, error) {
	name, err := AnchorPolicyKeyName(keyHex)
	if err != nil {
		return nil, err
	}
	return PolicyAuthorizeRef(name, []byte(ref)), nil
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
