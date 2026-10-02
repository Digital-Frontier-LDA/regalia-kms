package yubikey

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"math/big"
)

// ONE SIGN CONTRACT FOR EVERY BACKEND (regalia-kms#162).
//
// The API's sign operation means the same thing whichever token serves it, and its callers are
// written to that: certs.CardSigner, regalia-sign and the OpenBao plugin. It is what PKCS#11 does:
//
//   - ECDSA: the payload is the digest; the signature is r||s, each the width of the curve order.
//   - RSA: the payload is the PKCS #1 v1.5 DigestInfo (RFC 8017 §9.2); the token pads and signs
//     exactly that.
//   - Ed25519: the payload is the message; the signature is R||S.
//
// piv-go speaks crypto.Signer instead: it takes a bare digest with a hash for RSA and builds the
// DigestInfo itself, and it returns ECDSA as ASN.1 DER. Passed through unchanged, a PIV key
// answered a sign request in a form no caller could use: a certificate could not be issued from a
// PIV CA key, and regalia-sign refused every ECDSA signature (measured on a YubiKey 5.7.4: DER).
// The functions here bring the request and the answer to the contract. They are not behind the piv
// build tag, so the default build tests them.

// maxEd25519MessageBytes is the longest message an Ed25519 key signs through this API.
const maxEd25519MessageBytes = 1024

// digestInfoPrefixes are the DER encodings of DigestInfo up to the digest (RFC 8017 §9.2, note 1).
var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// signingHash names the hash a payload of this size stands for, or refuses the size.
func signingHash(algorithm string, size int) (crypto.Hash, bool) {
	switch algorithm {
	case "p256":
		return crypto.SHA256, size == crypto.SHA256.Size()
	case "p384":
		return crypto.SHA384, size == crypto.SHA384.Size()
	case "rsa2048":
		// A DigestInfo, never a bare digest: a bare digest would be signed here with a DigestInfo
		// around it and on a PKCS#11 token without one, and the two signatures would differ.
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if size == len(digestInfoPrefixes[hash])+hash.Size() {
				return hash, true
			}
		}
		return 0, false
	case "ed25519":
		// Ed25519 hashes what it is given itself, so there is no hash to name and no digest size
		// to hold it to: the card signs the bytes as the message (pure Ed25519; firmware 5.7 and
		// later). regalia-sign sends a 32-byte digest (regalia#530); OpenBao Transit sends the
		// message itself. The bound is the one the contract already states for Ed25519
		// (OPENBAO-COMPATIBILITY.md), and the card was measured well past it (3000 bytes signed,
		// 4096 refused). The purpose policy's max_payload_bytes is what narrows it per key.
		return crypto.Hash(0), size >= 1 && size <= maxEd25519MessageBytes
	default:
		return 0, false
	}
}

// cardDigest returns what the card library is handed for this payload. For RSA that is the digest
// inside the DigestInfo, once the DigestInfo is shown to be exactly the one for that hash: the
// library rebuilds the same bytes around it, so the signature is over the payload as sent.
func cardDigest(algorithm string, payload []byte, hash crypto.Hash) ([]byte, bool) {
	if algorithm != "rsa2048" {
		return payload, true
	}
	prefix, known := digestInfoPrefixes[hash]
	if !known || len(payload) != len(prefix)+hash.Size() || !bytes.Equal(payload[:len(prefix)], prefix) {
		return nil, false
	}
	return payload[len(prefix):], true
}

// contractSignature returns the card library's answer in the contract's encoding. Only ECDSA
// differs: ASN.1 DER becomes r||s at the width of the curve order.
func contractSignature(algorithm string, value []byte) ([]byte, bool) {
	switch algorithm {
	case "p256":
		return rawECDSA(value, 32)
	case "p384":
		return rawECDSA(value, 48)
	}
	return value, true
}

// rawECDSA re-encodes an ASN.1 DER ECDSA signature as r||s, each left-padded to width bytes. It
// refuses anything that is not exactly one well-formed signature whose values fit the curve: a
// guess here would hand a caller bytes that parse and do not verify.
func rawECDSA(der []byte, width int) ([]byte, bool) {
	var signature struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		return nil, false
	}
	if signature.R.Sign() <= 0 || signature.S.Sign() <= 0 || signature.R.BitLen() > 8*width || signature.S.BitLen() > 8*width {
		return nil, false
	}
	raw := make([]byte, 2*width)
	signature.R.FillBytes(raw[:width])
	signature.S.FillBytes(raw[width:])
	return raw, true
}
