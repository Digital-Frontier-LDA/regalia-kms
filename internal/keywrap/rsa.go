// Package keywrap implements public-key wrapping operations that run inside
// the KMS while leaving private-key unwrapping to hardware providers.
package keywrap

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // #nosec G505 -- registers the OAEP primitive named by OAEPHash; see the comment there.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"errors"
)

// OAEPHash is the ONE place the envelope's OAEP hash is chosen.
//
// It used to be chosen independently in three files: here, the PKCS#11 driver's OAEP mechanism
// parameters, and the PIV driver's decrypt options. Nothing connected them, so changing one would
// have produced envelopes the card could not open — and that failure surfaces when a secret is
// released, not when the code is built. Now the drivers derive their parameters from this constant
// and fail loudly if they cannot express it.
//
// SHA-1 is the interoperable OAEP primitive across the SmartCard-HSM middleware and PIV. Scanners
// flag it on sight; it is not a weakness here. OAEP's security does not rest on collision
// resistance, and the frame inside the envelope is bound to its context with SHA-256 regardless, so
// an OAEP collision would buy an attacker nothing. Moving to SHA-256 is a one-line change here plus
// a hardware interop run — which is why it is one line.
const OAEPHash = crypto.SHA1

var ErrInvalid = errors.New("key wrapping failed")

// frameMagic is a 4-byte prefix that names the frame format. Bumping the last byte from 1 to 2
// is what makes a v1 frame (header 36 bytes, no length field) refuse cleanly at OpenFrame instead
// of being misinterpreted as a v2 frame whose "length" is the first 4 bytes of the old plaintext.
// Old envelopes written before #206 must be re-wrapped; there is no production envelope inventory
// because the daemon does not store envelopes, so an in-place migration has nothing to migrate.
var frameMagic = [4]byte{'R', 'G', 'K', 2}

// frameHeaderLen is the size of the fixed prefix: magic(4) || SHA256(label)(32) || length(4 BE).
// The plaintext that follows is N bytes, where N is the big-endian uint32 at bytes 36..40.
const frameHeaderLen = len(frameMagic) + sha256.Size + 4

func RSAOAEP(publicDER, plaintext, label []byte, algorithm string) ([]byte, error) {
	if algorithm != "rsa2048" && algorithm != "rsa3072" && algorithm != "rsa4096" {
		return nil, ErrInvalid
	}
	public, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return nil, ErrInvalid
	}
	key, ok := public.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != expectedBits(algorithm) || len(plaintext) == 0 || len(label) == 0 {
		return nil, ErrInvalid
	}
	frame := make([]byte, 0, frameHeaderLen+len(plaintext))
	frame = append(frame, frameMagic[:]...)
	digest := sha256.Sum256(label)
	frame = append(frame, digest[:]...)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(plaintext)))
	frame = append(frame, lengthBuf[:]...)
	frame = append(frame, plaintext...)
	defer zero(frame)
	wrapped, err := rsa.EncryptOAEP(OAEPHash.New(), rand.Reader, key, frame, nil)
	if err != nil {
		return nil, ErrInvalid
	}
	return wrapped, nil
}

// OpenFrame verifies that an unwrapped hardware plaintext belongs to the request context before
// returning its data key.
//
// THE LENGTH FIELD IS THE SOURCE OF TRUTH. The frame layout carries a 4-byte big-endian length
// between the SHA256(label) digest and the plaintext. OpenFrame reads it and returns exactly that
// many bytes, ignoring any trailing material the underlying primitive appended. This makes the
// frame self-delimiting against a module whose C_UnwrapKey does not strip RFC 5649 padding
// (measured on SoftHSM 2.6.1, which returns the padded length instead of the original; without
// the length field, OpenFrame would treat the padding bytes as part of the data key and the
// envelope would later fail at envelope.go:220 with len(dataKey) != 32 -- a misleading refusal
// that blamed the envelope for a driver/module mismatch). On a compliant module the trailing
// bytes are absent and the length field describes exactly what the module returned; on a
// non-compliant module they are present and ignored.
//
// Falsified by: returning frame[len(frameMagic)+sha256.Size:] verbatim instead of
// frame[frameHeaderLen:frameHeaderLen+L]. The test TestOpenFrameIgnoresTrailingBytes simulates a
// non-compliant module by appending junk to a v2 frame and asserts OpenFrame still returns the
// declared plaintext.
func OpenFrame(frame, label []byte) ([]byte, error) {
	if len(frame) < frameHeaderLen || len(label) == 0 || subtle.ConstantTimeCompare(frame[:len(frameMagic)], frameMagic[:]) != 1 {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(label)
	if subtle.ConstantTimeCompare(frame[len(frameMagic):len(frameMagic)+sha256.Size], digest[:]) != 1 {
		return nil, ErrInvalid
	}
	declared := binary.BigEndian.Uint32(frame[len(frameMagic)+sha256.Size : frameHeaderLen])
	if uint32(len(frame)-frameHeaderLen) < declared {
		return nil, ErrInvalid
	}
	return append([]byte(nil), frame[frameHeaderLen:frameHeaderLen+int(declared)]...), nil
}

func expectedBits(algorithm string) int {
	switch algorithm {
	case "rsa2048":
		return 2048
	case "rsa3072":
		return 3072
	case "rsa4096":
		return 4096
	default:
		return 0
	}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
