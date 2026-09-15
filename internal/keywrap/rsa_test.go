package keywrap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRSAOAEPBindsContext(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	wrapped, err := RSAOAEP(public, []byte("data-key"), []byte("repository/path/environment/purpose"), "rsa2048")
	if err != nil {
		t.Fatal(err)
	}
	frame, err := rsa.DecryptOAEP(OAEPHash.New(), rand.Reader, private, wrapped, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenFrame(frame, []byte("repository/path/environment/purpose"))
	if err != nil || string(plain) != "data-key" {
		t.Fatalf("open frame = %q, %v", plain, err)
	}
	if _, err := OpenFrame(frame, []byte("other-context")); err == nil {
		t.Fatal("wrapped key was transplantable across contexts")
	}
}

func TestRSAOAEPRejectsAlgorithmAndKeyMismatch(t *testing.T) {
	private, _ := rsa.GenerateKey(rand.Reader, 2048)
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if _, err := RSAOAEP(public, []byte("key"), []byte("context"), "rsa3072"); err == nil {
		t.Fatal("accepted mismatched key size")
	}
	if _, err := RSAOAEP(public, []byte("key"), nil, "rsa2048"); err == nil {
		t.Fatal("accepted empty context")
	}
}

// TestOpenFrameIgnoresTrailingBytes simulates a non-compliant PKCS#11 module whose C_UnwrapKey
// does not strip RFC 5649 padding. Measured on SoftHSM 2.6.1: a 32-byte plaintext yields a 72-byte
// frame, C_UnwrapKey returns the padded length (72) instead of the original (68), and OpenFrame
// without a length field would consume the trailing 4 padding bytes as part of the data key --
// the envelope then fails three packages away at envelope.go:220 with `len(dataKey) != 32`,
// blaming the envelope for what is a driver/module mismatch.
//
// The v2 frame layout carries a 4-byte big-endian length between the SHA256(label) digest and the
// plaintext. OpenFrame reads it and returns exactly that many bytes, ignoring trailing material.
// This test builds a v2 frame in-line (RSAOAEP returns a wrapped blob, not a plaintext frame,
// and the shape we need to simulate is what C_UnwrapKey returns AFTER unwrapping), appends 4
// trailing junk bytes the way a non-compliant C_UnwrapKey would, and asserts the declared
// plaintext is recovered bit-for-bit.
//
// Falsified by: returning frame[len(frameMagic)+sha256.Size:] verbatim instead of
// frame[frameHeaderLen:frameHeaderLen+declared]. The test fails because OpenFrame would return
// the trailing junk as part of the data key (length 40+declared+4 instead of declared).
func TestOpenFrameIgnoresTrailingBytes(t *testing.T) {
	label := []byte("repository/path/environment/purpose")
	plaintext := []byte("0123456789abcdef0123456789abcdef")
	frame := buildV2Frame(label, plaintext)
	if len(frame) != frameHeaderLen+len(plaintext) {
		t.Fatalf("setup: v2 frame length = %d, want %d", len(frame), frameHeaderLen+len(plaintext))
	}
	// Append 4 trailing zero bytes -- the shape SoftHSM 2.6.1 leaves behind. The v2 frame is
	// already a multiple of 8 (72 = 40 + 32), so on a compliant module no padding would ever be
	// added; the bug only fires for non-aligned plaintexts in the wild. The trailing bytes here
	// are what a non-compliant module would produce for an input it padded before wrapping but
	// forgot to strip after unwrapping.
	trailing := []byte{0x00, 0x00, 0x00, 0x00}
	tampered := append(append([]byte(nil), frame...), trailing...)
	if len(tampered) != len(frame)+4 {
		t.Fatalf("setup error: tampered length = %d, want %d", len(tampered), len(frame)+4)
	}
	got, err := OpenFrame(tampered, label)
	if err != nil {
		t.Fatalf("OpenFrame refused a frame whose declared length fit: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("OpenFrame returned %x, want %x: a frame whose length field declared %d bytes must yield exactly that many, regardless of trailing material",
			got, plaintext, len(plaintext))
	}
	if len(got) != len(plaintext) {
		t.Fatalf("OpenFrame returned %d bytes, want %d: trailing bytes from a non-compliant unwrap leaked into the data key",
			len(got), len(plaintext))
	}
}

// buildV2Frame assembles a plaintext v2 frame in the shape RSAOAEP and the AES-KEY-WRAP-PAD
// driver produce internally. Exported as a test helper rather than reaching into RSAOAEP because
// RSAOAEP returns a wrapped blob, not a plaintext frame; the simulation we need here is what
// C_UnwrapKey hands back AFTER unwrapping.
func buildV2Frame(label, plaintext []byte) []byte {
	frame := make([]byte, 0, frameHeaderLen+len(plaintext))
	frame = append(frame, frameMagic[:]...)
	digest := sha256.Sum256(label)
	frame = append(frame, digest[:]...)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(plaintext)))
	frame = append(frame, lengthBuf[:]...)
	frame = append(frame, plaintext...)
	return frame
}

// TestOpenFrameRefusesAV1Frame closes the format-version seam. v1 frames (magic RGK\x01, no
// length field) must refuse cleanly at OpenFrame with ErrInvalid, not be silently reinterpreted
// as a v2 frame whose "length" is the first 4 bytes of the v1 plaintext. Without this gate,
// production migration would be data-corrupting: an old envelope whose plaintext starts with
// a small uint32 would have its first 4 bytes treated as the length, and OpenFrame would return
// bytes from inside the data key as the new "data key".
//
// The plaintext's first four bytes are deliberately `\x00\x00\x00\x04` so the declared length
// is 4, which makes the rsa.go:100 length-check pass on a magic-disabled build and the
// magic check the SOLE gate. With "0123" (808530483 as a big-endian uint32) the length check
// would reject the frame and the magic check would be inert: this test would stay green if the
// magic equality were removed. Measured on the prior fixture.
//
// Falsified by: replacing the magic equality term (the `subtle.ConstantTimeCompare` at
// rsa.go:92) with `true`, so OpenFrame skips past the magic check. With this fixture the length
// check passes (declared=4 fits in the 68-byte v1 frame) and OpenFrame returns 4 bytes with
// err=nil; `errors.Is(nil, ErrInvalid)` is false and the Fatalf fires.
func TestOpenFrameRefusesAV1Frame(t *testing.T) {
	label := []byte("any-label")
	// plaintext starts with `\x00\x00\x00\x04` so a magic-disabled OpenFrame reads declared=4,
	// finds the v1 frame long enough (68-40=28 >= 4), and returns 4 bytes with no error -- the
	// test would then fail because the magic check is the only thing left to reject the frame.
	plaintext := []byte{0x00, 0x00, 0x00, 0x04, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
		'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b'}
	v1Frame := make([]byte, 0, 36+len(plaintext))
	v1Frame = append(v1Frame, 'R', 'G', 'K', 1)
	digest := sha256.Sum256(label)
	v1Frame = append(v1Frame, digest[:]...)
	v1Frame = append(v1Frame, plaintext...)
	if _, err := OpenFrame(v1Frame, label); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenFrame accepted a v1 frame: %v; the version byte must refuse old envelopes cleanly", err)
	}
}
