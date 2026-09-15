package nitrokey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

func pkixOf(t *testing.T, public any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// THE PEER KEY IN A KEY AGREEMENT IS ATTACKER-SUPPLIED, AND THIS IS THE ONLY PLACE IT IS CHECKED.
//
// Every derivation runs the token's private scalar against whatever the caller sent. A peer key
// on a different curve, or a point that is not on the curve at all, is the classic invalid-curve
// attack: each derivation leaks information about the scalar, and enough of them recover it.
// There is no second check downstream -- the token will happily multiply by whatever it is given.
//
// This function was at 0%.
func TestPeerKeyIsRefusedUnlessItIsAPointOnTheTokensCurve(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	point, err := ecPointFromPKIX(pkixOf(t, &p256.PublicKey), "p256")
	if err != nil {
		t.Fatalf("a valid p256 peer key was refused: %v", err)
	}
	// Uncompressed SEC 1: 0x04 then two 32-byte coordinates. The token is handed these bytes.
	if len(point) != 65 || point[0] != 4 {
		t.Fatalf("the marshalled point is not an uncompressed p256 point: len=%d first=%#x", len(point), point[0])
	}

	for name, test := range map[string]struct {
		der       []byte
		algorithm string
		wants     string
	}{
		"a p384 key offered for a p256 token": {pkixOf(t, &p384.PublicKey), "p256", "different curve"},
		"a p256 key offered for a p384 token": {pkixOf(t, &p256.PublicKey), "p384", "different curve"},
		"an RSA key":                          {rsaPKIX(t), "p256", "not an EC key"},
		"not DER at all":                      {[]byte("certainly not a public key"), "p256", "malformed"},
		"empty":                               {nil, "p256", "malformed"},
		// secp256k1 is not in crypto/elliptic, so a peer key on it cannot be validated here at
		// all. Refusing is the only safe answer: passing it through unchecked is precisely the
		// invalid-curve exposure, on the curve the wallet signs with.
		"secp256k1, which cannot be validated": {pkixOf(t, &p256.PublicKey), "secp256k1", "different curve"},
		"an algorithm nobody serves":           {pkixOf(t, &p256.PublicKey), "ed25519", "different curve"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ecPointFromPKIX(test.der, test.algorithm)
			if err == nil {
				t.Fatalf("%s was accepted, returning %d bytes", name, len(got))
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Errorf("refused for the wrong reason: got %q, want it to mention %q", err, test.wants)
			}
			if got != nil {
				t.Errorf("a refused peer key still produced %d bytes for the token", len(got))
			}
		})
	}
}

// An off-curve point is refused, and it is worth recording WHERE.
//
// x509.ParsePKIXPublicKey validates the point itself -- a hand-crafted SubjectPublicKeyInfo with
// an off-curve Y is rejected there with "P256 point not on curve", so ecPointFromPKIX returns
// "malformed" and its own IsOnCurve check never runs. Measured, not assumed: the standard
// library also refuses to MARSHAL such a point, so the DER has to be built by hand to test this
// at all.
//
// The explicit check stays, and this test does not pretend to exercise it. What is pinned is the
// property that matters -- an off-curve point never reaches the token -- and which layer
// currently provides it, so nobody removes the belt believing the braces were doing the work.
func TestAnOffCurvePeerKeyNeverReachesTheToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offY := new(big.Int).Add(key.Y, big.NewInt(1))
	if elliptic.P256().IsOnCurve(key.X, offY) {
		t.Fatal("the crafted point is still on the curve: this test would prove nothing")
	}

	point := make([]byte, 1+32+32)
	point[0] = 4
	key.X.FillBytes(point[1:33])
	offY.FillBytes(point[33:])

	var document struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	document.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	document.Algorithm.Parameters = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	document.PublicKey = asn1.BitString{Bytes: point, BitLength: len(point) * 8}
	der, err := asn1.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ecPointFromPKIX(der, "p256")
	if err == nil {
		t.Fatalf("an off-curve peer key was accepted, returning %d bytes for the token", len(got))
	}
	if got != nil {
		t.Fatalf("an off-curve peer key still produced %d bytes", len(got))
	}
	// WHICH layer refused, not merely that one did. Asserting only "some error" would leave the
	// comment above claiming something the test does not check: if x509 ever accepted off-curve
	// points, IsOnCurve would silently become the protection and this would still pass.
	//
	// "malformed" is the parse-layer message; "not a point on the curve" is ecPointFromPKIX's
	// own. If this assertion ever fails with the latter, nothing is broken -- the protection has
	// moved a layer down, the explicit check has stopped being unreachable, and the comment above
	// needs rewriting rather than the code.
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("the off-curve point was refused by a different layer than documented: %v", err)
	}
}

func rsaPKIX(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pkixOf(t, &key.PublicKey)
}

// ABSENT IS NOT ZERO, BECAUSE ZERO IS A REAL KEY TYPE.
//
// attributeUint returns ^uint(0) when the attribute is not present. That sentinel is load-bearing:
// CKK_RSA is 0, so returning 0 for a missing CKA_KEY_TYPE would make an attribute the token never
// sent indistinguishable from one saying "this is an RSA key" -- and PublicKey branches on exactly
// that to decide which attributes to request.
func TestAttributeUintDistinguishesAbsentFromZero(t *testing.T) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		nil, // the driver tolerates a nil entry rather than panicking on it
	}
	if got := attributeUint(attributes, pkcs11.CKA_KEY_TYPE); got != pkcs11.CKK_EC {
		t.Errorf("CKA_KEY_TYPE = %d, want %d", got, pkcs11.CKK_EC)
	}
	if got := attributeUint(attributes, pkcs11.CKA_MODULUS); got != ^uint(0) {
		t.Errorf("an absent attribute returned %d, want the ^uint(0) sentinel", got)
	}
	if attributeUint(attributes, pkcs11.CKA_MODULUS) == pkcs11.CKK_RSA {
		t.Error("an absent attribute reads as CKK_RSA, which is 0: the driver would request RSA attributes for a key the token said nothing about")
	}
	if got := attributeUint(nil, pkcs11.CKA_KEY_TYPE); got != ^uint(0) {
		t.Errorf("an empty attribute list returned %d, want the sentinel", got)
	}
}

// nativeUint reads least-significant byte first, which is what a PKCS#11 token sends on the
// little-endian hosts this daemon is built for. That is a property of this function and of the
// current deployment, not of Go -- a big-endian target would need the token's own byte order
// consulted rather than assumed, and this test would be the thing that noticed.
//
// Reading these bytes the other way round turns CKK_EC (3) into 216172782113783808.
func TestNativeUintReadsAttributeBytesLittleEndian(t *testing.T) {
	for name, test := range map[string]struct {
		bytes []byte
		want  uint
	}{
		"zero":                         {[]byte{0, 0, 0, 0, 0, 0, 0, 0}, 0},
		"CKK_EC as the token sends it": {[]byte{3, 0, 0, 0, 0, 0, 0, 0}, 3},
		"a byte in the second place":   {[]byte{0, 1}, 256},
		"single byte":                  {[]byte{0xff}, 255},
		"empty":                        {nil, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nativeUint(test.bytes); got != test.want {
				t.Fatalf("nativeUint(%v) = %d, want %d", test.bytes, got, test.want)
			}
		})
	}
}
