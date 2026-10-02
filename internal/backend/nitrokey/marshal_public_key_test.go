package nitrokey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
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

// marshalPublicKey turns what a card reports about a key into a SubjectPublicKeyInfo, and it is the
// only place the KMS decides what a slot's public half IS. Getting it wrong does not fail loudly:
// a certificate would be issued for the wrong key, or a peer key checked against the wrong curve.
//
// Every case here asserts the ROUND TRIP through crypto/x509 rather than comparing bytes, because
// the property that matters is that a standard parser recovers the key the card described. Byte
// comparison would pass on an encoding only this repository can read.

func attribute(kind uint, value []byte) *pkcs11.Attribute {
	return &pkcs11.Attribute{Type: kind, Value: value}
}

// nativeUintBytes writes a uint the way the driver reads one back, so the fixtures cannot disagree
// with nativeUint about byte order on the machine running the test.
func nativeUintBytes(value uint) []byte {
	out := make([]byte, 8)
	for index := 0; index < 8; index++ {
		out[index] = byte(value >> (8 * index))
	}
	return out
}

func rsaAttributes(t *testing.T, modulus *big.Int, exponent int) []*pkcs11.Attribute {
	t.Helper()
	return []*pkcs11.Attribute{
		attribute(pkcs11.CKA_KEY_TYPE, nativeUintBytes(pkcs11.CKK_RSA)),
		attribute(pkcs11.CKA_MODULUS, modulus.Bytes()),
		attribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(exponent)).Bytes()),
	}
}

func TestAnRSAPublicKeyRoundTripsThroughAStandardParser(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := marshalPublicKey(rsaAttributes(t, key.N, key.E))
	if err != nil {
		t.Fatalf("marshalPublicKey() error = %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatalf("the encoding a card's attributes produced is not a parseable SPKI: %v", err)
	}
	recovered, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("parsed an RSA key as %T", parsed)
	}
	if recovered.N.Cmp(key.N) != 0 || recovered.E != key.E {
		t.Fatalf("round trip changed the key: got E=%d N-bits=%d, want E=%d N-bits=%d",
			recovered.E, recovered.N.BitLen(), key.E, key.N.BitLen())
	}
}

// TestAnUnusableRSAPublicKeyIsRefused. e=1 makes "encryption" the identity function and e=2 is not
// a valid RSA exponent; a zero or negative modulus is not a key at all. These are refused here
// rather than handed to x509, because a card reporting them means something is wrong with the slot
// and the KMS should say so in its own terms.
func TestAnUnusableRSAPublicKeyIsRefused(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, attributes := range map[string][]*pkcs11.Attribute{
		"exponent 1, which encrypts to the plaintext": rsaAttributes(t, key.N, 1),
		"exponent 2, below the smallest valid one":    rsaAttributes(t, key.N, 2),
		"a zero modulus": rsaAttributes(t, big.NewInt(0), key.E),
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := marshalPublicKey(attributes)
			if err == nil {
				t.Fatalf("marshalPublicKey accepted %s and produced %d bytes: the KMS would publish a key that cannot protect anything",
					name, len(encoded))
			}
			if !strings.Contains(err.Error(), "invalid PKCS#11 RSA public key") {
				t.Fatalf("error = %v, want the RSA refusal — a different failure would leave this one unproven", err)
			}
		})
	}
}

func ecAttributes(t *testing.T, curveOID asn1.ObjectIdentifier, point []byte) []*pkcs11.Attribute {
	t.Helper()
	params, err := asn1.Marshal(curveOID)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := asn1.Marshal(point)
	if err != nil {
		t.Fatal(err)
	}
	return []*pkcs11.Attribute{
		attribute(pkcs11.CKA_KEY_TYPE, nativeUintBytes(pkcs11.CKK_EC)),
		attribute(pkcs11.CKA_EC_PARAMS, params),
		attribute(pkcs11.CKA_EC_POINT, wrapped),
	}
}

func TestAnECPublicKeyRoundTripsOnItsOwnCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := elliptic.Marshal(elliptic.P256(), key.X, key.Y) //nolint:staticcheck // the card reports this encoding

	encoded, err := marshalPublicKey(ecAttributes(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, point))
	if err != nil {
		t.Fatalf("marshalPublicKey() error = %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatalf("the EC encoding is not a parseable SPKI: %v", err)
	}
	recovered, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("parsed an EC key as %T", parsed)
	}
	if recovered.Curve != elliptic.P256() {
		t.Fatalf("round trip moved the key to curve %v: a key checked against the wrong curve is not the same key", recovered.Curve.Params().Name)
	}
	if recovered.X.Cmp(key.X) != 0 || recovered.Y.Cmp(key.Y) != 0 {
		t.Fatal("round trip changed the point")
	}
}

// TestAnEd25519KeyIsNotEncodedAsAnECKey.
//
// Ed25519's AlgorithmIdentifier carries NO parameters — RFC 8410 says absent, not the curve OID.
// The EC branch would attach CKA_EC_PARAMS, and the result parses as something other than an
// Ed25519 key, so the KMS would publish a key whose type disagrees with the slot. This is the one
// case in the function with a branch of its own, and it is the one a byte comparison would miss.
func TestAnEd25519KeyIsNotEncodedAsAnECKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := marshalPublicKey(ecAttributes(t, oidEd25519, public))
	if err != nil {
		t.Fatalf("marshalPublicKey() error = %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatalf("the Ed25519 encoding is not a parseable SPKI: %v", err)
	}
	recovered, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("an Ed25519 slot produced a %T: the algorithm identifier is not Ed25519's", parsed)
	}
	if !recovered.Equal(public) {
		t.Fatal("round trip changed the Ed25519 key")
	}
}

// THE OTHER SPELLING OF THE SAME CURVE. PKCS#11 v3.0 lets an Edwards key name its curve by a
// PrintableString ("edwards25519") instead of an OID, and lets the point be the bare 32 bytes or an
// OCTET STRING around them. SoftHSM and pkcs11-tool use the string. The test above feeds the OID
// form only, which is how the driver came to refuse the first real Ed25519 key it met.
func TestAnEd25519KeyNamedByItsCurveNameIsRead(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name, err := asn1.MarshalWithParams("edwards25519", "printable")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := asn1.Marshal([]byte(public))
	if err != nil {
		t.Fatal(err)
	}
	const ckkECEdwards = 0x40
	for form, point := range map[string][]byte{"an OCTET STRING around the key": wrapped, "the bare 32 bytes": public} {
		encoded, err := marshalPublicKey([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, name), pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point),
		})
		if err != nil {
			t.Fatalf("%s: marshalPublicKey() error = %v", form, err)
		}
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		recovered, ok := parsed.(ed25519.PublicKey)
		if err != nil || !ok || !recovered.Equal(public) {
			t.Fatalf("%s: the encoding does not round-trip as this Ed25519 key (%T, %v)", form, parsed, err)
		}
	}

	// Refusals: another curve name, the name with trailing bytes, and a point that is not 32 bytes
	// in either form. Each would otherwise be published under the Ed25519 OID as a key it is not.
	other, _ := asn1.MarshalWithParams("edwards448", "printable")
	short, _ := asn1.Marshal([]byte(public[:31]))
	for what, attributes := range map[string][2][]byte{
		"another curve name":            {other, wrapped},
		"the name with trailing bytes":  {append(append([]byte{}, name...), 0x00), wrapped},
		"a 31-byte key in OCTET STRING": {name, short},
		"a bare 31-byte key":            {name, public[:31]},
		"a 33-byte point":               {name, append([]byte{0x04}, public...)},
		"an empty point":                {name, nil},
	} {
		encoded, err := marshalPublicKey([]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(ckkECEdwards)),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, attributes[0]), pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, attributes[1]),
		})
		// REFUSED, not merely unparseable: bytes that came back at all would be hashed into an
		// identity pin and handed to a verifier, whatever a later parser made of them.
		if err == nil {
			t.Errorf("%s was accepted and encoded as %x", what, encoded)
		}
	}
}

func TestAMalformedECKeyIsRefusedByPart(t *testing.T) {
	valid := ecAttributes(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}, []byte{4, 1, 2, 3})
	emptyPoint, err := asn1.Marshal([]byte{})
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		attributes []*pkcs11.Attribute
		wants      string
	}{
		"parameters that are not an OID": {
			attributes: []*pkcs11.Attribute{valid[0], attribute(pkcs11.CKA_EC_PARAMS, []byte{0xff, 0xff}), valid[2]},
			wants:      "invalid PKCS#11 EC parameters",
		},
		"a point that is not a DER octet string": {
			attributes: []*pkcs11.Attribute{valid[0], valid[1], attribute(pkcs11.CKA_EC_POINT, []byte{0xff, 0xff})},
			wants:      "invalid PKCS#11 EC point",
		},
		// A present-but-empty point is the case that separates "did it decode" from "is there a
		// key here": it decodes fine and describes nothing.
		"a point that decodes to nothing": {
			attributes: []*pkcs11.Attribute{valid[0], valid[1], attribute(pkcs11.CKA_EC_POINT, emptyPoint)},
			wants:      "invalid PKCS#11 EC point",
		},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := marshalPublicKey(test.attributes)
			if err == nil {
				t.Fatalf("marshalPublicKey accepted %s and produced %d bytes", name, len(encoded))
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("error = %v, want %q — the wrong refusal leaves this part unchecked", err, test.wants)
			}
		})
	}
}

// TestANilAttributeDoesNotPanic. The driver builds this slice from what the card returned, and a
// nil entry is skipped rather than dereferenced; a panic here would take the daemon down on a
// malformed card response.
func TestANilAttributeDoesNotPanic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attributes := append([]*pkcs11.Attribute{nil}, rsaAttributes(t, key.N, key.E)...)

	if _, err := marshalPublicKey(attributes); err != nil {
		t.Fatalf("a nil attribute alongside a complete key was not skipped: %v", err)
	}
}
