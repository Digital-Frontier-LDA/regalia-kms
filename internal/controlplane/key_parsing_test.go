package controlplane

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// THE TWO PEM PARSERS THAT ADMIT OPERATOR-SUPPLIED KEY FILES, AND THE EIGHT OPERANDS NOTHING
// EXERCISED.
//
// internal/controlplane was the least-examined large package in the module: 109 guards and 135
// leaf operands, of which 82 survived mutation when this file was written (67 on the 2026-09-08
// re-sweep — a count is a measurement with a date, not a property of the package). These eight
// were the highest-value cluster at the time, because
// their inputs are files an operator hands the tool and their failure modes are not "a refusal did
// not happen" — they are three different things:
//
//	:203/:226 op0  block == nil                 -> PANIC. pem.Decode returns nil for anything that
//	                                               is not PEM, and block.Type dereferences it.
//	:211/:234 op0  !ok (type assertion)         -> PANIC. a valid non-ECDSA key (Ed25519, RSA)
//	                                               makes the assertion fail and .Curve dereference nil.
//	:203/:226 op1  block.Type != "…"            -> refused, but by x509's ASN.1 decoder with a
//	                                               structure-error dump instead of "must be a PEM
//	                                               PUBLIC KEY". The operator who passed the wrong
//	                                               file learns nothing from it.
//	:211/:234 op1  Curve != elliptic.P256()     -> ACCEPTED. A P-384 key is taken as a recipient or
//	                                               an authority key. This operand is the only thing
//	                                               that refuses it.
//
// Measured with each operand neutralised in turn, not inferred from the shape of the code.

// wrongShapeKeys returns the material the parsers must refuse. The ACCEPTED anchors come from the
// package's existing testKeys helper rather than being generated again here — a second P-256
// generator would be a second thing to keep in step with what the parsers accept.
func wrongShapeKeys(t *testing.T) (p384 *ecdsa.PrivateKey, edPub ed25519.PublicKey, edPriv ed25519.PrivateKey) {
	t.Helper()
	var err error
	if p384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if edPub, edPriv, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	return
}

func pemBlock(t *testing.T, kind string, der []byte, marshalErr error) []byte {
	t.Helper()
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func TestParseRecipientRefusesEveryKeyThatIsNotAP256PublicKey(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	p384, edPub, _ := wrongShapeKeys(t)
	pkix384, err384 := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	pkixEd, errEd := x509.MarshalPKIXPublicKey(edPub)

	cases := []struct {
		name string
		in   []byte
		want string // "" means accepted
	}{
		// ANCHOR. Without it every refusal below is compatible with "ParseRecipient refuses everything".
		{"a P-256 public key", publicPEM, ""},

		// PANIC GUARD. pem.Decode returns nil for non-PEM input and block.Type dereferences it.
		{"not PEM at all", []byte("-----nope-----\n"), "must be a PEM PUBLIC KEY"},

		// THE OPERATOR HANDED OVER THE WRONG HALF. Refused either way — x509 rejects PKCS#8 bytes as
		// PKIX — but the message is the point: without this operand the operator gets an asn1
		// structure-error dump and no indication they passed a private key.
		{"the authority's PRIVATE KEY", privatePEM, "must be a PEM PUBLIC KEY"},

		// PANIC GUARD. A well-formed PKIX key that is not ECDSA at all.
		{"an Ed25519 public key", pemBlock(t, "PUBLIC KEY", pkixEd, errEd), "must be ECDSA P-256"},

		// THE SECURITY ONE. With the curve operand dead this is ACCEPTED and becomes a recipient.
		{"an ECDSA key on P-384", pemBlock(t, "PUBLIC KEY", pkix384, err384), "must be ECDSA P-256"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// RECOVERED DELIBERATELY. Four of these operands crash rather than refuse when removed,
			// and an unrecovered panic kills the binary and reports nothing about which fixture
			// reached it.
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("ParseRecipient panicked instead of refusing: %v", recovered)
				}
			}()
			recipient, err := ParseRecipient(testCase.in)
			if testCase.want == "" {
				if err != nil || recipient == nil {
					t.Fatalf("the anchor was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted as a recipient: %#v", recipient)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to contain %q — the operator who passed the wrong "+
					"file learns nothing from an ASN.1 structure dump", err, testCase.want)
			}
		})
	}
}

func TestParseAuthorityKeyRefusesEveryKeyThatIsNotAP256PrivateKey(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	p384, _, edPriv := wrongShapeKeys(t)
	pkcs384, err384 := x509.MarshalPKCS8PrivateKey(p384)
	pkcsEd, errEd := x509.MarshalPKCS8PrivateKey(edPriv)

	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"a P-256 private key", privatePEM, ""},
		{"not PEM at all", []byte("-----nope-----\n"), "must be a PEM PRIVATE KEY"},
		// The mirror of the recipient case: handing the tool the PUBLIC half.
		{"a PUBLIC KEY block", publicPEM, "must be a PEM PRIVATE KEY"},
		{"an Ed25519 private key", pemBlock(t, "PRIVATE KEY", pkcsEd, errEd), "must be ECDSA P-256"},
		// THE SECURITY ONE: accepted as the custody authority's key with the curve operand dead.
		{"an ECDSA key on P-384", pemBlock(t, "PRIVATE KEY", pkcs384, err384), "must be ECDSA P-256"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("ParseAuthorityKey panicked instead of refusing: %v", recovered)
				}
			}()
			key, err := ParseAuthorityKey(testCase.in)
			if testCase.want == "" {
				if err != nil || key == nil {
					t.Fatalf("the anchor was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted as the custody authority's key: %#v", key)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to contain %q", err, testCase.want)
			}
		})
	}
}
