package nitrokey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/miekg/pkcs11"
)

// keywrapOpen reverses what wrapRSA produced, which takes TWO steps and not one.
//
// RSAOAEP does not use the AAD as the OAEP label -- it encrypts with a nil label and puts
// SHA256(aad) inside the frame it encrypts. So opening is DecryptOAEP with a nil label to recover
// the frame, then OpenFrame to verify the context digest and strip the header. Getting this wrong
// in the test would have produced a passing round trip that proved something weaker than it claimed.
func keywrapOpen(private *rsa.PrivateKey, wrapped, aad []byte) ([]byte, error) {
	frame, err := rsa.DecryptOAEP(keywrap.OAEPHash.New(), rand.Reader, private, wrapped, nil)
	if err != nil {
		return nil, err
	}
	return keywrap.OpenFrame(frame, aad)
}

// NOTHING IN THIS REPOSITORY WRAPPED WITH RSA.
//
// wrapRSA has four guards and every one of them survived a sweep in BOTH directions, in both the
// unit suite and the SoftHSM battery. Read per-operand that is four gaps; it is one. Established by
// grep rather than inferred: the only RSA Wrap calls anywhere were refusal rows, which refuse before
// reaching this function, and the e2e wraps with aes-256 while only UNWRAPPING with rsa2048.
//
// So the function was undriven, and a widening mutation on any of its guards — making it always
// refuse — changed nothing any test could see. That is the shape worth naming: when every operand of
// a function survives in both directions, the finding is the function, not the operands.
//
// This drives it for real. The token reports a genuine RSA public key, PublicKey marshals it to
// PKIX, and keywrap.RSAOAEP performs an actual OAEP encryption against it — so the assertion is that
// the wrapped output decrypts back to the plaintext under the matching private key, which is the
// only check that distinguishes a real wrap from a function returning plausible bytes.

// rsaToken answers the object lookup and the two attribute reads PublicKey makes for an RSA key.
//
// The embedded nil cryptoki is the package convention: anything not stubbed panics rather than
// returning a usable zero value, so a code path that starts asking for something new fails loudly
// here rather than passing against an invented answer.
type rsaToken struct {
	cryptoki
	public *rsa.PublicKey
}

func (*rsaToken) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error { return nil }

func (*rsaToken) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{1}, false, nil
}

func (*rsaToken) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (token *rsaToken) GetAttributeValue(_ pkcs11.SessionHandle, _ pkcs11.ObjectHandle,
	requested []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	for _, attribute := range requested {
		if attribute.Type == pkcs11.CKA_KEY_TYPE {
			return []*pkcs11.Attribute{
				pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, uint(pkcs11.CKK_RSA)),
			}, nil
		}
	}
	return []*pkcs11.Attribute{
		{Type: pkcs11.CKA_MODULUS, Value: token.public.N.Bytes()},
		{Type: pkcs11.CKA_PUBLIC_EXPONENT, Value: big.NewInt(int64(token.public.E)).Bytes()},
	}, nil
}

// TestWrapRSAProducesCiphertextTheMatchingPrivateKeyOpens drives the whole wrapRSA path.
//
// Isolation is not the point here — every guard on the path is exercised at once, deliberately,
// because the finding is that the path itself was never taken. What the assertion pins is that the
// output is a REAL wrap: it decrypts back to the plaintext under the private half, and only under
// the same binding context. Asserting "no error and some bytes" would pass against a function that
// returned the plaintext, or a constant, or the modulus.
//
// The AAD is NOT the OAEP label. RSAOAEP encrypts with a nil label and folds SHA256(aad) into the
// frame it encrypts, so the binding is verified by OpenFrame after decryption rather than by the
// padding check. The two are not interchangeable: an OAEP label is authenticated by OAEP itself,
// while a digest inside the plaintext is authenticated by whatever parses the frame.
func TestWrapRSAProducesCiphertextTheMatchingPrivateKeyOpens(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := &rsaToken{public: &private.PublicKey}
	session := &pkcs11Session{module: token, loggedIn: true}

	plaintext := []byte("a data key that must survive the round trip")
	aad := []byte("regalia-envelope-v2|opaque-token|production")

	// The token must hand back the key we generated, or the round trip below would be testing
	// whatever else marshalPublicKey happened to produce.
	marshalled, err := session.PublicKey(context.Background(), "01")
	if err != nil {
		t.Fatalf("control is broken: PublicKey failed before any wrap was attempted: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(marshalled)
	if err != nil {
		t.Fatalf("control is broken: PublicKey produced something that is not a PKIX key: %v", err)
	}
	if got, ok := parsed.(*rsa.PublicKey); !ok || got.N.Cmp(private.N) != 0 || got.E != private.E {
		t.Fatalf("control is broken: PublicKey returned %T %v, not the RSA key the token holds", parsed, parsed)
	}

	wrapped, err := session.wrapRSA(context.Background(), "01", "rsa2048", plaintext, aad)
	if err != nil {
		t.Fatalf("DEFECT: wrapping with rsa2048 failed: %v. Nothing in this repository wrapped with "+
			"RSA before this test, so a break on this path would have gone unnoticed", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("DEFECT: wrapRSA returned no ciphertext and no error")
	}

	// THE ONLY ASSERTION THAT DISTINGUISHES A WRAP FROM PLAUSIBLE BYTES.
	opened, err := keywrapOpen(private, wrapped, aad)
	if err != nil {
		t.Fatalf("DEFECT: the wrapped output does not decrypt under the matching private key: %v. "+
			"That is what makes this a wrap rather than a function returning bytes of the right "+
			"shape", err)
	}
	if string(opened) != string(plaintext) {
		t.Fatalf("DEFECT: the round trip returned %q, want %q", opened, plaintext)
	}

	// The AAD binds the ciphertext to its context, and opening under a different one must fail.
	// Not because it is the OAEP label -- it is not, RSAOAEP encrypts with a nil label -- but
	// because SHA256(aad) is carried inside the frame and OpenFrame compares it.
	if _, err := keywrapOpen(private, wrapped, []byte("a different binding context")); err == nil {
		t.Fatal("DEFECT: the ciphertext opened under a different binding context, so the AAD is " +
			"not binding the wrap to anything")
	}
}

// TestWrapRSARefusesWithoutABindingContext pins the AAD guard on the same path.
//
// It is the one guard here that a caller can trip with well-formed inputs, and it sits before the
// public key is read — so the refusal must happen without the token being asked for anything.
func TestWrapRSARefusesWithoutABindingContext(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	session := &pkcs11Session{module: &rsaToken{public: &private.PublicKey}, loggedIn: true}

	// THE MESSAGE, NOT MERELY THE REFUSAL. This guard is masked: delete it and the wrap proceeds to
	// keywrap.RSAOAEP, which has its own `len(label) == 0` check and refuses too — so "an error came
	// back" is true either way. Measured: with the guard the message names the OAEP label; without
	// it the refusal is the generic "PKCS#11 wrap unavailable" from the RSAOAEP error branch.
	//
	// The distinction is operational, not cosmetic. One message tells an operator the request was
	// built without a binding context; the other says the token would not wrap, which is a different
	// investigation entirely.
	const want = "PKCS#11 wrap unavailable: RSA-OAEP requires a non-empty AAD as the OAEP label"
	for _, aad := range [][]byte{nil, {}} {
		_, err := session.wrapRSA(context.Background(), "01", "rsa2048", []byte("plaintext"), aad)
		if err == nil {
			t.Fatalf("DEFECT: an RSA wrap with aad=%v was accepted; SHA256(aad) is what binds the "+
				"frame to its context, so without it the ciphertext is bound to nothing", aad)
		}
		if err.Error() != want {
			t.Fatalf("DEFECT: aad=%v was refused as %q, want %q. The guard did not fire — "+
				"keywrap.RSAOAEP refused instead, which reports a token problem for what is "+
				"actually a malformed request", aad, err.Error(), want)
		}
	}
}
