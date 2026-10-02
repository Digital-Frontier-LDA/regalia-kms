package nitrokey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE ED25519 PATH, ON A REAL PKCS#11 MODULE FOR THE FIRST TIME.
//
// signingMechanism maps "ed25519" to CKM_EDDSA and marshalPublicKey has an Ed25519 branch, and the
// capability matrix advertises ed25519/sign for this backend. Neither HSM on the bench lists an
// EdDSA mechanism through OpenSC (regalia#541), so on hardware that promise is unkept and this code
// had run against nothing. SoftHSM does implement CKM_EDDSA, so the code can at least be held to
// what it claims on a module that offers the mechanism.
//
// What is asserted is the contract an OpenPGP EdDSA signature needs (regalia#530): the token signs
// THE BYTES IT IS GIVEN as the Ed25519 message — no hashing by the driver on the way — and returns
// the 64-byte signature, which the standard library verifies against the public key the driver
// itself reads off the token. Evidence class: emulated. It says nothing about a YubiKey.
func TestEd25519SignsTheBytesItIsGivenAgainstSoftHSM(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	driver, err := NewPKCS11Driver(modulePath, fixedDevAuth(devAuth), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := New(driver, &fakePIN{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	route := registry.Route{Algorithm: "ed25519", Binding: registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "hsm-e2e", DeviceSerial: serial,
		DevAuthFingerprint: devAuth, ObjectID: "0f", State: "active",
	}}

	publicDER, contentType, err := provider.Execute(context.Background(), route, "public-key", "", "", nil, nil)
	if err != nil || contentType != "application/pkix" {
		t.Fatalf("the driver could not read the Ed25519 public key: type=%q err=%v", contentType, err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatalf("the driver's encoding of the Ed25519 public key is not PKIX: %v (%x)", err, publicDER)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the public key parsed as %T, not Ed25519", parsed)
	}

	digest := sha256.Sum256([]byte("an OpenPGP signature digest stands here"))
	long := make([]byte, 64)
	if _, err := rand.Read(long); err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string][]byte{"a 32-byte digest": digest[:], "a 64-byte digest": long} {
		signature, _, err := provider.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.digest", message, nil)
		if err != nil || len(signature) != ed25519.SignatureSize {
			t.Fatalf("%s: signature length=%d err=%v", name, len(signature), err)
		}
		// Pure Ed25519 over exactly the bytes handed in. Had the driver or the module hashed them
		// first, or signed in a prehash mode, this verification would fail.
		if !ed25519.Verify(public, message, signature) {
			t.Fatalf("%s: the signature does not verify as Ed25519 over the bytes that were sent", name)
		}
		// The control: the same signature must not verify over other bytes.
		other := append([]byte{}, message...)
		other[0] ^= 1
		if ed25519.Verify(public, other, signature) {
			t.Fatalf("%s: the signature verified over different bytes", name)
		}
	}
}
