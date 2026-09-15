package integration_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// clientContentAAD is what a client computes locally to encrypt under, replicating the shape
// SealAssembled uses server-side. The envelope package deliberately does not export it.
func clientContentAAD(objectID string, bindingContext []byte) []byte {
	sum := sha256.Sum256(bindingContext)
	return []byte(fmt.Sprintf("regalia-envelope-v%d\x00%s\x00%s\x00sha256:%s",
		envelope.Version, objectID, "AES-256-GCM", hex.EncodeToString(sum[:])))
}

// SEAL ON A REAL CARD, THEN RELEASE FROM IT.
//
// Every Hardware double in this repository ignores route.Algorithm. That is why release-secret was
// unreachable on real hardware from 2026-08-26 with the whole suite green: the manifest admits
// `opaque` for these objects, the drivers accept only rsa2048/3072/4096, and no double ever looked.
//
// The seal path can fail the same way in the other direction, and worse: a wrap that succeeds
// against a double but produces bytes no card will unwrap is discovered when somebody needs the
// secret, not when they store it. Only a real PKCS#11 module can tell the difference, so this test
// does the whole round trip against one -- wrap the data key on the token, assemble the envelope,
// then release it back through the same token and require the plaintext.
//
// Gated on REGALIA_PKCS11_E2E_MODULE/_SERIAL, set by kms/e2e/softhsm-pkcs11.sh, like the other
// concrete-module tests here.
func TestSealOnConcretePKCS11ThenReleaseFromIt(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	driver, err := nitrokey.NewPKCS11Driver(modulePath, devAuthProbe(devAuth), secureChannel{}, retryProbe(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := nitrokey.New(driver, pinSource{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
	if err != nil {
		t.Fatal(err)
	}

	route := registry.Route{
		ObjectID: "deployment-api-token", Purpose: "deployment-api", Environment: "production",
		Algorithm: "opaque", KEKAlgorithm: "rsa2048", KEKVersion: "1",
		Binding: registry.Binding{
			Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-e2e", DeviceSerial: serial,
			// id 02 is the rsa2048 key kms/e2e/softhsm-pkcs11.sh provisions
			// (--keypairgen --key-type rsa:2048 --id 02). The PIN is that script's too.
			DevAuthFingerprint: devAuth, ObjectID: "02", KEKAlgorithm: "rsa2048", KEKVersion: "1",
			State: "active",
		},
	}
	secret := []byte("a service account token that must survive the round trip")
	bindingContext := envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment)

	// The caller assembles the ciphertext: SealAssembled proves possession of the data key through
	// the AEAD tag rather than taking the plaintext.
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	retained := append([]byte(nil), dataKey...) // SealAssembled zeroes the caller's slice
	block, err := aes.NewCipher(retained)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC()
	kek := envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: route.ObjectID, Version: route.KEKVersion}
	// The client replicates the content AAD without API help, which is deliberate on the seal
	// design's part: the package does not export its shape, so a client that gets it wrong produces
	// a tag SealAssembled cannot open and is refused rather than trusted. This is that replication,
	// done from outside the package exactly as a real client must.
	ciphertext := aead.Seal(nil, nonce, secret, clientContentAAD(route.ObjectID, bindingContext))

	wrapper, err := secrets.NewSealWrapper(manager, route)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.SealAssembled(context.Background(), wrapper, kek, route.ObjectID,
		bindingContext, ciphertext, nonce, dataKey, createdAt)
	if err != nil {
		t.Fatalf("SEAL FAILED ON A REAL MODULE: %v\n"+
			"The wrap produced nothing a card accepted, which no double would have shown.\n"+
			"If the token was provisioned elsewhere, note that this test is coupled to "+
			"kms/e2e/softhsm-pkcs11.sh: object id %q and the PIN it sets. Those are declared in both "+
			"places and only a comment ties them, so a token built differently fails here rather "+
			"than at the card.", err, route.Binding.ObjectID)
	}
	// THE CARD DID THE WRAP, not something in this process. An RSA-2048 OAEP ciphertext is exactly
	// one modulus wide; a passthrough, a stub, or a software fallback would not be. This is the
	// assertion that makes the test about hardware rather than about plumbing.
	if len(sealed.WrappedDataKey) != 256 {
		t.Fatalf("wrapped data key is %d bytes, want 256 (one RSA-2048 modulus): the wrap did not go "+
			"through the card", len(sealed.WrappedDataKey))
	}
	blob, err := sealed.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// THE HALF THAT MATTERS: the same card must unwrap what it just wrapped.
	releaser, err := secrets.NewReleaser(manager)
	if err != nil {
		t.Fatal(err)
	}
	released, contentType, err := releaser.Execute(context.Background(), route,
		"release-secret", "regalia-envelope-v2", "", blob, nil)
	if err != nil {
		t.Fatalf("RELEASE FAILED for an envelope this card sealed minutes ago: %v\n"+
			"The seal and release paths disagree about what the card will accept, which is the defect "+
			"that made release-secret unreachable for weeks with every test green.", err)
	}
	if !bytes.Equal(released, secret) {
		t.Fatalf("released %q, want %q", released, secret)
	}
	if contentType != "application/vnd.regalia.secret" {
		t.Fatalf("content type = %q", contentType)
	}
}
