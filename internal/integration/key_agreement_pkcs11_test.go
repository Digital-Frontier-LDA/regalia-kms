package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ECDH ON THE CARD, CHECKED AGAINST THE ANSWER COMPUTED HERE.
//
// The concrete driver's Derive was at 0% coverage: every key-agreement test in this repository runs
// against a fake, so nothing exercised CKM_ECDH1_DERIVE on a real module, and the e2e token had no
// key that could — its EC key is secp256k1, which the matrix advertises for sign only.
//
// ECDH is symmetric, so the expected value is computable here without the card's private key: the
// shared secret from (host private, card public) is the same one the card computes from (card
// private, host public). That turns "it returned 32 bytes" into a full round trip — the card
// really did the agreement, and the daemon really applied the HKDF the comment in provider.go
// promises.
func TestKeyAgreementOnAConcretePKCS11Module(t *testing.T) {
	module, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if module == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	driver, err := nitrokey.NewPKCS11Driver(module, devAuthProbe(devAuth), secureChannel{}, retryProbe(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := nitrokey.New(driver, pinSource{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	// id 03 is the p256 key e2e/softhsm-pkcs11.sh provisions with --usage-derive.
	route := registry.Route{
		ObjectID: "agreement-key", Purpose: "agreement", Environment: "production", Algorithm: "p256",
		Binding: registry.Binding{
			Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-ecdh", DeviceSerial: serial,
			DevAuthFingerprint: devAuth, ObjectID: "03", State: "active",
		},
	}

	cardPKIX, _, err := provider.Execute(context.Background(), route, "public-key", "", "", nil, nil)
	if err != nil {
		t.Fatalf("fetching the card public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(cardPKIX)
	if err != nil {
		t.Fatal(err)
	}
	cardECDSA, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("card public key is %T, want *ecdsa.PublicKey", parsed)
	}
	cardPublic, err := cardECDSA.ECDH()
	if err != nil {
		t.Fatal(err)
	}

	agree := func(aad string) (got, want, raw []byte) {
		t.Helper()
		hostPrivate, keyErr := ecdh.P256().GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		hostPKIX, marshalErr := x509.MarshalPKIXPublicKey(hostPrivate.PublicKey())
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		raw, sharedErr := hostPrivate.ECDH(cardPublic)
		if sharedErr != nil {
			t.Fatal(sharedErr)
		}
		want, kdfErr := hkdf.Key(sha256.New, raw, nil, aad, 32)
		if kdfErr != nil {
			t.Fatal(kdfErr)
		}
		got, _, execErr := provider.Execute(context.Background(), route, "key-agreement", "", "",
			hostPKIX, []byte(aad))
		if execErr != nil {
			t.Fatalf("key-agreement against the module: %v", execErr)
		}
		return got, want, raw
	}

	got, want, raw := agree("regalia-agreement-context")
	if !bytes.Equal(got, want) {
		t.Fatalf("derived key does not match the value computed from the other side of the exchange:\n got  %x\n want %x", got, want)
	}
	// Implied by the equality above, but asserted because it is the documented promise and the
	// one an operator would care about: the raw curve coordinate never leaves the daemon.
	if bytes.Equal(got, raw) {
		t.Fatal("the raw ECDH shared secret was returned instead of a derived key")
	}

	// Context binding on a real module. The same card key and a fresh peer under a different
	// context must not produce the same key, or a derived key could be repurposed.
	other, _, _ := agree("a-different-context")
	if bytes.Equal(got, other) {
		t.Fatal("two different contexts produced the same derived key")
	}
}
