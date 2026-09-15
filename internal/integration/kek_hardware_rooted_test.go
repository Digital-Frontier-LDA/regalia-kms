package integration_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ONLY A KEK THE TOKEN GENERATED, AND WILL NOT HAND BACK, MAY BE USED.
//
// #6: "Production KEKs are non-exportable hardware keys and no software fallback exists." Nothing
// asked the token, and the measurement that started this is reproduced by the fixture below: an
// RSA key generated with openssl on the host and imported with CKA_EXTRACTABLE set wrapped a data
// key in 256 bytes and was indistinguishable, at every layer above the driver, from the key the
// token generated. The daemon called the resulting envelope hardware-rooted.
//
// The unit cases in internal/backend/nitrokey pin the wiring — that a refusal latches the device
// with a distinguishable reason. This one pins the part a fake cannot: that the driver reads
// PKCS#11 attributes which really do separate the two keys on a real module. A fake asserting
// "the fake refused" would prove nothing about CKA_LOCAL.
//
// Object 02 is generated on-token by kms/e2e/softhsm-pkcs11.sh; object 07 is imported by it.
func TestOnlyAHardwareRootedKEKIsUsable(t *testing.T) {
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

	routeTo := func(objectID string) registry.Route {
		return registry.Route{
			ObjectID: "deployment-api-token", Purpose: "deployment-api", Environment: "production",
			Algorithm: "rsa2048", KEKAlgorithm: "rsa2048", KEKVersion: "1",
			Binding: registry.Binding{
				Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-" + objectID,
				DeviceSerial: serial, DevAuthFingerprint: devAuth, ObjectID: objectID,
				KEKAlgorithm: "rsa2048", KEKVersion: "1", State: "active",
			},
		}
	}
	// A provider per case: quarantine is sticky by design, so sharing one would let the first
	// refusal latch the device and make the second case pass without being tested.
	wrapWith := func(objectID string) error {
		provider, providerErr := nitrokey.New(driver, pinSource{value: e2ePKCS11PIN(t)})
		if providerErr != nil {
			t.Fatal(providerErr)
		}
		manager, managerErr := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
		if managerErr != nil {
			t.Fatal(managerErr)
		}
		dataKey := make([]byte, 32)
		for i := range dataKey {
			dataKey[i] = byte(i)
		}
		_, _, execErr := manager.Execute(context.Background(), routeTo(objectID), "wrap",
			"regalia-envelope-v2", "application/vnd.regalia.data-key", dataKey, []byte("aad"))
		return execErr
	}

	// The control. Without it, a refusal below would be equally consistent with wrap being
	// broken for every key on this token.
	if err := wrapWith("02"); err != nil {
		t.Fatalf("the token-generated KEK was refused: %v", err)
	}
	if err := wrapWith("07"); err == nil {
		t.Fatal("wrapped a data key to an imported, extractable KEK: #6's hardware-rooting is not enforced")
	}
}

// THE UNWRAP GUARD READS A DIFFERENT ATTRIBUTE, ON A DIFFERENT OBJECT, BEHIND A LOGIN.
//
// CKA_LOCAL lives on the public key and is readable logged out, which is why wrap can afford it.
// CKA_EXTRACTABLE lives on the private key, which a logged-out PKCS#11 session cannot see at all —
// measured against SoftHSM: `pkcs11-tool --list-objects --type privkey` returns nothing until
// --login. So release asks the question wrap cannot, on the path that has already paid for it.
//
// The assertion is on the quarantine reason rather than on the error, because unwrapping a blob
// under the wrong key fails anyway and both failures surface as the same opaque "unavailable".
// Only the latch says which one happened -- and a decrypt failure latches nothing.
func TestReleaseRefusesAKEKTheTokenWillHandBack(t *testing.T) {
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
	route := registry.Route{
		ObjectID: "deployment-api-token", Purpose: "deployment-api", Environment: "production",
		Algorithm: "rsa2048", KEKAlgorithm: "rsa2048", KEKVersion: "1",
		Binding: registry.Binding{
			Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-unwrap-07",
			DeviceSerial: serial, DevAuthFingerprint: devAuth, ObjectID: "07",
			KEKAlgorithm: "rsa2048", KEKVersion: "1", State: "active",
		},
	}
	_, _, execErr := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2",
		"application/vnd.regalia.data-key", []byte("not a real wrapped key"), []byte("aad"))
	if execErr == nil {
		t.Fatal("released under an extractable KEK")
	}
	reason, latched := provider.QuarantineReason("softhsm-unwrap-07")
	if !latched || reason != "kek-exportable" {
		t.Fatalf("quarantine = %q/%v, want kek-exportable — the refusal came from decryption, not the guard", reason, latched)
	}
}

// THE LOGIN PRECONDITION IS CHECKED, NOT ASSUMED.
//
// AssertKEKNonExportable's own comment says it is asked on a path that has already logged in.
// That was a claim about the caller, and a caller that got the order wrong would have found the
// private object invisible, read the lookup failure as "could not determine", and latched a
// healthy device. Asking the session directly, before any login, is the only way to make the
// precondition a property rather than a sentence — and object 02 is the good key, so a refusal
// here cannot be blamed on the key.
func TestKEKAttributesRequireALoggedInSession(t *testing.T) {
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
	session, err := driver.Open(context.Background(), registry.Binding{
		Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-precondition",
		DeviceSerial: serial, DevAuthFingerprint: devAuth, ObjectID: "02",
		KEKAlgorithm: "rsa2048", KEKVersion: "1", State: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	// The logged-out control: CKA_LOCAL lives on the public key, which is readable without a
	// login. If this refused too, the case below would prove only that the session was unusable.
	if err := session.AssertKEKGeneratedOnToken(context.Background(), "02"); err != nil {
		t.Fatalf("CKA_LOCAL was unreadable on a logged-out session: %v", err)
	}
	// Asserting the SPECIFIC error, because without the precondition the lookup fails anyway --
	// the private object is invisible -- and a test that only required "some error" would pass
	// with the precondition deleted. It would then be pinning PKCS#11's behaviour rather than
	// ours, and would go quiet the day a module made private objects visible.
	err = session.AssertKEKNonExportable(context.Background(), "02")
	if !errors.Is(err, nitrokey.ErrKEKLoginRequired) {
		t.Fatalf("logged-out attribute read returned %v, want ErrKEKLoginRequired", err)
	}
	if errors.Is(err, nitrokey.ErrKEKExportable) {
		t.Fatal("a logged-out lookup was reported as a verdict that the key is exportable")
	}
}

// A SYMMETRIC KEK IS ONE OBJECT, NOT A PAIR, AND THE GUARDS WERE BLIND TO IT.
//
// AssertKEKGeneratedOnToken asked for CKO_PUBLIC_KEY and AssertKEKNonExportable for
// CKO_PRIVATE_KEY. An AES KEK is a single CKO_SECRET_KEY and has neither, so both returned
// "PKCS#11 object lookup failed" and the provider quarantined the device as
// kek-provenance-unreadable — fail-closed, but blaming provenance for a guard looking in the wrong
// drawer. That would have surfaced inside whoever lands #75's CKM_AES_KEY_WRAP_PAD branch, as a
// bug in their driver rather than in this file.
//
// The facts the guards rely on, from `pkcs11-tool --keygen --key-type AES:32` on this fixture, so
// a later editor removing the dispatch can see what it was reading:
//
//	Access: sensitive, always sensitive, never extractable, local   (id 09, --keygen --sensitive)
//	Access: never extractable, local                                (id 0a, --keygen alone)
//
// THOSE TWO ARE THE WHOLE ARGUMENT FOR CHECKING BOTH ATTRIBUTES. SoftHSM's default AES key reports
// "never extractable" and still returns its plaintext through C_GetAttributeValue -- 97 bytes of
// key material -- while the --sensitive one answers CKR_ATTRIBUTE_SENSITIVE. "Cannot be wrapped
// out" is not "cannot be read", and a guard checking only CKA_EXTRACTABLE would accept a KEK whose
// value the token hands to anyone who asks. The imported RSA key at 07 proves the converse: it IS
// sensitive and still extractable, so checking only CKA_SENSITIVE would accept that one.
//
//	Usage:  encrypt, decrypt, sign, verify, wrap, unwrap
//	class:  CKO_SECRET_KEY — visible without login on SoftHSM, unlike a private key
//
// Object 09 is that key; 02 is the token-generated RSA pair and 07 the imported extractable one.
func TestTheKEKGuardsSeeASymmetricKey(t *testing.T) {
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
	// ONE session, because PKCS#11 login state belongs to the token and not to the session: a
	// second Login against the same token comes back CKR_USER_ALREADY_LOGGED_IN, which the driver
	// reports as "login unavailable" and which reads like a broken guard rather than a test that
	// opened one handle too many.
	session, err := driver.Open(context.Background(), registry.Binding{
		Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "softhsm-sym", DeviceSerial: serial,
		DevAuthFingerprint: devAuth, ObjectID: "09", State: "active"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	// Logged out: CKA_LOCAL is readable on a secret key, as it is on a public key.
	if err := session.AssertKEKGeneratedOnToken(context.Background(), "09"); err != nil {
		t.Fatalf("a token-generated AES KEK was refused as not-token-generated: %v", err)
	}
	if err := session.AssertKEKGeneratedOnToken(context.Background(), "07"); err == nil {
		t.Fatal("the imported key passed the provenance guard after the class dispatch was added")
	}

	if err := session.Login(context.Background(), e2ePKCS11PIN(t)); err != nil {
		t.Fatal(err)
	}
	if err := session.AssertKEKNonExportable(context.Background(), "09"); err != nil {
		t.Fatalf("a sensitive, never-extractable AES KEK was refused as exportable: %v", err)
	}
	// Object 0a is generated without --sensitive: "never extractable", and its plaintext still
	// comes back from C_GetAttributeValue. This is the case that fails if the guard drops
	// CKA_SENSITIVE.
	if err := session.AssertKEKNonExportable(context.Background(), "0a"); err == nil {
		t.Fatal("an AES KEK whose plaintext value the token returns was accepted as non-exportable")
	}
	// And the imported RSA key must still be refused, so widening the lookup accepted nothing new.
	if err := session.AssertKEKNonExportable(context.Background(), "07"); err == nil {
		t.Fatal("the extractable key passed the exportability guard after the class dispatch was added")
	}
}
