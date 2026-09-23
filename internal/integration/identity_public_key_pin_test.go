package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ADR-0002 D1 ON A REAL MODULE, through the PRODUCTION driver constructor (NewPKCS11DriverWithProbes,
// the one cmd/regalia-kms uses) and the real TokenProbes — so "this token exposes no device
// certificate" is the probe's own answer, not a fake's.
//
// Run by e2e/softhsm-pkcs11.sh against SoftHSM, and against a real card with
//
//	REGALIA_D1_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so REGALIA_D1_SERIAL=DENK0404144 \
//	REGALIA_D1_OBJECT_ID=<hex id of a key pair on the card>
//
// It performs only the "public-key" operation, which never logs in: no PIN is read or spent, so it
// is safe to point at a staging card unattended.
func TestTheProductionDriverIdentifiesATokenByItsCommissionedPublicKey(t *testing.T) {
	module, serial, objectID := os.Getenv("REGALIA_D1_MODULE"), os.Getenv("REGALIA_D1_SERIAL"), os.Getenv("REGALIA_D1_OBJECT_ID")
	if module == "" || serial == "" || objectID == "" {
		t.Skip("set REGALIA_D1_MODULE, REGALIA_D1_SERIAL and REGALIA_D1_OBJECT_ID")
	}
	ctx := context.Background()
	driver, err := nitrokey.NewPKCS11DriverWithProbes(module, secureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()

	base := registry.Binding{Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "d1", DeviceSerial: serial, ObjectID: objectID, State: "active"}

	// COMMISSIONING, simulated: read the public key once and pin its hash. (For real, the ceremony
	// does this after hsm-key-attestation-verify.py proves the key was generated on the card.)
	session, err := driver.Open(ctx, base)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	commissioned, err := session.PublicKey(ctx, objectID)
	_ = session.Close()
	if err != nil || len(commissioned) == 0 {
		t.Fatalf("read the public key to commission: %v", err)
	}
	sum := sha256.Sum256(commissioned)
	pinned := base
	pinned.PublicKeySHA256 = "sha256:" + hex.EncodeToString(sum[:])

	// 1. Serial + public-key pin, no DevAut: served.
	provider, _ := nitrokey.New(driver, pinSource{value: []byte("never-read")})
	got, _, err := provider.Execute(ctx, registry.Route{Binding: pinned}, "public-key", "", "", nil, nil)
	if err != nil || !bytes.Equal(got, commissioned) {
		t.Fatalf("DEFECT: a token pinned by serial and commissioned public key was refused (err=%v) — this is how every genuine SmartCard-HSM is bound", err)
	}

	// 2. The same card, a pin for another key: quarantined as public-key-mismatch.
	wrong := pinned
	wrong.PublicKeySHA256 = "sha256:" + hex.EncodeToString(make([]byte, 32))
	other, _ := nitrokey.New(driver, pinSource{value: []byte("never-read")})
	if _, _, err := other.Execute(ctx, registry.Route{Binding: wrong}, "public-key", "", "", nil, nil); !errors.Is(err, nitrokey.ErrUnavailable) {
		t.Fatalf("a wrong public-key pin was served: err=%v", err)
	}
	if reason, _ := other.QuarantineReason("d1"); reason != "public-key-mismatch" {
		t.Fatalf("quarantine reason = %q, want public-key-mismatch", reason)
	}

	// 3. CONTROL — the probe really reports no device certificate: a binding that pins a DevAut is
	// refused as identity-mismatch. Without this, (1) could pass because the probe returned
	// something that happened to be accepted.
	devautPinned := base
	devautPinned.DevAuthFingerprint = "sha256:" + hex.EncodeToString(make([]byte, 32))
	control, _ := nitrokey.New(driver, pinSource{value: []byte("never-read")})
	if _, _, err := control.Execute(ctx, registry.Route{Binding: devautPinned}, "public-key", "", "", nil, nil); err == nil {
		t.Fatal("a DevAut-pinned binding was served by a token whose probe exposes no device certificate")
	}
	if reason, _ := control.QuarantineReason("d1"); reason != "identity-mismatch" {
		t.Fatalf("control reason = %q, want identity-mismatch", reason)
	}
	t.Logf("token %s object %s identified by commissioned public key %s; no device certificate exposed", serial, objectID, pinned.PublicKeySHA256)
}
