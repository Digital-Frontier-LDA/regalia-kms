//go:build piv

package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// regalia#20 ACCEPTANCE CRITERION 4, as a DRILL: rotation, host rebuild, HSM outage, YubiKey
// replacement and total recovery of the UNATTENDED PIN (ADR-0002 D2: a systemd encrypted service
// credential). Driven one phase per step by e2e/yubikey-pin-custody-drill.sh, which does the
// credential and card steps between them (systemd-creds, ykman) and reads the card's PIN counter
// before and after every phase — the counter is the drill's real measurement, and it can only be
// read from outside this process.
//
//	serve   the credential systemd handed this service opens the card: Healthy, then one sign whose
//	        signature verifies under the slot's public key.
//	stale   the credential no longer matches the card (the card's PIN was rotated, the blob was not):
//	        the first operation fails and LATCHES; a second presents no PIN; Healthy stays false.
//	        The script checks the counter fell by exactly one.
//	absent  the token is gone: Healthy is false and the operation fails without a PIN presented.
//
// The PIN is read ONLY through pin.LockedFileSource from $CREDENTIALS_DIRECTORY, the directory
// systemd creates for a service's decrypted credentials. The test refuses to run without it, so a
// plain file on disk cannot stand in for the sealed credential and make the drill look passed.
func TestYubiKeyPINCustodyDrill(t *testing.T) {
	phase, serial, credential := os.Getenv("REGALIA_PINDRILL_PHASE"), os.Getenv("REGALIA_PINDRILL_SERIAL"), os.Getenv("REGALIA_PINDRILL_CREDENTIAL")
	object := os.Getenv("REGALIA_PINDRILL_OBJECT")
	if phase == "" || serial == "" || credential == "" || object == "" {
		t.Skip("driven by e2e/yubikey-pin-custody-drill.sh")
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		t.Fatal("no $CREDENTIALS_DIRECTORY: this phase must run as a systemd service with LoadCredentialEncrypted=, not with a PIN file")
	}
	pins, err := pin.NewLockedFileSource(map[string]string{"drill-yubikey": filepath.Join(directory, credential)})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := yubikey.NewPIVDriver(map[string]string{"drill-yubikey": serial})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := yubikey.New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	route := registry.Route{
		ObjectID: "drill-yubikey-signer", Purpose: "pin-custody-drill", Environment: "staging", Algorithm: "p256",
		Binding: registry.Binding{
			Site: "drill", Backend: "yubikey-piv", DeviceID: "drill-yubikey", DeviceSerial: serial,
			ObjectID: object, PINPolicy: "once", TouchPolicy: "never", State: "active",
		},
	}
	digest := sha256.Sum256([]byte("regalia#20 PIN custody drill " + phase))
	sign := func() ([]byte, error) {
		out, _, err := provider.Execute(ctx, route, "sign", "", "application/octet-stream", digest[:], nil)
		return out, err
	}

	switch phase {
	case "serve":
		if !provider.Healthy(ctx, route.Binding) {
			t.Fatal("the token is not healthy before any PIN is presented: the drill cannot start")
		}
		signature, err := sign()
		if err != nil {
			t.Fatalf("the sealed credential did not open the card: %v", err)
		}
		public, _, err := provider.Execute(ctx, route, "public-key", "", "", nil, nil)
		if err != nil {
			t.Fatalf("read the slot's public key: %v", err)
		}
		key, err := x509.ParsePKIXPublicKey(public)
		ecKey, ok := key.(*ecdsa.PublicKey)
		if err != nil || !ok || !ecdsa.VerifyASN1(ecKey, digest[:], signature) {
			t.Fatal("the signature does not verify under the slot's public key")
		}
		t.Logf("served: %s slot %s signed through the systemd credential %q; signature verifies", serial, object, credential)

	case "stale":
		if !provider.Healthy(ctx, route.Binding) {
			t.Fatal("not healthy BEFORE the stale PIN was presented: the drill would not measure a stale credential")
		}
		if _, err := sign(); err == nil {
			t.Fatal("DEFECT OR NO ROTATION: a credential sealed before the card's PIN changed still opened it")
		}
		// The latch: nothing after the first failure may reach the card with a PIN. The script checks
		// the counter; here, every further path must refuse.
		for i := 0; i < 3; i++ {
			if _, err := sign(); err == nil {
				t.Fatal("DEFECT: an operation succeeded after the device latched")
			}
		}
		if provider.Healthy(ctx, route.Binding) {
			t.Fatal("DEFECT: the latched device reports healthy")
		}
		t.Logf("stale credential: refused, latched, unhealthy; four operations attempted, the script checks one retry was spent")

	case "absent":
		if provider.Healthy(ctx, route.Binding) {
			t.Fatal("DEFECT OR NOT ABSENT: an absent token reports healthy")
		}
		if _, err := sign(); err == nil {
			t.Fatal("DEFECT OR NOT ABSENT: an absent token signed")
		}
		t.Logf("absent token: unhealthy and refused")

	default:
		t.Fatalf("unknown phase %q", phase)
	}
}
