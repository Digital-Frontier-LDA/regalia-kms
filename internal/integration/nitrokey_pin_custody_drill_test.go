package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// regalia#20 CRITERION 4 FOR THE NITROKEY: the unattended user PIN (ADR-0002 D2, a systemd encrypted
// service credential; with PKA dropped by D4 this is the production design, not an interim). The
// Nitrokey twin of TestYubiKeyPINCustodyDrill, driven one phase per step by
// e2e/nitrokey-pin-custody-drill.sh, which seals credentials, rotates the card PIN and reads the
// card's retry counter from outside before and after every phase.
//
//	commission  read the drill key's public key WITHOUT logging in and print its pin
//	            (PUBKEY_SHA256=…), as the ceremony commissions a key; needs no credential
//	serve       the credential systemd handed this service opens the card through the PRODUCTION
//	            driver: Healthy, then one P-256 sign that verifies under the pinned public key
//	stale       the credential no longer matches the card: the first operation fails and LATCHES,
//	            later ones present no PIN, Healthy is false. The script checks exactly one retry
//	absent      the card is gone: unhealthy, refused, no PIN presented
//
// Outside commission, the PIN is read ONLY through pin.LockedFileSource from
// $CREDENTIALS_DIRECTORY; the test refuses to run without it, so a plain PIN file cannot stand in
// for the sealed credential.
func TestNitrokeyPINCustodyDrill(t *testing.T) {
	phase, module := os.Getenv("REGALIA_NKDRILL_PHASE"), os.Getenv("REGALIA_NKDRILL_MODULE")
	serial, objectID := os.Getenv("REGALIA_NKDRILL_SERIAL"), os.Getenv("REGALIA_NKDRILL_OBJECT_ID")
	if phase == "" || module == "" || serial == "" || objectID == "" {
		t.Skip("driven by e2e/nitrokey-pin-custody-drill.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	driver, err := nitrokey.NewPKCS11DriverWithProbes(module, secureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	binding := registry.Binding{
		Site: "drill", Backend: "nitrokey-pkcs11", DeviceID: "drill-nitrokey", DeviceSerial: serial,
		ObjectID: objectID, State: "active",
	}

	if phase == "commission" {
		session, err := driver.Open(ctx, binding)
		if err != nil {
			t.Fatalf("open %s: %v", serial, err)
		}
		public, err := session.PublicKey(ctx, objectID)
		_ = session.Close()
		if err != nil || len(public) == 0 {
			t.Fatalf("read the drill key's public key: %v", err)
		}
		sum := sha256.Sum256(public)
		t.Logf("PUBKEY_SHA256=sha256:%s", hex.EncodeToString(sum[:]))
		return
	}

	credential, pinned := os.Getenv("REGALIA_NKDRILL_CREDENTIAL"), os.Getenv("REGALIA_NKDRILL_PUBKEY_SHA256")
	if credential == "" || pinned == "" {
		t.Fatal("serve/stale/absent need REGALIA_NKDRILL_CREDENTIAL and REGALIA_NKDRILL_PUBKEY_SHA256")
	}
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if directory == "" {
		t.Fatal("no $CREDENTIALS_DIRECTORY: this phase must run as a systemd service with LoadCredentialEncrypted=, not with a PIN file")
	}
	pins, err := pin.NewLockedFileSource(map[string]string{"drill-nitrokey": filepath.Join(directory, credential)})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := nitrokey.New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	binding.PublicKeySHA256 = pinned
	route := registry.Route{
		ObjectID: "drill-nitrokey-signer", Purpose: "pin-custody-drill", Environment: "staging", Algorithm: "p256",
		Binding: binding,
	}
	digest := sha256.Sum256([]byte("regalia#20 Nitrokey PIN custody drill " + phase))
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
			t.Fatalf("read the public key: %v", err)
		}
		key, err := x509.ParsePKIXPublicKey(public)
		ecKey, ok := key.(*ecdsa.PublicKey)
		if err != nil || !ok || len(signature) != 64 {
			t.Fatalf("unexpected key or signature shape (err=%v, %d-byte signature)", err, len(signature))
		}
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		if !ecdsa.Verify(ecKey, digest[:], r, s) {
			t.Fatal("the signature does not verify under the card's public key")
		}
		t.Logf("served: %s key %s signed through the systemd credential %q; signature verifies", serial, objectID, credential)

	case "stale":
		if !provider.Healthy(ctx, route.Binding) {
			t.Fatal("not healthy BEFORE the stale PIN was presented: the drill would not measure a stale credential")
		}
		if _, err := sign(); err == nil {
			t.Fatal("DEFECT OR NO ROTATION: a credential sealed before the card's PIN changed still opened it")
		}
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
