//go:build piv

package yubikey

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"
)

// TestPIVPhysicalReadOnlyQualification exercises the real PC/SC boundary without
// consuming a PIN attempt or changing token state. It is opt-in because ordinary
// CI has no card reader. REGALIA_PIV_SERIAL must name a commissioned token whose
// 9A slot is PIN-once/touch-never; REGALIA_PIV_EMPTY_SERIAL may name an attached
// blank token to prove the negative device-selection path.
func TestPIVPhysicalReadOnlyQualification(t *testing.T) {
	serial := os.Getenv("REGALIA_PIV_SERIAL")
	if serial == "" {
		t.Skip("set REGALIA_PIV_SERIAL for the read-only physical PIV qualification")
	}
	emptySerial := os.Getenv("REGALIA_PIV_EMPTY_SERIAL")
	devices := map[string]string{"primary": serial}
	if emptySerial == "" {
		// No negative-token assertion when only one card is attached.
	} else {
		devices["standby"] = emptySerial
	}
	driver, err := NewPIVDriver(devices)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	session, err := driver.Open(ctx, "primary")
	if err != nil {
		t.Fatalf("open commissioned token: %v", err)
	}
	defer session.Close()

	if got, err := session.Identity(ctx); err != nil || got != serial {
		t.Fatalf("identity = %q, %v; want commissioned serial %q", got, err, serial)
	}
	pinPolicy, touchPolicy, err := session.Policies(ctx, "9a")
	if err != nil {
		t.Fatalf("read 9A policy: %v", err)
	}
	if pinPolicy != "once" || touchPolicy != "never" {
		t.Fatalf("9A policy = pin %q, touch %q; want once/never", pinPolicy, touchPolicy)
	}
	retries, err := session.PINRetries(ctx)
	if err != nil || retries < 1 {
		t.Fatalf("PIN retries = %d, %v; want a positive read-only count", retries, err)
	}
	publicKey, err := session.PublicKey(ctx, "9a")
	if err != nil {
		t.Fatalf("read 9A public key: %v", err)
	}
	if key, err := x509.ParsePKIXPublicKey(publicKey); err != nil || key == nil {
		t.Fatalf("9A public key is not parseable PKIX DER: %v", err)
	} else if pin := os.Getenv("REGALIA_PIV_PIN"); pin != "" {
		if err := session.Login(ctx, []byte(pin)); err != nil {
			t.Fatalf("login with supplied staging PIN: %v", err)
		}
		digest := sha256.Sum256([]byte("regalia physical PIV qualification"))
		signature, err := session.Sign(ctx, "9a", "p256", digest[:])
		if err != nil {
			t.Fatalf("sign with 9A: %v", err)
		}
		public, ok := key.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(public, digest[:], signature) {
			t.Fatal("9A signature did not verify against the discovered public key")
		}
	}

	if emptySerial != "" {
		standby, err := driver.Open(ctx, "standby")
		if err != nil {
			t.Fatalf("blank standby device should be discoverable before object admission: %v", err)
		}
		defer standby.Close()
		if _, _, err := standby.Policies(ctx, "9a"); err == nil {
			t.Fatal("blank standby policy lookup succeeded; expected ErrUnavailable")
		}
		if _, err := standby.PublicKey(ctx, "9a"); err == nil {
			t.Fatal("blank standby public-key lookup succeeded; expected ErrUnavailable")
		}
	}
}
