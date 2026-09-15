//go:build piv

package integration_test

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
)

// TestTwoPhysicalYubiKeysAreIndependentlyAddressable is a read-only qualification check.
// It never changes PIV state and therefore is safe to run on a staging bench. Set both serials
// explicitly; silently selecting the first enumerated token would make a one-key run look like
// evidence about a two-key fleet.
func TestTwoPhysicalYubiKeysAreIndependentlyAddressable(t *testing.T) {
	serialA, serialB := os.Getenv("REGALIA_YK_SERIAL_A"), os.Getenv("REGALIA_YK_SERIAL_B")
	pinA, pinB := os.Getenv("REGALIA_YK_PIN_A"), os.Getenv("REGALIA_YK_PIN_B")
	if serialA == "" || serialB == "" || pinA == "" || pinB == "" {
		t.Skip("set both serials and separate PINs for physical dual-YubiKey qualification")
	}
	if serialA == serialB {
		t.Fatal("dual-YubiKey qualification requires two distinct serials")
	}
	driver, err := yubikey.NewPIVDriver(map[string]string{"site-a": serialA, "site-b": serialB})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sessions := make([]yubikey.Session, 0, 2)
	for _, id := range []string{"site-a", "site-b"} {
		session, openErr := driver.Open(ctx, id)
		if openErr != nil {
			t.Fatalf("open %s: %v (both commissioned keys must be present)", id, openErr)
		}
		sessions = append(sessions, session)
		t.Cleanup(func() { _ = session.Close() })
	}
	identityA, err := sessions[0].Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	identityB, err := sessions[1].Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if identityA != serialA || identityB != serialB || identityA == identityB {
		t.Fatalf("identity separation failed: A=%q B=%q", identityA, identityB)
	}
	for name, session := range map[string]yubikey.Session{"site-a": sessions[0], "site-b": sessions[1]} {
		retries, retryErr := session.PINRetries(ctx)
		if retryErr != nil || retries < 1 {
			t.Fatalf("%s PIN retries = %d, %v; expected a usable non-presence PIN state", name, retries, retryErr)
		}
		pinPolicy, touchPolicy, policyErr := session.Policies(ctx, "9a")
		if policyErr != nil {
			t.Fatalf("%s slot 9a policy: %v (commissioned key must expose its policy)", name, policyErr)
		}
		if (pinPolicy != "once" && pinPolicy != "always") || touchPolicy != "never" {
			t.Fatalf("%s slot 9a policy = pin=%q touch=%q; want PIN once/always and touch never", name, pinPolicy, touchPolicy)
		}
		pin := pinA
		if name == "site-b" {
			pin = pinB
		}
		if err := session.Login(ctx, []byte(pin)); err != nil {
			t.Fatalf("%s PIN authentication failed: %v", name, err)
		}
		digest := sha256.Sum256([]byte("regalia dual-YubiKey qualification"))
		signature, err := session.Sign(ctx, "9c", "p256", digest[:])
		if err != nil || len(signature) == 0 {
			t.Fatalf("%s independent PIV signing failed: len=%d err=%v", name, len(signature), err)
		}
	}
}
