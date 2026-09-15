//go:build piv

package yubikey

import (
	"crypto"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestPIVDriverRequiresPinnedDecimalSerials(t *testing.T) {
	if _, err := NewPIVDriver(nil); err == nil {
		t.Fatal("accepted empty inventory")
	}
	if _, err := NewPIVDriver(map[string]string{"ops": "not-a-serial"}); err == nil {
		t.Fatal("accepted invalid serial")
	}
	driver, err := NewPIVDriver(map[string]string{"ops": "12345678"})
	if err != nil || driver.devices["ops"] != "12345678" {
		t.Fatalf("driver = %#v, %v", driver, err)
	}
}

func TestPIVSlotAndAlgorithmAllowlist(t *testing.T) {
	for _, value := range []string{"9a", "0x9c", "9d", "9e", "82", "95"} {
		if _, err := parseSlot(value); err != nil {
			t.Fatalf("parseSlot(%q): %v", value, err)
		}
	}
	for _, value := range []string{"", "81", "96", "zz"} {
		if _, err := parseSlot(value); err == nil {
			t.Fatalf("parseSlot(%q) accepted", value)
		}
	}
	if !algorithmMatches(piv.AlgorithmEC256, "p256") || !algorithmMatches(piv.AlgorithmEC384, "p384") ||
		!algorithmMatches(piv.AlgorithmRSA2048, "rsa2048") || algorithmMatches(piv.AlgorithmEC256, "ed25519") {
		t.Fatal("PIV algorithm allowlist mismatch")
	}
	if hash, ok := signingHash("p256", 32); !ok || hash != crypto.SHA256 {
		t.Fatal("P-256 hash rejected")
	}
	if _, ok := signingHash("p256", 31); ok {
		t.Fatal("accepted wrong digest size")
	}
}

func TestPIVPolicyNamesRejectPresenceAndPINNever(t *testing.T) {
	if pinPolicyName(piv.PINPolicyOnce) != "once" || pinPolicyName(piv.PINPolicyAlways) != "always" ||
		pinPolicyName(piv.PINPolicyNever) != "unsupported" {
		t.Fatal("PIN policy mapping mismatch")
	}
	if touchPolicyName(piv.TouchPolicyNever) != "never" || touchPolicyName(piv.TouchPolicyAlways) != "unsupported" ||
		touchPolicyName(piv.TouchPolicyCached) != "unsupported" {
		t.Fatal("touch policy mapping mismatch")
	}
}
