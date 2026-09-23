//go:build piv

package yubikey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"strconv"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// TestPIVPhysicalSessionNeitherInheritsNorLeavesPINVerification pins, on a REAL card, the two halves
// of one YubiKey behaviour measured on 5.7.4 (2026-09-23): a PC/SC disconnect leaves the PIV PIN
// verified, and the next connection — from any process — inherits it.
//
//   - LEAVES: after a daemon session that logged in and signed is closed, a raw connection that
//     knows NO PIN must not be able to sign with the PIN-policy-ONCE key. Before the fix it could.
//   - INHERITS: a fresh driver session must read the real retry counter. Before the fix the empty
//     VERIFY answered 9000, PINRetries failed, and a restarted daemon reported a healthy key as
//     unavailable (the dual-YubiKey failover test passed alone and failed when run after another).
//
// It presents only the correct PIN and spends no retries. The object must be a PIN-policy-ONCE,
// touch-NEVER signing key (e.g. 9c provisioned for the dual-YubiKey tests).
func TestPIVPhysicalSessionNeitherInheritsNorLeavesPINVerification(t *testing.T) {
	serial, pin, object := os.Getenv("REGALIA_PIV_SERIAL"), os.Getenv("REGALIA_PIV_PIN"), os.Getenv("REGALIA_PIV_SIGN_OBJECT")
	if serial == "" || pin == "" || object == "" {
		t.Skip("set REGALIA_PIV_SERIAL, REGALIA_PIV_PIN and REGALIA_PIV_SIGN_OBJECT (a PIN-policy-ONCE signing slot, e.g. 9c)")
	}
	ctx := context.Background()
	driver, err := NewPIVDriver(map[string]string{"primary": serial})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("regalia session-state probe"))

	// A daemon session: log in and sign, as the provider does.
	session, err := driver.Open(ctx, "primary")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	before, err := session.PINRetries(ctx)
	if err != nil {
		t.Fatalf("a fresh session cannot read the PIN counter — the card is still carrying another connection's verification: %v", err)
	}
	if err := session.Login(ctx, []byte(pin)); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := session.Sign(ctx, object, "p256", digest[:]); err != nil {
		t.Fatalf("known-good sign failed, so the refusals below would prove nothing: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// LEAVES: another process, with no PIN, connects straight through piv-go.
	cards, err := piv.Cards()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range cards {
		card, err := piv.Open(name)
		if err != nil {
			continue
		}
		if s, err := card.Serial(); err != nil || strconv.FormatUint(uint64(s), 10) != serial {
			_ = card.Close()
			continue
		}
		found = true
		slot, err := parseSlot(object)
		if err != nil {
			t.Fatal(err)
		}
		info, err := card.KeyInfo(slot)
		if err != nil || info.PINPolicy != piv.PINPolicyOnce {
			_ = card.Close()
			t.Fatalf("%s is not a PIN-policy-ONCE key (err=%v): the probe needs one", object, err)
		}
		key, err := card.PrivateKey(slot, info.PublicKey, piv.KeyAuth{PINPolicy: piv.PINPolicyOnce})
		if err == nil {
			if sig, signErr := key.(crypto.Signer).Sign(rand.Reader, digest[:], crypto.SHA256); signErr == nil && len(sig) > 0 {
				_ = card.Close()
				t.Fatal("DEFECT: a connection that never presented the PIN signed with the daemon's key — the closed session left the PIN verified")
			}
		}
		_ = card.Close()
	}
	if !found {
		t.Fatalf("card %s not found for the raw probe", serial)
	}

	// INHERITS: a new driver session reads the real counter, unchanged.
	session, err = driver.Open(ctx, "primary")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer session.Close()
	after, err := session.PINRetries(ctx)
	if err != nil {
		t.Fatalf("DEFECT: a new session cannot read the PIN counter after an earlier session logged in: %v", err)
	}
	if after != before {
		t.Fatalf("PIN retries moved from %d to %d on a correct-PIN run", before, after)
	}
}
