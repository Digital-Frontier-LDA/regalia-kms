//go:build piv

package yubikey

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// TestPIVPhysicalWrongPINLatchesAfterExactlyOneAttempt is regalia#20 AC3 on a REAL card: one wrong
// PIN costs the card exactly one retry, and the provider then refuses without ever presenting a PIN
// again — so no fault, retry loop or restart storm can walk the counter down to a blocked card.
// The unit tests prove it against a fake session; a fake cannot prove what the card's counter did.
//
// IT SPENDS ONE PIN RETRY, so it is doubly opt-in: REGALIA_PIV_SPEND_ONE_PIN=YES, and
// REGALIA_PIV_PIN must be the card's correct PIN, which is used at the end to restore the counter.
// It refuses to start below three retries, and on the way out verifies the counter is back.
func TestPIVPhysicalWrongPINLatchesAfterExactlyOneAttempt(t *testing.T) {
	serial, pin := os.Getenv("REGALIA_PIV_SERIAL"), os.Getenv("REGALIA_PIV_PIN")
	if os.Getenv("REGALIA_PIV_SPEND_ONE_PIN") != "YES" || serial == "" || pin == "" {
		t.Skip("set REGALIA_PIV_SPEND_ONE_PIN=YES, REGALIA_PIV_SERIAL and REGALIA_PIV_PIN (the correct PIN, to restore the counter)")
	}
	// A wrong PIN of the SAME LENGTH: the card is a length oracle, so a different length could be
	// refused before the counter is consulted and prove nothing about it.
	wrong := []byte(pin)
	for i := range wrong {
		wrong[i] = '0' + (wrong[i]-'0'+1)%10
	}
	if string(wrong) == pin {
		t.Fatal("could not derive a distinct same-length wrong PIN")
	}

	ctx := context.Background()
	driver, err := NewPIVDriver(map[string]string{"primary": serial})
	if err != nil {
		t.Fatal(err)
	}
	// Each read on a FRESH session: after a Login a YubiKey can make the counter unreadable in the
	// same session (see Provider.pinReadings).
	retries := func() int {
		t.Helper()
		session, err := driver.Open(ctx, "primary")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer session.Close()
		n, err := session.PINRetries(ctx)
		if err != nil {
			t.Fatalf("read PIN retries: %v", err)
		}
		return n
	}
	restore := func() {
		t.Helper()
		session, err := driver.Open(ctx, "primary")
		if err != nil {
			t.Fatalf("RESTORE FAILED — could not open the card; its PIN counter is still reduced: %v", err)
		}
		defer session.Close()
		if err := session.Login(ctx, []byte(pin)); err != nil {
			t.Fatalf("RESTORE FAILED — the correct PIN was refused; the counter is still reduced: %v", err)
		}
	}

	before := retries()
	if before < 3 {
		t.Fatalf("refusing to spend a retry with only %d left — restore the counter first", before)
	}
	t.Cleanup(func() {
		restore()
		// AFTER A SUCCESSFUL VERIFY THE CARD STOPS REPORTING THE COUNTER in this process: the retries
		// query answers "already verified" rather than 63Cx (see Provider.pinReadings). Measured on
		// 36345471, 2026-09-23 — the first physical run proved the latch and then failed HERE, with the
		// card at 3/3. A successful VERIFY resets the counter to its maximum (NIST SP 800-73), so the
		// restore above is itself the reset; this confirms it from OUTSIDE the process, with ykman.
		out, err := exec.Command("ykman", "--device", serial, "piv", "info").CombinedOutput()
		if err != nil {
			t.Errorf("could not confirm the restore with ykman (%v); check the counter by hand: ykman --device %s piv info", err, serial)
			return
		}
		want := fmt.Sprintf("PIN tries remaining:      %d/", before)
		if !strings.Contains(string(out), want) {
			t.Errorf("counter after restore is not %d: %s", before, out)
			return
		}
		t.Logf("counter restored to %d (confirmed by ykman)", before)
	})

	provider, err := New(driver, &fakePIN{value: wrong})
	if err != nil {
		t.Fatal(err)
	}
	route := registry.Route{Algorithm: "p256", Binding: registry.Binding{
		Backend: "yubikey-piv", DeviceID: "primary", DeviceSerial: serial, ObjectID: "9a",
		PINPolicy: "once", TouchPolicy: "never",
	}}
	digest := sha256.Sum256([]byte("regalia#20 AC3 latch"))

	if _, _, err := provider.Execute(ctx, route, "sign", "", "application/vnd.regalia.digest", digest[:], nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("first attempt with a wrong PIN: err = %v, want ErrUnavailable", err)
	}
	afterFirst := retries()
	if afterFirst != before-1 {
		t.Fatalf("one wrong PIN moved the card's counter %d -> %d; want exactly one retry spent", before, afterFirst)
	}

	// The latch: four more requests, and the card's counter must not move at all.
	for i := 0; i < 4; i++ {
		if _, _, err := provider.Execute(ctx, route, "sign", "", "application/vnd.regalia.digest", digest[:], nil); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("request %d after the latch: err = %v, want ErrUnavailable", i+2, err)
		}
	}
	if provider.Healthy(ctx, route.Binding) {
		t.Fatal("a latched provider reports Healthy")
	}
	if got := retries(); got != afterFirst {
		t.Fatalf("DEFECT: the latched provider presented the PIN again — counter %d -> %d", afterFirst, got)
	}
	t.Logf("card counter %d -> %d after one wrong PIN, unchanged across 4 further requests; provider unhealthy", before, afterFirst)
}
