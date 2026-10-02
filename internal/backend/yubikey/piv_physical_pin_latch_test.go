//go:build piv

package yubikey

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// endingCardDriver is the real PIV driver; its sessions are the real ones, except that the request
// can be ended the moment the retry counter has been read: the last card call before the login.
type endingCardDriver struct {
	*PIVDriver
	end func()
	// reads counts the counter reads made on a session of a request that was being ended.
	reads int
}

type endingCardSession struct {
	Session
	driver *endingCardDriver
}

func (driver *endingCardDriver) Open(ctx context.Context, deviceID string) (Session, error) {
	session, err := driver.PIVDriver.Open(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return &endingCardSession{Session: session, driver: driver}, nil
}

func (session *endingCardSession) PINRetries(ctx context.Context) (int, error) {
	retries, err := session.Session.PINRetries(ctx)
	if session.driver.end != nil {
		if err == nil {
			session.driver.reads++
		}
		session.driver.end()
	}
	return retries, err
}

// ON A REAL YUBIKEY, A REQUEST THAT ENDS BEFORE THE PIN IS PRESENTED LATCHES NOTHING
// (regalia-kms#178, PIV side).
//
// The real driver and session, with the request ended right after the retry counter was read. The
// PIN is presented only by the two requests that are meant to sign; the card's own counter must
// read the same before and after.
//
//	REGALIA_PIV_LATCH_SERIAL  the card
//	REGALIA_PIV_LATCH_SLOT    a slot holding an Ed25519 key, PIN policy once, touch never
//	REGALIA_PIV_LATCH_PIN     the PIV PIN
//
// REGALIA_PIV_LATCH_BEFORE_FIX=1 turns the expectation round, for reproducing the defect on a
// commit before the fix: there the card must come out latched although no PIN was presented.
//
// MEASURED ON YubiKey 5 NFC 35718625 (firmware 5.7.4), 2026-10-02 16:31, a quiet bench:
//
//	e73c198 (before the fix)  PIN latch set=true after the ended request; the card's own counter
//	                          3/3 before and after: latched with no PIN presented
//	with the fix              PIN latch set=false; the next request signs; counter still 3/3
//
// Each fails the other's expectation.
func TestPIVPhysicalARequestThatEndsBeforeThePINIsPresentedLatchesNothing(t *testing.T) {
	serial, slot, pin := os.Getenv("REGALIA_PIV_LATCH_SERIAL"), os.Getenv("REGALIA_PIV_LATCH_SLOT"), os.Getenv("REGALIA_PIV_LATCH_PIN")
	if serial == "" || slot == "" {
		t.Skip("set REGALIA_PIV_LATCH_SERIAL, REGALIA_PIV_LATCH_SLOT and REGALIA_PIV_LATCH_PIN")
	}
	if pin == "" {
		t.Fatal("REGALIA_PIV_LATCH_SERIAL is set but REGALIA_PIV_LATCH_PIN is not: the test cannot run")
	}
	beforeFix := os.Getenv("REGALIA_PIV_LATCH_BEFORE_FIX") == "1"
	real, err := NewPIVDriver(map[string]string{"primary": serial})
	if err != nil {
		t.Fatal(err)
	}
	driver := &endingCardDriver{PIVDriver: real}
	pins := &fakePIN{value: []byte(pin)}
	provider, err := New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	live := context.Background()
	route := registry.Route{Algorithm: "ed25519", Binding: registry.Binding{
		Backend: "yubikey-piv", DeviceID: "primary", DeviceSerial: serial, ObjectID: slot, State: "active", PINPolicy: "once", TouchPolicy: "never",
	}}
	message := []byte("regalia-kms#178: a request that ends is not a refused PIN")
	sign := func(ctx context.Context) ([]byte, error) {
		signature, _, err := provider.Execute(ctx, route, "sign", "", "application/octet-stream", append([]byte{}, message...), nil)
		return signature, err
	}
	publicDER, _, err := provider.Execute(live, route, "public-key", "", "", nil, nil)
	if err != nil {
		t.Fatalf("read the public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		t.Fatalf("slot %s does not hold an Ed25519 key: %T, %v", slot, parsed, err)
	}

	// 0. The card signs, and its counter is read.
	signature, err := sign(live)
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatalf("setup: the card does not sign: %v", err)
	}
	before := provider.PINRetriesReadings()["primary"].Retries
	t.Logf("the card signs; PIN retries %d", before)

	// 1. A request that ends after the counter was read and before the login.
	ended, end := context.WithCancel(context.Background())
	driver.end = end
	if _, err := sign(ended); err == nil {
		t.Fatal("a request that had ended was served")
	}
	driver.end = nil
	end()
	if driver.reads != 1 {
		t.Fatalf("the ended request did not read the counter exactly once (%d reads): it never reached the login, and the case tests nothing", driver.reads)
	}
	latched := provider.pinBlocked("primary")
	t.Logf("after a request that ended between the counter read and the login: PIN latch set=%v", latched)
	if beforeFix {
		if !latched {
			t.Fatal("expected the defect (the card latched although no PIN was presented), and the card is not latched")
		}
		if _, err := sign(live); err == nil {
			t.Fatal("a latched card signed")
		}
		t.Log("DEFECT REPRODUCED: no PIN was presented, and the card is out of service until an operator resets it")
		return
	}
	if latched {
		t.Fatal("a request that ended before the PIN was presented latched the card")
	}

	// 2. The next request signs, and the card's counter has not moved.
	signature, err = sign(live)
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatalf("the next request did not sign: %v", err)
	}
	if after := provider.PINRetriesReadings()["primary"].Retries; after != before {
		t.Fatalf("PIN retries went from %d to %d", before, after)
	}
	t.Logf("the next request signs; PIN retries still %d", before)
}
