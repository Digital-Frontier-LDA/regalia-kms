package integration_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// regalia#48 rows F3 and F5 ON REAL CARDS, with ONE long-lived provider — the running daemon — across
// the whole sequence. Driven by e2e/nitrokey-token-swap-drill.sh, which reads every card's PIN retry
// counter from OUTSIDE this process before and after; this test cannot see a counter it did not spend
// and would not be believed if it reported its own.
//
//	1 baseline   an envelope sealed to the commissioned card (serial + public-key pin) releases
//	2 F3 detach  the commissioned card is de-authorised on USB while the provider lives: release fails,
//	             the binding is not healthy — and nothing else on the bus is used in its place
//	3 F5 swap    a route pinned to the commissioned KEY but bound to ANOTHER genuine card (one holding
//	             a different key under the same object ID) is quarantined public-key-mismatch — before
//	             any PIN, so that card's counter must not move
//	4 F3 return  the card is re-authorised: the SAME provider releases again on a fresh session, with the
//	             identity and pin re-verified and no PIN failure
//
// The PINs come from the environment; the USB toggle is `sudo -n tee …/authorized`, as in the drill
// scripts. Staging cards only (the script gates on the staging registry).
func TestPhysicalTokenSwapIsRefusedBeforeAnyPIN(t *testing.T) {
	module, serial, pin, usb := os.Getenv("REGALIA_SWAPDRILL_MODULE"), os.Getenv("REGALIA_SWAPDRILL_SERIAL"),
		os.Getenv("REGALIA_SWAPDRILL_PIN"), os.Getenv("REGALIA_SWAPDRILL_USB")
	other, otherPIN, objectID := os.Getenv("REGALIA_SWAPDRILL_OTHER_SERIAL"), os.Getenv("REGALIA_SWAPDRILL_OTHER_PIN"),
		os.Getenv("REGALIA_SWAPDRILL_OBJECT_ID")
	if module == "" || serial == "" || pin == "" || usb == "" || other == "" || otherPIN == "" || objectID == "" {
		t.Skip("driven by e2e/nitrokey-token-swap-drill.sh")
	}
	ctx := context.Background()
	driver, err := nitrokey.NewPKCS11DriverWithProbes(module, secureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	pins := devicePINs{"commissioned": []byte(pin), "swapped-in": []byte(otherPIN)}
	provider, err := nitrokey.New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
	if err != nil {
		t.Fatal(err)
	}
	route := func(deviceID, deviceSerial, pinned string) registry.Route {
		return registry.Route{
			ObjectID: "swap-drill-token", Purpose: "deployment-api", Environment: "staging",
			Algorithm: "opaque", KEKAlgorithm: "rsa2048", KEKVersion: "1",
			Binding: registry.Binding{
				Site: "drill", Backend: "nitrokey-pkcs11", DeviceID: deviceID, DeviceSerial: deviceSerial,
				PublicKeySHA256: pinned, ObjectID: objectID, KEKAlgorithm: "rsa2048", KEKVersion: "1", State: "active",
			},
		}
	}

	// Commissioning, as the ceremony does it: pin the commissioned card's KEK by its public key.
	session, err := driver.Open(ctx, route("commissioned", serial, "").Binding)
	if err != nil {
		t.Fatalf("open the commissioned card: %v", err)
	}
	public, err := session.PublicKey(ctx, objectID)
	_ = session.Close()
	if err != nil || len(public) == 0 {
		t.Fatalf("read the commissioned KEK: %v", err)
	}
	sum := sha256.Sum256(public)
	pinned := "sha256:" + hex.EncodeToString(sum[:])
	commissioned := route("commissioned", serial, pinned)

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	blob := sealTo(t, ctx, manager, commissioned, secret)
	release := func(r registry.Route) ([]byte, error) {
		releaser, err := secrets.NewReleaser(manager)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := releaser.Execute(ctx, r, "release-secret", "regalia-envelope-v2", "", blob, nil)
		return out, err
	}
	usbAuthorize := func(value string) {
		t.Helper()
		cmd := exec.Command("sudo", "-n", "tee", "/sys/bus/usb/devices/"+usb+"/authorized")
		cmd.Stdin = strings.NewReader(value + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("USB %s authorized=%s: %v %s", usb, value, err, out)
		}
	}

	// 1 BASELINE — without it every refusal below could be a provider that never works.
	if got, err := release(commissioned); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("baseline: the commissioned card does not release its own envelope (err=%v)", err)
	}
	t.Logf("1 baseline: %s released the envelope (KEK pinned %s)", serial, pinned)

	// 2 F3 DETACH, the provider still running.
	usbAuthorize("0")
	defer usbAuthorize("1") // never leave the bench with the card de-authorised
	time.Sleep(3 * time.Second)
	if _, err := release(commissioned); err == nil {
		t.Fatal("DEFECT: the envelope released while the commissioned card was detached")
	}
	if provider.Healthy(ctx, commissioned.Binding) {
		t.Fatal("DEFECT: the binding reports healthy while its card is detached")
	}
	reason, _ := provider.QuarantineReason("commissioned")
	t.Logf("2 F3 detach: release refused, binding unhealthy (quarantine=%q)", reason)

	// 3 F5 SWAP: the commissioned key's pin, bound to a different genuine card.
	swapped := route("swapped-in", other, pinned)
	if _, err := release(swapped); err == nil {
		t.Fatal("DEFECT: a different genuine card released an envelope pinned to another card's key")
	}
	if reason, ok := provider.QuarantineReason("swapped-in"); !ok || reason != "public-key-mismatch" {
		t.Fatalf("DEFECT: the swapped-in card was not quarantined as public-key-mismatch (reason=%q, quarantined=%v)", reason, ok)
	}
	t.Logf("3 F5 swap: %s quarantined public-key-mismatch before any PIN", other)

	// 4 F3 RETURN, same provider.
	usbAuthorize("1")
	deadline := time.Now().Add(30 * time.Second)
	var got []byte
	for {
		got, err = release(commissioned)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil || !bytes.Equal(got, secret) {
		reason, _ := provider.QuarantineReason("commissioned")
		t.Fatalf("F3 return: the SAME provider does not release after the card came back (err=%v, quarantine=%q)", err, reason)
	}
	t.Logf("4 F3 return: %s released again through the same provider", serial)
}

// devicePINs is a PIN source keyed by device, so the swapped-in card is offered ITS OWN PIN — if the
// provider ever presented one, the card's counter would not move and the drill could not see it; a
// correct PIN is what an attacker who owned that card would supply.
type devicePINs map[string][]byte

func (p devicePINs) PIN(_ context.Context, deviceID string) ([]byte, error) {
	return append([]byte(nil), p[deviceID]...), nil
}

func sealTo(t *testing.T, ctx context.Context, manager *backend.Manager, r registry.Route, secret []byte) []byte {
	t.Helper()
	bindingContext := envelope.ReleaseContext(r.ObjectID, r.Purpose, r.Environment)
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(append([]byte(nil), dataKey...))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, nonce, secret, clientContentAAD(r.ObjectID, bindingContext))
	wrapper, err := secrets.NewSealWrapper(manager, r)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.SealAssembled(ctx, wrapper, envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: r.ObjectID, Version: "1"},
		r.ObjectID, bindingContext, ciphertext, nonce, dataKey, time.Now().UTC())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	blob, err := sealed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return blob
}
