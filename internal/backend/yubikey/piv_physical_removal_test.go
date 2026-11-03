//go:build piv

package yubikey

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/pcscwatch"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A YUBIKEY TAKEN OFF THE BUS AND PUT BACK WAITS FOR A FRESH LEASE (regalia-kms#72, PoC 12.4).
//
// The removal is the kernel's own: the USB device's "authorized" attribute set to 0 and back to 1,
// a real disconnect and reconnect that pcscd's hotplug sees (the mechanism of e2e/pkcs11-removal.sh).
// The clock is the host's boot clock, the one the daemon uses; only the lease is a stand-in, so
// that the test decides when the node "asked for" one.
//
// REGALIA_PIV_REMOVAL_SERIAL names the card, REGALIA_PIV_REMOVAL_SLOT a slot holding an Ed25519
// key with PIN policy once and touch policy never, REGALIA_PIV_REMOVAL_PIN the PIV PIN, and
// REGALIA_PIV_REMOVAL_USBDEV the card's name under /sys/bus/usb/devices (for example 1-3). Needs
// passwordless sudo. Nothing is written to the card.
func TestPIVPhysicalRemovedCardWaitsForALeaseAskedForAfterItsReturn(t *testing.T) {
	serial, slot, pin, usb := os.Getenv("REGALIA_PIV_REMOVAL_SERIAL"), os.Getenv("REGALIA_PIV_REMOVAL_SLOT"), os.Getenv("REGALIA_PIV_REMOVAL_PIN"), os.Getenv("REGALIA_PIV_REMOVAL_USBDEV")
	if serial == "" || usb == "" {
		t.Skip("set REGALIA_PIV_REMOVAL_SERIAL, _SLOT, _PIN and _USBDEV for the physical PIV removal test")
	}
	if pin == "" || slot == "" || !regexp.MustCompile(`^[0-9]+-[0-9]+(\.[0-9]+)*$`).MatchString(usb) {
		t.Fatal("REGALIA_PIV_REMOVAL_SLOT and _PIN are needed, and _USBDEV must be a USB device name such as 1-3")
	}
	vendor, err := os.ReadFile("/sys/bus/usb/devices/" + usb + "/idVendor")
	if err != nil || strings.TrimSpace(string(vendor)) != "1050" {
		t.Fatalf("USB device %s is not a Yubico device (idVendor %q, %v): refusing to remove it", usb, strings.TrimSpace(string(vendor)), err)
	}
	authorize := func(value string) {
		t.Helper()
		command := exec.Command("sudo", "-n", "tee", "/sys/bus/usb/devices/"+usb+"/authorized")
		command.Stdin = strings.NewReader(value)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("set authorized=%s on %s: %v: %s", value, usb, err, output)
		}
	}
	t.Cleanup(func() { authorize("1") }) // whatever happens, the card is left on the bus

	driver, err := NewPIVDriver(map[string]string{"primary": serial})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(driver, &fakePIN{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	now := func() int64 {
		t.Helper()
		value, err := admission.Boottime()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	gate := &leaseGate{admitted: true}
	if err := provider.RequireReauthorization(gate, admission.Boottime, now()); err != nil {
		t.Fatal(err)
	}
	// the real PC/SC watcher, as the daemon gives it (regalia-kms#72, G2): a pull is seen as it happens
	watchCtx, stopWatching := context.WithCancel(context.Background())
	defer stopWatching()
	provider.WatchReaders(pcscwatch.Start(watchCtx, pcscwatch.System(), func(err error) { t.Logf("reader watcher: %v", err) }))
	ctx := context.Background()
	route := registry.Route{Algorithm: "ed25519", Binding: registry.Binding{
		Backend: "yubikey-piv", DeviceID: "primary", DeviceSerial: serial, ObjectID: slot, State: "active", PINPolicy: "once", TouchPolicy: "never",
	}}
	message := []byte("regalia-kms#72: a card that was gone waits")
	sign := func() ([]byte, error) {
		signature, _, err := provider.Execute(ctx, route, "sign", "", "application/octet-stream", append([]byte{}, message...), nil)
		return signature, err
	}
	// askForALease is the lease service renewing: the node now holds a lease asked for at this moment.
	askForALease := func() {
		time.Sleep(5 * time.Millisecond)
		gate.requestedMs = now()
	}
	retries := func() int { return provider.PINRetriesReadings()["primary"].Retries }

	// 1. Before any lease asked for since the start, the card is there and does not serve.
	if _, err := sign(); err == nil {
		t.Fatal("the card signed with no lease asked for since the provider started")
	}
	askForALease()
	publicDER, _, err := provider.Execute(ctx, route, "public-key", "", "", nil, nil)
	if err != nil {
		t.Fatalf("read the public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		t.Fatalf("slot %s does not hold an Ed25519 key: %T, %v", slot, parsed, err)
	}
	signature, err := sign()
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatalf("under a lease asked for after the start the card must sign: %v", err)
	}
	before := retries()
	t.Logf("serving: signature verifies; PIN retries %d", before)

	// 2. Off the bus.
	authorize("0")
	removed := now()
	time.Sleep(2 * time.Second)
	if _, err := sign(); err == nil {
		t.Fatal("a card that is off the bus signed")
	}
	if provider.Healthy(ctx, route.Binding) {
		t.Fatal("a card that is off the bus reports healthy")
	}
	if waiting := provider.AwaitingReauthorization(); waiting["primary"] != -1 {
		t.Fatalf("the card is not recorded as gone: %v", waiting)
	}
	// A lease asked for while it is away must not count once it is back.
	askForALease()
	whileAway := gate.requestedMs

	// 3. Back on the bus. The health check is what notices, as it does in the daemon.
	authorize("1")
	var seenBack int64 = -1
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if provider.Healthy(ctx, route.Binding) {
			t.Fatal("the returned card reports healthy on the lease asked for while it was away")
		}
		if seenBack = provider.AwaitingReauthorization()["primary"]; seenBack >= 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if seenBack < 0 {
		t.Fatal("the card was not seen back within 30 s of being re-authorized on the bus")
	}
	if seenBack <= whileAway || seenBack <= removed {
		t.Fatalf("the return is dated %d, not after the removal (%d) and the lease asked for meanwhile (%d)", seenBack, removed, whileAway)
	}
	if _, err := sign(); err == nil {
		t.Fatal("the returned card signed on the lease asked for while it was away")
	}
	if after := retries(); after != before {
		t.Fatalf("PIN retries went from %d to %d while the card was waiting: the PIN must not be presented", before, after)
	}
	t.Logf("back: seen %d ms after removal, refused signing and health, PIN retries still %d", seenBack-removed, before)

	// 4. A lease asked for after the return: it serves again.
	askForALease()
	if !provider.Healthy(ctx, route.Binding) {
		t.Fatal("under a lease asked for after its return the card must be healthy")
	}
	signature, err = sign()
	if err != nil || !ed25519.Verify(public, message, signature) {
		t.Fatalf("under a lease asked for after its return the card must sign: %v", err)
	}
	if waiting := provider.AwaitingReauthorization(); len(waiting) != 0 {
		t.Fatalf("still listed as waiting after serving: %v", waiting)
	}
	t.Logf("serving again: signature verifies; PIN retries %d", retries())
}
