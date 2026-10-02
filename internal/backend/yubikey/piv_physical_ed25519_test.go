//go:build piv

package yubikey

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"
)

// ED25519 IN A PIV SLOT, THROUGH THIS BACKEND'S OWN SESSION (regalia#541).
//
// Firmware 5.7 added Ed25519 to the PIV applet. Neither SmartCard-HSM offers it, and the OpenPGP
// applet has one signing slot; PIV has twenty-four, on the applet and middleware this backend
// already uses. REGALIA_PIV_ED25519_SERIAL names the card, REGALIA_PIV_ED25519_SLOT a slot holding
// an Ed25519 key with PIN policy once (or always) and touch policy never, and
// REGALIA_PIV_ED25519_PIN the PIV PIN.
func TestPIVPhysicalEd25519Signing(t *testing.T) {
	serial, slot, pin := os.Getenv("REGALIA_PIV_ED25519_SERIAL"), os.Getenv("REGALIA_PIV_ED25519_SLOT"), os.Getenv("REGALIA_PIV_ED25519_PIN")
	if serial == "" || slot == "" {
		t.Skip("set REGALIA_PIV_ED25519_SERIAL, REGALIA_PIV_ED25519_SLOT and REGALIA_PIV_ED25519_PIN for the physical PIV Ed25519 test")
	}
	if pin == "" {
		t.Fatal("REGALIA_PIV_ED25519_SERIAL is set but REGALIA_PIV_ED25519_PIN is not: the test cannot run")
	}
	driver, err := NewPIVDriver(map[string]string{"primary": serial})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := driver.Open(ctx, "primary")
	if err != nil {
		t.Fatalf("open the card: %v", err)
	}
	defer session.Close()
	if got, err := session.Identity(ctx); err != nil || got != serial {
		t.Fatalf("identity = %q, %v; want %q", got, err, serial)
	}
	pinPolicy, touchPolicy, err := session.Policies(ctx, slot)
	if err != nil || (pinPolicy != "once" && pinPolicy != "always") || touchPolicy != "never" {
		t.Fatalf("slot %s policy = pin %q, touch %q, %v; want once or always, and never", slot, pinPolicy, touchPolicy, err)
	}
	publicDER, err := session.PublicKey(ctx, slot)
	if err != nil {
		t.Fatalf("read the slot's public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("slot %s holds a %T, not an Ed25519 key", slot, parsed)
	}
	if err := session.Login(ctx, []byte(pin)); err != nil {
		t.Fatalf("PIN authentication failed: %v", err)
	}

	digest := sha256.Sum256([]byte("an OpenPGP signature digest stands here"))
	signature, err := session.Sign(ctx, slot, "ed25519", digest[:])
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("signature length=%d err=%v", len(signature), err)
	}
	// Pure Ed25519 over exactly the bytes handed in, as regalia-sign needs.
	if !ed25519.Verify(public, digest[:], signature) {
		t.Fatal("the signature does not verify as Ed25519 over the bytes that were sent")
	}
	other := digest
	other[0] ^= 1
	if ed25519.Verify(public, other[:], signature) {
		t.Fatal("the signature verified over different bytes")
	}

	// The gates that apply to every algorithm apply to this one: a payload of another length is
	// not a SHA-256 digest, and the key is not another kind of key.
	if _, err := session.Sign(ctx, slot, "ed25519", digest[:31]); err == nil {
		t.Fatal("a 31-byte payload was signed")
	}
	if _, err := session.Sign(ctx, slot, "p256", digest[:]); err == nil {
		t.Fatal("an Ed25519 key signed as though it were a P-256 key")
	}
}
