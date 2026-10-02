package nitrokey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ED25519 ON A YUBIKEY'S OPENPGP APPLET, THROUGH OPENSC AND THIS DRIVER (regalia#541).
//
// Neither HSM lists an EdDSA mechanism. OpenSC's own OpenPGP card driver does: it presents the
// applet as a PKCS#11 token whose signature key signs with CKM_EDDSA. This runs the production
// driver, its real token probes and the provider against that token, so the Ed25519 path is held to
// hardware and not only to SoftHSM (TestEd25519SignsTheBytesItIsGivenAgainstSoftHSM).
//
// It needs, on the host:
//
//   - an opensc.conf that gives the YubiKey's ATR the "openpgp" driver (OpenSC presents a YubiKey
//     as PIV by default), named by OPENSC_CONF;
//   - an Ed25519 signature key on the applet, with its fingerprint set: OpenSC lists no key object
//     for a slot whose fingerprint is all zeros;
//   - REGALIA_OPENPGP_PKCS11_MODULE (opensc-pkcs11.so), REGALIA_OPENPGP_PKCS11_SERIAL (the serial
//     the token reports, e.g. 000635718625) and REGALIA_OPENPGP_PKCS11_PIN (PW1).
//
// The secure channel is a stand-in: SmartCard-HSM secure messaging does not exist on this applet.
// Evidence class: physical, for the driver, the probes and the provider. It is not the daemon.
func TestEd25519OnAYubiKeyOpenPGPAppletThroughOpenSC(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_OPENPGP_PKCS11_MODULE"), os.Getenv("REGALIA_OPENPGP_PKCS11_SERIAL")
	pin := os.Getenv("REGALIA_OPENPGP_PKCS11_PIN")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_OPENPGP_PKCS11_MODULE, REGALIA_OPENPGP_PKCS11_SERIAL and REGALIA_OPENPGP_PKCS11_PIN, with OPENSC_CONF selecting the openpgp driver")
	}
	if pin == "" {
		t.Fatal("REGALIA_OPENPGP_PKCS11_SERIAL is set but REGALIA_OPENPGP_PKCS11_PIN is not: the test cannot run")
	}
	const signatureToken, signatureKey = "OpenPGP card (User PIN (sig))", "01"

	driver, err := NewPKCS11DriverWithProbes(modulePath, &recordingSecureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	ctx := context.Background()
	binding := registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "yubikey-openpgp", DeviceSerial: serial,
		TokenLabel: signatureToken, ObjectID: signatureKey, State: "active",
	}

	// The serial alone names two tokens, and that is refused. If this passes without a label, the
	// card is not presented the way this test assumes and nothing below proves the selection.
	unlabelled := binding
	unlabelled.TokenLabel = ""
	if session, err := driver.Open(ctx, unlabelled); err == nil {
		_ = session.Close()
		t.Fatal("the serial alone resolved to one token: the applet is not presented as two tokens here")
	}

	// Commissioning: read the public key off the token and pin it. The applet has no device
	// certificate, so the pinned key is what identifies it (ADR-0002 D1).
	session, err := driver.Open(ctx, binding)
	if err != nil {
		t.Fatalf("the labelled signature token did not open: %v", err)
	}
	publicDER, err := session.PublicKey(ctx, signatureKey)
	if closeErr := session.Close(); err != nil || closeErr != nil {
		t.Fatalf("read the signature key's public half: %v (close: %v)", err, closeErr)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatalf("the driver's encoding of the public key is not PKIX: %v (%x)", err, publicDER)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the signature key parsed as %T, not Ed25519", parsed)
	}
	sum := sha256.Sum256(publicDER)
	binding.PublicKeySHA256 = "sha256:" + hex.EncodeToString(sum[:])

	provider, err := New(driver, &fakePIN{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	route := registry.Route{Algorithm: "ed25519", Binding: binding}
	if !provider.Healthy(ctx, binding) {
		reason, _ := provider.QuarantineReason(binding.DeviceID)
		t.Fatalf("the provider does not consider the token healthy (quarantine reason %q)", reason)
	}

	digest := sha256.Sum256([]byte("an OpenPGP signature digest stands here"))
	long := make([]byte, 64)
	if _, err := rand.Read(long); err != nil {
		t.Fatal(err)
	}
	for name, message := range map[string][]byte{"a 32-byte digest": digest[:], "a 64-byte digest": long} {
		signature, _, err := provider.Execute(ctx, route, "sign", "", "application/vnd.regalia.digest", message, nil)
		if err != nil || len(signature) != ed25519.SignatureSize {
			reason, _ := provider.QuarantineReason(binding.DeviceID)
			t.Fatalf("%s: signature length=%d err=%v (quarantine reason %q)", name, len(signature), err, reason)
		}
		// Pure Ed25519 over exactly the bytes handed in, which is what an OpenPGP EdDSA signature
		// needs (regalia#530).
		if !ed25519.Verify(public, message, signature) {
			t.Fatalf("%s: the signature does not verify as Ed25519 over the bytes that were sent", name)
		}
		other := append([]byte{}, message...)
		other[0] ^= 1
		if ed25519.Verify(public, other, signature) {
			t.Fatalf("%s: the signature verified over different bytes", name)
		}
	}

	// A binding pinned to another key is a different card as far as the provider can tell, and it
	// latches rather than signs. Last, because the latch is per device.
	wrong := binding
	wrong.PublicKeySHA256 = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	if _, _, err := provider.Execute(ctx, registry.Route{Algorithm: "ed25519", Binding: wrong}, "sign", "", "application/vnd.regalia.digest", digest[:], nil); err == nil {
		t.Fatal("a binding pinned to another public key signed")
	}
	if reason, quarantined := provider.QuarantineReason(binding.DeviceID); !quarantined {
		t.Fatal("a public-key mismatch did not quarantine the device")
	} else {
		t.Logf("public-key mismatch quarantined the device: %s", reason)
	}
}
