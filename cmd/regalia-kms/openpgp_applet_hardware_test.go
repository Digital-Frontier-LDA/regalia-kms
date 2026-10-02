package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// buildHardware, AS THE DAEMON CALLS IT, SERVES A YUBIKEY'S OPENPGP APPLET (regalia#541).
//
// Configuration in, signature out: the evidence file, the PIN credential file and the registry are
// read the way a deployment provides them, and the signature comes back through the backend manager
// under the yubikey-openpgp name. The same environment as
// TestEd25519OnAYubiKeyOpenPGPAppletThroughOpenSC: OPENSC_CONF giving the YubiKey the "openpgp"
// driver, and REGALIA_OPENPGP_PKCS11_MODULE, _SERIAL and _PIN.
func TestBuildHardwareServesTheOpenPGPAppletOverLocalTokenEvidence(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_OPENPGP_PKCS11_MODULE"), os.Getenv("REGALIA_OPENPGP_PKCS11_SERIAL")
	pin := os.Getenv("REGALIA_OPENPGP_PKCS11_PIN")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_OPENPGP_PKCS11_MODULE, REGALIA_OPENPGP_PKCS11_SERIAL and REGALIA_OPENPGP_PKCS11_PIN, with OPENSC_CONF selecting the openpgp driver")
	}
	if pin == "" {
		t.Fatal("REGALIA_OPENPGP_PKCS11_SERIAL is set but REGALIA_OPENPGP_PKCS11_PIN is not: the test cannot run")
	}
	const label = "OpenPGP card (User PIN (sig))"
	directory := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	entry := func(deviceSerial, claim string) string {
		return fmt.Sprintf(`{"schema_version":1,"devices":[{"device_serial":%q,"verified_by":"bench","verified_at":%q,"expires_at":%q,"firmware":"5.7.4",%s}]}`,
			deviceSerial, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339), claim)
	}
	localEvidence := write("local.json", entry(serial, `"secure_messaging_established":false,"channel":"local-usb"`))
	pinPath := write("yubikey-sitea.pin", pin) // exactly the PIN: the credential source refuses a newline

	// Commissioning reads the public key off the token; the registry then pins it.
	probe, err := nitrokey.NewPKCS11DriverWithProbes(modulePath, noSecureMessaging{})
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.ServeLocalTokens(noSecureMessaging{}); err != nil {
		t.Fatal(err)
	}
	session, err := probe.Open(context.Background(), registry.Binding{Backend: nitrokey.OpenPGPAppletBackend, DeviceID: "yubikey-sitea", DeviceSerial: serial, TokenLabel: label})
	if err != nil {
		t.Fatalf("the signature token did not open: %v", err)
	}
	publicDER, err := session.PublicKey(context.Background(), "01")
	_ = session.Close()
	if closeErr := probe.Close(); err != nil || closeErr != nil {
		t.Fatalf("read the public key: %v (close: %v)", err, closeErr)
	}
	parsed, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal(err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("the signature key is %T, not Ed25519", parsed)
	}
	sum := sha256.Sum256(publicDER)
	keyPin := "sha256:" + hex.EncodeToString(sum[:])

	settings := config.Config{
		PKCS11ModulePath: modulePath, SecureChannelEvidence: localEvidence,
		PINPaths: map[string]string{"yubikey-sitea": pinPath},
	}
	keyRegistry := appletRegistry(t, `"sign"`, serial, label, keyPin)
	_, manager, _, closer, err := buildHardware(settings, keyRegistry)
	if err != nil {
		t.Fatalf("buildHardware refused a servable applet configuration: %v", err)
	}
	if !manager.Serves(nitrokey.OpenPGPAppletBackend) || !manager.Serves("nitrokey-pkcs11") {
		closer()
		t.Fatal("the manager does not serve both PKCS#11 backends")
	}
	routed := keyRegistry.RoutedTo(nitrokey.OpenPGPAppletBackend)
	digest := sha256.Sum256([]byte("a release digest"))
	signature, _, err := manager.Execute(context.Background(), registry.Route{Algorithm: "ed25519", Binding: routed[0].Binding},
		"sign", "", "application/vnd.regalia.digest", digest[:], nil)
	closer()
	if err != nil || !ed25519.Verify(public, digest[:], signature) {
		t.Fatalf("the manager's signature does not verify: length %d, err %v", len(signature), err)
	}

	// Without a local-usb attestation the applet backend is not served at all, whatever the
	// registry says. The evidence here vouches for some other, secure-messaging token.
	settings.SecureChannelEvidence = write("secure.json", entry("DENK0000001", `"secure_messaging_established":true`))
	_, manager, _, closer, err = buildHardware(settings, keyRegistry)
	if err != nil {
		t.Fatal(err)
	}
	served := manager.Serves(nitrokey.OpenPGPAppletBackend)
	closer()
	if served {
		t.Fatal("the applet backend is served with no local-usb attestation")
	}

	// And a registry the daemon could not serve is refused here, not at the first signature.
	settings.SecureChannelEvidence = localEvidence
	if _, _, _, closer, err := buildHardware(settings, appletRegistry(t, `"sign"`, serial, "", keyPin)); err == nil {
		closer()
		t.Fatal("buildHardware accepted an applet binding with no token_label")
	}
}

// noSecureMessaging is the commissioning read's stand-in: it only reads a public key.
type noSecureMessaging struct{}

func (noSecureMessaging) Establish(context.Context, string, string) error { return nil }
