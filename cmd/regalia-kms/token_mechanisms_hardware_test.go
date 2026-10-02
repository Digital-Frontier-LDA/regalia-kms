package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// buildHardware ASKS A REAL TOKEN WHAT IT CAN DO (regalia#541).
//
// REGALIA_MECHANISM_HW_MODULE names the PKCS#11 module and REGALIA_MECHANISM_HW_SERIAL a
// SmartCard-HSM attached to this host (a Nitrokey HSM 2 or a Pico HSM). Nothing is written to the
// token and no PIN is presented: C_GetMechanismList needs no login, and the keys the registry names
// need not exist.
func TestBuildHardwareRefusesAKeyTypeTheAttachedTokenDoesNotOffer(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_MECHANISM_HW_MODULE"), os.Getenv("REGALIA_MECHANISM_HW_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_MECHANISM_HW_MODULE and REGALIA_MECHANISM_HW_SERIAL to a SmartCard-HSM attached to this host")
	}
	// An absent token is deliberately not a startup refusal, so without this the test would "pass"
	// its control and fail its refusal on a token that is simply not there.
	probe, err := nitrokey.NewPKCS11DriverWithProbes(modulePath, noSecureMessaging{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := probe.Open(context.Background(), registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: serial})
	if err != nil {
		_ = probe.Close()
		t.Fatalf("token %s is not attached, or not as exactly one slot: %v", serial, err)
	}
	_ = session.Close()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	settings := config.Config{
		PKCS11ModulePath: modulePath,
		SecureChannelEvidence: write("evidence.json", fmt.Sprintf(`{"schema_version":1,"devices":[{"device_serial":%q,"verified_by":"bench","verified_at":%q,"expires_at":%q,"firmware":"bench","secure_messaging_established":true}]}`,
			serial, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))),
		// Never read: nothing here logs in. The source only requires a mapping to exist.
		PINPaths: map[string]string{"hsm-sitea": write("hsm-sitea.pin", "000000")},
	}

	// What a SmartCard-HSM offers: ECDSA, ECDH and RSA. The control, so that the refusal below is
	// about the key type and not about the token being unreachable.
	_, manager, _, closer, err := buildHardware(settings, hsmRegistryFor(t, serial,
		"release-p384 p384 - sign key-agreement", "kek rsa3072 - unwrap", "wallet secp256k1 - sign"))
	if err != nil {
		t.Fatalf("buildHardware refused key types the token offers: %v", err)
	}
	served := manager.Serves("nitrokey-pkcs11")
	closer()
	if !served {
		t.Fatal("the PKCS#11 backend is not served")
	}

	// And what it does not: EdDSA and AES key wrap, both advertised for the backend.
	_, _, _, closer, err = buildHardware(settings, hsmRegistryFor(t, serial,
		"release-p384 p384 - sign", "release-ed25519 ed25519 - sign", "deploy-token opaque aes-256 release-secret"))
	if err == nil {
		closer()
		t.Fatal("buildHardware accepted an ed25519 key and an aes-256 KEK on a token that offers neither mechanism")
	}
	for _, want := range []string{"release-ed25519 declares sign on a ed25519 key", "deploy-token declares release-secret on a aes-256 key", serial} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "release-p384") {
		t.Errorf("the refusal names the P-384 key, which the token can serve: %v", err)
	}
	t.Logf("refused: %v", err)
}
