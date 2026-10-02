//go:build piv

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ONE YUBIKEY, ONE HSM, ONE DAEMON (regalia#541).
//
// The YubiKey holds a P-256 key and an Ed25519 key in PIV slots and is served by the PIV backend;
// the SmartCard-HSM is served by the PKCS#11 backend through OpenSC, in the same process. This is
// the configuration the owner asked for: one YubiKey for everything the HSM cannot do.
//
// It works only when OpenSC is told to ignore the YubiKey's reader (deploy/opensc/ignore-yubikey.conf,
// named by OPENSC_CONF): the PIV backend opens the card exclusively, and OpenSC otherwise holds a
// connection to it. The first step below fails with OpenSC's defaults.
//
// It needs a piv-tagged build, and:
//
//	REGALIA_ONE_YK_MODULE        opensc-pkcs11.so
//	REGALIA_ONE_YK_SERIAL        the YubiKey's serial
//	REGALIA_ONE_YK_PIV_PIN       its PIV PIN
//	REGALIA_ONE_YK_ED25519_SLOT  a PIV slot holding an Ed25519 key (PIN once or always, touch never)
//	REGALIA_ONE_YK_HSM_SERIAL    a SmartCard-HSM attached to the same host
//
// PIV slot 9c must hold a P-256 key (PIN once, touch never). Nothing is written to either token,
// and the HSM is never logged in to.
//
// REGALIA_ONE_YK_EXPECT_LOCKOUT=1 runs the other half instead: with OPENSC_CONF NOT naming the
// ignore rule, the daemon's own module holds the YubiKey, and buildHardware must refuse to start
// and name the setting (requirePIVCardsOpenBesidePKCS11).
func TestOneYubiKeyServesPIVKeysBesideThePKCS11Backend(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_ONE_YK_MODULE"), os.Getenv("REGALIA_ONE_YK_SERIAL")
	pin, ed25519Slot, hsmSerial := os.Getenv("REGALIA_ONE_YK_PIV_PIN"), os.Getenv("REGALIA_ONE_YK_ED25519_SLOT"), os.Getenv("REGALIA_ONE_YK_HSM_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_ONE_YK_MODULE, _SERIAL, _PIV_PIN, _ED25519_SLOT and _HSM_SERIAL, with OPENSC_CONF naming deploy/opensc/ignore-yubikey.conf")
	}
	if pin == "" || ed25519Slot == "" || hsmSerial == "" {
		t.Fatal("REGALIA_ONE_YK_SERIAL is set but the PIN, the Ed25519 slot or the HSM serial is not: the test cannot run")
	}
	ctx := context.Background()
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
			hsmSerial, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))),
		YubiKeyDevices: map[string]string{"yubikey-sitea": serial},
		// The HSM's entry is never read: nothing here logs in to it.
		PINPaths: map[string]string{"yubikey-sitea": write("yubikey.pin", pin), "hsm-sitea": write("hsm.pin", "000000")},
	}

	if os.Getenv("REGALIA_ONE_YK_EXPECT_LOCKOUT") == "1" {
		_, _, _, closer, err := buildHardware(settings, hsmRegistryFor(t, hsmSerial, "issuing-ca p384 - sign"))
		if err == nil {
			closer()
			t.Fatal("the daemon started although its PKCS#11 module holds the YubiKey: every PIV request would fail (is OPENSC_CONF naming the ignore rule? this half runs without it)")
		}
		for _, want := range []string{"yubikey-sitea", "another connection holds a card reader", "OPENSC_CONF", "deploy/opensc/ignore-yubikey.conf"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal does not name %q: %v", want, err)
			}
		}
		t.Logf("refused to start: %v", err)
		return
	}
	// The PKCS#11 side is alive in this process: the HSM answers the startup question about what it
	// offers, which is how an Ed25519 key bound to it is refused...
	if _, _, _, closer, err := buildHardware(settings, hsmRegistryFor(t, hsmSerial, "release-ed25519 ed25519 - sign")); err == nil {
		closer()
		t.Fatal("an Ed25519 key bound to the SmartCard-HSM was accepted: either the HSM was not asked, or it is not attached")
	} else if !strings.Contains(err.Error(), "release-ed25519") {
		t.Fatalf("the refusal is not about the Ed25519 key on the HSM: %v", err)
	}
	// ...and a key type it does offer is accepted, with both backends served.
	_, manager, _, closer, err := buildHardware(settings, hsmRegistryFor(t, hsmSerial, "issuing-ca p384 - sign"))
	if err != nil {
		t.Fatalf("buildHardware with the HSM and the YubiKey: %v", err)
	}
	defer closer()
	if !manager.Serves("nitrokey-pkcs11") || !manager.Serves("yubikey-piv") {
		t.Fatal("the manager does not serve both backends")
	}

	binding := func(slot string) registry.Binding {
		return registry.Binding{Backend: "yubikey-piv", DeviceID: "yubikey-sitea", DeviceSerial: serial, ObjectID: slot, State: "active", PINPolicy: "once", TouchPolicy: "never"}
	}
	p256Route := registry.Route{Algorithm: "p256", Binding: binding("9c")}
	ed25519Route := registry.Route{Algorithm: "ed25519", Binding: binding(ed25519Slot)}
	publicKey := func(route registry.Route) any {
		der, _, err := manager.Execute(ctx, route, "public-key", "", "", nil, nil)
		if err != nil {
			t.Fatalf("read the public key of PIV slot %s: %v (with OpenSC's defaults this is where it fails: the module holds the card)", route.Binding.ObjectID, err)
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	p256Key, ok := publicKey(p256Route).(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("PIV slot 9c does not hold an ECDSA key")
	}
	ed25519Key, ok := publicKey(ed25519Route).(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PIV slot %s does not hold an Ed25519 key", ed25519Slot)
	}

	sign := func(route registry.Route, index int) error {
		digest := sha256.Sum256([]byte(fmt.Sprintf("%s %d", route.Algorithm, index)))
		signature, _, err := manager.Execute(ctx, route, "sign", "", "application/vnd.regalia.digest", digest[:], nil)
		if err != nil {
			return fmt.Errorf("%s sign %d: %w", route.Algorithm, index, err)
		}
		verified := false
		if route.Algorithm == "ed25519" {
			verified = ed25519.Verify(ed25519Key, digest[:], signature)
		} else {
			verified = verifyECDSA(p256Key, digest[:], signature)
		}
		if !verified {
			return fmt.Errorf("%s sign %d: the signature does not verify", route.Algorithm, index)
		}
		return nil
	}

	// Alternating between the two keys of the one card, then both requested at the same time.
	var failures []string
	for index := 0; index < 6; index++ {
		for _, route := range []registry.Route{ed25519Route, p256Route} {
			if err := sign(route, index); err != nil {
				failures = append(failures, err.Error())
			}
		}
	}
	alternating := len(failures)
	// Simultaneous: each worker reports on a channel, so nothing is shared between them.
	const workers, perWorker = 4, 3
	results := make(chan error, workers*perWorker)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for index := 0; index < perWorker; index++ {
				route := ed25519Route
				if (worker+index)%2 == 0 {
					route = p256Route
				}
				results <- sign(route, 100*worker+index)
			}
		}(worker)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			failures = append(failures, err.Error())
		}
	}
	t.Logf("alternating: 12 signatures, %d failed; concurrent: 12 signatures, %d failed", alternating, len(failures)-alternating)
	if len(failures) > 0 {
		t.Fatalf("%d of 24 signatures failed: %v", len(failures), failures)
	}
	if !manager.Healthy(ctx, ed25519Route.Binding) {
		t.Fatal("the YubiKey is not healthy after the run")
	}
}

// verifyECDSA verifies r||s at the width of the curve order: the one encoding every backend
// returns. ASN.1 DER, which this backend used to return, does not pass (regalia-kms#162).
func verifyECDSA(public *ecdsa.PublicKey, digest, signature []byte) bool {
	half := (public.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*half {
		return false
	}
	return ecdsa.Verify(public, digest, new(big.Int).SetBytes(signature[:half]), new(big.Int).SetBytes(signature[half:]))
}
