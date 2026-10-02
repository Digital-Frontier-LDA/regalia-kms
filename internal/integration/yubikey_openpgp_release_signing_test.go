package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// AN ED25519 OPENPGP RELEASE SIGNATURE FROM A YUBIKEY, THROUGH THE KMS (regalia#541, regalia#530).
//
// The key is on a YubiKey's OpenPGP applet. The daemon reaches it the way it is deployed to: the
// production PKCS#11 driver with its real token probes, over OpenSC's own OpenPGP card driver, under
// a local-usb attestation loaded from an evidence file. In front of it are the registry, RBAC, the
// purpose policy, the audit journal and mTLS. regalia-sign is the built executable, and GnuPG is the
// judge.
//
// It needs what TestEd25519OnAYubiKeyOpenPGPAppletThroughOpenSC needs: OPENSC_CONF giving the
// YubiKey's ATR the "openpgp" driver, an Ed25519 signature key on the applet with its fingerprint
// set, and REGALIA_OPENPGP_PKCS11_MODULE, _SERIAL and _PIN.
//
// Evidence class: physical. What it is not: the daemon binary under its systemd unit.
func TestRegaliaSignEd25519OnAYubiKeyOpenPGPApplet(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_OPENPGP_PKCS11_MODULE"), os.Getenv("REGALIA_OPENPGP_PKCS11_SERIAL")
	pin := os.Getenv("REGALIA_OPENPGP_PKCS11_PIN")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_OPENPGP_PKCS11_MODULE, REGALIA_OPENPGP_PKCS11_SERIAL and REGALIA_OPENPGP_PKCS11_PIN, with OPENSC_CONF selecting the openpgp driver")
	}
	if pin == "" {
		t.Fatal("REGALIA_OPENPGP_PKCS11_SERIAL is set but REGALIA_OPENPGP_PKCS11_PIN is not: the test cannot run")
	}
	gpg := requireGPG(t)
	binary := buildRegaliaSign(t)
	pki := newSidecarPKI(t)
	const signatureToken, signatureKey, objectID = "OpenPGP card (User PIN (sig))", "01", "release-signing-yubikey"

	// The operator's attestation, as the daemon loads it. now is a variable so the last arm can
	// move the clock past the expiry.
	now := time.Now()
	evidence := filepath.Join(t.TempDir(), "secure-channel.json")
	document := fmt.Sprintf(`{"schema_version":1,"devices":[{"device_serial":%q,"verified_by":"bench","verified_at":%q,"expires_at":%q,"firmware":"5.7.4","secure_messaging_established":false,"channel":"local-usb"}]}`,
		serial, now.Add(-time.Hour).UTC().Format(time.RFC3339), now.Add(time.Hour).UTC().Format(time.RFC3339))
	if err := os.WriteFile(evidence, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	channel, err := nitrokey.LoadSecureChannelEvidence(evidence, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	local := channel.LocalTokens()
	if local == nil {
		t.Fatal("the evidence offers no local attestation")
	}
	driver, err := nitrokey.NewPKCS11DriverWithProbes(modulePath, channel)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Close() })
	if err := driver.ServeLocalTokens(local); err != nil {
		t.Fatal(err)
	}

	// Commissioning: read the public key off the token and pin it, in the binding and in the
	// release job's configuration.
	binding := registry.Binding{Backend: nitrokey.OpenPGPAppletBackend, DeviceID: "yubikey-e2e", DeviceSerial: serial, TokenLabel: signatureToken, ObjectID: signatureKey}
	session, err := driver.Open(context.Background(), binding)
	if err != nil {
		t.Fatalf("the signature token did not open: %v", err)
	}
	publicDER, err := session.PublicKey(context.Background(), signatureKey)
	if closeErr := session.Close(); err != nil || closeErr != nil {
		t.Fatalf("read the signature key's public half: %v (close: %v)", err, closeErr)
	}
	if parsed, err := x509.ParsePKIXPublicKey(publicDER); err != nil {
		t.Fatal(err)
	} else if _, isEd25519 := parsed.(ed25519.PublicKey); !isEd25519 {
		t.Fatalf("the signature key is %T, not Ed25519", parsed)
	}
	sum := sha256.Sum256(publicDER)
	keyPin := "sha256:" + hex.EncodeToString(sum[:])

	provider, err := nitrokey.New(driver, pinSource{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{nitrokey.OpenPGPAppletBackend: provider})
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"release-yubikey","generated_at":"2026-10-02T00:00:00Z","objects":[{"id":%q,"name":"Release signing on a YubiKey","kind":"asymmetric-key","classification":"restricted","environment":"development","owner":"security","purpose":"release-artifact","custody":"direct-hardware","algorithm":"ed25519","operations":["sign"],"policy_id":"release-yubikey-policy","bindings":[{"site":"e2e-site","backend":"yubikey-openpgp","device_id":"yubikey-e2e","device_serial":%q,"token_label":%q,"object_id":%q,"public_fingerprint":%q,"public_key_sha256":%q,"state":"active","pin_policy":"once","touch_policy":"never"}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`,
		objectID, serial, signatureToken, signatureKey, keyPin, keyPin)
	policies := []policy.Policy{{
		ID: "release-yubikey-policy", ObjectID: objectID, Purpose: "release-artifact", Environment: "development",
		Operation: "sign", Algorithm: "ed25519", ContentTypes: []string{"application/vnd.regalia.digest"},
		MaxPayloadBytes: 32, MaxFuture: 2 * time.Minute,
	}}
	daemon := startReleaseSigningDaemon(t, hardware, manifest, []string{strconv.Quote(objectID)}, policies, pki)

	deployment := t.TempDir()
	config := writeSignDeployment(t, deployment, signConfig{
		kmsURL: daemon.server.URL, serverName: "kms.e2e.internal", ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		objectID: objectID, purpose: "release-artifact", publicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
	})
	fingerprint := strings.TrimSpace(regaliaSign(t, binary, config, "--fingerprint"))
	exported := regaliaSign(t, binary, config, "--export-key")
	home := importIntoThrowawayGnuPG(t, gpg, exported, fingerprint)
	// requireGPG found gpg on PATH, and that is the one this runs.
	verify := func(args ...string) (string, error) {
		output, err := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--no-tty", "--status-fd", "1"}, args...)...).CombinedOutput()
		return string(output), err
	}

	// A detached signature over a checksum file, as a release publishes it.
	sums := filepath.Join(deployment, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("9f2c…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	regaliaSign(t, binary, config, "--detach", sums)
	if output, err := verify("--verify", sums+".asc", sums); err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+fingerprint) {
		t.Fatalf("GnuPG does not accept the YubiKey-made signature: %v\n%s", err, output)
	}
	if err := os.WriteFile(sums, []byte("9f2c…  regalia-kms_1.0.1_linux_amd64.tar.gz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, err := verify("--verify", sums+".asc", sums); err == nil || !strings.Contains(output, "[GNUPG:] BADSIG") {
		t.Fatalf("GnuPG accepted the signature over a changed file: %v\n%s", err, output)
	}

	// A cleartext signature, the form an apt repository serves as InRelease.
	release, inRelease, extracted := filepath.Join(deployment, "Release"), filepath.Join(deployment, "InRelease"), filepath.Join(deployment, "Release.extracted")
	releaseText := "Origin: Regalia\nSuite: stable\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 Packages\n"
	if err := os.WriteFile(release, []byte(releaseText), 0o644); err != nil {
		t.Fatal(err)
	}
	regaliaSign(t, binary, config, "--clearsign", release, "--output", inRelease)
	if output, err := verify("--output", extracted, "--decrypt", inRelease); err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+fingerprint) {
		t.Fatalf("GnuPG does not accept the YubiKey-made cleartext signature: %v\n%s", err, output)
	}
	if text, err := os.ReadFile(extracted); err != nil || string(text) != releaseText {
		t.Fatalf("GnuPG extracted a different text (%v): %q", err, text)
	}

	// Every signature that reached the card is an authorized/success pair in the audit journal.
	events := daemon.sink.snapshot()
	if len(events) != 6 {
		t.Fatalf("expected 6 audit events for 3 signatures, got %d: %#v", len(events), events)
	}
	for index, event := range events {
		if want := []string{"authorized", "success"}[index%2]; event.Operation != "sign" || event.ObjectID != objectID || event.Outcome != want {
			t.Fatalf("audit event %d is %s/%s/%s, want sign/%s/%s", index, event.Operation, event.ObjectID, event.Outcome, objectID, want)
		}
	}

	// THE ATTESTATION EXPIRES, AND THE CARD STOPS SIGNING. Nothing about the token changed; only
	// the operator's claim aged out. Last, because a channel that will not establish latches the
	// device until an operator clears it.
	now = now.Add(2 * time.Hour)
	digest := sha256.Sum256([]byte("signed after the attestation expired"))
	binding.PublicKeySHA256 = keyPin
	if signature, _, err := hardware.Execute(context.Background(), registry.Route{Algorithm: "ed25519", Binding: binding}, "sign", "", "application/vnd.regalia.digest", digest[:], nil); err == nil {
		t.Fatalf("the card signed after the local-usb attestation expired (%d bytes)", len(signature))
	}
	if reason, quarantined := provider.QuarantineReason("yubikey-e2e"); !quarantined {
		t.Fatal("an expired attestation did not latch the device")
	} else {
		t.Logf("expired attestation latched the device: %s", reason)
	}
}
