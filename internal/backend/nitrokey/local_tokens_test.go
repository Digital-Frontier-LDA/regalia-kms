package nitrokey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A TOKEN WITH NO SECURE MESSAGING IS ATTESTED AS WHAT IT IS (regalia#541).
//
// A YubiKey's OpenPGP applet has no secure-messaging session, so the evidence the SmartCard-HSM
// path requires would be false for it. The applet backend is served over a different claim,
// "local-usb", held to the same rules. These tests are about the two claims never standing in for
// each other, in either direction.

const mixedEvidence = `{"schema_version":1,"devices":[
  {"device_serial":"DENK0000001","verified_by":"custodian","verified_at":"2026-09-01T00:00:00Z",
   "expires_at":"2026-12-01T00:00:00Z","firmware":"4.1","secure_messaging_established":true},
  {"device_serial":"000600000001","verified_by":"custodian","verified_at":"2026-09-01T00:00:00Z",
   "expires_at":"2026-10-01T00:00:00Z","firmware":"5.7.4","secure_messaging_established":false,"channel":"local-usb"}]}`

func evidenceAt(t *testing.T, body string, now time.Time) *AttestedSecureChannel {
	t.Helper()
	channel, err := LoadSecureChannelEvidence(writeEvidence(t, body), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return channel
}

func TestTheTwoAttestationsNeverStandInForEachOther(t *testing.T) {
	ctx := context.Background()
	channel := evidenceAt(t, mixedEvidence, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	local := channel.LocalTokens()
	if local == nil {
		t.Fatal("evidence naming a local-usb token offers no local attestation")
	}
	// Each claim covers its own device.
	if err := channel.Establish(ctx, "hsm", "DENK0000001"); err != nil {
		t.Fatalf("the secure-messaging control was refused: %v", err)
	}
	if err := local.Establish(ctx, "yubikey", "000600000001"); err != nil {
		t.Fatalf("the local-usb control was refused: %v", err)
	}
	// And never the other's. A SmartCard-HSM is not relaxed by anything the local view says, and
	// an applet is not vouched for by evidence about secure messaging it does not have.
	if err := channel.Establish(ctx, "yubikey", "000600000001"); err == nil {
		t.Fatal("a local-usb entry satisfied the secure-messaging check")
	}
	if err := local.Establish(ctx, "hsm", "DENK0000001"); err == nil {
		t.Fatal("a secure-messaging entry satisfied the local-usb check")
	}
	if err := local.Establish(ctx, "yubikey", "000600000002"); err == nil {
		t.Fatal("local-usb evidence for one device covered another")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := local.Establish(cancelled, "yubikey", "000600000001"); err == nil {
		t.Fatal("a cancelled context established a channel")
	}
}

func TestLocalTokenEvidenceExpires(t *testing.T) {
	// The local entry expires 2026-10-01; the secure-messaging one, two months later.
	channel := evidenceAt(t, mixedEvidence, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err := channel.LocalTokens().Establish(context.Background(), "yubikey", "000600000001"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired local-usb evidence was accepted: %v", err)
	}
	if err := channel.Establish(context.Background(), "hsm", "DENK0000001"); err != nil {
		t.Fatalf("the unexpired control was refused: %v", err)
	}
}

func TestEvidenceWithNoLocalTokenOffersNoLocalAttestation(t *testing.T) {
	onlySecure := `{"schema_version":1,"devices":[{"device_serial":"DENK0000001","verified_by":"custodian",
	  "verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"4.1",
	  "secure_messaging_established":true,"channel":"secure-messaging"}]}`
	channel := evidenceAt(t, onlySecure, time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC))
	if channel.LocalTokens() != nil {
		t.Fatal("evidence with no local-usb entry offered a local attestation: the daemon would serve the applet backend on nothing")
	}
	// Naming the default channel explicitly is the same claim as leaving it out.
	if err := channel.Establish(context.Background(), "hsm", "DENK0000001"); err != nil {
		t.Fatalf("an explicit secure-messaging entry was refused: %v", err)
	}
	var none *AttestedSecureChannel
	if none.LocalTokens() != nil {
		t.Fatal("no evidence at all offered a local attestation")
	}
}

func TestContradictoryOrUnknownChannelClaimsAreRefusedAtLoad(t *testing.T) {
	entry := func(extra string) string {
		return `{"schema_version":1,"devices":[{"device_serial":"000600000001","verified_by":"custodian",
		  "verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z",` + extra + `}]}`
	}
	if _, err := LoadSecureChannelEvidence(writeEvidence(t, entry(`"firmware":"5.7.4","secure_messaging_established":false,"channel":"local-usb"`)), time.Now); err != nil {
		t.Fatalf("the control entry does not load: %v", err)
	}
	for name, extra := range map[string]string{
		"local-usb together with established secure messaging": `"firmware":"5.7.4","secure_messaging_established":true,"channel":"local-usb"`,
		"an unknown channel":            `"firmware":"5.7.4","secure_messaging_established":false,"channel":"bluetooth"`,
		"a channel in another case":     `"firmware":"5.7.4","secure_messaging_established":false,"channel":"Local-USB"`,
		"local-usb with no firmware":    `"secure_messaging_established":false,"channel":"local-usb"`,
		"local-usb on a blank firmware": `"firmware":"  ","secure_messaging_established":false,"channel":"local-usb"`,
	} {
		if _, err := LoadSecureChannelEvidence(writeEvidence(t, entry(extra)), time.Now); err == nil {
			t.Fatalf("evidence claiming %s loaded", name)
		}
	}
}

// The driver opens an applet binding only when it was given a local attestation, and establishes
// it against that attestation and no other.
func TestTheAppletBackendIsOpenedOnlyOverItsOwnAttestation(t *testing.T) {
	ctx := context.Background()
	applet := registry.Binding{Backend: OpenPGPAppletBackend, DeviceID: "yubikey", DeviceSerial: openPGPSerial, TokenLabel: openPGPSigPIN}
	hsm := labelled("DENK0404144", "")

	secure, local := &recordingSecureChannel{}, &recordingSecureChannel{}
	module := yubiKeyAsOpenSCPresentsIt()
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), secure, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	// Not served until the attestation is handed over, and nothing was opened to find that out.
	if session, err := driver.Open(ctx, applet); err == nil || session != nil {
		t.Fatal("an applet binding opened with no local attestation")
	}
	if len(module.opened) != 0 {
		t.Fatalf("a session was opened on slot %v", module.opened)
	}
	if err := driver.ServeLocalTokens(nil); err == nil {
		t.Fatal("a nil local attestation was accepted")
	}
	if err := driver.ServeLocalTokens(local); err != nil {
		t.Fatal(err)
	}

	session, err := driver.Open(ctx, applet)
	if err != nil {
		t.Fatalf("the applet binding did not open: %v", err)
	}
	if err := session.EstablishSecureChannel(ctx); err != nil {
		t.Fatal(err)
	}
	if local.calls != 1 || secure.calls != 0 {
		t.Fatalf("applet: local attestation asked %d times, secure-messaging %d; want 1 and 0", local.calls, secure.calls)
	}
	session, err = driver.Open(ctx, hsm)
	if err != nil {
		t.Fatalf("the SmartCard-HSM binding did not open: %v", err)
	}
	if err := session.EstablishSecureChannel(ctx); err != nil {
		t.Fatal(err)
	}
	if local.calls != 1 || secure.calls != 1 {
		t.Fatalf("SmartCard-HSM: local attestation asked %d times, secure-messaging %d; want 1 and 1", local.calls, secure.calls)
	}

	// The applet is two tokens, so a binding with no label names neither (resolveSlot's rule, the
	// same for every backend); and a backend that is not a PKCS#11 token at all is never opened.
	unlabelled := applet
	unlabelled.TokenLabel = ""
	piv := applet
	piv.Backend = "yubikey-piv"
	opened := len(module.opened)
	for name, binding := range map[string]registry.Binding{"an applet binding with no label": unlabelled, "a PIV binding": piv} {
		if session, err := driver.Open(ctx, binding); err == nil || session != nil {
			t.Fatalf("%s opened", name)
		}
	}
	if len(module.opened) != opened {
		t.Fatal("a refused binding reached OpenSession")
	}
}

// countingDriver records whether the provider reached the token at all.
type countingDriver struct{ opens int }

func (driver *countingDriver) Open(context.Context, registry.Binding) (Session, error) {
	driver.opens++
	return nil, pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)
}
func (*countingDriver) Ready(context.Context) bool { return true }

// The applet is served for signing. Its capability row also lists unwrap; nothing but sign and the
// public-key read reaches the card, and no PIN is fetched for an operation that cannot be served.
func TestTheAppletBackendServesSigningAndNothingElse(t *testing.T) {
	driver := &countingDriver{}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	route := registry.Route{Algorithm: "ed25519", Binding: registry.Binding{
		Backend: OpenPGPAppletBackend, DeviceID: "yubikey", DeviceSerial: openPGPSerial, TokenLabel: openPGPSigPIN,
		ObjectID: "01", PublicKeySHA256: "sha256:" + strings.Repeat("a", 64), State: "active",
	}}
	for _, operation := range []string{"unwrap", "wrap", "key-agreement", "certificate-sign", "release-secret", "seal-envelope", "authenticate", ""} {
		if _, _, err := provider.Execute(context.Background(), route, operation, "regalia-envelope-v2", "", []byte("payload"), []byte("aad")); err == nil {
			t.Fatalf("%q was served on the applet backend", operation)
		}
	}
	// Nor any key but Ed25519: the token would sign with an RSA key, and the applet is not served
	// as a second home for what an HSM holds.
	for _, algorithm := range []string{"rsa2048", "rsa3072", "rsa4096", "p256", ""} {
		other := route
		other.Algorithm = algorithm
		for _, operation := range []string{"sign", "public-key"} {
			if _, _, err := provider.Execute(context.Background(), other, operation, "", "application/vnd.regalia.digest", []byte("digest"), nil); err == nil {
				t.Fatalf("%s on a %q key was served on the applet backend", operation, algorithm)
			}
		}
	}
	if driver.opens != 0 {
		t.Fatalf("the token was opened %d times for operations the applet backend does not serve", driver.opens)
	}
	// The control: sign and public-key do reach the driver (which fails here, as arranged).
	for _, operation := range []string{"sign", "public-key"} {
		before := driver.opens
		_, _, _ = provider.Execute(context.Background(), route, operation, "", "application/vnd.regalia.digest", []byte("digest"), nil)
		if driver.opens != before+1 {
			t.Fatalf("%q did not reach the driver, so the refusals above prove nothing", operation)
		}
	}
}
