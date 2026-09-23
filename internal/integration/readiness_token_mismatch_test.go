package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// regalia#48 ACCEPTANCE CRITERION 2, in software against a real PKCS#11 module: "a guest cannot
// become ready with a missing, wrong, or policy-mismatched token even if Proxmox boots it
// successfully." Proxmox only decides whether the GUEST boots; whether the daemon reports READY is
// registry.Ready over the backend's Healthy — so this drives exactly that path, with the production
// driver constructor and the real identity probes, from a manifest, and asks Ready.
//
// What it cannot show is the Proxmox half (a re-enumerated device, a changed bus number, a host
// reboot); those are #48's hardware drills. What it does show is that no combination of token
// the host might hand the guest makes the daemon claim readiness it does not have.
func TestAGuestIsNotReadyWithAMissingWrongOrMismatchedToken(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	ctx := context.Background()

	// Commissioning, simulated: the real public-key pin of object 01 on this token.
	probe, err := nitrokey.NewPKCS11DriverWithProbes(modulePath, secureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	session, err := probe.Open(ctx, registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "probe", DeviceSerial: serial, ObjectID: "01"})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	public, err := session.PublicKey(ctx, "01")
	_ = session.Close()
	_ = probe.Close()
	if err != nil {
		t.Fatalf("read the commissioned public key: %v", err)
	}
	sum := sha256.Sum256(public)
	goodPin := "sha256:" + hex.EncodeToString(sum[:])
	otherPin := "sha256:" + hex.EncodeToString(make([]byte, 32))

	ready := func(t *testing.T, pins string) bool {
		t.Helper()
		// A fresh driver and provider per case: a quarantine is sticky by design, and one case's
		// latch must not decide the next case's answer.
		driver, err := nitrokey.NewPKCS11DriverWithProbes(modulePath, secureChannel{})
		if err != nil {
			t.Fatal(err)
		}
		// Closed before the next case opens one: PKCS#11 is initialised once per process, so a
		// driver left open until test cleanup makes every later case fail to initialise.
		defer driver.Close()
		provider, err := nitrokey.New(driver, pinSource{value: []byte("never-read-by-readiness")})
		if err != nil {
			t.Fatal(err)
		}
		hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
		if err != nil {
			t.Fatal(err)
		}
		manifest := fmt.Sprintf(`{
      "schema_version":1,"manifest_id":"readiness","generated_at":"2026-09-23T12:00:00Z",
      "objects":[{"id":"readiness-key","name":"Readiness","kind":"asymmetric-key","classification":"restricted","environment":"development",
      "owner":"security","purpose":"e2e-signing","custody":"direct-hardware","algorithm":"secp256k1",
      "operations":["sign"],"policy_id":"e2e-policy","bindings":[{"site":"e2e-site","backend":"nitrokey-pkcs11",
      "device_id":"hsm-e2e",%s,
      "public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],
      "recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`, pins)
		router, err := registry.Load(bytes.NewBufferString(manifest), "e2e-site", hardware)
		if err != nil {
			t.Fatalf("manifest refused at load: %v", err)
		}
		return router.Ready(ctx)
	}

	// KNOWN-GOOD FIRST: without it every "not ready" below could be a daemon that is never ready.
	if !ready(t, fmt.Sprintf(`"device_serial":%q,"object_id":"01","public_key_sha256":%q`, serial, goodPin)) {
		t.Fatal("the commissioned token, correctly pinned, was not ready — the refusals below would prove nothing")
	}
	for _, row := range []struct{ name, pins string }{
		{"missing token: no slot carries the pinned serial", fmt.Sprintf(`"device_serial":"ABSENT-SERIAL","object_id":"01","public_key_sha256":%q`, goodPin)},
		{"wrong token: the pinned key is not the key on this one", fmt.Sprintf(`"device_serial":%q,"object_id":"01","public_key_sha256":%q`, serial, otherPin)},
		{"policy-mismatched: the bound object is not on the token", fmt.Sprintf(`"device_serial":%q,"object_id":"7e","public_key_sha256":%q`, serial, goodPin)},
		{"a DevAut pin the token cannot answer", fmt.Sprintf(`"device_serial":%q,"object_id":"01","devaut_fingerprint":%q`, serial, otherPin)},
	} {
		t.Run(row.name, func(t *testing.T) {
			if ready(t, row.pins) {
				t.Fatal("DEFECT: the daemon reported READY for a token it cannot prove is the commissioned one")
			}
		})
	}
}
