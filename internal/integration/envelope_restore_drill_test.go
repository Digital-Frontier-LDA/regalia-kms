package integration_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// regalia#6 ACCEPTANCE CRITERION 4, as a DRILL: "backup and restore work without depending on the
// original token." An envelope sealed to a hardware KEK must open after that token is WIPED and the
// KEK is restored from its DKEK-wrapped backup — the restored card is, to the daemon, a replacement.
//
// Driven in three phases by e2e/nitrokey-envelope-restore-drill.sh, which does the destructive steps
// between them with sc-hsm-tool (initialise, DKEK import, --unwrap-key):
//
//	seal          before the wipe: seal an envelope through the production seal path and record it,
//	              with the KEK's commissioned public-key pin (ADR-0002 D1), in REGALIA_ENVDRILL_STATE.
//	open-refused  after the wipe, BEFORE the key is restored: the envelope must NOT open. Without this
//	              negative control, "open" could pass against a card that was never actually wiped.
//	open          after the DKEK restore: the SAME pin must match the restored key, and the envelope
//	              must release byte-identical.
//
// The production driver constructor and the real identity probes are used throughout; the binding
// is pinned by serial and public_key_sha256, exactly as a Nitrokey is bound in production.
func TestEnvelopeSurvivesTokenWipeAndDKEKRestore(t *testing.T) {
	phase, module, serial := os.Getenv("REGALIA_ENVDRILL_PHASE"), os.Getenv("REGALIA_ENVDRILL_MODULE"), os.Getenv("REGALIA_ENVDRILL_SERIAL")
	objectID, pin, state := os.Getenv("REGALIA_ENVDRILL_OBJECT_ID"), os.Getenv("REGALIA_ENVDRILL_PIN"), os.Getenv("REGALIA_ENVDRILL_STATE")
	if phase == "" || module == "" || serial == "" || objectID == "" || pin == "" || state == "" {
		t.Skip("driven by e2e/nitrokey-envelope-restore-drill.sh")
	}
	ctx := context.Background()
	driver, err := nitrokey.NewPKCS11DriverWithProbes(module, secureChannel{})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := nitrokey.New(driver, pinSource{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(state, "envelope-drill.json")
	type drillRecord struct {
		PublicKeySHA256 string `json:"public_key_sha256"`
		Envelope        []byte `json:"envelope"`
		SecretSHA256    string `json:"secret_sha256"`
		Secret          []byte `json:"secret"` // test data, generated for this drill
	}
	route := func(pinned string) registry.Route {
		return registry.Route{
			ObjectID: "drill-deployment-token", Purpose: "deployment-api", Environment: "staging",
			Algorithm: "opaque", KEKAlgorithm: "rsa2048", KEKVersion: "1",
			Binding: registry.Binding{
				Site: "drill", Backend: "nitrokey-pkcs11", DeviceID: "drill-nitrokey", DeviceSerial: serial,
				PublicKeySHA256: pinned, ObjectID: objectID, KEKAlgorithm: "rsa2048", KEKVersion: "1", State: "active",
			},
		}
	}
	release := func(r drillRecord) ([]byte, error) {
		releaser, err := secrets.NewReleaser(manager)
		if err != nil {
			t.Fatal(err)
		}
		out, _, err := releaser.Execute(ctx, route(r.PublicKeySHA256), "release-secret", "regalia-envelope-v2", "", r.Envelope, nil)
		return out, err
	}

	switch phase {
	case "seal":
		// Commissioning, as the ceremony does it: the pin is the SHA-256 of the KEK's public key.
		session, err := driver.Open(ctx, route("").Binding)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		public, err := session.PublicKey(ctx, objectID)
		_ = session.Close()
		if err != nil || len(public) == 0 {
			t.Fatalf("read the KEK public key: %v", err)
		}
		sum := sha256.Sum256(public)
		pinned := "sha256:" + hex.EncodeToString(sum[:])

		secret := make([]byte, 48)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		r := route(pinned)
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
			t.Fatalf("seal on the card failed: %v", err)
		}
		blob, err := sealed.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		// Release once BEFORE the wipe: an envelope that does not open on the original card proves
		// nothing about the restored one.
		rec := drillRecord{PublicKeySHA256: pinned, Envelope: blob, Secret: secret}
		got, err := release(rec)
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("the envelope does not open even on the ORIGINAL card (err=%v): the drill cannot start", err)
		}
		s := sha256.Sum256(secret)
		rec.SecretSHA256 = hex.EncodeToString(s[:])
		raw, _ := json.Marshal(rec)
		if err := os.WriteFile(record, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("sealed on %s object %s, KEK pinned %s; opens on the original card", serial, objectID, pinned)

	case "open-refused", "open":
		raw, err := os.ReadFile(record)
		if err != nil {
			t.Fatalf("no seal record from the seal phase: %v", err)
		}
		var rec drillRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		got, err := release(rec)
		if phase == "open-refused" {
			if err == nil {
				t.Fatal("DEFECT OR NO WIPE: the envelope opened on a card whose KEK has not been restored — either the card was not wiped, or something other than the card opened it")
			}
			// The refusal must be the RIGHT one: the card is reachable and its key is not the pinned one.
			// Any error at all used to count, and an unreachable card refuses too, which proves nothing
			// about the key (it happened: the first cross-card run, 2026-09-24, OpenSC's hidden slot).
			reason, _ := provider.QuarantineReason("drill-nitrokey")
			if reason != "public-key-mismatch" {
				t.Fatalf("refused, but not because the key differs (err=%v, quarantine=%q): the negative control proves nothing", err, reason)
			}
			t.Logf("refused as required before the restore (err=%v, quarantine=%q)", err, reason)
			return
		}
		if err != nil {
			t.Fatalf("RESTORE FAILED: the envelope sealed before the wipe does not open after the DKEK restore: %v", err)
		}
		s := sha256.Sum256(got)
		if !bytes.Equal(got, rec.Secret) || hex.EncodeToString(s[:]) != rec.SecretSHA256 {
			t.Fatal("the released secret is not the one sealed before the wipe")
		}
		t.Logf("envelope sealed before the wipe opened after the DKEK restore; the restored KEK matches the commissioned pin %s", rec.PublicKeySHA256)
	default:
		t.Fatalf("unknown phase %q", phase)
	}
}
