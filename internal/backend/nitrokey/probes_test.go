package nitrokey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

type probeModule struct {
	fakeCryptoki
	slots     []uint
	infos     map[uint]pkcs11.TokenInfo
	certs     [][]byte
	lastClass uint
	findErr   error
	openErr   error
	closedBy  int
	// Error hooks for the PKCS#11 calls TokenProbes makes. Defaults preserve the
	// happy-path behavior; setting any of them turns the named call into the
	// failing path the production guard exists to handle.
	slotErr      error
	tokenInfoErr error
	attrErr      error
	attrEmpty    bool
	// tokenInfoErrOnSecondCall makes GetTokenInfo return tokenInfoErr starting from the
	// second invocation. slotFor's call is the first (so the slot resolves), and Remaining's
	// own call is the second — the only way a unit test can reach the production guard at
	// probes.go's GetTokenInfo err site, since slotFor's "matches != 1" would otherwise mask
	// the error first.
	tokenInfoErrOnSecondCall bool
	tokenInfoCalls           int
}

func (module *probeModule) GetSlotList(bool) ([]uint, error) {
	return module.slots, module.slotErr
}
func (module *probeModule) GetTokenInfo(slot uint) (pkcs11.TokenInfo, error) {
	module.tokenInfoCalls++
	if module.tokenInfoErr != nil && (!module.tokenInfoErrOnSecondCall || module.tokenInfoCalls >= 2) {
		return pkcs11.TokenInfo{}, module.tokenInfoErr
	}
	return module.infos[slot], nil
}
func (module *probeModule) OpenSession(uint, uint) (pkcs11.SessionHandle, error) {
	return 1, module.openErr
}
func (module *probeModule) CloseSession(pkcs11.SessionHandle) error { module.closedBy++; return nil }

// THE CLASS AND THE TEMPLATE ARE HONOURED. This fixture used to return the certificate handles
// for EVERY FindObjects call whatever class was asked for, and to answer every
// GetAttributeValue with CKA_VALUE whatever was requested. A probe that asks "which key ids are
// on this token?" was therefore handed certificates, and their CKA_ID came back as certificate
// bytes — so every certificate looked paired with itself. A model that answers questions it was
// not asked cannot tell a correct probe from an incorrect one.
func (module *probeModule) FindObjectsInit(_ pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	module.lastClass = 0
	for _, attribute := range template {
		if attribute != nil && attribute.Type == pkcs11.CKA_CLASS && len(attribute.Value) > 0 {
			module.lastClass = nativeUint(attribute.Value)
		}
	}
	return module.findErr
}
func (module *probeModule) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	if module.lastClass != pkcs11.CKO_CERTIFICATE {
		// These tokens carry certificates and no keys, which is what a device certificate looks
		// like when it is the only object on the card.
		return nil, false, nil
	}
	handles := make([]pkcs11.ObjectHandle, len(module.certs))
	for i := range module.certs {
		handles[i] = pkcs11.ObjectHandle(i + 1)
	}
	return handles, false, nil
}
func (module *probeModule) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }
func (module *probeModule) GetAttributeValue(_ pkcs11.SessionHandle, object pkcs11.ObjectHandle, template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if module.attrErr != nil {
		return nil, module.attrErr
	}
	if module.attrEmpty {
		return []*pkcs11.Attribute{}, nil
	}
	index := int(object) - 1
	if index < 0 || index >= len(module.certs) {
		return nil, os.ErrNotExist
	}
	out := make([]*pkcs11.Attribute, 0, len(template))
	for _, attribute := range template {
		switch attribute.Type {
		case pkcs11.CKA_VALUE:
			out = append(out, pkcs11.NewAttribute(pkcs11.CKA_VALUE, module.certs[index]))
		case pkcs11.CKA_ID:
			// Distinct per certificate, and never equal to a key id here because these tokens
			// carry no keys.
			out = append(out, pkcs11.NewAttribute(pkcs11.CKA_ID, []byte{byte(index + 1)}))
		}
	}
	return out, nil
}

func moduleWithToken(serial string, flags uint) *probeModule {
	return &probeModule{
		slots: []uint{7},
		infos: map[uint]pkcs11.TokenInfo{7: {SerialNumber: serial, Flags: flags}},
	}
}

// THE RETRY COUNT UNDER-REPORTS ON PURPOSE. PKCS#11 exposes three coarse states, not a counter, and
// the provider refuses to attempt a login when the count is low — so under-reporting can only stop
// work early, never spend a retry the caller believed it had.
func TestRetryProbeMapsTokenFlagsConservatively(t *testing.T) {
	cases := []struct {
		name  string
		flags uint
		want  int
	}{
		{"healthy", 0, 3},
		{"count low", pkcs11.CKF_USER_PIN_COUNT_LOW, 2},
		{"final try", pkcs11.CKF_USER_PIN_FINAL_TRY, 1},
		{"locked", pkcs11.CKF_USER_PIN_LOCKED, 0},
		{"locked wins over count low", pkcs11.CKF_USER_PIN_LOCKED | pkcs11.CKF_USER_PIN_COUNT_LOW, 0},
		{"final try wins over count low", pkcs11.CKF_USER_PIN_FINAL_TRY | pkcs11.CKF_USER_PIN_COUNT_LOW, 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			probes, err := NewTokenProbes(moduleWithToken("serial-1", test.flags))
			if err != nil {
				t.Fatal(err)
			}
			got, err := probes.Remaining(context.Background(), "hsm", "serial-1")
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("Remaining() = %d, want %d", got, test.want)
			}
		})
	}
}

// An unknown or duplicated serial is not resolved by position.
func TestProbesRefuseAnAmbiguousOrAbsentDevice(t *testing.T) {
	probes, _ := NewTokenProbes(moduleWithToken("serial-1", 0))
	if _, err := probes.Remaining(context.Background(), "hsm", "serial-2"); err == nil {
		t.Fatal("an absent device reported a retry count")
	}

	duplicate := &probeModule{slots: []uint{1, 2}, infos: map[uint]pkcs11.TokenInfo{
		1: {SerialNumber: "same"}, 2: {SerialNumber: "same"},
	}}
	probes, _ = NewTokenProbes(duplicate)
	if _, err := probes.Remaining(context.Background(), "hsm", "same"); err == nil {
		t.Fatal("two devices with one serial were resolved by position")
	}
}

// The fingerprint is taken over the certificate the card actually presents.
func TestFingerprintHashesThePresentedCertificate(t *testing.T) {
	certificate := []byte("device-authentication-certificate")
	module := moduleWithToken("serial-1", 0)
	module.certs = [][]byte{certificate}

	probes, _ := NewTokenProbes(module)
	got, err := probes.Fingerprint(context.Background(), "hsm", "serial-1")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(certificate)
	if want := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("Fingerprint() = %s, want %s", got, want)
	}
	if module.closedBy == 0 {
		t.Fatal("the probe session was not closed")
	}
}

// Ambiguity must not be resolved by taking the first certificate.
func TestFingerprintRefusesAmbiguousOrMissingCertificates(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.certs = [][]byte{[]byte("one"), []byte("two")}
	probes, _ := NewTokenProbes(module)
	if _, err := probes.Fingerprint(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("two device certificates produced a fingerprint")
	}

	module.certs = nil
	if _, err := probes.Fingerprint(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("a token with no device certificate produced a fingerprint")
	}
}

func writeEvidence(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "channel.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// THE ATTESTATION FAILS CLOSED IN EVERY DIRECTION. It is a dated operator claim, not a runtime
// proof, so the ways it can go stale or be misapplied are exactly what must be checked.
func TestSecureChannelEvidenceFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	valid := `{"schema_version":1,"devices":[{"device_serial":"serial-1","verified_by":"custodian",
	  "verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z",
	  "firmware":"6.6","secure_messaging_established":true}]}`

	channel, err := LoadSecureChannelEvidence(writeEvidence(t, valid), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Establish(context.Background(), "hsm", "serial-1"); err != nil {
		t.Fatalf("valid evidence was refused: %v", err)
	}
	// One device's evidence never covers another.
	if err := channel.Establish(context.Background(), "hsm", "serial-2"); err == nil {
		t.Fatal("evidence for one device covered a different device")
	}

	expired := `{"schema_version":1,"devices":[{"device_serial":"serial-1","verified_by":"custodian",
	  "verified_at":"2026-01-01T00:00:00Z","expires_at":"2026-02-01T00:00:00Z",
	  "firmware":"6.6","secure_messaging_established":true}]}`
	channel, err = LoadSecureChannelEvidence(writeEvidence(t, expired), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := channel.Establish(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("expired evidence was accepted")
	}

	negative := `{"schema_version":1,"devices":[{"device_serial":"serial-1","verified_by":"custodian",
	  "verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z",
	  "firmware":"6.6","secure_messaging_established":false}]}`
	channel, _ = LoadSecureChannelEvidence(writeEvidence(t, negative), func() time.Time { return now })
	if err := channel.Establish(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("evidence recording NO secure messaging was accepted")
	}

	for name, body := range map[string]string{
		"unknown field":       `{"schema_version":1,"devices":[],"extra":true}`,
		"no devices":          `{"schema_version":1,"devices":[]}`,
		"wrong schema":        `{"schema_version":2,"devices":[{"device_serial":"s","verified_by":"c","verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"6.6","secure_messaging_established":true}]}`,
		"expires before made": `{"schema_version":1,"devices":[{"device_serial":"s","verified_by":"c","verified_at":"2026-12-01T00:00:00Z","expires_at":"2026-09-01T00:00:00Z","firmware":"6.6","secure_messaging_established":true}]}`,
		"missing verifier":    `{"schema_version":1,"devices":[{"device_serial":"s","verified_by":"","verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"6.6","secure_messaging_established":true}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSecureChannelEvidence(writeEvidence(t, body), func() time.Time { return now }); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}

	// No evidence at all is a refusal, not a default.
	var empty *AttestedSecureChannel
	if err := empty.Establish(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("a nil attestation established a channel")
	}
}

// THE PKCS#11 ERROR SURFACE IS PROPAGATED, NOT SWALLOWED. Each guard exists to refuse
// a specific failure path; if a guard is removed the probe either returns a misleading
// success or panics on a nil dereference. Both make the test fail.

func TestRemainingPropagatesGetSlotListError(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.slotErr = errors.New("pkcs11 enumeration failed")
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	got, err := probes.Remaining(context.Background(), "hsm", "serial-1")
	if err == nil {
		t.Fatalf("GetSlotList error was swallowed: got retries=%d", got)
	}
	if !strings.Contains(err.Error(), "enumeration") {
		t.Fatalf("expected enumeration error, got %q", err)
	}
}

func TestRemainingPropagatesContextCancellation(t *testing.T) {
	probes, err := NewTokenProbes(moduleWithToken("serial-1", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := probes.Remaining(ctx, "hsm", "serial-1"); err == nil {
		t.Fatalf("cancelled context was ignored: got retries=%d", got)
	}
}

func TestRemainingPropagatesTokenInfoError(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.tokenInfoErr = errors.New("token info unavailable")
	module.tokenInfoErrOnSecondCall = true
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := probes.Remaining(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatalf("GetTokenInfo error was swallowed: got retries=%d", got)
	}
}

func TestFingerprintPropagatesContextCancellation(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.certs = [][]byte{[]byte("device-auth-certificate")}
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probes.Fingerprint(ctx, "hsm", "serial-1"); err == nil {
		t.Fatal("cancelled context was ignored")
	}
}

func TestFingerprintPropagatesOpenSessionError(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.certs = [][]byte{[]byte("device-auth-certificate")}
	module.openErr = errors.New("session unavailable")
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probes.Fingerprint(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("OpenSession error was swallowed")
	}
}

func TestFingerprintPropagatesFindObjectsInitError(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	// module.certs is set so the FindObjects handle list is non-empty — without the guard the
	// probe would silently proceed to the certificate read and return a fingerprint.
	module.certs = [][]byte{[]byte("device-auth-certificate")}
	module.findErr = errors.New("find init failed")
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probes.Fingerprint(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("FindObjectsInit error was swallowed")
	}
}

func TestFingerprintPropagatesAttributeValueError(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.certs = [][]byte{[]byte("device-auth-certificate")}
	module.attrErr = errors.New("attribute unreadable")
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := probes.Fingerprint(context.Background(), "hsm", "serial-1"); err == nil {
		t.Fatal("GetAttributeValue error was swallowed")
	}
}

// An empty certificate list is "not present", not "ambiguous". The two messages dispatch
// the operator to different places, so the wording is load-bearing — when the FindObjects
// guard at probes.go:107-111 is bypassed, the next guard at :113-115 reports "ambiguous"
// for what is structurally an empty result.
func TestFingerprintMissingCertificateReportsNotPresent(t *testing.T) {
	module := moduleWithToken("serial-1", 0)
	module.certs = nil
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	got, err := probes.Fingerprint(context.Background(), "hsm", "serial-1")
	if err == nil {
		t.Fatalf("empty certificate list produced a fingerprint: %q", got)
	}
	// TYPED, not phrased. The caller that matters here is the one deciding whether to fall back to
	// EF 2F02 — where an SC-HSM actually keeps its device certificate — and it cannot make that
	// decision on a substring. errors.Is is what it checks.
	if !errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatalf("expected ErrNoDeviceCertificate, got %q", err)
	}
	if !strings.Contains(err.Error(), "EF 2F02") {
		t.Fatalf("the message does not say where the certificate actually lives: %q", err)
	}
}

// A document that names the same device twice is an integrity violation — refuse it.
// Measurement: when the guard at securechannel.go:101-103 is bypassed, the second entry
// silently wins (entries[serial] = device), so an attacker who can edit the evidence file
// can append a second entry for an existing device that flips secure_messaging_established.
// The diagnostic below prints which entry survived when the loader fails to refuse.
func TestSecureChannelEvidenceRefusesDuplicateSerials(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	body := `{"schema_version":1,"devices":[
		{"device_serial":"serial-1","verified_by":"custodian","verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"6.6","secure_messaging_established":true},
		{"device_serial":"serial-1","verified_by":"custodian","verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"6.6","secure_messaging_established":false}
	]}`
	channel, err := LoadSecureChannelEvidence(writeEvidence(t, body), func() time.Time { return now })
	if err == nil {
		for _, ev := range channel.entries {
			if ev.DeviceSerial == "serial-1" {
				t.Logf("MEASUREMENT: duplicate accepted, surviving entry has SecureMsg=%v", ev.SecureMsg)
				break
			}
		}
		t.Fatal("duplicate serial was accepted")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Fatalf("expected 'twice' message, got %q", err)
	}
}

// The 64 KiB evidence-file cap is a DoS / memory bound. The LimitReader returns at most
// maximumEvidenceBytes+1 bytes, and the check at securechannel.go:157-159 distinguishes
// "we hit the cap" (the size-bound failure) from "the truncated bytes don't parse"
// (the malformed-JSON failure). Without the size check, an oversized document returns
// "is malformed" instead of "exceeds 64 KiB" — different operator message, same end state.
func TestSecureChannelEvidenceRefusesOversized(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	padding := strings.Repeat("x", 70<<10)
	body := fmt.Sprintf(`{"schema_version":1,"devices":[{"device_serial":"%s","verified_by":"custodian","verified_at":"2026-09-01T00:00:00Z","expires_at":"2026-12-01T00:00:00Z","firmware":"6.6","secure_messaging_established":true}]}`, padding)
	_, err := LoadSecureChannelEvidence(writeEvidence(t, body), func() time.Time { return now })
	if err == nil {
		t.Fatal("oversized evidence was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-cap message, got %q", err)
	}
}

// Malformed JSON must surface as "malformed", not as a downstream message from a guard
// that didn't see it. Without securechannel.go:80-82, the document is zero-valued and the
// next guard (SchemaVersion != 1) reports "names no device" — which sends the operator
// to a different remedy.
func TestSecureChannelEvidenceMalformedReportsMalformed(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	_, err := LoadSecureChannelEvidence(writeEvidence(t, `{`), func() time.Time { return now })
	if err == nil {
		t.Fatal("malformed JSON was accepted")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("expected 'malformed' message, got %q", err)
	}
}
