package nitrokey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ADR-0002 D1. A genuine SmartCard-HSM keeps its device certificate in EF 2F02, which PKCS#11 cannot
// reach (regalia#448, measured on DENK0404144), so a binding for one pins the serial and the
// commissioned public key of the bound object instead. These tests pin what that must and must not
// allow. Every refusing case asserts it happened BEFORE login: a wrong card must never be handed
// the PIN.

func pinFor(public []byte) string {
	sum := sha256.Sum256(public)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// pinnedBinding is how a real Nitrokey HSM 2 is bound: serial + public-key pin, no DevAut.
func pinnedBinding(public []byte) registry.Binding {
	b := binding()
	b.DevAuthFingerprint = ""
	b.PublicKeySHA256 = pinFor(public)
	return b
}

func unwrapPinned(provider *Provider, b registry.Binding) ([]byte, error) {
	out, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: b},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	return out, err
}

func TestABindingPinnedByPublicKeyServesATokenThatExposesNoDevAut(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: ""} // what an SC-HSM reports
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	out, err := unwrapPinned(provider, pinnedBinding([]byte("public")))
	if err != nil || string(out) != "data-key" || !session.logged {
		t.Fatalf("a Nitrokey bound by serial + commissioned public key was refused: out=%q err=%v — every genuine SC-HSM would be unusable", out, err)
	}
	if _, blocked := provider.QuarantineReason("hsm-sitea"); blocked {
		t.Fatal("a correctly pinned device was quarantined")
	}
}

func TestAPublicKeyThatIsNotTheCommissionedOneIsQuarantinedBeforeLogin(t *testing.T) {
	session := &fakeSession{serial: "serial-1", publicKey: []byte("a different key")}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, err := unwrapPinned(provider, pinnedBinding([]byte("public"))); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if session.logged || session.loginCalls != 0 {
		t.Fatal("DEFECT: the PIN was presented to a card holding a key other than the commissioned one")
	}
	if reason, _ := provider.QuarantineReason("hsm-sitea"); reason != "public-key-mismatch" {
		t.Fatalf("quarantine reason = %q, want public-key-mismatch", reason)
	}
	// Sticky, like identity-mismatch: the next request does not re-open the question.
	session.publicKey = []byte("public")
	if _, err := unwrapPinned(provider, pinnedBinding([]byte("public"))); err == nil {
		t.Fatal("the latch cleared itself")
	}
}

func TestAnUnreadablePublicKeyIsRefusedLikeAWrongOne(t *testing.T) {
	for name, session := range map[string]*fakeSession{
		"read error":  {serial: "serial-1", publicKeyErr: errors.New("CKR_DEVICE_ERROR")},
		"empty bytes": {serial: "serial-1", publicKeyEmpty: true},
	} {
		t.Run(name, func(t *testing.T) {
			provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			if _, err := unwrapPinned(provider, pinnedBinding([]byte("public"))); err == nil || session.logged {
				t.Fatalf("err=%v logged=%v: 'cannot show this is the commissioned key' must refuse before login", err, session.logged)
			}
			if reason, _ := provider.QuarantineReason("hsm-sitea"); reason != "public-key-mismatch" {
				t.Fatalf("reason = %q", reason)
			}
		})
	}
}

// Pinning a DevAut keeps the strict check wherever it is possible: a token that exposes none
// reports "", which cannot equal the pin.
func TestAPinnedDevAutStillMustMatchWhenTheTokenExposesNone(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: ""}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, err := unwrapPinned(provider, binding()); err == nil || session.logged {
		t.Fatalf("a binding pinning a DevAut was served by a token exposing none: err=%v", err)
	}
	if reason, _ := provider.QuarantineReason("hsm-sitea"); reason != "identity-mismatch" {
		t.Fatalf("reason = %q, want identity-mismatch", reason)
	}
}

// Both pins present: both enforced. A right public key does not excuse a wrong DevAut.
func TestBothPinsAreEnforcedWhenBothArePresent(t *testing.T) {
	b := binding()
	b.PublicKeySHA256 = pinFor([]byte("public"))
	session := &fakeSession{serial: "serial-1", devaut: "sha256:" + strings.Repeat("b", 64)}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, err := unwrapPinned(provider, b); err == nil || session.logged {
		t.Fatal("a matching public key excused a mismatched DevAut")
	}
}

// A binding with NEITHER pin cannot be served at all, and is refused before the card is opened.
func TestABindingWithNeitherPinIsRefusedBeforeTheCardIsOpened(t *testing.T) {
	b := binding()
	b.DevAuthFingerprint, b.PublicKeySHA256 = "", ""
	driver := &fakeDriver{session: &fakeSession{serial: "serial-1"}}
	provider, _ := New(driver, &fakePIN{value: []byte("123456")})
	if _, err := unwrapPinned(provider, b); err == nil || driver.opens != 0 {
		t.Fatalf("err=%v opens=%d: a binding that pins nothing must not reach the card", err, driver.opens)
	}
	if provider.Healthy(context.Background(), b) {
		t.Fatal("a binding that pins nothing reported healthy")
	}
}

// THE WRAP GUARD (regalia#447): with the public key pinned, provenance was proven at commissioning
// from the card's attestation, so CKA_LOCAL — which on an SC-HSM tracks certificates, not birth —
// is not asked. Without the pin it still is.
func TestWrapTrustsCommissioningProvenanceOnlyWhenThePublicKeyIsPinned(t *testing.T) {
	key := wrappableKey(t)
	undeterminable := errors.New("provenance undeterminable on this device class")

	session := &fakeSession{serial: "serial-1", publicKey: key, notTokenGenerated: undeterminable}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: pinnedBinding(key)},
		"wrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("data-key"), []byte("aad")); err != nil {
		t.Fatalf("a pinned, commissioning-attested KEK was refused at wrap: %v", err)
	}

	control := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, publicKey: key, notTokenGenerated: undeterminable}
	unpinned, _ := New(&fakeDriver{session: control}, &fakePIN{value: []byte("123456")})
	if _, _, err := unpinned.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"wrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("data-key"), []byte("aad")); err == nil {
		t.Fatal("CONTROL: without a public-key pin the runtime provenance guard must still refuse")
	}
}

func TestHealthyChecksThePinToo(t *testing.T) {
	good := &fakeSession{serial: "serial-1", retries: 3, retriesSet: true}
	provider, _ := New(&fakeDriver{session: good}, &fakePIN{value: []byte("123456")})
	if !provider.Healthy(context.Background(), pinnedBinding([]byte("public"))) {
		t.Fatal("a correctly pinned device reported unhealthy")
	}
	bad := &fakeSession{serial: "serial-1", retries: 3, retriesSet: true, publicKey: []byte("other")}
	provider, _ = New(&fakeDriver{session: bad}, &fakePIN{value: []byte("123456")})
	if provider.Healthy(context.Background(), pinnedBinding([]byte("public"))) {
		t.Fatal("a device holding another key reported healthy — routing would keep sending it requests")
	}
	if reason, _ := provider.QuarantineReason("hsm-sitea"); reason != "public-key-mismatch" {
		t.Fatalf("reason = %q", reason)
	}
}
