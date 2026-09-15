package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"
)

// THE DATA KEY IS ZEROED ON EVERY PATH THAT HOLDS IT (#6 criterion 3).
//
// Open, Seal and Rewrap each `defer zero(dataKey)`. Removing any one of those defers left the whole
// module green (the #6 acceptance audit, measured on b1219f1): the only zeroization test watched
// the plaintext Open hands its callback, never the key that decrypts it. retainingHardware keeps
// the exact slices the envelope code passes to and receives from the hardware, so each test can
// look at that memory after the call returns.
//
// NOT TESTED, AND WHY. Rewrap also calls zero(plaintext) on the content it authenticates, but that
// slice is allocated by aead.Open inside Rewrap and never leaves the function. No caller, callback
// or double can observe it, so from this package's boundary it is unobservable, not untested.
//
// Falsifiers, each the only failure in the package: delete `defer zero(dataKey)` in Seal, in Open,
// or in Rewrap.

type retainingHardware struct {
	*fakeHardware
	handedIn  [][]byte // the dataKey slices WrapKey received
	handedOut [][]byte // the dataKey slices UnwrapKey returned
	wasLive   bool     // a handed-in key was non-zero while the call held it
}

func (hardware *retainingHardware) WrapKey(ctx context.Context, ref KeyRef, dataKey, binding []byte) ([]byte, error) {
	hardware.handedIn = append(hardware.handedIn, dataKey)
	hardware.wasLive = hardware.wasLive || !bytes.Equal(dataKey, make([]byte, len(dataKey)))
	return hardware.fakeHardware.WrapKey(ctx, ref, dataKey, binding)
}

func (hardware *retainingHardware) UnwrapKey(ctx context.Context, ref KeyRef, wrapped, binding []byte) ([]byte, error) {
	dataKey, err := hardware.fakeHardware.UnwrapKey(ctx, ref, wrapped, binding)
	if err == nil {
		hardware.handedOut = append(hardware.handedOut, dataKey)
	}
	return dataKey, err
}

func retaining(keys map[string][]byte) *retainingHardware {
	return &retainingHardware{fakeHardware: hardware("nitrokey-pkcs11", keys)}
}

func allZero(value []byte) bool {
	return len(value) > 0 && bytes.Equal(value, make([]byte, len(value)))
}

var zeroizationContext = []byte("repository=infra/path=prod.yaml")

func sealForZeroization(t *testing.T, device Wrapper, version string) Envelope {
	t.Helper()
	envelope, err := Seal(context.Background(), device, KeyRef{Backend: device.Backend(), ID: "company-kek", Version: version},
		"deployment-api-token", zeroizationContext, []byte("top-secret-value"), rand.Reader, time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestSealZeroesTheDataKeyItHandedTheHardware(t *testing.T) {
	device := retaining(map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)})
	sealForZeroization(t, device, "1")
	if len(device.handedIn) != 1 || len(device.handedIn[0]) != 32 {
		t.Fatalf("expected one 32-byte data key handed to WrapKey, saw %d", len(device.handedIn))
	}
	// Control: the key was live while the hardware held it, so "all zero" below is the work of the
	// zeroization and not a key that was never filled.
	if !device.wasLive {
		t.Fatal("control failed: the data key was already zero when WrapKey received it")
	}
	if !allZero(device.handedIn[0]) {
		t.Fatalf("Seal returned with the data key still in memory: %x", device.handedIn[0])
	}
}

func TestOpenZeroesTheUnwrappedDataKeyOnSuccessAndOnFailure(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}

	t.Run("success", func(t *testing.T) {
		device := retaining(keys)
		envelope := sealForZeroization(t, device, "1")
		var sawPlaintext bool
		if err := envelope.Open(context.Background(), device, zeroizationContext, func(plaintext []byte) error {
			sawPlaintext = string(plaintext) == "top-secret-value"
			return nil
		}); err != nil || !sawPlaintext {
			t.Fatalf("control failed: Open did not release the plaintext: %v", err)
		}
		if len(device.handedOut) != 1 || !allZero(device.handedOut[0]) {
			t.Fatalf("Open returned with the unwrapped data key still in memory: %x", device.handedOut)
		}
	})

	t.Run("the content fails to authenticate after the key was unwrapped", func(t *testing.T) {
		device := retaining(keys)
		envelope := sealForZeroization(t, device, "1")
		envelope.Ciphertext[0] ^= 1
		if err := envelope.Open(context.Background(), device, zeroizationContext, func([]byte) error { return nil }); err == nil {
			t.Fatal("control failed: a corrupted ciphertext opened")
		}
		if len(device.handedOut) != 1 {
			t.Fatalf("control failed: the key was not unwrapped before the failure (%d unwraps)", len(device.handedOut))
		}
		if !allZero(device.handedOut[0]) {
			t.Fatalf("Open's failure path left the unwrapped data key in memory: %x", device.handedOut[0])
		}
	})
}

func TestRewrapZeroesTheDataKeyTheOldHardwareReturned(t *testing.T) {
	old := retaining(map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)})
	next := retaining(map[string][]byte{"company-kek:2": bytes.Repeat([]byte{2}, 32)})
	envelope := sealForZeroization(t, old, "1")
	if err := envelope.Rewrap(context.Background(), old, next, KeyRef{Backend: next.Backend(), ID: "company-kek", Version: "2"}, zeroizationContext); err != nil {
		t.Fatalf("control failed: rewrap: %v", err)
	}
	if len(old.handedOut) != 1 {
		t.Fatalf("control failed: expected one unwrap by the old hardware, saw %d", len(old.handedOut))
	}
	if !allZero(old.handedOut[0]) {
		t.Fatalf("Rewrap returned with the data key still in memory: %x", old.handedOut[0])
	}
}
