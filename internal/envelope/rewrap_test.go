package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// Rewrap moves an envelope onto a new hardware KEK without touching its content ciphertext. Two
// properties make it safe to run over an estate, and neither was tested:
//
//	It PROVES the envelope opens before rewrapping. Unwrapping the data key is not enough — the
//	content AEAD is opened and the plaintext immediately zeroed, so a corrupted or tampered
//	envelope cannot be laundered onto a fresh KEK and carried forward looking healthy.
//
//	It mutates NOTHING on any failure path. The new KEK and wrapped key are assigned last, so a
//	refusal leaves an envelope that still opens under the key it already had. Assigning early
//	would leave envelopes openable by neither key, which is the one outcome worse than not
//	rotating.

const rewrapContext = "prod-context"

func rewrapFixture(t *testing.T) (*Envelope, *fakeHardware) {
	t.Helper()
	keys := map[string][]byte{
		"company-kek:1": bytes.Repeat([]byte{1}, 32),
		"company-kek:2": bytes.Repeat([]byte{2}, 32),
	}
	device := hardware("nitrokey-pkcs11", keys)
	sealed, err := Seal(context.Background(), device,
		KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		"deployment-api-token", []byte(rewrapContext), []byte("top-secret-value"),
		rand.Reader, time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return &sealed, device
}

func newKEK(device *fakeHardware) KeyRef {
	return KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "2"}
}

func TestARewrappedEnvelopeOpensUnderTheNewKeyAndNotTheOld(t *testing.T) {
	sealed, device := rewrapFixture(t)
	before := sealed.Clone()

	if err := sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte(rewrapContext)); err != nil {
		t.Fatalf("Rewrap() error = %v", err)
	}
	if sealed.KEK.Version != "2" {
		t.Fatalf("KEK version = %q, want 2", sealed.KEK.Version)
	}
	if bytes.Equal(sealed.WrappedDataKey, before.WrappedDataKey) {
		t.Fatal("the wrapped data key is unchanged: the envelope was relabelled rather than rewrapped, and the old KEK still opens it")
	}
	// The content is untouched — that is the point of rewrapping rather than resealing.
	if !bytes.Equal(sealed.Ciphertext, before.Ciphertext) || !bytes.Equal(sealed.Nonce, before.Nonce) {
		t.Fatal("Rewrap changed the content ciphertext")
	}
	// Compared INSIDE the callback. Open hands the plaintext to it and zeroes the buffer
	// afterwards; copying the value out to assert on it later would both contradict that design
	// and leave the secret in a second allocation this test never clears.
	saw := false
	if err := sealed.Open(context.Background(), device, []byte(rewrapContext), func(plaintext []byte) error {
		saw = bytes.Equal(plaintext, []byte("top-secret-value"))
		if !saw {
			t.Errorf("opened %d bytes that are not the sealed value", len(plaintext))
		}
		return nil
	}); err != nil {
		t.Fatalf("the rewrapped envelope does not open: %v", err)
	}
	if !saw {
		t.Fatal("the callback never ran, so nothing was compared")
	}

	// ...AND NOT THE OLD, which the name promises and nothing above establishes. An envelope
	// carrying the new wrapped key while still naming version 1 must not open: that is what makes
	// the rewrap a rebinding rather than a relabelling.
	//
	// TWO SEPARATE MECHANISMS FORBID IT and this case only exercises one. Here the versions are
	// different key material, so the unwrap fails on the key — measured: removing the version from
	// the wrap AAD leaves this green. The AAD binding is exercised by the test below, where both
	// versions share key material and the AAD is the only thing left distinguishing them.
	relabelled := sealed.Clone()
	relabelled.KEK = before.KEK
	err := relabelled.Open(context.Background(), device, []byte(rewrapContext), func([]byte) error {
		t.Error("the rewrapped data key opened under the OLD KEK: it is not bound to the new one")
		return nil
	})
	if err == nil {
		t.Fatal("an envelope naming the old KEK with the new wrapped key opened")
	}
}

// TestNoFailedRewrapMutatesTheEnvelope is the property that makes a bulk rotation safe to
// interrupt: whatever goes wrong, the envelope is exactly as it was and still opens under its
// current key.
func TestNoFailedRewrapMutatesTheEnvelope(t *testing.T) {
	// corrupt runs BEFORE the snapshot. Written the other way first, the "wrapped data key that
	// does not unwrap" case compared against a clone taken before its own corruption and reported
	// the difference IT had introduced as one Rewrap made. The snapshot has to be of the state
	// Rewrap is actually handed.
	for _, test := range []struct {
		name    string
		corrupt func(*Envelope)
		rewrap  func(*Envelope, *fakeHardware) error
		wants   error
	}{
		{"the wrong binding context", nil, func(sealed *Envelope, device *fakeHardware) error {
			return sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte("another-context"))
		}, ErrInvalidEnvelope},
		{"a new KEK the wrapper does not hold", nil, func(sealed *Envelope, device *fakeHardware) error {
			absent := KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "9"}
			return sealed.Rewrap(context.Background(), device, device, absent, []byte(rewrapContext))
		}, ErrBackendUnavailable},
		{"a new KEK naming another backend", nil, func(sealed *Envelope, device *fakeHardware) error {
			foreign := KeyRef{Backend: "yubikey-piv", ID: "company-kek", Version: "2"}
			return sealed.Rewrap(context.Background(), device, device, foreign, []byte(rewrapContext))
		}, ErrInvalidEnvelope},
		{"a tampered ciphertext", func(sealed *Envelope) { sealed.Ciphertext[0] ^= 0xff }, nil, ErrInvalidEnvelope},
		{"a wrapped data key that does not unwrap", func(sealed *Envelope) { sealed.WrappedDataKey[0] ^= 0xff }, nil, ErrBackendUnavailable},
		{"a binding context over the cap", func(sealed *Envelope) {
			sealed.ContextDigest = contextDigest(bytes.Repeat([]byte("a"), maxContextBytes+1))
		}, func(sealed *Envelope, device *fakeHardware) error {
			return sealed.Rewrap(context.Background(), device, device, newKEK(device), bytes.Repeat([]byte("a"), maxContextBytes+1))
		}, ErrInvalidEnvelope},
	} {
		t.Run(test.name, func(t *testing.T) {
			sealed, device := rewrapFixture(t)
			if test.corrupt != nil {
				test.corrupt(sealed)
			}
			before := sealed.Clone()

			rewrap := test.rewrap
			if rewrap == nil {
				rewrap = func(sealed *Envelope, device *fakeHardware) error {
					return sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte(rewrapContext))
				}
			}
			err := rewrap(sealed, device)
			if err == nil {
				t.Fatalf("Rewrap accepted %s", test.name)
			}
			if !errors.Is(err, test.wants) {
				t.Fatalf("%s: error = %v, want %v — an integrity failure and a backend failure are told apart by the caller's retry, so the wrong one either retries forever or gives up on a transient fault",
					test.name, err, test.wants)
			}
			if sealed.KEK != before.KEK {
				t.Fatalf("%s: the KEK moved to %+v on a failed rewrap — the envelope now names a key that did not wrap it and opens under neither",
					test.name, sealed.KEK)
			}
			if !bytes.Equal(sealed.WrappedDataKey, before.WrappedDataKey) {
				t.Fatalf("%s: the wrapped data key changed on a failed rewrap", test.name)
			}
			if !bytes.Equal(sealed.Ciphertext, before.Ciphertext) || !bytes.Equal(sealed.Nonce, before.Nonce) {
				t.Fatalf("%s: the content changed on a failed rewrap", test.name)
			}
		})
	}
}

// TestARewrapProvesTheContentOpensBeforeMovingIt. The tampered-ciphertext case above shows the
// refusal; this shows WHY it must be there. Unwrapping the data key succeeds on a corrupted
// envelope — the wrap covers the key, not the content — so without opening the content the
// corruption would be carried onto the new KEK and look freshly rotated.
func TestARewrapProvesTheContentOpensBeforeMovingIt(t *testing.T) {
	sealed, device := rewrapFixture(t)
	sealed.Ciphertext[len(sealed.Ciphertext)-1] ^= 0x01

	// The data key still unwraps: that is the point.
	if _, err := device.UnwrapKey(context.Background(), sealed.KEK, sealed.WrappedDataKey, sealed.wrapAAD(sealed.KEK)); err != nil {
		t.Fatalf("the fixture's data key does not unwrap (%v), so this test is not showing what it claims", err)
	}
	if err := sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte(rewrapContext)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Rewrap() error = %v, want ErrInvalidEnvelope: a corrupted envelope was moved onto a fresh KEK and would look freshly rotated", err)
	}
}

func TestRewrapOnANilEnvelopeIsRefusedRatherThanAPanic(t *testing.T) {
	var sealed *Envelope
	_, device := rewrapFixture(t)
	if err := sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte(rewrapContext)); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("error = %v, want ErrInvalidEnvelope", err)
	}
}

// TestTheWrapAADBindsTheKEKVersionEvenWhenTheKeysAreIdentical.
//
// Contrived on purpose: two KEK versions holding the same key material. On real hardware they are
// different keys and the unwrap fails on the key alone, which is what the test above shows — so
// the AAD's contribution is invisible there. Here it is the only thing left.
//
// It matters because the two protections have different lifetimes. Key separation depends on an
// operator actually generating a new key rather than re-importing the old one under a new version
// label, which is a mistake a ceremony can make. The AAD binding holds regardless.
func TestTheWrapAADBindsTheKEKVersionEvenWhenTheKeysAreIdentical(t *testing.T) {
	shared := bytes.Repeat([]byte{7}, 32)
	device := hardware("nitrokey-pkcs11", map[string][]byte{
		"company-kek:1": shared,
		"company-kek:2": shared,
	})
	sealed, err := Seal(context.Background(), device,
		KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		"deployment-api-token", []byte(rewrapContext), []byte("top-secret-value"),
		rand.Reader, time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	original := sealed.KEK
	if err := sealed.Rewrap(context.Background(), device, device, newKEK(device), []byte(rewrapContext)); err != nil {
		t.Fatalf("Rewrap() error = %v", err)
	}

	relabelled := sealed.Clone()
	relabelled.KEK = original
	if err := relabelled.Open(context.Background(), device, []byte(rewrapContext), func([]byte) error {
		return nil
	}); err == nil {
		t.Fatal("the rewrapped key opened under the old version despite identical key material: the wrap AAD is not binding the KEK version, so a re-imported key would silently accept envelopes from before the rotation")
	}
}
