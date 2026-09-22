package nitrokey

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/miekg/pkcs11"
)

// TestIdentityProbeAgainstRealToken runs the REAL TokenProbes.Fingerprint against a real PKCS#11
// token. It exists because issue #448 was diagnosed exactly here: every other test in this package
// substitutes fixedDevAuth, so the identity probe had never run against hardware in this
// repository, and both of its defects survived.
//
// It is gated and skips without the variables. A skip is honest here — the assertion is about a
// card, and there is no card in CI.
//
//	REGALIA_DEVAUTH_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
//	REGALIA_DEVAUTH_SERIAL=DENK0404144 \
//	  go test ./internal/backend/nitrokey/ -run TestIdentityProbeAgainstRealToken -v
//
// MEASURED ON DENK0404144 (Nitrokey HSM 2, fw 4.1), 2026-09-22, commissioned with one imported
// key and its certificate — the state a production card is in. With the pairing check:
//
//	Fingerprint() = "", ErrNoDeviceCertificate
//
// With the pairing check removed, on the SAME card, the SAME minute:
//
//	Fingerprint() = "sha256:338587905edcfd838d638cf57869f476d028254d33588b0584f8423708a08059"
//
// and `sha256sum` of the card's only certificate object — the imported key's, CN=probe-check —
// is 338587905edcfd838d638cf57869f476d028254d33588b0584f8423708a08059. The probe was presenting a
// KEY certificate as the device identity. Two cards holding the same imported key would have been
// indistinguishable, and rotating the key would have made one card look like a different device.
func TestIdentityProbeAgainstRealToken(t *testing.T) {
	modulePath := os.Getenv("REGALIA_DEVAUTH_MODULE")
	serial := os.Getenv("REGALIA_DEVAUTH_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_DEVAUTH_MODULE and REGALIA_DEVAUTH_SERIAL")
	}
	module := pkcs11.New(modulePath)
	if module == nil {
		t.Fatalf("PKCS#11 module unavailable: %s", modulePath)
	}
	if err := module.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	defer func() { _ = module.Finalize(); module.Destroy() }()

	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatalf("NewTokenProbes: %v", err)
	}

	fingerprint, err := probes.Fingerprint(context.Background(), "bench", serial)
	t.Logf("Fingerprint() = %q, err = %v", fingerprint, err)

	switch {
	case err == nil:
		// An SC-HSM keeps C.DevAut in EF 2F02, so a fingerprint here means an UNPAIRED
		// certificate was found. That is legitimate on a token that does expose one — but it must
		// never be the imported key's, which is what the pairing check now prevents.
		if fingerprint == "" {
			t.Fatal("no error and no fingerprint")
		}
		t.Logf("this token exposes an unpaired certificate as its identity")
	case errors.Is(err, ErrNoDeviceCertificate):
		t.Logf("this token exposes no device certificate through PKCS#11, which is what an " +
			"SC-HSM does — the caller must read EF 2F02 (see hsm-devaut-read.sh in regalia-ceremony)")
	default:
		t.Fatalf("the probe failed for a reason other than an absent certificate: %v", err)
	}

	// Whatever the identity answer, a commissioned card must still report its retry counter:
	// #448's control showed the rest of the provider works on SC-HSM hardware.
	remaining, err := probes.Remaining(context.Background(), "bench", serial)
	if err != nil {
		t.Fatalf("Remaining: %v", err)
	}
	t.Logf("Remaining() = %d", remaining)
	if remaining <= 0 {
		t.Fatalf("Remaining() = %d — refusing to leave a card at or below zero retries in a test", remaining)
	}
}
