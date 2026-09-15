package nitrokey

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE SERIAL WAS PINNED AND THE ATTESTATION FINGERPRINT WAS NOT.
//
// Execute and Healthy each check three things about the device that answered: that the identity read
// succeeded, that the serial matches the binding, and that the DevAuth fingerprint matches. A sweep
// of both guards, in both directions, says the same thing about both call sites:
//
//	:134 / :309 op0  err != nil                             narrow SURVIVES
//	:134 / :309 op1  serial != binding.DeviceSerial         narrow killed
//	:134 / :309 op2  devaut != binding.DevAuthFingerprint   narrow SURVIVES
//
// The reason is visible in the fixtures rather than in the code. EVERY fakeSession in this package is
// built with `devaut: binding().DevAuthFingerprint` — the matching value. The two tests that vary
// identity at all vary the SERIAL and keep the fingerprint correct: observability_test.go uses
// `serial: "serial-WRONG"` and provider_test.go uses `serial: "substituted"`, both with the right
// devaut. So the fingerprint comparison has never been handed a value that could fail it.
//
// The two halves are not interchangeable. A serial is printed on the case and reported by any device
// that chooses to claim it; the DevAuth fingerprint is the attestation key's identity, which is what
// makes the commissioned card distinguishable from a substitute presenting the same serial. Pinning
// only the serial leaves the check that actually resists substitution unexercised.
//
// Isolation: the identity read succeeds and the serial matches, so neither sibling operand can
// account for the refusal, and the fingerprint is the only difference from the accepted control.
func TestExecuteAndHealthyRefuseADeviceWhoseAttestationFingerprintDiffers(t *testing.T) {
	const wrong = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if wrong == binding().DevAuthFingerprint {
		t.Fatal("fixture is not a mismatch: the wrong fingerprint equals the binding's")
	}

	newProvider := func(t *testing.T, devaut string) (*Provider, *fakeSession) {
		t.Helper()
		session := &fakeSession{serial: binding().DeviceSerial, devaut: devaut, retries: 3}
		provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
		if err != nil {
			t.Fatal(err)
		}
		return provider, session
	}
	route := registry.Route{Algorithm: "rsa2048", Binding: binding()}

	t.Run("Execute", func(t *testing.T) {
		// Control: the same session with the RIGHT fingerprint reaches the card, so a refusal
		// below cannot be blamed on anything else in the path.
		control, session := newProvider(t, binding().DevAuthFingerprint)
		if _, _, err := control.Execute(context.Background(), route, "unwrap",
			"regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context")); err != nil || session.loginCalls == 0 {
			t.Fatalf("control is broken, so the refusal below would prove nothing: a matching "+
				"fingerprint gave err=%v loginCalls=%d", err, session.loginCalls)
		}

		provider, session := newProvider(t, wrong)
		out, _, err := provider.Execute(context.Background(), route, "unwrap",
			"regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context"))
		if err == nil {
			t.Fatalf("DEFECT: a device whose DevAuth fingerprint is %q, not the binding's %q, served "+
				"an unwrap and returned %q; the serial it reports is the only identity being "+
				"checked, and a substitute can report any serial", wrong, binding().DevAuthFingerprint, out)
		}
		if session.loginCalls != 0 {
			t.Fatalf("DEFECT: the wrong device was logged into (%d calls) before being refused; the "+
				"identity check exists so no PIN is spent on a device that cannot prove what it is",
				session.loginCalls)
		}
		reason, latched := provider.QuarantineReason(binding().DeviceID)
		if !latched || reason != "identity-mismatch" {
			t.Fatalf("DEFECT: quarantine is latched=%v reason=%q, want true and %q — an identity "+
				"mismatch is a swap, not a glitch, and must latch the device out of service rather "+
				"than be retried", latched, reason, "identity-mismatch")
		}
	})

	t.Run("Healthy", func(t *testing.T) {
		control, _ := newProvider(t, binding().DevAuthFingerprint)
		if !control.Healthy(context.Background(), binding()) {
			t.Fatal("control is broken, so the refusal below would prove nothing: a device with a " +
				"matching fingerprint reported unhealthy")
		}

		provider, _ := newProvider(t, wrong)
		if provider.Healthy(context.Background(), binding()) {
			t.Fatalf("DEFECT: a device whose DevAuth fingerprint is %q reported healthy; routing "+
				"treats it as a serving candidate on the strength of a serial alone", wrong)
		}
		reason, latched := provider.QuarantineReason(binding().DeviceID)
		if !latched || reason != "identity-mismatch" {
			t.Fatalf("DEFECT: quarantine is latched=%v reason=%q, want true and %q",
				latched, reason, "identity-mismatch")
		}
	})
}

// TestAPINBeyondTheUpperBoundIsRefused pins the upper half of the PIN length check.
//
// The guard is `err != nil || len(pin) < 6 || len(pin) > 64`, and the sweep kills the error clause
// and the lower bound while the upper bound survives — every fixture in the package supplies a
// six-byte PIN, so the range is only ever approached from below. A bound tested from one side is not
// tested: widening it changes nothing any existing fixture can observe.
//
// It is worth having. The PIN is handed to the token's C_Login, and an over-long value is a
// misconfigured PIN source rather than a credential — sending it spends one of the retries the
// budget exists to protect, on an attempt that cannot succeed.
//
// Isolation: the source returns no error and the value is well above the lower bound, so neither
// sibling operand can fire. The 64-byte control sits exactly on the boundary and must be ACCEPTED,
// which is what makes this a bound rather than an assertion that long PINs are bad.
func TestAPINBeyondTheUpperBoundIsRefused(t *testing.T) {
	route := registry.Route{Algorithm: "rsa2048", Binding: binding()}
	run := func(t *testing.T, pin []byte) (*fakeSession, error) {
		t.Helper()
		session := &fakeSession{serial: binding().DeviceSerial, devaut: binding().DevAuthFingerprint, retries: 3}
		provider, err := New(&fakeDriver{session: session}, &fakePIN{value: pin})
		if err != nil {
			t.Fatal(err)
		}
		_, _, execErr := provider.Execute(context.Background(), route, "unwrap",
			"regalia-envelope-v2", "application/octet-stream", []byte("wrapped"), []byte("context"))
		return session, execErr
	}

	// Exactly at the bound: accepted, and the card is asked. Without this the test below would pass
	// against a guard that refused every PIN longer than six bytes.
	session, err := run(t, bytes.Repeat([]byte("a"), 64))
	if err != nil || session.loginCalls != 1 {
		t.Fatalf("control is broken: a 64-byte PIN, exactly the upper bound, gave err=%v "+
			"loginCalls=%d — the bound is `> 64`, so 64 must be accepted", err, session.loginCalls)
	}

	session, err = run(t, bytes.Repeat([]byte("a"), 65))
	if err == nil {
		t.Fatal("DEFECT: a 65-byte PIN was accepted; the guard's upper bound admits it and the " +
			"token is asked to spend a retry on a value that cannot be a valid PIN")
	}
	if session.loginCalls != 0 {
		t.Fatalf("DEFECT: an over-long PIN reached C_Login (%d calls), spending a retry from the "+
			"budget on an attempt that cannot succeed", session.loginCalls)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("refusal is %q, which does not match %v; the coordinator branches on that sentinel "+
			"to decide whether a request is retryable, and a string that merely reads the same does "+
			"not reach it", err, ErrUnavailable)
	}
}
