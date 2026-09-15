package nitrokey

import (
	"context"
	"testing"

	"github.com/miekg/pkcs11"
)

// #312. Healthy discarded its session close error while Execute treats the identical
// failure as fatal, so a token whose sessions cannot be closed was reported healthy and
// kept in rotation while every operation against it failed. That is the worst pairing of
// the two: the daemon believes the device is fine, routing keeps selecting it, and each
// attempt leaves behind whatever the failed close was meant to clean up — including, when
// C_Logout is the half that failed, an authenticated session on the card.
//
// The table drives both halves of pkcs11Session.Close's refusal (`logoutErr != nil ||
// closeErr != nil`) through this fake's single Close, because from Healthy's side they are
// one call and one error; token_failure_test.go already separates them at the driver.
//
// Every other session fake in this package returns nil from Close unconditionally, which
// is exactly why this guard had nothing that could fail it. A fake that makes the valid
// case convenient makes the invalid case unreachable — the same structural cause found in
// four other packages during #237.
func TestAHealthyProbeFailsWhenTheSessionWillNotClose(t *testing.T) {
	healthySession := func() *fakeSession {
		return &fakeSession{serial: binding().DeviceSerial, devaut: binding().DevAuthFingerprint, retries: 3}
	}

	// THE CONTROL, in the same run and through the same call. Without it every assertion
	// below would pass against a Healthy that returns false unconditionally, and none of
	// them would be evidence. It also proves `retries: 3` clears the retries > 1 clause,
	// so a refusal in the gate is not that clause firing.
	control := healthySession()
	provider, err := New(&fakeDriver{session: control}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !provider.Healthy(context.Background(), binding()) {
		t.Fatal("control: a session that closes cleanly was reported unhealthy — every assertion " +
			"below would pass against a Healthy that refuses everything")
	}

	for _, row := range []struct {
		name     string
		closeErr error
	}{
		// A real pkcs11.Error, not a lookalike string: once the driver inspects codes rather
		// than messages, a fixture built from errors.New would keep passing while meaning
		// nothing.
		{"C_CloseSession fails", pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)},
		{"C_Logout fails, leaving an authenticated session on the card", pkcs11.Error(pkcs11.CKR_DEVICE_REMOVED)},
	} {
		t.Run(row.name, func(t *testing.T) {
			// Identical to the control in every field but closeErr, so an unhealthy verdict
			// here is attributable to the close and to nothing else.
			session := healthySession()
			session.closeErr = row.closeErr
			provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			if provider.Healthy(context.Background(), binding()) {
				t.Fatalf("Healthy reported true although the session would not close (%v) — routing "+
					"keeps selecting a device on which Execute fails every request with "+
					"ErrUnavailable, so the fault is invisible in the health signal and shows up "+
					"only as unexplained operation failures", row.closeErr)
			}
			if !session.closed {
				t.Fatal("Healthy returned without calling Close at all; the verdict above would be " +
					"right for the wrong reason")
			}

			// THE CALIBRATION, and the reason this is not simply "make Healthy stricter".
			// quarantine() latches: only ResetPINBlock, an explicit operator action, clears
			// it. Identity mismatch and a secure channel that will not establish latch
			// because they mean the wrong device or a broken trust setup, and no amount of
			// retrying fixes either. A close failure may be transient, and Healthy is
			// re-evaluated on every routing decision with no cache, so returning false skips
			// the device exactly while it is failing. Latching here would turn a transient
			// fault into one that needs a human.
			if reason, blocked := provider.QuarantineReason(binding().DeviceID); blocked {
				t.Fatalf("a close failure latched the device as %q — quarantine is cleared only by "+
					"ResetPINBlock, so a transient close error would need an operator to undo, "+
					"which is a worse failure than the one being fixed", reason)
			}

			// And it must recover on its own. Same provider, same device, a session that
			// closes: the next routing decision has to find it healthy again, or "does not
			// quarantine" is a claim about the map rather than about behaviour.
			recovered := healthySession()
			provider.driver = &fakeDriver{session: recovered}
			if !provider.Healthy(context.Background(), binding()) {
				t.Fatal("the device stayed unhealthy after the close failure cleared — the refusal " +
					"is latched somewhere despite the quarantine map being empty")
			}
		})
	}
}
