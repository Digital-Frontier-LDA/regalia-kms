package nitrokey

import (
	"context"
	"testing"
)

// TestHealthyRefusesADeviceOneFailedPINFromLockout pins the retry-budget operand of Healthy.
//
// THE EXECUTE TWIN IS TESTED AND THE HEALTHY TWIN WAS NOT, AGAIN. This file already records one
// instance of that pair: TestHealthyRefusesWhenEstablishSecureChannelFails exists because "Healthy
// has the same channel-establishment guard as Execute, but the Healthy twin was the unverified half
// of the pair". The retry budget is the same pair, one guard along, and it was still unverified.
// TestLowRetryCountFailsBeforePINRetrievalOrLogin builds exactly the fixture this needs — a session
// with one retry left — and drives Execute with it, so the fixture existed and was pointed at the
// other method.
//
// What that leaves unpinned is the direction that matters. Widening the operand so any successful
// retry read counts as healthy leaves every existing test green, because they all use three or two
// retries and assert healthy. A device one failed PIN from locking would then be reported as a
// serving candidate, and routing would keep sending it work until it locked — which is the outcome
// the retry budget exists to avoid, and it is not recoverable without an operator and the SO PIN.
//
// Isolation: identity and secure channel both succeed and the retry read itself succeeds, so every
// other operand on the path is satisfied and only the count can refuse. The control row is two
// retries, the adjacent value on the other side of the boundary, so the row also says where the
// boundary is rather than merely that a low number is refused.
func TestHealthyRefusesADeviceOneFailedPINFromLockout(t *testing.T) {
	for _, test := range []struct {
		name    string
		retries int
		want    bool
	}{
		{"two retries left is still serving", 2, true},
		{"one retry left is one failed PIN from lockout", 1, false},
		{"no retries left", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &fakeSession{
				serial: binding().DeviceSerial,
				devaut: binding().DevAuthFingerprint,
				// retriesSet, because the fake reads a bare 0 as "unset" and answers 3 --
				// which made a fully spent card, the one state this guard exists for,
				// impossible to write down.
				retries:    test.retries,
				retriesSet: true,
			}
			provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatal(err)
			}

			got := provider.Healthy(context.Background(), binding())
			if got != test.want {
				t.Fatalf("DEFECT: a device with %d PIN retries remaining reported Healthy=%v, want %v; "+
					"routing keeps sending work to a device it believes is serving, and a lockout "+
					"needs an operator and the SO PIN to clear", test.retries, got, test.want)
			}

			// The refusal must come from the COUNT, not from a failed read: those are different
			// conditions with different operator responses, and Healthy returns the same bool for
			// both. The cached reading is what tells them apart -- notePINRetries only runs when
			// the read succeeded, so a recorded value proves the card answered.
			reading, ok := provider.PINRetriesReadings()[binding().DeviceID]
			if !ok || reading.Retries != test.retries {
				t.Fatalf("fixture is not isolated: PINRetriesReadings has %v, want a recorded %d. "+
					"Without a successful read this row would be refusing for the wrong reason",
					provider.PINRetriesReadings(), test.retries)
			}
		})
	}
}

// TestReadyOnANilProviderIsFalseNotAPanic pins the nil-receiver operand of Ready.
//
// Ready is reached through a readiness probe holding an interface value, and a *Provider that was
// never constructed sits in that interface as a typed nil rather than as an absent one -- so the
// method runs. Without the operand the very next read, provider.driver, dereferences nil and the
// health endpoint takes the process down instead of answering.
//
// The two operands after it, provider.driver != nil and provider.pins != nil, are deliberately NOT
// pinned: New refuses both ("Nitrokey driver and PIN source are required") and the fields are
// unexported, so no caller can produce a Provider that has one without the other. A test would have
// to hand-build a struct the constructor cannot return, which asserts a state nothing writes
// (TESTING.md §17). They are cheap defence in depth and this records why they stay unfalsified,
// rather than leaving them to be re-derived as gaps by the next sweep.
//
// Isolation: a nil receiver is the only thing wrong here; the control shows a properly constructed
// provider on the same path answers true, so a false below is the receiver and nothing else.
func TestReadyOnANilProviderIsFalseNotAPanic(t *testing.T) {
	live, err := New(&fakeDriver{session: &fakeSession{}}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if !live.Ready(context.Background()) {
		t.Fatal("control is broken, so the result below would prove nothing: a constructed provider " +
			"with a ready driver reported not ready")
	}

	var absent *Provider
	var ready bool
	panicked := func() (recovered any) {
		defer func() { recovered = recover() }()
		ready = absent.Ready(context.Background())
		return nil
	}()
	if panicked != nil {
		t.Fatalf("DEFECT: Ready on a nil *Provider panicked with %v; the readiness probe holds this "+
			"as an interface value, so the health endpoint crashes the process rather than "+
			"reporting not-ready", panicked)
	}
	if ready {
		t.Fatal("DEFECT: a nil *Provider reported ready, so a backend that was never constructed " +
			"reads as a serving one")
	}

	if _, err := New(nil, &fakePIN{value: []byte("123456")}); err == nil {
		t.Fatal("New accepted a nil driver, so the sibling operand IS reachable and the comment " +
			"above is wrong")
	}
	if _, err := New(&fakeDriver{session: &fakeSession{}}, nil); err == nil {
		t.Fatal("New accepted a nil PIN source, so the sibling operand IS reachable and the comment " +
			"above is wrong")
	}
}
