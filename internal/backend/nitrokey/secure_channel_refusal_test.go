package nitrokey

// A SECURE CHANNEL THAT WILL NOT ESTABLISH MUST STOP THE OPERATION, and nothing tested that.
// Defeating the refusal in pkcs11Session.EstablishSecureChannel left the entire kms module green
// — 25 packages, zero failures — while the provider signed over an unproven channel, declined to
// quarantine the device, and reported it healthy.
//
// It stayed invisible for the reason these gaps usually do, and the count matters: the package has
// TWO SecureChannel fakes — secureChannelStub and recordingSecureChannel — and BOTH return nil
// unconditionally. It is not that one fixture happened to be permissive; every channel the package
// can build establishes by construction, so no existing test could reach the refusal however it
// was written. The same shape as a binding helper that always supplies its pins, or a card fake
// that always returns a correctly sized key.
//
// The comment on the production guard already names the stake — "a channel that will not establish
// is a downgrade: everything after this would travel unprotected, so the key is latched rather
// than used over it". This is the test that holds it to that.

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type refusingSecureChannel struct{ calls int }

func (channel *refusingSecureChannel) Establish(context.Context, string, string) error {
	channel.calls++
	return errors.New("no attested evidence for this serial")
}

func secureChannelProvider(t *testing.T, channel SecureChannel) (*Provider, *fakeCryptoki) {
	t.Helper()
	bind := binding()
	module := &fakeCryptoki{serial: bind.DeviceSerial, signature: []byte("a-signature")}
	driver, err := newPKCS11Driver(module, devAuthProbe(bind.DevAuthFingerprint), channel, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider, module
}

func TestAChannelThatWillNotEstablishStopsTheOperationAndLatchesTheDevice(t *testing.T) {
	bind := binding()
	route := registry.Route{Algorithm: "rsa2048", Binding: bind}

	// ANCHOR: the identical construction with an establishing channel must be SERVED. Without it a
	// provider that refused everything would satisfy the gate below and this would pin nothing.
	served, _ := secureChannelProvider(t, secureChannelStub{})
	output, _, err := served.Execute(context.Background(), route, "sign", "", "application/octet-stream", []byte("payload"), nil)
	if err != nil || len(output) == 0 {
		t.Fatalf("anchor: Execute over an establishing channel = (%d bytes, %v), want a signature and no error — "+
			"if this fixture cannot sign, the refusal below proves nothing about the channel", len(output), err)
	}
	if _, latched := served.QuarantineReason(bind.DeviceID); latched {
		t.Fatal("anchor: the device was quarantined on a successful operation")
	}

	// GATE: the channel refuses. Everything after this point in Execute would travel unprotected.
	channel := &refusingSecureChannel{}
	provider, module := secureChannelProvider(t, channel)
	output, _, err = provider.Execute(context.Background(), route, "sign", "", "application/octet-stream", []byte("payload"), nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Execute over a channel that will not establish = (%d bytes, %v), want ErrUnavailable — "+
			"with the refusal removed this returns a signature and no error, over an unproven channel", len(output), err)
	}
	if len(output) != 0 {
		t.Fatalf("Execute returned %d bytes over an unestablished channel; nothing may leave the card on this path", len(output))
	}
	if channel.calls == 0 {
		t.Fatal("the channel was never asked to establish — the test is not reaching the guard it names")
	}
	// The card must not have been used at all. Signing and then discarding the result would still
	// have spent the operation on a downgraded link.
	if module.mechanism != 0 {
		t.Fatalf("a signing mechanism was initialised (%#x) despite the channel refusing", module.mechanism)
	}

	// LATCHED, not merely refused: the reason is what tells an operator this was a downgrade rather
	// than an outage, and a device that keeps answering must not be retried over the same link.
	reason, latched := provider.QuarantineReason(bind.DeviceID)
	if !latched || reason != "secure-channel-failed" {
		t.Fatalf("QuarantineReason = (%q, %v), want (\"secure-channel-failed\", true)", reason, latched)
	}
	if provider.Healthy(context.Background(), bind) {
		t.Fatal("Healthy reported true over a channel that will not establish")
	}
}
