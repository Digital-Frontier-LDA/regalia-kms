package nitrokey

// THE BINDING GUARD IN Execute HAD NO DETECTOR, while the identical guard in the yubikey
// provider has had one all along (TestABindingTheProviderCannotServeIsRefusedBeforeTheCardIsOpened
// in that package). Two providers, the same refusal, one tested — found by defeating each
// multi-line guard in the module in turn on 2026-09-07, the surface every mutation sweep in this
// campaign missed because its enumerators matched `if ... {` on a single line.
//
// What makes this testable is NOT the error. Every refusal in this provider returns
// ErrUnavailable, including the ones that happen after the card is open, so asserting the error
// class cannot distinguish "refused the manifest" from "opened a card and then failed". The
// assertion that carries the meaning is driver.opens == 0: a binding the provider cannot honour
// must not cause a session to be opened against real hardware at all.
//
// The two assertions kill disjoint sets of operands and neither is redundant. Measured
// 2026-09-07, defeating each of the five operands in turn:
//
//	backend / device id / object id  -> SERVED. err=nil, result="data-key". No downstream rule
//	                                    looks at these, so err is the only thing that catches them.
//	device serial / DevAut           -> refused, but AFTER opening a session. The identity pinning
//	                                    further down catches the substitution and returns the same
//	                                    ErrUnavailable, so only driver.opens catches these.
//
// Delete the opens check and the two identity rows pass while the provider is opening cards
// against manifests it cannot honour; assert only opens and the first three rows pass while the
// provider serves them.

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func TestABindingTheProviderCannotServeIsRefusedBeforeTheCardIsOpened(t *testing.T) {
	mutate := map[string]func(*registry.Binding){
		"another backend's binding": func(b *registry.Binding) { b.Backend = "yubikey-piv" },
		"no backend at all":         func(b *registry.Binding) { b.Backend = "" },
		"no device id":              func(b *registry.Binding) { b.DeviceID = "" },
		"no slot":                   func(b *registry.Binding) { b.ObjectID = "" },
		"no pinned serial":          func(b *registry.Binding) { b.DeviceSerial = "" },
		"no DevAut fingerprint":     func(b *registry.Binding) { b.DevAuthFingerprint = "" },
	}
	for name, apply := range mutate {
		t.Run(name, func(t *testing.T) {
			session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
			driver := &fakeDriver{session: session}
			provider, err := New(driver, &fakePIN{value: []byte("123456")})
			if err != nil {
				t.Fatal(err)
			}
			bad := binding()
			apply(&bad)

			result, _, execErr := provider.Execute(context.Background(),
				registry.Route{Algorithm: "rsa2048", Binding: bad},
				"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key",
				[]byte("wrapped"), []byte("context"))

			if !errors.Is(execErr, ErrUnavailable) {
				t.Fatalf("%s was served: err=%v result=%q — the manifest should never have loaded, and honouring it means the daemon acted on a binding it cannot fulfil", name, execErr, result)
			}
			// Before the card, not merely instead of the result. Opening a session against a
			// binding the provider cannot honour is already the wrong action, and it is the only
			// thing that distinguishes this guard from the identity checks further down, which
			// refuse with the same error after the card is open.
			if driver.opens != 0 {
				t.Fatalf("%s opened %d session(s) against the card before refusing", name, driver.opens)
			}
			if session.logged || session.secure {
				t.Fatalf("%s reached the card (logged=%v secure=%v)", name, session.logged, session.secure)
			}
		})
	}

	// §18 known-good: the unmodified binding must be served, or every row above would pass
	// against a provider that refuses everything.
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	driver := &fakeDriver{session: session}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key",
		[]byte("wrapped"), []byte("context")); err != nil || driver.opens != 1 {
		t.Fatalf("the unmodified binding was refused (err=%v opens=%d) — the rows above prove nothing", err, driver.opens)
	}
}
