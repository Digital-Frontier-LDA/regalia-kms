package nitrokey

import (
	"context"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Eleven operands across the driver's construction and Open paths -- two in NewPKCS11Driver, four
// in newPKCS11Driver, three in Open's binding check, two in Close -- all surviving both the unit
// suite and the SoftHSM battery. None is reachable through the e2e, which builds one well-formed
// driver from a real module and opens one well-formed binding: every fixture that reaches this code
// is complete by construction, so nothing has ever handed it an incomplete one.
//
// They are worth having because this is the boundary where a misconfiguration becomes a nil
// dereference. The driver's dependencies are stored and called later, on the request path, so a nil
// that construction accepts does not fail here — it fails on the first operation, inside a deferred
// recover that reports ErrUnavailable, and the operator sees a backend that is unavailable rather
// than one that was never configured.

// TestNewPKCS11DriverRefusesAModulePathItCannotUse pins the exported constructor's two guards.
//
// Isolation is by MESSAGE, because both refusals return an error and only the text distinguishes
// them: a blank path is refused before the module is loaded at all, and a path that is not a loadable
// PKCS#11 module is refused after pkcs11.New returns nil. Asserting only "an error came back" would
// pass with either guard deleted, since the other still refuses both inputs.
func TestNewPKCS11DriverRefusesAModulePathItCannotUse(t *testing.T) {
	for _, test := range []struct {
		name, path, want string
	}{
		{"empty", "", "module path is required"},
		{"whitespace only", "   \t ", "module path is required"},
		{"a path that is not a loadable module", "/nonexistent/not-a-pkcs11-module.so", "module unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver, err := NewPKCS11Driver(test.path, fixedDevAuth("sha256:abc"),
				&recordingSecureChannel{}, fixedRetries(3))
			if err == nil {
				t.Fatalf("DEFECT: module path %q was accepted and produced driver %v", test.path, driver)
			}
			if driver != nil {
				t.Fatalf("DEFECT: refused with %v but still returned a driver; a caller that checks "+
					"the driver first would use one that was never configured", err)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal for %q is %q, want it to contain %q — the two guards return "+
					"different messages and that is the only thing telling them apart, so a test "+
					"asserting merely that an error came back passes with either one deleted",
					test.path, err.Error(), test.want)
			}
		})
	}
}

// TestTheDriverRefusesAnIncompleteConfiguration pins the four nil checks on the internal
// constructor.
//
// Each dependency is stored and used later, on the request path: devAuth on every Open to prove the
// device's identity, secure on every session to establish messaging, retries to read the PIN budget
// before spending it. A nil accepted here is not a construction failure, it is a nil dereference on
// the first operation — and the operation path recovers into ErrUnavailable, so the operator is told
// the backend is unavailable rather than that it was never configured.
//
// Isolation: exactly one dependency is nil per row, the other three are the same values the control
// uses, and the control is the identical call with all four supplied.
func TestTheDriverRefusesAnIncompleteConfiguration(t *testing.T) {
	module := &acceptingToken{}
	devAuth := fixedDevAuth("sha256:abc")
	secure := &recordingSecureChannel{}
	retries := fixedRetries(3)

	if driver, err := newPKCS11Driver(module, devAuth, secure, retries); err != nil || driver == nil {
		t.Fatalf("control is broken, so the refusals below would prove nothing: a complete "+
			"configuration gave driver=%v err=%v", driver, err)
	}

	for _, test := range []struct {
		name string
		call func() (*PKCS11Driver, error)
	}{
		{"no module", func() (*PKCS11Driver, error) {
			return newPKCS11Driver(nil, devAuth, secure, retries)
		}},
		{"no DevAuth probe", func() (*PKCS11Driver, error) {
			return newPKCS11Driver(module, nil, secure, retries)
		}},
		{"no secure channel", func() (*PKCS11Driver, error) {
			return newPKCS11Driver(module, devAuth, nil, retries)
		}},
		{"no PIN retry probe", func() (*PKCS11Driver, error) {
			return newPKCS11Driver(module, devAuth, secure, nil)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			driver, err := test.call()
			if err == nil {
				t.Fatalf("DEFECT: a driver built with %s was accepted (%v); the dependency is "+
					"stored and called on the request path, so this becomes a nil dereference on "+
					"the first operation rather than a refusal here", test.name, driver)
			}
			if driver != nil {
				t.Fatalf("DEFECT: refused with %v but still returned a driver", err)
			}
			if want := "complete PKCS#11 driver configuration is required"; err.Error() != want {
				t.Fatalf("refusal is %q, want %q", err.Error(), want)
			}
		})
	}
}

// TestOpenRefusesABindingThatNamesNoDevice pins the three operands of Open's binding check.
//
// Every one is a field the custody manifest is required to carry, so an empty one means the binding
// was assembled somewhere that does not populate it. The backend check is what stops a binding for a
// different driver being served by this one; the device id and serial are what the slot search and
// the identity comparison are performed against, and an empty serial would compare equal to a token
// that reports none.
//
// Isolation: each row differs from the accepted control in exactly one field, and the control is
// asserted first so a refusal cannot be blamed on the driver or the module.
func TestOpenRefusesABindingThatNamesNoDevice(t *testing.T) {
	sound := registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "SERIAL-1",
	}
	// slotStub answers GetSlotList and nothing else, so a binding that gets PAST the guard under
	// test fails in the slot search rather than panicking on the embedded nil cryptoki. That is
	// what lets the control distinguish "refused by this guard" from "refused further in".
	newDriver := func(t *testing.T) *PKCS11Driver {
		t.Helper()
		driver, err := newPKCS11Driver(&slotStub{}, fixedDevAuth("sha256:abc"),
			&recordingSecureChannel{}, fixedRetries(3))
		if err != nil {
			t.Fatal(err)
		}
		return driver
	}

	// The control must get PAST the binding check. It then fails in the slot search against a token
	// that publishes no slots, which is a different refusal and proves the fixture reached the code
	// under test rather than being turned away at the door.
	if _, err := newDriver(t).Open(context.Background(), sound); err == nil {
		t.Fatal("control is unexpectedly succeeding; it was written to reach the slot search")
	} else if strings.Contains(err.Error(), "device is not configured") {
		t.Fatalf("control is broken: a sound binding was refused by the guard under test (%v), so "+
			"the rows below would pass without exercising anything", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(registry.Binding) registry.Binding
	}{
		{"a binding for another backend", func(b registry.Binding) registry.Binding {
			b.Backend = "yubikey-piv"
			return b
		}},
		{"no device id", func(b registry.Binding) registry.Binding { b.DeviceID = ""; return b }},
		{"a whitespace device id", func(b registry.Binding) registry.Binding { b.DeviceID = "  "; return b }},
		{"no device serial", func(b registry.Binding) registry.Binding { b.DeviceSerial = ""; return b }},
		{"a whitespace device serial", func(b registry.Binding) registry.Binding {
			b.DeviceSerial = " \t "
			return b
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := newDriver(t).Open(context.Background(), test.mutate(sound))
			if err == nil {
				t.Fatalf("DEFECT: %s was opened and returned session %v", test.name, session)
			}
			if session != nil {
				t.Fatalf("DEFECT: refused with %v but still returned a session", err)
			}
			if want := "PKCS#11 device is not configured"; err.Error() != want {
				t.Fatalf("refusal for %s is %q, want %q — anything else means the binding got past "+
					"this guard and was refused further in, which is not what this row tests",
					test.name, err.Error(), want)
			}
		})
	}
}

// TestClosingADriverWithNothingToCloseIsANoOp pins both operands of Close.
//
// Close is deferred by callers that may not have constructed a driver, and newPKCS11Driver leaves
// the cleanup nil unless one was supplied — which is the ordinary case, since only the exported
// constructor has a module to destroy. Without these the deferred close on an error path calls a nil
// function.
//
// Isolation: the control shows a driver WITH a cleanup runs it exactly once, so the nil cases are
// distinguishable from "Close never calls anything".
func TestClosingADriverWithNothingToCloseIsANoOp(t *testing.T) {
	calls := 0
	withCleanup, err := newPKCS11Driver(&acceptingToken{}, fixedDevAuth("sha256:abc"),
		&recordingSecureChannel{}, fixedRetries(3), func() error { calls++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := withCleanup.Close(); err != nil || calls != 1 {
		t.Fatalf("control is broken: a driver with a cleanup gave err=%v calls=%d, want nil and 1",
			err, calls)
	}
	// And only once: Close clears the func, so a deferred close after an explicit one is safe.
	if err := withCleanup.Close(); err != nil || calls != 1 {
		t.Fatalf("DEFECT: a second Close ran the cleanup again (calls=%d) or errored (%v); the "+
			"field is cleared precisely so a deferred close after an explicit one is a no-op",
			calls, err)
	}

	var absent *PKCS11Driver
	if panicked := recovered(func() { _ = absent.Close() }); panicked != nil {
		t.Fatalf("DEFECT: Close on a nil *PKCS11Driver panicked with %v; callers defer Close before "+
			"knowing whether construction succeeded", panicked)
	}

	noCleanup, err := newPKCS11Driver(&acceptingToken{}, fixedDevAuth("sha256:abc"),
		&recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	if panicked := recovered(func() { _ = noCleanup.Close() }); panicked != nil {
		t.Fatalf("DEFECT: Close on a driver built without a cleanup panicked with %v; the internal "+
			"constructor leaves that field nil for every caller that has no module to destroy", panicked)
	}
}

// recovered runs call and returns whatever it panicked with, or nil.
//
// An unrecovered panic takes the whole test binary down, and then "which test failed" has no answer:
// the run reports a crashed package, so the operand that caused it cannot be attributed to a test.
func recovered(call func()) (escaped any) {
	defer func() { escaped = recover() }()
	call()
	return nil
}
