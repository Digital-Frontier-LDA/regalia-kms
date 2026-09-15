package nitrokey

// Round two of the #237 sweep of this package.
//
// 182 sites / 258 operands / 516 operand-directions, both directions, against the only three
// packages that can see these symbols — this one, cmd/regalia-kms and internal/integration.
// That scope was chosen rather than defaulted: a driver package is not automatically
// self-contained, and two other packages do import it.
//
// 132 operands survive in at least one direction; 31 survive in BOTH, and those cluster by
// function rather than scattering:
//
//	unwrapAES()                   6 both-direction survivors, and NO test calls it
//	wrapAES()                     6, and NO test calls it
//	NewPKCS11DriverWithProbes()   4, and NO test calls it
//	Derive()                      5, called by 7 tests -- fixtures do not discriminate
//	Execute()                     5, called by 35 tests -- same
//
// The wrap and unwrap paths are the ones this file closes. They were reachable in software
// the whole time: the driver takes its module through the `cryptoki` interface, and
// pkcs11_driver_test.go already ships fakeCryptoki implementing it. Nothing here touches
// hardware.
//
// TWO FIXTURES ARE SHAPED BY A MASKING RELATIONSHIP AND SAY SO. unwrapAES's
// `err != nil || len(values) == 0 || len(values[0].Value) == 0` cannot have its first operand
// isolated by a stub that fails empty-handed: a nil-with-error return is refused by the
// SECOND operand, so the mutation would be masked. The row for it returns an error TOGETHER
// with a populated attribute, which is the only input the first operand refuses alone.
// wrapAES's `err != nil || len(wrapped) == 0` has the identical shape, and I missed it on the
// first pass: the falsification run reported :450[0] still SURVIVED while every other operand
// on the path was closed. The row returning bytes ALONGSIDE an error is what isolates it.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// wrapUnwrapStub drives the two paths through the cryptoki seam. It embeds fakeCryptoki so it
// satisfies the whole interface, and overrides only the calls these two functions make.
type wrapUnwrapStub struct {
	*fakeCryptoki
	findErr    error
	createErr  error
	wrapKeyErr error
	wrapped    []byte
	unwrapErr  error
	attrErr    error
	attrs      []*pkcs11.Attribute
	attrsSet   bool
}

func (stub *wrapUnwrapStub) FindObjects(handle pkcs11.SessionHandle, count int) ([]pkcs11.ObjectHandle, bool, error) {
	if stub.findErr != nil {
		return nil, false, stub.findErr
	}
	return stub.fakeCryptoki.FindObjects(handle, count)
}

func (stub *wrapUnwrapStub) CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if stub.createErr != nil {
		return 0, stub.createErr
	}
	return 21, nil
}

func (stub *wrapUnwrapStub) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	return stub.wrapped, stub.wrapKeyErr
}

func (stub *wrapUnwrapStub) UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if stub.unwrapErr != nil {
		return 0, stub.unwrapErr
	}
	return 31, nil
}

func (stub *wrapUnwrapStub) GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if stub.attrsSet || stub.attrErr != nil {
		return stub.attrs, stub.attrErr
	}
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("plaintext"))}, nil
}

// kekObjectID is hex because findObject hex-decodes the identifier before it looks anything
// up; a non-hex id is refused three guards earlier and every row would read "unavailable".
const kekObjectID = "a1b2c3"

func wrapSession(stub *wrapUnwrapStub, loggedIn bool) *pkcs11Session {
	stub.fakeCryptoki = &fakeCryptoki{objectHandle: 9}
	return &pkcs11Session{module: stub, loggedIn: loggedIn}
}

// TestWrappingRefusesAndSaysWhichStepFailed covers pkcs11_driver.go:427, :431, :443, :450
// operands 0 and 1, and :451.
//
// wrapAES is called by no test in this package, so all six of its operands survived the sweep
// in both directions — nothing drove either arm. It is the path that turns a data key into
// the ciphertext the envelope carries, and every refusal on it is the difference between a
// wrap that did not happen and a wrap that produced nothing usable.
//
// Falsifier: `(false && (err != nil))` at each site, and
// `(false && (len(wrapped) == 0))` for the empty-result row.
func TestWrappingRefusesAndSaysWhichStepFailed(t *testing.T) {
	boom := errors.New("token said no")
	for _, row := range []struct {
		name     string
		loggedIn bool
		stub     *wrapUnwrapStub
		want     string
	}{
		{"the session is not logged in", false, &wrapUnwrapStub{}, "PKCS#11 wrap unavailable"},
		{"the KEK cannot be found", true, &wrapUnwrapStub{findErr: boom}, "PKCS#11 wrap unavailable"},
		{"the staging object cannot be created", true, &wrapUnwrapStub{createErr: boom}, "PKCS#11 wrap staging:"},
		{
			// WITH BYTES PRESENT, and that is the whole point of the row. A stub that fails
			// empty-handed leaves `len(wrapped) == 0` true, so the sibling operand refuses the
			// same input and `err != nil` is masked -- measured: the mutation survived until
			// this row existed. Returning bytes AND an error is the only input the first
			// operand refuses alone, and without it a token that errors while handing back a
			// buffer would have that buffer returned as a successful wrap.
			"the wrap call fails but hands back bytes anyway",
			true,
			&wrapUnwrapStub{wrapKeyErr: boom, wrapped: []byte("partial ciphertext")},
			"PKCS#11 wrap execution:",
		},
		{"the wrap call fails", true, &wrapUnwrapStub{wrapKeyErr: boom}, "PKCS#11 wrap execution:"},
		{"the wrap call returns nothing", true, &wrapUnwrapStub{wrapped: nil}, "PKCS#11 wrap returned no data"},
	} {
		t.Run(row.name, func(t *testing.T) {
			session := wrapSession(row.stub, row.loggedIn)
			out, err := session.wrapAES(context.Background(), kekObjectID, []byte("data key"))
			if err == nil {
				t.Fatalf("wrapAES accepted and returned %d bytes", len(out))
			}
			if out != nil {
				t.Fatalf("a refused wrap returned %d bytes; a caller that checks the slice before "+
					"the error would ship them", len(out))
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("err = %q, want it to name %q — the four refusals on this path are "+
					"distinguishable only by message", err, row.want)
			}
		})
	}
}

// TestUnwrappingRefusesAndSaysWhichStepFailed covers pkcs11_driver.go:302, :306, :311 and
// :317 operands 0, 1 and 2.
//
// unwrapAES is likewise called by no test. The last three operands share ONE message, so they
// are separated by fixture rather than by assertion text, and each fixture is the only input
// its operand refuses alone — see the note at the top of this file for why the error row
// carries a populated attribute.
//
// Falsifier: `(false && (err != nil))`, `(false && (len(values) == 0))` — which then panics on
// values[0] rather than refusing — and `(false && (len(values[0].Value) == 0))`, which returns
// an empty plaintext as a successful unwrap.
func TestUnwrappingRefusesAndSaysWhichStepFailed(t *testing.T) {
	boom := errors.New("token said no")
	populated := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("something"))}
	for _, row := range []struct {
		name     string
		loggedIn bool
		stub     *wrapUnwrapStub
		want     string
	}{
		{"the session is not logged in", false, &wrapUnwrapStub{}, "PKCS#11 unwrap unavailable"},
		{"the KEK cannot be found", true, &wrapUnwrapStub{findErr: boom}, "PKCS#11 unwrap unavailable"},
		{"the unwrap call fails", true, &wrapUnwrapStub{unwrapErr: boom}, "PKCS#11 unwrap execution:"},
		{
			"reading the unwrapped value fails WITH a value present",
			true,
			&wrapUnwrapStub{attrErr: boom, attrs: populated, attrsSet: true},
			"PKCS#11 unwrap returned no data",
		},
		{
			"the token returns no attributes",
			true,
			&wrapUnwrapStub{attrs: nil, attrsSet: true},
			"PKCS#11 unwrap returned no data",
		},
		{
			"the token returns an attribute with no value",
			true,
			&wrapUnwrapStub{attrs: []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}, attrsSet: true},
			"PKCS#11 unwrap returned no data",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			session := wrapSession(row.stub, row.loggedIn)
			out, err := session.unwrapAES(context.Background(), kekObjectID, []byte("ciphertext"))
			if err == nil {
				t.Fatalf("unwrapAES accepted and returned %d bytes", len(out))
			}
			if out != nil {
				t.Fatalf("a refused unwrap returned %d bytes — this path returns a DATA KEY, so "+
					"handing back a slice alongside an error is the wrong shape", len(out))
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("err = %q, want it to name %q", err, row.want)
			}
		})
	}
}

// TestTheProbeConstructorRefusesAMissingSecureChannel covers probes.go:132
// (`secure == nil`).
//
// NewPKCS11DriverWithProbes is called by no test, and this is the one of its four operands
// that can be reached without a real PKCS#11 module on the box: it refuses before
// pkcs11.New is called at all. The other three (`module == nil`, Initialize failing,
// NewTokenProbes failing) need a module path that loads, and are recorded in the sweep ledger
// rather than pinned here.
//
// Falsifier: `(false && (secure == nil))`. The constructor then proceeds to load a module
// with a nil secure channel and the refusal moves to whatever the module path does.
func TestTheProbeConstructorRefusesAMissingSecureChannel(t *testing.T) {
	driver, err := NewPKCS11DriverWithProbes("/nonexistent/module.so", nil)
	if err == nil {
		t.Fatal("a driver was constructed with no secure-channel implementation")
	}
	if driver != nil {
		t.Fatal("a refused construction returned a driver")
	}
	if err.Error() != "a secure-channel implementation is required" {
		t.Fatalf("err = %q, want the secure-channel refusal — any other message means the guard "+
			"did not fire and the module path was reached", err)
	}
}
