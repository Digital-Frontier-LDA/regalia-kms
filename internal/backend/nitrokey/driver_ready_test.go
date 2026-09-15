package nitrokey

import (
	"context"
	"errors"
	"testing"
)

// slotStub answers GetSlotList and nothing else. The embedded nil cryptoki makes any other call
// panic rather than return a usable zero value.
type slotStub struct {
	cryptoki
	slots         []uint
	err           error
	tokenPresent  bool
	askedForToken bool
}

// GetSlotList models two independent things, because Ready reads two independent things.
//
// tokenPresent decides the LIST: asked for slots with a token and configured without one, the stub
// returns none, which is the empty-slot case. err decides the ERROR, and is returned whatever the
// list contains.
//
// The combination that matters is slots AND an error together, which is why err is not allowed to
// force the list empty. A stub that returned nothing on failure could not distinguish "the error is
// checked" from "the list happened to be empty" — both reach len(slots) == 0, so the
// error-ignoring mutation passes against it, as it did against the first version of this. PKCS#11
// permits a non-empty buffer with a non-OK return, so keeping them separate is also truthful.
func (stub *slotStub) GetSlotList(tokenPresent bool) ([]uint, error) {
	stub.askedForToken = tokenPresent
	if tokenPresent && !stub.tokenPresent {
		return nil, stub.err
	}
	return stub.slots, stub.err
}

// READINESS IS ABOUT A TOKEN BEING PRESENT, NOT ABOUT THE LIBRARY LOADING.
//
// PKCS11Driver.Ready feeds provider.Ready, then manager.Ready, then /v1/health/ready. A module
// that loads with no token in the slot must not report ready: the daemon would advertise itself as
// able to serve, and every operation would then fail one request at a time, at the moment someone
// needed a key — the same failure the startup servability gate exists to prevent, arriving later
// and by a different route. That distinction is carried entirely by the `true` argument to
// GetSlotList, which is one keystroke from meaning the opposite.
func TestReadinessRequiresATokenAndNotMerelyALoadedModule(t *testing.T) {
	present := &slotStub{slots: []uint{0}, tokenPresent: true}
	driver, err := newPKCS11Driver(present, devAuthProbe(""), secureChannelStub{}, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	if !driver.Ready(context.Background()) {
		t.Fatal("a module with a token present reported not ready")
	}
	if !present.askedForToken {
		t.Fatal("GetSlotList was called with tokenPresent=false, so an empty slot would count as ready")
	}

	// One respect differs: the token is gone. This is the bench's normal state.
	empty := &slotStub{slots: []uint{0}, tokenPresent: false}
	emptyDriver, err := newPKCS11Driver(empty, devAuthProbe(""), secureChannelStub{}, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	if emptyDriver.Ready(context.Background()) {
		t.Fatal("a module with no token present reported ready: the daemon would advertise a key store it cannot reach")
	}
}

func TestReadinessFailsClosedOnEveryUnusableDriverState(t *testing.T) {
	usable := &slotStub{slots: []uint{0}, tokenPresent: true}
	control, err := newPKCS11Driver(usable, devAuthProbe(""), secureChannelStub{}, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	if !control.Ready(context.Background()) {
		t.Fatal("the control is not ready, so nothing below can be attributed to the state under test")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if control.Ready(cancelled) {
		t.Error("a cancelled context reported ready")
	}

	// Slots AND an error: the combination that separates "the error is checked" from "the list
	// was empty anyway".
	failing := &slotStub{slots: []uint{0}, tokenPresent: true, err: errors.New("CKR_DEVICE_ERROR")}
	failingDriver, err := newPKCS11Driver(failing, devAuthProbe(""), secureChannelStub{}, retryProbeStub(3))
	if err != nil {
		t.Fatal(err)
	}
	if failingDriver.Ready(context.Background()) {
		t.Error("a module whose slot enumeration failed reported ready")
	}

	// A nil *PKCS11Driver is reachable: Ready has a pointer receiver and the guard is the first
	// thing it does, so a caller holding a nil driver gets false rather than a panic that would
	// take the readiness handler down with it.
	var nilDriver *PKCS11Driver
	if nilDriver.Ready(context.Background()) {
		t.Error("a nil driver reported ready")
	}
	if (&PKCS11Driver{}).Ready(context.Background()) {
		t.Error("a driver with no module reported ready")
	}
}

// Stubs for the probe arguments the constructor requires; readiness consults none of them.
type secureChannelStub struct{}

func (secureChannelStub) Establish(context.Context, string, string) error { return nil }

type retryProbeStub int

func (probe retryProbeStub) Remaining(context.Context, string, string) (int, error) {
	return int(probe), nil
}

type devAuthProbe string

func (probe devAuthProbe) Fingerprint(context.Context, string, string) (string, error) {
	return string(probe), nil
}
