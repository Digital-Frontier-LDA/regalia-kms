package yubikey

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// reachingDriver is a driver that cannot open its card and can say why.
type reachingDriver struct {
	missing []string
	held    bool
	err     error
	looks   int
	// during runs inside Reach: what else is going on while the readers are looked at.
	during func()
}

func (*reachingDriver) Open(context.Context, string) (Session, error) {
	return nil, errors.New("no card with that serial")
}
func (*reachingDriver) Ready(context.Context) bool { return true }
func (driver *reachingDriver) Reach(context.Context) ([]string, bool, error) {
	driver.looks++
	if driver.during != nil {
		driver.during()
	}
	return driver.missing, driver.held, driver.err
}

func TestProviderReachReportsWhatTheDriverSaysAndTakesItsTurn(t *testing.T) {
	driver := &reachingDriver{missing: []string{"yubi-sitea"}, held: true}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	// The readers are looked at inside the turn every request takes: while Reach runs, the turn
	// is held, so a request arriving then waits instead of colliding on the readers.
	driver.during = func() {
		if len(provider.turn) != 1 {
			t.Error("Reach looked at the readers without holding the turn")
		}
	}
	missing, held, err := provider.Reach(context.Background())
	if err != nil || !held || !reflect.DeepEqual(missing, []string{"yubi-sitea"}) {
		t.Fatalf("Reach = %v, %v, %v; want what the driver said", missing, held, err)
	}
	if len(provider.turn) != 0 {
		t.Fatal("Reach kept the turn")
	}
	// a caller that gives up while another holds the turn never looks
	provider.turn <- struct{}{}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	looks := driver.looks
	if _, _, err := provider.Reach(ended); err == nil || driver.looks != looks {
		t.Fatalf("Reach under an ended context with the turn taken: err=%v, %d looks", err, driver.looks-looks)
	}
	<-provider.turn
	// a driver that cannot say reports nothing, and that is not an error
	plain, _ := New(&fakeDriver{session: &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}}, &fakePIN{value: []byte("123456")})
	if missing, held, err := plain.Reach(context.Background()); err != nil || held || len(missing) != 0 {
		t.Fatalf("a driver that cannot say: %v, %v, %v", missing, held, err)
	}
}

// A CARD ATTACHED AFTER THE DAEMON STARTED meets the lockout with the daemon running. The cause is
// then named when a request for it fails, once a minute at most.
func TestALockoutMetWhileRunningIsNamedAndNotOnEveryRequest(t *testing.T) {
	driver := &reachingDriver{missing: []string{"yubi-sitea"}, held: true}
	provider, err := New(driver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	sign := func() {
		t.Helper()
		if _, _, err := provider.Execute(ctx, route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
			t.Fatal("setup: the card cannot be opened, the request must fail")
		}
	}
	sign()
	if driver.looks != 1 {
		t.Fatalf("the readers were looked at %d times after the first failed request, want once", driver.looks)
	}
	sign()
	provider.Healthy(ctx, route().Binding)
	if driver.looks != 1 {
		t.Fatalf("the readers were looked at again within the minute (%d looks): every request would open every reader", driver.looks)
	}
	provider.mu.Lock()
	provider.lockoutLooked = time.Now().Add(-lockoutLookEvery)
	provider.mu.Unlock()
	sign()
	if driver.looks != 2 {
		t.Fatalf("after the minute the readers were looked at %d times in all, want twice", driver.looks)
	}
}

func TestNameLockoutNamesOnlyTheLockedOutDevice(t *testing.T) {
	for name, test := range map[string]struct {
		driver *reachingDriver
		ctx    func() context.Context
		named  bool
	}{
		"missing and a YubiKey reader held": {&reachingDriver{missing: []string{"yubi-sitea"}, held: true}, context.Background, true},
		"missing, nothing held: unplugged":  {&reachingDriver{missing: []string{"yubi-sitea"}}, context.Background, false},
		"another device is the missing one": {&reachingDriver{missing: []string{"yubi-siteb"}, held: true}, context.Background, false},
		"the readers cannot be looked at":   {&reachingDriver{missing: []string{"yubi-sitea"}, held: true, err: errors.New("pcsc")}, context.Background, false},
		"the request has ended": {&reachingDriver{missing: []string{"yubi-sitea"}, held: true}, func() context.Context {
			ended, cancel := context.WithCancel(context.Background())
			cancel()
			return ended
		}, false},
	} {
		provider, err := New(test.driver, &fakePIN{value: []byte("123456")})
		if err != nil {
			t.Fatal(err)
		}
		if named := provider.nameLockout(test.ctx(), "yubi-sitea"); named != test.named {
			t.Errorf("%s: named=%v, want %v", name, named, test.named)
		}
	}
}
