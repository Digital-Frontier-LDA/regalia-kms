package yubikey

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// healthSession answers every probe Healthy makes, including by failing.
type healthSession struct {
	fakeSession
	identityErr, policiesErr, retriesErr error
	retriesValue                         int
}

func (s *healthSession) Identity(context.Context) (string, error) {
	return s.serial, s.identityErr
}

func (s *healthSession) Policies(context.Context, string) (string, string, error) {
	return s.pinPolicy, s.touchPolicy, s.policiesErr
}

func (s *healthSession) PINRetries(context.Context) (int, error) {
	return s.retriesValue, s.retriesErr
}

type healthDriver struct {
	session Session
	openErr error
	ready   bool
}

func (driver *healthDriver) Open(context.Context, string) (Session, error) {
	return driver.session, driver.openErr
}
func (driver *healthDriver) Ready(context.Context) bool { return driver.ready }

func healthy() *healthSession {
	return &healthSession{
		fakeSession:  fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"},
		retriesValue: 3,
	}
}

func providerFor(t *testing.T, session Session, openErr error) *Provider {
	t.Helper()
	made, err := New(&healthDriver{session: session, openErr: openErr, ready: true}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return made
}

// HEALTHY IS THE UNATTENDED-USE CHECK, NOT A PING.
//
// A YubiKey is only usable by this daemon if nobody has to be standing next to it, and the
// binding alone cannot establish that: the manifest says what the credential is supposed to be
// and the card says what it is. Healthy is where the two are compared, so every clause in it is
// a separate way the fleet's picture can be wrong about a device that is physically present and
// answering.
//
// Each of these was uncovered. Healthy and Ready were at 0%, and both are read from
// /v1/health/ready, so a device that should have been refused was being reported on by nothing.
func TestHealthyRefusesEveryWayTheCardCanDisagreeWithTheBinding(t *testing.T) {
	base := route().Binding

	t.Run("the healthy case", func(t *testing.T) {
		if !providerFor(t, healthy(), nil).Healthy(context.Background(), base) {
			t.Fatal("a card matching its binding was reported unhealthy: the control for every case below")
		}
	})

	// Binding-side refusals: wrong on their face, before the card is opened.
	for name, mutate := range map[string]func(*registry.Binding){
		"another backend's binding": func(b *registry.Binding) { b.Backend = "nitrokey-pkcs11" },
		"no serial to pin against":  func(b *registry.Binding) { b.DeviceSerial = "" },
		"touch required":            func(b *registry.Binding) { b.TouchPolicy = "always" },
		"touch cached":              func(b *registry.Binding) { b.TouchPolicy = "cached" },
	} {
		t.Run(name, func(t *testing.T) {
			binding := base
			mutate(&binding)
			if providerFor(t, healthy(), nil).Healthy(context.Background(), binding) {
				t.Fatalf("%s was reported healthy", name)
			}
		})
	}

	// Card-side refusals: the device is present and answers, and what it says is wrong.
	for name, mutate := range map[string]func(*healthSession){
		"a different serial than the manifest pins": func(s *healthSession) { s.serial = "87654321" },
		"identity unreadable":                       func(s *healthSession) { s.identityErr = errors.New("no card") },
		"a PIN policy the manifest did not declare": func(s *healthSession) { s.pinPolicy = "always" },
		"touch required on the card itself":         func(s *healthSession) { s.touchPolicy = "always" },
		"policies unreadable":                       func(s *healthSession) { s.policiesErr = errors.New("slot unreadable") },
		"one retry left":                            func(s *healthSession) { s.retriesValue = 1 },
		"no retries left":                           func(s *healthSession) { s.retriesValue = 0 },
		"retry count unreadable":                    func(s *healthSession) { s.retriesErr = errors.New("no answer") },
	} {
		t.Run(name, func(t *testing.T) {
			session := healthy()
			mutate(session)
			if providerFor(t, session, nil).Healthy(context.Background(), base) {
				t.Fatalf("%s was reported healthy", name)
			}
		})
	}

	t.Run("the card cannot be opened", func(t *testing.T) {
		if providerFor(t, nil, errors.New("device busy")).Healthy(context.Background(), base) {
			t.Fatal("an unopenable card was reported healthy")
		}
	})

	t.Run("the driver returns no session and no error", func(t *testing.T) {
		if providerFor(t, nil, nil).Healthy(context.Background(), base) {
			t.Fatal("a nil session was reported healthy: the nil check is what stops the deref below it")
		}
	})
}

// A LATCHED DEVICE STAYS UNHEALTHY UNTIL AN OPERATOR CLEARS IT.
//
// The PIN latch is deliberately sticky — a spent budget is not a condition to retry into — and
// Healthy has to honour it, or readiness would report a device the executor refuses to use and
// the load balancer would keep sending it traffic.
func TestHealthyHonoursThePINLatch(t *testing.T) {
	session := &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", loginErr: errors.New("bad PIN")}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, execErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); execErr == nil {
		t.Fatal("an incorrect PIN was accepted")
	}
	if provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("a device latched out for a spent PIN was reported healthy")
	}
	// From the same route as the binding probed above. This case fails loudly
	// rather than silently if the two drift apart, unlike its twin in
	// provider_test.go, but a literal that has to agree with route() and is not
	// taken from it is the same defect either way.
	provider.ResetPINBlock(route().Binding.DeviceID)
	if !provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("clearing the latch did not restore health")
	}
}

func TestReadyRequiresADriverAPINSourceAndAReadyDriver(t *testing.T) {
	if (*Provider)(nil).Ready(context.Background()) {
		t.Error("a nil provider reported ready")
	}
	if (&Provider{}).Ready(context.Background()) {
		t.Error("a provider with no driver reported ready")
	}
	if (&Provider{driver: &healthDriver{ready: true}}).Ready(context.Background()) {
		t.Error("a provider with no PIN source reported ready")
	}
	notReady := &Provider{driver: &healthDriver{ready: false}, pins: &fakePIN{}}
	if notReady.Ready(context.Background()) {
		t.Error("an unready driver reported ready")
	}
	ready := &Provider{driver: &healthDriver{ready: true}, pins: &fakePIN{}}
	if !ready.Ready(context.Background()) {
		t.Error("a fully configured provider with a ready driver reported not ready")
	}
}
