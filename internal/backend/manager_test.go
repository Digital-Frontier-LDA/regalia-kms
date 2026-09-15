package backend

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// stubProvider answers however the test needs, including by panicking.
type stubProvider struct {
	healthy      bool
	ready        bool
	panicHealthy bool
	panicReady   bool
}

func (stub stubProvider) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	return []byte("out"), "application/octet-stream", nil
}

func (stub stubProvider) Healthy(context.Context, registry.Binding) bool {
	if stub.panicHealthy {
		panic("provider panicked in Healthy")
	}
	return stub.healthy
}

func (stub stubProvider) Ready(context.Context) bool {
	if stub.panicReady {
		panic("provider panicked in Ready")
	}
	return stub.ready
}

func manager(t *testing.T, providers map[string]Provider) *Manager {
	t.Helper()
	made, err := New(providers)
	if err != nil {
		t.Fatal(err)
	}
	return made
}

// SERVES IS WHAT STOPS A REGISTRY ROUTING SOMEWHERE THE DAEMON CANNOT REACH.
//
// The daemon refuses to start when the key registry names a backend it has no provider for,
// because every operation on those objects would otherwise fail at signing time — the failure
// arrives when somebody needs the key rather than at startup. #130 is the same question from
// the other side: an object that is a record and not a route must not make this demand at all.
func TestServesAnswersOnlyForBackendsThatHaveAProvider(t *testing.T) {
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": stubProvider{}})

	if !made.Serves("nitrokey-pkcs11") {
		t.Error("a configured backend is not served")
	}
	for _, absent := range []string{"yubikey-piv", "fido2", "software", ""} {
		if made.Serves(absent) {
			t.Errorf("Serves(%q) is true with no provider for it: the daemon would start against a "+
				"registry it cannot serve", absent)
		}
	}

	var nilManager *Manager
	if nilManager.Serves("nitrokey-pkcs11") {
		t.Error("a nil manager claims to serve a backend")
	}
	if (&Manager{providers: nil}).Serves("nitrokey-pkcs11") {
		t.Error("a manager with no providers claims to serve a backend")
	}
}

// A PANICKING PROVIDER MUST BE UNHEALTHY, NOT FATAL.
//
// Healthy and Ready are reached from /v1/health/ready, which a load balancer polls. A provider
// that panics there — a driver bug, a nil map inside a backend, a library that aborts on a
// disconnected device — would otherwise take the daemon down through the one endpoint whose
// entire job is to report whether the daemon is up.
//
// The recover() in each is untested until something panics through it, and a recover that does
// not recover looks identical to one that does until the day it matters.
func TestAPanickingProviderIsUnhealthyRatherThanFatal(t *testing.T) {
	binding := registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-1"}

	panicking := manager(t, map[string]Provider{"nitrokey-pkcs11": stubProvider{panicHealthy: true}})
	if panicking.Healthy(context.Background(), binding) {
		t.Error("a provider that panicked was reported healthy")
	}

	readyPanicking := manager(t, map[string]Provider{"nitrokey-pkcs11": stubProvider{panicReady: true}})
	if readyPanicking.Ready(context.Background()) {
		t.Error("a provider that panicked in Ready was reported ready")
	}
}

func TestHealthyRequiresAProviderForTheBindingsBackend(t *testing.T) {
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": stubProvider{healthy: true}})

	if !made.Healthy(context.Background(), registry.Binding{Backend: "nitrokey-pkcs11"}) {
		t.Error("a healthy provider was reported unhealthy")
	}
	// A binding naming a backend nobody serves is unhealthy, not a panic on a nil map entry.
	if made.Healthy(context.Background(), registry.Binding{Backend: "yubikey-piv"}) {
		t.Error("a binding for an unserved backend was reported healthy")
	}
	if made.Healthy(context.Background(), registry.Binding{}) {
		t.Error("a binding with no backend at all was reported healthy")
	}
}

// READY IS ALL OF THEM, NOT ANY OF THEM.
//
// The daemon serves every backend it is configured with, so one unready provider means some
// object in the registry cannot be operated. Reporting ready on a partial fleet sends a load
// balancer traffic for keys that cannot be reached.
func TestReadyRequiresEveryProviderAndNotMerelyOne(t *testing.T) {
	all := manager(t, map[string]Provider{
		"nitrokey-pkcs11": stubProvider{ready: true},
		"yubikey-piv":     stubProvider{ready: true},
	})
	if !all.Ready(context.Background()) {
		t.Error("every provider is ready and the manager is not")
	}

	// Map iteration order is random, so this holds whichever provider is visited first.
	mixed := manager(t, map[string]Provider{
		"nitrokey-pkcs11": stubProvider{ready: true},
		"yubikey-piv":     stubProvider{ready: false},
	})
	for attempt := 0; attempt < 8; attempt++ {
		if mixed.Ready(context.Background()) {
			t.Fatal("one unready provider and the manager reports ready: traffic would be sent for keys it cannot reach")
		}
	}
}

func TestNewRefusesAnEmptyOrInvalidProviderSet(t *testing.T) {
	for name, providers := range map[string]map[string]Provider{
		"no providers":    {},
		"nil provider":    {"nitrokey-pkcs11": nil},
		"unnamed backend": {"": stubProvider{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(providers); err == nil {
				t.Fatalf("New accepted %s", name)
			}
		})
	}
	// The constructor copies, so a later edit to the caller's map cannot add a backend the
	// daemon already refused to start against.
	original := map[string]Provider{"nitrokey-pkcs11": stubProvider{}}
	made := manager(t, original)
	original["fido2"] = stubProvider{}
	if made.Serves("fido2") {
		t.Error("mutating the caller's map added a backend to a constructed manager")
	}
}

// executeStub hands back a buffer it keeps a reference to, so a test can look at what the
// manager did to it after the call returned.
type executeStub struct {
	stubProvider
	returned     []byte
	err          error
	panicExecute bool
}

func (stub *executeStub) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	if stub.panicExecute {
		stub.returned = []byte("half-formed signature")
		panic("provider panicked mid-operation")
	}
	stub.returned = []byte("sensitive-output")
	return stub.returned, "application/octet-stream", stub.err
}

func routeTo(backend string) registry.Route {
	return registry.Route{Binding: registry.Binding{Backend: backend, DeviceID: "hsm-1"}}
}

// A FAILED OPERATION MUST LEAVE NOTHING BEHIND AND SAY NOTHING ABOUT WHY.
//
// Execute is the one call that reaches the token. Two properties matter beyond returning an
// error: the bytes the provider already produced are zeroed rather than left in a buffer the
// caller still holds, and the provider's own error never escapes — a backend detail on the wire
// is a description of the hardware to whoever asked.
//
// A partial result is the case to worry about. A provider that returns output AND an error has
// produced something, and returning the error while dropping the reference leaves those bytes in
// memory for as long as the allocator keeps them.
func TestExecuteZeroesTheOutputAndHidesTheReasonWhenAProviderFails(t *testing.T) {
	stub := &executeStub{err: errors.New("PKCS#11 CKR_DEVICE_ERROR at slot 3")}
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": stub})

	output, contentType, err := made.Execute(context.Background(), routeTo("nitrokey-pkcs11"),
		"sign", "raw", "application/octet-stream", []byte("digest"), nil)

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if output != nil || contentType != "" {
		t.Fatalf("a failed operation returned output=%q type=%q", output, contentType)
	}
	if strings.Contains(err.Error(), "CKR_DEVICE_ERROR") || strings.Contains(err.Error(), "slot 3") {
		t.Errorf("the provider's error reached the caller: %v", err)
	}
	for index, value := range stub.returned {
		if value != 0 {
			t.Fatalf("the buffer the provider produced was not zeroed: byte %d is %#x (%q)",
				index, value, stub.returned)
		}
	}
}

// The panic path CONTAINS, and cannot zero -- measured, not assumed.
//
// Execute's recover calls zero(output), but `output` is a named return the caller assigns from
// `provider.Execute(...)`, and a panic in the provider means that assignment never completes.
// Verified by instrumenting the recover: it sees len(output) == 0 even when the provider sets
// its return values and then panics from its own deferred function, because the panic
// propagates before the caller's assignment.
//
// So this test claims what is true -- the panic is contained, ErrUnavailable is returned, and no
// output or content type escapes -- and deliberately does not assert zeroing. A test asserting
// the panic path zeroes something would pass forever while proving nothing, which is the failure
// this file exists to avoid.
func TestExecuteContainsAPanickingProviderWithoutLeakingOutput(t *testing.T) {
	stub := &executeStub{panicExecute: true}
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": stub})

	output, contentType, err := made.Execute(context.Background(), routeTo("nitrokey-pkcs11"),
		"sign", "raw", "application/octet-stream", []byte("digest"), nil)

	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if output != nil || contentType != "" {
		t.Fatalf("a panicking operation returned output=%q type=%q", output, contentType)
	}
}

func TestExecuteReturnsTheProvidersOutputWhenItSucceeds(t *testing.T) {
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": &executeStub{}})
	output, contentType, err := made.Execute(context.Background(), routeTo("nitrokey-pkcs11"),
		"sign", "raw", "application/octet-stream", []byte("digest"), nil)
	if err != nil || string(output) != "sensitive-output" || contentType != "application/octet-stream" {
		t.Fatalf("output=%q type=%q err=%v", output, contentType, err)
	}
}

func TestExecuteRefusesABackendItDoesNotServe(t *testing.T) {
	made := manager(t, map[string]Provider{"nitrokey-pkcs11": &executeStub{}})
	if _, _, err := made.Execute(context.Background(), routeTo("yubikey-piv"),
		"sign", "raw", "application/octet-stream", []byte("digest"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unserved backend returned %v, want ErrUnavailable", err)
	}
}
