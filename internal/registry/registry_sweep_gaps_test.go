package registry

// COVERAGE GAPS FROM THE 7-PACKAGE MUTATION SWEEP — REGISTRY LAYER.
//
// Each test in this file pins one production guard that the audit sweep
// found no test for. Removing the guard in production flips the test red.
// FIDO-multi-enrollment tests (L654, L1040, L1130-custodyRecord) are
// deferred because the custody mode's compile-time gating makes a single
// targeted test brittle without a deeper restructuring of the fido-credential
// helper; that work belongs in a separate PR per the peer's protocol on
// defect-class isolation.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// validateObject L668 — required fields, every present-as-zero one is refused.
//
// Falsify: removing the L668 nil-check compound — the loader carries zero
// values forward into validateBinding and Route, which then refuses with a
// different operator message ("unsupported state", "no usable binding").
//
// THE MESSAGE ASSERTION IS THE TEST. The #237 sweep neutralised this site's
// operands one at a time and found that `object.Algorithm == ""` and
// `object.Classification == ""` both survived: with either removed the fixture
// is still refused, by the capability-matrix gate at registry.go:750 and by the
// classification enum at :578 respectively. Asserting only `err != nil` let
// those two guards answer on this one's behalf, so two of the four cases proved
// nothing. Naming the message is what makes each case fail for its own guard —
// and it is also what an operator needs: "unsupported classification" sends
// somebody to the wrong field.
func TestValidateObjectRefusesMissingRequiredFields(t *testing.T) {
	baseBindings := binding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "hs-2", "slot-2", "standby")
	cases := map[string]func(string) string{
		"blank algorithm":   func(p string) string { return strings.Replace(p, `"algorithm":"secp256k1"`, `"algorithm":""`, 1) },
		"blank policy_id":   func(p string) string { return strings.Replace(p, `"policy_id":"test-policy"`, `"policy_id":""`, 1) },
		"blank environment": func(p string) string { return strings.Replace(p, `"environment":"production"`, `"environment":""`, 1) },
		"blank classification": func(p string) string {
			return strings.Replace(p, `"classification":"critical"`, `"classification":""`, 1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			body := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", baseBindings))
			_, err := Load(strings.NewReader(mutate(body)), "sitea", &healthMap{states: map[string]bool{}})
			if err == nil {
				t.Fatalf("Load accepted %s", name)
			}
			if !strings.Contains(err.Error(), "algorithm, policy, environment and operations are required") {
				t.Fatalf("err = %v for %s; want the required-fields refusal from validateObject. "+
					"Another guard refusing this fixture is not this guard being tested: the operator "+
					"is sent to whichever field that other guard names", err, name)
			}
		})
	}
}

// validateObject L676 — empty operation string.

// Falsify: empty operation passes through to validateBinding's loop, which
// returns the `backend X does not support Y/Z` error instead of "operation
// must not be empty" — different message, different remedy.
func TestValidateObjectRefusesAnEmptyOperationString(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "hs-2", "slot-2", "standby")
	body := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))
	body = strings.Replace(body, `"sign"`, `""`, 1)
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
		t.Fatal("Load accepted an empty operation")
	} else if !strings.Contains(err.Error(), "operation must not be empty") {
		t.Fatalf("err = %v, want it to name empty operation", err)
	}
}

// validateObject L679 — duplicate operation string.

// Falsify: a duplicate "sign" goes into operationsSet without complaint,
// and the loop in validateBinding runs once per "sign" — the duplicate
// never gets a distinct refusal because there isn't one to give.
func TestValidateObjectRefusesDuplicateOperations(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "hs-2", "slot-2", "standby")
	body := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))
	body = strings.Replace(body, `"operations":["sign"]`, `"operations":["sign","sign"]`, 1)
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
		t.Fatal("Load accepted duplicate operations")
	} else if !strings.Contains(err.Error(), "duplicate operation") {
		t.Fatalf("err = %v, want it to name duplicate operation", err)
	}
}

// validateBinding L720 — site, device_id, object_id all required.

// Falsify: each missing field causes validateBinding to read a zero value;
// the zero value passes the commissioned fingerprint/serial checks (L731)
// because those require a non-empty value. Without L720, Load returns
// success on a binding whose site/device/object is blank, and downstream
// Route() answers with a zero-value route.
func TestValidateBindingRefusesMissingSiteDeviceOrObject(t *testing.T) {
	cases := map[string]string{
		"no site":   `{"backend":"nitrokey-pkcs11","device_id":"hs-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}`,
		"no device": `{"site":"sitea","backend":"nitrokey-pkcs11","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}`,
		"no object": `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"hs-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}`,
	}
	for name, bindingJSON := range cases {
		t.Run(name, func(t *testing.T) {
			obj := `{"id":"wallet-key","name":"Test key","kind":"asymmetric-key","classification":"critical","environment":"development",
				"owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware","algorithm":"secp256k1",
				"operations":["sign"],"policy_id":"test-policy","bindings":[` + bindingJSON + `],
				"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
				"rotation":{"maximum_age_days":365,"last_rotated":null},
				"migration":{"status":"migrated","source":"test"},
				"verification":{"status":"verified"}
			}`
			body := `{"schema_version":1,"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[` + obj + `]}`
			if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
				t.Fatalf("Load accepted binding with %s", name)
			} else if !strings.Contains(err.Error(), "site, device_id and object_id are required") {
				t.Fatalf("err = %v, want it to name the required fields", err)
			}
		})
	}
}

// validateBinding L723 — a binding must have either public_fingerprint or key_check.

// Falsify: a binding with neither field is accepted; downstream, no proof of
// the key's identity exists in the manifest, and Route() would still answer.
func TestValidateBindingRefusesBindingWithoutFingerprintOrKeyCheck(t *testing.T) {
	bindings := `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"hs-1","device_serial":"test-serial",
		"devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"object_id":"slot-1","state":"active"}`
	obj := `{"id":"wallet-key","name":"Test key","kind":"asymmetric-key","classification":"critical","environment":"development",
		"owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware","algorithm":"secp256k1",
		"operations":["sign"],"policy_id":"test-policy","bindings":[` + bindings + `],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}
	}`
	body := `{"schema_version":1,"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[` + obj + `]}`
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
		t.Fatal("Load accepted a binding without fingerprint or key_check")
	} else if !strings.Contains(err.Error(), "public fingerprint or key check") {
		t.Fatalf("err = %v, want it to name the missing fingerprint/key check", err)
	}
}

// validateBinding L741 — pin_policy / touch_policy are YubiKey-only.

// validateBinding L741 — pin_policy / touch_policy are YubiKey-only.

// Falsify: a nitrokey-pkcs11 binding with a touch_policy field would load
// without L741; downstream the field is silently ignored.
func TestValidateBindingRefusesPinTouchPolicyOnNonYubikey(t *testing.T) {
	bindings := `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"hs-1","device_serial":"test-serial",
		"devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"pin_policy":"once","touch_policy":"never","state":"active"}`
	obj := `{"id":"wallet-key","name":"Test key","kind":"asymmetric-key","classification":"critical","environment":"development",
		"owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware","algorithm":"secp256k1",
		"operations":["sign"],"policy_id":"test-policy","bindings":[` + bindings + `],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}
	}`
	body := `{"schema_version":1,"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[` + obj + `]}`
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
		t.Fatal("Load accepted nitrokey-pkcs11 binding with pin_policy")
	} else if !strings.Contains(err.Error(), "interaction policy is only valid for YubiKey") {
		t.Fatalf("err = %v, want it to name interaction policy as YubiKey-only", err)
	}
}

// validateBinding L822 — seal-envelope kek_version must match the version pattern.

// Falsify: a malformed kek_version passes the empty check at L819 but trips
// L822; without L822, an envelope's KEK reference can carry any value.
func TestValidateBindingRefusesSealEnvelopeWithMalformedKEKVersion(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "active", "rsa2048", "has space")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"hs-1": true}})
	if err == nil {
		t.Fatal("Load accepted seal-envelope binding with malformed kek_version")
	} else if !strings.Contains(err.Error(), "must match") {
		t.Fatalf("err = %v, want it to mention the pattern", err)
	}
}

// selectBindingForState L966 — multiple usable bindings at site is refused.

// Falsify: two qualified bindings at the same site pass selectBinding's
// active-only check; selectBindingForState then trips L966. Without L966,
// the first wins by iteration order. To reach L966 cleanly: build a seal
// envelope with two qualified bindings at the same site and call
// RouteForSeal — the L1130-style check does not fire (because both bindings
// are non-fido2), the L1136-style check does not fire (no rotation is past
// deadline), and the L1090-style health check passes.
func TestSelectBindingForStateRefusesMultipleUsableBindings(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "qualified", "rsa2048", "1") + "," +
		sealBinding("sitea", "nitrokey-pkcs11", "hs-2", "slot-2", "qualified", "rsa2048", "1")
	registry, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"hs-1": true, "hs-2": true}})
	if err != nil {
		t.Fatalf("Load() error = %v: the L966 guard fires at runtime, not at load", err)
	}
	_, err = registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose")
	if err == nil {
		t.Fatal("RouteForSeal() succeeded with two qualified bindings at the same site")
	}
	// THE CODE, NOT JUST THE ERROR. The #237 sweep neutralised RouteForSeal's
	// check on this helper's error (registry.go:1139) and this test stayed
	// green: the zero Binding that comes back instead is then handed to the
	// health probe, which answers false for its empty device id, so the caller
	// gets DEPENDENCY_UNAVAILABLE. That is a retryable code for a manifest
	// mistake — the caller retries a configuration error until somebody looks
	// at the wrong dashboard. Asserting the code is what tells the two apart.
	if !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal() error = %v, want DENIED: two usable bindings at one site is a manifest "+
			"mistake to be fixed, not a dependency outage to be waited out", err)
	}
}

// Route L986 — object not found.

// Falsify: a missing object would silently succeed without L986, because the
// registry.entries map lookup would return a zero entry that the rest of
// Route accepts.
func TestRouteRefusesUnknownObject(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "standby")
	registry, err := Load(strings.NewReader(manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Route(context.Background(), "absent-object", "cosmos-transaction", "sign"); !IsCode(err, CodeNotFound) {
		t.Fatalf("Route(unknown) error = %v, want NOT_FOUND", err)
	}
}

// RouteForUnwrap L1031 — object not found.

func TestRouteForUnwrapRefusesUnknownObject(t *testing.T) {
	registry, err := Load(strings.NewReader(opaqueObject(opaqueBinding("rsa2048"))), "sitea", allHealthy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RouteForUnwrap(context.Background(), "absent-object", "deployment-api", "1"); !IsCode(err, CodeNotFound) {
		t.Fatalf("RouteForUnwrap(unknown) error = %v, want NOT_FOUND", err)
	}
}

// RouteForUnwrap L1034 — wrong purpose.

func TestRouteForUnwrapRefusesWrongPurpose(t *testing.T) {
	registry, err := Load(strings.NewReader(opaqueObject(opaqueBinding("rsa2048"))), "sitea", allHealthy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RouteForUnwrap(context.Background(), "deployment-api-token", "other-purpose", "1"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(wrong-purpose) error = %v, want DENIED", err)
	}
}

// RouteForUnwrap L1037 — object does not advertise release-secret.

// Uses a sign-only asymmetric key (the package's standard test fixture).
func TestRouteForUnwrapRefusesObjectWithoutReleaseSecret(t *testing.T) {
	bindings := binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "standby")
	registry, err := Load(strings.NewReader(manifest(object("sign-only", "signing", "secp256k1", "sign", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RouteForUnwrap(context.Background(), "sign-only", "signing", "1"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(no-release-secret) error = %v, want DENIED", err)
	}
}

// RouteForUnwrap L1046 — past rotation deadline.

// Falsify: an overdue object passes the early Route guards and reaches the
// unwrap loop, which would route. Without L1046, an old envelope would open
// against an object whose deadline has elapsed. Use SetClock so the test
// doesn't depend on the wall clock.
func TestRouteForUnwrapRefusesObjectPastRotationDeadline(t *testing.T) {
	registry, err := Load(strings.NewReader(opaqueObjectWithRotation(`{"maximum_age_days":30,"last_rotated":"2026-01-01T00:00:00Z"}`)), "sitea", allHealthy{})
	if err != nil {
		t.Fatal(err)
	}
	registry.SetClock(func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) })
	if _, err := registry.RouteForUnwrap(context.Background(), "deployment-api-token", "deployment-api", "1"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(overdue) error = %v, want DENIED", err)
	}
}

// RouteForUnwrap L1090 — backend unhealthy.

// Falsify: a binding exists and matches the envelope's kek_version, but the
// health check says no. Without L1090, RouteForUnwrap returns the route and
// the caller proceeds to ask the dead backend to unwrap.
func TestRouteForUnwrapRefusesUnhealthyBinding(t *testing.T) {
	registry, err := Load(strings.NewReader(opaqueObject(opaqueBinding("rsa2048"))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": false}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RouteForUnwrap(context.Background(), "deployment-api-token", "deployment-api", "1"); !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("RouteForUnwrap(unhealthy) error = %v, want DEPENDENCY_UNAVAILABLE", err)
	}
}

// RouteForSeal L1136 — past rotation deadline.

func TestRouteForSealRefusesObjectPastRotationDeadline(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "hs-1", "slot-1", "active", "rsa2048", "1")
	obj := `{"id":"seal-target","name":"seal target","kind":"opaque-secret","classification":"restricted","environment":"staging","owner":"security","purpose":"seal-purpose","custody":"hardware-envelope","algorithm":"opaque","operations":["seal-envelope"],"policy_id":"test-policy","bindings":[` + bindings + `],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":30,"last_rotated":"2026-01-01T00:00:00Z"},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}
	}`
	registry, err := Load(strings.NewReader(manifest(obj)), "sitea", &healthMap{states: map[string]bool{"hs-1": true}})
	if err != nil {
		t.Fatal(err)
	}
	registry.SetClock(func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) })
	if _, err := registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal(overdue) error = %v, want DENIED", err)
	}
}

// safeHealthy L1189 — recovers from a panicking health probe.

// Falsify: a health probe that panics on a binding must report unhealthy.
// Without the recover, the panic propagates and the daemon is killed —
// which is its own refusal, but the audit record would not match every
// other DEPENDENCY_UNAVAILABLE in the cluster.
func TestSafeHealthyReturnsFalseWhenTheProbePanics(t *testing.T) {
	probe := panickingHealth{}
	binding := Binding{
		Site:     "sitea",
		Backend:  "nitrokey-pkcs11",
		DeviceID: "hs-1",
		ObjectID: "slot-1",
		State:    "active",
	}
	if safeHealthy(context.Background(), probe, binding) {
		t.Fatal("safeHealthy returned true after a panic")
	}
}

// HELPERS

// panickingHealth is a BackendHealth whose Healthy() method panics. It is
// used to exercise the recover branch in safeHealthy.
type panickingHealth struct{}

func (panickingHealth) Healthy(context.Context, Binding) bool { panic("test panic") }

// opaqueObjectWithRotation returns an opaque object whose rotation block is
// the given JSON. The package's helpers do not cover an opaque + rotation
// combination — the production object has both for release-secret — and the
// release-time deadline check runs against the rotation block.
func opaqueObjectWithRotation(rotation string) string {
	return fmt.Sprintf(`{"schema_version":1,"manifest_id":"rotate","generated_at":"2026-09-04T00:00:00Z","objects":[{"id":"deployment-api-token","name":"Deploy token","kind":"api-token","classification":"restricted","environment":"development","owner":"platform","purpose":"deployment-api","custody":"hardware-envelope","algorithm":"opaque","operations":["release-secret"],"policy_id":"test-policy","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":%s,"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}]}`, opaqueBinding("rsa2048"), rotation)
}
