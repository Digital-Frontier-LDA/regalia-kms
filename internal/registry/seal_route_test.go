package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// sealObject builds a single-object manifest whose object is configured for seal-envelope. The
// helper exists because the package-wide object() helper assumes algorithm="secp256k1" and
// operation="sign"; a seal envelope's object is opaque + seal-envelope, and reusing those
// fixtures would lose the line between "the seal-side rules are different" and "the same field
// happens to be wrong".
func sealObject(objectID, purpose, bindings string) string {
	return fmt.Sprintf(`{"id":%q,"name":"seal target","kind":"opaque-secret","classification":"restricted","environment":"staging","owner":"security","purpose":%q,"custody":"hardware-envelope","algorithm":"opaque","operations":["seal-envelope"],"policy_id":"test-policy","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`,
		objectID, purpose, bindings)
}

// sealBinding mirrors registry_test.go's binding() but adds KEK fields. They are required on
// every seal-envelope binding (validateBinding at Load time refuses one without them), and the
// package-wide helper does not produce them. Sealing generates envelopes the binding's slot must
// later open; the version specifically is what an envelope's KEK reference is checked against,
// so its absence here would silently vanish what the envelope would later assert.
func sealBinding(site, backend, device, slot, state, kekAlg, kekVersion string) string {
	extra := ""
	if backend == "nitrokey-pkcs11" && state != "planned" && state != "retired" {
		extra = `,"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`
	}
	if kekAlg != "" || kekVersion != "" {
		extra += fmt.Sprintf(`,"kek_algorithm":%q,"kek_version":%q`, kekAlg, kekVersion)
	}
	return fmt.Sprintf(`{"site":%q,"backend":%q,"device_id":%q,"object_id":%q,"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":%q%s}`,
		site, backend, device, slot, state, extra)
}

func sealTestRegistry(t *testing.T, bindings string) *Registry {
	t.Helper()
	registry, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return registry
}

// The entry is advertised exactly when it is served: the primitive, the provider wrap
// case, the endpoint, and the coordinator path all landed (#84), so the matrix now
// promises it — and this test holds the matrix to the promise in both directions.
func TestCapabilitiesAdvertiseSealEnvelopeOnceServed(t *testing.T) {
	if !Capabilities()["nitrokey-pkcs11"]["opaque"]["seal-envelope"] {
		t.Fatal("nitrokey-pkcs11/opaque must advertise seal-envelope now that it is served: a manifest commissioning it would fail review while the daemon serves it")
	}
}

// TestSealAllowsReportsPermittedAndForbiddenStates pins the seal-eligibility function as the
// authorization surface. The previous form was a package-level mutable map named SealAllowedStates;
// that was an importer-writable surface (registry.SealAllowedStates["retired"] = struct{}{} would
// have widened eligibility with no diff and no review). SealAllows is a function backed by an
// unexported map, so the only way to widen it is to edit this package's source -- which is
// reviewable. The test asserts both halves: every state we say seal can use must be permitted,
// and every state we say it cannot must be refused. Re-introducing the original exported-map form
// would compile fine and the test would still pass; the security property is shape-based and
// lives in the function-symbol rename, not the test. Pair this with the explicit comment on
// sealEligibleStates to keep the rationale next to the data.
func TestSealAllowsReportsPermittedAndForbiddenStates(t *testing.T) {
	permitted := []string{"qualified", "active", "standby"}
	forbidden := []string{"planned", "retired", "", "unknown"}
	for _, state := range permitted {
		if !SealAllows(state) {
			t.Errorf("SealAllows(%q) = false; seal is permitted on commissioned (qualified), warmed-up (standby), and currently-serving (active) bindings", state)
		}
	}
	for _, state := range forbidden {
		if SealAllows(state) {
			t.Errorf("SealAllows(%q) = true; planned has no key to wrap against and retired leaves envelopes no live KEK can open", state)
		}
	}
}

func TestRouteForSealRoutesBindingInEachPermittedState(t *testing.T) {
	// One binding per allowed state (qualified|active|standby). The loadPath is identical for each
	// apart from the state string, so any error here points to validateBinding's state guard, not
	// the runtime selection. The Load succeeds per the existing validateBinding commissioning rule
	// (validateBinding of registry.go requires device_serial + DevAut fingerprint for qualified/active/standby
	// on nitrokey-pkcs11; planned/retired skip it).
	for _, state := range []string{"qualified", "active", "standby"} {
		t.Run(state, func(t *testing.T) {
			bindings := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", state, "rsa2048", "1")
			registry := sealTestRegistry(t, bindings)
			route, err := registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose")
			if err != nil {
				t.Fatalf("RouteForSeal() error = %v", err)
			}
			if route.Binding.State != state {
				t.Fatalf("RouteForSeal picked state %q, want %q", route.Binding.State, state)
			}
			if route.KEKAlgorithm != "rsa2048" || route.KEKVersion != "1" {
				t.Fatalf("RouteForSeal KEK = (algorithm=%q, version=%q); the sealer reads these to build the envelope's KEK reference", route.KEKAlgorithm, route.KEKVersion)
			}
		})
	}
}

func TestRouteForSealRefusesPlannedBindingAtLoadTime(t *testing.T) {
	// Falsifiability: removing the seal-envelope state guard from validateBinding makes this case
	// reach the binding's commissioning check (which allows planned because no serial is needed),
	// and Load would succeed -- so the test would fail for the reason its message names.
	control := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	if _, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", control))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}}); err != nil {
		t.Fatalf("control (state=active) must Load cleanly for this test to mean anything: %v", err)
	}

	planned := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "planned", "rsa2048", "1")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", planned))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load() = nil for a planned seal-envelope binding; planned seals against a slot that has no key yet")
	}
	if !strings.Contains(err.Error(), "planned") {
		t.Fatalf("Load() = %q; want an error that names the bad state", err)
	}
}

func TestRouteForSealRefusesRetiredBindingAtLoadTime(t *testing.T) {
	control := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	if _, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", control))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}}); err != nil {
		t.Fatalf("control (state=active) must Load cleanly: %v", err)
	}

	retired := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "retired", "rsa2048", "1")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", retired))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load() = nil for a retired seal-envelope binding; a retired slot has no key for the envelope to call back to")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("Load() = %q; want an error that names the bad state", err)
	}
}

func TestRouteForSealRefusesBindingWithoutKEKAlgorithmAtLoadTime(t *testing.T) {
	// The wrapper that opens an envelope (or wraps a fresh one) needs to know which key in the slot
	// it is talking to. A seal-envelope binding without kek_algorithm would reach the token with no
	// algorithm at all: the wrap would be a refusal from a real card and a no-op from a test stub.
	control := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	if _, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", control))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}}); err != nil {
		t.Fatalf("control (with kek_algorithm) must Load cleanly: %v", err)
	}

	missingKEK := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "", "1")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", missingKEK))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load() = nil for seal-envelope binding without kek_algorithm; the sealer's hardware wrap would have no key to address")
	}
	// THE MESSAGE, NOT JUST THE FIELD NAME. The #237 sweep neutralised the
	// empty-kek_algorithm guard and this test stayed green: the very next guard,
	// !supports(backend, "", "wrap"), refuses the same binding and its message
	// ("backend %q cannot wrap with kek_algorithm %q") also contains
	// "kek_algorithm". Matching the bare field name meant the test could never be
	// the sole failure for the guard it names. It also sent the operator to the
	// wrong remedy: "cannot wrap with kek_algorithm \"\"" reads as a capability
	// problem, and the fix is to fill in a field.
	if !strings.Contains(err.Error(), "must name the kek_algorithm") {
		t.Fatalf("Load() = %q; want the absent-field refusal, not the capability refusal that follows it", err)
	}
}

func TestRouteForSealRefusesBindingWithoutKEKVersionAtLoadTime(t *testing.T) {
	// kek_version is what lets the envelope (and Rewrap) tell generations apart. Without it, every
	// rewrite silently addresses whichever generation happens to be in the slot, and rotation
	// becomes decorative. The release path's analogous check at lines 439-447 closes the symmetric
	// hole; seal needs it for the same reason.
	control := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	if _, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", control))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}}); err != nil {
		t.Fatalf("control (with kek_version) must Load cleanly: %v", err)
	}

	missingVersion := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", missingVersion))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load() = nil for seal-envelope binding without kek_version")
	}
	// Same correction as the kek_algorithm case above, and the same cause: the
	// pattern check that follows refuses the empty string too, and its message
	// ("kek_version %q must match %s") also contains "kek_version". The #237
	// sweep neutralised the absent-field guard and this test did not move.
	if !strings.Contains(err.Error(), "must name the kek_version") {
		t.Fatalf("Load() = %q; want the absent-field refusal, not the pattern refusal that follows it", err)
	}
}

func TestRouteForSealRefusesBindingWhoseKEKAlgorithmTheBackendCannotWrap(t *testing.T) {
	// control: rsa2048 wrap is supported on nitrokey-pkcs11
	control := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	if _, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", control))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}}); err != nil {
		t.Fatalf("control (rsa2048 wrap on nitrokey-pkcs11) must Load cleanly: %v", err)
	}

	// aes-256 has no "wrap" entry in Capabilities(); a binding promising it for seal-envelope
	// would generate envelopes no key on the device could produce. The matrix check at Load time
	// is what stops it -- otherwise the wrap would fail later and report as a retryable backend
	// error.
	wrongAlgorithm := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "aes-256", "1")
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", wrongAlgorithm))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load() = nil for seal-envelope binding whose kek_algorithm the backend cannot wrap")
	}
	if !strings.Contains(err.Error(), "cannot wrap") {
		t.Fatalf("Load() = %q; want an error explaining the unsupported algorithm", err)
	}
}

func TestRouteForSealPicksBindingAtConfiguredSite(t *testing.T) {
	// Multi-site. The configured site is "sitea"; a binding at "siteb" must not be picked even
	// though it is in the same state. Same selection order as the existing selectBinding -- the
	// helper is shared because the rule is shared.
	sitea := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	siteb := sealBinding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "active", "rsa2048", "2")
	registry := sealTestRegistry(t, sitea+","+siteb)
	route, err := registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose")
	if err != nil {
		t.Fatalf("RouteForSeal() error = %v", err)
	}
	if route.Binding.Site != "sitea" {
		t.Fatalf("route picked site %q, want sitea", route.Binding.Site)
	}
	if route.KEKVersion != "1" {
		t.Fatalf("route picked the sitea binding's version %q, want 1", route.KEKVersion)
	}
}

func TestRouteForSealDeniesObjectThatDidNotAdvertiseTheOperation(t *testing.T) {
	// Build an object whose operations list does NOT include seal-envelope; the registry
	// promises release-secret only. The seal-side path must refuse even though a hardware key
	// exists, because the manifest didn't license the operation for this object.
	releaseOnlyObject := fmt.Sprintf(`{"id":"other-target","name":"other","kind":"opaque-secret","classification":"restricted","environment":"staging","owner":"security","purpose":"seal-purpose","custody":"hardware-envelope","algorithm":"opaque","operations":["release-secret"],"policy_id":"test-policy","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`,
		sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1"))
	registry, err := Load(strings.NewReader(manifest(releaseOnlyObject)), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, err := registry.RouteForSeal(context.Background(), "other-target", "seal-purpose"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal() error = %v; seal-envelope is not in this object's operations, so the registry must deny", err)
	}
}

func TestRouteForSealDeniesWrongPurpose(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	registry := sealTestRegistry(t, bindings)
	if _, err := registry.RouteForSeal(context.Background(), "seal-target", "wrong-purpose"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal() error = %v", err)
	}
}

func TestRouteForSealDeniesMissingObject(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	registry := sealTestRegistry(t, bindings)
	_, err := registry.RouteForSeal(context.Background(), "absent-object", "seal-purpose")
	if !IsCode(err, CodeNotFound) {
		t.Fatalf("RouteForSeal() error = %v; expected NOT_FOUND", err)
	}
}

func TestRouteForSealReturnsDependencyUnavailableWhenBindingUnhealthy(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active", "rsa2048", "1")
	registry, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": false}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	_, err = registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose")
	if !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("RouteForSeal() error = %v; expected DEPENDENCY_UNAVAILABLE for an unhealthy binding", err)
	}
}

// TestRouteForSealDoesNotColludeWithRoute proves that adding seal-envelope did not silently widen
// what Route() will serve. Per TESTING.md §6, the addition of an operation the matrix did not
// already have must not relax an existing guard: Route() must still pick active-only, even when
// the registry now has a RouteForSeal that is permitted to pick standby.
func TestRouteForSealDoesNotColludeWithRoute(t *testing.T) {
	bindings := sealBinding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "standby", "rsa2048", "1")
	registry, err := Load(strings.NewReader(manifest(sealObject("seal-target", "release-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// Route() for release-secret should DENY (assignment runs at Load, and at standby the active
	// binding is empty). The seal path is different and would ACCEPT.
	if _, err := registry.Route(context.Background(), "seal-target", "release-purpose", "release-secret"); !IsCode(err, CodeDenied) {
		t.Fatalf("release-secret on a standby-only object must be DENIED (release only routes active); got %v", err)
	}
	// This object is loaded under release-purpose, so the seal purpose must not resolve. The
	// assertion that this denial comes FROM the purpose check is made below against `rebuilt`,
	// where every other check passes -- see the comment there.
	if _, err := registry.RouteForSeal(context.Background(), "seal-target", "seal-purpose"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal() with a purpose the object does not declare = %v, want DENIED", err)
	}
	// Rebuild with the seal purpose so the seal path actually serves and we can compare.
	rebuilt, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))), "sitea",
		&healthMap{states: map[string]bool{"local-hsm": true}})
	if err != nil {
		t.Fatalf("Load(seal-purpose) error = %v", err)
	}
	if _, err := rebuilt.RouteForSeal(context.Background(), "seal-target", "seal-purpose"); err != nil {
		t.Fatalf("RouteForSeal() error = %v (release refused, seal must accept on the same standby-only object)", err)
	}

	// THE PURPOSE CHECK, TARGETED. registry.Error carries a Code and no reason, so a denial
	// from RouteForSeal cannot say WHICH check produced it -- asserting CodeDenied on the
	// call above is satisfied by any of the four. Verified: disabling the purpose comparison
	// leaves that assertion passing, because the operation set denies instead.
	//
	// So the causal case is asked of `rebuilt`, which resolves this object successfully one
	// line up. Every other check passes there by construction, which makes the purpose the
	// only thing that can deny -- and disabling the comparison makes this succeed.
	if _, err := rebuilt.RouteForSeal(context.Background(), "seal-target", "not-the-declared-purpose"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForSeal() with the wrong purpose on an object it otherwise serves = %v, "+
			"want DENIED -- the purpose is the only check this differs in, so it is not being made", err)
	}
}

// helper for §12-style fixture-precondition checks: when a test relies on HealthMap returning
// true for local-hsm, assert it. Avoids the false-green of "the test never reached the assertion".
func TestHealthProbeIsWiredWithLocalHSMHealthy(t *testing.T) {
	health := &healthMap{states: map[string]bool{"local-hsm": true}}
	if !health.Healthy(context.Background(), Binding{DeviceID: "local-hsm"}) {
		t.Fatal("HealthMap claims local-hsm is healthy but Healthy() returned false")
	}
}
