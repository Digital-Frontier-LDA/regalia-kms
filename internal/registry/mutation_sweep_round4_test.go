package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Tests pinning four guards that the #237 mutation sweep named as survivors.
// Each test is §18-anchored: it exercises the guard with the input the sweep
// claimed was missing and asserts the production refusal. Mutation by line
// index (not text match — `if err != nil {` is everywhere) confirms the
// test fires on the guard it was written for. See regalia-mutation-anchor-must-be-unique.

// r4stagingBinding is a single release-secret-eligible binding on its own,
// staging environment, used to make every fixture a loadable manifest so the
// guard under test is the only thing standing between the input and the
// routing decision. `object()` hardcodes production (which requires 2 bindings
// or custody "exception"); staging does not, which is why we build fixtures
// inline.
const r4stagingBinding = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active","device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","kek_algorithm":"rsa4096","kek_version":"1"}`

// r4object wraps an operation and a binding in a staging-environment object
// the registry will load. The environment matters: a production object
// requires two hardware bindings, which makes a single-binding fixture refuse
// to load for an unrelated reason and hides whether the guard under test fires.
func r4object(id, purpose, operation, binding string) string {
	return fmt.Sprintf(`{"id":%q,"name":"R4","kind":"opaque-secret","classification":"restricted","environment":"staging","owner":"security","purpose":%q,"custody":"direct-hardware","algorithm":"opaque","operations":[%q],"policy_id":"test-policy","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`,
		id, purpose, operation, binding)
}

// TestRouteForUnwrapRefusesAnObjectThatDoesNotDeclareReleaseSecret pins the
// guard at registry.go:1036 — `if _, allowed := entry.operations["release-secret"]`.
// Defeating the guard SERVED an object whose manifest licenses only seal-envelope,
// which is the sweep's claim for this site. The control is a manifest whose
// operations include release-secret: same fixture except the operations list,
// routed to the same RouteForUnwrap call. Without that control, a function
// that refused everything would pass.
//
// The two objects live on different (site, device_id, object_id) slots, so
// the slot-conflict guard at :688 is not the one that fires here.
func TestRouteForUnwrapRefusesAnObjectThatDoesNotDeclareReleaseSecret(t *testing.T) {
	// The seal-only object stays on the manifest's slot; only the control moves,
	// so the two occupy different (site, device_id, object_id) slots.
	withReleaseBinding := strings.Replace(r4stagingBinding, `"device_id":"dev-1","object_id":"slot-1"`,
		`"device_id":"dev-2","object_id":"slot-2"`, 1)
	if withReleaseBinding == r4stagingBinding {
		t.Fatalf("the control binding was not moved off dev-1/slot-1 — both objects would share a slot and :688 would refuse the control before the guard under test could be reached")
	}

	sealOnly := r4object("seal-only", "release-purpose", "seal-envelope", r4stagingBinding)
	withRelease := r4object("with-release", "release-purpose", "release-secret", withReleaseBinding)

	health := &healthMap{states: map[string]bool{"dev-1": true, "dev-2": true}}
	registry, err := Load(strings.NewReader(manifest(sealOnly+","+withRelease)), "sitea", health)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// The control: release-secret IS declared, routing succeeds.
	if _, err := registry.RouteForUnwrap(context.Background(), "with-release", "release-purpose", "1"); err != nil {
		t.Fatalf("control: RouteForUnwrap(release-secret-declared) error = %v, want nil", err)
	}

	// The guard: release-secret NOT declared, routing is denied.
	_, err = registry.RouteForUnwrap(context.Background(), "seal-only", "release-purpose", "1")
	if !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(operations=[seal-envelope]) error = %v, want denied: an object that does not declare release-secret was routed for unwrap",
			err)
	}
}

// TestRouteForUnwrapRefusesAPlannedBinding pins the guard at
// registry.go:1072 — `if !UnwrapAllows(binding.State) { continue }`.
//
// `planned` means a slot with no key in it; routing there can only land on a
// card that must fail. The existing TestUnwrapRefusesAPlannedBinding only
// asserts UnwrapAllows("planned") == false, which a mutation that breaks the
// routing check (the guard under test here, not the leaf predicate) still
// passes. This test forces a planned-only manifest and asserts RouteForUnwrap
// returns denied.
func TestRouteForUnwrapRefusesAPlannedBinding(t *testing.T) {
	planned := strings.Replace(r4stagingBinding, `"state":"active"`, `"state":"planned"`, 1)
	if planned == r4stagingBinding {
		t.Fatal("fixture did not change: the binding is still active")
	}
	registry, err := Load(strings.NewReader(manifest(r4object("planned-key", "release-purpose", "release-secret", planned))), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	_, err = registry.RouteForUnwrap(context.Background(), "planned-key", "release-purpose", "1")
	if !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(planned-only) error = %v, want denied: a planned binding has no key, so routing there reaches a card that must fail",
			err)
	}
}

// TestLoadRefusesDuplicateObjectIDs pins the guard at registry.go:424 — the
// duplicate object-id refusal. The sweep's claim is that two objects sharing
// an id both loaded and the later silently replaced the earlier. The current
// code returns a load error on duplicate; the test asserts that. The control
// (a manifest with one entry) catches a function that refuses every load.
func TestLoadRefusesDuplicateObjectIDs(t *testing.T) {
	once := r4object("shared-id", "release-purpose", "release-secret", r4stagingBinding)
	twice := once + "," + r4object("shared-id", "release-purpose", "release-secret", r4stagingBinding)

	// The control: a manifest with one entry loads.
	if _, err := Load(strings.NewReader(manifest(once)), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true}}); err != nil {
		t.Fatalf("control: Load(one-entry) error = %v, want nil", err)
	}

	_, err := Load(strings.NewReader(manifest(twice)), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true}})
	if err == nil {
		t.Fatal("a manifest with two objects sharing an id loaded: the later silently replaced the earlier, or the first was kept without notice")
	}
	if !strings.Contains(err.Error(), "duplicate registry object id") {
		t.Fatalf("Load(two-with-shared-id) error = %v, want a duplicate-id refusal", err)
	}
}

// TestLoadRefusesTwoObjectsSharingAHardwareSlot pins the guard at
// registry.go:688 — `if other, exists := occupied[slot]; exists && other != object.ID`.
// The slot is site+device_id+object_id; two objects that name the same physical
// slot would each think the key is theirs. The control is a manifest where
// the second object uses a different slot.
func TestLoadRefusesTwoObjectsSharingAHardwareSlot(t *testing.T) {
	// Two objects with different IDs but identical (site, device_id, object_id).
	sharing := r4object("alpha", "release-purpose", "release-secret", r4stagingBinding) + "," +
		r4object("beta", "release-purpose", "release-secret", r4stagingBinding)

	// The control: a manifest with two objects on different slots loads.
	distinct := r4object("alpha", "release-purpose", "release-secret",
		`{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active","device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","kek_algorithm":"rsa4096","kek_version":"1"}`) + "," +
		r4object("beta", "release-purpose", "release-secret",
			`{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-2","object_id":"slot-2","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active","device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","kek_algorithm":"rsa4096","kek_version":"1"}`)
	if _, err := Load(strings.NewReader(manifest(distinct)), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true, "dev-2": true}}); err != nil {
		t.Fatalf("control: Load(distinct-slots) error = %v, want nil", err)
	}

	_, err := Load(strings.NewReader(manifest(sharing)), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true}})
	if err == nil {
		t.Fatal("a manifest commissioning two objects into one (site, device_id, object_id) slot loaded: each object would think it owns the key")
	}
	if !strings.Contains(err.Error(), "also assigned to") {
		t.Fatalf("Load(shared-slot) error = %v, want a slot-conflict refusal", err)
	}
}
