package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// rotatingObject builds a manifest object that both seals and releases, which is what a rotation
// needs and neither existing helper produces: sealObject declares seal-envelope alone, so it can
// describe the key that wraps and not the key that opens.
func rotatingObject(bindings string) string {
	return fmt.Sprintf(`{"id":"rotating-secret","name":"rotating","kind":"opaque-secret","classification":"restricted","environment":"staging","owner":"security","purpose":"seal-purpose","custody":"hardware-envelope","algorithm":"opaque","operations":["seal-envelope","release-secret"],"policy_id":"test-policy","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`, bindings)
}

func rotatingRegistry(t *testing.T, bindings string) *Registry {
	t.Helper()
	registry, err := Load(strings.NewReader(manifest(rotatingObject(bindings))), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true, "dev-2": true, "dev-3": true}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return registry
}

// retiredV1ActiveV2 is the state every rotation passes through: the new KEK serves, the old one
// still has to open what it sealed. Before #84 this manifest would not even load.
// nitrokey-pkcs11 because it is the only backend the capability matrix advertises seal-envelope
// for; a fixture on a backend that cannot seal would fail Load for an unrelated reason and never
// reach the rotation rules under test. A commissioned Nitrokey needs a pinned serial and DevAut
// fingerprint — a retired one does not, which is validateBinding's existing distinction.
const retiredV1 = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"retired","kek_algorithm":"rsa4096","kek_version":"1"}`
const activeV2 = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-2","object_id":"slot-2","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active","device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","kek_algorithm":"rsa4096","kek_version":"2"}`

// TestARotatedManifestLoadsAtAll is the precondition for everything below, and was false until
// #84: validateBinding refused any retired binding on a seal-capable object, so the state a
// rotation is always briefly in could not be written down.
func TestARotatedManifestLoadsAtAll(t *testing.T) {
	rotatingRegistry(t, retiredV1+","+activeV2)
}

// TestUnwrapResolvesTheRetiredKEKTheEnvelopeNames is the point of the change: an envelope sealed
// under v1 must still reach v1's slot after v2 takes over.
func TestUnwrapResolvesTheRetiredKEKTheEnvelopeNames(t *testing.T) {
	registry := rotatingRegistry(t, retiredV1+","+activeV2)

	route, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", "1")
	if err != nil {
		t.Fatalf("a v1 envelope must still open after v1 retires: RouteForUnwrap() error = %v", err)
	}
	// The slot, not just the version: a route carrying version 1 while pointing at v2's device
	// would send the old envelope to the new card, where it cannot unwrap.
	if route.Binding.ObjectID != "slot-1" || route.KEKVersion != "1" {
		t.Fatalf("resolved to slot %q version %q, want slot-1/1 — the envelope's own generation must choose the slot",
			route.Binding.ObjectID, route.KEKVersion)
	}
	if route.Binding.State != "retired" {
		t.Fatalf("resolved binding state = %q, want retired: if this is active the test is proving nothing about rotation", route.Binding.State)
	}
}

// TestSealNeverPicksTheRetiredKEK is the other half. Retired means "opens what it sealed", not
// "still wraps": widening unwrap must not widen seal, or a rotation would keep minting envelopes
// under the key it is retiring.
func TestSealNeverPicksTheRetiredKEK(t *testing.T) {
	registry := rotatingRegistry(t, retiredV1+","+activeV2)

	route, err := registry.RouteForSeal(context.Background(), "rotating-secret", "seal-purpose")
	if err != nil {
		t.Fatalf("RouteForSeal() error = %v", err)
	}
	if route.KEKVersion != "2" || route.Binding.State != "active" {
		t.Fatalf("seal routed to version %q in state %q, want the active 2: a retired KEK must not wrap anything new",
			route.KEKVersion, route.Binding.State)
	}
	if SealAllows("retired") {
		t.Fatal("SealAllows(retired) is true: the seal and unwrap eligibility sets have been collapsed into one")
	}
	if !UnwrapAllows("retired") {
		t.Fatal("UnwrapAllows(retired) is false, so a rotation still strands every envelope sealed before it")
	}
}

// TestUnwrapRefusesAVersionNoBindingHolds — the caller-supplied version selects, so it must select
// nothing when it names nothing.
//
// ONE BINDING, DELIBERATELY. Written first against the two-binding fixture, this passed with the
// version filter deleted: with v1 and v2 both eligible the request matched both and was denied by
// the DUPLICATE guard instead, so the test reported the right verdict for the wrong reason and
// could not see the filter disappear. With only v2 present, dropping the filter returns v2's route
// for a v1 envelope — an old envelope silently sent to the new card — and the test goes red.
func TestUnwrapRefusesAVersionNoBindingHolds(t *testing.T) {
	registry := rotatingRegistry(t, activeV2)

	route, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", "1")
	if err == nil {
		t.Fatalf("RouteForUnwrap(version 1) resolved to version %q with no v1 binding in the manifest: an unheld generation fell back to a live key",
			route.KEKVersion)
	}
	if !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(version 1) error = %v, want denied", err)
	}
	// AND NO REASON, WHICH IS THE OTHER HALF OF #160'S DISTINCTION.
	//
	// TestAnEnvelopeUnderARevokedKEKIsRefusedWithTheDistinctReason pins the
	// positive: a miss caused by a revoked candidate is audited as kek-revoked.
	// The #237 sweep forced `revokedCandidateExists` true and nothing failed —
	// so the negative was unpinned, and an ordinary configuration mistake (a
	// version nobody holds) would be recorded as permanent data loss by design.
	// An operator reading that audit row stops looking for the misconfiguration.
	if reason := RefusalReason(err); reason != "" {
		t.Fatalf("RouteForUnwrap(version 1) reason = %q on a manifest with no revoked binding at all; "+
			"a plain routing miss recorded as %q tells the operator the envelope is gone forever when "+
			"the manifest is simply wrong", reason, ReasonRevoked)
	}
}

// TestUnwrapRefusesAnEmptyVersion. An empty string matching the first eligible binding is how
// "resolve by version" quietly degrades into "whatever is there".
//
// THE STATE THIS GUARDS IS ONE Load REFUSES, which is why the guard has to be tested against a
// registry built by hand. validateBinding requires a kek_version on every release-secret binding,
// so no loadable manifest reaches RouteForUnwrap with an empty one to match — and against a
// loadable manifest, deleting the empty-version check changes nothing and the test stays green
// while proving nothing. Both layers are asserted here so it is clear which one does what: Load
// refuses to describe the state, and the routing guard refuses to act on it if anything ever
// constructs it another way (RouteForUnwrap is exported; Load is not its only caller's only path).
func TestUnwrapRefusesAnEmptyVersion(t *testing.T) {
	emptyVersion := strings.Replace(activeV2, `"kek_version":"2"`, `"kek_version":""`, 1)
	if emptyVersion == activeV2 {
		t.Fatal("fixture did not change: the binding still names version 2")
	}
	if _, err := Load(strings.NewReader(manifest(rotatingObject(emptyVersion))), "sitea",
		&healthMap{states: map[string]bool{"dev-2": true}}); err == nil {
		t.Fatal("a manifest with an empty kek_version loaded: the routing guard below is then the only thing standing between an envelope and any live key")
	}

	registry := rotatingRegistry(t, activeV2)
	// The state Load will not produce, produced directly. In-package access is the point: this is
	// the shape a future relaxation of validateBinding would let through.
	entry := registry.entries["rotating-secret"]
	entry.bindings[0].KEKVersion = ""
	registry.entries["rotating-secret"] = entry

	if _, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", ""); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap(\"\") error = %v, want denied: an empty version matched a binding that also has none", err)
	}
}

// TestUnwrapRefusesTwoBindingsClaimingOneGeneration. Which card opened a secret must not depend on
// iteration order.
func TestUnwrapRefusesTwoBindingsClaimingOneGeneration(t *testing.T) {
	duplicate := strings.Replace(retiredV1, `"device_id":"dev-1","object_id":"slot-1"`, `"device_id":"dev-3","object_id":"slot-3"`, 1)
	if duplicate == retiredV1 {
		t.Fatal("fixture did not change: the duplicate binding is the same one, so this proves nothing")
	}
	registry := rotatingRegistry(t, retiredV1+","+duplicate+","+activeV2)

	if _, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", "1"); !IsCode(err, CodeDenied) {
		t.Fatalf("RouteForUnwrap() error = %v, want denied when two slots claim version 1", err)
	}
}

// TestUnwrapRefusesAPlannedBinding. planned has no key in the slot, so nothing was ever wrapped
// against it and admitting it would only route to a card that must fail.
func TestUnwrapRefusesAPlannedBinding(t *testing.T) {
	if UnwrapAllows("planned") {
		t.Fatal("UnwrapAllows(planned) is true: a slot with no key would be routed to")
	}
}

// TestAnObjectThatSealsMustStillHaveSomethingThatCanSeal replaces the per-binding retired refusal
// removed in #84, and catches strictly more: the old check passed each binding in isolation, so an
// object whose bindings were ALL retired was rejected one-at-a-time for the wrong reason and an
// object with none would not be rejected at all.
func TestAnObjectThatSealsMustStillHaveSomethingThatCanSeal(t *testing.T) {
	onlyRetired := strings.Replace(activeV2, `"state":"active"`, `"state":"retired"`, 1)
	if onlyRetired == activeV2 {
		t.Fatal("fixture did not change: both bindings are still active")
	}
	_, err := Load(strings.NewReader(manifest(rotatingObject(retiredV1+","+onlyRetired))), "sitea",
		&healthMap{states: map[string]bool{"dev-1": true, "dev-2": true, "dev-3": true}})
	if err == nil {
		t.Fatal("a manifest whose every binding is retired loaded: the object declares seal-envelope and nothing can seal")
	}
	if !strings.Contains(err.Error(), "no binding at site") {
		t.Fatalf("Load() error = %v, want the seal-eligibility refusal — another rule rejecting this manifest would hide whether the new one works", err)
	}
}
