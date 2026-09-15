package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// revoked is the new binding state admitted by #160: wraps-no, unwraps-no, refuses at route for
// both seal and unwrap. Envelopes sealed under a revoked KEK become unrecoverable by design, so
// the runbook row for setting the state warns about this before the operator can set it; the
// audit record names the refusal so a release at 3am is not mistaken for a routing failure.

const revokedV1 = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"revoked","kek_algorithm":"rsa4096","kek_version":"1"}`

// revokedOnlyReleaseRegistry loads an object whose only binding is `revoked` and whose only
// declared operation is `release-secret`. Release-only is the deliberate shape: a revoked
// KEK that operators still need to record in the manifest, but whose object has no live sealer
// (because revoking the last sealer and leaving `seal-envelope` declared would fail the
// existing seal-eligibility check at Load time — see TestSealManifestWithOnlyRevokedBindingsIsRefusedAtLoad
// for that side). The fact that this Load succeeds is the new admission in #160: before it,
// validateBinding refused the state at parse time.
//
// The object uses environment="staging" because the Load-time production rule requires either
// two hardware bindings or custody "exception"; the revoked-only fixture is testing the state
// admission and the audit-string distinction, neither of which depends on the multi-binding rule,
// and adding a second binding would hide the test under unrelated routing constraints.
func revokedOnlyReleaseRegistry(t *testing.T) *Registry {
	t.Helper()
	bindings := `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"revoked","kek_algorithm":"rsa4096","kek_version":"1"}`
	registry, err := Load(strings.NewReader(manifest(revokedOnlyReleaseObject(bindings))),
		"sitea", &healthMap{states: map[string]bool{"dev-1": true}})
	if err != nil {
		t.Fatalf("Load() error = %v: nothing-but-the-revoked-state must be loadable so the operator can record the fact in the manifest", err)
	}
	return registry
}

// revokedOnlyReleaseObject is a copy of object() with environment=staging so the production
// 2-binding rule does not fire. The state-admission half of #160 is independent of that rule —
// revoking a binding is what the operator does at any environment, and the rule must not mask
// the test. Mirrors object()'s field shape so a future schema change in one will surface as a
// compilation error in the other.
func revokedOnlyReleaseObject(bindings string) string {
	return fmt.Sprintf(`{
		"id":"revoked-only","name":"Revoked KEK only","kind":"asymmetric-key","classification":"critical","environment":"staging",
		"owner":"security","purpose":"release-purpose","custody":"direct-hardware","algorithm":"opaque",
		"operations":["release-secret"],"policy_id":"test-policy","bindings":[%s],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null},
		"migration":{"status":"migrated","source":"test"},
		"verification":{"status":"verified"}
	}`, bindings)
}

// TestRevokedIsAValidBindingState pins the admission half. A binding in state `revoked` must be
// loadable: the operator needs to write "this KEK is revoked" into the manifest before any
// release-side check can refuse an envelope under it. Before #160, validateBinding refused any
// unknown state with "unsupported binding state". Adding `revoked` here is the line that closes
// the gap on the load side.
//
// Falsified by: removing the literal `"revoked"` from validateBinding's state list. The test
// then fails with the registry.Error message "unsupported binding state \"revoked\"" — the same
// error a real operator would see at 3am when trying to record a compromise.
func TestRevokedIsAValidBindingState(t *testing.T) {
	revokedOnlyReleaseRegistry(t)
}

// TestRevokedIsExcludedFromUnwrapAllows pins the unwrap side. The unwrap eligibility set governs
// the RouteForUnwrap filter; admitting `revoked` would let a release succeed against a KEK the
// operator marked as gone. Before #160 there was no state with this exclusion (planned is
// excluded too, but for a different reason — no key in the slot yet); the gap is that `revoked`
// had to be excluded separately, not be conflated with `retired`.
//
// Falsified by: adding `"revoked": {}` to unwrapEligibleStates. The test fails with
// "UnwrapAllows(revoked) is true: a compromised KEK must not open what it sealed", which names
// the consequence an operator would experience as silent data leak if the gate were missing.
func TestRevokedIsExcludedFromUnwrapAllows(t *testing.T) {
	if UnwrapAllows("revoked") {
		t.Fatal("UnwrapAllows(revoked) is true: a compromised KEK must not open what it sealed")
	}
}

// TestRevokedIsExcludedFromSealAllows pins the seal side. The seal eligibility set is the one
// that picks a binding for a NEW envelope; admitting `revoked` would let the daemon write fresh
// envelopes under a key the operator has explicitly removed from service. The two exclusions
// (unwrap-no and seal-no) together make `revoked` mean "this KEK is gone for every operation" —
// which is the only definition consistent with the data-loss-by-design property #160 names.
//
// Falsified by: adding `"revoked": {}` to sealEligibleStates. The test fails with
// "SealAllows(revoked) is true: a revoked KEK must not wrap anything new", which names the
// consequence — silent minting of envelopes under a removed key, recoverable only by undoing
// the revocation.
func TestRevokedIsExcludedFromSealAllows(t *testing.T) {
	if SealAllows("revoked") {
		t.Fatal("SealAllows(revoked) is true: a revoked KEK must not wrap anything new")
	}
}

// TestAnEnvelopeUnderARevokedKEKIsRefusedWithTheDistinctReason is the audit-string half.
// RouteForUnwrap returns CodeDenied + ReasonRevoked when the only binding at the envelope's
// KEK generation was excluded by UnwrapAllows because its state was `revoked`. The coordinator
// maps ReasonRevoked to the audit outcome `denied-kek-revoked` (coordinator_revoked_test.go pins
// that side separately). Without the Reason, the refusal looks identical to a routing failure —
// and a responder at 3am opens RBAC, not the runbook for setting `revoked`.
//
// Falsified by: deleting the `if revokedCandidateExists` block from RouteForUnwrap. The test
// then fails because RefusalReason is "" — a routing denial looks the same as a revoked-KEK
// denial in the audit record.
func TestAnEnvelopeUnderARevokedKEKIsRefusedWithTheDistinctReason(t *testing.T) {
	registry := revokedOnlyReleaseRegistry(t)

	_, err := registry.RouteForUnwrap(context.Background(), "revoked-only", "release-purpose", "1")
	if err == nil {
		t.Fatal("RouteForUnwrap() succeeded against a revoked KEK: an envelope sealed under a revoked KEK must not open")
	}
	if !IsCode(err, CodeDenied) {
		t.Fatalf("err = %v, want CodeDenied", err)
	}
	if RefusalReason(err) != ReasonRevoked {
		t.Fatalf("RefusalReason(err) = %q, want %q: a release refused because the matched KEK is revoked must be distinguishable in the audit record from a routing failure",
			RefusalReason(err), ReasonRevoked)
	}
}

// TestAnEnvelopeUnderAHealthyKEKStillOpensWhenAnotherBindingIsRevoked pins the live-KEK side.
// A revoked binding on the same object must not poison routing for an envelope sealed against a
// generation that IS active. The envelope's own kek_version selects, so a v2 envelope against
// an object that has both a revoked v1 and an active v2 reaches v2 and opens. Without this, a
// loading operator who marks a key revoked would observe every release against the object fail,
// including those that do not touch the revoked generation — and the response would be "stop
// revoking things", which is the wrong lesson.
//
// Falsified by: removing the State == "revoked" branch from the RouteForUnwrap loop, which
// causes revoked bindings to short-circuit and prevent the loop from finding the active one.
// The test then fails because RouteForUnwrap returns CodeDenied — a v2 envelope refused.
func TestAnEnvelopeUnderAHealthyKEKStillOpensWhenAnotherBindingIsRevoked(t *testing.T) {
	registry := rotatingRegistry(t, revokedV1+","+activeV2)

	route, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", "2")
	if err != nil {
		t.Fatalf("a v2 envelope must still open when v1 is revoked: RouteForUnwrap(v2) error = %v", err)
	}
	if route.KEKVersion != "2" || route.Binding.State != "active" {
		t.Fatalf("resolved to version %q in state %q, want active/2: a revoked sibling must not shadow the live binding",
			route.KEKVersion, route.Binding.State)
	}
}

// TestAnEnvelopeUnderARevokedKEKUsesTheDistinctReasonEvenWithALiveSibling is the same point as
// above, applied to the revoked generation: an envelope whose KEK version names the revoked
// binding must take the ReasonRevoked path even when another binding on the same object is
// active. The envelope says "open me with version 1" — the loop filters v1 out as revoked —
// and the refusal has to carry ReasonRevoked, not CodeDenied-by-mistake.
//
// Falsified by: deleting the revokedCandidateExists flag. The test fails because the v1
// envelope's refusal has no reason in its audit record.
func TestAnEnvelopeUnderARevokedKEKUsesTheDistinctReasonEvenWithALiveSibling(t *testing.T) {
	registry := rotatingRegistry(t, revokedV1+","+activeV2)

	_, err := registry.RouteForUnwrap(context.Background(), "rotating-secret", "seal-purpose", "1")
	if err == nil {
		t.Fatal("RouteForUnwrap() succeeded against a revoked v1 KEK: a v1 envelope must not open after v1 is revoked")
	}
	if RefusalReason(err) != ReasonRevoked {
		t.Fatalf("RefusalReason(err) = %q, want %q even when another binding on the same object is active",
			RefusalReason(err), ReasonRevoked)
	}
}

// TestSealManifestWithOnlyRevokedBindingsIsRefusedAtLoad pins the Load-time gate. A manifest
// that declares seal-envelope must have a binding that can seal; validateBinding enforces this
// via its seal-eligibility loop (the `for _, operation := range object.Operations` block that
// calls SealAllows on each binding). `revoked` already fails SealAllows, so this test confirms
// the check integrates correctly: it does not need to know about revoked by name, because the
// existing SealAllows lookup excludes it. This is the negative of the seal-side gate, written
// as a Load-time test instead of a RouteForSeal test.
//
// Falsified by: widening the seal-eligibility iteration to admit `revoked`. The test fails
// because Load returns no error on a manifest whose only seal-capable binding is revoked.
func TestSealManifestWithOnlyRevokedBindingsIsRefusedAtLoad(t *testing.T) {
	bindings := `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"revoked","kek_algorithm":"rsa4096","kek_version":"1"}`
	_, err := Load(strings.NewReader(manifest(sealObject("seal-target", "seal-purpose", bindings))),
		"sitea", &healthMap{states: map[string]bool{"local-hsm": true}})
	if err == nil {
		t.Fatal("Load accepted a seal-envelope manifest whose only binding is revoked: the seal side has no live candidate")
	}
	if !strings.Contains(err.Error(), "seal-envelope") || !strings.Contains(err.Error(), "no binding") {
		t.Fatalf("err = %v, want the existing seal-eligibility refusal message naming the cause", err)
	}
}
