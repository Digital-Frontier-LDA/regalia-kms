package registry

// ROUND 5 OF THE #237 MUTATION SWEEP — REGISTRY LAYER.
//
// Re-derived on origin/main with kms/tools/guardenum: 120 sites / 164 operands
// / 328 operand-directions. Each operand was neutralised (the identity of its
// joiner: `(false && x)` inside an `||` chain, `(true || x)` inside an `&&`
// chain) and dominated (the annihilator, forcing the whole chain), one at a
// time, against the whole package suite.
//
// Every test below pins one operand-direction that NOTHING in the suite
// detected, and each was falsified by re-applying that single mutation and
// confirming this test was the SOLE failure. Where a test could not be the
// sole failure it says so in its own comment rather than presenting itself as
// a gate.
//
// THE UNIT MATTERS. "Untested" here means no test distinguishes the guard's
// presence from its absence — it is never a claim that the guard is wrong.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

const r5fingerprint = `"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`
const r5devaut = `"device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`

// r5object builds a STAGING object. object() hardcodes production, and a
// production object needs two hardware bindings or custody "exception" — a
// single-binding fixture would then be refused for a reason that has nothing
// to do with the guard under test, and the test would pass while proving
// nothing.
func r5object(id, purpose, kind, algorithm, custody, operations, bindings string) string {
	return fmt.Sprintf(`{"id":%q,"name":"R5","kind":%q,"classification":"restricted","environment":"staging",`+
		`"owner":"security","purpose":%q,"custody":%q,"algorithm":%q,"operations":[%s],"policy_id":"test-policy",`+
		`"bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},`+
		`"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},`+
		`"verification":{"status":"verified"}}`,
		id, kind, purpose, custody, algorithm, operations, bindings)
}

func r5nitrokey(site, device, slot, state, kekAlgorithm, kekVersion string) string {
	kek := ""
	if kekAlgorithm != "" || kekVersion != "" {
		kek = fmt.Sprintf(`,"kek_algorithm":%q,"kek_version":%q`, kekAlgorithm, kekVersion)
	}
	return fmt.Sprintf(`{"site":%q,"backend":"nitrokey-pkcs11","device_id":%q,"object_id":%q,%s,%s,"state":%q%s}`,
		site, device, slot, r5fingerprint, r5devaut, state, kek)
}

// r5yubikey parameterises the three fields validateBinding's YubiKey branch
// reads. The package-wide binding() helper hardcodes pin_policy=once,
// touch_policy=never and a serial on every commissioned state, so no fixture
// in the suite could vary them — which is why the whole branch survived.
func r5yubikey(state, serial, pinPolicy, touchPolicy string) string {
	extra := ""
	if serial != "" {
		extra += fmt.Sprintf(`,"device_serial":%q`, serial)
	}
	if pinPolicy != "" {
		extra += fmt.Sprintf(`,"pin_policy":%q`, pinPolicy)
	}
	if touchPolicy != "" {
		extra += fmt.Sprintf(`,"touch_policy":%q`, touchPolicy)
	}
	return fmt.Sprintf(`{"site":"sitea","backend":"yubikey-piv","device_id":"yk-1","object_id":"slot-1",%s,"state":%q%s}`,
		r5fingerprint, state, extra)
}

func r5load(t *testing.T, objects string, devices ...string) (*Registry, error) {
	t.Helper()
	states := make(map[string]bool, len(devices))
	for _, device := range devices {
		states[device] = true
	}
	return Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: states})
}

// ---------------------------------------------------------------------------
// The error type's two discriminators
// ---------------------------------------------------------------------------

// registry.go:69 operand 1 — `registryErr.Code == code` inside IsCode.
//
// Neutralised (`(true || registryErr.Code == code)`) IsCode answers true for
// EVERY registry error whatever code it is asked about, and nothing noticed.
// IsCode is how every caller tells a permanent refusal (DENIED) from a
// retryable one (DEPENDENCY_UNAVAILABLE) and from a missing object
// (NOT_FOUND); collapsing them makes the first code a caller happens to test
// swallow the other two. The suite only ever asked IsCode about the code it
// expected, so the discriminating half had never been exercised.
func TestIsCodeDistinguishesTheCodeItWasAskedAbout(t *testing.T) {
	for _, actual := range []Code{CodeDenied, CodeNotFound, CodeDependencyUnavailable} {
		err := error(&Error{Code: actual})
		if !IsCode(err, actual) {
			t.Fatalf("IsCode(%v, %q) = false", err, actual)
		}
		for _, other := range []Code{CodeDenied, CodeNotFound, CodeDependencyUnavailable} {
			if other == actual {
				continue
			}
			if IsCode(err, other) {
				t.Fatalf("IsCode(Code=%q, %q) = true: a caller mapping a refusal to an HTTP status "+
					"would report every registry error as whichever code it tested first — a permanent "+
					"denial read as a retryable dependency outage is a client that retries forever",
					actual, other)
			}
		}
	}
	if IsCode(fmt.Errorf("not a registry error"), CodeDenied) {
		t.Fatal("IsCode() = true for a non-registry error")
	}
}

// registry.go:61 operand 0 — `err.Reason == ""` inside (*Error).Error().
//
// BOTH directions survived: nothing in the package called Error() at all, so
// the message an operator reads in the audit record was unpinned in either
// direction. Reason is the field that separates "the manifest is misconfigured"
// from "this KEK was revoked and the envelope is gone by design" (#160).
func TestErrorMessageNamesTheReasonExactlyWhenThereIsOne(t *testing.T) {
	if got := (&Error{Code: CodeDenied}).Error(); got != "KMS routing failed" {
		t.Fatalf("Error() = %q for a reasonless refusal, want %q", got, "KMS routing failed")
	}
	got := (&Error{Code: CodeDenied, Reason: ReasonRevoked}).Error()
	if got != "KMS routing failed: kek-revoked" {
		t.Fatalf("Error() = %q, want it to carry the reason: the audit record is where an operator "+
			"learns that the envelope is unopenable by decision rather than by misconfiguration", got)
	}
}

// ---------------------------------------------------------------------------
// Load-time validation
// ---------------------------------------------------------------------------

// registry.go:266 operand 0 — `len(raw) == 0` inside rotationDeadline.
//
// Neutralised, an object with NO rotation block is refused at Load with
// "rotation policy is malformed", because json.Unmarshal of zero bytes is an
// error. rotation is not a required field: validateObject:667 requires
// algorithm, policy_id, environment, classification, verification and
// operations, and says nothing about rotation.
//
// This is a REFUSAL-direction defect, which a sweep is structurally worst at
// finding: every negative test stays green while the daemon refuses a
// legitimate manifest. envelopeMaxAge's identical guard at :285 has a direct
// unit test ("no rotation block at all"); rotationDeadline's had none, and no
// fixture anywhere reached Load without a rotation block.
func TestAnObjectWithNoRotationBlockLoadsWithNoDeadline(t *testing.T) {
	object := `{"id":"no-rotation","name":"R5","kind":"asymmetric-key","classification":"restricted",` +
		`"environment":"staging","owner":"security","purpose":"signing","custody":"direct-hardware",` +
		`"algorithm":"secp256k1","operations":["sign"],"policy_id":"test-policy","bindings":[` +
		r5nitrokey("sitea", "dev-1", "slot-1", "active", "", "") + `],` +
		`"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},` +
		`"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`
	if strings.Contains(object, `"rotation"`) {
		t.Fatal("the fixture still carries a rotation block; it cannot exercise the absent case")
	}

	registry, err := r5load(t, object, "dev-1")
	if err != nil {
		t.Fatalf("Load() error = %v; rotation is not a required field, and refusing an object that "+
			"omits it takes the daemon out of service for a manifest the schema accepts", err)
	}
	if overdue := registry.OverdueObjects(time.Now().AddDate(10, 0, 0)); len(overdue) != 0 {
		t.Fatalf("OverdueObjects() = %v ten years on; an absent rotation block establishes no deadline", overdue)
	}
}

// registry.go:664 operands 0 and 1 — the identifier shape of id and purpose.
//
// Neither survived because it is masked: neutralised, NOTHING else refuses a
// non-identifier id or purpose. No fixture in the suite fed either one, so the
// two operands that decide what an object may be CALLED were unexercised.
// A separate case per operand: one fixture spoiling both would leave each
// masked by the other, and pin neither.
func TestObjectIDAndPurposeMustBeLowercaseIdentifiers(t *testing.T) {
	binding := r5nitrokey("sitea", "dev-1", "slot-1", "active", "", "")
	control := r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware", `"sign"`, binding)
	if _, err := r5load(t, control, "dev-1"); err != nil {
		t.Fatalf("control must load for the cases below to mean anything: %v", err)
	}

	for name, object := range map[string]string{
		"id is not an identifier": r5object("Wallet-Key", "cosmos-transaction", "asymmetric-key", "secp256k1",
			"direct-hardware", `"sign"`, binding),
		"purpose is not an identifier": r5object("wallet-key", "Cosmos_Transaction", "asymmetric-key", "secp256k1",
			"direct-hardware", `"sign"`, binding),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r5load(t, object, "dev-1")
			if err == nil {
				t.Fatal("Load() accepted it; an object the manifest cannot name consistently is one the " +
					"policy engine looks up by a key nothing else spells the same way")
			}
			if !strings.Contains(err.Error(), "id and purpose must be lowercase identifiers") {
				t.Fatalf("err = %v, want the identifier refusal", err)
			}
		})
	}
}

// registry.go:667 operands 4 and 5 — `len(object.Verification) == 0` and
// `len(object.Operations) == 0`.
//
// Neutralised, both load. verification appears nowhere else in the loader, so
// nothing else can refuse its absence; an empty operations list makes
// validateBinding's per-operation loop and validateObject's seal loop both run
// zero times, so the object loads and then refuses every request it receives
// with a code that blames routing.
//
// The two blank-field cases in TestValidateObjectRefusesMissingRequiredFields
// (algorithm, classification) are NOT repeated here — that test is tightened in
// place instead, since asserting only `err != nil` let :578 and :750 refuse the
// fixture on its behalf.
func TestValidateObjectRequiresVerificationAndAtLeastOneOperation(t *testing.T) {
	binding := r5nitrokey("sitea", "dev-1", "slot-1", "active", "", "")
	noVerification := `{"id":"wallet-key","name":"R5","kind":"asymmetric-key","classification":"restricted",` +
		`"environment":"staging","owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware",` +
		`"algorithm":"secp256k1","operations":["sign"],"policy_id":"test-policy","bindings":[` + binding + `],` +
		`"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},` +
		`"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"}}`
	if strings.Contains(noVerification, `"verification"`) {
		t.Fatal("the fixture still carries a verification block")
	}

	for name, object := range map[string]string{
		"no verification block": noVerification,
		"no operations": r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1",
			"direct-hardware", ``, binding),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := r5load(t, object, "dev-1")
			if err == nil {
				t.Fatal("Load() accepted it")
			}
			if !strings.Contains(err.Error(), "algorithm, policy, environment and operations are required") {
				t.Fatalf("err = %v, want the required-fields refusal", err)
			}
		})
	}
}

// registry.go:725 operand 0 — `!ok` on the bindingStates lookup.
//
// Neutralised, ANY string is a binding state. No fixture in the suite ever fed
// an unknown one: TestLoadRejectsAmbiguousDuplicateUnsupportedAndIncompatibleEntries
// covers a duplicate id, two active bindings, an unknown backend and a
// capability mismatch — the "Unsupported" in its name is the backend, not the
// state.
//
// The consequence is silent rather than loud. A state that is not in the enum
// is not in commissionedStates either, so the device-pinning rules skip it, and
// it is not "active", so selectBinding skips it: a binding typed "activee"
// becomes an inert entry that pins no hardware and serves nothing, and the
// manifest reads as if the device were commissioned.
func TestAnUnsupportedBindingStateIsRefusedByName(t *testing.T) {
	control := r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware",
		`"sign"`, r5nitrokey("sitea", "dev-1", "slot-1", "active", "", ""))
	if _, err := r5load(t, control, "dev-1"); err != nil {
		t.Fatalf("control must load: %v", err)
	}

	typo := r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware",
		`"sign"`, r5nitrokey("sitea", "dev-1", "slot-1", "activee", "", ""))
	_, err := r5load(t, typo, "dev-1")
	if err == nil {
		t.Fatal("Load() accepted binding state \"activee\": a state outside the enum pins no device " +
			"(commissionedStates skips it) and routes nothing (selectBinding wants \"active\"), so the " +
			"manifest records a commissioned card that the daemon will never reach")
	}
	if !strings.Contains(err.Error(), "unsupported binding state") {
		t.Fatalf("err = %v, want the unsupported-state refusal", err)
	}
}

// ---------------------------------------------------------------------------
// The YubiKey branch of validateBinding — untested in both directions
// ---------------------------------------------------------------------------

// registry.go:734 — `commissioned && binding.DeviceSerial == ""`, dominated.
//
// Forcing the condition false accepts a commissioned YubiKey that pins no
// serial, and nothing detected it. This is the twin of
// TestACommissionedNitrokeyMustPinItsSerialAndFingerprint (:729), which exists:
// one side of the bound was named and the other was not. Without the pin, "this
// key lives on THAT card" is a sentence the manifest cannot check — any YubiKey
// presented at the right slot answers for the key.
func TestACommissionedYubiKeyMustPinItsSerial(t *testing.T) {
	// The control is the same binding in a state that is not commissioned:
	// planned needs no serial, so a Load failure here would mean the fixture
	// is refused for some reason other than the pin.
	planned := r5object("piv-key", "piv-purpose", "asymmetric-key", "rsa2048", "direct-hardware", `"sign"`,
		r5yubikey("planned", "", "once", "never"))
	if _, err := r5load(t, planned, "yk-1"); err != nil {
		t.Fatalf("control (planned, no serial) must load: %v", err)
	}

	for _, state := range []string{"qualified", "active", "standby"} {
		t.Run(state, func(t *testing.T) {
			object := r5object("piv-key", "piv-purpose", "asymmetric-key", "rsa2048", "direct-hardware", `"sign"`,
				r5yubikey(state, "", "once", "never"))
			_, err := r5load(t, object, "yk-1")
			if err == nil {
				t.Fatalf("Load() accepted a %s YubiKey with no device_serial: the manifest then names a "+
					"commissioned card it cannot identify, and any token in the right slot answers for the key", state)
			}
			if !strings.Contains(err.Error(), "commissioned YubiKey requires pinned serial") {
				t.Fatalf("err = %v, want the pinned-serial refusal", err)
			}
		})
	}
}

// registry.go:737 — `TouchPolicy != "never" || (PINPolicy != "once" && PINPolicy != "always")`.
//
// Three of this site's five operand-directions survived, because binding()
// hardcodes pin_policy=once and touch_policy=never on every YubiKey fixture in
// the package: the clause had exactly one input.
//
// The three cases below are deliberately of two kinds. touch_policy=always and
// pin_policy=never are ADMISSION-direction: a policy the daemon cannot satisfy
// (it has no way to prompt for a touch) would be accepted. pin_policy=always is
// REFUSAL-direction: it is a policy the rule explicitly permits, and neutralising
// the `!= "always"` operand makes the loader refuse a manifest that is correct —
// the failure mode where the KMS loses access to a key rather than leaking one.
func TestYubiKeyInteractionPolicyIsBoundedInBothDirections(t *testing.T) {
	refused := map[string]string{
		// touch_policy is the operand that is checked on its own, before the
		// PIN clause: `never` is the only value this daemon can honour.
		"touch_policy always": r5yubikey("active", "yubi-serial", "once", "always"),
		// Neither arm of the PIN clause admits `never`, so this case is the one
		// that needs BOTH `!= "once"` and `!= "always"` to be doing work.
		"pin_policy never": r5yubikey("active", "yubi-serial", "never", "never"),
	}
	for name, binding := range refused {
		t.Run(name, func(t *testing.T) {
			object := r5object("piv-key", "piv-purpose", "asymmetric-key", "rsa2048", "direct-hardware", `"sign"`, binding)
			_, err := r5load(t, object, "yk-1")
			if err == nil {
				t.Fatal("Load() accepted an interaction policy the daemon cannot satisfy: it has no " +
					"channel to prompt a human for a touch, so the operation would block at the token")
			}
			if !strings.Contains(err.Error(), "YubiKey requires PIN policy and touch_policy=never") {
				t.Fatalf("err = %v, want the interaction-policy refusal", err)
			}
		})
	}

	// The refusal direction. pin_policy=always is permitted by the rule as
	// written; a loader that refused it would deny service on a manifest CI
	// accepts, and every negative case above would stay green while it did.
	t.Run("pin_policy always is permitted", func(t *testing.T) {
		object := r5object("piv-key", "piv-purpose", "asymmetric-key", "rsa2048", "direct-hardware", `"sign"`,
			r5yubikey("active", "yubi-serial", "always", "never"))
		if _, err := r5load(t, object, "yk-1"); err != nil {
			t.Fatalf("Load() error = %v; pin_policy \"always\" is one of the two values the rule admits, "+
				"and refusing it takes a correctly configured key out of service", err)
		}
	})
}

// registry.go:740 operands 0 and 1 — `PINPolicy != "" || TouchPolicy != ""` on
// a non-YubiKey backend.
//
// TestValidateBindingRefusesPinTouchPolicyOnNonYubikey sets BOTH fields on one
// fixture, so each operand is masked by the other and NEITHER is pinned: with
// either one neutralised the other still refuses, and the test stays green.
// One field per fixture is the whole point of this test.
func TestInteractionPolicyIsRefusedOnANonYubiKeyBackendFieldByField(t *testing.T) {
	base := r5nitrokey("sitea", "dev-1", "slot-1", "active", "", "")
	for name, binding := range map[string]string{
		"pin_policy alone":   strings.Replace(base, `"state":"active"`, `"pin_policy":"once","state":"active"`, 1),
		"touch_policy alone": strings.Replace(base, `"state":"active"`, `"touch_policy":"never","state":"active"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if binding == base {
				t.Fatal("the fixture is identical to the base binding: the replacement did not land, " +
					"so this case carries no interaction policy at all")
			}
			object := r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware",
				`"sign"`, binding)
			_, err := r5load(t, object, "dev-1")
			if err == nil {
				t.Fatal("Load() accepted an interaction policy on nitrokey-pkcs11: the field is silently " +
					"ignored downstream, so the manifest promises a control that nothing applies")
			}
			if !strings.Contains(err.Error(), "interaction policy is only valid for YubiKey") {
				t.Fatalf("err = %v, want the YubiKey-only refusal", err)
			}
		})
	}
}

// registry.go:788 operand 3 — `binding.KEKVersion != ""` in the clause refusing
// KEK fields on a binding that neither releases nor seals.
//
// TestKEKAlgorithmIsRefusedOnBindingsThatDoNotReleaseSecrets sets kek_algorithm
// only, so operand 2 is pinned and operand 3 is not: a binding carrying a
// kek_version alone is accepted. A version with no key to version is the half
// of the pair that makes an envelope's KEK reference resolvable, so recording
// it on a signing binding is a manifest that describes rotation of a key that
// does no wrapping.
func TestKEKVersionAloneIsRefusedOnABindingThatNeitherReleasesNorSeals(t *testing.T) {
	binding := strings.Replace(r5nitrokey("sitea", "dev-1", "slot-1", "active", "", ""),
		`"state":"active"`, `"kek_version":"1","state":"active"`, 1)
	if !strings.Contains(binding, `"kek_version"`) {
		t.Fatal("the fixture carries no kek_version; the replacement did not land")
	}
	if strings.Contains(binding, `"kek_algorithm"`) {
		t.Fatal("the fixture also carries kek_algorithm, which operand 2 already refuses: this case " +
			"would then be masked exactly as it is in the existing test")
	}

	object := r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware",
		`"sign"`, binding)
	_, err := r5load(t, object, "dev-1")
	if err == nil {
		t.Fatal("Load() accepted kek_version on a sign-only binding: nothing reads it there, so the " +
			"manifest records a KEK generation for a slot that wraps nothing")
	}
	if !strings.Contains(err.Error(), "only meaningful for release-secret and seal-envelope") {
		t.Fatalf("err = %v, want the KEK-fields refusal", err)
	}
}

// ---------------------------------------------------------------------------
// Site-scoped custody decisions — which card serves the key
// ---------------------------------------------------------------------------

// registry.go:705 operand 0 — `binding.Site == site` in validateObject's
// "something here can still seal" loop.
//
// Neutralised (`(true || binding.Site == site)`) a binding at ANY site
// satisfies the check, so an object declaring seal-envelope loads on the
// strength of a card in another building. The refusal then arrives at
// RouteForSeal, at the moment somebody needs to seal something, as a routing
// denial that names no cause — which is precisely the Load-time-versus-
// release-time distinction this loop was added to keep.
//
// Operand 1 (SealAllows) is already pinned by
// TestAnObjectThatSealsMustStillHaveSomethingThatCanSeal; the site half was not.
func TestSealEligibilityIsJudgedAtTheConfiguredSite(t *testing.T) {
	local := r5object("seal-target", "seal-purpose", "opaque-secret", "opaque", "hardware-envelope",
		`"seal-envelope"`, r5nitrokey("sitea", "dev-1", "slot-1", "active", "rsa4096", "1"))
	if _, err := r5load(t, local, "dev-1"); err != nil {
		t.Fatalf("control (sealable binding AT the configured site) must load: %v", err)
	}

	remote := r5object("seal-target", "seal-purpose", "opaque-secret", "opaque", "hardware-envelope",
		`"seal-envelope"`, r5nitrokey("siteb", "dev-2", "slot-2", "active", "rsa4096", "1"))
	_, err := r5load(t, remote, "dev-2")
	if err == nil {
		t.Fatal("Load() accepted a seal-envelope object whose only sealable binding is at another site: " +
			"the daemon starts clean and then refuses every seal at request time, blaming routing for a " +
			"manifest that never had a card here to wrap against")
	}
	if !strings.Contains(err.Error(), "no binding at site \"sitea\" is in a state that can seal") {
		t.Fatalf("err = %v, want the site-scoped seal refusal", err)
	}
}

// registry.go:1065 operand 0 — `binding.Site != registry.site` in
// RouteForUnwrap's candidate filter.
//
// THIS IS THE ONE THAT PICKS THE WRONG CARD. Neutralised, the loop stops
// skipping bindings at other sites, so an envelope naming a KEK generation held
// only in another building resolves to that binding and the release is
// dispatched at a device this daemon does not have. Operand 1 (the version
// match) is pinned twice over; the site half of the same condition was pinned
// by nothing.
//
// Route()'s active-at-site selection happens at Load and is well covered. This
// filter is the runtime one, and it is the only thing keeping "the envelope
// chooses the generation" from becoming "the envelope chooses the site".
func TestRouteForUnwrapNeverSelectsABindingAtAnotherSite(t *testing.T) {
	bindings := r5nitrokey("sitea", "dev-1", "slot-1", "active", "rsa4096", "1") + "," +
		r5nitrokey("siteb", "dev-2", "slot-2", "active", "rsa4096", "2")
	object := r5object("release-target", "release-purpose", "opaque-secret", "opaque", "hardware-envelope",
		`"release-secret"`, bindings)
	registry, err := r5load(t, object, "dev-1", "dev-2")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// The control: the generation that IS held here resolves, so a
	// RouteForUnwrap that refused everything could not satisfy the assertion
	// below.
	route, err := registry.RouteForUnwrap(context.Background(), "release-target", "release-purpose", "1")
	if err != nil {
		t.Fatalf("the local generation must resolve for this test to mean anything: %v", err)
	}
	if route.Binding.DeviceID != "dev-1" {
		t.Fatalf("control resolved to %q, want dev-1", route.Binding.DeviceID)
	}

	route, err = registry.RouteForUnwrap(context.Background(), "release-target", "release-purpose", "2")
	if err == nil {
		t.Fatalf("DEFECT: an envelope naming generation 2 — held only at siteb — resolved to device %q at "+
			"site %q. This daemon has no such card: the unwrap would be dispatched against hardware that is "+
			"not here, and a routing decision made against the wrong card is the failure the site filter exists "+
			"to prevent", route.Binding.DeviceID, route.Binding.Site)
	}
	if !IsCode(err, CodeDenied) {
		t.Fatalf("err = %v, want denied", err)
	}
}

// ---------------------------------------------------------------------------
// The rotation deadline, on the two routes that are not Route()
// ---------------------------------------------------------------------------

// registry.go:1045 operand 1 and registry.go:1135 operand 1 —
// `registry.clock().After(entry.rotateBy)` in RouteForUnwrap and RouteForSeal.
//
// Both are REFUSAL-direction survivors. Neutralised (`(true || …)`) the clock
// stops being consulted and ANY object carrying a rotation deadline is denied,
// whether or not the deadline has passed. Every existing deadline test drives
// the clock PAST the deadline and asserts a denial, so it stays green while the
// daemon refuses every unwrap and every seal on every object with a rotation
// policy — a total loss of access, invisible to a suite of negative tests.
//
// A manifest with `last_rotated: null` (which is what the shared fixtures use)
// produces a zero rotateBy and never reaches this operand, which is why the
// fixture here names a real rotation date.
func TestUnwrapAndSealStillServeBeforeTheRotationDeadline(t *testing.T) {
	rotated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	object := fmt.Sprintf(`{"id":"rotating","name":"R5","kind":"opaque-secret","classification":"restricted",`+
		`"environment":"staging","owner":"security","purpose":"seal-purpose","custody":"hardware-envelope",`+
		`"algorithm":"opaque","operations":["seal-envelope","release-secret"],"policy_id":"test-policy",`+
		`"bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},`+
		`"rotation":{"maximum_age_days":365,"last_rotated":%q},"migration":{"status":"migrated","source":"test"},`+
		`"verification":{"status":"verified"}}`,
		r5nitrokey("sitea", "dev-1", "slot-1", "active", "rsa4096", "1"), rotated.Format(time.RFC3339))

	registry, err := r5load(t, object, "dev-1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// The fixture must actually carry a deadline, or operand 0 short-circuits and
	// this test cannot reach operand 1.
	if overdue := registry.OverdueObjects(rotated.AddDate(2, 0, 0)); len(overdue) != 1 {
		t.Fatalf("OverdueObjects() two years on = %v, want the object: the fixture establishes no "+
			"deadline, so it never reaches the clock comparison under test", overdue)
	}

	registry.SetClock(func() time.Time { return rotated.AddDate(0, 0, 30) })
	if _, err := registry.RouteForUnwrap(context.Background(), "rotating", "seal-purpose", "1"); err != nil {
		t.Fatalf("RouteForUnwrap() error = %v thirty days into a 365-day rotation window: an object "+
			"inside its own deadline must still open its envelopes, and refusing costs access to every "+
			"secret this key protects", err)
	}
	if _, err := registry.RouteForSeal(context.Background(), "rotating", "seal-purpose"); err != nil {
		t.Fatalf("RouteForSeal() error = %v thirty days into a 365-day rotation window: an object "+
			"inside its own deadline must still accept new envelopes", err)
	}
}

// ---------------------------------------------------------------------------
// RequiredBackends and the nil receiver
// ---------------------------------------------------------------------------

// registry.go:1252 operand 0 — `item.route.Binding.Backend != ""`, dominated.
//
// Forced true, an object with no active binding at this site contributes the
// EMPTY STRING to RequiredBackends. The daemon compares that list against the
// providers it constructed, so a "" entry makes startup fail demanding a
// backend with no name — for an object that is simply served elsewhere.
// Nothing detected it: no fixture combined an unassigned operated object with a
// RequiredBackends assertion.
func TestRequiredBackendsNeverNamesAnUnassignedObject(t *testing.T) {
	// Served here, so the assertion cannot be satisfied by an empty result.
	served := r5object("local-key", "cosmos-transaction", "asymmetric-key", "secp256k1", "direct-hardware",
		`"sign"`, r5nitrokey("sitea", "dev-1", "slot-1", "active", "", ""))
	// Operated custody, but every binding is at another site: assigned is false
	// and route.Binding is the zero Binding.
	elsewhere := r5object("remote-key", "other-purpose", "asymmetric-key", "secp256k1", "direct-hardware",
		`"sign"`, r5nitrokey("siteb", "dev-2", "slot-2", "active", "", ""))

	registry, err := r5load(t, served+","+elsewhere, "dev-1", "dev-2")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	required := registry.RequiredBackends()
	found := false
	for _, name := range required {
		if name == "" {
			t.Fatalf("DEFECT: RequiredBackends() = %q includes the empty backend: the startup check "+
				"would refuse to boot demanding a provider with no name, for an object this site does "+
				"not serve at all", required)
		}
		if name == "nitrokey-pkcs11" {
			found = true
		}
	}
	if !found {
		t.Fatalf("RequiredBackends() = %q does not name the served object's backend: the fixture "+
			"stopped exercising the case", required)
	}
}

// registry.go:341, :350, :977 and :1241 — the nil-receiver and nil-argument
// guards on SetClock, OverdueObjects, clock and RequiredBackends.
//
// SetBackendHealth (:328), HasBackendHealth (:337) and DeclaredPolicies (:1213)
// all have a nil-receiver test and all three were detected. The four below did
// not, which is the same bound named on one side only.
//
// The SetClock(nil) case pins :977 operand 1 rather than :341 operand 1: those
// two guards are interchangeable for the caller — if SetClock stores a nil
// clock, clock() substitutes time.Now, and if clock() stops substituting,
// SetClock's refusal is what keeps the field non-nil. Neutralising EITHER alone
// leaves the behaviour identical; neutralising BOTH panics on the first
// deadline comparison. This test therefore pins the pair, not each half, and
// says so rather than claiming a gate it does not have.
func TestANilRegistryAndANilClockAreToleratedByEveryAccessor(t *testing.T) {
	var absent *Registry
	absent.SetBackendHealth(nil)
	if absent.HasBackendHealth() {
		t.Fatal("HasBackendHealth() = true on a nil registry")
	}
	absent.SetClock(func() time.Time { return time.Unix(0, 0) })
	if overdue := absent.OverdueObjects(time.Now()); overdue != nil {
		t.Fatalf("OverdueObjects() = %v on a nil registry, want nil", overdue)
	}
	if backends := absent.RequiredBackends(); backends != nil {
		t.Fatalf("RequiredBackends() = %v on a nil registry, want nil", backends)
	}
	if policies := absent.DeclaredPolicies(); policies != nil {
		t.Fatalf("DeclaredPolicies() = %v on a nil registry, want nil", policies)
	}

	rotated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	object := fmt.Sprintf(`{"id":"wallet-key","name":"R5","kind":"asymmetric-key","classification":"restricted",`+
		`"environment":"staging","owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware",`+
		`"algorithm":"secp256k1","operations":["sign"],"policy_id":"test-policy","bindings":[%s],`+
		`"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},`+
		`"rotation":{"maximum_age_days":365,"last_rotated":%q},"migration":{"status":"migrated","source":"test"},`+
		`"verification":{"status":"verified"}}`,
		r5nitrokey("sitea", "dev-1", "slot-1", "active", "", ""), rotated.Format(time.RFC3339))
	registry, err := r5load(t, object, "dev-1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// A nil clock must leave the registry with a working one. The deadline
	// comparison below is what reads it.
	registry.SetClock(nil)
	if _, err := registry.Route(context.Background(), "wallet-key", "cosmos-transaction", "sign"); err != nil {
		t.Fatalf("Route() error = %v after SetClock(nil): a nil clock must be refused by SetClock or "+
			"substituted by clock(), and if neither happens the first rotation-deadline comparison "+
			"dereferences it", err)
	}
}

// THIS ONE IS NOT A GATE, AND SAYS SO.
//
// registry.go:1089, :1142 and :1162 operand 1 are the same construction as
// :999 operand 1 — `registry.health == nil ||` in front of a safeHealthy call —
// and all four survived. :999 is masked by safeHealthy's recover: neutralise
// the operand and the nil-interface call panics, the deferred recover turns it
// into false, and the caller takes the identical branch. Measured, not argued:
// with BOTH the operand and the recover neutralised, the run panics.
//
// The other three are the same, so no test can be their sole failure. But they
// differ from :999 in a way worth recording: the suite never drives
// RouteForUnwrap, RouteForSeal or Ready with an unattached probe AT ALL.
// TestBackendHealthMustBeAttachedBeforeTheRegistryCanServe covers Route() only,
// and the comment on SetBackendHealth names exactly this hazard — "a daemon
// that never attaches one looks exactly like a daemon whose hardware is down".
// So this test pins the fail-closed posture of the three uncovered paths; it is
// documentation with respect to the four operands, and a gate with respect to
// nothing else covering the paths.
func TestAnUnattachedProbeFailsClosedOnEveryRouteAndOnReadiness(t *testing.T) {
	object := r5object("release-target", "release-purpose", "opaque-secret", "opaque", "hardware-envelope",
		`"release-secret","seal-envelope"`, r5nitrokey("sitea", "dev-1", "slot-1", "active", "rsa4096", "1"))
	registry, err := Load(strings.NewReader(manifest(object)), "sitea", nil)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if registry.HasBackendHealth() {
		t.Fatal("a registry loaded with a nil probe reports one attached")
	}

	if _, err := registry.RouteForUnwrap(context.Background(), "release-target", "release-purpose", "1"); !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("RouteForUnwrap() error = %v with no probe attached, want dependency-unavailable: "+
			"a daemon that never wired a probe must not open envelopes on hardware it has never asked about", err)
	}
	if _, err := registry.RouteForSeal(context.Background(), "release-target", "release-purpose"); !IsCode(err, CodeDependencyUnavailable) {
		t.Fatalf("RouteForSeal() error = %v with no probe attached, want dependency-unavailable", err)
	}
	if registry.Ready(context.Background()) {
		t.Fatal("Ready() = true with no probe attached: readiness would advertise a daemon that has " +
			"never established it can reach a single device")
	}

	// The control. Without it, a registry that refused everything for an
	// unrelated reason would satisfy all three assertions above.
	registry.SetBackendHealth(&healthMap{states: map[string]bool{"dev-1": true}})
	if _, err := registry.RouteForUnwrap(context.Background(), "release-target", "release-purpose", "1"); err != nil {
		t.Fatalf("RouteForUnwrap() error = %v once a healthy probe is attached", err)
	}
	if _, err := registry.RouteForSeal(context.Background(), "release-target", "release-purpose"); err != nil {
		t.Fatalf("RouteForSeal() error = %v once a healthy probe is attached", err)
	}
	if !registry.Ready(context.Background()) {
		t.Fatal("Ready() = false once a healthy probe is attached")
	}
}

// ---------------------------------------------------------------------------
// Errors the loader must not swallow
// ---------------------------------------------------------------------------

// failingReader delivers a complete manifest and then fails. That ordering is
// the point: a reader that fails BEFORE delivering a whole document is caught
// by the JSON decoder at registry.go:399 whether or not the read error is
// checked, so it cannot tell the read guard apart from its absence.
type failingReader struct {
	content string
	done    bool
}

func (reader *failingReader) Read(buffer []byte) (int, error) {
	if reader.done {
		return 0, fmt.Errorf("storage went away mid-read")
	}
	reader.done = true
	return copy(buffer, reader.content), nil
}

// registry.go:390 operand 0 — `err != nil` on io.ReadAll.
//
// Neutralised, a read that fails after handing over a syntactically complete
// manifest is accepted, and the registry's digest is computed over whatever
// arrived. The digest is the manifest's identity in every audit record, so
// "the daemon loaded manifest X" would be a claim about bytes nobody wrote.
func TestLoadRefusesAManifestItCouldNotFinishReading(t *testing.T) {
	body := manifest(r5object("wallet-key", "cosmos-transaction", "asymmetric-key", "secp256k1",
		"direct-hardware", `"sign"`, r5nitrokey("sitea", "dev-1", "slot-1", "active", "", "")))
	// The control: the same bytes from a reader that does not fail must load,
	// so the refusal below is the read error and not the fixture.
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{states: map[string]bool{"dev-1": true}}); err != nil {
		t.Fatalf("control must load: %v", err)
	}

	_, err := Load(&failingReader{content: body}, "sitea", &healthMap{states: map[string]bool{"dev-1": true}})
	if err == nil {
		t.Fatal("Load() accepted a manifest whose read failed: the digest recorded in every audit " +
			"entry would then describe bytes that were never fully read")
	}
	if !strings.Contains(err.Error(), "read registry") {
		t.Fatalf("err = %v, want the read refusal", err)
	}
}

// registry.go:439 operand 0 — `err != nil` on envelopeMaxAge, at Load.
//
// TestAnUnusableRotationBlockIsAnErrorRatherThanUnbounded covers every bad
// spelling of envelope_max_age_days, but it calls envelopeMaxAge directly, so
// Load's decision to propagate that error was pinned by nothing. Neutralised,
// a manifest CI rejects starts the daemon with the bound silently switched
// off — which is the exact failure the RawMessage decoding was written to
// avoid, reintroduced one layer up.
//
// registry.go:435 (rotationDeadline's error, same shape) stays unpinned on
// purpose and is recorded as such: both functions unmarshal the SAME bytes into
// the same struct, so :435 errors only when :439 does, and neither can be the
// sole refuser. TestMalformedRotationPolicyIsRejectedAtLoad is refused by
// whichever of the two is still present, with the identical message.
func TestABadEnvelopeMaxAgeIsRefusedAtLoadAndNotJustInTheHelper(t *testing.T) {
	object := func(rotation string) string {
		return fmt.Sprintf(`{"id":"wallet-key","name":"R5","kind":"asymmetric-key","classification":"restricted",`+
			`"environment":"staging","owner":"security","purpose":"cosmos-transaction","custody":"direct-hardware",`+
			`"algorithm":"secp256k1","operations":["sign"],"policy_id":"test-policy","bindings":[%s],`+
			`"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},`+
			`"rotation":%s,"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}`,
			r5nitrokey("sitea", "dev-1", "slot-1", "active", "", ""), rotation)
	}
	// The control names a rotation block that parses, so the case below cannot
	// be refused for being malformed in general.
	if _, err := r5load(t, object(`{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":90}`), "dev-1"); err != nil {
		t.Fatalf("control (a usable bound) must load: %v", err)
	}

	// Zero, not a syntax error: rotationDeadline reads this block perfectly
	// well, so only envelopeMaxAge's error reaches Load and only :439 can
	// carry it there.
	_, err := r5load(t, object(`{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":0}`), "dev-1")
	if err == nil {
		t.Fatal("Load() accepted envelope_max_age_days:0 — the schema and custody_manifest.py both " +
			"refuse it, so the daemon would start on a manifest CI rejects with the envelope lifetime " +
			"bound silently switched off")
	}
	if !strings.Contains(err.Error(), "positive integer of days") {
		t.Fatalf("err = %v, want the envelope-bound refusal", err)
	}
}

// registry.go:652 (dominated) and :653 — the recovery block of a FIDO object.
//
// The two produce different messages for two different mistakes, and one
// fixture cannot show that: an absent recovery block must be reported as a
// missing multi-enrollment MODE (the operator has to write one), and a recovery
// value that is not an object must be reported as a shape error (the operator
// has to fix the JSON). Forcing :652 true turns the first into the second, and
// removing :653 turns the second into the first. A previous round listed the
// absent-recovery case as deferred; it needs no restructuring, only two
// fixtures instead of one.
func TestFIDORecoveryReportsAbsenceAndMalformationDifferently(t *testing.T) {
	bindings := fidoEnrollment("sitea", "fido-admin-a", "active") + "," +
		fidoEnrollment("custodian-b", "fido-admin-b", "active")
	fido := func(recovery string) string {
		return fmt.Sprintf(`{"id":"github-org-admin-fido","name":"GitHub admin continuity","kind":"fido-credential",`+
			`"classification":"critical","environment":"staging","owner":"security","purpose":"github-admin-login",`+
			`"custody":"fido-multi-enrollment","algorithm":"device-managed","operations":["authenticate"],`+
			`"policy_id":"github-org-admin","bindings":[%s]%s,`+
			`"rotation":{"maximum_age_days":730,"last_rotated":null},"migration":{"status":"migrated","source":"test"},`+
			`"verification":{"status":"verified"}}`, bindings, recovery)
	}
	health := &healthMap{states: map[string]bool{}}
	if _, err := Load(strings.NewReader(manifest(fido(`,"recovery":{"mode":"multi-enrollment","minimum_replicas":2,"status":"tested"}`))),
		"sitea", health); err != nil {
		t.Fatalf("control (a well-formed recovery block) must load: %v", err)
	}

	absent := fido("")
	if strings.Contains(absent, `"recovery"`) {
		t.Fatal("the absent-recovery fixture still carries a recovery block")
	}
	_, err := Load(strings.NewReader(manifest(absent)), "sitea", health)
	if err == nil {
		t.Fatal("Load() accepted a FIDO object with no recovery block")
	}
	if !strings.Contains(err.Error(), `requires recovery mode "multi-enrollment"`) {
		t.Fatalf("err = %v for an ABSENT recovery block; want the missing-mode refusal. Reporting it "+
			"as a shape error sends the operator to fix JSON that is not there", err)
	}

	_, err = Load(strings.NewReader(manifest(fido(`,"recovery":"none"`))), "sitea", health)
	if err == nil {
		t.Fatal("Load() accepted a FIDO object whose recovery is a string")
	}
	if !strings.Contains(err.Error(), "recovery is not an object") {
		t.Fatalf("err = %v for a MALFORMED recovery block; want the shape refusal. Reporting it as a "+
			"missing mode sends the operator to add a field that is already there, in the wrong shape", err)
	}
}

// ---------------------------------------------------------------------------
// Why two isCustodyRecord guards are unreachable rather than untested
// ---------------------------------------------------------------------------

// registry.go:1039 and :1130 — `isCustodyRecord(entry.custody)` in
// RouteForUnwrap and RouteForSeal.
//
// A previous round recorded these as DEFERRED, on the grounds that the custody
// mode's gating made a targeted test brittle. Re-measured: they are not
// brittle, they are UNREACHABLE, and this test is the reason.
//
// custodyRecord is reached only by custody "fido-multi-enrollment".
// validateFIDOContinuity then requires every binding to be fido2, and the
// capability matrix gives fido2 exactly one row, device-managed/authenticate.
// validateBinding refuses any operation the backend does not support, so a
// fido-custody object can never declare release-secret or seal-envelope — and
// those are the only operations that reach RouteForUnwrap and RouteForSeal.
// The operations guard at :1036 and :1127 is therefore not merely masking the
// custody guard; no manifest exists that would reach it.
//
// This test is not a gate on those two guards. It is the invariant the
// unreachability argument rests on: widen the fido2 row in Capabilities() and
// it fails, which is exactly when :1039 and :1130 become live and need pinning.
func TestAFIDOCustodyRecordCannotDeclareTheOperationsThatReachUnwrapOrSeal(t *testing.T) {
	bindings := fidoEnrollment("sitea", "fido-admin-a", "active") + "," +
		fidoEnrollment("custodian-b", "fido-admin-b", "active")
	for _, operation := range []string{"release-secret", "seal-envelope"} {
		t.Run(operation, func(t *testing.T) {
			object := fidoObjectFull("staging", "fido-credential", "opaque", operation, "multi-enrollment", bindings)
			_, err := Load(strings.NewReader(manifest(object)), "sitea", &healthMap{states: map[string]bool{}})
			if err == nil {
				t.Fatalf("Load() accepted a fido-multi-enrollment object declaring %q. That makes "+
					"RouteForUnwrap/RouteForSeal reachable for a custody record, and their "+
					"isCustodyRecord guards — currently unreachable and therefore unpinned — become "+
					"the only thing between a recorded enrollment and a routing decision", operation)
			}
			if !strings.Contains(err.Error(), "does not support") {
				t.Fatalf("err = %v, want the capability-matrix refusal: the unreachability argument for "+
					"registry.go:1039 and :1130 rests on this being the reason", err)
			}
		})
	}
}
