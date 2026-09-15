package registry

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fidoObject builds a FIDO custody record. Every field the continuity rules care about is a
// parameter, so a test can spoil exactly one of them and leave the rest valid.
func fidoObject(kind, recoveryMode string, bindings string) string {
	return fidoObjectIn("production", kind, recoveryMode, bindings)
}

func fidoObjectIn(environment, kind, recoveryMode, bindings string) string {
	return fidoObjectFull(environment, kind, "device-managed", "authenticate", recoveryMode, bindings)
}

// fidoObjectFull also parameterises algorithm and operation. A FIDO-custody object is not obliged
// by the schema to declare device-managed/authenticate, and that matters for testing: with
// device-managed/authenticate the capability matrix refuses every non-fido2 backend on its own, so
// a fixture using them cannot show whether the custody rule is doing anything.
func fidoObjectFull(environment, kind, algorithm, operation, recoveryMode, bindings string) string {
	return fmt.Sprintf(`{
		"id":"github-org-admin-fido","name":"GitHub admin continuity","kind":%q,
		"classification":"critical","environment":%q,"owner":"security",
		"purpose":"github-admin-login","custody":"fido-multi-enrollment","algorithm":%q,
		"operations":[%q],"policy_id":"github-org-admin","bindings":[%s],
		"recovery":{"mode":%q,"minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":730,"last_rotated":null},
		"migration":{"status":"migrated","source":"organization:github"},
		"verification":{"status":"verified"}
	}`, kind, environment, algorithm, operation, bindings, recoveryMode)
}

func fidoEnrollment(site, device, state string) string {
	return binding(site, "fido2", device, "enrollment-"+device, state)
}

// A FIDO CREDENTIAL IS A RECORD, NOT A ROUTE — AND ROUTE MUST SAY SO WITHOUT CONSULTING HARDWARE.
//
// The manifest lists these objects so a person can find the second enrollment after losing the
// first. Nothing in this daemon authenticates: /v1/operations exposes no such route and no fido2
// provider is ever built. Before this rule existed the outcome depended on where the custodian
// happened to be — an enrollment recorded at some other site fell out as DEPENDENCY_UNAVAILABLE
// (the binding was simply not selected), which invites a caller to retry until hardware that does
// not exist comes back.
func TestRouteDeniesAFIDOCustodyRecordRatherThanReportingHardwareTrouble(t *testing.T) {
	bindings := fidoEnrollment("sitea", "fido-admin-a", "active") + "," +
		fidoEnrollment("custodian-b", "fido-admin-b", "active")
	health := &healthMap{states: map[string]bool{"fido-admin-a": true, "fido-admin-b": true}}
	registry, err := Load(strings.NewReader(manifest(fidoObject("fido-credential", "multi-enrollment", bindings))), "sitea", health)
	if err != nil {
		t.Fatalf("a valid FIDO continuity record does not load: %v", err)
	}

	// The control. Without it, a Load that quietly dropped the object would satisfy every
	// assertion below by making the object absent rather than unroutable.
	if _, declared := registry.entries["github-org-admin-fido"]; !declared {
		t.Fatal("the FIDO object is not in the registry at all: this test would then prove nothing about routing")
	}

	_, err = registry.Route(context.Background(), "github-org-admin-fido", "github-admin-login", "authenticate")
	if !IsCode(err, CodeDenied) {
		t.Fatalf("DEFECT: Route on a FIDO custody record returned %v, want denied — a record the daemon never operates must not read as a device it could not reach", err)
	}
	if len(health.calls) != 0 {
		t.Fatalf("DEFECT: the health probe was consulted for a FIDO record (%v): there is no device here to be healthy", health.calls)
	}
}

// THE DAEMON MUST NOT DEMAND A BACKEND FOR SOMETHING IT NEVER OPERATES.
//
// RequiredBackends feeds the startup check that refuses a manifest routing to backends this daemon
// cannot serve. That check is correct and stays. But a FIDO enrollment recorded as active at the
// deployment's own site is not a routing claim, and counting it made the daemon refuse to boot with
// an error about operations that "would fail at signing time" — on an object nothing signs.
//
// The site collision is the ordinary case, not a contrived one: `site` is a free identifier and a
// custodian who sits at the SiteA site is exactly who you want holding the second enrollment.
func TestRequiredBackendsExcludesFIDOEnrollmentsAtTheDaemonSite(t *testing.T) {
	bindings := fidoEnrollment("sitea", "fido-admin-a", "active") + "," +
		fidoEnrollment("custodian-b", "fido-admin-b", "active")
	fido := fidoObject("fido-credential", "multi-enrollment", bindings)
	// The control: a real routed object at the same site, so the assertion below cannot be
	// satisfied by RequiredBackends being empty for an unrelated reason.
	signing := object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active")+","+
			binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "active"))

	registry, err := Load(strings.NewReader(manifest(fido+","+signing)), "sitea", &healthMap{states: map[string]bool{}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	required := registry.RequiredBackends()
	servingBackend := false
	for _, name := range required {
		if name == "fido2" {
			t.Fatalf("DEFECT: RequiredBackends() = %v includes fido2 — the daemon would refuse to start because it cannot serve a backend it is never asked to use", required)
		}
		if name == "nitrokey-pkcs11" {
			servingBackend = true
		}
	}
	if !servingBackend {
		t.Fatalf("RequiredBackends() = %v does not name the routed object's backend: the fixture stopped exercising the case", required)
	}
}

// THE CONTINUITY RULES ARE THE WHOLE GUARANTEE, SO THE DAEMON ENFORCES THEM TOO.
//
// A FIDO private key is born on the authenticator and never leaves it: no escrow, no Shamir path,
// nothing to fall back on if these rules do not hold. They existed in the JSON Schema and in
// tools/custody_manifest.py, both of which check the manifest in this repository during CI —
// while the daemon loads whatever registry_path names.
func TestLoadEnforcesFIDOContinuityRules(t *testing.T) {
	twoSites := fidoEnrollment("custodian-a", "fido-admin-a", "active") + "," +
		fidoEnrollment("custodian-b", "fido-admin-b", "active")

	// The control first: the complete record must load, or every refusal below is satisfied by a
	// loader that refuses FIDO objects outright and the test pins nothing.
	if _, err := Load(strings.NewReader(manifest(fidoObject("fido-credential", "multi-enrollment", twoSites))), "sitea", &healthMap{states: map[string]bool{}}); err != nil {
		t.Fatalf("a complete FIDO record was refused (%v): the cases below would prove nothing", err)
	}

	for _, spoiled := range []struct {
		what     string
		document string
		why      string
	}{
		{
			"both enrollments in one place",
			manifest(fidoObject("fido-credential", "multi-enrollment",
				fidoEnrollment("custodian-a", "fido-admin-a", "active")+","+
					fidoEnrollment("custodian-a", "fido-admin-b", "active"))),
			"two tokens in one drawer are two devices and one fire, and there is no way to re-derive either",
		},
		{
			// Deliberately NOT production. The production-redundancy rule already refuses any
			// production object with one binding, so a production fixture here would pass whether
			// or not the FIDO minimum exists — pinning the older rule and reporting it as this one.
			"a single enrollment outside production",
			manifest(fidoObjectIn("staging", "fido-credential", "multi-enrollment", fidoEnrollment("custodian-a", "fido-admin-a", "active"))),
			"losing the one token locks the account out permanently, and no environment makes a credential re-derivable",
		},
		{
			"the wrong kind",
			manifest(fidoObject("asymmetric-key", "multi-enrollment", twoSites)),
			"an asymmetric-key reads as something with a recoverable private key",
		},
		{
			"a recovery mode that promises shares",
			manifest(fidoObject("fido-credential", "shamir-4-of-6", twoSites)),
			"there are no shares of a credential that never left the authenticator",
		},
		{
			// secp256k1/sign deliberately, not device-managed/authenticate: the capability matrix
			// refuses a Nitrokey the latter all by itself, so a fixture using it would pass with
			// this rule deleted and report the capability check as though it were custody.
			// secp256k1/sign on a Nitrokey is genuinely supported, which leaves the custody rule
			// as the only thing that can object.
			"hardware keys recorded under FIDO custody",
			manifest(fidoObjectFull("production", "fido-credential", "secp256k1", "sign", "multi-enrollment",
				binding("custodian-a", "nitrokey-pkcs11", "hsm-a", "01", "active")+","+
					binding("custodian-b", "nitrokey-pkcs11", "hsm-b", "01", "active"))),
			"a Nitrokey holds a key that can be re-provisioned from a seed, which is the opposite of what this custody mode promises — and calling it FIDO custody would exempt it from the Shamir recovery rules that should apply",
		},
		{
			"a fido2 binding under ordinary custody",
			manifest(strings.Replace(fidoObject("fido-credential", "multi-enrollment", twoSites),
				`"custody":"fido-multi-enrollment"`, `"custody":"direct-hardware"`, 1)),
			"direct-hardware custody implies a device whose key could be re-provisioned",
		},
	} {
		t.Run(spoiled.what, func(t *testing.T) {
			if spoiled.document == manifest(fidoObject("fido-credential", "multi-enrollment", twoSites)) {
				t.Fatal("this case is byte-identical to the control: the mutation did not land")
			}
			if _, err := Load(strings.NewReader(spoiled.document), "sitea", &healthMap{states: map[string]bool{}}); err == nil {
				t.Fatalf("DEFECT: a manifest with %s loaded — %s", spoiled.what, spoiled.why)
			}
		})
	}
}

// A CUSTODY RECORD MUST NOT TAKE THE DAEMON OUT OF SERVICE.
//
// Ready() requires every entry to be assigned at this site and healthy. A FIDO record satisfies
// neither and never can: its enrollments live with custodians, not in a rack, and there is no fido2
// provider to ask. Measured before the fix, on a manifest holding one signing key and one FIDO
// record, with the enrollments at custodian-a/custodian-b — the arrangement the continuity rules
// require — Ready() was false. Permanently. /v1/health/ready would answer 503 for as long as the
// record stayed in the manifest, so the reward for documenting FIDO continuity was an outage.
//
// Route() denying these objects was not enough on its own: readiness is a separate question asked
// by a separate caller, and it was still consulting hardware for a credential that is not there.
func TestACustodyRecordDoesNotHoldTheDaemonUnready(t *testing.T) {
	health := &healthMap{states: map[string]bool{"local-hsm": true, "fido-admin-a": false, "fido-admin-b": false}}
	signing := object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		binding("sitea", "nitrokey-pkcs11", "local-hsm", "01", "active")+","+
			binding("siteb", "nitrokey-pkcs11", "remote-hsm", "01", "active"))

	// The control: without any FIDO record this manifest is ready, so a false below is caused by
	// the record and not by the fixture.
	baseline, err := Load(strings.NewReader(manifest(signing)), "sitea", health)
	if err != nil {
		t.Fatal(err)
	}
	if !baseline.Ready(context.Background()) {
		t.Fatal("the fixture is not ready before a FIDO record is added: this test cannot attribute anything")
	}

	for _, placement := range []struct{ what, first, second string }{
		// The configuration the continuity rules ask for: neither enrollment is at the daemon.
		{"enrollments held away from the daemon site", "custodian-a", "custodian-b"},
		// And the one where a custodian happens to sit at the deployment.
		{"one enrollment at the daemon site", "sitea", "custodian-b"},
	} {
		t.Run(placement.what, func(t *testing.T) {
			fido := fidoObject("fido-credential", "multi-enrollment",
				fidoEnrollment(placement.first, "fido-admin-a", "active")+","+
					fidoEnrollment(placement.second, "fido-admin-b", "active"))
			registry, err := Load(strings.NewReader(manifest(signing+","+fido)), "sitea", health)
			if err != nil {
				t.Fatal(err)
			}
			if !registry.Ready(context.Background()) {
				t.Fatal("DEFECT: recording FIDO continuity made the daemon permanently unready — /v1/health/ready would answer 503 for as long as the record stays in the manifest")
			}
		})
	}

	// Skipping records must not make a daemon that can serve nothing report ready.
	recordsOnly, err := Load(strings.NewReader(manifest(fidoObject("fido-credential", "multi-enrollment",
		fidoEnrollment("custodian-a", "fido-admin-a", "active")+","+
			fidoEnrollment("custodian-b", "fido-admin-b", "active")))), "sitea", health)
	if err != nil {
		t.Fatal(err)
	}
	if recordsOnly.Ready(context.Background()) {
		t.Fatal("DEFECT: a registry holding nothing but custody records reported ready — it can serve no operation at all")
	}
}
