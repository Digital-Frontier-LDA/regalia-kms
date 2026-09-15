package registry_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// advertisedOperations is every operation the capability matrix marks true. An entry set false is
// deliberately excluded: it advertises nothing, so requiring a route for it would force a carve-out
// for an operation no backend claims to offer.
func advertisedOperations() map[string]bool {
	advertised := map[string]bool{}
	for _, algorithms := range registry.Capabilities() {
		for _, operations := range algorithms {
			for operation, allowed := range operations {
				if allowed {
					advertised[operation] = true
				}
			}
		}
	}
	return advertised
}

// servedOperations is every operation the router will accept, derived from the paths themselves so
// the two cannot drift apart the way a second hand-written list would.
//
// The prefix is asserted rather than assumed. TrimPrefix returns its input unchanged when the
// prefix is absent, so a path added under some other root would silently enter this set as a
// full path — "/v1/admin/rotate" as an operation name. It would match nothing advertised, the
// contract above would still pass, and the operation it was supposed to describe would be
// unrepresented. A helper that cannot produce a wrong answer quietly is the whole point of
// deriving the set instead of writing it down.
func servedOperations(t *testing.T) map[string]bool {
	t.Helper()
	const prefix = "/v1/operations/"
	served := map[string]bool{}
	for _, path := range api.OperationPaths() {
		operation, found := strings.CutPrefix(path, prefix)
		if !found || operation == "" {
			t.Fatalf("operation path %q does not have the form %s<operation>, so no operation name can be derived from it", path, prefix)
		}
		served[operation] = true
	}
	return served
}

// EVERY ADVERTISED OPERATION IS EITHER SERVED OR DECLARED UNSERVED, WITH A REASON.
//
// The capability matrix is what an operator reads to decide what the KMS can do, and it is
// published as backend-capabilities.json. `authenticate` appears there, in the shipped example
// manifest's `"operations": ["authenticate"]`, and nowhere in the router. API.md said the exclusion
// out loud — "FIDO2 authenticate is not part of this API" — and nothing enforced it, which is
// TESTING.md 14: the reason a thing is deliberately missing lived only in prose.
//
// What kept it harmless was unrelated: fido2 is the only backend advertising the operation and the
// daemon constructs no fido2 provider, so a manifest routing to it is refused at startup by
// TestRegistryRoutingToAnUnservableBackendIsRefusedAtStartup. That is a different guard against a
// different mistake, and it stops holding the moment someone adds the provider.
func TestEveryAdvertisedOperationIsServedOrDeclaredUnserved(t *testing.T) {
	served, unserved := servedOperations(t), registry.DeviceManagedOperations()
	var undeclared []string
	for operation := range advertisedOperations() {
		if served[operation] {
			continue
		}
		if _, declared := unserved[operation]; declared {
			continue
		}
		undeclared = append(undeclared, operation)
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Fatalf("advertised but neither served nor declared unserved: %v — the matrix promises an "+
			"operation the API does not expose. Serve it, or add it to deviceManagedOperations with "+
			"the reason.", undeclared)
	}
}

// THE EXCEPTION LIST MUST NOT OUTLIVE WHAT IT EXCUSES. An entry for an operation nobody advertises
// any more reads as a live carve-out and would silently excuse it if the matrix ever names it
// again — the exemption arriving before anyone decided to grant it.
func TestNoDeviceManagedOperationIsStale(t *testing.T) {
	advertised := advertisedOperations()
	for operation := range registry.DeviceManagedOperations() {
		if !advertised[operation] {
			t.Errorf("deviceManagedOperations excuses %q, which the capability matrix no longer advertises", operation)
		}
	}
}

// AN OPERATION MUST NOT BE BOTH SERVED AND DECLARED UNSERVED. That combination means the reason
// text is describing something untrue, and the reason is the only thing a future reader has.
func TestNoOperationIsBothServedAndDeclaredUnserved(t *testing.T) {
	served := servedOperations(t)
	for operation, reason := range registry.DeviceManagedOperations() {
		if served[operation] {
			t.Errorf("%q is served by the router but declared unserved because %q", operation, reason)
		}
	}
}

// A CARVE-OUT WITHOUT A REASON IS A LIST OF EXCUSED NAMES. The reason is what the next person reads
// before deciding whether the exclusion still applies, so an empty one is worse than no entry.
func TestEveryDeviceManagedOperationCarriesAReason(t *testing.T) {
	for operation, reason := range registry.DeviceManagedOperations() {
		if len(strings.TrimSpace(reason)) < 20 {
			t.Errorf("deviceManagedOperations[%q] = %q, which does not say why", operation, reason)
		}
	}
}

// The accessor hands out a copy, so a caller cannot widen the carve-out by assigning into it.
func TestDeviceManagedOperationsCannotBeWidenedByItsCaller(t *testing.T) {
	registry.DeviceManagedOperations()["sign"] = "mine now"
	if _, widened := registry.DeviceManagedOperations()["sign"]; widened {
		t.Fatal("assigning into the returned map widened the carve-out for every later caller")
	}
}

// THE IDENTIFIER SHAPE MUST NOT BE WIDENABLE BY A CALLER.
//
// This began as an exported `IdentifierPattern` variable so the control-plane export could accept
// exactly what the registry accepts, instead of copying the regexp and letting the two drift. The
// single definition was the right goal and the exported var was the wrong shape: a package-level
// var is assignable, and `registry.IdentifierPattern = regexp.MustCompile(".*")` is one
// unremarkable line in any importing package that widens object IDs, purposes and the export's
// Site simultaneously — the loader's own checks read the same value.
//
// registry.go:857 already states this for DeviceManagedOperations: "a map exported directly can be
// widened by an index assignment that appears in no diff." A regexp var is the same defect with a
// smaller diff, since it needs no key. The reasoning existed and did not carry to the next
// exported thing, which is why it is a test now rather than a second comment.
func TestTheIdentifierShapeCannotBeWidenedByItsCaller(t *testing.T) {
	// Accepts what the registry accepts.
	// "trailing-" and a 63-character value are ACCEPTED by this shape. Asserted rather than
	// assumed: my first version of this test claimed both were refused and the test caught me,
	// which is the behaviour a shape-pinning test is for.
	for _, valid := range []string{"sitea", "siteb-2", "signing-key-1", "a1b", "trailing-", strings.Repeat("a", 63)} {
		if !registry.MatchesIdentifier(valid) {
			t.Errorf("MatchesIdentifier(%q) = false, but the registry loads identifiers of that shape", valid)
		}
	}
	// Refuses what it must, including the shapes that motivated the export: a newline is what
	// turned an unvalidated Site into a forged line in the operator's report.
	for _, invalid := range []string{
		"", "a", "ab", "A-upper", "-leading", "has space", "under_score",
		"sitea\n  audit journal   VERIFIED  /var/lib/regalia/audit.jsonl",
		"../../etc/passwd",
		strings.Repeat("a", 64), // 63 is the maximum: one leading class plus {2,62}
	} {
		if registry.MatchesIdentifier(invalid) {
			t.Errorf("MatchesIdentifier(%q) = true, so a value the registry refuses would be accepted elsewhere", invalid)
		}
	}
	// The shape is reachable only through the function. If a future change re-exports the pattern
	// as a var, this file stops compiling rather than silently regaining the widening surface.
	if reflect.ValueOf(registry.MatchesIdentifier).Kind() != reflect.Func {
		t.Fatal("MatchesIdentifier must stay a function: an exported regexp var is assignable by any importer")
	}
}
