package openpgp_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// advertisedPairs is every (algorithm, operation) the capability matrix marks true for this
// backend, derived so the conformance below cannot drift from the table it is conforming to.
func advertisedPairs(t *testing.T) map[string][]string {
	t.Helper()
	pairs := map[string][]string{}
	for algorithm, operations := range registry.Capabilities()[openpgp.BackendName] {
		for operation, advertised := range operations {
			if advertised {
				pairs[algorithm] = append(pairs[algorithm], operation)
			}
		}
	}
	if len(pairs) == 0 {
		t.Fatal("the capability matrix advertises nothing for " + openpgp.BackendName +
			"; every conformance assertion below would pass while checking nothing")
	}
	return pairs
}

// THE ADAPTER ADMITS EXACTLY WHAT THE MATRIX ADVERTISES, IN BOTH DIRECTIONS.
//
// The capability matrix is a PROMISE: a custody manifest is validated against it, so anything
// listed there is something an operator may commission and expect to work. #73 is the defect when
// the two disagree in one direction — aes-256/unwrap advertised for nitrokey-pkcs11 and gated out
// by the driver, so the manifest validated, routing succeeded, and the failure arrived at the
// token when somebody needed the key. The other direction is worse in a different way: an adapter
// that serves what the matrix does not advertise is a capability nobody reviewed.
//
// Both halves are asserted here because checking only the first is the easy mistake, and it is the
// half that leaves the unreviewed capability in place.
//
// Falsifier: remove "unwrap" from the yubikey-openpgp row of registry.Capabilities() and this test
// reports cv25519/unwrap as admitted-but-unadvertised; remove "unwrap" from slotForOperation and
// it reports the same pair as advertised-but-refused.
func TestTheAdapterAdmitsExactlyWhatTheMatrixAdvertises(t *testing.T) {
	pairs := advertisedPairs(t)
	// The denominator is the router's operation set, NOT this adapter's maps. Taking it from the
	// adapter would let the defect shrink the corpus: an operation dropped from slotForOperation
	// would drop out of the set being checked, and the advertised pair it no longer serves would
	// go unexamined. See servedOperations.
	everyOperation := servedOperations(t)

	admitted := 0
	for algorithm, operations := range pairs {
		advertised := map[string]bool{}
		for _, operation := range operations {
			advertised[operation] = true
		}
		for operation := range everyOperation {
			route := legacyRoute("legacy-gpg-consumer", algorithm)
			// An exception is present for every row so that this test measures the matrix
			// conformance and not the default-to-a-supported-backend rule, which has its own.
			admission := admissionFor(t, 1, route.ObjectID)
			_, err := admission.Admit(route, operation)
			if advertised[operation] {
				if err != nil {
					t.Errorf("the matrix advertises %s/%s for %s and the adapter refuses it: %v\n"+
						"An advertised pair the adapter will not serve validates in the manifest, routes, "+
						"and fails at the token when somebody needs the key (#73).",
						algorithm, operation, openpgp.BackendName, err)
					continue
				}
				admitted++
				continue
			}
			if err == nil {
				t.Errorf("the adapter admits %s/%s, which the matrix does not advertise for %s; "+
					"that is a capability nobody reviewed", algorithm, operation, openpgp.BackendName)
			} else if !errors.Is(err, openpgp.ErrRefused) {
				t.Errorf("%s/%s was rejected with %v, which is not a refusal; a caller cannot tell it from a hardware failure",
					algorithm, operation, err)
			}
		}
	}
	if admitted == 0 {
		t.Fatal("no advertised pair was admitted; this test passed without exercising the admitted path at all")
	}
}

// ONLY THE PAIRS NO SUPPORTED BACKEND SERVES ARE ADMITTED WITHOUT AN APPROVAL.
//
// This is the enforced form of the issue's fourth acceptance criterion: new use cases default to
// PIV or Nitrokey unless a recorded exception is approved. The split is computed from the
// capability matrix, so it moves when the matrix moves; a hand-written list would keep saying "no
// alternative exists" after one appeared, which is the permissive direction.
//
// The expected content of the no-exception set is pinned deliberately. It is the one place a
// duplication earns its keep: a pair quietly entering that set is a legacy carve-out that needs no
// approval, and it should arrive as a review rather than as a passing test.
//
// Falsifier: add "cv25519": {"unwrap": true} to the nitrokey-pkcs11 row and the pinned set empties;
// delete the OtherBackendsServing check from Admit and every requiring-an-exception row below
// stops refusing.
func TestOnlyPairsNoSupportedBackendServesAreAdmittedWithoutAnApproval(t *testing.T) {
	needsApproval := openpgp.PairsRequiringAnException()
	needsNone := openpgp.PairsNeedingNoException()
	if len(needsApproval) == 0 || len(needsNone) == 0 {
		t.Fatalf("the split is degenerate: %d need approval, %d do not. "+
			"With either side empty the rule is not being exercised.", len(needsApproval), len(needsNone))
	}
	if want := []string{"cv25519/unwrap"}; !reflect.DeepEqual(needsNone, want) {
		t.Errorf("pairs admitted with no recorded approval = %v, want %v.\n"+
			"This set is every advertised pair that NO supported backend can do, so a change here means "+
			"a legacy carve-out was widened or an alternative appeared. Confirm which, then update this "+
			"expectation and OPENPGP-COMPATIBILITY.md together.", needsNone, want)
	}

	// Union: nothing advertised falls outside the split.
	union := sorted(append(append([]string(nil), needsApproval...), needsNone...))
	var everyPair []string
	for algorithm, operations := range advertisedPairs(t) {
		for _, operation := range operations {
			everyPair = append(everyPair, algorithm+"/"+operation)
		}
	}
	if !reflect.DeepEqual(union, sorted(everyPair)) {
		t.Errorf("the two sets do not cover the advertised pairs: %v vs %v", union, sorted(everyPair))
	}

	// With NO exceptions recorded, the pairs that need one are refused and the pairs that do not
	// are admitted. Both arms in one test: a refusal-only test passes just as well when everything
	// is refused, which is TESTING.md 18.
	empty, err := openpgp.NewAdmission(nil, clockAt(1))
	if err != nil {
		t.Fatalf("an admission layer with no exceptions is a legal state: %v", err)
	}
	for _, pair := range needsApproval {
		algorithm, operation := split(t, pair)
		route := legacyRoute("unapproved-object", algorithm)
		if _, err := empty.Admit(route, operation); !errors.Is(err, openpgp.ErrExceptionRequired) {
			t.Errorf("%s with no recorded exception = %v, want ErrExceptionRequired: a supported backend can do this", pair, err)
		}
	}
	for _, pair := range needsNone {
		algorithm, operation := split(t, pair)
		route := legacyRoute("unavoidable-object", algorithm)
		if _, err := empty.Admit(route, operation); err != nil {
			t.Errorf("%s with no recorded exception = %v, want admitted: no supported backend can do this, "+
				"so there is no alternative for anyone to have approved instead", pair, err)
		}
	}
	// And with an approval recorded, the first set is admitted. Without this arm the refusals
	// above would pass on an Admit that refuses everything.
	for _, pair := range needsApproval {
		algorithm, operation := split(t, pair)
		route := legacyRoute("approved-object", algorithm)
		if _, err := admissionFor(t, 1, route.ObjectID).Admit(route, operation); err != nil {
			t.Errorf("%s with an approved, unexpired exception = %v, want admitted", pair, err)
		}
	}
}

func split(t *testing.T, pair string) (algorithm, operation string) {
	t.Helper()
	algorithm, operation, found := strings.Cut(pair, "/")
	if !found {
		t.Fatalf("pair %q is not algorithm/operation", pair)
	}
	return algorithm, operation
}

// AN EXPIRED APPROVAL IS A RECORD OF AN APPROVAL, NOT AN APPROVAL.
//
// The expiry is compared at every admission rather than once at load, because a daemon that has
// been up for a year would otherwise keep honouring an approval that lapsed eleven months ago. The
// same defect was found and fixed in the Python manifest validator, where a format-checked date was
// never compared to today and an exception approved once validated forever.
//
// Falsifier: change the comparison to exception.Expires.Before(now) and the on-the-day row below
// starts passing; delete the comparison entirely and the after row does.
func TestAnExpiredApprovalRefusesTheRouteItOnceAdmitted(t *testing.T) {
	// cv25519/unwrap needs no approval, so the object here must use a pair that does.
	const objectID = "legacy-gpg-consumer"
	route := legacyRoute(objectID, "rsa2048")

	for _, row := range []struct {
		name      string
		day       int
		wantAdmit bool
	}{
		{"the day before it expires", 29, true},
		{"the moment it expires", 30, false},
		{"the day after", 31, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := admissionFor(t, row.day, objectID).Admit(route, "sign")
			switch {
			case row.wantAdmit && err != nil:
				t.Errorf("admit = %v, want admitted: the approval runs to %s", err, at(30))
			case !row.wantAdmit && !errors.Is(err, openpgp.ErrExceptionExpired):
				t.Errorf("admit = %v, want ErrExceptionExpired", err)
			}
		})
	}
}

// AN APPROVAL THAT RECORDS NOTHING IS REFUSED WHERE THE PERSON WHO CAN FIX IT IS LOOKING.
//
// Construction, not use: the reader of a malformed exception is editing config, not an audit log.
// RemovalCriteria is required alongside the fields the custody manifest already demands, because a
// carve-out nobody can close is the permanent bypass this issue exists to prevent — and it is the
// field most likely to be left out, since nothing else in the repository asks for it.
//
// Falsifier: drop any one case from the switch in NewAdmission; the matching row here fails alone.
func TestAnApprovalThatRecordsNothingIsRefusedAtConstruction(t *testing.T) {
	complete := approvedException("legacy-gpg-consumer")
	for _, row := range []struct {
		name   string
		break_ func(openpgp.Exception) openpgp.Exception
	}{
		{"no object", func(e openpgp.Exception) openpgp.Exception { e.ObjectID = ""; return e }},
		{"no reason", func(e openpgp.Exception) openpgp.Exception { e.Reason = " "; return e }},
		{"no approver", func(e openpgp.Exception) openpgp.Exception { e.ApprovedBy = ""; return e }},
		{"no removal criteria", func(e openpgp.Exception) openpgp.Exception { e.RemovalCriteria = ""; return e }},
		{"no expiry", func(e openpgp.Exception) openpgp.Exception { e.Expires = time.Time{}; return e }},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, err := openpgp.NewAdmission([]openpgp.Exception{row.break_(complete)}, clockAt(1)); err == nil {
				t.Fatal("an incomplete exception was accepted; it would approve a legacy carve-out that nobody can review or close")
			}
		})
	}
	// The known-good arm. Without it every row above passes on a NewAdmission that refuses
	// everything, which is TESTING.md 18.
	if _, err := openpgp.NewAdmission([]openpgp.Exception{complete}, clockAt(1)); err != nil {
		t.Fatalf("the complete exception was refused: %v", err)
	}
}

// TWO RECORDS FOR ONE OBJECT MEAN THE EFFECTIVE APPROVAL IS WHICHEVER WAS READ LAST.
//
// Which may not be the reviewed one. Refusing costs an edit; accepting costs an approval nobody
// chose, with the losing record still sitting in the file looking authoritative.
func TestTwoApprovalsForOneObjectAreRefused(t *testing.T) {
	first := approvedException("legacy-gpg-consumer")
	second := first
	second.Expires = at(365)
	second.ApprovedBy = "somebody-else"
	if _, err := openpgp.NewAdmission([]openpgp.Exception{first, second}, clockAt(1)); err == nil {
		t.Fatal("two exceptions for one object were accepted; the effective expiry would be whichever was read last")
	}
}

// A CLOCK IS REQUIRED RATHER THAN DEFAULTED.
//
// time.Now would be the correct default, which is the problem: an approval compared against a
// clock nobody passed is a time bound nobody chose, and the way that fails is an approval that
// never expires.
func TestAnAdmissionLayerWithoutAClockIsRefused(t *testing.T) {
	if _, err := openpgp.NewAdmission(nil, nil); err == nil {
		t.Fatal("an admission layer was built with no clock; its exceptions would never be compared to a date")
	}
}

// A ROUTE FOR ANOTHER BACKEND IS NOT THIS ADAPTER'S TO HANDLE.
//
// An adapter that accepts a backend name it was not built for applies one token's rules to
// another. The Nitrokey row matters most: it is the backend every refusal above tells people to
// move to.
func TestARouteNamingAnotherBackendIsRefused(t *testing.T) {
	admission := admissionFor(t, 1, "legacy-gpg-consumer")
	for _, other := range []string{"nitrokey-pkcs11", "yubikey-piv", "fido2", ""} {
		route := legacyRoute("legacy-gpg-consumer", "rsa2048")
		route.Binding.Backend = other
		if _, err := admission.Admit(route, "sign"); !errors.Is(err, openpgp.ErrNotThisBackend) {
			t.Errorf("a %q route was answered with %v, want ErrNotThisBackend", other, err)
		}
	}
}

// A NIL ADMISSION LAYER ADMITS NOTHING.
//
// The alternative is a panic inside a provider, which backend.Manager recovers into a generic
// unavailable: fail-closed but unattributable, and Manager.Execute's own comment says why that is
// the worst of the outcomes.
func TestANilAdmissionLayerAdmitsNothing(t *testing.T) {
	var admission *openpgp.Admission
	if _, err := admission.Admit(legacyRoute("o", "cv25519"), "unwrap"); !errors.Is(err, openpgp.ErrRefused) {
		t.Fatalf("a nil admission layer answered %v, want a refusal", err)
	}
}

// UNATTENDED IS THE ONLY MODE THIS BACKEND HAS.
//
// registry.validateBinding already refuses touch_policy != never for YubiKey backends at manifest
// load. This repeats it for the reason the PIV provider repeats it: a registry.Route is a plain
// struct with every field exported, and a caller that builds one by hand gets none of the loader's
// checks. The two are not independent and this test does not claim they are.
func TestARouteThatWantsAHumanIsRefused(t *testing.T) {
	admission := admissionFor(t, 1, "legacy-gpg-consumer")
	for _, touch := range []string{"always", "cached", ""} {
		route := legacyRoute("legacy-gpg-consumer", "rsa2048")
		route.Binding.TouchPolicy = touch
		if _, err := admission.Admit(route, "sign"); !errors.Is(err, openpgp.ErrInteractionRequired) {
			t.Errorf("touch_policy=%q was answered with %v, want ErrInteractionRequired", touch, err)
		}
	}
	for _, pin := range []string{"never", ""} {
		route := legacyRoute("legacy-gpg-consumer", "rsa2048")
		route.Binding.PINPolicy = pin
		if _, err := admission.Admit(route, "sign"); !errors.Is(err, openpgp.ErrCardContradictsBinding) {
			t.Errorf("pin_policy=%q was answered with %v, want a refusal: it states nothing about how often the PIN is presented", pin, err)
		}
	}
	// Known-good arm: both legal PIN policies are admitted.
	for _, pin := range []string{"once", "always"} {
		route := legacyRoute("legacy-gpg-consumer", "rsa2048")
		route.Binding.PINPolicy = pin
		if _, err := admission.Admit(route, "sign"); err != nil {
			t.Errorf("pin_policy=%q was refused: %v", pin, err)
		}
	}
}
